"""hash_patch/detect/go.py — Go standard library crypto detector.

Uses tree-sitter to parse Go source files and identify calls to Go stdlib
crypto packages (crypto/rsa, crypto/ecdsa, crypto/aes, crypto/cipher,
crypto/sha256, crypto/md5, crypto/des, crypto/rc4, etc.) as listed in
rules/go_crypto.yaml.

Hash Patch constraints (enforced here):
  - No algorithm names, OIDs, or patterns hardcoded in this file — all
    detection knowledge comes exclusively from rules/go_crypto.yaml.
  - Every CryptoAsset is backed by at least one Evidence with file, line,
    column, byte offset, and snippet populated from the tree-sitter node.
  - No network calls, no uuid4(), no datetime.now() on the detection path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

try:
    import tree_sitter_go as _tsgo
    from tree_sitter import Language, Parser

    _LANG = Language(_tsgo.language())
    _PARSER = Parser(_LANG)
    _TREE_SITTER_AVAILABLE = True
except Exception:  # noqa: BLE001 -- graceful degradation if the native parser fails to load  # pragma: no cover
    _TREE_SITTER_AVAILABLE = False
    _LANG = None  # type: ignore[assignment]
    _PARSER = None  # type: ignore[assignment]

from hash_patch.detect.base import Detector, registry
from hash_patch.detect.go_resolver import resolve_go_argument
from hash_patch.model.assets import (
    AssetType,
    Confidence,
    CryptoAsset,
    Primitive,
    QuantumStatus,
)
from hash_patch.model.evidence import Evidence

# Locate the rules file relative to this source file.
# layout:  hash_patch/detect/go.py  →  ../../rules/go_crypto.yaml
_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "go_crypto.yaml"

_DETECTOR_ID = "go-crypto"
_DETECTOR_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Rules loading
# ---------------------------------------------------------------------------


def _load_rules(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _build_function_index(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return a dict mapping '<pkg>.<FuncName>' -> rule dict."""
    return rules.get("functions", {})


def _build_crypto_references(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return {literal_text -> rule} for standalone string-literal references from shared registry."""
    from hash_patch.detect.canonical_registry import get_canonical_registry

    refs = dict(get_canonical_registry())
    refs.update(rules.get("crypto_references", {}))
    return refs



def _primitive_from_str(value: str | None) -> Primitive:
    if value is None:
        return Primitive.UNKNOWN
    try:
        return Primitive(value)
    except ValueError:
        return Primitive.UNKNOWN


def _quantum_status_from_str(value: str | None) -> QuantumStatus:
    if value is None:
        return QuantumStatus.UNKNOWN
    try:
        return QuantumStatus(value)
    except ValueError:
        return QuantumStatus.UNKNOWN


# ---------------------------------------------------------------------------
# AST traversal helpers
# ---------------------------------------------------------------------------


def _collect_calls(root_node: Any) -> list[dict[str, Any]]:
    """Walk the AST and collect all call_expression nodes with selector function.

    Returns a list of dicts with:
        target: '<pkg>.<Func>'
        receiver_target: '<pkg>.<Func>' or None
        call_node: Node
        fn_node: Node
    """
    results: list[dict[str, Any]] = []
    receiver_calls: set[int] = set()
    _find_receiver_calls(root_node, receiver_calls)
    _walk(root_node, results, receiver_calls)
    return results


def _find_receiver_calls(node: Any, receivers: set[int]) -> None:
    """Identify intermediate call_expression nodes serving as receivers in chained method calls."""
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn and fn.type == "selector_expression":
            op = fn.child_by_field_name("operand")
            curr = op
            while curr and curr.type == "call_expression":
                receivers.add(curr.id)
                inner_fn = curr.child_by_field_name("function")
                curr = (
                    inner_fn.child_by_field_name("operand")
                    if inner_fn and inner_fn.type == "selector_expression"
                    else None
                )
    for c in node.children:
        _find_receiver_calls(c, receivers)


def _walk(node: Any, results: list[dict[str, Any]], receiver_calls: set[int]) -> None:
    if node.type == "call_expression":
        if node.id not in receiver_calls:
            _try_collect(node, results)
    for child in node.children:
        _walk(child, results, receiver_calls)


def _decompose_node(node: Any) -> str | None:
    """Decompose an identifier, selector, or call expression into a dot-separated string."""
    if node is None:
        return None
    if node.type in ("identifier", "field_identifier", "package_identifier"):
        return node.text.decode("utf-8", errors="replace")
    if node.type == "selector_expression":
        operand = node.child_by_field_name("operand")
        field = node.child_by_field_name("field")
        if operand is None or field is None:
            parts = [c for c in node.children if c.type in ("identifier", "field_identifier", "package_identifier")]
            if len(parts) >= 2:
                operand, field = parts[0], parts[1]
        op_str = _decompose_node(operand)
        f_str = _decompose_node(field)
        if op_str and f_str:
            return f"{op_str}.{f_str}"
        return f_str or op_str
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is None:
            for child in node.children:
                if child.type != "argument_list":
                    fn = child
                    break
        return _decompose_node(fn)
    return None


def _try_collect(call_node: Any, results: list[dict[str, Any]]) -> None:
    """If call_node has a selector_expression function (e.g. rsa.GenerateKey), collect it."""
    fn_node = call_node.child_by_field_name("function")
    if fn_node is None:
        for child in call_node.children:
            if child.type != "argument_list":
                fn_node = child
                break

    if fn_node and fn_node.type == "selector_expression":
        operand = fn_node.child_by_field_name("operand")
        field = fn_node.child_by_field_name("field")
        if operand is None or field is None:
            parts = [c for c in fn_node.children if c.type in ("identifier", "field_identifier", "package_identifier")]
            if len(parts) >= 2:
                operand, field = parts[0], parts[1]

        if operand and field:
            op_text = _decompose_node(operand)
            field_text = _decompose_node(field)
            if op_text and field_text:
                results.append({
                    "target": f"{op_text}.{field_text}",
                    "receiver_target": op_text,
                    "call_node": call_node,
                    "fn_node": fn_node,
                })


_REFERENCE_CONTAINER_TYPES = frozenset(
    {"var_declaration", "const_declaration", "return_statement", "short_var_declaration"}
)
_REFERENCE_EXCLUDED_ANCESTOR_TYPES = frozenset({"call_expression", "argument_list"})
_REFERENCE_STRING_TYPES = frozenset({"interpreted_string_literal", "raw_string_literal"})


def _collect_crypto_references(
    root_node: Any,
    crypto_references: dict[str, dict[str, Any]],
    consumed_offsets: set[int] | None = None,
) -> list[tuple[Any, Any, dict[str, Any]]]:
    """Find standalone string-literal nodes matching a known algorithm/protocol
    name that are never passed as an argument to any call — only assigned to
    a var/const or map literal value, or returned. Same rationale as
    hash_patch/detect/c.py's `_try_collect_reference`.
    """
    if not crypto_references:
        return []
    results: list[tuple[Any, Any, dict[str, Any]]] = []
    stack: list[Any] = [root_node]
    while stack:
        current = stack.pop()
        if current.type in _REFERENCE_STRING_TYPES:
            _try_collect_reference(current, crypto_references, results, consumed_offsets=consumed_offsets)
        for child in current.children:
            stack.append(child)
    return results


def _try_collect_reference(
    node: Any,
    crypto_references: dict[str, dict[str, Any]],
    results: list[tuple[Any, Any, dict[str, Any]]],
    consumed_offsets: set[int] | None = None,
) -> None:
    if consumed_offsets and node.start_byte in consumed_offsets:
        return
    child = node
    parent = node.parent
    in_call = False
    in_container = False
    while parent:
        if parent.type in _REFERENCE_EXCLUDED_ANCESTOR_TYPES:
            in_call = True
            break
        if parent.type == "keyed_element" and parent.child_by_field_name("key") is child:
            # A map key literal (e.g. "default" in Profiles["default"]) is
            # never itself an algorithm-name reference — its slot means it
            # would only ever match a rule that also happened to name a map
            # key, which crypto_references never does by construction.
            in_call = True
            break
        if parent.type in _REFERENCE_CONTAINER_TYPES:
            in_container = True
        child = parent
        parent = parent.parent
    if in_container and not in_call:
        from hash_patch.detect.go_resolver import extract_string_literal

        text = extract_string_literal(node)
        if text is None:
            return
        rule = crypto_references.get(text)
        if rule is None:
            from hash_patch.detect.canonical_registry import lookup_canonical_algorithm

            rule = lookup_canonical_algorithm(text)
        if rule is not None:
            stmt = node
            while stmt.parent and stmt.parent.type not in ("source_file", "block"):
                stmt = stmt.parent
            results.append((node, stmt, rule))


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


class GoCryptoDetector(Detector):
    """Detects Go standard library crypto calls in Go source files.

    All algorithm knowledge is loaded from rules/go_crypto.yaml at
    instantiation time. No algorithm names are hardcoded in this class.
    """

    # Reachability classification (hash_patch/analyze/reachability.py) is only
    # wired up for Python and Java; Go is out of scope for now, so assets from
    # this detector keep the model's default CryptoAsset.reachability = UNKNOWN
    # rather than risk a wrong (unsafe) classification from an unbuilt call graph.

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        rules = _load_rules(_RULES_PATH)
        self._functions: dict[str, dict[str, Any]] = _build_function_index(rules)
        self._algo_arg_functions: dict[str, dict[str, Any]] = rules.get("algorithm_arg_functions", {})
        self._algorithms: dict[str, dict[str, Any]] = rules.get("algorithms", {})
        self._crypto_references: dict[str, dict[str, Any]] = _build_crypto_references(rules)

    def _lookup_algo(self, algo_raw: str) -> tuple[str, dict[str, Any]] | None:
        key = algo_raw.upper()
        if key in self._algorithms:
            return self._algorithms[key]["canonical"], self._algorithms[key]
        norm = key.replace("-", "").replace("_", "")
        for k, v in self._algorithms.items():
            if k.upper().replace("-", "").replace("_", "") == norm:
                return v["canonical"], v
        from hash_patch.detect.canonical_registry import lookup_canonical_algorithm

        c_rule = lookup_canonical_algorithm(algo_raw)
        if c_rule is not None:
            return c_rule["canonical"], c_rule
        return None

    def supports(self, target: Path) -> bool:
        """Return True for .go files (when tree-sitter is available)."""
        return _TREE_SITTER_AVAILABLE and target.is_file() and target.suffix.lower() == ".go"

    def detect(self, target: Path) -> list[CryptoAsset]:
        """Parse target and return one CryptoAsset per unique detected algorithm.

        Each asset carries Evidence with file path, 1-based line number,
        0-based column, byte offset of the function selector, and a
        snippet of the full call expression.
        """
        if not self.supports(target):
            return []

        source_bytes = target.read_bytes()
        tree = _PARSER.parse(source_bytes)  # type: ignore[union-attr]
        calls = _collect_calls(tree.root_node)

        local: dict[str, CryptoAsset] = {}
        locator = str(target)
        consumed_offsets: set[int] = set()

        known_pkgs = {k.split(".")[0] for k in self._functions.keys()}

        for call in calls:
            target_func = call["target"]
            receiver_target = call.get("receiver_target")
            pkg = target_func.split(".")[0]
            fn_node = call["fn_node"]
            call_node = call["call_node"]
            snippet = call_node.text.decode("utf-8", errors="replace")

            def _emit(
                c_name: str,
                c_rule: dict[str, Any] | None,
                conf: Confidence,
                props: dict[str, str],
                extra_seed: str | None,
                t_node: Any,
            ) -> None:
                if c_rule is not None:
                    c_prim = _primitive_from_str(c_rule.get("primitive"))
                    c_param = c_rule.get("parameter_set")
                    c_mode = c_rule.get("mode")
                    c_quantum = _quantum_status_from_str(c_rule.get("quantum_status"))
                    c_oid = c_rule.get("oid")
                else:
                    c_prim = Primitive.UNKNOWN
                    c_param = None
                    c_mode = None
                    c_quantum = QuantumStatus.UNKNOWN
                    c_oid = None

                ev = Evidence(
                    source_type="source",
                    locator=locator,
                    line=t_node.start_point.row + 1,
                    column=t_node.start_point.column,
                    byte_offset=t_node.start_byte,
                    snippet=snippet,
                    detector_id=_DETECTOR_ID,
                    detector_version=_DETECTOR_VERSION,
                )

                asset = CryptoAsset.create(
                    asset_type=AssetType.ALGORITHM,
                    name=c_name,
                    primitive=c_prim,
                    parameter_set=c_param,
                    mode=c_mode,
                    quantum_status=c_quantum,
                    oid=c_oid,
                    confidence=conf,
                    properties=props,
                    extra_id_seed=extra_seed,
                    evidence=[ev],
                )

                asset_id = asset.id
                if asset_id in local:
                    existing = local[asset_id]
                    seen = {e.key() for e in existing.evidence}
                    if ev.key() not in seen:
                        existing.evidence.append(ev)
                    for k, v in props.items():
                        existing.properties.setdefault(k, v)
                else:
                    local[asset_id] = asset

            if target_func in self._algo_arg_functions:
                func_cfg = self._algo_arg_functions[target_func]
                arg_idx = func_cfg.get("arg_index", 0) if isinstance(func_cfg, dict) else 0
                arg_list = None
                for child in call_node.children:
                    if child.type == "argument_list":
                        arg_list = child
                        break
                arg_nodes = list(arg_list.named_children) if arg_list else []
                target_arg = arg_nodes[arg_idx] if len(arg_nodes) > arg_idx else None

                resolutions = resolve_go_argument(target_arg, target) if target_arg else []
                if not resolutions:
                    _emit(
                        c_name="UNRESOLVED",
                        c_rule=None,
                        conf="LOW",
                        props={"api": target_func, "resolution_path": "null"},
                        extra_seed=target_func,
                        t_node=fn_node,
                    )
                else:
                    for res in resolutions:
                        if res.algo_node is not None:
                            consumed_offsets.add(res.algo_node.start_byte)
                        lookup = self._lookup_algo(res.algo_raw) if res.algo_raw else None
                        t_node = res.algo_node if res.algo_node is not None else fn_node
                        if lookup is not None:
                            c_name, c_rule = lookup
                            props: dict[str, str] = {}
                            if res.resolution_path:
                                props["resolution_path"] = json.dumps(res.resolution_path)
                            if res.branch_condition:
                                props["branch_condition"] = res.branch_condition
                            _emit(
                                c_name=c_name,
                                c_rule=c_rule,
                                conf="confirmed",
                                props=props,
                                extra_seed=None,
                                t_node=t_node,
                            )
                        else:
                            _emit(
                                c_name="UNRESOLVED",
                                c_rule=None,
                                conf="LOW",
                                props={"api": target_func, "resolution_path": "null"},
                                extra_seed=target_func,
                                t_node=t_node,
                            )
            elif target_func in self._functions:
                rule = self._functions[target_func]
                _emit(
                    c_name=rule["canonical"],
                    c_rule=rule,
                    conf="confirmed",
                    props={},
                    extra_seed=None,
                    t_node=fn_node,
                )
            elif receiver_target and receiver_target in self._functions:
                rule = self._functions[receiver_target]
                _emit(
                    c_name=rule["canonical"],
                    c_rule=rule,
                    conf="confirmed",
                    props={},
                    extra_seed=None,
                    t_node=fn_node,
                )
            elif pkg in known_pkgs:
                _emit(
                    c_name="UNRESOLVED",
                    c_rule=None,
                    conf="LOW",
                    props={"api": target_func, "resolution_path": "null"},
                    extra_seed=target_func,
                    t_node=fn_node,
                )

        # Standalone string literal references (CRYPTO_REFERENCE) — a literal
        # that looks like an algorithm/cipher-suite name but is never passed
        # to any call in this file.
        ref_matches = _collect_crypto_references(
            tree.root_node, self._crypto_references, consumed_offsets=consumed_offsets
        )
        for pos_node, stmt_node, rule in ref_matches:
            primitive = _primitive_from_str(rule.get("primitive"))
            quantum_status = _quantum_status_from_str(rule.get("quantum_status"))
            ref_asset_type = (
                AssetType.PROTOCOL if rule.get("primitive") == "protocol" else AssetType.ALGORITHM
            )

            ev = Evidence(
                source_type="source",
                locator=locator,
                line=pos_node.start_point.row + 1,
                column=pos_node.start_point.column,
                byte_offset=pos_node.start_byte,
                snippet=stmt_node.text.decode("utf-8", errors="replace").strip(),
                detector_id=_DETECTOR_ID,
                detector_version=_DETECTOR_VERSION,
            )

            ref_properties = {"finding_type": "CRYPTO_REFERENCE"}
            if "matched_text" in rule:
                ref_properties["matched_text"] = rule["matched_text"]
            if "matched_name" in rule:
                ref_properties["matched_name"] = rule["matched_name"]

            ref_asset = CryptoAsset.create(
                asset_type=ref_asset_type,
                name=rule["canonical"],
                primitive=primitive,
                parameter_set=rule.get("parameter_set"),
                mode=rule.get("mode"),
                quantum_status=quantum_status,
                oid=rule.get("oid"),
                confidence="confirmed",
                finding_type="CRYPTO_REFERENCE",
                properties=ref_properties,
                extra_id_seed="CRYPTO_REFERENCE",
                evidence=[ev],
            )

            ref_id = ref_asset.id
            if ref_id in local:
                existing = local[ref_id]
                seen_keys = {e.key() for e in existing.evidence}
                if ev.key() not in seen_keys:
                    existing.evidence.append(ev)
            else:
                local[ref_id] = ref_asset

        for asset in local.values():
            asset.evidence.sort(key=lambda e: e.key())

        return sorted(local.values(), key=lambda a: a.id)


# ---------------------------------------------------------------------------
# Self-register when this module is imported.
# ---------------------------------------------------------------------------
registry.register(GoCryptoDetector())
