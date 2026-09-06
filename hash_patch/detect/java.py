"""hash_patch/detect/java.py — Java JCA/JCE crypto-call detector.

Uses tree-sitter to parse Java source files and identify calls to JCA/JCE
factory methods (Cipher.getInstance, MessageDigest.getInstance, etc.) and
BouncyCastle equivalents listed in rules/java_jca.yaml.

Hash Patch constraints (enforced here):
  - No algorithm names, OIDs, or patterns hardcoded in this file — all
    detection knowledge comes exclusively from rules/java_jca.yaml.
  - Every CryptoAsset is backed by at least one Evidence with file, line,
    column, byte offset, and snippet populated from the tree-sitter node.
  - No network calls, no uuid4(), no datetime.now() on the detection path.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

try:
    import tree_sitter_java as _ts_java
    from tree_sitter import Language, Parser

    _LANG = Language(_ts_java.language())
    _PARSER = Parser(_LANG)
    _TREE_SITTER_AVAILABLE = True
except Exception:  # noqa: BLE001 -- graceful degradation if the native parser fails to load  # pragma: no cover
    _TREE_SITTER_AVAILABLE = False
    _LANG = None  # type: ignore[assignment]
    _PARSER = None  # type: ignore[assignment]

from hash_patch.detect.base import Detector, registry
from hash_patch.model.assets import (
    AssetType,
    Confidence,
    CryptoAsset,
    Primitive,
    QuantumStatus,
)
from hash_patch.model.evidence import Evidence

# Locate the rules file relative to this source file.
# layout:  hash_patch/detect/java.py  →  ../../rules/java_jca.yaml
_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "java_jca.yaml"

_DETECTOR_ID = "java-jca"
_DETECTOR_VERSION = "0.1.0"

# Regex used to strip the "With…" suffix from compound JCA algo names such as
# "SHA256WithRSAEncryption" → "SHA256" on the left, "RSAEncryption" on right.
# Both halves are tried as fallback lookup keys.
_WITH_RE = re.compile(r"(?i)with")

# ---------------------------------------------------------------------------
# Rules loading — executed once at class instantiation, never at module import
# so that import order does not matter and tests can patch the path.
# ---------------------------------------------------------------------------


def _load_rules(path: Path) -> dict[str, Any]:
    """Parse java_jca.yaml and return the raw dict."""
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _build_target_set(rules: dict[str, Any]) -> frozenset[str]:
    """Return a frozenset of 'ClassName.methodName' strings to match."""
    return frozenset(rules.get("target_methods", []))


def _build_bc_constructor_index(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return {'SimpleClassName' -> rule} from bc_constructors — BouncyCastle
    lightweight-API classes instantiated via `new ClassName(...)`, a call
    shape (object_creation_expression) distinct from the getInstance-family
    method_invocation this detector otherwise matches exclusively."""
    raw: dict[str, dict[str, Any]] = rules.get("bc_constructors", {})
    return {k: v for k, v in raw.items()}


def _build_algo_index(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return a dict keyed by UPPERCASE algorithm name → rule entry."""
    raw: dict[str, dict[str, Any]] = rules.get("algorithms", {})
    return {name.upper(): entry for name, entry in raw.items()}


def _build_crypto_references(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return {literal_text -> rule} for standalone string-literal references from shared registry."""
    from hash_patch.detect.canonical_registry import get_canonical_registry

    refs = dict(get_canonical_registry())
    refs.update(rules.get("crypto_references", {}))
    return refs


def _primitive_from_str(value: str | None) -> Primitive:
    """Map a YAML primitive string to Primitive enum, defaulting to UNKNOWN."""
    if value is None:
        return Primitive.UNKNOWN
    try:
        return Primitive(value)
    except ValueError:
        return Primitive.UNKNOWN


def _quantum_status_from_str(value: str | None) -> QuantumStatus:
    """Map a YAML quantum_status string to QuantumStatus enum."""
    if value is None:
        return QuantumStatus.UNKNOWN
    try:
        return QuantumStatus(value)
    except ValueError:
        return QuantumStatus.UNKNOWN


# ---------------------------------------------------------------------------
# AST traversal helpers
# ---------------------------------------------------------------------------


def _extract_string_fragment(string_literal_node: Any) -> str | None:
    """Return the inner text of a tree-sitter string_literal node, or None."""
    for child in string_literal_node.children:
        if child.type == "string_fragment":
            return child.text.decode("utf-8", errors="replace")
    return None


_REFERENCE_CONTAINER_TYPES = frozenset(
    {"variable_declarator", "local_variable_declaration", "field_declaration", "return_statement"}
)
_REFERENCE_EXCLUDED_ANCESTOR_TYPES = frozenset(
    {"method_invocation", "argument_list", "object_creation_expression", "import_declaration", "package_declaration"}
)


def _collect_crypto_references(
    root_node: Any,
    crypto_references: dict[str, dict[str, Any]],
    consumed_offsets: set[int] | None = None,
) -> list[tuple[Any, Any, dict[str, Any]]]:
    """Find standalone string_literal nodes matching a known algorithm/protocol
    name that are never passed as an argument to any call (JCA or otherwise) —
    only assigned to a variable/field or returned. Same rationale as
    hash_patch/detect/c.py's `_try_collect_reference`.
    """
    if not crypto_references:
        return []
    results: list[tuple[Any, Any, dict[str, Any]]] = []
    stack: list[tuple[Any, int]] = [(root_node, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            continue
        if current.type == "string_literal":
            _try_collect_reference(current, crypto_references, results, consumed_offsets=consumed_offsets)
        children = current.children
        if children:
            stack.extend((child, depth + 1) for child in reversed(children))
    return results


def _try_collect_reference(
    node: Any,
    crypto_references: dict[str, dict[str, Any]],
    results: list[tuple[Any, Any, dict[str, Any]]],
    consumed_offsets: set[int] | None = None,
) -> None:
    if consumed_offsets and node.start_byte in consumed_offsets:
        return
    parent = node.parent
    in_call = False
    in_container = False
    while parent:
        if parent.type in _REFERENCE_EXCLUDED_ANCESTOR_TYPES:
            in_call = True
            break
        if parent.type in _REFERENCE_CONTAINER_TYPES:
            in_container = True
        parent = parent.parent
    if in_container and not in_call:
        text = _extract_string_fragment(node)
        if text is None:
            return
        rule = crypto_references.get(text)
        if rule is None:
            from hash_patch.detect.canonical_registry import lookup_canonical_algorithm

            rule = lookup_canonical_algorithm(text)
        if rule is not None:
            stmt = node
            while stmt.parent and stmt.parent.type not in ("program", "class_body", "block"):
                stmt = stmt.parent
            results.append((node, stmt, rule))


def _collect_jca_calls(root_node: Any, bc_classes: frozenset[str] = frozenset()) -> list[dict[str, Any]]:
    """Walk the AST and collect all method_invocation nodes of interest,
    plus (only when `bc_classes` is non-empty) matching BC constructor calls.

    Returns a list of dicts with keys:
        class_name, method_name, algo_raw, node, algo_node
    where ``node`` is the method_invocation node and ``algo_node`` is the
    first string_literal in the argument_list (the algorithm argument);
    OR, for a BC constructor match: {bc_class, node, type_node}.

    Only calls whose first argument is a string literal are returned — calls
    where the algorithm is a variable reference are not detectable without
    data-flow analysis and are deliberately excluded to avoid false positives.
    """
    results: list[dict[str, Any]] = []
    _walk(root_node, results, bc_classes)
    return results


# Uses an explicit heap-allocated stack instead of function-call recursion —
# same rationale and pattern as
# `hash_patch/detect/python.py::_walk` /
# `hash_patch/analyze/callgraph.py::_walk_py_calls` /
# `hash_patch/detect/shelf_life/data_context.py::_walk_python_spans`: a
# deeply nested real file can exceed the native C thread stack, and even a
# clean RecursionError previously propagated uncaught through detect() and
# aborted the whole scan over one pathological file. `_MAX_WALK_DEPTH` is
# defense in depth — a branch deeper than that is simply not descended
# further, the same fail-safe shape as any other call this detector cannot
# resolve.
_MAX_WALK_DEPTH = 500


def _walk(node: Any, results: list[dict[str, Any]], bc_classes: frozenset[str] = frozenset()) -> None:
    """Iterative DFS walk that collects matching method_invocation nodes,
    plus (only when `bc_classes` is non-empty) `new ClassName(...)`
    object_creation_expression nodes whose class is in `bc_classes` — the
    BouncyCastle lightweight API (e.g. `new RSAKeyPairGenerator()`), which
    has no getInstance-style string-literal argument to match on at all.
    Callers that omit `bc_classes` (the default) get exactly the original
    method_invocation-only behavior.
    """
    stack: list[tuple[Any, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            continue
        if current.type == "method_invocation":
            _try_collect(current, results)
            # Still recurse into children — a method invocation can itself be
            # an argument to another call (e.g. Cipher.getInstance(getAlgo())).
        elif current.type == "object_creation_expression" and bc_classes:
            _try_collect_object_creation(current, results, bc_classes)
        children = current.children
        if children:
            stack.extend((child, depth + 1) for child in reversed(children))


def _try_collect_object_creation(
    node: Any, results: list[dict[str, Any]], bc_classes: frozenset[str]
) -> None:
    """If node is `new ClassName(...)` for a known BC class, append an entry.

    No import resolution happens anywhere else in this codebase either (see
    e.g. hash_patch/detect/shelf_life's own docstring), so a fully-qualified
    `new org.bouncycastle.crypto...ClassName(...)` is matched the same way a
    plain `new ClassName(...)` is: by its simple (trailing) type name.
    """
    type_node: Any | None = None
    for child in node.children:
        if child.type in ("type_identifier", "generic_type", "scoped_type_identifier"):
            type_node = child
            break
    if type_node is None:
        return

    type_text = type_node.text.decode("utf-8", errors="replace")
    simple_name = type_text.rsplit(".", 1)[-1].split("<", 1)[0]
    if simple_name not in bc_classes:
        return

    results.append({"bc_class": simple_name, "node": node, "type_node": type_node})


def _try_collect(node: Any, results: list[dict[str, Any]]) -> None:
    """If node is a qualifying JCA-style call, append an entry to results."""
    children = list(node.children)

    # A JCA call looks like:
    #   method_invocation
    #     identifier   (class name,  e.g. "Cipher")
    #     .
    #     identifier   (method name, e.g. "getInstance")
    #     argument_list
    #
    # We need exactly two identifier children before the argument_list.
    identifiers = [c for c in children if c.type == "identifier"]
    arglists = [c for c in children if c.type == "argument_list"]

    if len(identifiers) < 2 or not arglists:
        return

    # The first identifier is the receiver class; the second is the method.
    class_node = identifiers[0]
    method_node = identifiers[1]
    arglist_node = arglists[0]

    named_args = list(arglist_node.named_children)
    first_arg = named_args[0] if named_args else None

    # Find the first string_literal in the argument list (the algorithm arg).
    string_literals = [c for c in arglist_node.children if c.type == "string_literal"]
    if string_literals:
        algo_node = string_literals[0]
        algo_raw = _extract_string_fragment(algo_node)
        if algo_raw:
            results.append(
                {
                    "class_name": class_node.text.decode("utf-8", errors="replace"),
                    "method_name": method_node.text.decode("utf-8", errors="replace"),
                    "algo_raw": algo_raw,
                    "node": node,
                    "algo_node": algo_node,
                    "arg_node": first_arg,
                }
            )
            return

    # If first_arg is present but not a resolvable literal (variable, expression, or missing):
    algo_node = first_arg if first_arg is not None else method_node
    results.append(
        {
            "class_name": class_node.text.decode("utf-8", errors="replace"),
            "method_name": method_node.text.decode("utf-8", errors="replace"),
            "algo_raw": None,
            "node": node,
            "algo_node": algo_node,
            "arg_node": first_arg,
        }
    )


# ---------------------------------------------------------------------------
# Algorithm normalisation and lookup (rules-driven, no hardcoded names)
# ---------------------------------------------------------------------------


def _lookup_algo(algo_raw: str, index: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]] | None:
    """Return (canonical_name, rule_entry) or None if not in rules.

    Normalisation steps (all driven by the index, not hardcoded names):
    1. Exact uppercase match.
    2. Split a JCA transformation string "Algorithm/Mode/Padding" (e.g.
       "AES/GCM/NoPadding") on "/" and look up the algorithm segment — but,
       unlike a bare compound-name split, the mode segment is never
       discarded: two different modes of the same algorithm (AES/GCM vs
       AES/CBC) are two different crypto assets, not the same one, so the
       returned rule carries `mode` overridden from the transformation
       string itself (this is generic JCA transformation-string structure,
       not an algorithm-specific fact, so it is parsed here rather than
       enumerated per-algorithm in rules/java_jca.yaml).
    3. Strip everything after "With" (compound signature algo, e.g.
       "SHA256WithRSAEncryption") — try both halves in order: right-of-With
       first (the signing algorithm), then left-of-With.
    """
    # Step 1: exact uppercase
    key = algo_raw.upper()
    if key in index:
        return algo_raw, index[key]

    # Step 2: JCA transformation string  (e.g. "AES/GCM/NoPadding")
    slash_parts = key.split("/")
    slash_key = slash_parts[0]
    if slash_key != key and slash_key in index:
        base_rule = index[slash_key]
        mode_segment = slash_parts[1] if len(slash_parts) >= 2 else ""
        if mode_segment:
            rule_with_mode = dict(base_rule)
            rule_with_mode["mode"] = mode_segment.lower()
            return slash_key, rule_with_mode
        return slash_key, base_rule

    # Step 3a/3b: split on "With"  (e.g. "SHA256WithRSAEncryption")
    parts = _WITH_RE.split(key, maxsplit=1)
    if len(parts) == 2:
        left, right = parts
        # Try the right-hand side (the crypto primitive, e.g. "RSA")
        # Strip common suffixes that are part of OID / full name but not
        # the simple canonical form  (e.g. "RSAENCRYPTION" → "RSA").
        for candidate in (right, right.removesuffix("ENCRYPTION").removesuffix("SIGNATURE")):
            if candidate in index:
                return candidate, index[candidate]
        # Try left-hand side (the hash, e.g. "SHA256" → not in index? try "SHA-256")
        for candidate in (left,):
            if candidate in index:
                return candidate, index[candidate]

    from hash_patch.detect.canonical_registry import lookup_canonical_algorithm

    c_rule = lookup_canonical_algorithm(algo_raw)
    if c_rule is not None:
        return c_rule["canonical"], c_rule

    return None


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


class JavaJcaDetector(Detector):
    """Detects JCA/JCE and BouncyCastle crypto calls in Java source files.

    All algorithm knowledge is loaded from rules/java_jca.yaml at
    instantiation time. No algorithm names are hardcoded in this class.
    """

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        rules = _load_rules(_RULES_PATH)
        self._targets: frozenset[str] = _build_target_set(rules)
        self._algo_index: dict[str, dict[str, Any]] = _build_algo_index(rules)
        self._bc_constructors: dict[str, dict[str, Any]] = _build_bc_constructor_index(rules)
        self._crypto_references: dict[str, dict[str, Any]] = _build_crypto_references(rules)

    def supports(self, target: Path) -> bool:
        """Return True for .java files (when tree-sitter is available)."""
        return _TREE_SITTER_AVAILABLE and target.is_file() and target.suffix.lower() == ".java"

    def detect(self, target: Path) -> list[CryptoAsset]:
        """Parse target and return one CryptoAsset per unique detected algorithm.

        Each asset carries Evidence with file path, 1-based line number,
        0-based column, byte offset of the algorithm string literal, and a
        snippet of the full call expression.
        """
        if not self.supports(target):
            return []

        source_bytes = target.read_bytes()
        tree = _PARSER.parse(source_bytes)  # type: ignore[union-attr]
        calls = _collect_jca_calls(tree.root_node, bc_classes=frozenset(self._bc_constructors))

        # Accumulate assets by id so that multiple call sites for the same
        # algorithm merge their evidence (via ScanResult.add_asset semantics).
        # Here we build a local dict first; the caller (cli.scan) uses
        # result.add_asset() which handles cross-file dedup.
        local: dict[str, CryptoAsset] = {}
        locator = str(target)
        consumed_offsets: set[int] = set()
        from hash_patch.detect.java_resolver import resolve_java_argument

        def _emit(
            canonical_name: str,
            rule: dict[str, Any] | None,
            conf: Confidence,
            props: dict[str, str],
            extra_seed: str | None,
            t_node: Any,
            i_node: Any,
        ) -> None:
            if rule is not None:
                prim = _primitive_from_str(rule.get("primitive"))
                param_set: str | None = rule.get("parameter_set")
                q_status = _quantum_status_from_str(rule.get("quantum_status"))
                o_id: str | None = rule.get("oid")
                mode: str | None = rule.get("mode")
            else:
                prim = Primitive.UNKNOWN
                param_set = None
                q_status = QuantumStatus.UNKNOWN
                o_id = None
                mode = None

            ev = Evidence(
                source_type="source",
                locator=locator,
                line=t_node.start_point.row + 1,
                column=t_node.start_point.column,
                byte_offset=t_node.start_byte,
                snippet=i_node.text.decode("utf-8", errors="replace"),
                detector_id=_DETECTOR_ID,
                detector_version=_DETECTOR_VERSION,
            )

            ast = CryptoAsset.create(
                asset_type=AssetType.ALGORITHM,
                name=canonical_name,
                primitive=prim,
                parameter_set=param_set,
                mode=mode,
                quantum_status=q_status,
                oid=o_id,
                confidence=conf,
                properties=props,
                extra_id_seed=extra_seed,
                evidence=[ev],
            )

            a_id = ast.id
            if a_id in local:
                existing = local[a_id]
                seen_keys = {e.key() for e in existing.evidence}
                if ev.key() not in seen_keys:
                    existing.evidence.append(ev)
                for k, v in props.items():
                    existing.properties.setdefault(k, v)
            else:
                local[a_id] = ast

        for call in calls:
            bc_class = call.get("bc_class")
            if bc_class is not None:
                rule = self._bc_constructors.get(bc_class)
                if rule is None:
                    continue
                _emit(
                    canonical_name=rule["canonical"],
                    rule=rule,
                    conf="confirmed",
                    props={},
                    extra_seed=None,
                    t_node=call["type_node"],
                    i_node=call["node"],
                )
            else:
                qualified = f"{call['class_name']}.{call['method_name']}"
                if qualified not in self._targets:
                    continue

                algo_raw: str | None = call.get("algo_raw")
                algo_node = call["algo_node"]
                inv_node = call["node"]
                arg_node = call.get("arg_node")

                if algo_raw is not None:
                    lookup = _lookup_algo(algo_raw, self._algo_index)
                    if lookup is not None:
                        canonical_name, rule = lookup
                        _emit(
                            canonical_name=canonical_name,
                            rule=rule,
                            conf="confirmed",
                            props={},
                            extra_seed=None,
                            t_node=algo_node,
                            i_node=inv_node,
                        )
                    else:
                        _emit(
                            canonical_name="UNRESOLVED",
                            rule=None,
                            conf="LOW",
                            props={"api": qualified, "resolution_path": "null"},
                            extra_seed=qualified,
                            t_node=algo_node,
                            i_node=inv_node,
                        )
                else:
                    resolutions = resolve_java_argument(arg_node, target)
                    if not resolutions:
                        _emit(
                            canonical_name="UNRESOLVED",
                            rule=None,
                            conf="LOW",
                            props={"api": qualified, "resolution_path": "null"},
                            extra_seed=qualified,
                            t_node=algo_node,
                            i_node=inv_node,
                        )
                    for res in resolutions:
                        lookup = _lookup_algo(res.algo_raw, self._algo_index) if res.algo_raw else None
                        # A resolved node's tree-sitter position is only
                        # meaningful when paired with the file it was
                        # actually parsed from. `locator` below is always
                        # `target` (this file) — so a resolution whose
                        # algo_node came from a DIFFERENT file (parameter
                        # passthrough can cross into other files; see
                        # java_resolver.py's `algo_file`) must never have
                        # its row/column used here, or the emitted Evidence
                        # would claim a line number that is only valid in a
                        # different file's coordinate space. Fall back to
                        # the original in-file call argument node instead —
                        # still accurate, just less granular.
                        if res.algo_node is not None and res.algo_file in (None, target):
                            consumed_offsets.add(res.algo_node.start_byte)
                            t_node = res.algo_node
                        else:
                            t_node = algo_node
                        if lookup is not None:
                            canonical_name, rule = lookup
                            props: dict[str, str] = {}
                            if res.resolution_path:
                                props["resolution_path"] = json.dumps(res.resolution_path)
                            if res.branch_condition:
                                props["branch_condition"] = res.branch_condition
                            _emit(
                                canonical_name=canonical_name,
                                rule=rule,
                                conf=res.confidence,  # type: ignore[arg-type]
                                props=props,
                                extra_seed=res.branch_condition,
                                t_node=t_node,
                                i_node=inv_node,
                            )
                        else:
                            props = {
                                "api": qualified,
                                "resolution_path": json.dumps(res.resolution_path)
                                if res.resolution_path
                                else "null",
                            }
                            if res.branch_condition:
                                props["branch_condition"] = res.branch_condition
                            _emit(
                                canonical_name="UNRESOLVED",
                                rule=None,
                                conf="LOW",
                                props=props,
                                extra_seed=f"{qualified}:{res.branch_condition or ''}",
                                t_node=t_node,
                                i_node=inv_node,
                            )

        # Standalone string literal references (CRYPTO_REFERENCE) — a literal
        # that looks like an algorithm/cipher-suite name but is never passed
        # to any call (JCA or otherwise) in this file.
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
                properties={"finding_type": "CRYPTO_REFERENCE"},
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

        # Sort evidence within each asset for determinism.
        for asset in local.values():
            asset.evidence.sort(key=lambda e: e.key())

        # Return assets sorted by id for deterministic ordering.
        return sorted(local.values(), key=lambda a: a.id)


# ---------------------------------------------------------------------------
# Self-register when this module is imported.
# ---------------------------------------------------------------------------
registry.register(JavaJcaDetector())
