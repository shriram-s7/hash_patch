"""hash_patch/detect/python.py — Python crypto-library detector.

Uses tree-sitter to parse Python source files and identify calls to:

  Pattern A — PyCA `cryptography` library:
    module.AttributeName(...)  where the module is a known PyCA namespace
    (hashes, algorithms, rsa, ec, dsa, dh, x25519, ed25519, …) and the
    attribute name is the algorithm class or factory function.
    Examples:  hashes.SHA256()   algorithms.AES(key)   ec.SECP256R1()
               rsa.generate_private_key(...)   ec.generate_private_key(...)

  Pattern B — pycryptodome / PyCrypto:
    ALGO.method(...)  where the object name is the algorithm (AES, RSA, MD5 …)
    and the method is a recognised factory (new, generate, import_key, …).
    Examples:  AES.new(key, AES.MODE_GCM)   RSA.generate(2048)   MD5.new()

All detection knowledge lives exclusively in rules/python_crypto.yaml.
No algorithm names, OIDs, or patterns are hardcoded in this file.

Hash Patch constraints enforced here:
  - Rules-only: every lookup goes through the YAML index; no `if name == "RSA"`.
  - Evidence: every CryptoAsset carries an Evidence with file, 1-based line,
    column, byte offset, and snippet from the tree-sitter node.
  - Offline / deterministic: no network calls, no uuid4(), no datetime.now().
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

try:
    import tree_sitter_python as _tspy
    from tree_sitter import Language, Parser

    _LANG = Language(_tspy.language())
    _PARSER = Parser(_LANG)
    _TREE_SITTER_AVAILABLE = True
except Exception:  # noqa: BLE001 -- graceful degradation if the native parser fails to load  # pragma: no cover
    _TREE_SITTER_AVAILABLE = False
    _LANG = None  # type: ignore[assignment]
    _PARSER = None  # type: ignore[assignment]

from hash_patch.detect.base import Detector, registry
from hash_patch.model.assets import (
    AssetType,
    CryptoAsset,
    Primitive,
    QuantumStatus,
)
from hash_patch.model.evidence import Evidence

# rules/python_crypto.yaml sits two directories above this file
# layout: hash_patch/detect/python.py → ../../rules/python_crypto.yaml
_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "python_crypto.yaml"

_DETECTOR_ID = "python-crypto"
_DETECTOR_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Rules loading (once per instantiation, not at import time)
# ---------------------------------------------------------------------------


def _load_rules(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _build_pyca_index(rules: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    """Build {namespace -> {AttributeName_upper -> rule}} from pyca_modules."""
    raw: dict[str, dict[str, Any]] = rules.get("pyca_modules", {})
    return {
        ns: {attr.upper(): entry for attr, entry in attrs.items()}
        for ns, attrs in raw.items()
    }


def _build_pycryptodome_index(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build {'ALGO.method' -> rule} from pycryptodome_classes (keys are case-sensitive
    because pycryptodome class names are upper-cased by convention).
    """
    raw: dict[str, dict[str, Any]] = rules.get("pycryptodome_classes", {})
    return {k: v for k, v in raw.items()}


def _build_bare_constructor_index(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build {'ClassName' -> rule} from bare_constructors (case-sensitive,
    exact match — no case-folding, to keep this narrow-surface pattern from
    matching more loosely than it should)."""
    raw: dict[str, dict[str, Any]] = rules.get("bare_constructors", {})
    return {k: v for k, v in raw.items()}


def _build_jwt_algorithm_index(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build {'HS256' -> rule, ...} from jwt_algorithms, uppercased (JWT
    `alg` header values are conventionally uppercase already, but this
    mirrors the same case-insensitive-lookup convention `hashlib`'s table
    uses)."""
    raw: dict[str, dict[str, Any]] = rules.get("jwt_algorithms", {})
    return {k.upper(): v for k, v in raw.items()}


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
# AST traversal
#
# Both patterns produce a tree-sitter node of the shape:
#
#   call
#     attribute          ← obj.attr
#       identifier       ← obj  (e.g. "hashes" or "AES")
#       .
#       identifier       ← attr (e.g. "SHA256" or "new")
#     argument_list
#
# We walk the entire file collecting every such `call` node.
# ---------------------------------------------------------------------------


def _collect_calls(root_node: Any, bare_names: frozenset[str] = frozenset()) -> list[dict[str, Any]]:
    """Walk the AST and return every call node that has an attribute receiver,
    plus (only when `bare_names` is non-empty) every BARE call whose callee
    identifier is a member of `bare_names` — e.g. `Box(sk, pk)` when "Box" is
    in `bare_names`. Callers that omit `bare_names` (the default) get
    EXACTLY the original attribute-call-only behavior — a bare call like
    `print(...)` or `some_function(...)` is never collected, matching every
    existing caller/test of this function unchanged.

    Each entry: {"obj": str, "attr": str, "call_node": Node, "attr_node": Node}
      - obj:       the left-hand identifier text  (e.g. "hashes", "AES")
      - attr:      the right-hand identifier text (e.g. "SHA256",  "new")
      - call_node: the top-level `call` node (for snippet extraction)
      - attr_node: the `attribute` node (for position extraction)
    A bare-call entry instead has {"bare_call": str, "call_node": Node, "attr_node": Node}.
    """
    results: list[dict[str, Any]] = []
    _walk(root_node, results, bare_names)
    return results


# Real-world files with deeply nested expressions can exceed the native C
# thread stack before Python's own RecursionError guard fires reliably —
# and even when RecursionError does fire, it previously propagated
# uncaught through detect() -> run_scan() -> the CLI, aborting the whole
# scan over one pathological file (see docs/REACHABILITY.md's "Deep-nesting
# safety cap" note; `hash_patch/analyze/callgraph.py::_walk_py_calls` and
# `hash_patch/detect/shelf_life/data_context.py::_walk_python_spans` use the
# same explicit-stack pattern for the same reason). `_walk` therefore uses
# an explicit heap-allocated stack instead of function-call recursion, with
# `_MAX_WALK_DEPTH` as defense in depth: a branch deeper than that is simply
# not descended further, which surfaces as "fewer calls found" — the same
# fail-safe shape as any other call this detector cannot resolve — rather
# than crashing or losing evidence for the whole file.
_MAX_WALK_DEPTH = 500


def _walk(node: Any, results: list[dict[str, Any]], bare_names: frozenset[str] = frozenset()) -> None:
    stack: list[tuple[Any, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            continue
        if current.type == "call":
            _try_collect_call(current, results, bare_names)
            # Still recurse: calls can be nested (e.g. algorithm=hashes.SHA256())
        children = current.children
        if children:
            stack.extend((child, depth + 1) for child in reversed(children))


def _first_child_of_type(node: Any, type_name: str) -> Any | None:
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def _positional_or_keyword_arg(call_node: Any, index: int, keyword: str) -> Any | None:
    """Return the `index`-th positional argument of `call_node`'s
    `argument_list`, or the value of a `keyword=...` keyword argument if
    the call used that form instead — whichever the call site actually
    used. None if neither is present (e.g. fewer args than `index`).
    """
    args_node = _first_child_of_type(call_node, "argument_list")
    if args_node is None:
        return None
    pos = 0
    for child in args_node.named_children:
        if child.type == "keyword_argument":
            kw_named = list(child.named_children)
            if len(kw_named) >= 2 and kw_named[0].type == "identifier":
                name_text = kw_named[0].text.decode("utf-8", errors="replace")
                if name_text == keyword:
                    return kw_named[1]
            continue
        if pos == index:
            return child
        pos += 1
    return None


def _string_literal_text(node: Any) -> str | None:
    """Best-effort literal text of a plain quoted string node: strip the
    surrounding quote characters — the same convention
    hash_patch/detect/config/source_tls_intent.py's `visit()` already uses
    for its `string` nodes. A prefixed (`b"..."`, `f"..."`) or otherwise
    non-trivial literal comes back with leftover quote/prefix noise that
    will not match any known algorithm name, so the caller's dict lookup
    naturally fails and the call is skipped — never guessed at.
    """
    if node.type != "string":
        return None
    return node.text.decode("utf-8", errors="replace").strip().strip("\"'")


def _try_collect_call(
    call_node: Any, results: list[dict[str, Any]], bare_names: frozenset[str] = frozenset()
) -> None:
    """If call_node is an attribute-based call, append it to results."""
    # A qualifying call has an `attribute` child as its first named child.
    attr_node: Any | None = None
    for child in call_node.children:
        if child.type == "attribute":
            attr_node = child
            break
    if attr_node is None:
        # No attribute receiver — a BARE call (e.g. `Box(sk, pk)`). Only
        # collected when the callee identifier is one of `bare_names`
        # (PyNaCl's Box/SecretBox/PrivateKey/SigningKey, per
        # rules/python_crypto.yaml's `bare_constructors` table) — anything
        # else (print(...), some_function(...)) is left uncollected exactly
        # as before, per this function's original contract.
        if bare_names and call_node.children and call_node.children[0].type == "identifier":
            id_node = call_node.children[0]
            id_text = id_node.text.decode("utf-8", errors="replace")
            if id_text in bare_names:
                results.append({"bare_call": id_text, "call_node": call_node, "attr_node": id_node})
        return

    # Decompose the attribute node: identifier . identifier
    # Named children of `attribute` are the two identifiers; the dot is unnamed.
    named = list(attr_node.named_children) if hasattr(attr_node, "named_children") else [
        c for c in attr_node.children if c.is_named
    ]
    if len(named) < 2:
        return

    obj_id = named[0].text.decode("utf-8", errors="replace") if named[0].type == "identifier" else None
    attr_id = named[-1].text.decode("utf-8", errors="replace") if named[-1].type == "identifier" else None

    if obj_id is None or attr_id is None:
        return

    if obj_id == "hashlib" and attr_id == "new":
        name_arg = _positional_or_keyword_arg(call_node, index=0, keyword="name")
        literal = _string_literal_text(name_arg) if name_arg is not None else None
        if literal:
            results.append({
                "special_lookup": literal,
                "lookup_table": "hashlib",
                "call_node": call_node,
                "attr_node": name_arg,
                "api": "hashlib.new",
            })
        else:
            results.append({
                "unresolved": True,
                "api": "hashlib.new",
                "call_node": call_node,
                "attr_node": name_arg if name_arg is not None else attr_node,
            })
        return

    if obj_id == "hmac" and attr_id == "new":
        digestmod_arg = _positional_or_keyword_arg(call_node, index=2, keyword="digestmod")
        matched = False
        if digestmod_arg is not None:
            if digestmod_arg.type == "attribute":
                dm_named = list(digestmod_arg.named_children)
                if (
                    len(dm_named) >= 2
                    and dm_named[0].type == "identifier"
                    and dm_named[0].text.decode("utf-8", errors="replace") == "hashlib"
                    and dm_named[-1].type == "identifier"
                ):
                    results.append({
                        "special_lookup": dm_named[-1].text.decode("utf-8", errors="replace"),
                        "lookup_table": "hashlib",
                        "call_node": call_node,
                        "attr_node": digestmod_arg,
                        "api": "hmac.new",
                    })
                    matched = True
            else:
                literal = _string_literal_text(digestmod_arg)
                if literal:
                    results.append({
                        "special_lookup": literal,
                        "lookup_table": "hashlib",
                        "call_node": call_node,
                        "attr_node": digestmod_arg,
                        "api": "hmac.new",
                    })
                    matched = True
        if not matched:
            results.append({
                "unresolved": True,
                "api": "hmac.new",
                "call_node": call_node,
                "attr_node": digestmod_arg if digestmod_arg is not None else attr_node,
            })
        return

    if obj_id == "jwt" and attr_id == "encode":
        algo_arg = _positional_or_keyword_arg(call_node, index=2, keyword="algorithm")
        literal = _string_literal_text(algo_arg) if algo_arg is not None else None
        if literal:
            results.append({
                "special_lookup": literal,
                "lookup_table": "jwt",
                "call_node": call_node,
                "attr_node": algo_arg,
                "api": "jwt.encode",
            })
        else:
            results.append({
                "unresolved": True,
                "api": "jwt.encode",
                "call_node": call_node,
                "attr_node": algo_arg if algo_arg is not None else attr_node,
            })
        return

    results.append({
        "obj": obj_id,
        "attr": attr_id,
        "call_node": call_node,
        "attr_node": attr_node,
    })


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


class PythonCryptoDetector(Detector):
    """Detects PyCA `cryptography` and pycryptodome API calls in Python files.

    All algorithm knowledge is loaded from rules/python_crypto.yaml.
    No algorithm names are hardcoded in this class.
    """

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        rules = _load_rules(_RULES_PATH)
        # Pattern A index: {namespace_lower -> {ATTR_UPPER -> rule}}
        self._pyca: dict[str, dict[str, dict[str, Any]]] = _build_pyca_index(rules)
        # Pattern B index: {"ALGO.method" -> rule}  (case-sensitive keys from YAML)
        self._pycryptodome: dict[str, dict[str, Any]] = _build_pycryptodome_index(rules)
        # Pattern C index: {"ClassName" -> rule} for bare constructor calls
        self._bare_constructors: dict[str, dict[str, Any]] = _build_bare_constructor_index(rules)
        # Pattern D index: {"HS256" -> rule, ...} for jwt.encode(algorithm=...)
        self._jwt_algorithms: dict[str, dict[str, Any]] = _build_jwt_algorithm_index(rules)

    def supports(self, target: Path) -> bool:
        return _TREE_SITTER_AVAILABLE and target.is_file() and target.suffix.lower() == ".py"

    def detect(self, target: Path) -> list[CryptoAsset]:
        """Parse target and return one CryptoAsset per detected unique algorithm.

        Each asset carries Evidence with 1-based line, 0-based column, byte
        offset of the call expression's attribute node, and a snippet of the
        whole call. Multiple call sites for the same logical algorithm are
        merged into a single asset with multiple Evidence entries.
        """
        if not self.supports(target):
            return []

        source_bytes = target.read_bytes()
        tree = _PARSER.parse(source_bytes)  # type: ignore[union-attr]
        calls = _collect_calls(tree.root_node, bare_names=frozenset(self._bare_constructors))

        local: dict[str, CryptoAsset] = {}
        locator = str(target)

        for call in calls:
            confidence: Confidence = "confirmed"
            properties: dict[str, str] = {}
            extra_id_seed: str | None = None
            is_unresolved = call.get("unresolved", False)
            rule = None
            canonical: str | None = None

            if is_unresolved:
                canonical = "UNRESOLVED"
                confidence = "LOW"
                api_name = call.get("api", "crypto.call")
                properties = {
                    "api": api_name,
                    "resolution_path": "null",
                }
                extra_id_seed = api_name
            else:
                special_lookup = call.get("special_lookup")
                bare_call = call.get("bare_call")
                if special_lookup is not None:
                    if call.get("lookup_table") == "jwt":
                        rule = self._jwt_algorithms.get(special_lookup.upper())
                    else:
                        rule = self._pyca.get("hashlib", {}).get(special_lookup.upper())
                    if rule is None:
                        canonical = "UNRESOLVED"
                        confidence = "LOW"
                        api_name = call.get("api", "hashlib.new" if call.get("lookup_table") != "jwt" else "jwt.encode")
                        properties = {
                            "api": api_name,
                            "resolution_path": "null",
                        }
                        extra_id_seed = api_name
                elif bare_call is not None:
                    rule = self._bare_constructors.get(bare_call)
                else:
                    rule = self._match_rule(call["obj"], call["attr"])
                    if rule is None and (call.get("obj") in self._pyca):
                        canonical = "UNRESOLVED"
                        confidence = "LOW"
                        api_name = f"{call['obj']}.{call['attr']}"
                        properties = {
                            "api": api_name,
                            "resolution_path": "null",
                        }
                        extra_id_seed = api_name

            if rule is None and canonical != "UNRESOLVED":
                continue

            if canonical != "UNRESOLVED":
                assert rule is not None
                canonical = rule["canonical"]
                primitive = _primitive_from_str(rule.get("primitive"))
                parameter_set: str | None = rule.get("parameter_set")
                quantum_status = _quantum_status_from_str(rule.get("quantum_status"))
                oid: str | None = rule.get("oid")
            else:
                primitive = Primitive.UNKNOWN
                parameter_set = None
                quantum_status = QuantumStatus.UNKNOWN
                oid = None

            # Use the attribute node for position (it pinpoints the algo name).
            attr_node = call["attr_node"]
            call_node = call["call_node"]
            line = attr_node.start_point.row + 1       # 1-based
            column = attr_node.start_point.column      # 0-based
            byte_offset = attr_node.start_byte
            snippet = call_node.text.decode("utf-8", errors="replace")

            evidence = Evidence(
                source_type="source",
                locator=locator,
                line=line,
                column=column,
                byte_offset=byte_offset,
                snippet=snippet,
                detector_id=_DETECTOR_ID,
                detector_version=_DETECTOR_VERSION,
            )

            asset = CryptoAsset.create(
                asset_type=AssetType.ALGORITHM,
                name=canonical,
                primitive=primitive,
                parameter_set=parameter_set,
                mode=None,
                quantum_status=quantum_status,
                oid=oid,
                confidence=confidence,
                properties=properties,
                extra_id_seed=extra_id_seed,
                evidence=[evidence],
            )

            asset_id = asset.id
            if asset_id in local:
                existing = local[asset_id]
                seen = {e.key() for e in existing.evidence}
                if evidence.key() not in seen:
                    existing.evidence.append(evidence)
            else:
                local[asset_id] = asset

        for asset in local.values():
            asset.evidence.sort(key=lambda e: e.key())

        return sorted(local.values(), key=lambda a: a.id)

    # ------------------------------------------------------------------
    # Rule matching — two patterns, all driven by YAML, no names in code
    # ------------------------------------------------------------------

    def _match_rule(self, obj: str, attr: str) -> dict[str, Any] | None:
        """Return a rule entry or None.

        Pattern A: obj is a PyCA namespace (case-sensitive match on namespace,
                   case-insensitive match on attribute).
        Pattern B: "obj.attr" matches a pycryptodome_classes key exactly.
        """
        # Pattern A: PyCA namespace lookup
        ns_attrs = self._pyca.get(obj)   # namespace is lower-case in practice
        if ns_attrs is not None:
            entry = ns_attrs.get(attr.upper())
            if entry is not None:
                return entry

        # Pattern B: pycryptodome class.method key (exact case from YAML)
        key = f"{obj}.{attr}"
        entry = self._pycryptodome.get(key)
        if entry is not None:
            return entry

        return None


# ---------------------------------------------------------------------------
# Self-register into the shared registry when this module is imported.
# ---------------------------------------------------------------------------
registry.register(PythonCryptoDetector())
