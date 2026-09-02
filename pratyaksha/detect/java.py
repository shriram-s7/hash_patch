"""pratyaksha/detect/java.py — Java JCA/JCE crypto-call detector.

Uses tree-sitter to parse Java source files and identify calls to JCA/JCE
factory methods (Cipher.getInstance, MessageDigest.getInstance, etc.) and
BouncyCastle equivalents listed in rules/java_jca.yaml.

PRATYAKSHA constraints (enforced here):
  - No algorithm names, OIDs, or patterns hardcoded in this file — all
    detection knowledge comes exclusively from rules/java_jca.yaml.
  - Every CryptoAsset is backed by at least one Evidence with file, line,
    column, byte offset, and snippet populated from the tree-sitter node.
  - No network calls, no uuid4(), no datetime.now() on the detection path.
"""

from __future__ import annotations

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

from pratyaksha.detect.base import Detector, registry
from pratyaksha.model.assets import (
    AssetType,
    CryptoAsset,
    Primitive,
    QuantumStatus,
)
from pratyaksha.model.evidence import Evidence

# Locate the rules file relative to this source file.
# layout:  pratyaksha/detect/java.py  →  ../../rules/java_jca.yaml
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


def _build_algo_index(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return a dict keyed by UPPERCASE algorithm name → rule entry."""
    raw: dict[str, dict[str, Any]] = rules.get("algorithms", {})
    return {name.upper(): entry for name, entry in raw.items()}


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


def _collect_jca_calls(root_node: Any) -> list[dict[str, Any]]:
    """Walk the AST and collect all method_invocation nodes of interest.

    Returns a list of dicts with keys:
        class_name, method_name, algo_raw, node, algo_node
    where ``node`` is the method_invocation node and ``algo_node`` is the
    first string_literal in the argument_list (the algorithm argument).

    Only calls whose first argument is a string literal are returned — calls
    where the algorithm is a variable reference are not detectable without
    data-flow analysis and are deliberately excluded to avoid false positives.
    """
    results: list[dict[str, Any]] = []
    _walk(root_node, results)
    return results


# Uses an explicit heap-allocated stack instead of function-call recursion —
# same rationale and pattern as
# `pratyaksha/detect/python.py::_walk` /
# `pratyaksha/analyze/callgraph.py::_walk_py_calls` /
# `pratyaksha/detect/shelf_life/data_context.py::_walk_python_spans`: a
# deeply nested real file can exceed the native C thread stack, and even a
# clean RecursionError previously propagated uncaught through detect() and
# aborted the whole scan over one pathological file. `_MAX_WALK_DEPTH` is
# defense in depth — a branch deeper than that is simply not descended
# further, the same fail-safe shape as any other call this detector cannot
# resolve.
_MAX_WALK_DEPTH = 500


def _walk(node: Any, results: list[dict[str, Any]]) -> None:
    """Iterative DFS walk that collects matching method_invocation nodes."""
    stack: list[tuple[Any, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            continue
        if current.type == "method_invocation":
            _try_collect(current, results)
            # Still recurse into children — a method invocation can itself be
            # an argument to another call (e.g. Cipher.getInstance(getAlgo())).
        children = current.children
        if children:
            stack.extend((child, depth + 1) for child in reversed(children))


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

    # Find the first string_literal in the argument list (the algorithm arg).
    string_literals = [c for c in arglist_node.children if c.type == "string_literal"]
    if not string_literals:
        return  # algorithm passed as variable — skip

    algo_node = string_literals[0]
    algo_raw = _extract_string_fragment(algo_node)
    if not algo_raw:
        return  # empty string literal

    results.append(
        {
            "class_name": class_node.text.decode("utf-8", errors="replace"),
            "method_name": method_node.text.decode("utf-8", errors="replace"),
            "algo_raw": algo_raw,
            "node": node,
            "algo_node": algo_node,
        }
    )


# ---------------------------------------------------------------------------
# Algorithm normalisation and lookup (rules-driven, no hardcoded names)
# ---------------------------------------------------------------------------


def _lookup_algo(algo_raw: str, index: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]] | None:
    """Return (canonical_name, rule_entry) or None if not in rules.

    Normalisation steps (all driven by the index, not hardcoded names):
    1. Exact uppercase match.
    2. Strip everything after the first "/" (transformation-string suffix).
    3. Strip everything after "With" (compound signature algo, e.g.
       "SHA256WithRSAEncryption") — try both halves in order: right-of-With
       first (the signing algorithm), then left-of-With.
    """
    # Step 1: exact uppercase
    key = algo_raw.upper()
    if key in index:
        return algo_raw, index[key]

    # Step 2: strip "/" suffix  (e.g. "AES/GCM/NoPadding" → "AES")
    slash_key = key.split("/")[0]
    if slash_key != key and slash_key in index:
        return slash_key, index[slash_key]

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
        calls = _collect_jca_calls(tree.root_node)

        # Accumulate assets by id so that multiple call sites for the same
        # algorithm merge their evidence (via ScanResult.add_asset semantics).
        # Here we build a local dict first; the caller (cli.scan) uses
        # result.add_asset() which handles cross-file dedup.
        local: dict[str, CryptoAsset] = {}

        locator = str(target)

        for call in calls:
            qualified = f"{call['class_name']}.{call['method_name']}"
            if qualified not in self._targets:
                continue  # not a JCA target method

            algo_raw: str = call["algo_raw"]
            lookup = _lookup_algo(algo_raw, self._algo_index)
            if lookup is None:
                continue  # algorithm not in our rules — skip silently

            canonical_name, rule = lookup
            primitive = _primitive_from_str(rule.get("primitive"))
            parameter_set: str | None = rule.get("parameter_set")
            quantum_status = _quantum_status_from_str(rule.get("quantum_status"))
            oid: str | None = rule.get("oid")

            algo_node = call["algo_node"]
            inv_node = call["node"]
            # line is 0-based in tree-sitter; convert to 1-based for humans.
            line = algo_node.start_point.row + 1
            column = algo_node.start_point.column
            byte_offset = algo_node.start_byte
            snippet = inv_node.text.decode("utf-8", errors="replace")

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

            # Derive the asset id from identity fields (deterministic, no uuid4).
            asset = CryptoAsset.create(
                asset_type=AssetType.ALGORITHM,
                name=canonical_name,
                primitive=primitive,
                parameter_set=parameter_set,
                mode=None,
                quantum_status=quantum_status,
                oid=oid,
                evidence=[evidence],
            )

            asset_id = asset.id
            if asset_id in local:
                # Merge additional evidence into the existing asset.
                existing = local[asset_id]
                seen_keys = {e.key() for e in existing.evidence}
                if evidence.key() not in seen_keys:
                    existing.evidence.append(evidence)
            else:
                local[asset_id] = asset

        # Sort evidence within each asset for determinism.
        for asset in local.values():
            asset.evidence.sort(key=lambda e: e.key())

        # Return assets sorted by id for deterministic ordering.
        return sorted(local.values(), key=lambda a: a.id)


# ---------------------------------------------------------------------------
# Self-register when this module is imported.
# ---------------------------------------------------------------------------
registry.register(JavaJcaDetector())
