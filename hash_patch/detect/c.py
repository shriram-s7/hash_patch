"""hash_patch/detect/c.py — OpenSSL C/C++ crypto detector.

Uses tree-sitter to parse C and C++ source files and identify calls to OpenSSL
crypto APIs (both legacy low-level API like RSA_*, DES_*, MD5_* and the modern
EVP_* API like EVP_aes_256_gcm, EVP_sha256, etc.) as listed in
rules/c_openssl.yaml.

PRATYAKSHA constraints (enforced here):
  - No algorithm names, OIDs, or patterns hardcoded in this file — all
    detection knowledge comes exclusively from rules/c_openssl.yaml.
  - Every CryptoAsset is backed by at least one Evidence with file, line,
    column, byte offset, and snippet populated from the tree-sitter node.
  - No network calls, no uuid4(), no datetime.now() on the detection path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

try:
    import tree_sitter_c as _tsc
    from tree_sitter import Language, Parser

    _LANG = Language(_tsc.language())
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

# Locate the rules file relative to this source file.
# layout:  hash_patch/detect/c.py  →  ../../rules/c_openssl.yaml
_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "c_openssl.yaml"

_DETECTOR_ID = "c-openssl"
_DETECTOR_VERSION = "0.1.0"

_SUPPORTED_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh"})


# ---------------------------------------------------------------------------
# Rules loading
# ---------------------------------------------------------------------------


def _load_rules(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


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


def _collect_matches(
    root_node: Any,
    functions: dict[str, dict[str, Any]],
    macro_args: dict[str, dict[str, Any]],
    string_args: dict[str, dict[str, Any]],
    macro_arg_functions: set[str],
    string_arg_functions: set[str],
) -> list[tuple[Any, Any, dict[str, Any]]]:
    """Walk the AST and collect all matching call expressions.

    Returns a list of tuples:
        (position_node, call_node, rule_dict)
    """
    results: list[tuple[Any, Any, dict[str, Any]]] = []
    _walk(
        root_node,
        functions,
        macro_args,
        string_args,
        macro_arg_functions,
        string_arg_functions,
        results,
    )
    return results


def _walk(
    node: Any,
    functions: dict[str, dict[str, Any]],
    macro_args: dict[str, dict[str, Any]],
    string_args: dict[str, dict[str, Any]],
    macro_arg_functions: set[str],
    string_arg_functions: set[str],
    results: list[tuple[Any, Any, dict[str, Any]]],
) -> None:
    if node.type == "call_expression":
        _try_collect(
            node,
            functions,
            macro_args,
            string_args,
            macro_arg_functions,
            string_arg_functions,
            results,
        )
    for child in node.children:
        _walk(
            child,
            functions,
            macro_args,
            string_args,
            macro_arg_functions,
            string_arg_functions,
            results,
        )


def _try_collect(
    call_node: Any,
    functions: dict[str, dict[str, Any]],
    macro_args: dict[str, dict[str, Any]],
    string_args: dict[str, dict[str, Any]],
    macro_arg_functions: set[str],
    string_arg_functions: set[str],
    results: list[tuple[Any, Any, dict[str, Any]]],
) -> None:
    fn_node = call_node.child_by_field_name("function")
    args_node = call_node.child_by_field_name("arguments")

    if fn_node:
        fn_text = fn_node.text.decode("utf-8", errors="replace")
        rule = functions.get(fn_text)
        if rule is not None:
            results.append((fn_node, call_node, rule))

        if args_node:
            if fn_text in macro_arg_functions:
                for child in args_node.children:
                    if child.type == "identifier":
                        id_text = child.text.decode("utf-8", errors="replace")
                        m_rule = macro_args.get(id_text)
                        if m_rule is not None:
                            results.append((child, call_node, m_rule))

            if fn_text in string_arg_functions:
                for child in args_node.children:
                    if child.type == "string_literal":
                        str_text = child.text.decode("utf-8", errors="replace").strip('"')
                        s_rule = string_args.get(str_text)
                        if s_rule is not None:
                            results.append((child, call_node, s_rule))


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


class COpenSSLDetector(Detector):
    """Detects OpenSSL crypto calls in C and C++ source files.

    All algorithm knowledge is loaded from rules/c_openssl.yaml at
    instantiation time. No algorithm names are hardcoded in this class.
    """

    # Reachability classification (hash_patch/analyze/reachability.py) is only
    # wired up for Python and Java; C is out of scope for now, so assets from
    # this detector keep the model's default CryptoAsset.reachability = UNKNOWN
    # rather than risk a wrong (unsafe) classification from an unbuilt call graph.

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        rules = _load_rules(_RULES_PATH)
        self._functions: dict[str, dict[str, Any]] = rules.get("functions", {})
        self._macro_args: dict[str, dict[str, Any]] = rules.get("macro_args", {})
        self._string_args: dict[str, dict[str, Any]] = rules.get("string_args", {})
        self._macro_arg_functions: set[str] = set(rules.get("macro_arg_functions", []))
        self._string_arg_functions: set[str] = set(rules.get("string_arg_functions", []))

    def supports(self, target: Path) -> bool:
        """Return True for C/C++ source/header files (when tree-sitter is available)."""
        return (
            _TREE_SITTER_AVAILABLE
            and target.is_file()
            and target.suffix.lower() in _SUPPORTED_EXTENSIONS
        )

    def detect(self, target: Path) -> list[CryptoAsset]:
        """Parse target and return one CryptoAsset per unique detected algorithm.

        Each asset carries Evidence with file path, 1-based line number,
        0-based column, byte offset of the target node, and a snippet
        of the call expression.
        """
        if not self.supports(target):
            return []

        source_bytes = target.read_bytes()
        tree = _PARSER.parse(source_bytes)  # type: ignore[union-attr]
        matches = _collect_matches(
            tree.root_node,
            self._functions,
            self._macro_args,
            self._string_args,
            self._macro_arg_functions,
            self._string_arg_functions,
        )

        local: dict[str, CryptoAsset] = {}
        locator = str(target)

        for pos_node, call_node, rule in matches:
            canonical: str = rule["canonical"]
            primitive = _primitive_from_str(rule.get("primitive"))
            parameter_set: str | None = rule.get("parameter_set")
            mode: str | None = rule.get("mode")
            quantum_status = _quantum_status_from_str(rule.get("quantum_status"))
            oid: str | None = rule.get("oid")

            line = pos_node.start_point.row + 1
            column = pos_node.start_point.column
            byte_offset = pos_node.start_byte
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
                mode=mode,
                quantum_status=quantum_status,
                oid=oid,
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


# ---------------------------------------------------------------------------
# Self-register when this module is imported.
# ---------------------------------------------------------------------------
registry.register(COpenSSLDetector())
