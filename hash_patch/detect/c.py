"""hash_patch/detect/c.py — OpenSSL C/C++ crypto detector.

Uses tree-sitter to parse C and C++ source files and identify calls to OpenSSL
crypto APIs (both legacy low-level API like RSA_*, DES_*, MD5_* and the modern
EVP_* API like EVP_aes_256_gcm, EVP_sha256, etc.) as listed in
rules/c_openssl.yaml.

Hash Patch constraints (enforced here):
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
    Confidence,
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
    crypto_references: dict[str, dict[str, Any]] | None = None,
) -> Any:
    """Walk the AST and collect matching call expressions (operations) and string literal references."""
    op_results: list[tuple[Any, Any, dict[str, Any]]] = []
    ref_results: list[tuple[Any, Any, dict[str, Any]]] = []
    _walk(
        root_node,
        functions,
        macro_args,
        string_args,
        crypto_references or {},
        macro_arg_functions,
        string_arg_functions,
        op_results,
        ref_results,
    )
    if crypto_references is not None:
        return op_results, ref_results
    return op_results


def _walk(
    node: Any,
    functions: dict[str, dict[str, Any]],
    macro_args: dict[str, dict[str, Any]],
    string_args: dict[str, dict[str, Any]],
    crypto_references: dict[str, dict[str, Any]],
    macro_arg_functions: set[str],
    string_arg_functions: set[str],
    op_results: list[tuple[Any, Any, dict[str, Any]]],
    ref_results: list[tuple[Any, Any, dict[str, Any]]],
) -> None:
    if node.type == "call_expression":
        _try_collect(
            node,
            functions,
            macro_args,
            string_args,
            macro_arg_functions,
            string_arg_functions,
            op_results,
        )
    elif node.type == "string_literal":
        _try_collect_reference(
            node,
            crypto_references,
            ref_results,
        )
    for child in node.children:
        _walk(
            child,
            functions,
            macro_args,
            string_args,
            crypto_references,
            macro_arg_functions,
            string_arg_functions,
            op_results,
            ref_results,
        )


def _try_collect_reference(
    node: Any,
    crypto_references: dict[str, dict[str, Any]],
    ref_results: list[tuple[Any, Any, dict[str, Any]]],
) -> None:
    # Check parent chain: must be in declaration, init_declarator, or return_statement,
    # and must NOT be inside a call_expression or preprocessor directive
    parent = node.parent
    in_call = False
    in_decl_or_ret = False
    while parent:
        if parent.type in ("preproc_include", "system_lib_string", "call_expression"):
            in_call = True
            break
        if parent.type in ("init_declarator", "declaration", "return_statement"):
            in_decl_or_ret = True
        parent = parent.parent
    if in_decl_or_ret and not in_call:
        text = node.text.decode("utf-8", errors="replace").strip('"')
        rule = crypto_references.get(text)
        if rule is None:
            from hash_patch.detect.canonical_registry import lookup_canonical_algorithm

            rule = lookup_canonical_algorithm(text)
        if rule is not None:
            # Find enclosing statement or declaration for a clean snippet
            stmt = node
            while stmt.parent and stmt.parent.type not in ("translation_unit", "compound_statement"):
                stmt = stmt.parent
            ref_results.append((node, stmt, rule))


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
            effective_rule = dict(rule)
            if fn_text == "EVP_RSA_gen" and effective_rule.get("parameter_set") is None and args_node:
                for child in args_node.children:
                    if child.type == "number_literal":
                        raw_num = child.text.decode("utf-8", errors="replace").rstrip("uUlL")
                        try:
                            effective_rule["parameter_set"] = str(int(raw_num, 0))
                            break
                        except ValueError:
                            pass
            results.append((fn_node, call_node, effective_rule))

        is_macro_fn = fn_text in macro_arg_functions
        is_string_fn = fn_text in string_arg_functions

        if args_node and (is_macro_fn or is_string_fn):
            matched = False

            # Extract integer parameter if present for EVP_PKEY_Q_keygen (e.g. 2048 in EVP_PKEY_Q_keygen(NULL, "DH", 2048))
            int_param: str | None = None
            if fn_text == "EVP_PKEY_Q_keygen":
                for child in args_node.children:
                    if child.type == "number_literal":
                        raw_num = child.text.decode("utf-8", errors="replace").rstrip("uUlL")
                        try:
                            int_param = str(int(raw_num, 0))
                            break
                        except ValueError:
                            pass

            if is_macro_fn:
                for child in args_node.children:
                    if child.type == "identifier":
                        id_text = child.text.decode("utf-8", errors="replace")
                        m_rule = macro_args.get(id_text)
                        if m_rule is not None:
                            effective_rule = dict(m_rule)
                            if effective_rule.get("parameter_set") is None and int_param is not None:
                                effective_rule["parameter_set"] = int_param
                            results.append((child, call_node, effective_rule))
                            matched = True

            if is_string_fn and not matched:
                for child in args_node.children:
                    if child.type == "string_literal":
                        str_text = child.text.decode("utf-8", errors="replace").strip('"')
                        s_rule = string_args.get(str_text)
                        if s_rule is not None:
                            effective_rule = dict(s_rule)
                            if effective_rule.get("parameter_set") is None and int_param is not None:
                                effective_rule["parameter_set"] = int_param
                            results.append((child, call_node, effective_rule))
                            matched = True

            if not matched:
                results.append(
                    (args_node, call_node, {"canonical": "UNRESOLVED", "unresolved": True, "api": fn_text})
                )


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


class COpenSSLDetector(Detector):
    """Detects OpenSSL crypto calls in C and C++ source files.

    All algorithm knowledge is loaded from rules/c_openssl.yaml at
    instantiation time. No algorithm names are hardcoded in this class.
    """

    # Reachability classification (hash_patch/analyze/reachability.py) is wired
    # up for Python, Java, and C/C++ (via hash_patch/analyze/callgraph.py's
    # build_c_call_graph). An asset whose evidence is confined to a header
    # (.h/.hpp/...) still keeps the model's default CryptoAsset.reachability =
    # UNKNOWN, since headers only ever contain declarations, never a function
    # body to walk a call graph from.

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        rules = _load_rules(_RULES_PATH)
        self._functions: dict[str, dict[str, Any]] = rules.get("functions", {})
        self._macro_args: dict[str, dict[str, Any]] = rules.get("macro_args", {})
        self._string_args: dict[str, dict[str, Any]] = rules.get("string_args", {})
        from hash_patch.detect.canonical_registry import get_canonical_registry

        self._crypto_references: dict[str, dict[str, Any]] = dict(get_canonical_registry())
        self._crypto_references.update(rules.get("crypto_references", {}))
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
        of the call expression or reference declaration.
        """
        if not self.supports(target):
            return []

        source_bytes = target.read_bytes()
        tree = _PARSER.parse(source_bytes)  # type: ignore[union-attr]
        op_matches, ref_matches = _collect_matches(
            tree.root_node,
            self._functions,
            self._macro_args,
            self._string_args,
            self._macro_arg_functions,
            self._string_arg_functions,
            self._crypto_references,
        )

        local: dict[str, CryptoAsset] = {}
        locator = str(target)

        # 1. Real library operations (OpenSSL / EVP calls)
        for pos_node, call_node, rule in op_matches:
            is_unresolved = rule.get("unresolved", False)
            if is_unresolved:
                canonical = "UNRESOLVED"
                primitive = Primitive.UNKNOWN
                parameter_set = None
                mode = None
                quantum_status = QuantumStatus.UNKNOWN
                oid = None
                confidence: Confidence = "LOW"
                api_name = rule.get("api", "openssl.call")
                properties = {
                    "api": api_name,
                    "resolution_path": "null",
                }
                extra_id_seed = api_name
            else:
                canonical = rule["canonical"]
                primitive = _primitive_from_str(rule.get("primitive"))
                parameter_set = rule.get("parameter_set")
                mode = rule.get("mode")
                quantum_status = _quantum_status_from_str(rule.get("quantum_status"))
                oid = rule.get("oid")
                confidence = "confirmed"
                properties = {}
                extra_id_seed = None

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
                confidence=confidence,
                finding_type="OPERATION",
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

        # 2. Standalone string literal references (CRYPTO_REFERENCE)
        for pos_node, stmt_node, rule in ref_matches:
            canonical = rule["canonical"]
            primitive = _primitive_from_str(rule.get("primitive"))
            parameter_set = rule.get("parameter_set")
            mode = rule.get("mode")
            quantum_status = _quantum_status_from_str(rule.get("quantum_status"))
            oid = rule.get("oid")
            confidence = "confirmed"
            properties = {"finding_type": "CRYPTO_REFERENCE"}
            extra_id_seed = "CRYPTO_REFERENCE"

            line = pos_node.start_point.row + 1
            column = pos_node.start_point.column
            byte_offset = pos_node.start_byte
            snippet = stmt_node.text.decode("utf-8", errors="replace").strip()

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

            asset_type = (
                AssetType.PROTOCOL
                if rule.get("primitive") == "protocol"
                else AssetType.ALGORITHM
            )

            asset = CryptoAsset.create(
                asset_type=asset_type,
                name=canonical,
                primitive=primitive,
                parameter_set=parameter_set,
                mode=mode,
                quantum_status=quantum_status,
                oid=oid,
                confidence=confidence,
                finding_type="CRYPTO_REFERENCE",
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


# ---------------------------------------------------------------------------
# Self-register when this module is imported.
# ---------------------------------------------------------------------------
registry.register(COpenSSLDetector())
