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
from hash_patch.model.assets import (
    AssetType,
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
        call_node: Node
        fn_node: Node
    """
    results: list[dict[str, Any]] = []
    _walk(root_node, results)
    return results


def _walk(node: Any, results: list[dict[str, Any]]) -> None:
    if node.type == "call_expression":
        _try_collect(node, results)
    for child in node.children:
        _walk(child, results)


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
            parts = [c for c in fn_node.children if c.type in ("identifier", "field_identifier")]
            if len(parts) >= 2:
                operand, field = parts[0], parts[1]

        if operand and field:
            op_text = operand.text.decode("utf-8", errors="replace")
            field_text = field.text.decode("utf-8", errors="replace")
            results.append({
                "target": f"{op_text}.{field_text}",
                "call_node": call_node,
                "fn_node": fn_node,
            })


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

        for call in calls:
            target_func = call["target"]
            rule = self._functions.get(target_func)
            if rule is None:
                continue

            canonical: str = rule["canonical"]
            primitive = _primitive_from_str(rule.get("primitive"))
            parameter_set: str | None = rule.get("parameter_set")
            mode: str | None = rule.get("mode")
            quantum_status = _quantum_status_from_str(rule.get("quantum_status"))
            oid: str | None = rule.get("oid")

            fn_node = call["fn_node"]
            call_node = call["call_node"]
            line = fn_node.start_point.row + 1
            column = fn_node.start_point.column
            byte_offset = fn_node.start_byte
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
registry.register(GoCryptoDetector())
