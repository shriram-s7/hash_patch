"""pratyaksha/detect/python.py — Python crypto-library detector.

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

PRATYAKSHA constraints enforced here:
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

from pratyaksha.detect.base import Detector, registry
from pratyaksha.model.assets import (
    AssetType,
    CryptoAsset,
    Primitive,
    QuantumStatus,
)
from pratyaksha.model.evidence import Evidence

# rules/python_crypto.yaml sits two directories above this file
# layout: pratyaksha/detect/python.py → ../../rules/python_crypto.yaml
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


def _collect_calls(root_node: Any) -> list[dict[str, Any]]:
    """Walk the AST and return every call node that has an attribute receiver.

    Each entry: {"obj": str, "attr": str, "call_node": Node, "attr_node": Node}
      - obj:       the left-hand identifier text  (e.g. "hashes", "AES")
      - attr:      the right-hand identifier text (e.g. "SHA256",  "new")
      - call_node: the top-level `call` node (for snippet extraction)
      - attr_node: the `attribute` node (for position extraction)
    """
    results: list[dict[str, Any]] = []
    _walk(root_node, results)
    return results


def _walk(node: Any, results: list[dict[str, Any]]) -> None:
    if node.type == "call":
        _try_collect_call(node, results)
        # Still recurse: calls can be nested (e.g. algorithm=hashes.SHA256())
    for child in node.children:
        _walk(child, results)


def _try_collect_call(call_node: Any, results: list[dict[str, Any]]) -> None:
    """If call_node is an attribute-based call, append it to results."""
    # A qualifying call has an `attribute` child as its first named child.
    attr_node: Any | None = None
    for child in call_node.children:
        if child.type == "attribute":
            attr_node = child
            break
    if attr_node is None:
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
        calls = _collect_calls(tree.root_node)

        local: dict[str, CryptoAsset] = {}
        locator = str(target)

        for call in calls:
            rule = self._match_rule(call["obj"], call["attr"])
            if rule is None:
                continue

            canonical: str = rule["canonical"]
            primitive = _primitive_from_str(rule.get("primitive"))
            parameter_set: str | None = rule.get("parameter_set")
            quantum_status = _quantum_status_from_str(rule.get("quantum_status"))
            oid: str | None = rule.get("oid")

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
