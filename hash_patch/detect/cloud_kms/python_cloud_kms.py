"""hash_patch/detect/cloud_kms/python_cloud_kms.py — Python cloud KMS/HSM
client-side usage detector. See hash_patch/detect/cloud_kms/__init__.py for
the full scope and honesty framing.

Two-pass, same-file matching (mirrors hash_patch/analyze/shelf_life's own
"no cross-function/cross-file tracing" restraint):
  1. Find every local variable or instance attribute assigned directly from
     a call matching a known client-constructor shape (rules/cloud_kms.yaml's
     python section) — never a finding by itself. Both `client = boto3...`
     and `self.kms_client = boto3...` are tracked; the attribute's exact
     dotted name (e.g. `self.kms_client`) is what the operation pass looks
     up again on `<that name>.<operation>(...)` calls.
  2. Find every `<that variable/attribute>.<operation>(...)` call, where
     `<operation>` is in the shared operations list — THIS is the finding. A
     client constructed but never used for a real operation produces
     nothing, the same reference-vs-operation discipline every other
     detector follows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hash_patch.detect.base import Detector, registry
from hash_patch.detect.cloud_kms._rules import load_cloud_kms_rules
from hash_patch.detect.python import _PARSER as _PY_PARSER
from hash_patch.detect.python import _TREE_SITTER_AVAILABLE as _PY_TREE_SITTER_AVAILABLE
from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, QuantumStatus
from hash_patch.model.evidence import Evidence

_DETECTOR_ID = "python-cloud-kms"
_DETECTOR_VERSION = "0.1.0"


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


def _string_literal_text(node: Any) -> str | None:
    if node is None or node.type != "string":
        return None
    for c in node.children:
        if c.type == "string_content":
            return _text(c)
    return None


class PythonCloudKmsDetector(Detector):
    """Detects boto3 (AWS KMS), google-cloud-kms, and azure-keyvault-keys
    client construction + operation calls in Python source files.
    """

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        rules = load_cloud_kms_rules()
        self._constructors: list[dict[str, Any]] = rules.get("python", {}).get("client_constructors", [])
        self._operations: set[str] = set(rules.get("operations", []))

    def supports(self, target: Path) -> bool:
        return _PY_TREE_SITTER_AVAILABLE and target.is_file() and target.suffix.lower() == ".py"

    def detect(self, target: Path) -> list[CryptoAsset]:
        if not self.supports(target):
            return []
        try:
            source = target.read_bytes()
        except OSError:
            return []

        tree = _PY_PARSER.parse(source)  # type: ignore[union-attr]
        locator = str(target)

        client_vars: dict[str, tuple[str, str]] = {}
        self._collect_client_vars(tree.root_node, client_vars)
        if not client_vars:
            return []

        assets: dict[str, CryptoAsset] = {}
        self._collect_operations(tree.root_node, client_vars, locator, assets)
        return sorted(assets.values(), key=lambda a: a.id)

    def _collect_client_vars(self, node: Any, out: dict[str, tuple[str, str]]) -> None:
        # Iterative DFS (mirrors java_cloud_kms.py / go_cloud_kms.py): the
        # deeply-nested-expression corpus fixture used by the tree-sitter
        # crash-regression test exceeds Python's default recursion limit, so
        # a recursive walk would crash on it; a plain stack never does.
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 500:
                continue
            if current.type == "assignment":
                left = current.child_by_field_name("left")
                right = current.child_by_field_name("right")
                if (
                    left is not None
                    and left.type in ("identifier", "attribute")
                    and right is not None
                    and right.type == "call"
                ):
                    match = self._match_constructor(right)
                    if match is not None:
                        out[_text(left)] = match
            stack.extend((child, depth + 1) for child in reversed(current.children))

    def _match_constructor(self, call_node: Any) -> tuple[str, str] | None:
        fn_node = call_node.child_by_field_name("function")
        if fn_node is None:
            return None
        fn_text = _text(fn_node)
        args_node = call_node.child_by_field_name("arguments")
        for ctor in self._constructors:
            if ctor["match"] != fn_text:
                continue
            required_lit = ctor.get("first_arg_literal")
            if required_lit is not None:
                if args_node is None:
                    continue
                first_args = list(args_node.named_children)
                if not first_args or _string_literal_text(first_args[0]) != required_lit:
                    continue
            return (ctor["provider"], ctor["sdk"])
        return None

    def _collect_operations(
        self,
        node: Any,
        client_vars: dict[str, tuple[str, str]],
        locator: str,
        assets: dict[str, CryptoAsset],
    ) -> None:
        # Iterative DFS — same rationale as _collect_client_vars.
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 500:
                continue
            if current.type == "call":
                fn_node = current.child_by_field_name("function")
                if fn_node is not None and fn_node.type == "attribute":
                    named = [c for c in fn_node.children if c.is_named]
                    if len(named) >= 2:
                        obj = ".".join(_text(c) for c in named[:-1])
                        attr = _text(named[-1])
                        if obj in client_vars and attr in self._operations:
                            provider, sdk = client_vars[obj]
                            self._emit(current, named[-1], provider, sdk, attr, locator, assets)
            stack.extend((child, depth + 1) for child in reversed(current.children))

    def _emit(
        self,
        call_node: Any,
        attr_node: Any,
        provider: str,
        sdk: str,
        operation: str,
        locator: str,
        assets: dict[str, CryptoAsset],
    ) -> None:
        evidence = Evidence(
            source_type="source",
            locator=locator,
            line=attr_node.start_point[0] + 1,
            column=attr_node.start_point[1],
            byte_offset=attr_node.start_byte,
            snippet=_text(call_node),
            detector_id=_DETECTOR_ID,
            detector_version=_DETECTOR_VERSION,
        )
        asset = CryptoAsset.create(
            asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
            name=f"{provider.upper()} KMS {operation}",
            primitive=Primitive.OTHER,
            quantum_status=QuantumStatus.ALGORITHM_OPAQUE,
            confidence="confirmed",
            finding_type="CLOUD_KEY_OPERATION",
            properties={
                "cloudKey.provider": provider,
                "cloudKey.sdk": sdk,
                "cloudKey.operation": operation,
                "cloudKey.verificationScope": "client_call_only",
            },
            extra_id_seed=f"{provider}:{operation}",
            evidence=[evidence],
        )
        if asset.id in assets:
            existing = assets[asset.id]
            seen = {e.key() for e in existing.evidence}
            if evidence.key() not in seen:
                existing.evidence.append(evidence)
        else:
            assets[asset.id] = asset


registry.register(PythonCloudKmsDetector())
