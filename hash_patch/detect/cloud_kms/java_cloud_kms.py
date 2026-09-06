"""hash_patch/detect/cloud_kms/java_cloud_kms.py — Java cloud KMS/HSM
client-side usage detector. See hash_patch/detect/cloud_kms/__init__.py for
the full scope and honesty framing.

Two-pass, same-file matching (mirrors
hash_patch/detect/cloud_kms/python_cloud_kms.py's discipline):
  1. Find every variable/field/try-with-resources resource whose initializer
     matches a known client-constructor shape by substring
     (rules/cloud_kms.yaml's java section -- Java construction is usually a
     builder/factory chain like `KmsClient.builder()...build()` or
     `KeyManagementServiceClient.create()`, so the constructor name is matched
     against the initializer text, never a single call-node shape) -- never a
     finding by itself.
  2. Find every `<that variable>.<operation>(...)` call, where `<operation>`
     is in the shared operations list -- THIS is the finding. A client
     constructed but never used for a real operation produces nothing, the
     same reference-vs-operation discipline every other detector follows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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
from hash_patch.detect.cloud_kms._rules import load_cloud_kms_rules
from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, QuantumStatus
from hash_patch.model.evidence import Evidence

_DETECTOR_ID = "java-cloud-kms"
_DETECTOR_VERSION = "0.1.0"


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


class JavaCloudKmsDetector(Detector):
    """Detects AWS KMS (aws-sdk-java-v1/v2), google-cloud-kms, and
    azure-keyvault-keys client construction + operation calls in Java source
    files.
    """

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        rules = load_cloud_kms_rules()
        self._constructors: list[dict[str, Any]] = rules.get("java", {}).get("client_constructors", [])
        self._operations: set[str] = set(rules.get("operations", []))

    def supports(self, target: Path) -> bool:
        return _TREE_SITTER_AVAILABLE and target.is_file() and target.suffix.lower() == ".java"

    def detect(self, target: Path) -> list[CryptoAsset]:
        if not self.supports(target):
            return []
        try:
            source = target.read_bytes()
        except OSError:
            return []

        tree = _PARSER.parse(source)  # type: ignore[union-attr]
        locator = str(target)

        client_vars: dict[str, tuple[str, str]] = {}
        self._collect_client_vars(tree.root_node, client_vars)
        if not client_vars:
            return []

        assets: dict[str, CryptoAsset] = {}
        self._collect_operations(tree.root_node, client_vars, locator, assets)
        return sorted(assets.values(), key=lambda a: a.id)

    def _collect_client_vars(self, node: Any, out: dict[str, tuple[str, str]]) -> None:
        # Iterative DFS (same rationale as hash_patch/detect/java.py's
        # `_walk`: a deeply nested real file can exceed the native C
        # thread stack; a branch deeper than _MAX_WALK_DEPTH is not
        # descended further, the same fail-safe shape as elsewhere).
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 500:
                continue
            if current.type == "variable_declarator":
                # local_variable_declaration / field_declaration /
                # enhanced for-loop, all funnel through this node type.
                name = current.child_by_field_name("name")
                value = current.child_by_field_name("value")
                if name is not None and name.type == "identifier" and value is not None:
                    match = self._match_constructor_text(_text(value))
                    if match is not None:
                        out[_text(name)] = match
            elif current.type == "resource":
                # try-with-resources: `try (KmsClient c = ...) { ... }`
                name = current.child_by_field_name("name")
                value = current.child_by_field_name("value")
                if name is not None and name.type == "identifier" and value is not None:
                    match = self._match_constructor_text(_text(value))
                    if match is not None:
                        out[_text(name)] = match
            children = current.children
            if children:
                stack.extend((child, depth + 1) for child in reversed(children))

    def _match_constructor_text(self, initializer_text: str) -> tuple[str, str] | None:
        for ctor in self._constructors:
            if ctor["match"] in initializer_text:
                return (ctor["provider"], ctor["sdk"])
        return None

    def _collect_operations(
        self,
        node: Any,
        client_vars: dict[str, tuple[str, str]],
        locator: str,
        assets: dict[str, CryptoAsset],
    ) -> None:
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 500:
                continue
            if current.type == "method_invocation":
                self._try_operation(current, client_vars, locator, assets)
            children = current.children
            if children:
                stack.extend((child, depth + 1) for child in reversed(children))

    def _try_operation(
        self,
        inv_node: Any,
        client_vars: dict[str, tuple[str, str]],
        locator: str,
        assets: dict[str, CryptoAsset],
    ) -> None:
        name_node = inv_node.child_by_field_name("name")
        obj_node = inv_node.child_by_field_name("object")
        if name_node is None or obj_node is None:
            return
        operation = _text(name_node)
        if operation not in self._operations:
            return
        if obj_node.type == "identifier":
            var = _text(obj_node)
        elif obj_node.type == "field_access":
            # `this.client.encrypt(...)` / `holder.kms.encrypt(...)` — the
            # trailing simple name is what a field_declarator recorded.
            var = _text(obj_node).rsplit(".", 1)[-1]
        else:
            return
        if var not in client_vars:
            return
        provider, sdk = client_vars[var]
        self._emit(inv_node, name_node, provider, sdk, operation, locator, assets)

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


registry.register(JavaCloudKmsDetector())
