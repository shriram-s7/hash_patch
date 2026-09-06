"""hash_patch/detect/cloud_kms/go_cloud_kms.py — Go cloud KMS/HSM client-side
usage detector. See hash_patch/detect/cloud_kms/__init__.py for the full
scope and honesty framing.

Two-pass, same-file matching (mirrors
hash_patch/detect/cloud_kms/python_cloud_kms.py's discipline):
  1. Find every variable declared from a call matching a known
     client-constructor shape (rules/cloud_kms.yaml's go section —
     `selector_expression` shape, e.g. `kms.New`, `kms.NewFromConfig`,
     `azkeys.NewClient`) via short-var-declaration, var_spec, or a later
     reassignment assignment_statement — never a finding by itself.
  2. Find every `<that variable>.<operation>(...)` call, where `<operation>`
     (PascalCase in Go's SDK, e.g. `Encrypt`, `Decrypt`, `Sign`, ...) is in
     the shared operations list — THIS is the finding. A client constructed
     but never used for a real operation produces nothing, the same
     reference-vs-operation discipline every other detector follows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import tree_sitter_go as _ts_go
    from tree_sitter import Language, Parser

    _LANG = Language(_ts_go.language())
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

_DETECTOR_ID = "go-cloud-kms"
_DETECTOR_VERSION = "0.1.0"


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


class GoCloudKmsDetector(Detector):
    """Detects AWS KMS (aws-sdk-go / aws-sdk-go-v2), google-cloud-go KMS
    (cloud.google.com/go/kms/apiv1), and Azure (azkeys) client construction +
    operation calls in Go source files.
    """

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        rules = load_cloud_kms_rules()
        self._constructors: list[dict[str, Any]] = rules.get("go", {}).get("client_constructors", [])
        self._operations: set[str] = set(rules.get("operations", []))
        self._constructor_fn_names: frozenset[str] = frozenset(c["match"] for c in self._constructors)

    def supports(self, target: Path) -> bool:
        return _TREE_SITTER_AVAILABLE and target.is_file() and target.suffix.lower() == ".go"

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

    @staticmethod
    def _first_identifier(expr_list: Any) -> Any | None:
        for child in expr_list.named_children:
            if child.type == "identifier":
                return child
        return None

    def _match_constructor_call(self, call_node: Any) -> tuple[str, str] | None:
        fn_node = call_node.child_by_field_name("function")
        if fn_node is None or fn_node.type != "selector_expression":
            return None
        fn_text = _text(fn_node)
        for ctor in self._constructors:
            if ctor["match"] == fn_text:
                return (ctor["provider"], ctor["sdk"])
        return None

    def _collect_client_vars(self, node: Any, out: dict[str, tuple[str, str]]) -> None:
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 500:
                continue
            if current.type in ("short_var_declaration", "assignment_statement"):
                left = current.child_by_field_name("left")
                right = current.child_by_field_name("right")
                if (
                    left is not None
                    and left.type == "expression_list"
                    and right is not None
                    and right.type == "expression_list"
                ):
                    name_node = self._first_identifier(left)
                    if name_node is not None:
                        var_text = _text(name_node)
                        for call in right.named_children:
                            if call.type != "call_expression":
                                continue
                            match = self._match_constructor_call(call)
                            if match is not None:
                                out[var_text] = match
                                break
            elif current.type == "var_spec":
                name = current.child_by_field_name("name")
                value = current.child_by_field_name("value")
                if (
                    name is not None
                    and name.type == "identifier"
                    and value is not None
                    and value.type == "expression_list"
                ):
                    var_text = _text(name)
                    for call in value.named_children:
                        if call.type != "call_expression":
                            continue
                        match = self._match_constructor_call(call)
                        if match is not None:
                            out[var_text] = match
                            break
            children = current.children
            if children:
                stack.extend((child, depth + 1) for child in reversed(children))

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
            if current.type == "call_expression":
                self._try_operation(current, client_vars, locator, assets)
            children = current.children
            if children:
                stack.extend((child, depth + 1) for child in reversed(children))

    def _try_operation(
        self,
        call_node: Any,
        client_vars: dict[str, tuple[str, str]],
        locator: str,
        assets: dict[str, CryptoAsset],
    ) -> None:
        fn_node = call_node.child_by_field_name("function")
        if fn_node is None or fn_node.type != "selector_expression":
            return
        operand = fn_node.child_by_field_name("operand")
        field_node = fn_node.child_by_field_name("field")
        if operand is None or field_node is None:
            return
        if operand.type != "identifier":
            return
        var = _text(operand)
        operation = _text(field_node)
        if var not in client_vars or operation not in self._operations:
            return
        provider, sdk = client_vars[var]
        self._emit(call_node, field_node, provider, sdk, operation, locator, assets)

    def _emit(
        self,
        call_node: Any,
        field_node: Any,
        provider: str,
        sdk: str,
        operation: str,
        locator: str,
        assets: dict[str, CryptoAsset],
    ) -> None:
        evidence = Evidence(
            source_type="source",
            locator=locator,
            line=field_node.start_point[0] + 1,
            column=field_node.start_point[1],
            byte_offset=field_node.start_byte,
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


registry.register(GoCloudKmsDetector())
