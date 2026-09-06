"""Java fixed-size buffer detector for blast-radius analysis.

Identifies fixed-size byte array allocations (e.g. ``new byte[64]``,
``ByteBuffer.allocate(64)``) that correlate with cryptographic operations
(either via declared size matching algorithm output or data-flow/call proximity).
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tree_sitter_java as _ts_java
    from tree_sitter import Language, Node, Parser

    _LANG = Language(_ts_java.language())
    _PARSER = Parser(_LANG)
    _JAVA_TREE_SITTER_AVAILABLE = True
except Exception:  # pragma: no cover
    _JAVA_TREE_SITTER_AVAILABLE = False
    _LANG = None  # type: ignore[assignment]
    _PARSER = None  # type: ignore[assignment]

from hash_patch.detect.blast_radius.names import NamePattern, load_name_patterns, match_name_pattern
from hash_patch.detect.blast_radius.output_sizes import infer_field_from_size
from hash_patch.model.blast_radius import SizeConstraint
from hash_patch.model.evidence import Evidence

_DETECTOR_ID = "java-blast-radius-buffers"
_DETECTOR_VERSION = "0.1.0"
_SUPPORTED_EXTENSIONS = frozenset({".java"})

_CRYPTO_CALL_RE = re.compile(
    r"\b(Signature|Cipher|Mac|MessageDigest|KeyAgreement|KeyPairGenerator|KeyFactory|SecretKeySpec)\b"
)
_CRYPTO_METHOD_RE = re.compile(
    r"\b(sign|verify|doFinal|digest|generateSecret|update)\b"
)


class JavaBufferBlastRadiusDetector:
    """Detects fixed-size byte array allocations in Java source files."""

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        self._patterns: list[NamePattern] = load_name_patterns()

    def supports(self, target: Path) -> bool:
        return (
            _JAVA_TREE_SITTER_AVAILABLE
            and target.is_file()
            and target.suffix.lower() in _SUPPORTED_EXTENSIONS
        )

    def detect(self, target: Path) -> list[SizeConstraint]:
        """Collect fixed-size buffer size constraints from a Java source file."""
        if not self.supports(target):
            return []

        try:
            source_bytes = target.read_bytes()
        except OSError:
            return []

        tree = _PARSER.parse(source_bytes)  # type: ignore[union-attr]
        constants = self._collect_constants(tree.root_node)
        locator = str(target)
        return self._walk_node(tree.root_node, source_bytes, locator, constants)

    def _collect_constants(self, root: Node) -> dict[str, int]:
        """Scan fields / local vars for integer constant values."""
        constants: dict[str, int] = {}
        stack: list[tuple[Node, int]] = [(root, 0)]
        while stack:
            node, depth = stack.pop()
            if depth > 500:
                continue
            if node.type in ("field_declaration", "local_variable_declaration"):
                for child in node.children:
                    if child.type == "variable_declarator":
                        name_node = child.child_by_field_name("name")
                        val_node = child.child_by_field_name("value")
                        if name_node and val_node:
                            val_text = val_node.text.decode("utf-8", errors="replace").strip()
                            if val_text.isdigit():
                                try:
                                    constants[name_node.text.decode("utf-8", errors="replace")] = int(val_text)
                                except ValueError:
                                    pass
            children = node.children
            if children:
                stack.extend((c, depth + 1) for c in reversed(children))
        return constants

    def _walk_node(
        self,
        node: Node,
        source_bytes: bytes,
        locator: str,
        constants: dict[str, int],
    ) -> list[SizeConstraint]:
        constraints: list[SizeConstraint] = []
        stack: list[tuple[Node, int]] = [(node, 0)]
        while stack:
            n, depth = stack.pop()
            if depth > 500:
                continue
            if n.type == "variable_declarator":
                c = self._inspect_declarator(n, source_bytes, locator, constants)
                if c:
                    constraints.append(c)
            elif n.type == "assignment_expression":
                c = self._inspect_assignment(n, source_bytes, locator, constants)
                if c:
                    constraints.append(c)

            children = n.children
            if children:
                stack.extend((child, depth + 1) for child in reversed(children))
        return constraints

    def _inspect_declarator(
        self,
        node: Node,
        source_bytes: bytes,
        locator: str,
        constants: dict[str, int],
    ) -> SizeConstraint | None:
        name_node = node.child_by_field_name("name")
        val_node = node.child_by_field_name("value")
        if not name_node or not val_node:
            return None

        var_name = name_node.text.decode("utf-8", errors="replace")
        declared_bytes = self._extract_buffer_size(val_node, constants)
        if declared_bytes is None or declared_bytes <= 0:
            return None

        return self._correlate_buffer(var_name, declared_bytes, name_node, node, source_bytes, locator)

    def _inspect_assignment(
        self,
        node: Node,
        source_bytes: bytes,
        locator: str,
        constants: dict[str, int],
    ) -> SizeConstraint | None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or not right:
            return None

        var_name = left.text.decode("utf-8", errors="replace")
        declared_bytes = self._extract_buffer_size(right, constants)
        if declared_bytes is None or declared_bytes <= 0:
            return None

        return self._correlate_buffer(var_name, declared_bytes, left, node, source_bytes, locator)

    def _extract_buffer_size(self, node: Node, constants: dict[str, int]) -> int | None:
        """Extract size from `new byte[64]` or `ByteBuffer.allocate(64)`."""
        if node.type == "array_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node:
                elem_type = type_node.text.decode("utf-8", errors="replace")
                if elem_type != "byte":
                    return None
            else:
                is_byte = False
                for c in node.children:
                    if c.type == "integral_type" and c.text == b"byte":
                        is_byte = True
                        break
                if not is_byte:
                    return None

            for c in node.children:
                if c.type == "dimensions_expr":
                    for sub in c.children:
                        if sub.type == "decimal_integer_literal":
                            try:
                                return int(sub.text.decode("utf-8", errors="replace"))
                            except ValueError:
                                return None
                        if sub.type == "identifier":
                            ident = sub.text.decode("utf-8", errors="replace")
                            return constants.get(ident)

        elif node.type == "method_invocation":
            text = node.text.decode("utf-8", errors="replace")
            if "ByteBuffer.allocate" in text:
                args = node.child_by_field_name("arguments")
                if args:
                    for arg in args.children:
                        if arg.type == "decimal_integer_literal":
                            try:
                                return int(arg.text.decode("utf-8", errors="replace"))
                            except ValueError:
                                return None
                        if arg.type == "identifier":
                            return constants.get(arg.text.decode("utf-8", errors="replace"))

        return None

    def _correlate_buffer(
        self,
        name: str,
        declared_bytes: int,
        ident_node: Node,
        span_node: Node,
        source_bytes: bytes,
        locator: str,
    ) -> SizeConstraint | None:
        """Evaluate whether buffer correlates with cryptographic operations."""
        enclosing_scope = self._find_enclosing_scope(span_node)
        scope_text = (
            enclosing_scope.text.decode("utf-8", errors="replace")
            if enclosing_scope
            else source_bytes.decode("utf-8", errors="replace")
        )

        pattern_match = match_name_pattern(name, self._patterns)
        inferred_field: str | None = pattern_match[1] if pattern_match else None

        has_crypto_api = bool(_CRYPTO_CALL_RE.search(scope_text) or _CRYPTO_METHOD_RE.search(scope_text))

        # 1. Structural / Size-to-algorithm output matching
        if inferred_field is None and has_crypto_api:
            inferred_field = infer_field_from_size(declared_bytes)

        # 2. Data-flow correlation: buffer is destination argument or passed to crypto call
        if inferred_field is None and self._is_crypto_data_flow(name, enclosing_scope):
            inferred_field = infer_field_from_size(declared_bytes) or "signature"

        if pattern_match is None and inferred_field is None:
            return None

        evidence = Evidence(
            source_type="source",
            locator=locator,
            line=ident_node.start_point[0] + 1,
            column=ident_node.start_point[1],
            byte_offset=ident_node.start_byte,
            snippet=span_node.text.decode("utf-8", errors="replace"),
            detector_id=_DETECTOR_ID,
            detector_version=_DETECTOR_VERSION,
        )

        return SizeConstraint(
            kind="heap_alloc",
            name=name,
            declared_bytes=declared_bytes,
            evidence=[evidence],
            language="java",
            inferred_field=inferred_field,  # type: ignore[arg-type]
        )

    def _is_crypto_data_flow(self, buf_name: str, scope: Node | None) -> bool:
        if not scope:
            return False
        scope_text = scope.text.decode("utf-8", errors="replace")

        arraycopy_pat = re.compile(
            rf"System\.arraycopy\s*\([^,]+,[^,]+,\s*{re.escape(buf_name)}\b"
        )
        if arraycopy_pat.search(scope_text):
            return True

        crypto_dest_pat = re.compile(
            rf"\b(sign|update|doFinal|digest)\s*\([^)]*\b{re.escape(buf_name)}\b"
        )
        if crypto_dest_pat.search(scope_text):
            return True

        return False

    @staticmethod
    def _find_enclosing_scope(node: Node) -> Node | None:
        curr = node.parent
        while curr:
            if curr.type in (
                "method_declaration",
                "constructor_declaration",
                "lambda_expression",
                "class_declaration",
            ):
                return curr
            curr = curr.parent
        return None
