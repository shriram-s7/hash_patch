"""hash_patch/detect/blast_radius/go_buffers.py — Go fixed-size-buffer detector
for Pillar 3 (Blast Radius).

Detects fixed-size byte arrays in Go source code (e.g. `var wire [64]byte`)
that hold cryptographic material or are sized for post-quantum vulnerable outputs.
Emits SizeConstraint objects for blast-radius correlation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hash_patch.detect.blast_radius.names import NamePattern, load_name_patterns, match_name_pattern
from hash_patch.detect.blast_radius.output_sizes import (
    infer_field_from_size,
    match_algorithm_output_size,
)
from hash_patch.detect.go import _PARSER as _GO_PARSER
from hash_patch.detect.go import _TREE_SITTER_AVAILABLE as _GO_TREE_SITTER_AVAILABLE
from hash_patch.model.blast_radius import SizeConstraint
from hash_patch.model.evidence import Evidence

_DETECTOR_ID = "go-blast-radius-buffers"
_DETECTOR_VERSION = "0.1.0"
_SUPPORTED_EXTENSIONS = frozenset({".go"})
_BYTE_TYPES = frozenset({"byte", "uint8"})


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


def _collect_consts(root_node: Any) -> dict[str, int]:
    consts: dict[str, int] = {}
    stack = [root_node]
    while stack:
        curr = stack.pop()
        if curr.type == "const_spec":
            names: list[str] = []
            val = None
            for c in curr.children:
                if c.type == "identifier":
                    names.append(_text(c))
                elif c.type == "int_literal":
                    try:
                        val = int(_text(c), 0)
                    except ValueError:
                        pass
            if val is not None:
                for n in names:
                    consts[n] = val
        stack.extend(reversed(curr.children))
    return consts


def _resolve_int(node: Any, consts: dict[str, int]) -> int | None:
    if node.type == "int_literal":
        try:
            return int(_text(node), 0)
        except ValueError:
            return None
    if node.type == "identifier":
        return consts.get(_text(node))
    return None


class GoBufferBlastRadiusDetector:
    """Detects fixed-size Go buffers ([N]byte) holding cryptographic material."""

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        self._patterns: list[NamePattern] = load_name_patterns()

    def supports(self, target: Path) -> bool:
        return (
            _GO_TREE_SITTER_AVAILABLE
            and target.is_file()
            and target.suffix.lower() in _SUPPORTED_EXTENSIONS
        )

    def detect(self, target: Path) -> list[SizeConstraint]:
        if not self.supports(target):
            return []

        source = target.read_bytes()
        tree = _GO_PARSER.parse(source)  # type: ignore[union-attr]
        consts = _collect_consts(tree.root_node)
        locator = str(target)
        results: list[SizeConstraint] = []

        stack = [tree.root_node]
        while stack:
            curr = stack.pop()

            # 1. var_spec: var wire [64]byte
            if curr.type == "var_spec" or curr.type == "parameter_declaration":
                ident_node = None
                array_node = None
                for c in curr.children:
                    if c.type == "identifier" and ident_node is None:
                        ident_node = c
                    elif c.type == "array_type":
                        array_node = c
                if ident_node is not None and array_node is not None:
                    self._try_add_constraint(ident_node, array_node, curr, consts, locator, tree.root_node, results)

            # 3. short_var_declaration: wire := [64]byte{}
            elif curr.type == "short_var_declaration":
                named = list(curr.named_children)
                if len(named) >= 2:
                    left = named[0]
                    right = named[1]
                    ident = left if left.type == "identifier" else (left.named_children[0] if left.named_children else None)
                    array_node = None
                    if right.type == "composite_literal":
                        for c in right.children:
                            if c.type == "array_type":
                                array_node = c
                                break
                    elif right.type == "array_type":
                        array_node = right
                    if ident is not None and array_node is not None:
                        self._try_add_constraint(ident, array_node, curr, consts, locator, tree.root_node, results)

            stack.extend(reversed(curr.children))

        return results

    def _try_add_constraint(
        self,
        ident_node: Any,
        array_node: Any,
        span_node: Any,
        consts: dict[str, int],
        locator: str,
        root_node: Any,
        results: list[SizeConstraint],
    ) -> None:
        len_node = None
        elem_node = None
        for c in array_node.children:
            if c.type in ("int_literal", "identifier") and len_node is None:
                len_node = c
            elif c.type == "type_identifier":
                elem_node = c

        if len_node is None or elem_node is None:
            return
        if _text(elem_node) not in _BYTE_TYPES:
            return

        size = _resolve_int(len_node, consts)
        if size is None:
            return

        name = _text(ident_node)
        pattern_match = match_name_pattern(name, self._patterns)
        inferred_field = pattern_match[1] if pattern_match else None

        if pattern_match is None:
            inferred_field = self._correlate_buffer(span_node, ident_node, size, root_node)
            if inferred_field is None:
                return

        evidence = Evidence(
            source_type="source",
            locator=locator,
            line=ident_node.start_point.row + 1,
            column=ident_node.start_point.column,
            byte_offset=ident_node.start_byte,
            snippet=span_node.text.decode("utf-8", errors="replace"),
            detector_id=_DETECTOR_ID,
            detector_version=_DETECTOR_VERSION,
        )
        results.append(
            SizeConstraint(
                kind="stack_buffer",
                name=name,
                declared_bytes=size,
                evidence=[evidence],
                language="go",
                inferred_field=inferred_field,  # type: ignore[arg-type]
            )
        )

    def _correlate_buffer(self, decl_node: Any, ident_node: Any, size: int, root_node: Any) -> str | None:
        func_node = decl_node
        while func_node and func_node.type not in ("function_declaration", "method_declaration"):
            func_node = func_node.parent

        scope_node = func_node if func_node else root_node
        scope_text = _text(scope_node)

        for algo in ("ED25519", "RSA", "ECDSA", "ECDH", "DH"):
            if algo.lower() in scope_text.lower():
                field = match_algorithm_output_size(algo, size)
                if field is not None:
                    return field

        ident_name = _text(ident_node)
        if func_node is not None and ident_name in _text(func_node):
            field = infer_field_from_size(size)
            if field is not None:
                return field

        return None

    def _is_crypto_data_flow(self, decl_node: Any, ident_node: Any) -> bool:
        func_node = decl_node
        while func_node and func_node.type not in ("function_declaration", "method_declaration"):
            func_node = func_node.parent
        if func_node is None:
            return False
        func_text = _text(func_node)
        ident_name = _text(ident_node)
        return ident_name in func_text and any(
            crypto_term in func_text.lower()
            for crypto_term in ("crypto", "sign", "digest", "hash", "copy(", "ed25519", "rsa")
        )
