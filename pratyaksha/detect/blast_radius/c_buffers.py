"""pratyaksha/detect/blast_radius/c_buffers.py — C fixed-size-buffer detector
for Pillar 3 (Blast Radius).

Finds fixed-size stack buffers and heap allocations whose variable name
suggests they hold cryptographic material (rules/blast_radius_names.yaml,
via pratyaksha.detect.blast_radius.names), and emits a SizeConstraint
(pratyaksha/model/blast_radius.py) for each — never a CryptoAsset; see
pratyaksha/detect/blast_radius/__init__.py.

Covers:
  - stack buffers:  char buf[N];  uint8_t buf[N];  unsigned char buf[N];
  - heap allocations: a malloc/calloc call with a literal (or one-level
    #define-resolved) size, assigned to such a name — either as a
    declaration initializer (`unsigned char *sig = malloc(256);`) or a
    plain assignment (`sig = malloc(256);`), including a C-style cast
    between the `=` and the call.

Uses the exact same tree-sitter C parser instance
pratyaksha.detect.c already constructs (no second Language/Parser stood up).

Size resolution: a literal integer, or one level of `#define NAME <int>`
resolution within the same file. calloc(count, size) resolves to
count * size only when BOTH arguments resolve; anything else (a variable, a
sizeof(...) expression, an unresolved macro, arithmetic) is left
unresolved, and NO SizeConstraint is emitted for it — never a guess.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pratyaksha.detect.blast_radius.names import NamePattern, load_name_patterns, match_name_pattern
from pratyaksha.detect.c import _PARSER as _C_PARSER
from pratyaksha.detect.c import _TREE_SITTER_AVAILABLE as _C_TREE_SITTER_AVAILABLE
from pratyaksha.model.blast_radius import SizeConstraint
from pratyaksha.model.evidence import Evidence

_DETECTOR_ID = "c-blast-radius-buffers"
_DETECTOR_VERSION = "0.1.0"

_SUPPORTED_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh"})

# What counts as a "byte buffer" C type for the stack-buffer pattern. This is
# a structural fact about the C type system, not a crypto algorithm/OID/
# pattern, so — unlike algorithm rules — it is a small constant here rather
# than YAML data (consistent with how detect/c.py hardcodes AST node-type
# strings like "call_expression").
_BUFFER_TYPE_NAMES = frozenset({"char", "unsigned char", "uint8_t", "int8_t", "byte"})

_ALLOC_FUNCS = frozenset({"malloc", "calloc"})


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# #define resolution (one level)
# ---------------------------------------------------------------------------


def _collect_defines(root_node: Any) -> dict[str, int]:
    defines: dict[str, int] = {}
    _walk_defines(root_node, defines)
    return defines


def _walk_defines(node: Any, defines: dict[str, int]) -> None:
    if node.type == "preproc_def":
        name_node = None
        value_node = None
        for c in node.children:
            if c.type == "identifier" and name_node is None:
                name_node = c
            elif c.type == "preproc_arg":
                value_node = c
        if name_node is not None and value_node is not None:
            text = _text(value_node).strip()
            try:
                defines[_text(name_node)] = int(text, 0)
            except ValueError:
                pass  # not a plain integer literal -> leave unresolved
    for c in node.children:
        _walk_defines(c, defines)


def _resolve_int(node: Any, defines: dict[str, int]) -> int | None:
    if node.type == "number_literal":
        text = _text(node).rstrip("uUlL")
        try:
            return int(text, 0)
        except ValueError:
            return None
    if node.type == "identifier":
        return defines.get(_text(node))
    return None


# ---------------------------------------------------------------------------
# Stack buffers: char/uint8_t/unsigned char NAME[N];
# ---------------------------------------------------------------------------


def _declaration_type_text(decl_node: Any) -> str | None:
    for c in decl_node.children:
        if c.type in ("primitive_type", "sized_type_specifier"):
            return _text(c)
    return None


def _collect_stack_buffers(root_node: Any) -> list[tuple[Any, Any, Any]]:
    """Returns (identifier_node, size_expr_node, declaration_node) triples."""
    out: list[tuple[Any, Any, Any]] = []
    _walk_stack(root_node, out)
    return out


def _walk_stack(node: Any, out: list[tuple[Any, Any, Any]]) -> None:
    if node.type == "declaration":
        type_text = _declaration_type_text(node)
        if type_text in _BUFFER_TYPE_NAMES:
            for c in node.children:
                if c.type == "array_declarator":
                    named = list(c.named_children)
                    if len(named) >= 2 and named[0].type == "identifier":
                        out.append((named[0], named[1], node))
                    break
    for c in node.children:
        _walk_stack(c, out)


# ---------------------------------------------------------------------------
# Heap allocations: NAME = malloc(N);  TYPE *NAME = malloc(N);  (+ calloc)
# ---------------------------------------------------------------------------


def _declarator_identifier(node: Any) -> Any | None:
    if node.type == "identifier":
        return node
    if node.type == "pointer_declarator":
        for c in node.children:
            found = _declarator_identifier(c)
            if found is not None:
                return found
    return None


def _unwrap_call(node: Any) -> Any | None:
    if node.type == "call_expression":
        return node
    if node.type == "cast_expression":
        named = list(node.named_children)
        if named and named[-1].type == "call_expression":
            return named[-1]
    return None


def _resolve_alloc_bytes(call_node: Any, defines: dict[str, int]) -> int | None:
    fn_node = call_node.child_by_field_name("function")
    args_node = call_node.child_by_field_name("arguments")
    if fn_node is None or args_node is None:
        return None
    fn_name = _text(fn_node)
    if fn_name not in _ALLOC_FUNCS:
        return None
    args = list(args_node.named_children)
    if fn_name == "malloc":
        if len(args) != 1:
            return None
        return _resolve_int(args[0], defines)
    # calloc(count, size)
    if len(args) != 2:
        return None
    count = _resolve_int(args[0], defines)
    size = _resolve_int(args[1], defines)
    if count is None or size is None:
        return None
    return count * size


def _collect_heap_allocs(root_node: Any, defines: dict[str, int]) -> list[tuple[Any, int, Any]]:
    """Returns (identifier_node, resolved_bytes, span_node) triples."""
    out: list[tuple[Any, int, Any]] = []
    _walk_heap(root_node, defines, out)
    return out


def _walk_heap(node: Any, defines: dict[str, int], out: list[tuple[Any, int, Any]]) -> None:
    if node.type in ("init_declarator", "assignment_expression"):
        named = list(node.named_children)
        if len(named) >= 2:
            ident = _declarator_identifier(named[0])
            call = _unwrap_call(named[-1])
            if ident is not None and call is not None:
                size = _resolve_alloc_bytes(call, defines)
                if size is not None:
                    out.append((ident, size, node))
    for c in node.children:
        _walk_heap(c, defines, out)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class CBufferBlastRadiusDetector:
    """Detects fixed-size C buffers/heap allocations named like crypto
    material. Emits SizeConstraint, never CryptoAsset — see
    pratyaksha/detect/blast_radius/__init__.py for why this isn't in the
    shared Detector registry.
    """

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        self._patterns: list[NamePattern] = load_name_patterns()

    def supports(self, target: Path) -> bool:
        return (
            _C_TREE_SITTER_AVAILABLE
            and target.is_file()
            and target.suffix.lower() in _SUPPORTED_EXTENSIONS
        )

    def detect(self, target: Path) -> list[SizeConstraint]:
        if not self.supports(target):
            return []

        source = target.read_bytes()
        tree = _C_PARSER.parse(source)  # type: ignore[union-attr]
        defines = _collect_defines(tree.root_node)
        locator = str(target)

        results: list[SizeConstraint] = []

        for ident_node, size_node, decl_node in _collect_stack_buffers(tree.root_node):
            name = _text(ident_node)
            if match_name_pattern(name, self._patterns) is None:
                continue
            size = _resolve_int(size_node, defines)
            if size is None:
                continue  # unresolved (variable, un-#define'd macro, etc.) -> skip
            results.append(
                self._make_constraint("stack_buffer", name, size, ident_node, decl_node, locator)
            )

        for ident_node, size, span_node in _collect_heap_allocs(tree.root_node, defines):
            name = _text(ident_node)
            if match_name_pattern(name, self._patterns) is None:
                continue
            results.append(
                self._make_constraint("heap_alloc", name, size, ident_node, span_node, locator)
            )

        return results

    def _make_constraint(
        self,
        kind: str,
        name: str,
        declared_bytes: int,
        ident_node: Any,
        span_node: Any,
        locator: str,
    ) -> SizeConstraint:
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
        return SizeConstraint(
            kind=kind,  # type: ignore[arg-type]
            name=name,
            declared_bytes=declared_bytes,
            evidence=[evidence],
            language="c",
        )
