"""hash_patch/detect/shelf_life/data_context.py — Pillar 2 (Shelf-Life
Inference) detection.

For every Python/Java CryptoAsset evidence occurrence (a crypto call site,
already detected by hash_patch/detect/{python,java}.py), re-parses that one
file with the SAME tree-sitter parser instances those detectors already
construct (`hash_patch.detect.python._PARSER` /
`hash_patch.detect.java._PARSER` — no second Language/Parser stood up, same
convention hash_patch/detect/blast_radius/c_buffers.py follows for the C
parser) and collects up to four kinds of nearby CANDIDATE IDENTIFIER, each
matched (hash_patch.detect.shelf_life.ontology.match_categories) against
ontology/data_sensitivity.yaml's name_patterns:

  1. call_argument      — a plain-identifier argument of the crypto call
                           itself, e.g. `SHA256.new(aadhaar_bytes)` ->
                           "aadhaar_bytes". Composite expressions, string and
                           numeric literals are never candidates — only a
                           bare `identifier` argument node counts.
  2. enclosing_function  — the name of the function/method containing the
                           call.
  3. enclosing_class     — the name of the class containing that function
                           (None for a module-level function).
  4. model_field         — a Python dataclass/pydantic-style annotated class
                           attribute, or a Java field/getter, declared
                           ANYWHERE in the SAME CLASS as the call (not
                           file-wide — see "Why class-scoped, not file-wide"
                           below).

This is explicitly a heuristic, NOT a real dataflow analysis: no assignment
tracing, no cross-function-boundary tracing, no import resolution. A
sensitive value passed under a generic name, or read into a crypto call many
lines away from where it was named meaningfully, is invisible to this
pillar. See docs/SHELF_LIFE.md.

If a candidate identifier matches MULTIPLE categories, or if multiple
DIFFERENT candidates near one call site match DIFFERENT categories, ALL
matches are kept as separate DataContextMatch objects — this module never
silently picks one. Resolving that ambiguity (longest shelf_life_years wins)
is hash_patch/analyze/shelf_life.py's job. If NO candidate matches anything,
NO DataContextMatch is produced for that call site — never a default guess.

Why class-scoped, not file-wide, for model_field
--------------------------------------------------
Correlating a model_field match to a CryptoAsset uses exact (locator, line)
equality against the asset's own evidence (see
hash_patch/model/shelf_life.py's DataContextMatch docstring and
hash_patch/analyze/shelf_life.py) — the same anti-cross-contamination
discipline hash_patch/analyze/blast_radius.py's nearest-by-line rule
enforces for Pillar 3 (see its module docstring's BUG 1 regression note).
Scoping model_field candidates to the crypto call's OWN enclosing class,
rather than every class anywhere in the file, is what keeps an unrelated
crypto call elsewhere in the same file (e.g. hashing a `temp_cache_value`
with no sensitive data nearby) from spuriously picking up a DIFFERENT
class's sensitive field names just because both happen to live in one file.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from hash_patch.detect.java import _PARSER as _JAVA_PARSER
from hash_patch.detect.java import _TREE_SITTER_AVAILABLE as _JAVA_TREE_SITTER_AVAILABLE
from hash_patch.detect.python import _PARSER as _PY_PARSER
from hash_patch.detect.python import _TREE_SITTER_AVAILABLE as _PY_TREE_SITTER_AVAILABLE
from hash_patch.detect.shelf_life.ontology import (
    SensitivityCategory,
    load_sensitivity_categories,
    match_categories,
)
from hash_patch.model.assets import CryptoAsset
from hash_patch.model.evidence import Evidence
from hash_patch.model.shelf_life import DataContextMatch

_DETECTOR_ID = "shelf-life-data-context"
_DETECTOR_VERSION = "0.1.0"

# (start_line, end_line) are 1-based, inclusive — same convention as
# hash_patch/analyze/callgraph.py's FunctionInfo.
_FuncSpan = tuple[str, "str | None", int, int]  # (name, class_name, start_line, end_line)
_FieldEntry = tuple[str, int]  # (field_name, declaration_line)


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


def _first_child_of_type(node: Any, type_name: str) -> Any | None:
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def _first_identifier_text(node: Any) -> str:
    for child in node.children:
        if child.type == "identifier":
            return _text(child)
    return "<anonymous>"


def _enclosing_span(spans: list[_FuncSpan], line: int) -> _FuncSpan | None:
    """Most specific (smallest) span containing `line`, mirroring
    hash_patch/analyze/callgraph.py's CallGraph.enclosing_function.
    """
    candidates = [s for s in spans if s[2] <= line <= s[3]]
    if not candidates:
        return None
    return min(candidates, key=lambda s: s[3] - s[2])


def _node_at(root_node: Any, line: int, column: int) -> Any:
    """1-based line, 0-based column -> the smallest tree-sitter node at that
    position (tree-sitter clips out-of-range points to the nearest valid
    node rather than raising).
    """
    point = (line - 1, column)
    return root_node.descendant_for_point_range(point, point)


def _call_argument_identifiers(node: Any | None, call_type: str, args_type: str = "argument_list") -> list[str]:
    """Walk up from `node` to the nearest ancestor of type `call_type`
    (python: "call"; java: "method_invocation") and return the plain-
    identifier names among its arguments. Composite expressions, literals,
    and attribute/field accesses are never candidates — only a bare
    `identifier` argument node counts (see module docstring).
    """
    current = node
    while current is not None and current.type != call_type:
        current = current.parent
    if current is None:
        return []
    args_node = _first_child_of_type(current, args_type)
    if args_node is None:
        return []
    return [_text(c) for c in args_node.named_children if c.type == "identifier"]


# ---------------------------------------------------------------------------
# Python: function/class spans and dataclass/pydantic-style field collection
# ---------------------------------------------------------------------------


def _collect_python_spans(root_node: Any) -> list[_FuncSpan]:
    out: list[_FuncSpan] = []
    _walk_python_spans(root_node, None, out)
    return out


# Real-world files with deeply nested classes/functions/expressions can
# exceed the native C thread stack before Python's own RecursionError guard
# ever fires (a tree-sitter-node-visiting function calling itself is native
# recursion, not bytecode-level recursion CPython can budget for) — an
# unrecoverable process crash, not a catchable exception. `_walk_python_spans`
# therefore uses an explicit heap-allocated stack instead of function-call
# recursion (siblings with `hash_patch/analyze/callgraph.py::_walk_py_calls`,
# same pattern), so traversal depth is bounded by available heap memory
# rather than native stack frames. `_MAX_WALK_DEPTH` is defense in depth
# against tree-sitter AST shapes deeper than any real file should need — a
# walk that hits it simply stops descending that branch, which surfaces as
# this pillar's existing fail-safe "no signal found" behavior (see
# docs/SHELF_LIFE.md): a call site past the cap gets no enclosing span, so
# no ShelfLifeFinding is produced for it rather than a guess.
_MAX_WALK_DEPTH = 500


def _walk_python_spans(node: Any, class_name: str | None, out: list[_FuncSpan]) -> None:
    stack: list[tuple[Any, str | None, int]] = [(node, class_name, 0)]
    while stack:
        current, cname_ctx, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            continue
        if current.type == "class_definition":
            cname = _first_identifier_text(current)
            body = _first_child_of_type(current, "block")
            if body is not None:
                stack.extend((c, cname, depth + 1) for c in reversed(body.children))
            continue
        if current.type == "function_definition":
            fname = _first_identifier_text(current)
            out.append((fname, cname_ctx, current.start_point.row + 1, current.end_point.row + 1))
            body = _first_child_of_type(current, "block")
            if body is not None:
                stack.extend((c, cname_ctx, depth + 1) for c in reversed(body.children))  # nested defs, best-effort
            continue
        if current.type == "decorated_definition":
            stack.extend(
                (c, cname_ctx, depth + 1)
                for c in reversed(current.children)
                if c.type in ("function_definition", "class_definition")
            )
            continue
        stack.extend((c, cname_ctx, depth + 1) for c in reversed(current.children))


def _collect_python_class_fields(root_node: Any) -> dict[str, list[_FieldEntry]]:
    """{class_name -> [(field_name, line), ...]} for every class-body
    top-level annotated assignment (`name: Type` or `name: Type = value`) —
    the shape both `@dataclass` fields and pydantic BaseModel fields use.
    Best-effort: this matches ANY class-level annotated attribute, not only
    ones actually decorated @dataclass or subclassing BaseModel — verifying
    that would need import resolution this project's detectors don't do
    anywhere else either (see docs/SHELF_LIFE.md).
    """
    out: dict[str, list[_FieldEntry]] = defaultdict(list)
    _walk_python_class_fields(root_node, out)
    return out


def _walk_python_class_fields(node: Any, out: dict[str, list[_FieldEntry]]) -> None:
    if node.type == "class_definition":
        cname = _first_identifier_text(node)
        body = _first_child_of_type(node, "block")
        if body is not None:
            for stmt in body.children:
                if stmt.type != "expression_statement" or not stmt.children:
                    continue
                assign = stmt.children[0]
                if assign.type != "assignment":
                    continue
                has_annotation = any(gc.type == "type" for gc in assign.children)
                if not has_annotation:
                    continue
                first = assign.children[0] if assign.children else None
                if first is not None and first.type == "identifier":
                    out[cname].append((_text(first), first.start_point.row + 1))
    for c in node.children:
        _walk_python_class_fields(c, out)


# ---------------------------------------------------------------------------
# Java: method spans and field/getter collection
# ---------------------------------------------------------------------------


def _method_name(method_node: Any) -> str | None:
    children = list(method_node.children)
    for i, c in enumerate(children):
        if c.type == "formal_parameters" and i > 0 and children[i - 1].type == "identifier":
            return _text(children[i - 1])
    return None


def _collect_java_spans(root_node: Any) -> list[_FuncSpan]:
    out: list[_FuncSpan] = []
    _walk_java_spans(root_node, None, out)
    return out


def _walk_java_spans(node: Any, class_name: str | None, out: list[_FuncSpan]) -> None:
    if node.type == "class_declaration":
        cname = _first_identifier_text(node)
        body = _first_child_of_type(node, "class_body")
        if body is not None:
            for c in body.children:
                _walk_java_spans(c, cname, out)
        return
    if node.type == "method_declaration":
        name = _method_name(node)
        if name is not None:
            out.append((name, class_name, node.start_point.row + 1, node.end_point.row + 1))
        return
    for c in node.children:
        _walk_java_spans(c, class_name, out)


def _collect_java_class_fields(root_node: Any) -> dict[str, list[_FieldEntry]]:
    """{class_name -> [(field_or_getter_name, line), ...]} — class field
    declarations (`variable_declarator` inside a `field_declaration`) and
    getter-shaped method names (starting with "get"/"is") — see module
    docstring's Step-2-equivalent bullet list.
    """
    out: dict[str, list[_FieldEntry]] = defaultdict(list)
    _walk_java_class_fields(root_node, None, out)
    return out


def _walk_java_class_fields(node: Any, class_name: str | None, out: dict[str, list[_FieldEntry]]) -> None:
    if node.type == "class_declaration":
        cname = _first_identifier_text(node)
        body = _first_child_of_type(node, "class_body")
        if body is not None:
            for c in body.children:
                _walk_java_class_fields(c, cname, out)
        return
    if node.type == "field_declaration" and class_name is not None:
        for c in node.children:
            if c.type == "variable_declarator":
                ident = _first_child_of_type(c, "identifier")
                if ident is not None:
                    out[class_name].append((_text(ident), ident.start_point.row + 1))
        return
    if node.type == "method_declaration" and class_name is not None:
        name = _method_name(node)
        if name is not None and name.startswith(("get", "is")):
            out[class_name].append((name, node.start_point.row + 1))
        return
    for c in node.children:
        _walk_java_class_fields(c, class_name, out)


# ---------------------------------------------------------------------------
# Shared per-call-site candidate collection -> DataContextMatch
# ---------------------------------------------------------------------------


def _make_match(
    category: SensitivityCategory,
    pattern: str,
    identifier: str,
    kind: str,
    language: str,
    locator: str,
    call_site_line: int,
    detail: str,
) -> DataContextMatch:
    evidence = Evidence(
        source_type="source",
        locator=locator,
        line=call_site_line,
        column=None,
        byte_offset=None,
        snippet=detail,
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
    )
    return DataContextMatch(
        category=category.category_name,
        matched_identifier=identifier,
        matched_pattern=pattern,
        candidate_kind=kind,  # type: ignore[arg-type]
        language=language,  # type: ignore[arg-type]
        evidence=[evidence],
    )


def _matches_for_candidate(
    identifier: str,
    kind: str,
    language: str,
    locator: str,
    call_site_line: int,
    detail: str,
    categories: list[SensitivityCategory],
) -> list[DataContextMatch]:
    hits = match_categories(identifier, categories)
    return [
        _make_match(cat, pattern, identifier, kind, language, locator, call_site_line, detail)
        for cat, pattern in hits
    ]


def _matches_for_file_python(
    locator: str,
    source: bytes,
    call_sites: Sequence[tuple[int, int]],
    categories: list[SensitivityCategory],
) -> list[DataContextMatch]:
    tree = _PY_PARSER.parse(source)  # type: ignore[union-attr]
    root = tree.root_node
    spans = _collect_python_spans(root)
    class_fields = _collect_python_class_fields(root)

    out: list[DataContextMatch] = []
    for line, column in call_sites:
        # (line, column) is the CryptoAsset's own evidence position — for
        # the Python detector this is the attribute node inside the call
        # itself (e.g. "new" in "SHA256.new(...)"), so it is guaranteed to
        # be a descendant of the actual "call" node, not a sibling of it
        # (unlike, say, column 0 on an assignment line such as
        # `digest = SHA256.new(x)`, which would land on "digest" instead).
        node = _node_at(root, line, column)
        for arg_name in _call_argument_identifiers(node, "call"):
            out.extend(
                _matches_for_candidate(
                    arg_name, "call_argument", "python", locator, line,
                    f"argument '{arg_name}' passed to the crypto call on this line",
                    categories,
                )
            )

        span = _enclosing_span(spans, line)
        if span is None:
            continue
        fname, cname, _, _ = span
        out.extend(
            _matches_for_candidate(
                fname, "enclosing_function", "python", locator, line,
                f"enclosing function '{fname}'", categories,
            )
        )
        if cname is not None:
            out.extend(
                _matches_for_candidate(
                    cname, "enclosing_class", "python", locator, line,
                    f"enclosing class '{cname}'", categories,
                )
            )
            for field_name, field_line in class_fields.get(cname, []):
                out.extend(
                    _matches_for_candidate(
                        field_name, "model_field", "python", locator, line,
                        f"field '{field_name}' declared in class '{cname}' (line {field_line})",
                        categories,
                    )
                )
    return out


def _matches_for_file_java(
    locator: str,
    source: bytes,
    call_sites: Sequence[tuple[int, int]],
    categories: list[SensitivityCategory],
) -> list[DataContextMatch]:
    tree = _JAVA_PARSER.parse(source)  # type: ignore[union-attr]
    root = tree.root_node
    spans = _collect_java_spans(root)
    class_fields = _collect_java_class_fields(root)

    out: list[DataContextMatch] = []
    for line, column in call_sites:
        # (line, column) is the Java detector's own evidence position — the
        # algorithm string_literal argument, always inside the
        # "method_invocation" node's own argument_list, so walking up from
        # it always reaches the right call (see the Python variant's
        # comment above for why the exact evidence position matters here).
        node = _node_at(root, line, column)
        for arg_name in _call_argument_identifiers(node, "method_invocation"):
            out.extend(
                _matches_for_candidate(
                    arg_name, "call_argument", "java", locator, line,
                    f"argument '{arg_name}' passed to the crypto call on this line",
                    categories,
                )
            )

        span = _enclosing_span(spans, line)
        if span is None:
            continue
        mname, cname, _, _ = span
        out.extend(
            _matches_for_candidate(
                mname, "enclosing_function", "java", locator, line,
                f"enclosing method '{mname}'", categories,
            )
        )
        if cname is not None:
            out.extend(
                _matches_for_candidate(
                    cname, "enclosing_class", "java", locator, line,
                    f"enclosing class '{cname}'", categories,
                )
            )
            for field_name, field_line in class_fields.get(cname, []):
                out.extend(
                    _matches_for_candidate(
                        field_name, "model_field", "java", locator, line,
                        f"field/getter '{field_name}' declared in class '{cname}' (line {field_line})",
                        categories,
                    )
                )
    return out


def find_data_context_matches(
    crypto_assets: Sequence[CryptoAsset],
    categories: Sequence[SensitivityCategory] | None = None,
) -> list[DataContextMatch]:
    """For every source-evidence occurrence of every Python/Java CryptoAsset,
    collect DataContextMatch signal near that call site — see module
    docstring.

    Only `Evidence.source_type == "source"` occurrences with a known
    `.locator`/`.line` in a `.py` or `.java` file contribute; anything else
    (binary/container/config/network evidence, Go/C assets) is silently
    skipped, not guessed at.
    """
    cats = list(categories) if categories is not None else load_sensitivity_categories()
    if not cats:
        return []

    py_sites_by_locator: dict[str, set[tuple[int, int]]] = defaultdict(set)
    java_sites_by_locator: dict[str, set[tuple[int, int]]] = defaultdict(set)

    for asset in crypto_assets:
        for ev in asset.evidence:
            if ev.source_type != "source" or ev.line is None:
                continue
            suffix = Path(ev.locator).suffix.lower()
            site = (ev.line, ev.column if ev.column is not None else 0)
            if suffix == ".py" and _PY_TREE_SITTER_AVAILABLE:
                py_sites_by_locator[ev.locator].add(site)
            elif suffix == ".java" and _JAVA_TREE_SITTER_AVAILABLE:
                java_sites_by_locator[ev.locator].add(site)

    matches: list[DataContextMatch] = []

    # Sorted locator iteration: not load-bearing for correctness (final
    # findings are independently sorted in analyze/shelf_life.py), but kept
    # for the same determinism discipline the rest of this codebase applies
    # everywhere it's cheap to do so.
    for locator in sorted(py_sites_by_locator):
        path = Path(locator)
        if not path.is_file():
            continue
        matches.extend(
            _matches_for_file_python(locator, path.read_bytes(), sorted(py_sites_by_locator[locator]), cats)
        )

    for locator in sorted(java_sites_by_locator):
        path = Path(locator)
        if not path.is_file():
            continue
        matches.extend(
            _matches_for_file_java(locator, path.read_bytes(), sorted(java_sites_by_locator[locator]), cats)
        )

    return matches
