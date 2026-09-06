"""hash_patch/analyze/callgraph.py — directory-level call graph builder.

Builds a simple, name-based call graph over a *set* of source files for one
language (Python, Java, or C/C++) — not per file, per Step 1 of the
reachability feature: two files in the same scan target can call into each
other, so the graph has to span the whole file set to be useful.

Name resolution deliberately mirrors the level of sophistication the
existing detectors (hash_patch/detect/python.py, hash_patch/detect/java.py,
hash_patch/detect/c.py) already use: plain identifier /
"identifier.identifier" matching, no import aliasing, no type inference, no
data-flow. There is no separate "resolver" module to reuse in this codebase
today — the detectors do their own ad-hoc name matching inline — so this
module follows that exact convention rather than inventing a fancier one,
and reuses the *parsers* the detectors already construct
(`hash_patch.detect.python._PARSER`, `hash_patch.detect.java._PARSER`,
`hash_patch.detect.c._PARSER`) instead of standing up new tree-sitter
`Language`/`Parser` instances.

C's call graph is flat (no classes/methods): a `FunctionId.qualname` is
just the bare function name. Two different files each defining a
same-named `static` function (legal, common C practice — internal linkage)
would be a genuine ambiguity a name-only resolver cannot tell apart, so
`_NameIndex`'s existing "more than one definition sharing a name -> treat
as unresolved" rule (see `_NameIndex` below) already does the safe thing
here for free, the same way it protects Python/Java call resolution from a
same-named-function false match.

Anything this simple matcher cannot resolve to exactly one function
definition in the set — a call through a variable, a call into a library
with no source here, an ambiguous name shared by two functions — is
recorded explicitly as an *unresolved* call on the calling function (see
`FunctionInfo.unresolved_call_count`), never silently dropped. Reachability
classification (hash_patch/analyze/reachability.py) treats "not reachable
from anything" as UNKNOWN rather than INERT for any function outside a test
file specifically so that this simplicity never produces a false INERT.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hash_patch.detect.c import _PARSER as _C_PARSER
from hash_patch.detect.c import _TREE_SITTER_AVAILABLE as _C_TREE_SITTER_AVAILABLE
from hash_patch.detect.java import _PARSER as _JAVA_PARSER
from hash_patch.detect.java import _TREE_SITTER_AVAILABLE as _JAVA_TREE_SITTER_AVAILABLE
from hash_patch.detect.python import _PARSER as _PY_PARSER
from hash_patch.detect.python import _TREE_SITTER_AVAILABLE as _PY_TREE_SITTER_AVAILABLE

# C/C++ source extensions that can contain function DEFINITIONS (bodies) --
# headers (.h/.hpp/...) only ever contain declarations/prototypes in the
# corpora this tool targets, so they never define a `function_definition`
# node and are deliberately excluded from the call-graph file set itself
# (evidence found IN a header still gets a reachability vote of UNKNOWN via
# hash_patch/analyze/reachability.py's `ctx is None` path, same as any other
# suffix with no context).
_C_SOURCE_EXTENSIONS = frozenset({".c", ".cpp", ".cc", ".cxx"})

# ---------------------------------------------------------------------------
# Shared data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FunctionId:
    """Identity of one function/method definition: its file and qualified name."""

    file: str
    qualname: str

    @property
    def simple_name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]


@dataclass
class FunctionInfo:
    """One function/method definition site, with everything both the call-graph
    builder and entrypoints.py need — kept together so entrypoints.py never has
    to re-walk the tree-sitter AST itself.
    """

    id: FunctionId
    start_line: int  # 1-based, inclusive
    end_line: int  # 1-based, inclusive
    node: Any = field(repr=False, compare=False, default=None)  # tree-sitter node for its body

    # Python-specific
    decorators: list[str] = field(default_factory=list)
    is_synthetic_main_block: bool = False

    # Shared / Java-specific
    class_name: str | None = None
    class_annotations: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    is_static: bool = False
    is_public: bool = False
    param_count: int | None = None


@dataclass
class CallGraph:
    """A directory-level, name-resolved call graph over one language's files."""

    function_infos: list[FunctionInfo] = field(default_factory=list)
    edges: dict[FunctionId, set[FunctionId]] = field(default_factory=dict)
    reverse_edges: dict[FunctionId, set[FunctionId]] = field(default_factory=dict)
    unresolved_call_count: dict[FunctionId, int] = field(default_factory=dict)

    def add_edge(self, caller: FunctionId, callee: FunctionId) -> None:
        self.edges.setdefault(caller, set()).add(callee)
        self.reverse_edges.setdefault(callee, set()).add(caller)

    def add_unresolved(self, caller: FunctionId) -> None:
        self.unresolved_call_count[caller] = self.unresolved_call_count.get(caller, 0) + 1

    def enclosing_function(self, file: str, line: int) -> FunctionId | None:
        """Return the most specific FunctionInfo.id whose span contains `line`."""
        candidates = [
            info
            for info in self.function_infos
            if info.id.file == file and info.start_line <= line <= info.end_line
        ]
        if not candidates:
            return None
        best = min(candidates, key=lambda info: info.end_line - info.start_line)
        return best.id

    def ancestors(self, node: FunctionId) -> set[FunctionId]:
        """Transitive reverse reachability set: everyone who (transitively) calls
        `node` via a resolved edge. Excludes `node` itself.
        """
        seen: set[FunctionId] = set()
        stack: list[FunctionId] = list(self.reverse_edges.get(node, ()))
        while stack:
            current = stack.pop()
            if current in seen or current == node:
                continue
            seen.add(current)
            stack.extend(self.reverse_edges.get(current, ()))
        return seen


class _NameIndex:
    """Best-effort name resolver: exact qualified name, else unique bare name.

    An ambiguous match (the same name defined more than once in the file set)
    is treated the same as no match — unresolved — rather than guessing.
    """

    def __init__(self, functions: Sequence[FunctionInfo]) -> None:
        self._by_qualname: dict[str, list[FunctionId]] = defaultdict(list)
        self._by_bare: dict[str, list[FunctionId]] = defaultdict(list)
        for fn in functions:
            self._by_qualname[fn.id.qualname].append(fn.id)
            self._by_bare[fn.id.simple_name].append(fn.id)

    def resolve_qualified(self, qualname: str) -> FunctionId | None:
        candidates = self._by_qualname.get(qualname)
        if candidates and len(candidates) == 1:
            return candidates[0]
        return None

    def resolve_bare(self, name: str) -> FunctionId | None:
        candidates = self._by_bare.get(name)
        if candidates and len(candidates) == 1:
            return candidates[0]
        return None


# ---------------------------------------------------------------------------
# Small tree-sitter helpers shared by both languages
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Python: function/method collection
# ---------------------------------------------------------------------------


def _decorator_final_identifier(decorator_node: Any) -> str | None:
    """Return the last identifier segment of a decorator expression.

    @app.route(...) -> "route"; @main -> "main"; @a.b.c(...) -> "c".
    """
    expr = None
    for child in decorator_node.children:
        if child.type != "@":
            expr = child
            break
    if expr is None:
        return None
    if expr.type == "call":
        callee = None
        for child in expr.children:
            if child.type != "argument_list":
                callee = child
        expr = callee
    if expr is None:
        return None
    if expr.type == "identifier":
        return _text(expr)
    if expr.type == "attribute":
        named = [c for c in expr.children if c.is_named]
        if named and named[-1].type == "identifier":
            return _text(named[-1])
    return None


def _is_main_guard(if_node: Any) -> bool:
    """True for `if __name__ == "__main__":` (order-insensitive, best-effort)."""
    children = list(if_node.children)
    if len(children) < 2:
        return False
    condition_text = _text(children[1])
    return "__name__" in condition_text and "__main__" in condition_text


def _make_main_block_info(if_node: Any, file_str: str) -> FunctionInfo:
    body = _first_child_of_type(if_node, "block")
    return FunctionInfo(
        id=FunctionId(file_str, f"__main_block__:{if_node.start_point.row + 1}"),
        start_line=if_node.start_point.row + 1,
        end_line=if_node.end_point.row + 1,
        node=body if body is not None else if_node,
        is_synthetic_main_block=True,
    )


def _make_py_function_info(
    span_node: Any, func_node: Any, file_str: str, class_name: str | None
) -> FunctionInfo:
    name = _first_identifier_text(func_node)
    qualname = f"{class_name}.{name}" if class_name else name
    decorators: list[str] = []
    if span_node.type == "decorated_definition":
        for child in span_node.children:
            if child.type == "decorator":
                d = _decorator_final_identifier(child)
                if d:
                    decorators.append(d)
    return FunctionInfo(
        id=FunctionId(file_str, qualname),
        start_line=span_node.start_point.row + 1,
        end_line=func_node.end_point.row + 1,
        node=func_node,
        decorators=decorators,
        class_name=class_name,
    )


def _scan_python_block(
    block_node: Any, file_str: str, class_name: str | None, out: list[FunctionInfo]
) -> None:
    for child in block_node.children:
        node = child
        if node.type == "decorated_definition":
            inner = None
            for c in node.children:
                if c.type in ("function_definition", "class_definition"):
                    inner = c
                    break
            if inner is None:
                continue
            if inner.type == "function_definition":
                out.append(_make_py_function_info(node, inner, file_str, class_name))
            else:
                _scan_python_class(inner, file_str, out)
            continue
        if node.type == "function_definition":
            out.append(_make_py_function_info(node, node, file_str, class_name))
            continue
        if node.type == "class_definition":
            _scan_python_class(node, file_str, out)
            continue
        if class_name is None and node.type == "if_statement" and _is_main_guard(node):
            out.append(_make_main_block_info(node, file_str))
            continue


def _scan_python_class(class_node: Any, file_str: str, out: list[FunctionInfo]) -> None:
    class_name = _first_identifier_text(class_node)
    body = _first_child_of_type(class_node, "block")
    if body is not None:
        _scan_python_block(body, file_str, class_name, out)


def _collect_python_functions(root_node: Any, file_str: str) -> list[FunctionInfo]:
    functions: list[FunctionInfo] = []
    _scan_python_block(root_node, file_str, None, functions)
    return functions


# ---------------------------------------------------------------------------
# Python: call-site collection and resolution
# ---------------------------------------------------------------------------


def _py_call_shape(call_node: Any) -> tuple[str, str | None, str | None]:
    """("simple", None, name) | ("attr", obj, name) | ("dynamic", None, None)."""
    first = call_node.children[0] if call_node.children else None
    if first is None:
        return ("dynamic", None, None)
    if first.type == "identifier":
        return ("simple", None, _text(first))
    if first.type == "attribute":
        named = [c for c in first.children if c.is_named]
        if len(named) >= 2 and named[0].type == "identifier" and named[-1].type == "identifier":
            return ("attr", _text(named[0]), _text(named[-1]))
    return ("dynamic", None, None)


# Real-world files with deeply nested expressions/definitions can exceed the
# native C thread stack before Python's own RecursionError guard ever fires
# (a tree-sitter-node-visiting function calling itself is native recursion,
# not bytecode-level recursion CPython can budget for) — an unrecoverable
# process crash, not a catchable exception. `_walk_py_calls` therefore uses
# an explicit heap-allocated stack instead of function-call recursion, so
# traversal depth is bounded by available heap memory rather than native
# stack frames. `_MAX_WALK_DEPTH` is defense in depth against tree-sitter
# AST shapes deeper than any real file should need — a walk that hits it
# simply stops descending that branch (fewer resolved calls -> more
# `unresolved`), which is already this module's existing fail-safe behavior
# for anything it cannot resolve (see docs/REACHABILITY.md).
_MAX_WALK_DEPTH = 500


def _walk_py_calls(node: Any, out: list[tuple[str, str | None, str | None]]) -> None:
    stack: list[tuple[Any, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            continue
        if current.type == "call":
            out.append(_py_call_shape(current))
        children = current.children
        if children:
            stack.extend((child, depth + 1) for child in reversed(children))


def _resolve_py_call(
    shape: tuple[str, str | None, str | None], caller: FunctionInfo, index: _NameIndex
) -> FunctionId | None:
    kind, obj, name = shape
    if kind == "simple" and name is not None:
        return index.resolve_bare(name)
    if kind == "attr" and obj is not None and name is not None:
        if obj in ("self", "cls") and caller.class_name:
            resolved = index.resolve_qualified(f"{caller.class_name}.{name}")
            if resolved is not None:
                return resolved
        resolved = index.resolve_qualified(f"{obj}.{name}")
        if resolved is not None:
            return resolved
        return index.resolve_bare(name)
    return None


def build_python_call_graph(files: Sequence[Path]) -> CallGraph:
    """Build one call graph spanning every given Python file (a "file set" per
    Step 1 — typically every .py file under a single scan target).
    """
    functions: list[FunctionInfo] = []
    if _PY_TREE_SITTER_AVAILABLE:
        for f in files:
            if not (f.is_file() and f.suffix.lower() == ".py"):
                continue
            source = f.read_bytes()
            tree = _PY_PARSER.parse(source)
            functions.extend(_collect_python_functions(tree.root_node, str(f)))

    graph = CallGraph(function_infos=functions)
    index = _NameIndex(functions)
    for fn in functions:
        if fn.node is None:
            continue
        calls: list[tuple[str, str | None, str | None]] = []
        _walk_py_calls(fn.node, calls)
        for shape in calls:
            target = _resolve_py_call(shape, fn, index)
            if target is not None:
                graph.add_edge(fn.id, target)
            else:
                graph.add_unresolved(fn.id)
    return graph


# ---------------------------------------------------------------------------
# Java: class/method collection
# ---------------------------------------------------------------------------


def _annotation_names(modifiers_node: Any | None) -> list[str]:
    if modifiers_node is None:
        return []
    names: list[str] = []
    for child in modifiers_node.children:
        if child.type in ("marker_annotation", "annotation"):
            ident = _first_child_of_type(child, "identifier")
            if ident is not None:
                names.append(_text(ident))
    return names


def _method_name(method_node: Any) -> str:
    children = list(method_node.children)
    for i, c in enumerate(children):
        if c.type == "formal_parameters" and i > 0 and children[i - 1].type == "identifier":
            return _text(children[i - 1])
    return "<unknown>"


def _make_java_function_info(
    method_node: Any, file_str: str, class_name: str | None, class_annotations: list[str]
) -> FunctionInfo:
    name = _method_name(method_node)
    qualname = f"{class_name}.{name}" if class_name else name
    modifiers = _first_child_of_type(method_node, "modifiers")
    annotations = _annotation_names(modifiers)
    is_static = modifiers is not None and any(c.type == "static" for c in modifiers.children)
    is_public = modifiers is not None and any(c.type == "public" for c in modifiers.children)
    params = _first_child_of_type(method_node, "formal_parameters")
    param_count = (
        sum(1 for c in params.children if c.type == "formal_parameter") if params is not None else 0
    )
    return FunctionInfo(
        id=FunctionId(file_str, qualname),
        start_line=method_node.start_point.row + 1,
        end_line=method_node.end_point.row + 1,
        node=method_node,
        class_name=class_name,
        class_annotations=class_annotations,
        annotations=annotations,
        is_static=is_static,
        is_public=is_public,
        param_count=param_count,
    )


def _scan_java_class(class_node: Any, file_str: str, out: list[FunctionInfo]) -> None:
    class_name = _first_identifier_text(class_node)
    modifiers = _first_child_of_type(class_node, "modifiers")
    class_annotations = _annotation_names(modifiers)
    body = _first_child_of_type(class_node, "class_body")
    if body is None:
        return
    for child in body.children:
        if child.type == "method_declaration":
            out.append(_make_java_function_info(child, file_str, class_name, class_annotations))
        elif child.type == "class_declaration":
            _scan_java_class(child, file_str, out)  # nested class, best-effort


def _collect_java_functions(root_node: Any, file_str: str) -> list[FunctionInfo]:
    functions: list[FunctionInfo] = []
    for child in root_node.children:
        if child.type == "class_declaration":
            _scan_java_class(child, file_str, functions)
    return functions


# ---------------------------------------------------------------------------
# Java: call-site collection and resolution
# ---------------------------------------------------------------------------


def _java_call_shape(node: Any) -> tuple[str, str | None, str | None]:
    """("simple"|"this", None, name) | ("attr", obj, name) | ("dynamic", None, name|None)."""
    children = list(node.children)
    arg_idx = next((i for i, c in enumerate(children) if c.type == "argument_list"), None)
    if arg_idx is None or arg_idx == 0:
        return ("dynamic", None, None)
    name_node = children[arg_idx - 1]
    if name_node.type != "identifier":
        return ("dynamic", None, None)
    name = _text(name_node)
    if arg_idx == 1:
        return ("simple", None, name)
    dot_node = children[arg_idx - 2]
    if dot_node.type != "." or arg_idx - 3 < 0:
        return ("dynamic", None, name)
    receiver_node = children[arg_idx - 3]
    if receiver_node.type == "this":
        return ("this", None, name)
    if receiver_node.type == "identifier":
        return ("attr", _text(receiver_node), name)
    return ("dynamic", None, name)  # field_access / object_creation_expression / nested call


def _walk_java_calls(node: Any, out: list[tuple[str, str | None, str | None]]) -> None:
    if node.type == "method_invocation":
        out.append(_java_call_shape(node))
    for child in node.children:
        _walk_java_calls(child, out)


def _resolve_java_call(
    shape: tuple[str, str | None, str | None], caller: FunctionInfo, index: _NameIndex
) -> FunctionId | None:
    kind, obj, name = shape
    if kind in ("simple", "this") and name is not None:
        if caller.class_name:
            resolved = index.resolve_qualified(f"{caller.class_name}.{name}")
            if resolved is not None:
                return resolved
        return index.resolve_bare(name)
    if kind == "attr" and obj is not None and name is not None:
        resolved = index.resolve_qualified(f"{obj}.{name}")
        if resolved is not None:
            return resolved
        return index.resolve_bare(name)
    return None


def build_java_call_graph(files: Sequence[Path]) -> CallGraph:
    """Build one call graph spanning every given Java file (a "file set" per
    Step 1 — typically every .java file under a single scan target).
    """
    functions: list[FunctionInfo] = []
    if _JAVA_TREE_SITTER_AVAILABLE:
        for f in files:
            if not (f.is_file() and f.suffix.lower() == ".java"):
                continue
            source = f.read_bytes()
            tree = _JAVA_PARSER.parse(source)
            functions.extend(_collect_java_functions(tree.root_node, str(f)))

    graph = CallGraph(function_infos=functions)
    index = _NameIndex(functions)
    for fn in functions:
        if fn.node is None:
            continue
        calls: list[tuple[str, str | None, str | None]] = []
        _walk_java_calls(fn.node, calls)
        for shape in calls:
            target = _resolve_java_call(shape, fn, index)
            if target is not None:
                graph.add_edge(fn.id, target)
            else:
                graph.add_unresolved(fn.id)
    return graph


# ---------------------------------------------------------------------------
# C/C++: function collection
# ---------------------------------------------------------------------------


def _c_function_declarator(declarator_node: Any) -> Any | None:
    """Descend through wrapping declarators (pointer_declarator for a
    pointer return type, parenthesized_declarator, etc.) to find the
    innermost `function_declarator` -- e.g. for `const char *foo(int x)`,
    the function_definition's `declarator` field is a `pointer_declarator`
    wrapping the actual `function_declarator`.
    """
    node = declarator_node
    depth = 0
    while node is not None and node.type != "function_declarator" and depth < 20:
        nxt = node.child_by_field_name("declarator")
        if nxt is None:
            return None
        node = nxt
        depth += 1
    return node if node is not None and node.type == "function_declarator" else None


def _c_function_name(function_definition_node: Any) -> str | None:
    """Name of a `function_definition` node, or None if it cannot be
    resolved to a plain identifier (e.g. a macro-generated declarator this
    simple matcher doesn't understand) -- callers must skip such a
    function rather than guess.
    """
    declarator = function_definition_node.child_by_field_name("declarator")
    if declarator is None:
        return None
    fd = _c_function_declarator(declarator)
    if fd is None:
        return None
    ident = fd.child_by_field_name("declarator")
    if ident is not None and ident.type == "identifier":
        return _text(ident)
    return None


def _collect_c_functions(root_node: Any, file_str: str) -> list[FunctionInfo]:
    """Top-level function definitions only -- standard C has no nested
    function definitions, so (unlike Python's class-nested methods) there
    is nothing to recurse into beyond `translation_unit`'s direct children.
    """
    functions: list[FunctionInfo] = []
    for child in root_node.children:
        if child.type != "function_definition":
            continue
        name = _c_function_name(child)
        if name is None:
            continue
        body = child.child_by_field_name("body")
        functions.append(
            FunctionInfo(
                id=FunctionId(file_str, name),
                start_line=child.start_point.row + 1,
                end_line=child.end_point.row + 1,
                node=body if body is not None else child,
            )
        )
    return functions


# ---------------------------------------------------------------------------
# C/C++: call-site collection and resolution
# ---------------------------------------------------------------------------


def _c_call_target(call_node: Any) -> str | None:
    """The called function's bare name for a plain `foo(...)` call, or None
    for anything this simple matcher can't resolve (a call through a
    function pointer, `obj->fn(...)`, a macro-expanded call, ...) -- an
    unresolved call, never a guess.
    """
    fn_node = call_node.child_by_field_name("function")
    if fn_node is not None and fn_node.type == "identifier":
        return _text(fn_node)
    return None


def _walk_c_calls(node: Any, out: list[str | None]) -> None:
    """Same explicit-heap-stack traversal as `_walk_py_calls` (see its
    comment) -- real C files can nest expressions/declarators deep enough
    to risk a native stack overflow under function-call recursion.
    """
    stack: list[tuple[Any, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            continue
        if current.type == "call_expression":
            out.append(_c_call_target(current))
        children = current.children
        if children:
            stack.extend((child, depth + 1) for child in reversed(children))


def build_c_call_graph(files: Sequence[Path]) -> CallGraph:
    """Build one call graph spanning every given C/C++ file (a "file set"
    per Step 1 — typically every .c/.cpp/.cc/.cxx file under a single scan
    target; headers are excluded, see `_C_SOURCE_EXTENSIONS`).
    """
    functions: list[FunctionInfo] = []
    if _C_TREE_SITTER_AVAILABLE:
        for f in files:
            if not (f.is_file() and f.suffix.lower() in _C_SOURCE_EXTENSIONS):
                continue
            source = f.read_bytes()
            tree = _C_PARSER.parse(source)
            functions.extend(_collect_c_functions(tree.root_node, str(f)))

    graph = CallGraph(function_infos=functions)
    index = _NameIndex(functions)
    for fn in functions:
        if fn.node is None:
            continue
        calls: list[str | None] = []
        _walk_c_calls(fn.node, calls)
        for name in calls:
            target = index.resolve_bare(name) if name is not None else None
            if target is not None:
                graph.add_edge(fn.id, target)
            else:
                graph.add_unresolved(fn.id)
    return graph
