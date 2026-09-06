"""hash_patch/detect/go_resolver.py — Argument resolver for Go crypto calls.

Resolves algorithm arguments passed into Go crypto calls:
1. String literals (direct interpreted or raw strings).
2. Named const declarations in the current file or sibling .go files in the
   same package directory.
3. Function and method return branching (e.g. policy.SignatureFamily(partner)),
   tracing return statements in if/else branches and resolving each returned
   constant/literal as an independent branch.
4. Local variable assignments with conditional branches.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tree_sitter_go as _tsgo
    from tree_sitter import Language, Parser

    _LANG = Language(_tsgo.language())
    _PARSER = Parser(_LANG)
except Exception:
    _LANG = None
    _PARSER = None


@dataclass
class GoResolution:
    """Represents one resolved or candidate crypto API argument."""

    algo_raw: str | None
    confidence: str  # "HIGH" or "LOW"
    resolution_path: list[str] | None = None
    branch_condition: str | None = None
    algo_node: Any | None = None


def extract_string_literal(node: Any | None) -> str | None:
    """Return stripped string text from a Go string literal node, or None."""
    if node is None:
        return None
    if node.type in ("interpreted_string_literal", "raw_string_literal"):
        text = node.text.decode("utf-8", errors="replace")
        if text.startswith(('"', "'", "`")) and text.endswith(('"', "'", "`")) and len(text) >= 2:
            return text[1:-1]
        return text
    return None


class GoPackageIndex:
    """Collects const definitions and function/method declarations across .go files in a directory."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.consts: dict[str, tuple[str, Any]] = {}
        self.functions: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if _PARSER is None or not self.directory.is_dir():
            return
        for p in self.directory.glob("*.go"):
            if not p.is_file():
                continue
            try:
                tree = _PARSER.parse(p.read_bytes())
            except Exception:
                continue
            self._index_file(tree.root_node)

    def _index_file(self, root: Any) -> None:
        for node in root.children:
            if node.type == "const_declaration":
                for spec in node.children:
                    if spec.type == "const_spec":
                        name_node: Any | None = None
                        val_node: Any | None = None
                        for c in spec.children:
                            if c.type == "identifier" and name_node is None:
                                name_node = c
                            elif c.type == "expression_list":
                                val_node = c
                        if name_node and val_node:
                            name = name_node.text.decode("utf-8", errors="replace")
                            for lit in val_node.children:
                                str_val = extract_string_literal(lit)
                                if str_val is not None:
                                    self.consts[name] = (str_val, lit)
                                    break
            elif node.type in ("function_declaration", "method_declaration"):
                for c in node.children:
                    if c.type in ("identifier", "field_identifier"):
                        fn_name = c.text.decode("utf-8", errors="replace")
                        self.functions[fn_name] = node
                        break


def _find_enclosing_function(node: Any) -> Any | None:
    curr = node
    while curr:
        if curr.type in ("function_declaration", "method_declaration"):
            return curr
        curr = curr.parent
    return None


def _walk_returns(node: Any, current_cond: str | None = None) -> list[tuple[Any, str | None]]:
    results: list[tuple[Any, str | None]] = []
    if node.type == "if_statement":
        cond_node = node.child_by_field_name("condition")
        cond_text = cond_node.text.decode("utf-8", errors="replace") if cond_node else "condition"
        consequence = node.child_by_field_name("consequence")
        if consequence:
            results.extend(_walk_returns(consequence, cond_text))
        alternative = node.child_by_field_name("alternative")
        if alternative:
            results.extend(_walk_returns(alternative, f"!({cond_text})"))
        return results

    if node.type == "return_statement":
        results.append((node, current_cond))
        return results

    for c in node.children:
        results.extend(_walk_returns(c, current_cond))
    return results


def _find_local_assignments(
    fn_node: Any, var_name: str, current_cond: str | None = None
) -> list[tuple[Any, str | None]]:
    results: list[tuple[Any, str | None]] = []
    if fn_node.type == "if_statement":
        cond_node = fn_node.child_by_field_name("condition")
        cond_text = cond_node.text.decode("utf-8", errors="replace") if cond_node else "condition"
        cons = fn_node.child_by_field_name("consequence")
        if cons:
            results.extend(_find_local_assignments(cons, var_name, cond_text))
        alt = fn_node.child_by_field_name("alternative")
        if alt:
            results.extend(_find_local_assignments(alt, var_name, f"!({cond_text})"))
        return results

    if fn_node.type in ("short_var_declaration", "assignment_statement"):
        left = fn_node.child_by_field_name("left")
        right = fn_node.child_by_field_name("right")
        if left and right:
            left_text = left.text.decode("utf-8", errors="replace").strip()
            if left_text == var_name:
                expr = right.children[0] if right.children else right
                results.append((expr, current_cond))
                return results

    for c in fn_node.children:
        results.extend(_find_local_assignments(c, var_name, current_cond))
    return results


def resolve_go_argument(arg_node: Any | None, target_file: Path) -> list[GoResolution]:
    """Resolve an argument node in Go source to one or more candidate GoResolutions."""
    if arg_node is None:
        return []

    # 1. Direct string literal
    str_lit = extract_string_literal(arg_node)
    if str_lit is not None:
        return [GoResolution(algo_raw=str_lit, confidence="HIGH", algo_node=arg_node)]

    index = GoPackageIndex(target_file.parent)

    # 2. Direct Identifier
    if arg_node.type == "identifier":
        name = arg_node.text.decode("utf-8", errors="replace")
        if name in index.consts:
            val, cnode = index.consts[name]
            return [
                GoResolution(
                    algo_raw=val,
                    confidence="HIGH",
                    resolution_path=[f"{name} -> \"{val}\""],
                    algo_node=cnode,
                )
            ]

        # Check local variable assignment in enclosing function
        fn_enclosing = _find_enclosing_function(arg_node)
        if fn_enclosing:
            assignments = _find_local_assignments(fn_enclosing, name)
            if assignments:
                resolutions: list[GoResolution] = []
                for right_node, cond in assignments:
                    right_lit = extract_string_literal(right_node)
                    if right_lit is not None:
                        resolutions.append(
                            GoResolution(
                                algo_raw=right_lit,
                                confidence="HIGH",
                                branch_condition=cond,
                                algo_node=right_node,
                            )
                        )
                    elif right_node.type == "identifier":
                        r_name = right_node.text.decode("utf-8", errors="replace")
                        if r_name in index.consts:
                            c_val, c_node = index.consts[r_name]
                            resolutions.append(
                                GoResolution(
                                    algo_raw=c_val,
                                    confidence="HIGH",
                                    resolution_path=[f"{name} := {r_name} -> \"{c_val}\""],
                                    branch_condition=cond,
                                    algo_node=c_node,
                                )
                            )
                if resolutions:
                    return resolutions

    # 3. Selector expression (e.g. policy.AuthSignature or crypto.AuthSignature)
    if arg_node.type == "selector_expression":
        field = arg_node.child_by_field_name("field")
        field_text = (
            field.text.decode("utf-8", errors="replace")
            if field
            else arg_node.text.decode("utf-8", errors="replace").split(".")[-1]
        )
        if field_text in index.consts:
            val, cnode = index.consts[field_text]
            return [
                GoResolution(
                    algo_raw=val,
                    confidence="HIGH",
                    resolution_path=[f"{arg_node.text.decode('utf-8', errors='replace')} -> \"{val}\""],
                    algo_node=cnode,
                )
            ]

    # 4. Call expression (e.g. policy.SignatureFamily(partner) or SignatureFamily(partner))
    if arg_node.type == "call_expression":
        fn_expr = arg_node.child_by_field_name("function")
        fn_name: str | None = None
        if fn_expr:
            if fn_expr.type == "selector_expression":
                field = fn_expr.child_by_field_name("field")
                fn_name = field.text.decode("utf-8", errors="replace") if field else None
            elif fn_expr.type == "identifier":
                fn_name = fn_expr.text.decode("utf-8", errors="replace")

        if fn_name and fn_name in index.functions:
            fn_decl = index.functions[fn_name]
            body = fn_decl.child_by_field_name("body")
            if body:
                returns = _walk_returns(body)
                resolutions = []
                for ret_node, cond in returns:
                    # Find expression child
                    expr: Any | None = None
                    for c in ret_node.children:
                        if c.type == "expression_list":
                            expr = c.children[0] if c.children else None
                            break
                    if expr is None:
                        continue

                    # Expr can be string literal or identifier
                    e_lit = extract_string_literal(expr)
                    if e_lit is not None:
                        resolutions.append(
                            GoResolution(
                                algo_raw=e_lit,
                                confidence="HIGH",
                                branch_condition=cond,
                                algo_node=expr,
                            )
                        )
                    elif expr.type == "identifier":
                        e_name = expr.text.decode("utf-8", errors="replace")
                        if e_name in index.consts:
                            c_val, c_node = index.consts[e_name]
                            resolutions.append(
                                GoResolution(
                                    algo_raw=c_val,
                                    confidence="HIGH",
                                    resolution_path=[f"{fn_name} -> {e_name} -> \"{c_val}\""],
                                    branch_condition=cond,
                                    algo_node=c_node,
                                )
                            )
                if resolutions:
                    return resolutions

    return []
