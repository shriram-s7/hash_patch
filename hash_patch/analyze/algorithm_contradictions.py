"""hash_patch/analyze/algorithm_contradictions.py — Pillar 4: declared-vs-
implemented algorithm divergence.

hash_patch/analyze/contradictions.py's existing Pillar 4 logic is narrowly
scoped to TLS: source-code TLS-version intent vs. deployed TLS config files.
This module is a SEPARATE, GENERAL kind of cross-layer contradiction within
pure source code: a policy/dispatch function whose returned value (a string
literal or a same-package named constant) names one crypto algorithm family,
correlated against a real crypto API call reachable — via a direct,
unguarded call edge — from the same function that consulted that policy
value, which actually invokes a DIFFERENT algorithm family.

Example (see testdata/go/policy_divergence for the golden fixture this
module is verified against): a Go package's `Policy.SignatureFamily` returns
the named constant `EllipticSignature` ("ECDSA") for one partner branch, but
`Sign()` — which calls `SignatureFamily` and is not gated on that specific
value anywhere — unconditionally calls `rsa.SignPKCS1v15` for that same
case. The code CLAIMS "ECDSA" (via the value it computed and could have
branched on) while actually doing RSA.

**Scope and honesty caveats (deliberately conservative, same design
discipline as CLAUDE.md's "Blast Radius" and shelf-life same-file rules):**

1. **Same package (directory) only.** A Go package is a real,
   language-defined visibility/call boundary — not an arbitrary heuristic
   the way "two files happen to be near each other" would be. This module
   never correlates across package directories.
2. **Direct call only, not transitive.** The caller function must directly
   invoke the declaring (policy) function by name — found via a plain
   `call_expression`/method-call scan, not a full call graph (Go has no
   call-graph infrastructure in this codebase yet — see
   hash_patch/analyze/call_relations.py's own "Go/C are out of scope"
   note). A two-hop indirection (`A calls B calls policy()`) is invisible
   to this pass.
3. **"Unguarded" is a syntactic approximation, not full dataflow.** A
   declared branch is treated as reaching an operation call unless that
   call sits inside an `if` block whose condition text visibly mentions the
   declared value: inside the ALTERNATIVE of an `if` whose condition
   mentions that declared value means it's explicitly excluded there, so
   it's suppressed. No general dataflow/exhaustiveness proof is attempted —
   see docs/CONTRADICTIONS.md.
4. **Only algorithm names already recognized elsewhere fire.** A declared
   value only counts when it resolves (via the exact same
   rules/go_crypto.yaml `crypto_references`/`algorithms` tables every other
   Go detection already uses) to a known canonical algorithm name — never a
   hardcoded string anywhere in this file.
5. **Only comparable primitives are compared.** A declared signature-scheme
   name is only checked against operation calls whose OWN primitive matches
   the declared value's primitive (both "signature", say) — an unrelated
   hash or KDF call in the same function (e.g. computing a message digest
   before signing it) is never treated as "the implementation" of a
   declared signature algorithm. This primitive comes from the same rules
   file, never guessed.
6. **"Different family" is substring-containment, not exact equality.** Two
   canonical names are the SAME family if one contains the other
   case-insensitively (e.g. declared "RSA" vs. implemented
   "RSASSA-PKCS1v15" — same family, no contradiction); anything else counts
   as different. This avoids false positives from a coarse declared label
   and a more specific real scheme name for the same underlying algorithm.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from hash_patch.detect.go import _PARSER, _RULES_PATH, _build_crypto_references, _load_rules
from hash_patch.detect.go_resolver import _walk_returns, extract_string_literal
from hash_patch.model.assets import CryptoAsset
from hash_patch.model.config_finding import AlgorithmDivergenceFinding
from hash_patch.model.evidence import Evidence

_DETECTOR_ID = "algorithm-divergence"
_DETECTOR_VERSION = "0.1.0"


def _normalize_locator(locator: str) -> str:
    return locator.replace("\\", "/")


def _load_go_algorithm_lookup() -> dict[str, tuple[str, str]]:
    """{UPPERCASE raw string -> (canonical algorithm family, primitive)},
    built from the same rules/go_crypto.yaml tables the real Go detector
    uses (crypto references and standalone algorithm entries) — never a
    name hardcoded in this module.
    """
    rules = _load_rules(_RULES_PATH)
    lookup: dict[str, tuple[str, str]] = {}
    for name, rule in _build_crypto_references(rules).items():
        lookup[name.upper()] = (rule["canonical"], rule.get("primitive", "unknown"))
    for name, rule in rules.get("algorithms", {}).items():
        lookup[name.upper()] = (rule["canonical"], rule.get("primitive", "unknown"))
    return lookup


def _same_family(a: str, b: str) -> bool:
    a_up, b_up = a.upper(), b.upper()
    return a_up == b_up or a_up in b_up or b_up in a_up


def _fn_name(node: Any) -> str | None:
    for c in node.children:
        if c.type in ("identifier", "field_identifier"):
            return c.text.decode("utf-8", errors="replace")
    return None


def _iter_call_expressions(node: Any) -> list[Any]:
    results: list[Any] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "call_expression":
            results.append(current)
        stack.extend(current.children)
    return results


def _call_target_name(call_node: Any) -> str | None:
    fn_expr = call_node.child_by_field_name("function")
    if fn_expr is None:
        return None
    if fn_expr.type == "selector_expression":
        field = fn_expr.child_by_field_name("field")
        return field.text.decode("utf-8", errors="replace") if field else None
    if fn_expr.type == "identifier":
        return fn_expr.text.decode("utf-8", errors="replace")
    return None


def _find_enclosing_function(node: Any) -> Any | None:
    current = node
    while current is not None:
        if current.type in ("function_declaration", "method_declaration"):
            return current
        current = current.parent
    return None


def _ancestor_branches(node: Any, stop_at: Any) -> list[tuple[Any, str]]:
    """Walk up from `node` to (not past) `stop_at`, collecting every
    enclosing if-statement this node sits inside, along with which side
    ("consequence" or "alternative") it's nested in.
    """
    branches: list[tuple[Any, str]] = []
    current = node
    while current is not None and current is not stop_at:
        parent = current.parent
        if parent is not None and parent.type == "if_statement":
            if parent.child_by_field_name("consequence") is current:
                branches.append((parent, "consequence"))
            elif parent.child_by_field_name("alternative") is current:
                branches.append((parent, "alternative"))
        current = parent
    return branches


def _is_guarded_away(call_node: Any, fn_node: Any, declared_raw: str) -> bool:
    """True when `call_node` sits in a branch that visibly excludes the
    `declared_raw` case (see module docstring point 3) — i.e. safe to skip.
    """
    for if_stmt, side in _ancestor_branches(call_node, fn_node):
        if side != "alternative":
            continue
        cond_node = if_stmt.child_by_field_name("condition")
        cond_text = cond_node.text.decode("utf-8", errors="replace") if cond_node else ""
        if declared_raw.upper() in cond_text.upper():
            return True
    return False


class _PackageDeclarations:
    """Same-directory (package) const and function declarations, each
    tracked with the SPECIFIC FILE it was parsed from — unlike
    hash_patch/detect/go_resolver.py's GoPackageIndex (built for a
    different purpose: resolving one already-known call's argument, where
    only the resolved VALUE matters, not provenance), this module needs to
    point evidence at the right file, so file provenance is tracked
    explicitly here rather than reusing that index.
    """

    def __init__(self, files: Sequence[Path]) -> None:
        # name -> (value, file, node)
        self.consts: dict[str, tuple[str, Path, Any]] = {}
        # name -> (file, node)
        self.functions: dict[str, tuple[Path, Any]] = {}
        for file in files:
            try:
                tree = _PARSER.parse(file.read_bytes())  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001 -- one bad file must not abort the whole pass
                continue
            self._index_file(tree.root_node, file)

    def _index_file(self, root: Any, file: Path) -> None:
        for node in root.children:
            if node.type == "const_declaration":
                for spec in node.children:
                    if spec.type != "const_spec":
                        continue
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
                                self.consts[name] = (str_val, file, lit)
                                break
            elif node.type in ("function_declaration", "method_declaration"):
                fn_name = _fn_name(node)
                if fn_name:
                    self.functions[fn_name] = (file, node)


def _resolve_declared_values(
    fn_node: Any, fn_file: Path, package: _PackageDeclarations
) -> list[tuple[str, Any, Path, str | None]]:
    """Every (raw_string, node, file, branch_condition) this function's
    `return` statements can produce — a direct string literal, or a
    same-package named constant. Mirrors
    hash_patch/detect/go_resolver.py::resolve_go_argument's "call
    expression" case, but preserves file provenance per result.
    """
    body = fn_node.child_by_field_name("body")
    if body is None:
        return []

    results: list[tuple[str, Any, Path, str | None]] = []
    for ret_node, cond in _walk_returns(body):
        expr: Any | None = None
        for c in ret_node.children:
            if c.type == "expression_list":
                expr = c.children[0] if c.children else None
                break
        if expr is None:
            continue

        lit = extract_string_literal(expr)
        if lit is not None:
            results.append((lit, expr, fn_file, cond))
            continue
        if expr.type == "identifier":
            name = expr.text.decode("utf-8", errors="replace")
            if name in package.consts:
                val, const_file, const_node = package.consts[name]
                results.append((val, const_node, const_file, cond))
    return results


def compute_algorithm_contradictions(
    crypto_assets: Sequence[CryptoAsset], scanned_files: Sequence[Path]
) -> list[AlgorithmDivergenceFinding]:
    """Entry point used by hash_patch/cli.py::run_scan. See module docstring
    for the full method and its scope/honesty caveats.
    """
    if _PARSER is None:
        return []

    go_files = [f for f in scanned_files if f.suffix.lower() == ".go"]
    if not go_files:
        return []

    algo_lookup = _load_go_algorithm_lookup()

    op_by_key: dict[tuple[str, int], CryptoAsset] = {}
    for asset in crypto_assets:
        if asset.finding_type != "OPERATION":
            continue
        for ev in asset.evidence:
            if ev.source_type != "source" or ev.line is None:
                continue
            op_by_key[(_normalize_locator(ev.locator), ev.line)] = asset

    by_directory: dict[Path, list[Path]] = defaultdict(list)
    for f in go_files:
        by_directory[f.parent].append(f)

    findings: list[AlgorithmDivergenceFinding] = []

    for directory, files in sorted(by_directory.items()):
        package = _PackageDeclarations(files)

        for file in sorted(files):
            try:
                tree = _PARSER.parse(file.read_bytes())
            except Exception:  # noqa: BLE001 -- a single unparseable file must not abort the whole scan
                continue

            for call_node in _iter_call_expressions(tree.root_node):
                fn_enclosing = _find_enclosing_function(call_node)
                if fn_enclosing is None:
                    continue

                op_line = call_node.start_point.row + 1
                op_asset = op_by_key.get((_normalize_locator(str(file)), op_line))
                if op_asset is None:
                    continue
                implemented_family = op_asset.name
                implemented_primitive = op_asset.primitive.value

                caller_name = _fn_name(fn_enclosing) or "?"

                for policy_call in _iter_call_expressions(fn_enclosing):
                    if policy_call is call_node:
                        continue
                    target_name = _call_target_name(policy_call)
                    if target_name is None or target_name not in package.functions:
                        continue
                    decl_file, decl_node = package.functions[target_name]

                    for raw, node, node_file, branch_cond in _resolve_declared_values(
                        decl_node, decl_file, package
                    ):
                        lookup_entry = algo_lookup.get(raw.upper())
                        if lookup_entry is None:
                            continue  # not a recognized algorithm name -- no signal
                        declared_family, declared_primitive = lookup_entry
                        if declared_primitive != implemented_primitive:
                            continue  # not a comparable operation (e.g. hash vs signature)
                        if _same_family(declared_family, implemented_family):
                            continue
                        if _is_guarded_away(call_node, fn_enclosing, raw):
                            continue

                        declaring_ev = Evidence(
                            source_type="source",
                            locator=str(node_file),
                            line=node.start_point.row + 1,
                            column=node.start_point.column,
                            byte_offset=node.start_byte,
                            snippet=node.text.decode("utf-8", errors="replace"),
                            detector_id=_DETECTOR_ID,
                            detector_version=_DETECTOR_VERSION,
                        )
                        call_ev = op_asset.evidence[0]
                        for ev in op_asset.evidence:
                            if (
                                _normalize_locator(ev.locator) == _normalize_locator(str(file))
                                and ev.line == op_line
                            ):
                                call_ev = ev
                                break

                        seed = (
                            f"{declaring_ev.locator}:{declaring_ev.line}|{call_ev.locator}:{call_ev.line}|"
                            f"{declared_family}|{implemented_family}"
                        )
                        cid = f"algo-contradiction-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"

                        desc = (
                            f"{target_name} (declares {declared_family} at "
                            f"{declaring_ev.locator}:{declaring_ev.line}) is called from {caller_name}, "
                            f"which invokes {implemented_family} at {call_ev.locator}:{call_ev.line} on "
                            "that same, unguarded path — the implementation does not match what the "
                            "policy declares."
                        )

                        findings.append(
                            AlgorithmDivergenceFinding(
                                id=cid,
                                declared_algorithm=declared_family,
                                implemented_algorithm=implemented_family,
                                declaring_function=target_name,
                                declaring_branch_condition=branch_cond,
                                declaring_evidence=declaring_ev,
                                call_site_function=caller_name,
                                call_site_evidence=call_ev,
                                description=desc,
                                severity="high",
                            )
                        )

    by_id: dict[str, AlgorithmDivergenceFinding] = {f.id: f for f in findings}
    return sorted(by_id.values(), key=lambda f: f.id)
