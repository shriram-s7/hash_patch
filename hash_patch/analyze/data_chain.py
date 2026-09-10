"""hash_patch/analyze/data_chain.py — same-function data-flow chains between
Java crypto calls, for the UI's "Asset Relationships" graph.

This is a SEPARATE, narrower analysis from
hash_patch/analyze/call_relations.py, not an extension of it.
call_relations.py answers "does finding A's enclosing function directly
call finding B's enclosing function" (cross-function call-graph adjacency).
This module answers a different question entirely: "within ONE function,
does crypto call B's argument expression literally carry crypto call A's
output" — e.g. `chaChaCipher.doFinal(aesCipher.doFinal(rsaCipher.doFinal(pt)))`,
or the same thing spread across statements via a local variable. Two crypto
calls sharing an enclosing function (call_relations.py's blind spot) say
nothing on their own about whether one feeds the other — this module is
what actually answers that, and only when it can prove it structurally.

Why this needs TWO levels of variable tracking, not one: a Hash Patch Java
finding's evidence line is always the `getInstance(...)`-family factory
call (hash_patch/detect/java.py) — e.g. `Cipher.getInstance("AES/GCM/NoPadding")`
— never the later `cipher.doFinal(...)` call that actually produces
ciphertext or `keygen.generateKey(...)` that produces key material. So
`var_map` here tracks BOTH:
  (1) an object variable bound to an asset's factory call
      (`Cipher aesCipher = Cipher.getInstance(...)` -> aesCipher: AES asset), and
  (2) a data/key variable bound to whichever asset's object-bound call produced it
      (`byte[] aesEncrypted = aesCipher.doFinal(...)` -> aesEncrypted: AES asset, or
       `SecretKey aesKey = aesGenerator.generateKey()` -> aesKey: AES keygen asset, or
       `KeyPair rsaKeys = rsaGenerator.generateKeyPair()` -> rsaKeys: RSA keygen asset),
using the SAME map, because both are just "this name currently carries
asset X's identity" from the analysis's point of view. A call's method name
(doFinal, generateKey, generateKeyPair, init, digest, sign, ...) is
deliberately never hardcoded here — ANY method invoked on an asset-bound
receiver counts as belonging to that asset, so a chain is detected
structurally (receiver resolves to asset B, one of its arguments resolves to
asset A) rather than by a per-algorithm method-name allowlist.

Definitive rule for what counts as a data chain:
A directed data-flow chain edge (A -> B) is formed whenever:
  (a) Ciphertext output chaining: cipher A's output feeds cipher B (e.g.
      `aes.doFinal(rsa.doFinal(pt))` or `c = rsa.doFinal(pt); aes.doFinal(c)`).
  (b) Key-material binding: keygen A's generated key/keypair is passed to
      cipher B's initialization (e.g. `key = aesKg.generateKey(); aes.init(mode, key)`
      or `keys = rsaKpg.generateKeyPair(); rsa.init(mode, keys.getPublic())`).
A keygen remains isolated if and only if its generated key material is not
passed to any cipher or other crypto operation (e.g. unused keygen variables).

Scope — Java only, deliberately narrow (see the task that added this):
  - A chain edge A -> B is recorded when B's call has an argument that is
    either (a) A's method_invocation nested directly as that argument
    (either A's own getInstance call, or a call whose receiver resolves to
    A), or (b) a bare local variable whose most recent assignment, at the
    SAME flat top-level statement sequence of the method body, resolves to
    asset A, with nothing else assigned to that name in between.
  - Only the method body's own direct (top-level) statements are walked.
    A statement nested inside an `if`/`for`/`while`/etc. block is a child
    of THAT block, not of the method body, so it is simply never visited —
    this is what makes "no conditional/loop tracking" and "no intervening
    reassignment" hold for free: an assignment or use hidden inside a
    nested block can never enter `var_map`, so the analysis fails closed
    to no-edge rather than guessing about a branch it never inspected.
  - Only bare local identifiers are tracked as variables. Field/instance
    access (`this.x`, `obj.field`) is a different node shape
    (`field_access`, not `identifier`) and is therefore never matched —
    field-variable chains are out of scope, not silently approximated.

This is intentionally a light def-use check over one method body, not
general intra-procedural data-flow analysis — see docs/COVERAGE.md.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from hash_patch.analyze.reachability import ReachabilityContext
from hash_patch.model.assets import CryptoAsset

_JAVA_SUFFIX = ".java"


def _first_child_of_type(node: Any, type_name: str) -> Any | None:
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def _decl_name_and_value(declarator: Any) -> tuple[str, Any] | None:
    """`variable_declarator` := identifier ('=' value)? — pull out the plain
    (name, value_node) pair, or None for a declaration with no initializer.
    """
    name_node = None
    eq_seen = False
    value_node = None
    for child in declarator.children:
        if child.type == "identifier" and name_node is None:
            name_node = child
        elif child.type == "=":
            eq_seen = True
        elif eq_seen and value_node is None:
            value_node = child
    if name_node is None or value_node is None:
        return None
    return name_node.text.decode("utf-8", errors="replace"), value_node


def _top_level_assignment(stmt: Any) -> tuple[str, Any] | None:
    """If `stmt` is a plain `T x = value;` declaration or `x = value;`
    assignment (no compound operators, no destructuring), return
    (name, value_node); else None.
    """
    if stmt.type == "local_variable_declaration":
        declarator = _first_child_of_type(stmt, "variable_declarator")
        return _decl_name_and_value(declarator) if declarator is not None else None
    if stmt.type == "expression_statement" and stmt.children:
        expr = stmt.children[0]
        if expr.type == "assignment_expression":
            children = list(expr.children)
            if len(children) >= 3 and children[0].type == "identifier" and children[1].type == "=":
                return children[0].text.decode("utf-8", errors="replace"), children[2]
    return None


def _collect_invocations(node: Any, out: list[Any]) -> None:
    if node.type == "method_invocation":
        out.append(node)
    for child in node.children:
        _collect_invocations(child, out)


def _receiver_name(invocation: Any) -> str | None:
    """For `receiver.name(args)`, return `receiver`'s bare identifier text,
    or None for anything else (a static/simple call with no receiver, a
    field-access or nested-expression receiver, `this.name(...)`, etc.) —
    mirrors hash_patch/analyze/callgraph.py::_java_call_shape's structural
    read of the same node shape, kept independent rather than imported
    since that function's return shape also encodes call-graph-specific
    "this"/"dynamic" cases this module has no use for.
    """
    children = list(invocation.children)
    arg_idx = next((i for i, c in enumerate(children) if c.type == "argument_list"), None)
    if arg_idx is None or arg_idx < 3:
        return None
    name_node = children[arg_idx - 1]
    dot_node = children[arg_idx - 2]
    receiver_node = children[arg_idx - 3]
    if name_node.type != "identifier" or dot_node.type != "." or receiver_node.type != "identifier":
        return None
    return receiver_node.text.decode("utf-8", errors="replace")


def _resolve_asset_for_invocation(
    invocation: Any, var_map: dict[str, str], line_to_asset: dict[int, str]
) -> str | None:
    """Which asset does this method_invocation "belong to" — either it IS a
    tracked getInstance-family call itself, or it's a call on a receiver
    already bound (via var_map) to a tracked asset.
    """
    direct = line_to_asset.get(invocation.start_point.row + 1)
    if direct is not None:
        return direct
    receiver = _receiver_name(invocation)
    return var_map.get(receiver) if receiver is not None else None


def _resolve_asset_for_expr(node: Any, var_map: dict[str, str], line_to_asset: dict[int, str]) -> str | None:
    if node.type == "method_invocation":
        return _resolve_asset_for_invocation(node, var_map, line_to_asset)
    if node.type == "identifier":
        return var_map.get(node.text.decode("utf-8", errors="replace"))
    return None


def _invocation_method_name(invocation: Any) -> str | None:
    """For `receiver.name(args)` or `name(args)`, return the method name identifier text."""
    children = list(invocation.children)
    arg_idx = next((i for i, c in enumerate(children) if c.type == "argument_list"), None)
    if arg_idx is None or arg_idx < 1:
        return None
    name_node = children[arg_idx - 1]
    if name_node.type != "identifier":
        return None
    return name_node.text.decode("utf-8", errors="replace")


def _chains_in_function(body: Any, line_to_asset: dict[int, str]) -> set[tuple[str, str, str]]:
    """Walk the method body's direct statements in source order, tracking
    each local variable's most recent top-level asset binding and role
    (see module docstring), and recording (source_asset_id, target_asset_id, chain_type)
    chain edges where chain_type is 'ciphertext' or 'key_material'.
    """
    var_map: dict[str, str] = {}
    var_kind: dict[str, str] = {}
    edges: set[tuple[str, str, str]] = set()

    for stmt in body.children:
        if not stmt.is_named:
            continue

        invocations: list[Any] = []
        _collect_invocations(stmt, invocations)
        for inv in invocations:
            target_asset = _resolve_asset_for_invocation(inv, var_map, line_to_asset)
            if target_asset is None:
                continue
            arg_list = _first_child_of_type(inv, "argument_list")
            if arg_list is None:
                continue
            method_name = _invocation_method_name(inv) or ""
            for arg in arg_list.children:
                if not arg.is_named:
                    continue
                source_asset = _resolve_asset_for_expr(arg, var_map, line_to_asset)
                if source_asset is not None and source_asset != target_asset:
                    arg_name = arg.text.decode("utf-8", errors="replace") if arg.type == "identifier" else ""
                    is_key = (
                        method_name.startswith("init")
                        or var_kind.get(arg_name) == "key_material"
                    )
                    chain_type = "key_material" if is_key else "ciphertext"
                    edges.add((source_asset, target_asset, chain_type))

        assignment = _top_level_assignment(stmt)
        if assignment is not None:
            name, value_node = assignment
            asset_id = _resolve_asset_for_expr(value_node, var_map, line_to_asset)
            if asset_id is not None:
                var_map[name] = asset_id
                val_method = _invocation_method_name(value_node) if value_node.type == "method_invocation" else None
                if val_method in ("generateKey", "generateKeyPair", "getPublic", "getPrivate"):
                    var_kind[name] = "key_material"
                elif val_method in ("doFinal", "update", "digest", "sign"):
                    var_kind[name] = "ciphertext"
                else:
                    var_kind.pop(name, None)
            else:
                # Reassigned to something with no provable asset binding —
                # the variable no longer carries a provable chain, so drop
                # it rather than keep a stale mapping.
                var_map.pop(name, None)
                var_kind.pop(name, None)

    return edges


def compute_data_chains(
    assets: list[CryptoAsset], contexts: dict[str, ReachabilityContext]
) -> dict[str, dict[str, Any]]:
    """Java-only same-function data-chain edges.

    Returns `{asset_id: {"chainSources": [...], "chainTargets": [...], "edges": [...]}}`,
    sorted for determinism, omitting any asset with no chain edges at all
    (mirrors hash_patch/analyze/call_relations.py::compute_call_relations'
    output-minimality convention).
    """
    ctx = contexts.get(_JAVA_SUFFIX)
    if ctx is None:
        return {}

    line_to_asset_by_file: dict[str, dict[int, str]] = defaultdict(dict)
    for asset in assets:
        for ev in asset.evidence:
            if ev.source_type != "source" or ev.line is None:
                continue
            if PurePosixPath(ev.locator.replace("\\", "/")).suffix.lower() != _JAVA_SUFFIX:
                continue
            line_to_asset_by_file[ev.locator.replace("\\", "/")][ev.line] = asset.id

    all_edges: set[tuple[str, str, str]] = set()
    for func_info in ctx.graph.function_infos:
        if func_info.node is None:
            continue
        file_key = func_info.id.file.replace("\\", "/")
        line_to_asset = line_to_asset_by_file.get(file_key)
        if not line_to_asset or len(line_to_asset) < 2:
            continue
        body = _first_child_of_type(func_info.node, "block")
        if body is None:
            continue
        all_edges.update(_chains_in_function(body, line_to_asset))

    result: dict[str, dict[str, Any]] = {}
    for source, target, chain_type in all_edges:
        result.setdefault(source, {"chainSources": [], "chainTargets": [], "edges": []})["chainTargets"].append(target)
        result.setdefault(target, {"chainSources": [], "chainTargets": [], "edges": []})["chainSources"].append(source)
        edge_dict = {"source": source, "target": target, "chainType": chain_type}
        if edge_dict not in result[source]["edges"]:
            result[source]["edges"].append(edge_dict)
        if edge_dict not in result[target]["edges"]:
            result[target]["edges"].append(edge_dict)

    for entry in result.values():
        entry["chainSources"] = sorted(set(entry["chainSources"]))
        entry["chainTargets"] = sorted(set(entry["chainTargets"]))
        entry["edges"] = sorted(entry["edges"], key=lambda e: (e["source"], e["target"], e["chainType"]))
        edge_types = {e["chainType"] for e in entry["edges"]}
        if len(edge_types) == 1:
            entry["chainType"] = next(iter(edge_types))
    return result
