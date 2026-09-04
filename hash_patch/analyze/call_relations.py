"""hash_patch/analyze/call_relations.py — direct caller/callee edges between
findings, for the UI's "Asset Relationships" graph.

Reuses the exact same call graph reachability classification already builds
(hash_patch/analyze/reachability.py::build_reachability_contexts) rather than
re-parsing the file set: two findings are related if the function enclosing
one evidence occurrence of the first has a DIRECT (one-hop, not transitive)
caller/callee edge to the function enclosing an evidence occurrence of the
second, per the same name-resolved call graph
(hash_patch/analyze/callgraph.py) used for reachability. Only Python and Java
evidence participates — Go/C are out of scope for the call graph entirely
(see docs/REACHABILITY.md).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath

from hash_patch.analyze.callgraph import FunctionId
from hash_patch.analyze.reachability import ReachabilityContext
from hash_patch.model.assets import CryptoAsset


def _enclosing_functions(asset: CryptoAsset, contexts: dict[str, ReachabilityContext]) -> set[FunctionId]:
    """Every distinct function that encloses at least one of this asset's
    source-evidence occurrences, across every language context.
    """
    found: set[FunctionId] = set()
    for ev in asset.evidence:
        if ev.source_type != "source" or ev.line is None:
            continue
        suffix = PurePosixPath(ev.locator.replace("\\", "/")).suffix.lower()
        ctx = contexts.get(suffix)
        if ctx is None:
            continue
        func = ctx.graph.enclosing_function(ev.locator, ev.line)
        if func is not None:
            found.add(func)
    return found


def compute_call_relations(
    assets: list[CryptoAsset], contexts: dict[str, ReachabilityContext]
) -> dict[str, dict[str, list[str]]]:
    """For each asset, the set of OTHER assets whose enclosing function is a
    direct caller / direct callee of one of this asset's enclosing functions.

    Returns `{asset_id: {"callers": [asset_id, ...], "callees": [asset_id, ...]}}`,
    sorted for determinism, omitting any asset with no relations at all (an
    empty dict entry would carry no information and CLAUDE.md hard constraint
    #2 requires deterministic, minimal output).
    """
    if not contexts:
        return {}

    asset_functions: dict[str, set[FunctionId]] = {
        asset.id: _enclosing_functions(asset, contexts) for asset in assets
    }

    # Reverse index: which asset ids does a given function enclose? A
    # function can enclose more than one asset's evidence (e.g. two crypto
    # calls in the same method), and an asset can be enclosed by more than
    # one function (evidence in multiple places) — this is a many-to-many map.
    assets_by_function: dict[FunctionId, set[str]] = defaultdict(set)
    for asset_id, funcs in asset_functions.items():
        for func in funcs:
            assets_by_function[func].add(asset_id)

    relations: dict[str, dict[str, list[str]]] = {}
    for asset in assets:
        funcs = asset_functions.get(asset.id, set())
        if not funcs:
            continue

        caller_ids: set[str] = set()
        callee_ids: set[str] = set()
        for func in funcs:
            ctx = contexts.get(PurePosixPath(func.file.replace("\\", "/")).suffix.lower())
            if ctx is None:
                continue
            for caller_func in ctx.graph.reverse_edges.get(func, ()):
                caller_ids.update(assets_by_function.get(caller_func, ()))
            for callee_func in ctx.graph.edges.get(func, ()):
                callee_ids.update(assets_by_function.get(callee_func, ()))

        caller_ids.discard(asset.id)
        callee_ids.discard(asset.id)
        if not caller_ids and not callee_ids:
            continue

        relations[asset.id] = {
            "callers": sorted(caller_ids),
            "callees": sorted(callee_ids),
        }

    return relations
