"""hash_patch/analyze/call_relations.py — direct caller/callee edges between
findings, for the UI's "Asset Relationships" graph.

Reuses the exact same call graph reachability classification already builds
(hash_patch/analyze/reachability.py::build_reachability_contexts) rather than
re-parsing the file set: two findings are related if the function enclosing
one evidence occurrence of the first has a DIRECT (one-hop, not transitive)
caller/callee edge to the function enclosing an evidence occurrence of the
second, per the same name-resolved call graph
(hash_patch/analyze/callgraph.py) used for reachability. Python, Java, and
C/C++ evidence all participate — Go is out of scope for the call graph
entirely (see docs/REACHABILITY.md).
"""

from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path, PurePosixPath

from hash_patch.analyze.callgraph import FunctionId
from hash_patch.analyze.reachability import ReachabilityContext
from hash_patch.model.assets import CryptoAsset


def _func_to_label(func: FunctionId, target_root: Path | None = None) -> str:
    if target_root is not None:
        try:
            rel = Path(func.file).relative_to(target_root)
            parts = list(rel.with_suffix("").parts)
            if parts and parts[-1] == "__init__":
                parts.pop()
            mod = ".".join(parts)
            return f"{mod}.{func.qualname}"
        except ValueError:
            pass
    stem = Path(func.file).stem
    return f"{stem}.{func.qualname}"


def compute_call_graph_edges(
    contexts: dict[str, ReachabilityContext],
    target_root: Path | None = None,
) -> list[dict[str, str]]:
    """Compute all direct function-to-function call graph edges across all contexts.

    Omits synthetic execution blocks (e.g. `__main_block__`) and deduplicates
    edges. Returns a deterministically sorted list of {"caller": ..., "callee": ...}.
    """
    edges: set[tuple[str, str]] = set()
    for ctx in contexts.values():
        for caller, callees in ctx.graph.edges.items():
            if "__main_block__" in caller.qualname:
                continue
            c_str = _func_to_label(caller, target_root)
            for callee in callees:
                if "__main_block__" in callee.qualname:
                    continue
                t_str = _func_to_label(callee, target_root)
                edges.add((c_str, t_str))

    return [
        {"caller": c, "callee": t}
        for c, t in sorted(edges, key=lambda p: (p[0], p[1]))
    ]


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


# Real codebases overwhelmingly route crypto calls through thin orchestrator
# functions (`authenticate`, `create_payment`, `protect_document`, ...) that
# enclose no evidence of their own -- they just delegate. A pure single-hop
# caller/callee check between two assets' DIRECTLY enclosing functions almost
# never fires on such code: the orchestrator sits in between and is invisible
# to that check. So relation-finding has to walk THROUGH orchestrator
# (zero-finding) functions rather than stop at the first one, treating them as
# transparent pass-through nodes that are never themselves a relation
# endpoint. Depth-capped and visited-tracked, so a cycle in the function graph
# (mutual recursion, etc.) can never hang this -- it just terminates the
# branch early once every reachable node has been seen.
_MAX_ORCHESTRATOR_HOPS = 8


def _finding_bearing_reachable(
    start: FunctionId,
    edge_map: dict[FunctionId, set[FunctionId]],
    assets_by_function: dict[FunctionId, set[str]],
    max_hops: int = _MAX_ORCHESTRATOR_HOPS,
) -> set[FunctionId]:
    """Functions reachable from `start` by following `edge_map` (either the
    forward call graph or its reverse), stopping at -- and never expanding
    past -- the first finding-bearing function on each branch. Orchestrator
    (zero-finding) functions in between are walked through transparently.
    """
    found: set[FunctionId] = set()
    visited: set[FunctionId] = {start}
    frontier: deque[tuple[FunctionId, int]] = deque(
        (n, 1) for n in edge_map.get(start, ())
    )
    while frontier:
        node, depth = frontier.popleft()
        if node in visited:
            continue
        visited.add(node)
        if node in assets_by_function:
            found.add(node)
            continue  # a finding is a relation endpoint, never a pass-through
        if depth >= max_hops:
            continue
        for nxt in edge_map.get(node, ()):
            if nxt not in visited:
                frontier.append((nxt, depth + 1))
    return found


def _sibling_finding_bearing(
    start: FunctionId,
    forward: dict[FunctionId, set[FunctionId]],
    reverse: dict[FunctionId, set[FunctionId]],
    assets_by_function: dict[FunctionId, set[str]],
    max_hops: int = _MAX_ORCHESTRATOR_HOPS,
) -> set[FunctionId]:
    """Finding-bearing functions that are "siblings" of `start`: both
    delegated to by the same ancestor orchestrator, with neither transitively
    calling the other. Neither a pure-forward nor a pure-backward walk from
    `start` can ever find these -- reaching a sibling requires climbing
    backward to the shared ancestor and then heading forward again, a
    direction change neither single-direction walk makes.

    Climbs backward through orchestrator (zero-finding) functions ONLY as
    long as each one purely passes through (a single forward child -- no
    branch). The moment climbing reaches a function with more than one
    forward child, that's the nearest ancestor that actually fans out to
    more than one thing; its OTHER branches (not the one `start` came from)
    are the siblings, and climbing stops there. Continuing to climb past a
    fan-out point would keep pulling in every unrelated branch all the way up
    to the program's single top-level entry point, collapsing the whole call
    tree into one clique -- the opposite of what "sibling" is meant to mean.
    """
    found: set[FunctionId] = set()
    visited: set[FunctionId] = {start}
    frontier: deque[FunctionId] = deque(reverse.get(start, set()))
    hops = 0
    while frontier and hops < max_hops:
        hops += 1
        for _ in range(len(frontier)):
            node = frontier.popleft()
            if node in visited:
                continue
            visited.add(node)
            children = forward.get(node, set())
            if len(children) >= 2:
                # Fan-out boundary: harvest sibling branches, stop climbing past it.
                for child in children:
                    if child in visited:
                        continue
                    if child in assets_by_function:
                        found.add(child)
                    else:
                        found |= _finding_bearing_reachable(
                            child, forward, assets_by_function, max(max_hops - hops, 1)
                        )
            else:
                # Pure passthrough (0 or 1 forward child): keep climbing.
                for caller in reverse.get(node, set()):
                    if caller not in visited:
                        frontier.append(caller)
    return found


def compute_call_relations(
    assets: list[CryptoAsset], contexts: dict[str, ReachabilityContext]
) -> dict[str, dict[str, list[str]]]:
    """For each asset, the set of OTHER assets whose enclosing function is a
    caller / callee of one of this asset's enclosing functions -- direct, OR
    transitively through a chain of orchestrator functions that enclose no
    evidence of their own (see `_finding_bearing_reachable` /
    `_sibling_finding_bearing`). Orchestrator functions are always
    pass-through: they never become a relation endpoint and never appear as a
    node anywhere in this output, matching the UI's "findings only" node
    model for the Relationships graph.

    Returns `{asset_id: {"callers": [asset_id, ...], "callees": [asset_id, ...]}}`,
    sorted for determinism, omitting any asset with no relations at all (an
    empty dict entry would carry no information and CLAUDE.md hard constraint
    #2 requires deterministic, minimal output). A same-orchestrator "sibling"
    relation (neither asset transitively calls the other; they're both
    delegated to by a shared ancestor) has no natural caller/callee direction
    of its own, so it is recorded symmetrically in both assets' `callees`.
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
            forward = ctx.graph.edges
            reverse = ctx.graph.reverse_edges

            callee_funcs = _finding_bearing_reachable(func, forward, assets_by_function)
            caller_funcs = _finding_bearing_reachable(func, reverse, assets_by_function)
            sibling_funcs = (
                _sibling_finding_bearing(func, forward, reverse, assets_by_function)
                - callee_funcs
                - caller_funcs
            )

            for callee_func in callee_funcs:
                callee_ids.update(assets_by_function.get(callee_func, ()))
            for caller_func in caller_funcs:
                caller_ids.update(assets_by_function.get(caller_func, ()))
            for sibling_func in sibling_funcs:
                callee_ids.update(assets_by_function.get(sibling_func, ()))

        caller_ids.discard(asset.id)
        callee_ids.discard(asset.id)
        if not caller_ids and not callee_ids:
            continue

        relations[asset.id] = {
            "callers": sorted(caller_ids),
            "callees": sorted(callee_ids),
        }

    return relations
