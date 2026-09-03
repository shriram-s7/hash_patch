"""hash_patch/analyze/optimizer_bruteforce.py — Pillar 5 (Migration
Optimiser) optimality-gap validation.

This is a TESTING/VALIDATION TOOL, not part of the normal `pratyaksha
optimize` CLI path — see docs/OPTIMISER.md. Real scans routinely produce
more than `_MAX_BRUTE_FORCE_CANDIDATES` migration candidates, at which
point an exact solve becomes combinatorially infeasible; this module
refuses to run above that cap rather than hang.

The scheduling problem `hash_patch/analyze/optimizer.py::_schedule` solves
is exactly the MULTIPLE KNAPSACK problem: choose a subset of candidates and
partition it across `parallelism` identical-capacity (`budget_days`) bins,
maximizing total risk eliminated. `_schedule`'s greedy risk-density
heuristic is a fast approximation of this; `brute_force_optimal` below
explores the TRUE exact answer via branch-and-bound recursion (not a full
2^n * P^n enumeration — see its docstring for the two pruning rules that
keep it tractable at the sizes this module is meant for).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from hash_patch.analyze.optimizer import schedule_greedy
from hash_patch.model.optimizer import OptimalityGapResult, OptimizerCandidate

# Hard cap: refuse to brute-force above this many candidates rather than
# risk an unbounded-time search. This is a SAFETY guard, not a promise of
# fast execution up to exactly this many items at any parallelism -- keep
# real test instances well below this (this codebase's own tests use
# single-digit-to-low-teens instances specifically so the search completes
# near-instantly). See docs/OPTIMISER.md.
_MAX_BRUTE_FORCE_CANDIDATES = 15


@dataclass(frozen=True)
class BruteForceItem:
    finding_id: str
    risk: float
    cost: float


def _candidate_to_item(candidate: OptimizerCandidate) -> BruteForceItem:
    return BruteForceItem(finding_id=candidate.finding_id, risk=candidate.risk_score, cost=candidate.cost_days)


def brute_force_optimal(items: Sequence[BruteForceItem], budget_days: float, parallelism: int) -> float:
    """Exact maximum total risk eliminated, over every way of choosing a
    subset of `items` and assigning it across `parallelism` bins of
    capacity `budget_days` each (an item is assigned whole to one bin, or
    left out entirely -- no splitting, matching
    `hash_patch/analyze/optimizer.py::_schedule`'s own model).

    Two pruning rules keep this tractable at the sizes this module is
    meant for, without changing the answer:
      1. Branch-and-bound: items are visited highest-risk-first, and a
         branch is abandoned once "current total + every remaining item's
         risk" can no longer beat the best total found so far -- an
         admissible (never-too-low) upper bound, so this never prunes away
         the true optimum.
      2. Slot symmetry: the `parallelism` bins are interchangeable (all the
         same capacity), so trying to place an item into two DIFFERENT
         bins that currently hold the SAME total load is redundant -- only
         one representative per distinct current load is tried.
    """
    if len(items) > _MAX_BRUTE_FORCE_CANDIDATES:
        raise ValueError(
            f"refusing to brute-force {len(items)} items (cap is {_MAX_BRUTE_FORCE_CANDIDATES}) "
            "-- this is a small-instance validation tool, not a general scheduler"
        )
    if parallelism < 1:
        raise ValueError("parallelism must be >= 1")

    ordered = sorted(items, key=lambda it: -it.risk)
    n = len(ordered)
    suffix_max = [0.0] * (n + 1)
    for i in range(n - 1, -1, -1):
        suffix_max[i] = suffix_max[i + 1] + ordered[i].risk

    slot_loads = [0.0] * parallelism
    best = 0.0

    def recurse(i: int, current_total: float) -> None:
        nonlocal best
        best = max(best, current_total)
        if i == n:
            return
        if current_total + suffix_max[i] <= best:
            return  # cannot possibly beat the best found so far -- prune

        item = ordered[i]
        tried_loads: set[float] = set()
        for s in range(parallelism):
            load = slot_loads[s]
            if load in tried_loads:
                continue  # symmetry: an identical-load slot was already tried
            tried_loads.add(load)
            if load + item.cost <= budget_days + 1e-9:
                slot_loads[s] = load + item.cost
                recurse(i + 1, current_total + item.risk)
                slot_loads[s] = load
        recurse(i + 1, current_total)  # leave this item unmigrated

    recurse(0, 0.0)
    return best


def optimality_gap(
    candidates: Sequence[OptimizerCandidate], budget_days: float, parallelism: int
) -> OptimalityGapResult:
    """Compare hash_patch/analyze/optimizer.py::schedule_greedy's total
    eliminated risk against the true optimum from `brute_force_optimal` on
    the SAME (small) candidate set, budget, and parallelism. The gap is
    always >= 0: `schedule_greedy` produces one particular FEASIBLE
    schedule under this exact same multiple-knapsack model, and
    `brute_force_optimal` is the true maximum over every feasible schedule,
    so greedy can never do better.
    """
    greedy_plan = schedule_greedy(candidates, budget_days, parallelism)
    items = [_candidate_to_item(c) for c in candidates]
    optimal = brute_force_optimal(items, budget_days, parallelism)
    greedy_total = greedy_plan.eliminated_risk

    gap_pct = 0.0 if optimal <= 0 else max(0.0, (optimal - greedy_total) / optimal * 100.0)

    return OptimalityGapResult(
        candidate_count=len(candidates),
        greedy_eliminated_risk=greedy_total,
        optimal_eliminated_risk=optimal,
        optimality_gap_pct=gap_pct,
    )
