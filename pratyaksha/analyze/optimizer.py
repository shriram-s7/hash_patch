"""pratyaksha/analyze/optimizer.py — Pillar 5 (Migration Optimiser)
scheduling.

Given a set of `OptimizerCandidate` (pratyaksha/analyze/cbom_reader.py, each
already carrying a real Pillar-2/3-derived or documented-default
`risk_score`/`cost_days`), a budget in engineer-days, and a parallelism
(how many findings can be worked on at once), this module produces:

  - a GREEDY RISK-DENSITY schedule: candidates sorted by
    `risk_score / cost_days` descending, greedily bin-packed into
    `parallelism` parallel work-slots (`schedule_greedy`), with a
    best-of-both-orderings safety net against a known pathology of pure
    density-greedy packing — see `_schedule_hybrid_greedy` and
    docs/OPTIMISER.md for the exact algorithm.
  - a NAIVE BASELINE schedule for comparison: the SAME bin-packing
    procedure, but ordered by `risk_score` alone, ignoring cost
    (`schedule_naive`) — see docs/OPTIMISER.md for why this, and not
    discovery order, is the fairer "naive" baseline to beat.
  - per named quantum-arrival scenario (`ontology/quantum_arrival.yaml`,
    pratyaksha/analyze/quantum_scenarios.py), a SCENARIO-ADJUSTED version
    of both schedules (`run_optimizer`) that discounts (never zeroes) the
    risk of a finding whose real Pillar-2 shelf-life would already have
    lapsed before that scenario's estimated CRQC-arrival year — see
    `_urgency_multiplier` and docs/OPTIMISER.md's "scenario urgency
    adjustment" section. This is what makes the 3 scenarios' plans
    genuinely differ, not just carry a different label.

Both the greedy and naive schedules are FEASIBLE bin-packings (every slot's
total assigned cost never exceeds `budget_days`) using the same model
`pratyaksha/analyze/optimizer_bruteforce.py`'s exact solver checks against
— see that module for the optimality-gap proof this design supports.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from pratyaksha.analyze.quantum_scenarios import (
    QuantumArrivalScenario,
    load_quantum_arrival_scenarios,
)
from pratyaksha.model.optimizer import (
    MigrationPlan,
    OptimizationReport,
    OptimizerCandidate,
    ResidualRiskPoint,
    ScenarioResult,
    ScheduledFinding,
)

# The risk multiplier applied when a finding's real (non-default)
# Pillar-2 shelf-life would already have lapsed BEFORE a scenario's
# estimated CRQC-arrival year -- i.e. the data this asset protects is
# plausibly already safe to disclose by the time a quantum computer capable
# of breaking it exists, under that scenario. Never 0: a shelf-life figure
# is itself a heuristic estimate (docs/SHELF_LIFE.md), not a certainty, so
# "probably already safe" is discounted, not eliminated. See
# docs/OPTIMISER.md.
_SCENARIO_SAFE_DISCOUNT = 0.35

# Number of samples (inclusive of both endpoints) making up a residual-risk
# curve -- deliberately small and fixed regardless of budget size, so
# output stays a readable, bounded size. "Regular day intervals" per the
# task description; the interval itself is budget_days / (N-1), not
# necessarily a whole number of days for a small budget.
_RESIDUAL_CURVE_SAMPLE_COUNT = 21


def _urgency_multiplier(
    candidate: OptimizerCandidate, scenario: QuantumArrivalScenario, reference_year: int
) -> float:
    """1.0 unless we have REAL (non-default) Pillar-2 shelf-life evidence
    AND that evidence says the data's secrecy window ends before this
    scenario's estimated CRQC-arrival year -- see module docstring.
    Never discounts a finding with no real shelf-life signal (honesty rule
    mirrored from pratyaksha/analyze/shelf_life.py: "no data" must never be
    silently treated as "no risk", extended here to "no data" must never be
    silently treated as "safe under this scenario" either).
    """
    if candidate.shelf_life_is_default:
        return 1.0
    expiry_year = reference_year + candidate.shelf_life_years
    if expiry_year > scenario.estimated_year:
        return 1.0
    return _SCENARIO_SAFE_DISCOUNT


def _scenario_risk_lookup(
    candidates: Sequence[OptimizerCandidate],
    scenario: QuantumArrivalScenario | None,
    reference_year: int | None,
) -> dict[str, float]:
    if scenario is None:
        return {c.finding_id: c.risk_score for c in candidates}
    assert reference_year is not None
    return {
        c.finding_id: c.risk_score * _urgency_multiplier(c, scenario, reference_year)
        for c in candidates
    }


def _residual_risk_curve(
    candidates: Sequence[OptimizerCandidate],
    schedule: Sequence[ScheduledFinding],
    total_risk: float,
    budget_days: float,
) -> list[ResidualRiskPoint]:
    completion = {sf.finding_id: (sf.end_day, sf.scenario_risk_score) for sf in schedule}
    if budget_days <= 0:
        eliminated = sum(risk for end_day, risk in completion.values() if end_day <= 0)
        return [ResidualRiskPoint(day=0.0, residual_risk=total_risk - eliminated)]

    step = budget_days / (_RESIDUAL_CURVE_SAMPLE_COUNT - 1)
    curve: list[ResidualRiskPoint] = []
    for i in range(_RESIDUAL_CURVE_SAMPLE_COUNT):
        day = min(i * step, budget_days)
        eliminated = sum(risk for end_day, risk in completion.values() if end_day <= day)
        curve.append(ResidualRiskPoint(day=day, residual_risk=total_risk - eliminated))
    return curve


def _schedule(
    candidates: Sequence[OptimizerCandidate],
    risk_lookup: dict[str, float],
    sort_key: Callable[[OptimizerCandidate], tuple],
    budget_days: float,
    parallelism: int,
    ordering: str,
) -> MigrationPlan:
    """Shared bin-packing procedure for both the greedy and naive
    orderings: process candidates in `sort_key` order, always placing the
    next one into whichever of `parallelism` work-slots currently has the
    LEAST assigned load, skipping (leaving unmigrated) any candidate that
    does not fit in that least-loaded slot within `budget_days` — see
    docs/OPTIMISER.md for why "least-loaded slot" and why skip-not-stop.
    """
    total_risk = sum(risk_lookup.values())
    ordered = sorted(candidates, key=sort_key)

    slot_loads = [0.0] * max(parallelism, 1)
    schedule: list[ScheduledFinding] = []
    unmigrated: list[str] = []

    for candidate in ordered:
        idx = min(range(len(slot_loads)), key=lambda i: (slot_loads[i], i))
        start = slot_loads[idx]
        end = start + candidate.cost_days
        if end <= budget_days + 1e-9:
            slot_loads[idx] = end
            schedule.append(
                ScheduledFinding(
                    finding_id=candidate.finding_id,
                    name=candidate.name,
                    start_day=start,
                    end_day=end,
                    cost_days=candidate.cost_days,
                    scenario_risk_score=risk_lookup[candidate.finding_id],
                )
            )
        else:
            # Doesn't fit in the LEAST loaded slot (so it cannot fit in any
            # slot) at this point in the schedule -- but a smaller/cheaper
            # candidate considered later still might, so keep going rather
            # than stopping the whole loop here.
            unmigrated.append(candidate.finding_id)

    eliminated_risk = sum(sf.scenario_risk_score for sf in schedule)
    pct = (eliminated_risk / total_risk * 100.0) if total_risk > 0 else 0.0

    return MigrationPlan(
        ordering=ordering,  # type: ignore[arg-type]
        schedule=schedule,
        unmigrated_finding_ids=unmigrated,
        total_risk=total_risk,
        eliminated_risk=eliminated_risk,
        risk_eliminated_pct=pct,
        residual_risk_curve=_residual_risk_curve(candidates, schedule, total_risk, budget_days),
    )


def _density_key(risk_lookup: dict[str, float]) -> Callable[[OptimizerCandidate], tuple]:
    def key(c: OptimizerCandidate) -> tuple:
        density = risk_lookup[c.finding_id] / c.cost_days if c.cost_days > 0 else float("inf")
        return (-density, c.finding_id)

    return key


def _value_key(risk_lookup: dict[str, float]) -> Callable[[OptimizerCandidate], tuple]:
    def key(c: OptimizerCandidate) -> tuple:
        return (-risk_lookup[c.finding_id], c.finding_id)

    return key


def _schedule_hybrid_greedy(
    candidates: Sequence[OptimizerCandidate],
    risk_lookup: dict[str, float],
    budget_days: float,
    parallelism: int,
) -> MigrationPlan:
    """The optimiser: bin-packs candidates TWO ways -- by risk-density
    (risk_score / cost_days) descending, and by raw risk_score descending
    (the same ordering `schedule_naive`/naive baseline uses) -- and returns
    WHICHEVER eliminates more total risk.

    This "best of both" hybrid is a well-known, standard fix for a real,
    documented failure mode of pure density-greedy 0/1-knapsack packing:
    density-first ordering can, on some instances, waste a slot on a
    high-density-but-low-absolute-value item and end up worse than simply
    taking the single highest-value item that fits -- found empirically on
    this project's own optimizer corpus (parallelism=2, budget=3.0 days:
    pure density-greedy eliminated less risk than the naive baseline).
    Rather than paper over that with a hand-picked "nicer" demo budget,
    this hybrid GUARANTEES `schedule_greedy` never eliminates less total
    risk than `schedule_naive` on the SAME (budget, parallelism, risk
    values) — naive's own ordering is literally one of the two candidates
    this function chooses between. See docs/OPTIMISER.md and
    tests/unit/test_optimizer.py::test_optimizer_never_worse_than_naive_*.

    Ties (both orderings eliminate exactly the same total risk) prefer the
    density-ordered plan, deterministically.
    """
    density_plan = _schedule(
        candidates, risk_lookup, _density_key(risk_lookup), budget_days, parallelism, "greedy_risk_density"
    )
    value_plan = _schedule(
        candidates, risk_lookup, _value_key(risk_lookup), budget_days, parallelism, "greedy_risk_density"
    )
    return density_plan if density_plan.eliminated_risk >= value_plan.eliminated_risk else value_plan


def schedule_greedy(
    candidates: Sequence[OptimizerCandidate], budget_days: float, parallelism: int
) -> MigrationPlan:
    """The optimiser, using each candidate's own plain Pillar-2/3
    `risk_score` (scenario-independent) -- the schedule
    `pratyaksha/analyze/optimizer_bruteforce.py` checks against. See
    `_schedule_hybrid_greedy` for the algorithm.
    """
    risk_lookup = _scenario_risk_lookup(candidates, None, None)
    return _schedule_hybrid_greedy(candidates, risk_lookup, budget_days, parallelism)


def schedule_naive(
    candidates: Sequence[OptimizerCandidate], budget_days: float, parallelism: int
) -> MigrationPlan:
    """The naive baseline: candidates ordered by risk_score ALONE
    (ignoring cost) -- "fix the scariest-looking things first", a common
    real-world naive prioritisation, and the ordering the optimiser must
    beat. See docs/OPTIMISER.md for why this, not discovery order, is the
    fairer baseline.
    """
    risk_lookup = _scenario_risk_lookup(candidates, None, None)
    return _schedule(
        candidates, risk_lookup, _value_key(risk_lookup), budget_days, parallelism, "naive_risk_only"
    )


def _headline_message(
    scenario: QuantumArrivalScenario, optimizer_plan: MigrationPlan, naive_plan: MigrationPlan
) -> str:
    # 2 decimal places: on this pillar's discrete inputs (year-valued
    # shelf-life categories, 0.5-day cost increments), the greedy-vs-naive
    # gap at a given budget checkpoint is sometimes genuinely small -- see
    # docs/OPTIMISER.md's worked example -- and 1 decimal place can round
    # two DIFFERENT real percentages to the same displayed value.
    return (
        f"Scenario '{scenario.scenario_name}' (~{scenario.estimated_year}): "
        f"optimiser eliminates {optimizer_plan.risk_eliminated_pct:.2f}% risk vs "
        f"{naive_plan.risk_eliminated_pct:.2f}% naive at same budget."
    )


def run_optimizer(
    candidates: Sequence[OptimizerCandidate],
    budget_days: float,
    parallelism: int,
    reference_year: int,
    scenarios: Sequence[QuantumArrivalScenario] | None = None,
    excluded_count: int = 0,
) -> OptimizationReport:
    """End-to-end entry point used by `pratyaksha optimize`
    (pratyaksha/cli.py): for each quantum-arrival scenario, compute a
    scenario-adjusted greedy plan and naive baseline (see module docstring
    on the scenario urgency multiplier), and the headline risk-reduction
    comparison line.
    """
    scenario_list = list(scenarios) if scenarios is not None else load_quantum_arrival_scenarios()

    results: list[ScenarioResult] = []
    for scenario in scenario_list:
        risk_lookup = _scenario_risk_lookup(candidates, scenario, reference_year)

        optimizer_plan = _schedule_hybrid_greedy(candidates, risk_lookup, budget_days, parallelism)
        naive_plan = _schedule(
            candidates, risk_lookup, _value_key(risk_lookup), budget_days, parallelism, "naive_risk_only"
        )

        results.append(
            ScenarioResult(
                scenario_name=scenario.scenario_name,
                estimated_year=scenario.estimated_year,
                probability_weight=scenario.probability_weight,
                optimizer_plan=optimizer_plan,
                naive_plan=naive_plan,
                headline_message=_headline_message(scenario, optimizer_plan, naive_plan),
            )
        )

    return OptimizationReport(
        budget_days=budget_days,
        parallelism=parallelism,
        candidate_count=len(candidates),
        excluded_count=excluded_count,
        reference_year=reference_year,
        scenarios=results,
    )
