from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CostSource = Literal["blast_radius", "default"]
ScheduleOrdering = Literal["greedy_risk_density", "naive_risk_only"]


class OptimizerCandidate(BaseModel):
    """One migration candidate parsed from an already-emitted CBOM
    (pratyaksha/analyze/cbom_reader.py) — every field here is read from a
    real `pratyaksha:` property already attached to that CBOM component by
    P1/P2/P3, never invented. Only components whose
    `pratyaksha:quantumStatus` is `broken-by-shor` become candidates at all
    — see pratyaksha/analyze/risk_score.py::is_migration_candidate and
    docs/OPTIMISER.md for why broken-classically/weakened-by-grover findings
    are out of scope for this pillar.

    `shelf_life_is_default` / `cost_source` make clear, per CLAUDE.md's
    honesty conventions, when a figure came from real P2/P3 data versus a
    documented low-confidence fallback — never silently blur the two.
    """

    model_config = ConfigDict(frozen=False)

    finding_id: str  # CBOM bom-ref
    name: str
    reachability: str  # Reachability enum value, as recorded in the CBOM
    shelf_life_years: int
    shelf_life_category: str | None  # None when shelf_life_is_default is True
    shelf_life_is_default: bool
    cost_days: float
    cost_source: CostSource
    risk_score: float


class ScheduledFinding(BaseModel):
    model_config = ConfigDict(frozen=False)

    finding_id: str
    name: str
    start_day: float
    end_day: float
    cost_days: float
    scenario_risk_score: float


class ResidualRiskPoint(BaseModel):
    model_config = ConfigDict(frozen=False)

    day: float
    residual_risk: float


class MigrationPlan(BaseModel):
    """One schedule (either the greedy risk-density optimiser or the naive
    baseline) for one quantum-arrival scenario — see
    pratyaksha/analyze/optimizer.py and docs/OPTIMISER.md.
    """

    model_config = ConfigDict(frozen=False)

    ordering: ScheduleOrdering
    schedule: list[ScheduledFinding] = Field(default_factory=list)
    unmigrated_finding_ids: list[str] = Field(default_factory=list)
    total_risk: float
    eliminated_risk: float
    risk_eliminated_pct: float
    residual_risk_curve: list[ResidualRiskPoint] = Field(default_factory=list)


class ScenarioResult(BaseModel):
    model_config = ConfigDict(frozen=False)

    scenario_name: str
    estimated_year: int
    probability_weight: float
    optimizer_plan: MigrationPlan
    naive_plan: MigrationPlan
    headline_message: str


class OptimalityGapResult(BaseModel):
    """Output of pratyaksha/analyze/optimizer_bruteforce.py's validation
    check — NOT part of the normal `pratyaksha optimize` CLI path (real
    scans routinely exceed the brute-force candidate cap). See
    docs/OPTIMISER.md.
    """

    model_config = ConfigDict(frozen=False)

    candidate_count: int
    greedy_eliminated_risk: float
    optimal_eliminated_risk: float
    optimality_gap_pct: float


class OptimizationReport(BaseModel):
    model_config = ConfigDict(frozen=False)

    budget_days: float
    parallelism: int
    candidate_count: int
    excluded_count: int  # components filtered out by is_migration_candidate
    reference_year: int  # from the input CBOM's metadata.timestamp
    scenarios: list[ScenarioResult] = Field(default_factory=list)
