"""tests/unit/test_risk_score.py

Unit tests for Pillar 5 (Migration Optimiser) risk scoring and cost
estimation: pratyaksha/analyze/risk_score.py.

Section 1: the risk-score formula (risk_score = shelf_life_magnitude *
reachability_multiplier) is monotonic in both inputs, as documented.

Section 2: only BROKEN_BY_SHOR findings are migration candidates --
broken-classically and weakened-by-grover are excluded, per the module
docstring's rationale.

Section 3: "no shelf-life data" uses a documented, non-zero default, never
silently "no risk".

Section 4: cost estimation's blast-radius-vs-default distinction.
"""

from __future__ import annotations

from pratyaksha.analyze.risk_score import (
    DEFAULT_COST_DAYS_NO_BLAST_RADIUS,
    DEFAULT_SHELF_LIFE_YEARS_NO_DATA,
    compute_risk_score,
    estimate_cost_days,
    estimate_shelf_life_magnitude,
    is_migration_candidate,
    reachability_multiplier,
)
from pratyaksha.model.assets import QuantumStatus, Reachability

# ===========================================================================
# Section 1 — risk-score formula monotonicity.
# ===========================================================================


def test_live_external_scores_higher_than_inert_for_identical_shelf_life() -> None:
    live_external_score = compute_risk_score(Reachability.LIVE_EXTERNAL, 10)
    inert_score = compute_risk_score(Reachability.INERT, 10)
    assert live_external_score > inert_score


def test_reachability_ranking_is_strictly_ordered() -> None:
    """live-external > live-internal > unknown > inert, as multipliers,
    holding shelf-life constant.
    """
    scores = [
        compute_risk_score(Reachability.LIVE_EXTERNAL, 10),
        compute_risk_score(Reachability.LIVE_INTERNAL, 10),
        compute_risk_score(Reachability.UNKNOWN, 10),
        compute_risk_score(Reachability.INERT, 10),
    ]
    assert scores == sorted(scores, reverse=True)
    assert len(set(scores)) == 4, "each reachability level must score strictly differently"


def test_inert_scores_near_zero_but_not_exactly_zero() -> None:
    score = compute_risk_score(Reachability.INERT, 10)
    assert 0.0 < score < 1.0, "INERT must be near-zero, not exactly zero -- see module docstring"


def test_longer_shelf_life_scores_higher_for_identical_reachability() -> None:
    short = compute_risk_score(Reachability.LIVE_EXTERNAL, 1)
    medium = compute_risk_score(Reachability.LIVE_EXTERNAL, 10)
    long_ = compute_risk_score(Reachability.LIVE_EXTERNAL, 27)
    longest = compute_risk_score(Reachability.LIVE_EXTERNAL, 50)
    assert short < medium < long_ < longest


def test_risk_score_is_the_documented_plain_product() -> None:
    """risk_score = shelf_life_magnitude * reachability_multiplier, exactly."""
    score = compute_risk_score(Reachability.LIVE_EXTERNAL, 27)
    assert score == 27 * reachability_multiplier(Reachability.LIVE_EXTERNAL)

    score2 = compute_risk_score(Reachability.LIVE_INTERNAL, 5)
    assert score2 == 5 * reachability_multiplier(Reachability.LIVE_INTERNAL)


def test_unknown_reachability_multiplier_is_a_deliberate_middle_value() -> None:
    """UNKNOWN must sit strictly between LIVE_INTERNAL and INERT -- never
    treated as safe (see docs/REACHABILITY.md's fail-safe rule).
    """
    assert (
        reachability_multiplier(Reachability.INERT)
        < reachability_multiplier(Reachability.UNKNOWN)
        < reachability_multiplier(Reachability.LIVE_INTERNAL)
        < reachability_multiplier(Reachability.LIVE_EXTERNAL)
    )


# ===========================================================================
# Section 2 — only broken-by-shor findings are migration candidates.
# ===========================================================================


def test_broken_by_shor_is_a_migration_candidate() -> None:
    assert is_migration_candidate(QuantumStatus.BROKEN_BY_SHOR) is True


def test_broken_classically_is_excluded() -> None:
    """Already broken with no quantum computer required -- an ordinary
    classical bug fix, not this pillar's problem. See module docstring.
    """
    assert is_migration_candidate(QuantumStatus.BROKEN_CLASSICALLY) is False


def test_weakened_by_grover_is_excluded() -> None:
    """Mitigated by a key-size doubling within the same primitive family,
    not a PQC migration -- see module docstring.
    """
    assert is_migration_candidate(QuantumStatus.WEAKENED_BY_GROVER) is False


def test_quantum_safe_is_excluded() -> None:
    assert is_migration_candidate(QuantumStatus.QUANTUM_SAFE) is False


def test_unknown_quantum_status_is_excluded() -> None:
    assert is_migration_candidate(QuantumStatus.UNKNOWN) is False


# ===========================================================================
# Section 3 — "no shelf-life data" never silently means "no risk".
# ===========================================================================


def test_no_shelf_life_data_uses_documented_nonzero_default() -> None:
    magnitude, is_default = estimate_shelf_life_magnitude(None)
    assert magnitude == DEFAULT_SHELF_LIFE_YEARS_NO_DATA
    assert magnitude > 0
    assert is_default is True


def test_real_shelf_life_data_is_used_verbatim_and_flagged_as_real() -> None:
    magnitude, is_default = estimate_shelf_life_magnitude(27)
    assert magnitude == 27
    assert is_default is False


def test_missing_shelf_life_data_still_produces_positive_risk() -> None:
    """The exact "do not silently treat 'no data' as 'no risk'" rule."""
    score = compute_risk_score(Reachability.LIVE_EXTERNAL, None)
    assert score > 0


# ===========================================================================
# Section 4 — cost estimation.
# ===========================================================================


def test_cost_uses_real_blast_radius_figure_when_present() -> None:
    cost, source = estimate_cost_days(1.5)
    assert cost == 1.5
    assert source == "blast_radius"


def test_cost_falls_back_to_documented_default_when_absent() -> None:
    cost, source = estimate_cost_days(None)
    assert cost == DEFAULT_COST_DAYS_NO_BLAST_RADIUS
    assert source == "default"


def test_cost_falls_back_to_default_for_zero_blast_radius_days() -> None:
    """A literal 0.0 blast-radius figure is treated the same as "absent"
    -- it cannot represent a real migration cost.
    """
    cost, source = estimate_cost_days(0.0)
    assert cost == DEFAULT_COST_DAYS_NO_BLAST_RADIUS
    assert source == "default"


def test_default_cost_and_default_shelf_life_are_distinguishable_sources() -> None:
    """CLAUDE.md's honesty convention: a default must never be
    indistinguishable from a real figure in the output.
    """
    _, shelf_is_default = estimate_shelf_life_magnitude(None)
    _, cost_source = estimate_cost_days(None)
    assert shelf_is_default is True
    assert cost_source == "default"
