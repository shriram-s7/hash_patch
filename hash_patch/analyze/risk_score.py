"""hash_patch/analyze/risk_score.py — Pillar 5 (Migration Optimiser) risk
scoring and cost estimation.

Both functions here are PURE: they take already-parsed values (never touch
a file, a CBOM document, or a clock) so they're trivially unit-testable and
inspectable in isolation — see docs/OPTIMISER.md for the formulas restated
in prose, and tests/unit/test_risk_score.py.

============================================================================
Why only broken-by-shor findings are migration candidates
============================================================================
`is_migration_candidate` restricts this pillar to `QuantumStatus.BROKEN_BY_SHOR`
findings only. This is deliberate, not an oversight:

  - `BROKEN_CLASSICALLY` algorithms (MD5, DES, RC4, ...) are already broken
    with NO quantum computer required. Replacing them is an ordinary
    classical-security bug fix, orthogonal to a PQC migration budget and to
    Mosca's inequality entirely — pulling them into a "years until CRQC"
    optimisation would conflate two unrelated problems.
  - `WEAKENED_BY_GROVER` algorithms (AES, SHA-256, ...) are symmetric
    primitives/hashes that Grover's algorithm only halves the effective
    security level of. The standard mitigation is a KEY-SIZE DOUBLING
    within the SAME primitive family (e.g. AES-128 -> AES-256), not a
    migration to a different PQC algorithm family. This pillar's cost model
    (blast-radius engineer-days, a same-file size-constraint overflow
    check) is built around Pillar 3's PQC-replacement-family logic
    (`hash_patch/analyze/blast_radius.py`), which itself only ever
    correlates `BROKEN_BY_SHOR` assets — there is no equivalent
    "PQC replacement size" for a Grover-weakened primitive to reuse here.

`BROKEN_BY_SHOR` (RSA, ECDSA, Ed25519, DH, ...) is exactly the set Shor's
algorithm breaks outright once a CRQC exists — the actual PQC migration
problem this pillar schedules.

============================================================================
The risk-score formula
============================================================================
    risk_score = shelf_life_magnitude * reachability_multiplier

  - `shelf_life_magnitude` is the finding's real `shelf_life_years` (Pillar
    2) when present, else `DEFAULT_SHELF_LIFE_YEARS_NO_DATA` — a documented
    low-confidence stand-in, never silently treated as "zero risk" just
    because Pillar 2 found no name-pattern signal for that finding (see
    `estimate_shelf_life_magnitude` below). This also stands in for the
    "exposure scope" input this pillar's design calls for: shelf-life is
    the only per-finding "how much is at stake" signal already available
    anywhere in this codebase (Pillar 2's whole purpose), so rather than
    inventing a second, ungrounded magnitude metric, this pillar treats
    that one real signal as the exposure-scope term too. See
    docs/OPTIMISER.md.
  - `reachability_multiplier` comes from `_REACHABILITY_WEIGHTS` below:
    live-external highest, inert near-zero (never exactly zero — an inert
    classification can still be wrong, see docs/REACHABILITY.md's own
    fail-safe caveats; this pillar does not treat "probably dead" as
    "provably risk-free").

This is a plain weighted product, deliberately simple and inspectable —
see docs/OPTIMISER.md for the full worked explanation. It is NOT calibrated
against real incident data, the same honesty caveat
`hash_patch/analyze/blast_radius.py`'s severity bands carry.

============================================================================
Cost estimation
============================================================================
`estimate_cost_days` uses a real Pillar 3 `estimated_effort_days` figure
(summed across every blast-radius finding correlated to this asset — an
asset can have more than one size-constraint overflow to fix) when one
exists; otherwise a flat, documented default
(`DEFAULT_COST_DAYS_NO_BLAST_RADIUS`), explicitly flagged via the
`cost_source` field on `OptimizerCandidate`
(hash_patch/model/optimizer.py) rather than being indistinguishable from a
real blast-radius-derived figure.
"""

from __future__ import annotations

from hash_patch.model.assets import QuantumStatus, Reachability

# ---------------------------------------------------------------------------
# Reachability -> risk multiplier.
#
# live-external highest (externally reachable, live code path); live-
# internal next (live, but not externally reachable); unknown a
# deliberately MIDDLE value (never assumed safe -- see docs/REACHABILITY.md's
# fail-safe rule: "not reachable from anything we can prove" is UNKNOWN, not
# INERT, so UNKNOWN can genuinely be live code our simple call-graph just
# couldn't trace); inert near-zero but never exactly zero, for the same
# reason -- an INERT classification is still a heuristic, not proof.
# ---------------------------------------------------------------------------
_REACHABILITY_WEIGHTS: dict[Reachability, float] = {
    Reachability.LIVE_EXTERNAL: 1.0,
    Reachability.LIVE_INTERNAL: 0.6,
    Reachability.UNKNOWN: 0.3,
    Reachability.INERT: 0.05,
}

# Low-confidence stand-in shelf-life magnitude used ONLY when Pillar 2 found
# no name-pattern signal for a finding at all (never a silent 0 -- see
# docs/OPTIMISER.md). Deliberately shorter than every NAMED category in
# ontology/data_sensitivity.yaml except `credentials` (1yr) -- "we don't
# know what this protects" should not outrank "we know this protects
# Aadhaar data for 27 years", but it must never round down to zero risk
# either.
DEFAULT_SHELF_LIFE_YEARS_NO_DATA = 5

# Flat placeholder migration cost (engineer-days) used ONLY when no
# Pillar 3 blast-radius finding is correlated to this asset at all. Chosen
# to match hash_patch/analyze/blast_radius.py's own
# `_estimate_effort_days` base case (0.5 days) for consistency across
# pillars -- see docs/OPTIMISER.md.
DEFAULT_COST_DAYS_NO_BLAST_RADIUS = 0.5


def is_migration_candidate(quantum_status: QuantumStatus) -> bool:
    """True only for BROKEN_BY_SHOR -- see this module's docstring for why
    broken-classically and weakened-by-grover are excluded from this
    pillar entirely.
    """
    return quantum_status == QuantumStatus.BROKEN_BY_SHOR


def reachability_multiplier(reachability: Reachability) -> float:
    return _REACHABILITY_WEIGHTS.get(reachability, _REACHABILITY_WEIGHTS[Reachability.UNKNOWN])


def estimate_shelf_life_magnitude(shelf_life_years: int | None) -> tuple[int, bool]:
    """Returns (magnitude, is_default). `shelf_life_years` is the real
    Pillar 2 figure when Pillar 2 produced a ShelfLifeFinding for this
    asset, or None when it did not (no name-pattern signal found -- see
    docs/SHELF_LIFE.md's "no signal -> no finding" rule). `is_default` is
    True exactly when the fallback constant was used, so callers can flag
    it rather than presenting it as equivalent to a real Pillar 2 figure.
    """
    if shelf_life_years is not None:
        return shelf_life_years, False
    return DEFAULT_SHELF_LIFE_YEARS_NO_DATA, True


def compute_risk_score(reachability: Reachability, shelf_life_years: int | None) -> float:
    """risk_score = shelf_life_magnitude * reachability_multiplier -- see
    this module's docstring for the full explanation of both terms.
    """
    magnitude, _ = estimate_shelf_life_magnitude(shelf_life_years)
    return magnitude * reachability_multiplier(reachability)


def estimate_cost_days(blast_radius_effort_days: float | None) -> tuple[float, str]:
    """Returns (cost_days, cost_source). `cost_source` is "blast_radius"
    when a real Pillar 3 figure (summed across that asset's blast-radius
    findings) was supplied, or "default" when
    DEFAULT_COST_DAYS_NO_BLAST_RADIUS was used instead -- see this module's
    docstring.
    """
    if blast_radius_effort_days is not None and blast_radius_effort_days > 0:
        return blast_radius_effort_days, "blast_radius"
    return DEFAULT_COST_DAYS_NO_BLAST_RADIUS, "default"
