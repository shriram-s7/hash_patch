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
exists.

Blast-radius findings only ever come from C/SQL (see
hash_patch/analyze/blast_radius.py's module docstring), so for every
Python/Java/Go migration candidate — i.e. most real-world corpora — that
figure is never present. Falling straight to a single flat constant in that
case would make `cost_days` (and therefore risk-density, and therefore the
optimiser's whole reason to differ from a naive risk-only ordering) a
no-op: see docs/OPTIMISER.md. Instead, the second-best real complexity
signal already sitting in every emitted CBOM is used: the NUMBER OF
EVIDENCE OCCURRENCES (call sites) hash_patch's own evidence rule already
requires for every asset (CLAUDE.md hard constraint #3) — an algorithm
called from five places in the codebase genuinely costs more engineer-days
to migrate than the same algorithm called from exactly one place (more
call sites to update, more surrounding tests to touch, more chance of a
missed call site). This is `cost_source = "call_sites"`.

Only when NEITHER a real blast-radius figure NOR any evidence-occurrence
count is available at all does this fall back to the flat, documented
default (`DEFAULT_COST_DAYS_NO_BLAST_RADIUS`) — `cost_source = "default"`.
All three cases are explicitly flagged via the `cost_source` field on
`OptimizerCandidate` (hash_patch/model/optimizer.py) rather than being
indistinguishable from each other.
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
# Pillar 3 blast-radius finding AND no evidence-occurrence count is
# available at all. Chosen to match hash_patch/analyze/blast_radius.py's
# own `_estimate_effort_days` base case (0.5 days) for consistency across
# pillars -- see docs/OPTIMISER.md. This also doubles as the single-call-
# site cost floor in the call-sites path below, so a finding with exactly
# one occurrence costs the same as the old flat constant did.
DEFAULT_COST_DAYS_NO_BLAST_RADIUS = 0.5

# Extra engineer-days added per ADDITIONAL evidence occurrence (call site)
# beyond the first, when no real blast-radius figure exists -- see this
# module's docstring. Deliberately smaller than blast-radius's own
# db_column increment (0.5): a call site is cheaper to touch than a schema
# migration, but more of them still means more engineer-days.
CALL_SITE_COST_INCREMENT_DAYS = 0.25

# Cap on the call-sites-derived cost, so a utility function with dozens of
# call sites doesn't produce an implausibly large single-finding estimate
# that would dominate every schedule -- see docs/OPTIMISER.md.
MAX_CALL_SITE_COST_DAYS = 3.0


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


def estimate_cost_days(
    blast_radius_effort_days: float | None,
    evidence_occurrence_count: int | None = None,
) -> tuple[float, str]:
    """Returns (cost_days, cost_source).

    - "blast_radius": a real Pillar 3 figure (summed across that asset's
      blast-radius findings) was supplied.
    - "call_sites": no blast-radius figure, but this asset carries at least
      one real evidence occurrence -- cost scales with how many call sites
      there are to migrate (`CALL_SITE_COST_INCREMENT_DAYS` per occurrence
      beyond the first, capped at `MAX_CALL_SITE_COST_DAYS`). A single-
      occurrence finding costs exactly `DEFAULT_COST_DAYS_NO_BLAST_RADIUS`.
    - "default": neither of the above was available at all.

    See this module's docstring for why call-site count is used here.
    """
    if blast_radius_effort_days is not None and blast_radius_effort_days > 0:
        return blast_radius_effort_days, "blast_radius"
    if evidence_occurrence_count is not None and evidence_occurrence_count > 0:
        extra_sites = evidence_occurrence_count - 1
        days = DEFAULT_COST_DAYS_NO_BLAST_RADIUS + CALL_SITE_COST_INCREMENT_DAYS * extra_sites
        return min(days, MAX_CALL_SITE_COST_DAYS), "call_sites"
    return DEFAULT_COST_DAYS_NO_BLAST_RADIUS, "default"


def estimate_binary_artefact_cost_days() -> tuple[float, str]:
    """Cost estimate for a COMPILED_CRYPTO_ARTEFACT finding (binary/container
    symbol, linked-library, embedded-string, or embedded-certificate
    evidence -- hash_patch/detect/binary/detector.py).

    `evidence_occurrence_count` for this finding type counts distinct
    byte-offset observations of the SAME static artefact (e.g. two places
    the same embedded algorithm string appears), not distinct source call
    sites -- there is no source line, no surrounding test to touch, no
    "one more place a developer has to edit" the way a real call site is.
    Reusing `estimate_cost_days`'s call-sites formula against that count
    would treat "the same string was seen a second time" as "twice as
    expensive to migrate", which is meaningless. So this finding type
    always gets the flat, documented default instead -- tagged with its own
    `cost_source` ("binary_artefact_default") rather than plain "default"
    so it stays honestly distinguishable in the CBOM/optimizer output from
    a source-code finding that fell back to the same number for a different
    reason (see this module's docstring's "Cost estimation" section).
    """
    return DEFAULT_COST_DAYS_NO_BLAST_RADIUS, "binary_artefact_default"
