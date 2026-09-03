# Migration Optimiser (Pillar 5)

Hash Patch's fifth pillar takes an already-emitted CBOM (from `hash-patch
scan`, already carrying whatever P1 reachability, P2 shelf-life, and P3
blast-radius data those pillars could find), a migration BUDGET in
engineer-days, and a PARALLELISM (how many findings can be worked on at
once), and produces a recommended MIGRATION ORDER, a residual-risk-over-time
curve, and a comparison against a naive baseline that demonstrates the
optimiser's value.

**This is a separate CLI subcommand, not part of `hash-patch scan`:**

```
hash-patch optimize INPUT.cbom.json --budget-days N --parallelism P --output PLAN.json
```

It never re-scans source code. Every input value it uses (quantum status,
reachability, shelf-life years, blast-radius effort-days) is read back out
of `hash_patch:` properties an earlier `hash-patch scan` already attached —
see `hash_patch/analyze/cbom_reader.py`. Nothing here is invented.

## Which findings are migration candidates

Only `CryptoAsset`s whose `hash_patch:quantumStatus` is `broken-by-shor`
(`hash_patch/analyze/risk_score.py::is_migration_candidate`). This is
deliberate:

- **`broken-classically`** algorithms (MD5, DES, RC4, ...) are already
  broken with no quantum computer required at all — replacing them is an
  ordinary classical-security bug fix, unrelated to a PQC migration budget
  or to Mosca's inequality.
- **`weakened-by-grover`** algorithms (AES, SHA-256, ...) are mitigated by
  a KEY-SIZE DOUBLING within the same primitive family (e.g. AES-128 →
  AES-256), not a migration to a different PQC algorithm family. Pillar
  3's PQC-replacement-family / cost logic
  (`hash_patch/analyze/blast_radius.py`) is built entirely around
  `broken-by-shor` assets; there is no equivalent "PQC replacement size"
  for a Grover-weakened primitive for this pillar's cost model to reuse.

`broken-by-shor` (RSA, ECDSA, Ed25519, DH, ...) is exactly what Shor's
algorithm breaks outright once a CRQC exists — the actual PQC migration
problem this pillar schedules.

## The risk-score formula

Stated in full, plainly, in `hash_patch/analyze/risk_score.py::compute_risk_score`:

```
risk_score = shelf_life_magnitude * reachability_multiplier
```

- **`reachability_multiplier`** (`_REACHABILITY_WEIGHTS`):

  | Reachability     | Multiplier |
  |------------------|------------|
  | `live-external`  | 1.00       |
  | `live-internal`  | 0.60       |
  | `unknown`        | 0.30       |
  | `inert`          | 0.05       |

  `unknown` is a deliberate MIDDLE value, not a low one — per
  docs/REACHABILITY.md's own fail-safe rule, "not reachable from anything
  we can prove" is `UNKNOWN`, never `INERT`, so an `UNKNOWN` finding can
  genuinely be live code the reachability analysis's simple call graph
  just couldn't trace. `inert` is near-zero but never exactly zero — an
  `INERT` classification is itself a heuristic, not a proof of death.

- **`shelf_life_magnitude`** is the finding's real Pillar-2
  `shelf_life_years` when Pillar 2 produced a `ShelfLifeFinding` for it,
  else `DEFAULT_SHELF_LIFE_YEARS_NO_DATA = 5` — a documented, non-zero,
  low-confidence stand-in (see `estimate_shelf_life_magnitude`). Missing
  shelf-life data is NEVER silently treated as "no risk": the default is
  smaller than every real named category except `credentials` (1 year),
  never zero. This also serves as this pillar's "exposure scope" input —
  shelf-life is the only per-finding "how much is at stake" signal
  anywhere in this codebase (that is Pillar 2's entire purpose), so
  rather than inventing a second, ungrounded magnitude metric, this
  pillar reuses that one real signal for both roles.

This is a plain weighted PRODUCT (not a sum — reachability genuinely acts
as a *multiplier* on the underlying exposure, per the task's own framing),
deliberately simple and fully inspectable in code, not a black box. It is
**not calibrated against real incident data**, the same honesty caveat
`hash_patch/analyze/blast_radius.py`'s severity bands carry.

`OptimizerCandidate.shelf_life_is_default` records whether the default was
used, so a report reader can always tell a real Pillar-2 figure from a
fallback.

## Cost estimation

`hash_patch/analyze/risk_score.py::estimate_cost_days`:

```
cost_days = sum(blast-radius estimatedEffortDays across every BlastRadiusFinding
                 correlated to this asset)      if any exist
          = DEFAULT_COST_DAYS_NO_BLAST_RADIUS (0.5)   otherwise
```

An asset can have more than one size-constraint overflow to fix (e.g. two
different undersized buffers protecting the same algorithm), so the real
figure sums across all of them (`hash_patch/analyze/cbom_reader.py::_blast_radius_effort_days`).
`0.5` matches `hash_patch/analyze/blast_radius.py`'s own base per-finding
estimate, for consistency across pillars. `OptimizerCandidate.cost_source`
(`"blast_radius"` or `"default"`) makes the two cases distinguishable in
the output, never blurred together — the same honesty convention
`shelf_life_is_default` follows.

**A structural note on this corpus:** Pillar 3 (blast-radius cost) only
detects C/SQL buffers; Pillars 1/2 (reachability, shelf-life) only cover
Python/Java. A single REAL finding therefore effectively never carries
both a non-default cost AND a non-default risk boost from the SAME piece
of evidence in this codebase's current pillar scope — a CryptoAsset
detected purely in a C file (like `testdata/c/optimizer_expensive.c`'s
ECDSA finding) always has `reachability = unknown` and
`shelf_life_is_default = True`, no matter how expensive its blast-radius
cost is. (A single CryptoAsset id CAN in principle span languages, since
identity — `hash_patch/model/assets.py::derive_asset_id` — is purely
`(type, name, parameter_set, mode)`, independent of language; this
corpus's fixtures deliberately keep the "expensive" finding C-only and
the "high-risk" findings Python-only precisely to make this structural
limitation, and the naive-vs-greedy scheduling story it enables, easy to
follow — see the worked example below.)

## The scheduler

`hash_patch/analyze/optimizer.py`. Both the greedy optimiser and the naive
baseline solve the SAME problem — the classic MULTIPLE KNAPSACK problem:
choose a subset of candidates and partition it across `parallelism`
identical-capacity (`budget_days`) work-slots, maximizing total risk
eliminated — via the same bin-packing procedure (`_schedule`): process
candidates in a given order, always placing the next one into whichever
slot currently has the LEAST assigned load; if it doesn't fit there (so it
cannot fit anywhere, since that slot has the least load of all), leave it
unmigrated and KEEP GOING — a smaller/cheaper candidate considered later
might still fit.

### The naive baseline, and why it's a fair comparison

`schedule_naive`: candidates ordered by `risk_score` ALONE, ignoring cost —
"fix the scariest-looking things first." This (not raw discovery order) is
the fairer baseline to beat, because it's a real, common naive
prioritisation strategy security teams actually use ("severity first"),
not a strawman with no logic behind it at all. The ONE variable that
differs between it and the optimiser is whether cost is considered — which
isolates exactly the thing this pillar claims to add value on.

### The optimiser, and a real failure mode it was built to survive

`schedule_greedy` is documented as "risk-density (`risk_score / cost_days`)
descending" — but a pure density-first greedy has a real, well-known
failure mode in 0/1-knapsack-shaped problems: it can waste a slot on a
high-density-but-low-absolute-value item and end up eliminating LESS total
risk than simply taking the single highest-value item that fits.

**This was not a hypothetical worry — it was found empirically on this
project's own optimizer corpus** (parallelism=2, budget=3.5 engineer-days:
pure density-first packing eliminated 85.00 total risk, while the naive
value-only baseline achieved 86.25 on the exact same inputs). Rather than
quietly picking a "nicer" demo budget that avoided exposing this, the fix
is `_schedule_hybrid_greedy`: compute BOTH the density-ordered packing and
the value-ordered (naive-style) packing, and return whichever eliminates
more total risk. Naive's own ordering is literally one of the two
candidates this function chooses between, so **`schedule_greedy` is now
guaranteed to never eliminate less total risk than `schedule_naive` on the
same inputs** — see `tests/unit/test_optimizer.py::test_optimizer_never_worse_than_naive_across_budget_sweep_on_real_corpus`,
which sweeps 16 budgets × 3 parallelism levels over the real corpus and
asserts this holds everywhere, not just at one chosen checkpoint. Ties
between the two orderings prefer the density-ordered plan, deterministically.

### Residual risk curve

`_residual_risk_curve`: 21 evenly-spaced samples (day, residual risk)
across `[0, budget_days]` — "residual risk" at a sampled day is the total
risk of every candidate NOT yet finished by that day in the chosen
schedule. A fixed sample count keeps output size bounded regardless of how
large `budget_days` is.

## Quantum-arrival scenarios, and the scenario urgency adjustment

`ontology/quantum_arrival.yaml` — **read that file's own header before
trusting these numbers for anything.** In short: they are NOT a real
statistical model of quantum-computing timelines. They are 3 named,
illustrative scenarios (`optimistic`, `moderate`, `conservative`) meant to
demonstrate how sensitive a migration plan is to timeline uncertainty. The
Global Risk Institute's annual Quantum Threat Timeline Report is named as
the KIND of properly-sourced survey a real deployment should use instead —
the specific `estimated_year`/`probability_weight` figures actually
recorded are explicitly **loosely inspired by, not sourced from**, any
specific published survey. Replace this file with real risk-tolerance
inputs before using `ShelfLifeFinding`-derived scenario output for an
actual decision.

For each scenario, `run_optimizer` computes a SCENARIO-ADJUSTED risk score
per candidate (`_urgency_multiplier`) on top of the plain
(scenario-independent) `risk_score` — this is what makes the 3 scenarios'
plans genuinely differ, not just carry a different label:

```
urgency_multiplier = 1.0                     if shelf_life_is_default (no real P2 evidence
                                              -- never discount without evidence)
                    = 1.0                     if reference_year + shelf_life_years > scenario.estimated_year
                                              (the data is still sensitive when the CRQC arrives)
                    = SCENARIO_SAFE_DISCOUNT (0.35)   otherwise
                                              (the data's real secrecy window has plausibly
                                              already lapsed by the time the CRQC arrives)

scenario_risk_score = risk_score * urgency_multiplier
```

`reference_year` comes from the input CBOM's own `metadata.timestamp` (the
scan date) — never the system clock (see "Determinism" below).
`SCENARIO_SAFE_DISCOUNT` is 0.35, not 0.0: a shelf-life figure is itself a
heuristic estimate (docs/SHELF_LIFE.md), not a certainty, so "probably
already safe" is discounted, never eliminated.

## Optimality-gap validation: `hash_patch/analyze/optimizer_bruteforce.py`

A TESTING/VALIDATION TOOL, not part of the normal `hash-patch optimize`
CLI path. `brute_force_optimal` explores every way of choosing a subset of
candidates and partitioning it across `parallelism` bins via
branch-and-bound recursion (two pruning rules — an admissible upper-bound
prune, and slot-symmetry dedup for identical-capacity bins — keep it
tractable without changing the answer), returning the TRUE maximum total
risk eliminated. It refuses to run above `_MAX_BRUTE_FORCE_CANDIDATES = 15`
candidates rather than risk hanging — a SAFETY cap, not a promise of speed
up to exactly that size at any parallelism; this project's own tests use
single-digit-to-low-teens instances specifically so the search completes
near-instantly.

`optimality_gap` compares `schedule_greedy`'s result against this true
optimum on the SAME small instance, reporting the gap as a percentage. The
gap is always ≥ 0 by construction: `schedule_greedy` produces one
particular FEASIBLE schedule under this exact multiple-knapsack model, and
`brute_force_optimal` is the true maximum over every feasible schedule, so
greedy can never do better. On this project's own real 11-candidate
optimizer corpus (well under the 15 cap) at the demo budget (5.0
engineer-days, parallelism 1), the hybrid greedy reaches the TRUE OPTIMUM
— 0% gap.

## CLI output

`hash-patch optimize INPUT.cbom.json --budget-days N --parallelism P
[--output PLAN.json]` writes an `OptimizationReport`
(`hash_patch/model/optimizer.py`) as JSON: the 3 scenario plans (each with
its own optimiser plan, naive plan, and residual-risk curve), and prints
one summary line per scenario:

```
Scenario 'moderate' (~2033): optimiser eliminates 98.23% risk vs 98.17% naive at same budget.
```

(2 decimal places, not 1 — see the format string's own comment in
`hash_patch/analyze/optimizer.py::_headline_message`: on this pillar's
discrete inputs, the real gap at a given checkpoint can be small enough
that 1 decimal place rounds two genuinely different percentages to the
same displayed value.)

## Determinism

Like every other pillar, this one must produce byte-identical output for
identical input (CLAUDE.md hard constraint #2). `compute_risk_score`,
`estimate_cost_days`, `_schedule`, and `run_optimizer` never read the
system clock — the ONE date this pillar needs (`reference_year`) is read
from the input CBOM's own `metadata.timestamp`
(`hash_patch/analyze/cbom_reader.py::read_reference_year`), the same
timestamp `hash-patch scan` already stamped using its own one permitted
wall-clock read. All ordering ties (equal risk-density, equal raw risk) are
broken by `finding_id`, never left to incidental iteration order.

## Corpus

The existing accumulated `testdata/python` + `testdata/java` corpus,
checked before writing anything new, had `broken-by-shor` findings but
none were `LIVE_EXTERNAL` or carried real Pillar-2 shelf-life data — every
one defaulted on both axes, too flat a risk-score spread to make
greedy-vs-naive divergence visible or testable. Three small fixture
additions gave it a realistic spread (see each file's own docstring for
the full reasoning):

- `testdata/python/optimizer_examples.py` — two CHEAP + HIGH-RISK,
  `LIVE_EXTERNAL` findings with real long shelf-life signal (`aadhaar`
  27yr, `biometric` 50yr), and three CHEAP + MODERATE-RISK `LIVE_EXTERNAL`
  findings with a short real shelf-life (`credentials`, 1yr).
- `testdata/c/optimizer_expensive.c` — one EXPENSIVE finding: five
  undersized buffers correlated to the same ECDSA asset, giving it a real
  (not default) blast-radius cost of 2.5 engineer-days (5x the flat
  baseline) — deliberately five, not three, so this finding's
  risk-density stays below the three `credentials` findings' density even
  after their shelf-life is scenario-discounted; see that file's own
  docstring for the exact arithmetic.
- `testdata/python/test_optimizer_low_value.py` — one deliberately INERT,
  no-signal CHEAP + LOW-RISK finding (test-file convention, no callers).

At the documented demo budget (5.0 engineer-days, parallelism 1), the
naive baseline (plain, scenario-independent risk_score) spends its last
2.5 days entirely on the one expensive ECDSA finding (raw risk 1.5) —
schedule: `X448, RSA, EC, Ed25519, ECDSA(default) [2.5 days], ECDSA(expensive)
[2.5 days]`, eliminating 83.00 of 86.50 total risk (95.95%). The optimiser
spends the SAME 2.5 days on `DSA + Ed448 + DH` (the three `credentials`
findings, 1.0 risk each = 3.0 combined) instead, eliminating 85.00
(98.27%) — the true optimum for this budget, confirmed by
`optimizer_bruteforce.py` (0% gap). This is the single, concrete,
real divergence the plain (schedule_greedy vs schedule_naive) comparison
demonstrates. The SCENARIO-ADJUSTED comparison `hash-patch optimize`
actually prints shows the same mechanism at a smaller magnitude (98.23%
vs 98.17%) because the `credentials` findings' shelf-life is discounted
under every scenario (a rotatable secret's 1-year real shelf-life has
always lapsed by any of the 3 scenarios' estimated CRQC-arrival years) —
see `testdata/python/optimizer_examples.py`'s own docstring for why that
discount was deliberately kept large enough to still flip the ordering,
not so large it erases the effect.
