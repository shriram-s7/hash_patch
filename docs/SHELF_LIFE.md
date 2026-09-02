# Shelf-Life Inference (Pillar 2)

PRATYAKSHA's second detection pillar estimates how long the data protected
by a cryptographic asset must plausibly remain confidential — the "X"
variable in Mosca's inequality (X = data shelf-life, Y = migration time,
Z = years until a cryptographically-relevant quantum computer exists; the
classic risk statement is that an organisation is already too late if
X + Y > Z). This pillar computes X only. It does NOT implement the
comparison against Y and Z — that needs Pillar 5's Monte Carlo work over a
quantum-arrival estimate, planned separately. `ShelfLifeFinding.mosca_note`
is a descriptive string only, not a risk verdict.

**Scope for this pillar (current):** Python and Java only, source-code
NAME-PATTERN matching only. No live database introspection, no real
dataflow tracing across function boundaries, no import resolution. This is
explicitly a heuristic with the same false-negative risk class as Pillar 3
(Blast Radius): if sensitive data flows through a generically-named
variable, or is only associated with its real meaning several function
calls away from the crypto call site, this pillar will not see it. See
"What this pillar cannot see" below.

## The ontology — and its honesty caveat

`ontology/data_sensitivity.yaml` is the single source of truth for every
category name, name pattern, `shelf_life_years` figure, `statutory_basis`
citation, and `confidence` level this pillar uses. No Python code
duplicates any of this as a literal.

**Read the file's own header before trusting a `shelf_life_years` number for
anything beyond a demonstration.** In short: these figures are NOT derived
from a legal database, NOT verified against the actual DPDP Act 2023 rules/
schedules (or any other statute), and NOT reviewed by counsel. They are
reasonable-effort, conservative, round-number defaults chosen so this
system can demonstrate what "X" looks like when it's derived from something
a static scanner can observe, rather than invented outright. **A real
deployment must replace this file with organisation-specific,
legally-reviewed figures** before any `ShelfLifeFinding` is used to inform
an actual migration-priority decision.

`confidence` (`"high"` / `"medium"`) reflects how well-grounded the
CATEGORY ITSELF is as "clearly sensitive personal data" under a reasonable
reading of applicable law/regulation — it is NOT a claim that the specific
number is verified. Nothing in this file is number-verified; `generic_pii`
(the catch-all bucket) and `credentials` (a "until rotated" placeholder
standing in for a real rotation policy, not a retention-law concept at all)
are marked `medium` because their categorical grounding is weaker than the
five named categories (aadhaar, pan, health_record, financial_account,
biometric), which are all explicitly the kind of data DPDP Act 2023 and
sectoral regulation single out for special handling.

## Detection: `pratyaksha/detect/shelf_life/data_context.py`

Uses the exact same tree-sitter parser instances
`pratyaksha.detect.python`/`pratyaksha.detect.java` already construct (no
second `Language`/`Parser` stood up — the same convention
`pratyaksha/detect/blast_radius/c_buffers.py` follows for the C parser).

For every source-evidence occurrence of every already-detected Python/Java
`CryptoAsset` (a crypto call site), it collects up to four kinds of nearby
candidate identifier and matches each (case-insensitive substring) against
`ontology/data_sensitivity.yaml`'s `name_patterns`:

1. **`call_argument`** — a plain-identifier argument of the crypto call
   itself, e.g. `SHA256.new(aadhaar_bytes)` → `"aadhaar_bytes"`. Composite
   expressions, string/numeric literals, and attribute accesses are never
   candidates — only a bare `identifier` argument node counts. In practice
   this fires often for pycryptodome-style factory calls that take data
   directly (`AES.new(key, ...)`, `SHA256.new(data)`), and rarely for Java's
   JCA `getInstance(...)` factory methods, which take only an
   algorithm-name string literal — see
   `testdata/java/ShelfLifeExamples.java`'s own note on this.
2. **`enclosing_function`** — the name of the function/method containing
   the call.
3. **`enclosing_class`** — the name of the class containing that function
   (nothing, if the function is module-level).
4. **`model_field`** — a Python dataclass/pydantic-style annotated class
   attribute (`name: Type` or `name: Type = value` inside a class body,
   best-effort — matched structurally, not by verifying the class is
   actually decorated `@dataclass` or subclasses `BaseModel`, since this
   project's detectors don't do import resolution anywhere else either), or
   a Java field declaration / getter-shaped method name (`get*`/`is*`).
   **Class-scoped, not file-wide**: only fields declared in the SAME CLASS
   as the crypto call are candidates. See "Why class-scoped, not
   file-wide" below.

If a candidate matches multiple categories, or multiple different
candidates near one call site match different categories, **all matches are
kept** as separate `DataContextMatch` objects (`pratyaksha/model/shelf_life.py`)
— detection never silently picks one. If nothing matches anything, no
`DataContextMatch` is produced for that call site at all — never a
default guess.

### Why class-scoped, not file-wide, for `model_field`

`pratyaksha/analyze/shelf_life.py` correlates a `DataContextMatch` to a
`CryptoAsset` using EXACT `(locator, line)` equality against the asset's own
evidence — every `DataContextMatch.evidence[0].line` is always the line of
the crypto call site it was found near, not necessarily the line the
matched identifier itself is declared on (see the field's own docstring in
`pratyaksha/model/shelf_life.py`). This gives the same
anti-cross-contamination discipline `pratyaksha/analyze/blast_radius.py`'s
nearest-by-line rule provides for Pillar 3 (see that module's BUG 1
regression note), without a second distance heuristic: correlation is a
simple, honest, exact-match lookup. Scoping `model_field` candidates to the
crypto call's own enclosing class — rather than every class anywhere in the
file — is what keeps an unrelated crypto call elsewhere in the same file
(e.g. hashing a `temp_cache_value` with nothing sensitive nearby) from
spuriously picking up a DIFFERENT class's sensitive field names just
because both happen to live in one file. See
`testdata/python/shelf_life_examples.py`'s three scenarios, which would
contradict each other under a naive file-wide interpretation.

## Correlation and the longest-shelf-life-wins rule: `pratyaksha/analyze/shelf_life.py`

`compute_shelf_life` takes every `CryptoAsset` and every `DataContextMatch`,
and produces a `ShelfLifeFinding` (`pratyaksha/model/shelf_life.py`) for an
asset when at least one `DataContextMatch` shares BOTH the asset's file
(`locator`) AND one of the asset's own evidence LINES — never cross-file
(the same same-file correlation honesty rule
`pratyaksha/analyze/blast_radius.py` follows, per CLAUDE.md's "Blast
Radius" section), and never merely "somewhere else in the same file"
either, per the class-scoping design above.

**When more than one category matches a single call site (Step 2's "keep
ALL matches" rule), the category with the LONGEST `shelf_life_years` wins**
— a fail-safe: on ambiguity, always assume the more sensitive/longer-lived
category, never the shorter one. This is order-independent by construction
(every candidate is compared; see `_pick_winning_match`) — it does not
matter which pattern the parser happened to visit first. A deterministic
tie-break (category name, then matched identifier) applies only when two
categories have the exact same `shelf_life_years`, so the result stays
reproducible either way. See `tests/unit/test_shelf_life.py`'s
`test_longest_shelf_life_wins_*` tests, which prove this with both a
synthetic and a real-file order-swap, not just a single hardcoded outcome.

**An asset with zero same-file, same-call-site `DataContextMatch` gets no
`ShelfLifeFinding` at all.** This is deliberately NOT the same as "assign
the `generic_pii` default" — genuinely unmatched code produces no opinion,
per the "hard evidence or it doesn't exist" principle CLAUDE.md's "Name"
section describes for the rest of this tool.

`scan_date` is a required parameter, always supplied by the caller
(`pratyaksha/cli.py::run_scan` passes `ScanResult.scan_started_at.date()` —
the one wall-clock read CLAUDE.md's determinism hard constraint already
permits, and only there). `compute_shelf_life` and `run_shelf_life`
themselves never read the system clock, so two calls with the same
`scan_date` and the same inputs always produce byte-identical
`mosca_note` text.

## CLI wiring

`pratyaksha scan PATH --output FILE` runs this pillar automatically for
every Python/Java `CryptoAsset` found. Unlike Pillar 3's `db_column`
fallback, every `ShelfLifeFinding` always has a real, already-present
correlated `CryptoAsset` — there is no synthetic-component path here.
Findings are mirrored onto that asset's CBOM component as
`pratyaksha:property.shelfLife.<category>` properties (JSON value:
`shelfLifeYears`, `statutoryBasis`, `confidence`, `moscaNote`, `locator`) —
the same free-form `properties` bag / `pratyaksha:property.<key>`
namespacing CLAUDE.md documents. Every scan prints a summary line:
`N shelf-life findings (longest: X years, category)`.

## Corpus

`testdata/python/shelf_life_examples.py` and
`testdata/java/ShelfLifeExamples.java`, with expected outcomes in
`tests/golden/shelf_life_manifest.json` (checked by
`tests/golden/test_shelf_life_golden.py`) and exercised individually by
`tests/unit/test_shelf_life.py`. Each file seeds three scenarios: a match
via `call_argument`/`enclosing_function`, a deliberate no-signal case, and
the aadhaar-vs-financial_account longest-shelf-life-wins tie-break. Each
scenario uses a DIFFERENT hash algorithm so its call site produces its own
distinct `CryptoAsset` — the same canonical algorithm called twice in one
file would otherwise merge both call sites' evidence onto a single asset,
which would defeat the point of keeping the three scenarios independent.

## What this pillar cannot see

This is name-pattern matching on nearby identifiers, not dataflow analysis,
and shares Pillar 3's false-negative risk class:

- **Generic variable names.** If sensitive data is stored in a variable
  named `data`, `payload`, `value`, or any other name this pillar's
  patterns don't recognise, it is invisible — there is no NLP, no
  type-based inference, no data-flow tracing here.
- **Cross-function-boundary data flow.** If a crypto call's data argument
  is passed in from a caller several frames away under a generic local
  parameter name, this pillar cannot trace back to the caller's own
  meaningfully-named variable. `AES.new(key, AES.MODE_GCM)` followed by a
  LATER, separate `cipher.encrypt(aadhaar_number)` call is invisible: the
  detected crypto call (`AES.new`) and the call that actually touches the
  sensitive data (`cipher.encrypt`) are different call sites, and only the
  detected one's own arguments/enclosing scope are examined.
- **Cross-file correlation.** Never attempted, by design (see above) — a
  sensitively-named field in one file has no principled relationship to a
  crypto call in another file just because both are in the same scan
  target.
- **Live database schemas, ORMs, config files, or any non-source-code
  signal.** Out of scope for this prompt entirely, as stated in the task
  scope: no live database introspection.

Extend `ontology/data_sensitivity.yaml`'s `name_patterns` for a specific
codebase's naming conventions rather than trying to anticipate every name
up front — the same guidance `docs/BLAST_RADIUS.md` gives for
`rules/blast_radius_names.yaml`.
