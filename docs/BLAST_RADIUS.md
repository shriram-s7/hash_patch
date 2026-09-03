# Blast Radius (Pillar 3)

Hash Patch's third detection pillar looks for places in the codebase that
statically assume a cryptographic artefact — a key, a signature, a
ciphertext — is small, and predicts whether migrating the algorithm that
produces it to its PQC replacement will overflow that assumption.

**Scope for this pillar (current):** C fixed-size stack buffers and heap
allocations, and SQL DDL fixed-width columns, only. Java/Go/Python buffer
detection and wire-format/protocol detection are explicitly out of scope
and not attempted.

## The size reference table

`rules/pqc_sizes.yaml` is the single source of truth for every byte size
this pillar uses — classical algorithm sizes and PQC candidate sizes alike.
No Python code duplicates these numbers as literals; everything reads them
from this file. Full source citations (which FIPS document, which table)
are comments in the file itself. In short:

- **Classical:** RSA-2048/3072/4096, ECDSA-P256, Ed25519, ECDH-P256 —
  standard encodings (PKCS#1/X.509, SEC1, RFC 8032/7748). RSA and ECDSA
  pubkey/signature sizes are marked `approximate: true` (ASN.1 DER
  structural overhead varies by a few bytes); Ed25519/X25519 sizes are
  exact.
- **PQC:** ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204),
  SLH-DSA-SHA2-128s/192s/256s (FIPS 205) — exact, standardised byte
  lengths.
- **`default_replacement`:** which PQC parameter set this pillar treats as
  "the" replacement per classical primitive family —
  `key_agreement_or_pke -> ml_kem_768`, `signature -> ml_dsa_65`.
  Deliberately NOT the smallest table entry overall (ML-KEM-512/ML-DSA-44,
  NIST category 1/2) — those are below the security level most migration
  guidance treats as a realistic floor. Category 3 (ML-KEM-768/ML-DSA-65)
  is the base case. A stronger parameter set only makes a buffer/column
  overflow *worse*, never better, so this is a conservative lower bound on
  the blast radius, not an upper one.

SLH-DSA sizes are recorded for completeness (a future migration
recommendation pathway may want them) but are **not currently used** in the
blast-radius computation — only `ml_kem_768` and `ml_dsa_65` are.

## Detectors

**`hash_patch/detect/blast_radius/c_buffers.py`** — tree-sitter C parsing
(the exact parser instance `hash_patch.detect.c` already constructs, not a
second one). Finds:
- stack buffers: `char`/`uint8_t`/`unsigned char`/`int8_t`/`byte NAME[N];`
- heap allocations: `malloc(N)` or `calloc(count, size)` assigned to such a
  name, as a declaration initializer or a plain assignment, optionally
  through a C-style cast

Size resolution is a literal integer, or ONE level of `#define NAME <int>`
resolution within the same file. Anything else — a plain variable, a
`sizeof(...)` expression, an un-`#define`'d macro, arithmetic — is left
unresolved, and **no `SizeConstraint` is emitted for it at all.** Guessing
a size would be worse than reporting nothing.

**`hash_patch/detect/blast_radius/sql_ddl.py`** — a **regex-based**
lightweight parser, not a full SQL grammar (there is no tree-sitter-sql
dependency in this project, and `CREATE TABLE` column lists are regular
enough that a targeted regex is sufficient and easy to audit). It only
recognises `CREATE TABLE (...)` blocks and `<column> <TYPE>(<N>)` column
definitions for `VARCHAR`/`CHAR`/`BINARY`/`VARBINARY`/`BLOB`. Anything
else — constraints, computed columns, `ALTER TABLE`, an unsized `TEXT`/
`BLOB` — is simply not matched. A false negative here is far safer than a
mis-parsed guess.

**Byte-size assumption, stated plainly:** `VARCHAR(N)`/`CHAR(N)` are
treated as **N bytes**, assuming 1 byte per character (ASCII-range
content) — the crypto material these columns are named for (hex- or
base64-encoded keys/signatures/digests) is ASCII-range by construction. A
multi-byte charset storing raw binary in a text column would be unusual
practice and is out of scope. `BINARY(N)`/`VARBINARY(N)`/`BLOB(N)` are
already byte counts, no charset assumption needed.

## Crypto-name matching

Both detectors match the buffer/column identifier (substring,
case-insensitive) against `rules/blast_radius_names.yaml` — one shared
pattern list, loaded once via `hash_patch/detect/blast_radius/names.py`,
never duplicated between the two detectors. Longest pattern first, so e.g.
`rsa_private_key_buf` matches `private_key` (no PQC field — see below)
rather than the shorter `key` it also contains.

Each pattern carries a `field`: `signature`, `pubkey`, `ciphertext`, or
`null`. A `null` field (`privkey`, `private_key`, `cert`, `certificate`,
`digest`, `hash`) means the name is clearly crypto-suggestive but there is
no single PQC field to compare it against — such a `SizeConstraint` is
still emitted (it's real, directly-observed evidence of a size limit), but
`hash_patch/analyze/blast_radius.py` never produces a `BlastRadiusFinding`
for it. **Known false-negative risk:** if crypto material is stored under a
generic name this pattern list doesn't recognise at all (`buf`, `data`,
`payload`, a language-specific idiom), it is invisible to this pillar
entirely — there is no NLP or data-flow tracing here, just name matching.
Extend `rules/blast_radius_names.yaml` for a specific codebase's
conventions rather than trying to anticipate every name.

## The correlation heuristic — and its limits

`hash_patch/analyze/blast_radius.py::compute_blast_radius` takes every
`CryptoAsset` whose `quantum_status` is `BROKEN_BY_SHOR` (the algorithms a
PQC migration actually replaces) and every `SizeConstraint`, and produces a
`BlastRadiusFinding` when:

1. **The SizeConstraint and the CryptoAsset share a file, and the asset is
   the NEAREST plausible one by line distance.** The same-file requirement
   is checked via evidence `locator` equality — **never** across files.
   This is the single most important anti-false-positive property of this
   pillar: a `signature` buffer in one file has no principled relationship
   to an `RSA` call three files away just because both are in the same
   scan target. See `tests/unit/test_blast_radius.py`'s
   `test_cross_file_correlation_never_happens*` tests.

   Within a file, `_pick_correlated_asset` (`hash_patch/analyze/
   blast_radius.py`) picks, for EACH constraint, only the single closest
   same-file candidate asset by line distance — never every same-file
   asset independently. This is what stops a single file that legitimately
   contains multiple, unrelated crypto operations (e.g. both an RSA
   signing routine and an unrelated Ed25519 keygen routine) from letting a
   `SizeConstraint` near one get credited to the *other* algorithm too.
   See `tests/unit/test_blast_radius.py::
   test_rsa_signature_and_ed25519_pubkey_do_not_cross_contaminate` and the
   corpus example below. A candidate asset must also have a primitive that
   maps to a PQC family for which the constraint's name-pattern field is a
   meaningful comparison (see point 2) — ties between two different-family
   candidates at equal line distance are broken in favour of the pke/
   key-agreement family for a `pubkey`-named constraint
   (`_FIELD_FAMILY_PRIORITY`), since that's the one field meaningful for
   both families; proximity alone decides in every other case.
2. **The asset's primitive maps to a PQC family with a size reference.**
   `signature -> ML-DSA-65`; `pke`/`key-agree`/`kem -> ML-KEM-768`. Any
   other primitive (hash, block-cipher, mac, ...) is never correlated —
   Grover-weakened primitives aren't what this pillar predicts, only
   Shor-broken ones. This is always the CORRELATED asset's own detected
   primitive (`_pqc_family_for_primitive(asset.primitive)`), never a
   hardcoded default — e.g. an RSA asset detected via a signing call
   (`RSA_sign`, primitive `signature` in `rules/c_openssl.yaml`) is checked
   against ML-DSA-65, while an RSA asset detected via an encryption/keygen
   call (`RSA_public_encrypt`, `RSA_generate_key_ex`, primitive `pke`) is
   checked against ML-KEM-768. See
   `tests/unit/test_blast_radius.py::test_pqc_family_comes_from_correlated_assets_own_primitive`.
3. **The asset's canonical name has a classical reference size.** Only
   `RSA` (2048/3072/4096, by `parameter_set` when known, defaulting to
   2048), `ECDSA` (P-256), `Ed25519`, and `ECDH` (P-256) do — exactly the
   algorithms `rules/pqc_sizes.yaml`'s `classical` section documents.
   `DSA`, `DH`, `X25519`/`X448`, `Ed448`, and RSA padding-scheme variants
   (`RSASSA-PSS`, `RSA-OAEP`, `RSA-PKCS1v15`) have no classical reference
   size here and are simply never correlated. This only affects the
   informational `classical_bytes` field on a finding, never whether it
   fires.
4. **The PQC replacement's relevant field exceeds `declared_bytes`.**
   `overflow_bytes = pqc_bytes - declared_bytes`. A buffer that already
   fits the PQC replacement produces no finding at all.

### The `db_column` name-pattern-only fallback

No detector in this codebase produces a `CryptoAsset` from a `.sql` file —
there is no SQL algorithm detector. Under rule 1 above, a `db_column`
`SizeConstraint` can therefore *never* have a same-file `CryptoAsset` to
correlate against. Rather than silently never firing for SQL DDL at all,
or loosening same-file correlation for `db_column` specifically (which
would reopen the exact cross-file risk rule 1 exists to prevent),
`compute_blast_radius` runs a second pass: any `db_column` constraint that
found no same-file `CryptoAsset` gets a finding synthesized directly from
its own name pattern (`signature -> ML-DSA-65`, `ciphertext -> ML-KEM-768`,
`pubkey ->` the larger, more conservative of the two — ML-DSA-65's
1952-byte pubkey beats ML-KEM-768's 1184-byte one, so this default never
*understates* the blast radius), with a synthetic `asset_id` of
`"blast-radius-inferred:<field>"` instead of a real `CryptoAsset` id.

This is deliberately weaker evidence than a real correlation. Rather than
being silently dropped from the CBOM (there is no real, pre-existing
`CryptoAsset` component to mirror it onto), `hash_patch/cli.py::
_attach_blast_radius_properties` builds a SYNTHETIC `CryptoAsset` for it
(`_synthetic_asset_for_inferred_finding`) — named after the inferred PQC
family (e.g. `"ML-DSA-65 (inferred)"`), typed `cryptographic-asset` like
every other component, carrying the `SizeConstraint`'s own evidence (so
CLAUDE.md hard constraint #3 is still satisfied: it points at the real
`.sql` file/line), and with `hash_patch:confidence = "inferred"` rather
than `"confirmed"` — never merged into the confirmed inventory as if it
were an equivalent, direct observation (CLAUDE.md's "Name" section). This
makes the finding visible in the actual written CBOM, not just the CLI
summary line and `ScanResult.blast_radius_findings`. See
`tests/golden/test_blast_radius_golden.py::
test_sql_inferred_finding_is_emitted_as_a_synthetic_cbom_component`.

## Severity and effort — heuristic placeholders

**Severity** is derived solely from `overflow_bytes`, in four
coarse, arbitrarily-chosen bands (not calibrated against real incident
data): `< 256 -> low`, `256-1023 -> medium`, `1024-4095 -> high`,
`>= 4096 -> critical`. See
`hash_patch/analyze/blast_radius.py::_severity_for_overflow`.

**`estimated_effort_days` is a heuristic placeholder, NOT derived from
real migration data.** Base 0.5 engineer-days per finding; +0.5 if the
constraint is a `db_column` (schema migrations — `ALTER TABLE`, backfills,
downstream consumers — cost more than resizing a buffer). See
`hash_patch/analyze/blast_radius.py::_estimate_effort_days`. Do not present
this number to a stakeholder as a real estimate; it exists to give a
scan's overall summary line a rough sense of scale, nothing more.

## CLI wiring

`hash-patch scan PATH --output FILE` runs this pillar automatically
whenever the scanned file set contains `.c`/`.h`/`.cpp`/`.cc`/`.cxx`/
`.hpp`/`.hh` and/or `.sql` files. Findings with a real correlated
`CryptoAsset` are mirrored onto that asset's CBOM component as
`hash_patch:property.blastRadius.<kind>.<name>.<line>` properties (JSON
value: `declaredBytes`, `classicalBytes`, `pqcBytes`, `overflowBytes`,
`pqcReplacement`, `severity`, `estimatedEffortDays`, `locator`) — the same
free-form `properties` bag / `hash_patch:property.<key>` namespacing
CLAUDE.md already documents, not a new top-level CBOM section. A finding
with no real correlated `CryptoAsset` (the `db_column` name-pattern-only
fallback — see above) gets a SYNTHETIC component of its own instead, with
the same `blastRadius.*` property and `hash_patch:confidence = "inferred"`.
Every scan prints a summary line: `N blast-radius findings, estimated M
engineer-days`.

## Corpus

`testdata/c/blast_radius_examples.c` and `testdata/sql/schema.sql`, with
expected outcomes in `tests/golden/blast_radius_manifest.json` (checked by
`tests/golden/test_blast_radius_golden.py`) and exercised individually by
`tests/unit/test_blast_radius.py`.
