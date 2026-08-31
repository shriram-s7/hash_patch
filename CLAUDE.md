# PRATYAKSHA — Project Constitution

## One-liner

PRATYAKSHA is an offline cryptographic discovery and post-quantum risk analysis
tool. It scans source code, binaries, container images, config/IaC, and live
network endpoints to find every cryptographic asset (algorithms, keys,
certificates, protocols, libraries, HSM/KMS usage) and emits a CycloneDX 1.6
(ECMA-424) Cryptography Bill of Materials (CBOM). Built for Smart India
Hackathon 2026, Problem Statement 26164 (NTRO).

## Name

PRATYAKSHA (प्रत्यक्ष) means "direct perception" — the first and most
authoritative pramana (valid means of knowledge) in Indian epistemology:
knowledge obtained by directly observing a thing, as opposed to anumana
(inference) or shabda (testimony). This is the project's core principle.
Every finding MUST carry direct evidence: file, line, column, byte offset,
snippet. Inference (e.g. local LLM output) without corroborating direct
evidence is labelled `pratyaksha:confidence = inferred` and is NEVER merged
into the confirmed inventory.

## Hard constraints (non-negotiable)

These are enforced by CI and by design; do not weaken them to make a feature
easier to build.

1. **Fully offline at scan time.** No component involved in scanning may make
   a network call during a scan. Network access is permitted only in dev
   tooling (linters, package installs) and in tests that explicitly opt into
   network access (e.g. a test that spins up a local mock server is fine; a
   test that reaches the public internet is not).
2. **Deterministic output.** Scanning the same input twice must produce a
   byte-identical CBOM, with the sole exception of the scan timestamp field.
   No randomness, no dict/set iteration-order leakage, no wall-clock reads,
   no uuid4() anywhere in the identity or ordering of output. This is
   enforced by a CI test — do not introduce anything that could break it.
3. **Hard evidence or it doesn't exist.** Every `CryptoAsset` must carry at
   least one `Evidence` entry with a locator (file path, URL, or image ref)
   and, wherever applicable, line, column, byte offset, and snippet. A
   finding with no evidence must never be constructed, emitted, or merged
   into the model.

## Directory layout

```
pratyaksha/
  cli.py           typer CLI entry point
  model/           internal representation (Evidence, CryptoAsset, ScanResult) — pydantic v2
  detect/          Detector base class + registry; concrete detectors live here later
  analyze/         post-quantum risk / reachability analysis over detected assets
  emit/            CBOM (CycloneDX 1.6) and other output serializers
  recommend/       migration / remediation recommendation logic
rules/             YAML detection rules (algorithm signatures, OIDs, patterns)
ontology/          crypto/PQC ontology data (quantum-status mappings, etc.)
schemas/           vendored official CycloneDX JSON schemas (bom-1.6, spdx, jsf-0.82)
                    — downloaded once at build/dev time, committed, used offline
                    at test/scan time; see "Output format" below
tests/
  unit/            fast, isolated unit tests
  golden/          golden-corpus tests: fixed input -> expected CBOM output
testdata/          sample inputs used by tests and golden corpus
docs/              design notes and documentation
```

## Output format

**Implementation path chosen: PATH A — `cyclonedx-python-lib`.** Re-verified
before extending the emitter (installed version 11.12.0, checked again
2026-08-31): `cyclonedx.model.crypto` has first-class, complete CycloneDX 1.6
cryptographic-asset support — `CryptoProperties`, `AlgorithmProperties`,
`CertificateProperties`, `ProtocolProperties`, `RelatedCryptoMaterialProperties`,
the `CryptoAssetType` / `CryptoPrimitive` / `CryptoFunction` / `CryptoMode`
enums (values match the spec exactly: `CryptoAssetType` = `algorithm` /
`certificate` / `protocol` / `related-crypto-material`), `ComponentType.CRYPTOGRAPHIC_ASSET`,
and `SchemaVersion.V1_6` / `JsonV1Dot6` output. `ComponentEvidence.occurrences`
(`Occurrence(location, line, offset, symbol, additional_context)`) is present
with a `SchemaVersion1Dot6` view. Given that, PATH B (hand-building JSON) was
not needed. `to_cyclonedx()` (`pratyaksha/emit/cyclonedx.py`) builds the object
model through the library, serializes via `make_outputter(..., SchemaVersion.V1_6)`,
re-parses to a plain `dict`, then runs its own explicit determinism
normalization pass (see below) before returning. We still vendor the official
schema and validate against it independently in tests — using the library
does not substitute for standards-conformance proof.

**Vendored schema.** `schemas/bom-1.6.schema.json`, `schemas/spdx.schema.json`,
and `schemas/jsf-0.82.schema.json` — official CycloneDX 1.6 schemas, tag `1.6`
of `CycloneDX/specification`, fetched (and re-verified byte-identical to
upstream) 2026-08-31. Source URLs and re-fetch instructions are in
`schemas/README.md`. `pratyaksha/emit/validate.py::validate_cbom` resolves
`$ref`s (`spdx.schema.json`, `jsf-0.82.schema.json#/definitions/signature`)
purely from these local files via a `referencing.Registry` keyed by each
schema's own `$id` — no network access at scan time or test time, ever. This
is the one validator both the CLI's `--validate` flag and
`tests/unit/test_cyclonedx.py` go through, so what's tested is what ships.

**Note:** `cyclonedx-python-lib`'s JSON output stage auto-injects a flat
`dependencies` array (one entry per component, no `dependsOn`) via its
internal `BomDependencyGraphFlatMerger`. We did not ask for this and our
model has no dependency-graph concept yet; it is harmless (schema-valid, and
happens to already be sorted) but is a library behavior to be aware of, not
something `to_cyclonedx` added.

**Determinism.**
- The BOM `serialNumber` is `uuid5(NAMESPACE_URL, f"pratyaksha:cbom:{target}:{sorted_asset_ids}")`
  — derived from the scan target *and* the full sorted set of emitted asset
  ids, never `uuid4()`. Two scans of the same target that found the same
  assets always get the same serial number, regardless of insertion order;
  a scan that found different assets gets a different one.
- `metadata.timestamp` (from `ScanResult.scan_started_at`) is the *only*
  field allowed to vary between runs over identical input.
- Before returning, `to_cyclonedx()` runs `_sort_document_for_determinism`
  on the plain dict: components sorted by `bom-ref`, each component's
  `properties` sorted by `name`, each component's evidence `occurrences`
  sorted by `(location, line, offset)`, each `cryptoFunctions` list sorted.
  This is deliberately a post-process over the library's own output rather
  than relying on `cyclonedx-python-lib`'s internal `SortedSet` ordering
  (which sorts components by `(type, group, name, version, bom-ref, ...)`,
  not bom-ref-first, and is an internal detail that could change across
  library versions) — it's the one thing in this pipeline we make an
  explicit, tested contract rather than an implicit dependency.
- `render_cbom_json()` is the single canonical serializer
  (`json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False)` plus a
  trailing newline) that every writer — CLI, `write_cbom`, tests — goes
  through, so nothing downstream can reintroduce nondeterministic key order.
- Tested four ways in `tests/unit/test_cyclonedx.py`: shuffled asset
  insertion order + shuffled evidence order with two different timestamps
  (byte-identical after stripping `metadata.timestamp`); a fresh
  `python -c` subprocess with `PYTHONHASHSEED` unset compared against the
  in-process render (catches hash-randomization leaks the in-process test
  alone would miss); repeated `serialNumber` across two independent runs;
  and namespace hygiene (every component property name starts with
  `pratyaksha:`).

**Field mapping.**
- `AssetType` → `cryptoProperties.assetType`.
- `algorithmProperties` is populated **only when `asset_type is ALGORITHM`**:
  `primitive`, `parameter_set` → `parameterSetIdentifier`, `mode` (mapped
  when it matches the CycloneDX `CryptoMode` enum), `crypto_functions` →
  `cryptoFunctions` (mapped when each value matches the CycloneDX
  `CryptoFunction` enum, sorted), `nist_quantum_security_level` →
  `nistQuantumSecurityLevel`. `executionEnvironment` / `certificationLevel`
  are never emitted — our internal model has no such fields, and we never
  invent values for them. For certificate / protocol / related-crypto-material
  assets, `algorithmProperties` is omitted entirely rather than filled with
  a meaningless `primitive: unknown` — our internal model has no
  certificate-specific (subject/issuer/validity) or protocol-specific
  (cipher suite) fields, so `certificateProperties`/`protocolProperties`
  are correspondingly never populated either; there is nothing evidenced to
  put there.
- `oid` → `cryptoProperties.oid` on every asset type, when known.
- `bom-ref` = `CryptoAsset.id` verbatim (already a deterministic derived
  value; see `derive_asset_id`).
- `Evidence.locator/line/byte_offset` → `Occurrence.location/line/offset`
  (direct CycloneDX homes). `Occurrence.symbol` is never populated — it
  names a programming-language symbol/import, which is not what our
  `Evidence.snippet` is, and we don't repurpose fields.
- **Fields with no standard CycloneDX home** (never silently dropped, per
  hard constraint #3 — all under the `pratyaksha:` namespace, camelCase):
  - `Evidence.source_type`, `.column`, `.snippet` have no structured field
    on `occurrenceType`. They are folded into that occurrence's
    `additionalContext` as a compact JSON object, scoped to the correct
    piece of evidence rather than flattened into unscoped component-level
    properties.
  - `CryptoAsset.quantum_status` → `pratyaksha:quantumStatus`,
    `.reachability` → `pratyaksha:reachability`.
  - The sorted, comma-joined set of `Evidence.detector_id` /
    `.detector_version` values across an asset's evidence →
    `pratyaksha:detectorId` / `pratyaksha:detectorVersion`. Tradeoff: if a
    single asset has evidence from more than one distinct detector, which
    *specific* evidence came from which detector is not preserved beyond
    this asset-level aggregate (only `additionalContext`'s source_type/
    column/snippet stay per-occurrence).
  - `pratyaksha:confidence` is always `"confirmed"`. Every asset that
    reaches this module already has ≥1 `Evidence` (enforced below), so
    every emitted finding is, by construction, direct-evidence. The
    `inferred` value described in CLAUDE.md's Name section is reserved for
    a future inference pathway (e.g. local-LLM-assisted detection) that
    the model does not yet support — there is no code path today that can
    construct an asset without evidence, so `confidence` cannot currently
    be anything else.
  - Any `crypto_functions` / `mode` value that does *not* match the
    CycloneDX enum is preserved verbatim in
    `pratyaksha:cryptoFunctionsUnmapped` / `pratyaksha:modeUnmapped` rather
    than being coerced or dropped.
  - `CryptoAsset.properties` (our own free-form bag) maps to
    `pratyaksha:property.<key>`.
- An asset with zero `Evidence` is refused at emit time (`ValueError`) —
  this is the emitter-level enforcement of hard constraint #3.

**CLI.** `pratyaksha scan PATH --output FILE` writes the CBOM.
`--validate/--no-validate` (default: validate) runs the emitted document
through `validate_cbom` and exits non-zero — printing each schema error to
stderr — without writing the output file if it fails. Every run prints a
one-line summary: asset count broken down by quantum status
(`N assets (status=count, ...)`).

**Known limitation.** `pratyaksha/emit/validate.py` locates `schemas/` via
`Path(__file__).resolve().parents[2]`, i.e. relative to the source tree.
This holds for the editable dev install this project currently uses; a
real (non-editable) wheel install would need `schemas/` declared as package
data to keep working. Not solved here — out of scope until this ships as a
distributed package.

## Detection rules live in YAML, not Python

All algorithm/pattern/OID detection rules belong in `rules/` as YAML data,
loaded at runtime. `pratyaksha/detect/` contains detector *mechanics* (how to
walk a target, how to invoke a matcher, how to attach evidence) — it must
never contain a hardcoded table of algorithm names, OIDs, or regex patterns
for a specific crypto primitive. If you catch yourself writing
`if name == "RSA":` in a detector, stop and move that fact into a rules/*.yaml
file instead.

## Testing convention

Every new detector requires:
1. A unit test in `tests/unit/` exercising it in isolation.
2. A golden-corpus entry: a fixture under `testdata/` plus an expected-output
   fixture under `tests/golden/`, asserting the detector's output is stable
   and correct against real (or realistic) input.

## DO NOT

- Do NOT add network calls anywhere on a scan path (detect/, analyze/,
  emit/, recommend/, or anything the CLI `scan` command touches).
- Do NOT use `uuid4()` or `datetime.now()` (or any other non-deterministic
  or wall-clock-dependent source) inside anything that contributes to a
  `CryptoAsset.id` or to output ordering. Asset IDs are derived
  deterministically from asset identity fields (see
  `pratyaksha/model/assets.py::derive_asset_id`).
- Do NOT hardcode algorithm/OID/pattern detection rules in Python. They
  belong in `rules/` as YAML.
- Do NOT construct or emit a finding/asset without at least one `Evidence`
  entry.
- Do NOT fetch `schemas/*.json` (or any other schema/spec) over the network
  from `emit/` or from tests. They are vendored and committed; re-fetch them
  only as a deliberate, one-off dev-tooling step when bumping the CycloneDX
  version, the same way they were first added.
- Do NOT use `uuid4()` for the CBOM `serialNumber` either. It is derived via
  `uuid5(NAMESPACE_URL, ...)` from the scan target (see
  `pratyaksha/emit/cyclonedx.py::_derive_serial_number`).
