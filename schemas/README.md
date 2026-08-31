# Vendored CycloneDX schemas

These files are the official CycloneDX 1.6 JSON schemas, downloaded once as a
dev-tooling step (network access is allowed here — see CLAUDE.md hard
constraint #1) and committed so that scan-time and test-time stay fully
offline.

| File | Source | Fetched |
|---|---|---|
| `bom-1.6.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/refs/tags/1.6/schema/bom-1.6.schema.json | 2026-08-31 |
| `spdx.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/refs/tags/1.6/schema/spdx.schema.json | 2026-08-31 |
| `jsf-0.82.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/refs/tags/1.6/schema/jsf-0.82.schema.json | 2026-08-31 |

`bom-1.6.schema.json` is the entry point; it `$ref`s `spdx.schema.json`
(license expressions) and `jsf-0.82.schema.json#/definitions/signature`
(JSON Signature Format, used for BOM signatures). All three were fetched
from tag `1.6` of the official `CycloneDX/specification` repository — the
tagged release, not a moving branch, so re-fetching later will not silently
change these files underneath us.

## Re-fetching

Only do this deliberately, as a one-off dev-tooling step, when bumping the
CycloneDX spec version this project targets (see CLAUDE.md "DO NOT"). Never
fetch these at scan time or test time.

```bash
curl -sSL -o schemas/bom-1.6.schema.json \
  https://raw.githubusercontent.com/CycloneDX/specification/refs/tags/1.6/schema/bom-1.6.schema.json
curl -sSL -o schemas/spdx.schema.json \
  https://raw.githubusercontent.com/CycloneDX/specification/refs/tags/1.6/schema/spdx.schema.json
curl -sSL -o schemas/jsf-0.82.schema.json \
  https://raw.githubusercontent.com/CycloneDX/specification/refs/tags/1.6/schema/jsf-0.82.schema.json
```

## Offline validation

Tests resolve `bom-1.6.schema.json`'s `$ref`s purely from these local files,
via a `referencing.Registry` keyed by each schema's own `$id`
(`http://cyclonedx.org/schema/spdx.schema.json` and
`http://cyclonedx.org/schema/jsf-0.82.schema.json`) — no network call is
made during `pytest`. See `tests/unit/test_cyclonedx.py::_load_schema_validator`.
