from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema
from referencing import Registry, Resource

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


@lru_cache(maxsize=1)
def _load_schema_validator() -> jsonschema.Draft7Validator:
    """Build a jsonschema validator for the vendored CycloneDX 1.6 schema.

    Resolves $refs (spdx.schema.json, jsf-0.82.schema.json#/definitions/signature)
    purely from the local vendored files under schemas/ -- never over the
    network, at scan time or test time (see CLAUDE.md hard constraint #1 and
    "DO NOT"). This is the single validator both the CLI's --validate flag
    and tests/unit/test_cyclonedx.py go through.
    """
    bom_schema = json.loads((SCHEMAS_DIR / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    spdx_schema = json.loads((SCHEMAS_DIR / "spdx.schema.json").read_text(encoding="utf-8"))
    jsf_schema = json.loads((SCHEMAS_DIR / "jsf-0.82.schema.json").read_text(encoding="utf-8"))

    registry = Registry().with_resources(
        [
            (spdx_schema["$id"], Resource.from_contents(spdx_schema)),
            (jsf_schema["$id"], Resource.from_contents(jsf_schema)),
        ]
    )
    return jsonschema.Draft7Validator(bom_schema, registry=registry)


def validate_cbom(doc: dict[str, Any]) -> list[str]:
    """Validate doc against the vendored CycloneDX 1.6 schema.

    Returns a list of human-readable "<path>: <message>" error strings,
    empty if the document is valid.
    """
    validator = _load_schema_validator()
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    return [f"{'.'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
