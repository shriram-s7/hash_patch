"""tests/golden/test_go_bcrypt_golden.py

Golden-corpus test for the golang.org/x/crypto/bcrypt coverage-gap fix
found in the post-hashlib-fix audit (see docs/COVERAGE.md).

Scans testdata/go/bcrypt_examples.go with a fixed timestamp and compares
against tests/golden/go_bcrypt_expected.json.

To regenerate:
    HASH_PATCH_REGEN_GOLDEN=1 pytest tests/golden/test_go_bcrypt_golden.py
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hash_patch.detect.go import GoCryptoDetector
from hash_patch.emit import render_cbom_json, to_cyclonedx, validate_cbom
from hash_patch.model.findings import ScanResult

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "testdata" / "go" / "bcrypt_examples.go"
GOLDEN_FILE = REPO_ROOT / "tests" / "golden" / "go_bcrypt_expected.json"
FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)
FIXED_TIMESTAMP_STR = "2026-01-01T00:00:00+00:00"

REGEN = os.environ.get("HASH_PATCH_REGEN_GOLDEN", "").strip().lower() in ("1", "true", "yes")


def _build_doc() -> dict:  # type: ignore[type-arg]
    result = ScanResult(
        target=str(FIXTURE),
        assets=[],
        scan_started_at=FIXED_TIMESTAMP,
        tool_version="0.1.0",
    )
    for asset in GoCryptoDetector().detect(FIXTURE):
        result.add_asset(asset)
    doc = to_cyclonedx(result)
    doc["metadata"]["timestamp"] = FIXED_TIMESTAMP_STR
    return doc


def _regen_golden(doc: dict) -> None:  # type: ignore[type-arg]
    GOLDEN_FILE.write_text(render_cbom_json(doc), encoding="utf-8")
    print(f"\n[regen] Wrote golden: {GOLDEN_FILE}")


def _normalize_doc(doc: dict) -> dict:  # type: ignore[type-arg]
    d = json.loads(json.dumps(doc))
    d.pop("serialNumber", None)
    for c in d.get("components", []):
        for occ in c.get("evidence", {}).get("occurrences", []):
            if "location" in occ:
                loc = occ["location"].replace("\\", "/")
                idx = loc.find("testdata/")
                if idx != -1:
                    occ["location"] = loc[idx:]
    return d


def test_fixture_exists() -> None:
    assert FIXTURE.is_file()


def test_golden_file_exists() -> None:
    if REGEN:
        pytest.skip("Regen mode")
    assert GOLDEN_FILE.is_file(), f"Missing: {GOLDEN_FILE}. Run with HASH_PATCH_REGEN_GOLDEN=1."


def test_bcrypt_golden_corpus() -> None:
    doc = _build_doc()
    if REGEN:
        _regen_golden(doc)
        pytest.skip("Golden regenerated; re-run without HASH_PATCH_REGEN_GOLDEN to verify.")

    assert GOLDEN_FILE.is_file()
    live = json.loads(render_cbom_json(doc))
    golden = json.loads(GOLDEN_FILE.read_text(encoding="utf-8"))
    assert live.get("serialNumber", "").startswith("urn:uuid:")
    assert _normalize_doc(live) == _normalize_doc(golden), (
        "Live CBOM does not match golden file.\n"
        f"Live:   {[c['name'] for c in live.get('components', [])]}\n"
        f"Golden: {[c['name'] for c in golden.get('components', [])]}\n"
        "Run with HASH_PATCH_REGEN_GOLDEN=1 to regenerate."
    )


def test_bcrypt_golden_validates_against_cyclonedx_schema() -> None:
    errors = validate_cbom(_build_doc())
    assert errors == [], "Schema validation failed:\n" + "\n".join(errors)


def test_bcrypt_golden_has_expected_component_count() -> None:
    doc = _build_doc()
    assert len(doc["components"]) == 1, (
        f"Expected 1 component (bcrypt), got {len(doc['components'])}: "
        f"{[c['name'] for c in doc['components']]}"
    )


def test_bcrypt_golden_all_components_have_occurrences() -> None:
    doc = _build_doc()
    for comp in doc["components"]:
        occs = comp.get("evidence", {}).get("occurrences", [])
        assert len(occs) >= 1, f"Component {comp['name']!r} has no evidence occurrences"


def test_bcrypt_golden_occurrences_have_location_line_offset() -> None:
    doc = _build_doc()
    for comp in doc["components"]:
        for occ in comp.get("evidence", {}).get("occurrences", []):
            assert occ.get("location"), f"Missing location in {comp['name']!r}"
            assert occ.get("line") and occ["line"] > 0
            assert occ.get("offset") is not None and occ["offset"] >= 0
