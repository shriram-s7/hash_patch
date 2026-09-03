"""tests/golden/test_java_golden.py

Golden-corpus test for the Java JCA/JCE detector.

The test scans testdata/java/crypto_examples.java with a fixed timestamp
and compares the resulting CBOM JSON (minus the timestamp field) against
tests/golden/java_jca_expected.json.

To regenerate the golden file after an intentional change:
    PRATYAKSHA_REGEN_GOLDEN=1 pytest tests/golden/test_java_golden.py

PRATYAKSHA constraints enforced here:
  - No algorithm names hardcoded in this file.
  - The golden file is the source of truth for expected output; the test
    only verifies the live detector matches it.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hash_patch.detect.java import JavaJcaDetector
from hash_patch.emit import render_cbom_json, to_cyclonedx, validate_cbom
from hash_patch.model.findings import ScanResult

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "testdata" / "java" / "crypto_examples.java"
GOLDEN_FILE = REPO_ROOT / "tests" / "golden" / "java_jca_expected.json"

# Fixed timestamp used both when generating and when comparing the golden file.
# The golden file stores this exact string in metadata.timestamp so the
# comparison strips it cleanly.
FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)
FIXED_TIMESTAMP_STR = "2026-01-01T00:00:00+00:00"

REGEN = (os.environ.get("HASH_PATCH_REGEN_GOLDEN", "") or os.environ.get("PRATYAKSHA_REGEN_GOLDEN", "")).strip().lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Helper: build deterministic CBOM document from the fixture
# ---------------------------------------------------------------------------


def _build_doc() -> dict:  # type: ignore[type-arg]
    result = ScanResult(
        target=str(FIXTURE),
        assets=[],
        scan_started_at=FIXED_TIMESTAMP,
        tool_version="0.1.0",
    )
    detector = JavaJcaDetector()
    for asset in detector.detect(FIXTURE):
        result.add_asset(asset)

    doc = to_cyclonedx(result)
    # Normalise the timestamp to the fixed sentinel so golden comparisons work.
    doc["metadata"]["timestamp"] = FIXED_TIMESTAMP_STR
    return doc


# ---------------------------------------------------------------------------
# Regeneration helper (used when PRATYAKSHA_REGEN_GOLDEN=1)
# ---------------------------------------------------------------------------


def _regen_golden(doc: dict) -> None:  # type: ignore[type-arg]
    golden_json = render_cbom_json(doc)
    GOLDEN_FILE.write_text(golden_json, encoding="utf-8")
    print(f"\n[regen] Wrote golden file: {GOLDEN_FILE}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


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


def test_golden_file_exists() -> None:
    """The golden file must exist (checked in before any comparison test)."""
    if REGEN:
        pytest.skip("Regen mode — golden file may be overwritten by other tests")
    assert GOLDEN_FILE.is_file(), (
        f"Golden file missing: {GOLDEN_FILE}\n"
        "Run with PRATYAKSHA_REGEN_GOLDEN=1 to generate it."
    )


def test_java_golden_corpus() -> None:
    """Live detector output must match the committed golden CBOM, byte-for-byte
    (after normalising the timestamp field).
    """
    doc = _build_doc()

    if REGEN:
        _regen_golden(doc)
        pytest.skip("Golden file regenerated; re-run without PRATYAKSHA_REGEN_GOLDEN to verify.")

    assert GOLDEN_FILE.is_file(), (
        f"Golden file missing: {GOLDEN_FILE}. "
        "Run with PRATYAKSHA_REGEN_GOLDEN=1 to generate it."
    )

    live_json = render_cbom_json(doc)
    golden_json = GOLDEN_FILE.read_text(encoding="utf-8")

    # Compare as parsed dicts so we get a structured diff on failure.
    live_parsed = json.loads(live_json)
    golden_parsed = json.loads(golden_json)

    assert live_parsed.get("serialNumber", "").startswith("urn:uuid:")
    assert _normalize_doc(live_parsed) == _normalize_doc(golden_parsed), (
        "Live CBOM does not match golden file.\n"
        f"Golden:  {GOLDEN_FILE}\n"
        f"Live components: {[c['name'] for c in live_parsed.get('components', [])]}\n"
        f"Golden components: {[c['name'] for c in golden_parsed.get('components', [])]}\n"
        "Run with PRATYAKSHA_REGEN_GOLDEN=1 to regenerate if this is an intentional change."
    )


def test_golden_cbom_validates_against_cyclonedx_schema() -> None:
    """The golden CBOM (and live output) must validate against CycloneDX 1.6."""
    doc = _build_doc()

    errors = validate_cbom(doc)
    assert errors == [], (
        "Schema validation failed for live CBOM:\n" + "\n".join(errors)
    )


def test_golden_has_expected_asset_count() -> None:
    """The fixture contains known algorithm calls; we expect 7 unique assets."""
    doc = _build_doc()
    # RSA, AES, MD5, SHA-1, EC, ECDSA, SHA-256
    assert len(doc["components"]) == 7, (
        f"Expected 7 unique crypto assets, got {len(doc['components'])}: "
        f"{[c['name'] for c in doc['components']]}"
    )


def test_golden_components_sorted_by_bom_ref() -> None:
    """Components must be sorted by bom-ref (determinism requirement)."""
    doc = _build_doc()
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs == sorted(refs)


def test_golden_all_components_have_occurrences() -> None:
    """Every component must carry at least one evidence occurrence (hard constraint #3)."""
    doc = _build_doc()
    for component in doc["components"]:
        occurrences = component.get("evidence", {}).get("occurrences", [])
        assert len(occurrences) >= 1, (
            f"Component {component['name']!r} has no evidence occurrences"
        )


def test_golden_occurrences_have_location_line_offset() -> None:
    """Each occurrence must have location, line, and offset populated."""
    doc = _build_doc()
    for component in doc["components"]:
        for occ in component.get("evidence", {}).get("occurrences", []):
            assert occ.get("location"), f"Missing location in {component['name']!r}"
            assert occ.get("line") is not None and occ["line"] > 0, (
                f"Missing/zero line in {component['name']!r}"
            )
            assert occ.get("offset") is not None and occ["offset"] >= 0, (
                f"Missing/negative offset in {component['name']!r}"
            )
