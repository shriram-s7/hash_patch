"""tests/golden/test_python_hashlib_golden.py

Golden-corpus test for the hashlib coverage-gap fix
(rules/python_crypto.yaml's new `hashlib` namespace + the
hashlib.new()/hmac.new() special-shape handling in
hash_patch/detect/python.py).

Scans two new fixtures with a fixed timestamp and compares against their
own golden CBOM JSON files:
  - testdata/python/hashlib_sha256_alone.py — the exact minimal
    reproduction from the bug report (see that file's own docstring).
  - testdata/python/hashlib_examples.py — hmac.new()'s hashlib-referenced
    digestmod argument, hashlib.new("<literal>"), and the unresolvable
    (variable-named) hashlib.new() negative case.

To regenerate:
    HASH_PATCH_REGEN_GOLDEN=1 pytest tests/golden/test_python_hashlib_golden.py
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hash_patch.detect.python import PythonCryptoDetector
from hash_patch.emit import render_cbom_json, to_cyclonedx, validate_cbom
from hash_patch.model.findings import ScanResult

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)
FIXED_TIMESTAMP_STR = "2026-01-01T00:00:00+00:00"

REGEN = os.environ.get("HASH_PATCH_REGEN_GOLDEN", "").strip().lower() in ("1", "true", "yes")

CASES = {
    "alone": {
        "fixture": REPO_ROOT / "testdata" / "python" / "hashlib_sha256_alone.py",
        "golden": REPO_ROOT / "tests" / "golden" / "python_hashlib_sha256_alone_expected.json",
        "expected_component_count": 1,
    },
    "examples": {
        "fixture": REPO_ROOT / "testdata" / "python" / "hashlib_examples.py",
        "golden": REPO_ROOT / "tests" / "golden" / "python_hashlib_examples_expected.json",
        # MD5 (hashlib.new("md5")) + SHA-256 (hmac.new's hashlib.sha256
        # digestmod) + UNRESOLVED (dynamic_checksum()'s variable-named hashlib.new()).
        "expected_component_count": 3,
    },
}


def _build_doc(fixture: Path) -> dict:  # type: ignore[type-arg]
    result = ScanResult(
        target=str(fixture),
        assets=[],
        scan_started_at=FIXED_TIMESTAMP,
        tool_version="0.1.0",
    )
    for asset in PythonCryptoDetector().detect(fixture):
        result.add_asset(asset)
    doc = to_cyclonedx(result)
    doc["metadata"]["timestamp"] = FIXED_TIMESTAMP_STR
    return doc


def _regen_golden(doc: dict, golden_file: Path) -> None:  # type: ignore[type-arg]
    golden_file.write_text(render_cbom_json(doc), encoding="utf-8")
    print(f"\n[regen] Wrote golden: {golden_file}")


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


@pytest.mark.parametrize("case_name", sorted(CASES))
def test_fixture_exists(case_name: str) -> None:
    assert CASES[case_name]["fixture"].is_file()


@pytest.mark.parametrize("case_name", sorted(CASES))
def test_golden_file_exists(case_name: str) -> None:
    if REGEN:
        pytest.skip("Regen mode")
    golden_file = CASES[case_name]["golden"]
    assert golden_file.is_file(), f"Missing: {golden_file}. Run with HASH_PATCH_REGEN_GOLDEN=1."


@pytest.mark.parametrize("case_name", sorted(CASES))
def test_hashlib_golden_corpus(case_name: str) -> None:
    case = CASES[case_name]
    doc = _build_doc(case["fixture"])
    if REGEN:
        _regen_golden(doc, case["golden"])
        pytest.skip("Golden regenerated; re-run without HASH_PATCH_REGEN_GOLDEN to verify.")

    assert case["golden"].is_file()
    live = json.loads(render_cbom_json(doc))
    golden = json.loads(case["golden"].read_text(encoding="utf-8"))
    assert live.get("serialNumber", "").startswith("urn:uuid:")
    assert _normalize_doc(live) == _normalize_doc(golden), (
        f"Live CBOM does not match golden file for case {case_name!r}.\n"
        f"Live:   {[c['name'] for c in live.get('components', [])]}\n"
        f"Golden: {[c['name'] for c in golden.get('components', [])]}\n"
        "Run with HASH_PATCH_REGEN_GOLDEN=1 to regenerate."
    )


@pytest.mark.parametrize("case_name", sorted(CASES))
def test_hashlib_golden_validates_against_cyclonedx_schema(case_name: str) -> None:
    doc = _build_doc(CASES[case_name]["fixture"])
    errors = validate_cbom(doc)
    assert errors == [], "Schema validation failed:\n" + "\n".join(errors)


@pytest.mark.parametrize("case_name", sorted(CASES))
def test_hashlib_golden_has_expected_component_count(case_name: str) -> None:
    case = CASES[case_name]
    doc = _build_doc(case["fixture"])
    assert len(doc["components"]) == case["expected_component_count"], (
        f"Expected {case['expected_component_count']} components for {case_name!r}, "
        f"got {len(doc['components'])}: {[c['name'] for c in doc['components']]}"
    )


@pytest.mark.parametrize("case_name", sorted(CASES))
def test_hashlib_golden_components_sorted_by_bom_ref(case_name: str) -> None:
    doc = _build_doc(CASES[case_name]["fixture"])
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs == sorted(refs)


@pytest.mark.parametrize("case_name", sorted(CASES))
def test_hashlib_golden_all_components_have_occurrences(case_name: str) -> None:
    doc = _build_doc(CASES[case_name]["fixture"])
    for comp in doc["components"]:
        occs = comp.get("evidence", {}).get("occurrences", [])
        assert len(occs) >= 1, f"Component {comp['name']!r} has no evidence occurrences"


@pytest.mark.parametrize("case_name", sorted(CASES))
def test_hashlib_golden_occurrences_have_location_line_offset(case_name: str) -> None:
    doc = _build_doc(CASES[case_name]["fixture"])
    for comp in doc["components"]:
        for occ in comp.get("evidence", {}).get("occurrences", []):
            assert occ.get("location"), f"Missing location in {comp['name']!r}"
            assert occ.get("line") and occ["line"] > 0
            assert occ.get("offset") is not None and occ["offset"] >= 0


def test_hashlib_sha256_alone_is_a_single_sha256_weakened_by_grover_finding() -> None:
    """The literal bug-report assertion: hashlib.sha256() scanned in
    isolation must produce exactly one SHA-256 finding, weakened-by-grover.
    """
    doc = _build_doc(CASES["alone"]["fixture"])
    assert len(doc["components"]) == 1
    comp = doc["components"][0]
    assert comp["name"] == "SHA-256"
    props = {p["name"]: p["value"] for p in comp.get("properties", [])}
    assert props.get("hash_patch:quantumStatus") == "weakened-by-grover"
