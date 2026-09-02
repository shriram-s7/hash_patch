"""tests/golden/test_shelf_life_golden.py

Golden-corpus test for Pillar 2 (Shelf-Life Inference). Runs the real
detection + correlation pipeline over testdata/python/shelf_life_examples.py
and testdata/java/ShelfLifeExamples.java and checks every entry in
tests/golden/shelf_life_manifest.json — so each seeded scenario is
regression-tested, not just eyeballed once. See docs/SHELF_LIFE.md.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from pratyaksha.analyze.shelf_life import compute_shelf_life
from pratyaksha.detect.java import JavaJcaDetector
from pratyaksha.detect.python import PythonCryptoDetector
from pratyaksha.detect.shelf_life.data_context import find_data_context_matches
from pratyaksha.detect.shelf_life.ontology import load_sensitivity_categories

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_FILE = REPO_ROOT / "tests" / "golden" / "shelf_life_manifest.json"
PY_FIXTURE = REPO_ROOT / "testdata" / "python" / "shelf_life_examples.py"
JAVA_FIXTURE = REPO_ROOT / "testdata" / "java" / "ShelfLifeExamples.java"

_SCAN_DATE = date(2026, 1, 1)


def _load_manifest() -> dict:
    with MANIFEST_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _finding_for(findings, algorithm: str):
    for f in findings:
        if f.asset_name == algorithm:
            return f
    return None


def test_shelf_life_manifest_file_exists() -> None:
    assert MANIFEST_FILE.is_file()


def test_python_corpus_matches_manifest() -> None:
    manifest = _load_manifest()
    assets = PythonCryptoDetector().detect(PY_FIXTURE)
    matches = find_data_context_matches(assets)
    findings = compute_shelf_life(assets, matches, _SCAN_DATE)

    for entry in manifest["python"]:
        finding = _finding_for(findings, entry["algorithm"])
        if entry["expected_category"] is None:
            assert finding is None, f"expected NO finding for {entry}, got {finding}"
        else:
            assert finding is not None, f"expected a finding for {entry}"
            assert finding.category == entry["expected_category"], (
                f"{entry}: expected category {entry['expected_category']!r}, got {finding.category!r}"
            )
            assert finding.evidence[0].locator.replace("\\", "/").endswith(entry["locator_suffix"])


def test_java_corpus_matches_manifest() -> None:
    manifest = _load_manifest()
    assets = JavaJcaDetector().detect(JAVA_FIXTURE)
    matches = find_data_context_matches(assets)
    findings = compute_shelf_life(assets, matches, _SCAN_DATE)

    for entry in manifest["java"]:
        finding = _finding_for(findings, entry["algorithm"])
        if entry["expected_category"] is None:
            assert finding is None, f"expected NO finding for {entry}, got {finding}"
        else:
            assert finding is not None, f"expected a finding for {entry}"
            assert finding.category == entry["expected_category"], (
                f"{entry}: expected category {entry['expected_category']!r}, got {finding.category!r}"
            )
            assert finding.evidence[0].locator.replace("\\", "/").endswith(entry["locator_suffix"])


def test_tie_break_case_verified_against_real_ontology_numbers() -> None:
    """Regression guard for the tie-break scenario specifically: assert
    aadhaar wins over financial_account by READING the actual numbers from
    ontology/data_sensitivity.yaml, not by assuming which one wins.
    """
    categories = {c.category_name: c for c in load_sensitivity_categories()}
    aadhaar_years = categories["aadhaar"].shelf_life_years
    financial_years = categories["financial_account"].shelf_life_years
    assert aadhaar_years > financial_years, (
        "this test's premise (aadhaar's shelf life exceeds financial_account's) no longer holds "
        f"in ontology/data_sensitivity.yaml (aadhaar={aadhaar_years}, financial_account={financial_years}) "
        "-- update the tie-break corpus scenario and manifest if this figure changes"
    )

    assets = PythonCryptoDetector().detect(PY_FIXTURE)
    matches = find_data_context_matches(assets)
    findings = compute_shelf_life(assets, matches, _SCAN_DATE)
    tie_break_finding = _finding_for(findings, "SHA3-256")
    assert tie_break_finding is not None
    assert tie_break_finding.category == "aadhaar"
    assert tie_break_finding.shelf_life_years == aadhaar_years
