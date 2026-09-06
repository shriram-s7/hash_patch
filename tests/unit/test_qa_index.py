"""tests/unit/test_qa_index.py — Tests for ScanIndex normalized representation."""

from __future__ import annotations

from pathlib import Path

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.index import ScanIndex

REPO_ROOT = Path(__file__).resolve().parents[2]


def _test2_index() -> ScanIndex:
    result = run_scan(REPO_ROOT / "test2")
    cbom = to_cyclonedx(result)
    return ScanIndex.from_cbom(cbom)


def test_scan_index_builds_all_levels() -> None:
    index = _test2_index()

    # Scan level
    assert index.total_scanned_files_count > 0
    assert len(index.findings) >= 25
    assert len(index.operations) > 0
    assert len(index.references) > 0

    # Broken by Shor count
    assert len(index.broken_by_shor) > 0

    # Finding level
    rsa_records = index.findings_by_name.get("RSA", [])
    assert len(rsa_records) > 0
    rsa = rsa_records[0]
    assert rsa.name == "RSA"
    assert len(rsa.evidence) > 0

    # Repository level
    assert len(index.files_with_findings) > 0
    assert "c" in index.language_distribution
    assert "go" in index.language_distribution
    assert "java" in index.language_distribution
    assert "python" in index.language_distribution

    # Migration candidates
    assert len(index.migration_candidates) > 0
    top = index.migration_candidates[0]
    assert top.rank == 1
    assert top.risk_score > 0

    # Shelf life
    longest = index.longest_shelf_life_finding
    assert longest is not None
    assert longest.shelf_life_years is not None
    assert longest.shelf_life_years >= 10
