"""tests/golden/test_contradictions_golden.py — Golden corpus tests for Pillar 4 (Contradictions)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pratyaksha.cli import run_scan

_MANIFEST_PATH = Path(__file__).parent / "contradictions_manifest.json"
_BASE_DIR = Path(__file__).resolve().parents[2]


def _load_manifest() -> list[dict]:
    data = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    return data["scenarios"]


@pytest.mark.parametrize("scenario", _load_manifest(), ids=lambda s: s["name"])
def test_contradictions_scenario_golden(scenario: dict) -> None:
    target_path = _BASE_DIR / scenario["path"]
    assert target_path.is_dir(), f"Target fixture path does not exist: {target_path}"

    result = run_scan(target_path)

    expected_count = scenario["expected_contradictions"]
    assert len(result.contradiction_findings) == expected_count, (
        f"Expected {expected_count} contradictions for {scenario['name']}, "
        f"got {len(result.contradiction_findings)}: {result.contradiction_findings}"
    )

    if expected_count > 0:
        c = result.contradiction_findings[0]
        assert c.severity == scenario["expected_severity"]
        assert c.source_intent.value == "TLSv1.3"
        assert "TLSv1" in c.deployed_config.value
        assert "Source code at" in c.description
        assert "nginx" in c.description


def test_contradictions_isolated_subdirectories_do_not_leak() -> None:
    """When scanning testdata/contradictions as a whole target root, exactly
    1 contradiction should be identified (from scenario1_conflict).
    Scenario 3's standalone legacy nginx.conf must not correlate across
    directories with Scenario 2's app.py.
    """
    root_target = _BASE_DIR / "testdata" / "contradictions"
    result = run_scan(root_target)

    # Exactly 1 contradiction from scenario1_conflict
    assert len(result.contradiction_findings) == 1
    c = result.contradiction_findings[0]
    assert "scenario1_conflict" in c.source_intent.source_file
    assert "scenario1_conflict" in c.deployed_config.source_file
