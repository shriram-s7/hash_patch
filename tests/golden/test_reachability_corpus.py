"""tests/golden/test_reachability_corpus.py

Regression test for the reachability corpus additions under testdata/python/
and testdata/java/ (see docs/REACHABILITY.md and the "Reachability" section
of CLAUDE.md). Runs the real CLI scan path (hash_patch.cli.run_scan) — the
same one `pratyaksha scan` uses — over each language's testdata directory
and checks every entry in tests/golden/reachability_manifest.json against
the resulting CryptoAsset.reachability, so each of the four classifications
(LIVE_EXTERNAL, LIVE_INTERNAL, INERT, UNKNOWN) is regression-tested rather
than just eyeballed once.
"""

from __future__ import annotations

import json
from pathlib import Path

from hash_patch.cli import run_scan
from hash_patch.model.assets import CryptoAsset

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_FILE = REPO_ROOT / "tests" / "golden" / "reachability_manifest.json"


def _load_manifest() -> dict[str, list[dict[str, str]]]:
    with MANIFEST_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _asset_for(
    assets: list[CryptoAsset], algorithm: str, locator_suffix: str
) -> CryptoAsset | None:
    for asset in assets:
        if asset.name != algorithm:
            continue
        for ev in asset.evidence:
            if ev.locator.replace("\\", "/").endswith(locator_suffix):
                return asset
    return None


def test_reachability_manifest_file_exists() -> None:
    assert MANIFEST_FILE.is_file(), f"Missing: {MANIFEST_FILE}"


def test_python_reachability_corpus_matches_manifest() -> None:
    manifest = _load_manifest()["python"]
    result = run_scan(REPO_ROOT / "testdata" / "python")
    for entry in manifest:
        asset = _asset_for(result.assets, entry["algorithm"], entry["locator_suffix"])
        assert asset is not None, (
            f"No {entry['algorithm']!r} asset with evidence in "
            f"{entry['locator_suffix']!r} found in the scan.\nScenario: {entry['scenario']}"
        )
        assert asset.reachability.value == entry["expected"], (
            f"{entry['locator_suffix']} ({entry['algorithm']}): "
            f"expected reachability={entry['expected']!r}, got {asset.reachability.value!r}.\n"
            f"Scenario: {entry['scenario']}"
        )


def test_java_reachability_corpus_matches_manifest() -> None:
    manifest = _load_manifest()["java"]
    result = run_scan(REPO_ROOT / "testdata" / "java")
    for entry in manifest:
        asset = _asset_for(result.assets, entry["algorithm"], entry["locator_suffix"])
        assert asset is not None, (
            f"No {entry['algorithm']!r} asset with evidence in "
            f"{entry['locator_suffix']!r} found in the scan.\nScenario: {entry['scenario']}"
        )
        assert asset.reachability.value == entry["expected"], (
            f"{entry['locator_suffix']} ({entry['algorithm']}): "
            f"expected reachability={entry['expected']!r}, got {asset.reachability.value!r}.\n"
            f"Scenario: {entry['scenario']}"
        )
