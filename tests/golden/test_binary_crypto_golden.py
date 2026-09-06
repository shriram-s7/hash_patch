"""tests/golden/test_binary_crypto_golden.py

Manifest-driven golden test for Phase 2 binary and compiled-artifact cryptography scanning.
Verifies:
- Asset types, evidence types, observed values, algorithms, libraries, operations
- Verification scope and honest framing
- Deterministic reachability (always UNKNOWN)
- Deterministic quantum status (library linkage does not fabricate algorithm vulnerability)
- Zero findings for malformed, empty, corrupted, and negative control binaries
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hash_patch.detect.binary.detector import BinaryDetector

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "tests" / "golden" / "binary_crypto_manifest.json"


def _load_manifest() -> dict:
    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def test_manifest_file_exists():
    assert MANIFEST_PATH.is_file(), f"Missing manifest: {MANIFEST_PATH}"


@pytest.mark.parametrize(
    "rel_path",
    list(_load_manifest()["fixtures"].keys()),
)
def test_binary_crypto_golden_fixture(rel_path: str):
    manifest = _load_manifest()
    fixture_info = manifest["fixtures"][rel_path]
    target_file = REPO_ROOT / rel_path

    assert target_file.is_file(), f"Fixture file not found: {target_file}"

    detector = BinaryDetector()
    findings = detector.detect(target_file)
    expected_findings = fixture_info.get("expected_findings", [])

    assert len(findings) == len(expected_findings), (
        f"Findings count mismatch for {rel_path}: got {len(findings)}, expected {len(expected_findings)}. "
        f"Observed: {[(f.name, f.properties.get('evidenceType'), f.properties.get('observedValue')) for f in findings]}"
    )

    if not expected_findings:
        return

    # Check each expected finding is present with exact attributes
    for exp in expected_findings:
        match = None
        for f in findings:
            if (
                f.properties.get("evidenceType") == exp["evidenceType"]
                and f.properties.get("observedValue") == exp["observedValue"]
            ):
                match = f
                break

        assert match is not None, (
            f"Expected finding {exp} not found in {rel_path}. "
            f"Got: {[f.properties for f in findings]}"
        )

        assert match.name == exp["name"]
        assert match.properties.get("library") == exp["library"]
        assert match.properties.get("algorithm") == exp["algorithm"]
        assert match.properties.get("operation") == exp["operation"]
        assert match.properties.get("verificationScope") == exp["verificationScope"]
        assert match.properties.get("binaryFormat") == fixture_info["binaryFormat"]
        assert match.quantum_status.value == exp["quantumStatus"]
        assert match.reachability.value == exp["reachability"]
        assert match.confidence == exp["confidence"]
        assert match.finding_type == "COMPILED_CRYPTO_ARTEFACT"
        assert len(match.evidence) >= 1
        assert match.evidence[0].source_type == "binary"
        assert match.evidence[0].detector_id == "binary-crypto"
        assert "runtime execution is not" in match.properties.get("honestFraming", "").lower() or "not established" in match.properties.get("honestFraming", "").lower()
