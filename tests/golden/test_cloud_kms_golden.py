"""tests/golden/test_cloud_kms_golden.py

Golden-corpus test for the cloud KMS/HSM client-side usage detectors
(hash_patch/detect/cloud_kms/ — python-cloud-kms, java-cloud-kms,
go-cloud-kms). Runs each registered detector over every fixture under
testdata/cloud_kms/{python,java,go}/ (positive AWS/GCP/Azure call sites plus
the negative cases that must produce ZERO findings: SDK import/construction
only, and unrelated HTTP calls whose variable names merely mention
"key"/"encrypt") and checks every entry in
tests/golden/cloud_kms_manifest.json against the resulting CryptoAsset
fields.

Manifest-driven like test_certificates_golden.py rather than byte-exact-CBOM
(because these findings span three languages whose exact instance field
there is no pre-existing single golden corpus to extend) — the derived,
deterministic identity fields are still fully asserted, and a separate test
emits the entire corpus through the real CBOM pipeline and validates it
against the vendored CycloneDX 1.6 schema.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from hash_patch.detect import registry
from hash_patch.emit import to_cyclonedx, validate_cbom
from hash_patch.model.findings import ScanResult

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO_ROOT / "testdata" / "cloud_kms"
MANIFEST_FILE = REPO_ROOT / "tests" / "golden" / "cloud_kms_manifest.json"

FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)

_FINDING_TYPE = "CLOUD_KEY_OPERATION"
_QUANTUM_STATUS = "algorithm-opaque-provider-managed"
_SCOPE = "client_call_only"


def _load_manifest() -> dict:
    with MANIFEST_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _registered_detectors() -> dict:
    return {d.detector_id: d for d in registry.detectors()}


def test_cloud_kms_manifest_file_exists() -> None:
    assert MANIFEST_FILE.is_file(), f"Missing: {MANIFEST_FILE}"


def test_cloud_kms_fixtures_exist() -> None:
    manifest = _load_manifest()["cloud_kms"]
    for entry in manifest:
        assert (CORPUS_DIR / entry["file"]).is_file(), f"Missing fixture {entry['file']!r}"


def test_all_registered_detectors_are_present() -> None:
    detectors = _registered_detectors()
    for expected_id in ("python-cloud-kms", "java-cloud-kms", "go-cloud-kms"):
        assert expected_id in detectors, f"{expected_id} not registered"


def _assert_finding_matches(asset, expected: dict) -> None:
    expected_name = f"{expected['provider'].upper()} KMS {expected['operation']}"
    assert asset.name == expected_name, f"expected name={expected_name!r}, got {asset.name!r}"
    assert asset.finding_type == _FINDING_TYPE, (
        "cloud-key finding must carry finding_type=CLOUD_KEY_OPERATION"
    )
    assert asset.quantum_status.value == _QUANTUM_STATUS, (
        "cloud-key finding must be ALGORITHM_OPAQUE (provider-managed), never a guessed quantum status"
    )
    assert asset.primitive.value == "other"
    assert asset.asset_type.value == "related-crypto-material"
    props = asset.properties
    assert props.get("cloudKey.provider") == expected["provider"]
    assert props.get("cloudKey.operation") == expected["operation"]
    sdk = expected.get("sdk")
    if sdk is not None:
        assert props.get("cloudKey.sdk") == sdk
    assert props.get("cloudKey.verificationScope") == _SCOPE, (
        "every cloud-key finding must carry verificationScope=client_call_only"
    )
    assert len(asset.evidence) >= 1, "cloud-key finding must carry direct evidence"
    ev = asset.evidence[0]
    assert "cloud_kms" in ev.locator, f"unexpected locator: {ev.locator}"
    assert ev.line >= 1 and ev.byte_offset >= 0, "invalid evidence location"
    assert ev.snippet.strip() != "", "evidence snippet must not be empty"


def test_cloud_kms_corpus_matches_manifest() -> None:
    detectors = _registered_detectors()
    manifest = _load_manifest()["cloud_kms"]
    for entry in manifest:
        detector = detectors.get(entry["detector_id"])
        assert detector is not None, f"{entry['detector_id']} not registered"
        target = CORPUS_DIR / entry["file"]
        assets = detector.detect(target)
        expected_list = entry["expected_findings"]
        assert len(assets) == len(expected_list), (
            f"{entry['file']}: expected {len(expected_list)} finding(s), got {len(assets)}: "
            f"{[a.name for a in assets]}"
        )
        for asset, expected in zip(assets, expected_list, strict=True):
            _assert_finding_matches(asset, expected)


def _build_full_corpus_doc() -> dict:
    detectors = _registered_detectors()
    manifest = _load_manifest()["cloud_kms"]
    result = ScanResult(
        target=str(CORPUS_DIR),
        assets=[],
        scan_started_at=FIXED_TIMESTAMP,
        tool_version="0.1.0",
    )
    for entry in manifest:
        detector = detectors[entry["detector_id"]]
        target = CORPUS_DIR / entry["file"]
        for asset in detector.detect(target):
            result.add_asset(asset)
    return to_cyclonedx(result)


def test_full_corpus_cbom_validates_against_cyclonedx_schema() -> None:
    doc = _build_full_corpus_doc()
    errors = validate_cbom(doc)
    assert errors == [], (
        "Schema validation failed for cloud-kms corpus CBOM:\n" + "\n".join(errors)
    )


def test_full_corpus_cbom_has_expected_asset_count() -> None:
    doc = _build_full_corpus_doc()
    distinct_names = sorted(
        {
            f"{e['provider'].upper()} KMS {e['operation']}"
            for entry in _load_manifest()["cloud_kms"]
            for e in entry["expected_findings"]
        }
    )
    assert len(distinct_names) == 11, f"unexpected distinct expectation: {len(distinct_names)}"
    got = sorted(c["name"] for c in doc["components"])
    assert got == distinct_names, (
        f"component names must be exactly the distinct (provider, verbatim-operation) pairs: {got}"
    )

    # Assets are identified by (provider, verbatim-operation spelling), so the
    # same operation lettering in different files/languages merges into one
    # component whose evidence accumulates across call sites.
    occurrences = {
        c["name"]: len(c.get("evidence", {}).get("occurrences", [])) for c in doc["components"]
    }
    assert occurrences["GCP KMS decrypt"] == 2, "python+java same-spelling decrypt must merge"
    assert occurrences["AWS KMS Encrypt"] == 2, "aws-sdk-go v1 + v2 Encrypt must merge"
    assert occurrences["AZURE KMS createKey"] == 1


def test_full_corpus_cbom_carries_honesty_properties() -> None:
    doc = _build_full_corpus_doc()
    for component in doc["components"]:
        prop_names = {p["name"] for p in component.get("properties", [])}
        assert "hash_patch:findingType" in prop_names
        ft = next(p["value"] for p in component["properties"] if p["name"] == "hash_patch:findingType")
        assert ft == _FINDING_TYPE
        assert "hash_patch:property.cloudKey.verificationScope" in prop_names
        scope = next(
            p["value"]
            for p in component["properties"]
            if p["name"] == "hash_patch:property.cloudKey.verificationScope"
        )
        assert scope == _SCOPE, f"{component['bom-ref']} lost its client_call_only framing"
        assert "hash_patch:property.cloudKey.provider" in prop_names
        assert "hash_patch:property.cloudKey.operation" in prop_names


def test_full_corpus_cbom_components_sorted_by_bom_ref() -> None:
    doc = _build_full_corpus_doc()
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs == sorted(refs)


def test_full_corpus_cbom_all_components_have_occurrences() -> None:
    doc = _build_full_corpus_doc()
    for component in doc["components"]:
        occurrences = component.get("evidence", {}).get("occurrences", [])
        assert len(occurrences) >= 1, f"Component {component['name']!r} has no evidence"
