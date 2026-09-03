from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hash_patch.emit import render_cbom_json, to_cyclonedx, validate_cbom
from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, QuantumStatus
from hash_patch.model.evidence import Evidence
from hash_patch.model.findings import ScanResult

REPO_ROOT = Path(__file__).resolve().parents[2]

FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)


# -- Five fixture assets, one per branch required by STEP 5.1 -----------------


def _rsa_2048() -> CryptoAsset:
    """(a) RSA-2048 algorithm, primitive pke, BROKEN_BY_SHOR."""
    return CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.PKE,
        parameter_set="2048",
        mode=None,
        crypto_functions=["keygen", "encrypt", "decrypt"],
        nist_quantum_security_level=0,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[
            Evidence(
                source_type="source",
                locator="app/crypto.py",
                line=42,
                column=5,
                byte_offset=1024,
                snippet="RSA.generate(2048)",
                detector_id="python-ast",
                detector_version="0.1.0",
            )
        ],
    )


def _aes_256_gcm() -> CryptoAsset:
    """(b) AES-256-GCM algorithm, primitive ae, WEAKENED_BY_GROVER."""
    return CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="AES",
        primitive=Primitive.AE,
        parameter_set="256",
        mode="gcm",
        crypto_functions=["encrypt", "decrypt"],
        nist_quantum_security_level=5,
        quantum_status=QuantumStatus.WEAKENED_BY_GROVER,
        evidence=[
            Evidence(
                source_type="source",
                locator="app/aead.py",
                line=7,
                column=1,
                byte_offset=None,
                snippet="AES.new(key, AES.MODE_GCM)",
                detector_id="python-ast",
                detector_version="0.1.0",
            )
        ],
    )


def _md5() -> CryptoAsset:
    """(c) MD5 algorithm, primitive hash, BROKEN_CLASSICALLY."""
    return CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="MD5",
        primitive=Primitive.HASH,
        parameter_set="128",
        mode=None,
        crypto_functions=["digest"],
        quantum_status=QuantumStatus.BROKEN_CLASSICALLY,
        evidence=[
            Evidence(
                source_type="source",
                locator="app/legacy.py",
                line=99,
                column=None,
                byte_offset=None,
                snippet="hashlib.md5(data)",
                detector_id="python-ast",
                detector_version="0.1.0",
            )
        ],
    )


def _x509_certificate() -> CryptoAsset:
    """(d) an X.509 certificate asset."""
    return CryptoAsset.create(
        asset_type=AssetType.CERTIFICATE,
        name="X.509",
        primitive=Primitive.UNKNOWN,
        parameter_set=None,
        mode=None,
        oid="1.2.840.113549.1.1.11",
        evidence=[
            Evidence(
                source_type="binary",
                locator="server.crt",
                line=None,
                column=None,
                byte_offset=0,
                snippet="-----BEGIN CERTIFICATE-----",
                detector_id="cert-parser",
                detector_version="0.1.0",
            )
        ],
    )


def _tls_1_2() -> CryptoAsset:
    """(e) a TLSv1.2 protocol asset."""
    return CryptoAsset.create(
        asset_type=AssetType.PROTOCOL,
        name="TLS",
        primitive=Primitive.UNKNOWN,
        parameter_set="1.2",
        mode=None,
        evidence=[
            Evidence(
                source_type="config",
                locator="nginx.conf",
                line=10,
                column=None,
                byte_offset=None,
                snippet="ssl_protocols TLSv1.2;",
                detector_id="config-scan",
                detector_version="0.1.0",
            )
        ],
    )


def _five_assets() -> list[CryptoAsset]:
    return [_rsa_2048(), _aes_256_gcm(), _md5(), _x509_certificate(), _tls_1_2()]


def _build_result(
    assets: list[CryptoAsset], scan_started_at: datetime = FIXED_TIMESTAMP
) -> ScanResult:
    result = ScanResult(
        target="testdata/sample",
        assets=[],
        scan_started_at=scan_started_at,
        tool_version="0.1.0",
    )
    for asset in assets:
        result.add_asset(asset)
    return result


def _five_asset_result() -> ScanResult:
    """Used both in-process and (by name) from the STEP 5.4 subprocess test."""
    return _build_result(_five_assets())


# -- STEP 5.1: schema validity across every branch -----------------------------


def test_emitted_cbom_validates_against_vendored_1_6_schema() -> None:
    result = _five_asset_result()

    doc = to_cyclonedx(result)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["version"] == 1
    assert len(doc["components"]) == 5

    errors = validate_cbom(doc)
    assert errors == [], "\n".join(errors)


# -- STEP 5.2: negative schema test (proves the validator actually runs) -------


def test_emitted_cbom_rejects_when_asset_type_is_corrupted() -> None:
    result = _build_result([_rsa_2048()])
    doc = to_cyclonedx(result)
    doc["components"][0]["cryptoProperties"]["assetType"] = "banana"

    errors = validate_cbom(doc)
    assert errors, "expected the corrupted document to fail schema validation"


# -- STEP 5.3: determinism across shuffled insertion + evidence order ----------


def _rsa_with_shuffled_evidence(seed: int) -> CryptoAsset:
    extra_evidence = [
        Evidence(
            source_type="source",
            locator="app/crypto.py",
            line=42,
            column=5,
            byte_offset=1024,
            snippet="RSA.generate(2048)",
            detector_id="python-ast",
            detector_version="0.1.0",
        ),
        Evidence(
            source_type="source",
            locator="app/other.py",
            line=3,
            column=None,
            byte_offset=None,
            snippet="key = RSA.generate(2048)",
            detector_id="python-ast",
            detector_version="0.1.0",
        ),
    ]
    random.Random(seed).shuffle(extra_evidence)
    return CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.PKE,
        parameter_set="2048",
        mode=None,
        crypto_functions=["keygen", "encrypt", "decrypt"],
        nist_quantum_security_level=0,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=extra_evidence,
    )


def test_cbom_is_deterministic_across_shuffled_insertion_and_evidence_order() -> None:
    assets_a = [_rsa_with_shuffled_evidence(7), _aes_256_gcm(), _md5(), _x509_certificate(), _tls_1_2()]
    assets_b = [_tls_1_2(), _x509_certificate(), _md5(), _aes_256_gcm(), _rsa_with_shuffled_evidence(99)]
    random.Random(11).shuffle(assets_a)
    random.Random(13).shuffle(assets_b)

    # Deliberately different scan timestamps: everything except
    # metadata.timestamp must still come out byte-identical.
    result_a = _build_result(assets_a, scan_started_at=datetime(2026, 1, 1, tzinfo=UTC))
    result_b = _build_result(assets_b, scan_started_at=datetime(2027, 6, 15, tzinfo=UTC))

    doc_a = to_cyclonedx(result_a)
    doc_b = to_cyclonedx(result_b)

    del doc_a["metadata"]["timestamp"]
    del doc_b["metadata"]["timestamp"]

    json_a = json.dumps(doc_a, sort_keys=True, indent=2, ensure_ascii=False)
    json_b = json.dumps(doc_b, sort_keys=True, indent=2, ensure_ascii=False)

    assert json_a == json_b


# -- STEP 5.4: subprocess determinism (catches PYTHONHASHSEED leaks) -----------


def test_cbom_is_deterministic_across_a_fresh_subprocess() -> None:
    in_process_doc = to_cyclonedx(_five_asset_result())
    in_process_json = render_cbom_json(in_process_doc)

    subprocess_script = (
        "from tests.unit.test_cyclonedx import _five_asset_result\n"
        "from hash_patch.emit import to_cyclonedx, render_cbom_json\n"
        "import sys\n"
        "sys.stdout.write(render_cbom_json(to_cyclonedx(_five_asset_result())))\n"
    )

    env = os.environ.copy()
    env.pop("PYTHONHASHSEED", None)  # let the subprocess pick its own random seed

    completed = subprocess.run(
        [sys.executable, "-c", subprocess_script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    subprocess_json = completed.stdout

    in_process_stripped = json.loads(in_process_json)
    subprocess_stripped = json.loads(subprocess_json)
    del in_process_stripped["metadata"]["timestamp"]
    del subprocess_stripped["metadata"]["timestamp"]

    assert json.dumps(in_process_stripped, sort_keys=True) == json.dumps(
        subprocess_stripped, sort_keys=True
    )


# -- STEP 5.5: evidence round-trip ---------------------------------------------


def test_evidence_file_and_line_survive_round_trip_into_occurrences() -> None:
    result = _build_result([_rsa_2048()])

    doc = to_cyclonedx(result)

    occurrences = doc["components"][0]["evidence"]["occurrences"]
    assert len(occurrences) == 1
    occurrence = occurrences[0]
    assert occurrence["location"] == "app/crypto.py"
    assert occurrence["line"] == 42
    assert occurrence["offset"] == 1024


# -- STEP 5.6: namespace hygiene ------------------------------------------------


def test_every_component_property_is_namespaced_hash_patch() -> None:
    result = _five_asset_result()
    doc = to_cyclonedx(result)

    checked_any = False
    for component in doc["components"]:
        for prop in component.get("properties", []):
            checked_any = True
            assert prop["name"].startswith("hash_patch:"), prop["name"]
    assert checked_any


# -- STEP 5.7: no uuid4 --------------------------------------------------------


def test_serial_number_is_stable_across_two_runs_of_the_same_input() -> None:
    doc_1 = to_cyclonedx(_five_asset_result())
    doc_2 = to_cyclonedx(_five_asset_result())
    assert doc_1["serialNumber"] == doc_2["serialNumber"]
    assert doc_1["serialNumber"].startswith("urn:uuid:")


# -- Extra coverage kept from the original suite -------------------------------


def test_asset_with_no_evidence_is_refused() -> None:
    asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="AES",
        primitive=Primitive.BLOCK_CIPHER,
        parameter_set="256",
        mode=None,
    )
    result = ScanResult(
        target="t",
        assets=[asset],
        scan_started_at=FIXED_TIMESTAMP,
        tool_version="0.1.0",
    )
    with pytest.raises(ValueError, match="no evidence"):
        to_cyclonedx(result)


def test_algorithm_properties_omitted_for_non_algorithm_asset_types() -> None:
    result = _build_result([_x509_certificate(), _tls_1_2()])
    doc = to_cyclonedx(result)

    for component in doc["components"]:
        assert "algorithmProperties" not in component["cryptoProperties"]


def test_components_are_sorted_by_bom_ref() -> None:
    result = _five_asset_result()
    doc = to_cyclonedx(result)
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs == sorted(refs)
