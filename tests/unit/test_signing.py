"""Unit tests for Pillar 6: ML-DSA-65 post-quantum signing, verification, and tamper detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pratyaksha.cli import app
from pratyaksha.sign.keys import (
    ALGORITHM_NAME,
    STANDARD_NAME,
    compute_public_key_fingerprint,
    generate_keypair,
    load_private_key,
    load_public_key,
)
from pratyaksha.sign.sign_cbom import sign_cbom_file
from pratyaksha.sign.verify_cbom import (
    VerificationStatus,
    verify_cbom_file,
)

runner = CliRunner()


@pytest.fixture
def temp_keys(tmp_path: Path) -> tuple[Path, Path]:
    keys_dir = tmp_path / "keys"
    return generate_keypair(keys_dir)


@pytest.fixture
def sample_cbom(tmp_path: Path) -> Path:
    cbom_path = tmp_path / "test.cbom.json"
    cbom_content = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
        "version": 1,
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "RSA-2048",
                "bom-ref": "asset:rsa:2048",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "signature",
                        "parameterSetIdentifier": "2048",
                    },
                },
            }
        ],
    }
    cbom_path.write_text(json.dumps(cbom_content, indent=2) + "\n", encoding="utf-8")
    return cbom_path


def test_keygen_roundtrip(tmp_path: Path) -> None:
    """Keygen produces a valid ML-DSA-65 keypair that can load, sign, and verify."""
    priv_path, pub_path = generate_keypair(tmp_path)
    assert priv_path.is_file()
    assert pub_path.is_file()

    priv = load_private_key(priv_path)
    pub = load_public_key(pub_path)

    assert compute_public_key_fingerprint(pub) == compute_public_key_fingerprint(priv.public_key())

    # Sign and verify raw bytes round-trip
    message = b"roundtrip test payload"
    signature = priv.sign(message)
    pub.verify(signature, message)


def test_sign_and_verify_valid_cbom(sample_cbom: Path, temp_keys: tuple[Path, Path]) -> None:
    """Sign-then-verify on an authentic CBOM returns VALID."""
    priv_path, pub_path = temp_keys
    sig_path = sign_cbom_file(sample_cbom, priv_path)

    assert sig_path.is_file()
    result = verify_cbom_file(sample_cbom, sig_path, pub_path)

    assert result.status == VerificationStatus.VALID
    assert result.is_valid is True
    assert result.algorithm == ALGORITHM_NAME
    assert result.file_sha256_match is True
    assert result.signature_match is True
    assert "verified successfully" in result.message.lower()


def test_tampered_cbom_is_detected_as_invalid(
    sample_cbom: Path, temp_keys: tuple[Path, Path]
) -> None:
    """Safety-critical test: a single-byte tamper to the signed file causes verify to return INVALID."""
    priv_path, pub_path = temp_keys
    sig_path = sign_cbom_file(sample_cbom, priv_path)

    # Tamper with a single byte in the CBOM file
    content = sample_cbom.read_bytes()
    # Flip the first character (e.g. '{' to '[') or replace 'RSA' with 'DSA'
    tampered_content = content.replace(b"RSA-2048", b"RSA-4096")
    assert tampered_content != content
    sample_cbom.write_bytes(tampered_content)

    result = verify_cbom_file(sample_cbom, sig_path, pub_path)

    assert result.status == VerificationStatus.INVALID
    assert result.is_valid is False
    assert result.file_sha256_match is False
    # Crucial distinction: message must identify document tampering, not broken signature or key
    assert "modified or tampered" in result.message.lower() or "mismatch" in result.message.lower()
    assert "document" in result.message.lower() or "file" in result.message.lower()


def test_wrong_public_key_returns_invalid(
    sample_cbom: Path, temp_keys: tuple[Path, Path], tmp_path: Path
) -> None:
    """Verifying with a different valid keypair returns INVALID (signature doesn't match), not ERROR."""
    priv_path, _ = temp_keys
    sig_path = sign_cbom_file(sample_cbom, priv_path)

    # Generate a second, completely different valid keypair
    other_keys_dir = tmp_path / "other_keys"
    _, other_pub_path = generate_keypair(other_keys_dir)

    result = verify_cbom_file(sample_cbom, sig_path, other_pub_path)

    assert result.status == VerificationStatus.INVALID
    assert result.is_valid is False
    assert "signature mismatch" in result.message.lower() or "does not match" in result.message.lower()


def test_missing_or_corrupted_signature_file_returns_error(
    sample_cbom: Path, temp_keys: tuple[Path, Path], tmp_path: Path
) -> None:
    """Missing or malformed signature file returns ERROR, distinguishable from INVALID."""
    _, pub_path = temp_keys

    # Missing signature file
    missing_sig = tmp_path / "nonexistent.sig"
    res_missing = verify_cbom_file(sample_cbom, missing_sig, pub_path)
    assert res_missing.status == VerificationStatus.ERROR
    assert "not found" in res_missing.message.lower()

    # Corrupted JSON signature file
    corrupt_sig = tmp_path / "corrupt.sig"
    corrupt_sig.write_text("{this is not json", encoding="utf-8")
    res_corrupt = verify_cbom_file(sample_cbom, corrupt_sig, pub_path)
    assert res_corrupt.status == VerificationStatus.ERROR
    assert "malformed" in res_corrupt.message.lower()

    # Signature file missing required fields
    incomplete_sig = tmp_path / "incomplete.sig"
    incomplete_sig.write_text(json.dumps({"algorithm": ALGORITHM_NAME}), encoding="utf-8")
    res_incomplete = verify_cbom_file(sample_cbom, incomplete_sig, pub_path)
    assert res_incomplete.status == VerificationStatus.ERROR
    assert "missing required fields" in res_incomplete.message.lower()


def test_signing_determinism_and_hedging_behavior(
    sample_cbom: Path, temp_keys: tuple[Path, Path], tmp_path: Path
) -> None:
    """Document and assert signing behavior under pyca/cryptography's FIPS 204 ML-DSA-65.

    NOTE ON DETERMINISM:
    FIPS 204 defines both deterministic signing and randomized (hedged) signing (Algorithm 7).
    The pyca/cryptography implementation of ML-DSA-65 utilizes randomized hedging by default
    to mitigate side-channel and fault-injection vulnerabilities.
    Consequently, two signatures of the same message generated with the same key produce
    different signature bytes, but both are structurally valid and independently verify
    against the public key.
    """
    priv_path, pub_path = temp_keys

    sig_path_1 = tmp_path / "sig1.sig"
    sig_path_2 = tmp_path / "sig2.sig"

    sign_cbom_file(sample_cbom, priv_path, sig_path_1)
    sign_cbom_file(sample_cbom, priv_path, sig_path_2)

    data1 = json.loads(sig_path_1.read_text(encoding="utf-8"))
    data2 = json.loads(sig_path_2.read_text(encoding="utf-8"))

    # Common invariant metadata fields must match exactly
    assert data1["algorithm"] == data2["algorithm"] == ALGORITHM_NAME
    assert data1["standard"] == data2["standard"] == STANDARD_NAME
    assert data1["file_sha256"] == data2["file_sha256"]
    assert data1["public_key_fingerprint"] == data2["public_key_fingerprint"]
    assert data1["public_key_pem"] == data2["public_key_pem"]

    # In pyca/cryptography ML-DSA-65, randomized hedging means signature bytes differ:
    assert data1["signature"] != data2["signature"]

    # Both signatures must independently verify against the public key as VALID:
    res1 = verify_cbom_file(sample_cbom, sig_path_1, pub_path)
    res2 = verify_cbom_file(sample_cbom, sig_path_2, pub_path)
    assert res1.status == VerificationStatus.VALID
    assert res2.status == VerificationStatus.VALID


def test_cli_keygen_sign_verify_tamper_pipeline(tmp_path: Path, sample_cbom: Path) -> None:
    """Full CLI round-trip: keygen -> sign -> verify (VALID) -> tamper -> verify (INVALID)."""
    keys_dir = tmp_path / "cli_keys"

    # 1. keygen
    res_kg = runner.invoke(app, ["keygen", "--output-dir", str(keys_dir)])
    assert res_kg.exit_code == 0
    assert "generated ML-DSA-65 keypair" in res_kg.stdout

    priv_path = keys_dir / "pratyaksha_signing.key"
    pub_path = keys_dir / "pratyaksha_signing.pub"
    assert priv_path.is_file()
    assert pub_path.is_file()

    # 2. sign
    sig_path = tmp_path / "cli_test.cbom.json.sig"
    res_sign = runner.invoke(
        app,
        ["sign", str(sample_cbom), "--key", str(priv_path), "--output", str(sig_path)],
    )
    assert res_sign.exit_code == 0
    assert "signed CBOM" in res_sign.stdout
    assert sig_path.is_file()

    # 3. verify (VALID)
    res_verify = runner.invoke(
        app,
        ["verify", str(sample_cbom), "--sig", str(sig_path), "--key", str(pub_path)],
    )
    assert res_verify.exit_code == 0
    assert "VALID:" in res_verify.stdout

    # 4. tamper with document
    content = sample_cbom.read_text(encoding="utf-8")
    sample_cbom.write_text(content.replace("RSA-2048", "RSA-1024"), encoding="utf-8")

    # 5. verify (INVALID)
    res_tamper = runner.invoke(
        app,
        ["verify", str(sample_cbom), "--sig", str(sig_path), "--key", str(pub_path)],
    )
    assert res_tamper.exit_code == 1
    assert "INVALID:" in res_tamper.stderr or "INVALID:" in res_tamper.stdout
