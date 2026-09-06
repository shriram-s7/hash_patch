"""tests/golden/test_certificates_golden.py

Golden-corpus test for certificate file parsing
(hash_patch/detect/certificates.py). Runs the real parser over every fixture
under testdata/certificates/ (generated via OpenSSL — see
tests/golden/README_certificates.md for the exact reproducible commands)
and checks every entry in tests/golden/certificate_manifest.json against
the resulting CryptoAsset fields.

Unlike other golden tests in this suite, this does NOT diff a fixed
expected-CBOM-JSON blob: three of the five fixtures use OpenSSL's `-days N`
(relative to generation time), so their exact notBefore/notAfter dates are
never byte-for-byte reproducible. Only structural fields (algorithm, key
size, self-signed, chain position/depth, quantum status, expired flag) are
asserted for those; the one fixture generated with explicit
-not_before/-not_after (expired_rsa2048.crt) additionally gets its exact
dates checked.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from hash_patch.detect.certificates import detect_certificate_file

REPO_ROOT = Path(__file__).resolve().parents[2]
CERT_DIR = REPO_ROOT / "testdata" / "certificates"
MANIFEST_FILE = REPO_ROOT / "tests" / "golden" / "certificate_manifest.json"

# A fixed reference date well after every fixture's generation but before
# any of the -days-825/-days-3650 fixtures could plausibly expire, and
# after the explicit expired_rsa2048.crt's 2021-01-01 not_after.
REFERENCE_DATE = date(2026, 6, 1)


def _load_manifest() -> dict:
    with MANIFEST_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _subject_cn(rfc4514_subject: str) -> str | None:
    for part in rfc4514_subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:]
    return None


def test_certificate_manifest_file_exists() -> None:
    assert MANIFEST_FILE.is_file(), f"Missing: {MANIFEST_FILE}"


def test_certificate_fixtures_exist() -> None:
    manifest = _load_manifest()
    for entry in manifest["certificates"]:
        assert (CERT_DIR / entry["file"]).is_file(), (
            f"Missing fixture {entry['file']!r} -- see tests/golden/README_certificates.md"
        )


def _assert_finding_matches(asset, expected: dict) -> None:
    assert asset.name == expected["name"], f"expected name={expected['name']!r}, got {asset.name!r}"
    if "parameter_set" in expected:
        assert asset.parameter_set == expected["parameter_set"]
    if "quantum_status" in expected:
        assert asset.quantum_status.value == expected["quantum_status"]
    if "finding_type" in expected:
        assert asset.finding_type == expected["finding_type"]
    props = asset.properties
    if "self_signed" in expected:
        assert props.get("certificate.selfSigned") == ("true" if expected["self_signed"] else "false")
    if "expired" in expected:
        assert props.get("certificate.expired") == ("true" if expected["expired"] else "false")
    if "chain_position" in expected:
        assert props.get("certificate.chainPosition") == str(expected["chain_position"])
    if "chain_depth" in expected:
        assert props.get("certificate.chainDepth") == str(expected["chain_depth"])
    if "subject_cn" in expected:
        assert _subject_cn(props.get("certificate.subject", "")) == expected["subject_cn"]
    if "issuer_cn" in expected:
        assert _subject_cn(props.get("certificate.issuer", "")) == expected["issuer_cn"]
    if "not_before" in expected:
        assert props.get("certificate.notBefore") == expected["not_before"]
    if "not_after" in expected:
        assert props.get("certificate.notAfter") == expected["not_after"]
    if "shelf_life_years" in expected:
        shelf_life = json.loads(props["shelfLife.certificate_expiry"])
        assert shelf_life["shelfLifeYears"] == expected["shelf_life_years"]
        assert shelf_life["evidenceSource"] == "certificate_expiry"
    if "error_contains" in expected:
        assert expected["error_contains"] in props.get("certificate.error", "")


def test_certificate_corpus_matches_manifest() -> None:
    manifest = _load_manifest()["certificates"]
    for entry in manifest:
        target = CERT_DIR / entry["file"]
        assets = detect_certificate_file(target, REFERENCE_DATE)
        expected_list = entry["expected_findings"]
        assert len(assets) == len(expected_list), (
            f"{entry['file']}: expected {len(expected_list)} finding(s), got {len(assets)}"
        )
        for asset, expected in zip(assets, expected_list, strict=True):
            _assert_finding_matches(asset, expected)


def test_password_protected_p12_parses_with_correct_password() -> None:
    manifest = _load_manifest()["certificates"]
    entry = next(e for e in manifest if e["file"] == "protected.p12")
    assert "with_password" in entry, "manifest missing with_password case for protected.p12"
    target = CERT_DIR / entry["file"]
    assets = detect_certificate_file(
        target, REFERENCE_DATE, p12_password=entry["with_password"].encode()
    )
    expected_list = entry["expected_findings_with_password"]
    assert len(assets) == len(expected_list)
    for asset, expected in zip(assets, expected_list, strict=True):
        _assert_finding_matches(asset, expected)
