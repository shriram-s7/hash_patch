"""tests/unit/test_certificates.py

Unit tests for hash_patch/detect/certificates.py's integration points not
already covered by tests/golden/test_certificates_golden.py:

- end-to-end wiring through hash_patch.cli.run_scan (asset_type, reachability
  default, CBOM emission not crashing on AssetType.CERTIFICATE)
- reachability is never forced away from the model default (UNKNOWN) for a
  certificate finding -- certificates are never "called", so no reachability
  vote is ever cast (mirrors non-"source" evidence elsewhere)
- an unreadable/corrupt file is reported, never raises
- an unsupported extension is skipped entirely (not even attempted)
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from hash_patch.cli import run_scan
from hash_patch.detect.certificates import detect_certificate_file, detect_certificates, supports
from hash_patch.model.assets import AssetType, Reachability

REPO_ROOT = Path(__file__).resolve().parents[2]
CERT_DIR = REPO_ROOT / "testdata" / "certificates"
REFERENCE_DATE = date(2026, 6, 1)


def test_supports_only_certificate_extensions() -> None:
    assert supports(CERT_DIR / "valid_rsa2048.crt")
    assert supports(CERT_DIR / "protected.p12")
    assert not supports(CERT_DIR / "does_not_exist.crt")


def test_unsupported_extension_produces_nothing() -> None:
    assert detect_certificate_file(CERT_DIR / "README.md", REFERENCE_DATE) == []


def test_corrupt_file_reported_not_raised(tmp_path: Path) -> None:
    bad = tmp_path / "garbage.crt"
    bad.write_bytes(b"this is not a certificate")
    assets = detect_certificate_file(bad, REFERENCE_DATE)
    assert len(assets) == 1
    assert assets[0].finding_type == "CERTIFICATE_UNPARSEABLE"
    assert assets[0].asset_type is AssetType.CERTIFICATE


def test_certificate_asset_type_is_distinct_from_algorithm() -> None:
    assets = detect_certificate_file(CERT_DIR / "valid_rsa2048.crt", REFERENCE_DATE)
    assert len(assets) == 1
    assert assets[0].asset_type is AssetType.CERTIFICATE


def test_certificate_never_gets_a_reachability_vote() -> None:
    """Reachability does not apply to certificate files -- they are never
    "called" from code. Evidence.source_type="certificate" (not "source")
    means hash_patch/analyze/reachability.py's classifier casts no vote, so
    it stays at the model default. See CLAUDE.md's Reachability section.
    """
    result = run_scan(CERT_DIR)
    cert_assets = [a for a in result.assets if a.asset_type is AssetType.CERTIFICATE]
    assert cert_assets, "expected at least one certificate finding from run_scan(testdata/certificates)"
    for asset in cert_assets:
        assert asset.reachability == Reachability.UNKNOWN
        for ev in asset.evidence:
            assert ev.source_type == "certificate"


def test_run_scan_over_certificate_directory_does_not_crash_and_emits_valid_cbom() -> None:
    from hash_patch.emit import to_cyclonedx, validate_cbom

    result = run_scan(CERT_DIR)
    doc = to_cyclonedx(result)
    errors = validate_cbom(doc)
    assert errors == [], f"CBOM schema validation errors: {errors}"


def test_detect_certificates_filters_scanned_files_by_extension(tmp_path: Path) -> None:
    non_cert = tmp_path / "notes.txt"
    non_cert.write_text("this is not a certificate file")
    assets = detect_certificates([CERT_DIR / "valid_rsa2048.crt", non_cert], REFERENCE_DATE)
    assert len(assets) == 1
    assert assets[0].asset_type is AssetType.CERTIFICATE
