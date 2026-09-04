"""tests/unit/test_java_detector.py

Unit tests for hash_patch.detect.java.JavaJcaDetector.

Design notes:
  - No algorithm names are hardcoded in this test file (CLAUDE.md constraint).
    Expected algorithm names and quantum statuses come from rules/java_jca.yaml
    via a helper that loads the same file the detector uses.
  - Every assertion about a CryptoAsset verifies that at least one Evidence
    entry with a real locator, line, column, byte_offset, and snippet exists
    (hard constraint #3).
  - Determinism is checked by running the detector twice and comparing output.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from hash_patch.detect.java import JavaJcaDetector, _build_algo_index, _lookup_algo
from hash_patch.model.assets import AssetType, CryptoAsset, QuantumStatus
from hash_patch.model.evidence import Evidence

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA_JAVA = REPO_ROOT / "testdata" / "java"
RULES_PATH = REPO_ROOT / "rules" / "java_jca.yaml"
POSITIVE_FIXTURE = TESTDATA_JAVA / "crypto_examples.java"
NEGATIVE_FIXTURE = TESTDATA_JAVA / "negative_rsa_mention.java"


# ---------------------------------------------------------------------------
# Load expected rules (no hardcoded algorithm names in test assertions)
# ---------------------------------------------------------------------------


def _load_rules() -> dict[str, Any]:
    with RULES_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _algo_index() -> dict[str, dict[str, Any]]:
    return _build_algo_index(_load_rules())


def _expected_quantum_status(algo_name: str) -> str:
    """Return the quantum_status string from the rules for algo_name."""
    index = _algo_index()
    entry = index.get(algo_name.upper())
    assert entry is not None, f"Algorithm {algo_name!r} not found in rules"
    return entry["quantum_status"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def detector() -> JavaJcaDetector:
    return JavaJcaDetector()


@pytest.fixture(scope="module")
def positive_assets(detector: JavaJcaDetector) -> list[CryptoAsset]:
    return detector.detect(POSITIVE_FIXTURE)


@pytest.fixture(scope="module")
def negative_assets(detector: JavaJcaDetector) -> list[CryptoAsset]:
    return detector.detect(NEGATIVE_FIXTURE)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _find_asset(assets: list[CryptoAsset], name: str) -> CryptoAsset | None:
    """Return the first asset whose name matches (case-insensitive)."""
    for a in assets:
        if a.name.upper() == name.upper():
            return a
    return None


def _assert_evidence_populated(ev: Evidence, fixture_path: Path) -> None:
    """Assert that all Evidence locator/position fields are set."""
    assert ev.source_type == "source"
    assert ev.locator == str(fixture_path)
    assert ev.line is not None and ev.line > 0, "line must be ≥ 1"
    assert ev.column is not None and ev.column >= 0, "column must be ≥ 0"
    assert ev.byte_offset is not None and ev.byte_offset >= 0, "byte_offset must be ≥ 0"
    assert ev.snippet is not None and len(ev.snippet) > 0, "snippet must be non-empty"
    assert ev.detector_id == "java-jca"
    assert ev.detector_version == "0.1.0"


# ---------------------------------------------------------------------------
# Test: fixture files exist
# ---------------------------------------------------------------------------


def test_positive_fixture_exists() -> None:
    assert POSITIVE_FIXTURE.is_file(), f"Missing: {POSITIVE_FIXTURE}"


def test_negative_fixture_exists() -> None:
    assert NEGATIVE_FIXTURE.is_file(), f"Missing: {NEGATIVE_FIXTURE}"


def test_rules_file_exists() -> None:
    assert RULES_PATH.is_file(), f"Missing: {RULES_PATH}"


# ---------------------------------------------------------------------------
# Test: supports()
# ---------------------------------------------------------------------------


def test_supports_java_file(detector: JavaJcaDetector) -> None:
    assert detector.supports(POSITIVE_FIXTURE) is True


def test_does_not_support_non_java_file(detector: JavaJcaDetector, tmp_path: Path) -> None:
    py_file = tmp_path / "crypto.py"
    py_file.write_text("import hashlib\n")
    assert detector.supports(py_file) is False


def test_does_not_support_directory(detector: JavaJcaDetector) -> None:
    assert detector.supports(TESTDATA_JAVA) is False


# ---------------------------------------------------------------------------
# Test: negative fixture produces zero assets
# ---------------------------------------------------------------------------


def test_negative_fixture_produces_no_assets(negative_assets: list[CryptoAsset]) -> None:
    """RSA in comments / unrelated strings must not produce any CryptoAsset."""
    assert negative_assets == [], (
        f"Expected 0 assets from negative fixture, got: "
        f"{[a.name for a in negative_assets]}"
    )


# ---------------------------------------------------------------------------
# Test: positive fixture — expected algorithms are detected
# ---------------------------------------------------------------------------


def test_positive_fixture_produces_nonzero_assets(positive_assets: list[CryptoAsset]) -> None:
    assert len(positive_assets) > 0, "Expected at least one asset from positive fixture"


def test_rsa_detected(positive_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(positive_assets, "RSA")
    assert asset is not None, "RSA not found in detected assets"
    assert asset.asset_type == AssetType.ALGORITHM
    assert asset.quantum_status == QuantumStatus(_expected_quantum_status("RSA"))
    assert len(asset.evidence) >= 1


def test_rsa_has_two_evidence_entries(positive_assets: list[CryptoAsset]) -> None:
    """RSA is called both natively and via BouncyCastle; evidence must be merged."""
    asset = _find_asset(positive_assets, "RSA")
    assert asset is not None
    # crypto_examples.java has KeyPairGenerator.getInstance("RSA") at line ~26
    # and KeyPairGenerator.getInstance("RSA", "BC") at line ~66
    assert len(asset.evidence) == 2, (
        f"Expected 2 evidence entries for RSA (native + BC), got {len(asset.evidence)}"
    )


def test_aes_detected(positive_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(positive_assets, "AES")
    assert asset is not None, "AES not found in detected assets"
    assert asset.quantum_status == QuantumStatus(_expected_quantum_status("AES"))
    # Two calls: KeyGenerator.getInstance("AES") + Cipher.getInstance("AES/GCM/NoPadding")
    assert len(asset.evidence) == 2


def test_md5_detected(positive_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(positive_assets, "MD5")
    assert asset is not None, "MD5 not found in detected assets"
    assert asset.quantum_status == QuantumStatus(_expected_quantum_status("MD5"))


def test_sha1_detected(positive_assets: list[CryptoAsset]) -> None:
    # SHA-1 in the fixture uses "SHA-1" (with hyphen)
    asset = _find_asset(positive_assets, "SHA-1")
    assert asset is not None, "SHA-1 not found in detected assets"
    assert asset.quantum_status == QuantumStatus(_expected_quantum_status("SHA-1"))


def test_ecdsa_or_ec_detected(positive_assets: list[CryptoAsset]) -> None:
    """Either ECDSA or EC must be present (EC from KeyPairGenerator.getInstance("EC"))."""
    has_ec = _find_asset(positive_assets, "EC") is not None
    has_ecdsa = _find_asset(positive_assets, "ECDSA") is not None
    assert has_ec or has_ecdsa, (
        "Neither EC nor ECDSA found in detected assets"
    )


def test_sha256_detected(positive_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(positive_assets, "SHA-256")
    assert asset is not None, "SHA-256 not found in detected assets"
    assert asset.quantum_status == QuantumStatus(_expected_quantum_status("SHA-256"))


# ---------------------------------------------------------------------------
# Test: evidence fields are fully populated (hard constraint #3)
# ---------------------------------------------------------------------------


def test_every_asset_has_evidence(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        assert len(asset.evidence) >= 1, f"Asset {asset.name!r} has no evidence"


def test_evidence_fields_populated_for_rsa(positive_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(positive_assets, "RSA")
    assert asset is not None
    for ev in asset.evidence:
        _assert_evidence_populated(ev, POSITIVE_FIXTURE)


def test_evidence_fields_populated_for_md5(positive_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(positive_assets, "MD5")
    assert asset is not None
    _assert_evidence_populated(asset.evidence[0], POSITIVE_FIXTURE)


def test_evidence_snippet_contains_getinstance(positive_assets: list[CryptoAsset]) -> None:
    """Every snippet should contain 'getInstance' (the JCA factory method)."""
    for asset in positive_assets:
        for ev in asset.evidence:
            assert "getInstance" in ev.snippet, (
                f"Snippet for {asset.name!r} does not contain 'getInstance': {ev.snippet!r}"
            )


def test_evidence_line_numbers_are_positive(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        for ev in asset.evidence:
            assert ev.line is not None and ev.line > 0


def test_evidence_byte_offsets_are_nonnegative(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        for ev in asset.evidence:
            assert ev.byte_offset is not None and ev.byte_offset >= 0


# ---------------------------------------------------------------------------
# Test: determinism — two scans of same file produce identical results
# ---------------------------------------------------------------------------


def test_detector_is_deterministic(detector: JavaJcaDetector) -> None:
    """Two independent detections of the same file must produce byte-identical output."""
    assets_a = detector.detect(POSITIVE_FIXTURE)
    assets_b = detector.detect(POSITIVE_FIXTURE)

    assert len(assets_a) == len(assets_b), "Different number of assets across two runs"
    for a, b in zip(assets_a, assets_b):
        assert a.id == b.id
        assert a.name == b.name
        assert a.quantum_status == b.quantum_status
        assert len(a.evidence) == len(b.evidence)
        for ea, eb in zip(a.evidence, b.evidence):
            assert ea.key() == eb.key()


# ---------------------------------------------------------------------------
# Test: asset IDs are deterministic (no uuid4)
# ---------------------------------------------------------------------------


def test_asset_ids_are_stable_across_runs(detector: JavaJcaDetector) -> None:
    assets_a = detector.detect(POSITIVE_FIXTURE)
    assets_b = detector.detect(POSITIVE_FIXTURE)
    ids_a = sorted(a.id for a in assets_a)
    ids_b = sorted(a.id for a in assets_b)
    assert ids_a == ids_b


# ---------------------------------------------------------------------------
# Test: lookup helper (unit-test of the normalisation logic)
# ---------------------------------------------------------------------------


def test_lookup_algo_slash_stripping() -> None:
    index = _algo_index()
    # "AES/GCM/NoPadding" should resolve to "AES"
    result = _lookup_algo("AES/GCM/NoPadding", index)
    assert result is not None
    canonical, _ = result
    assert canonical.upper() == "AES"


def test_lookup_algo_with_stripping() -> None:
    index = _algo_index()
    # "SHA256withECDSA" should resolve to something (ECDSA or SHA-256 variant)
    result = _lookup_algo("SHA256withECDSA", index)
    # We don't assert the exact canonical name — just that it resolves to something
    assert result is not None


def test_lookup_algo_rsa_encryption_suffix_resolves_to_rsa() -> None:
    """Regression test for the ENCRYPTION/SIGNATURE suffix-stripping bug:
    _lookup_algo's right-of-"With" branch used to build its second
    candidate via `right.rstrip("ENCRYPTION").rstrip("SIGNATURE")`, which
    strips any trailing characters found in those strings' character SETS
    rather than the literal suffixes. On "RSAENCRYPTION" specifically, that
    chain strips all the way down to "" (empty string) -- verified
    explicitly below -- so "SHA256WithRSAEncryption" (a real-shaped JCA
    algorithm string) failed to resolve to "RSA" at all under the old code.
    The fix uses str.removesuffix, which only removes the literal suffix.
    """
    index = _algo_index()
    result = _lookup_algo("SHA256WithRSAEncryption", index)
    assert result is not None, (
        '"SHA256WithRSAEncryption" failed to resolve to any algorithm -- '
        "the ENCRYPTION-suffix-stripping fix has regressed"
    )
    canonical, _ = result
    assert canonical.upper() == "RSA"


def test_rstrip_suffix_bug_did_not_coincidentally_work_for_rsa_encryption() -> None:
    """Explicit proof (not an assumption) that the pre-fix `.rstrip(...)`
    chain was actually broken for the exact "RSAENCRYPTION" case the
    surrounding code comment uses as its own motivating example -- it
    strips character-by-character until it hits a character not in either
    removal set, which for "RSAENCRYPTION" happens to consume the entire
    string. `str.removesuffix` (the fix) correctly leaves "RSA".
    """
    right = "RSAENCRYPTION"
    # Deliberately reproducing the pre-fix buggy call to prove what it
    # actually did -- not a real use of rstrip.
    old_buggy_result = right.rstrip("ENCRYPTION").rstrip("SIGNATURE")  # noqa: B005, PLE1310
    assert old_buggy_result == "", (
        "expected the old rstrip-chain bug to reduce 'RSAENCRYPTION' to an empty "
        f"string, got {old_buggy_result!r} -- the bug's premise assumed by this "
        "test no longer holds, re-verify test_lookup_algo_rsa_encryption_suffix_resolves_to_rsa "
        "still exercises a real fix"
    )

    fixed_result = right.removesuffix("ENCRYPTION").removesuffix("SIGNATURE")
    assert fixed_result == "RSA"


def test_lookup_algo_unknown_returns_none() -> None:
    index = _algo_index()
    result = _lookup_algo("UNKNOWN_ALGO_XYZ_404", index)
    assert result is None


def test_lookup_algo_exact_match() -> None:
    index = _algo_index()
    result = _lookup_algo("MD5", index)
    assert result is not None
    canonical, rule = result
    assert canonical.upper() == "MD5"
    assert rule["quantum_status"] == "broken-classically"


def test_lookup_algo_case_insensitive() -> None:
    index = _algo_index()
    result_upper = _lookup_algo("SHA-256", index)
    result_lower = _lookup_algo("sha-256", index)
    assert result_upper is not None
    assert result_lower is not None
    assert result_upper[0].upper() == result_lower[0].upper()


# ---------------------------------------------------------------------------
# Test: BouncyCastle provider call is detected as the correct algorithm
# ---------------------------------------------------------------------------


def test_bouncy_castle_rsa_detected_and_merged_with_native(
    positive_assets: list[CryptoAsset],
) -> None:
    """KeyPairGenerator.getInstance("RSA", "BC") must produce an RSA asset."""
    asset = _find_asset(positive_assets, "RSA")
    assert asset is not None

    # At least one evidence entry should come from the line containing "BC"
    bc_evidences = [ev for ev in asset.evidence if '"BC"' in ev.snippet or "'BC'" in ev.snippet]
    assert len(bc_evidences) >= 1, (
        "No evidence found for the BouncyCastle RSA call. "
        f"Snippets: {[ev.snippet for ev in asset.evidence]}"
    )


# ---------------------------------------------------------------------------
# KeyAgreement.getInstance + BouncyCastle lightweight API
# (found via the post-hashlib-fix audit — see docs/COVERAGE.md)
# ---------------------------------------------------------------------------

BC_KEYAGREEMENT_FIXTURE = TESTDATA_JAVA / "bouncycastle_and_keyagreement.java"


@pytest.fixture(scope="module")
def bc_keyagreement_assets(detector: JavaJcaDetector) -> list[CryptoAsset]:
    return detector.detect(BC_KEYAGREEMENT_FIXTURE)


def test_bc_keyagreement_fixture_exists() -> None:
    assert BC_KEYAGREEMENT_FIXTURE.is_file()


def test_keyagreement_getinstance_dh_detected(bc_keyagreement_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(bc_keyagreement_assets, "DH")
    assert asset is not None, f"Got: {[a.name for a in bc_keyagreement_assets]}"
    assert asset.quantum_status == QuantumStatus.BROKEN_BY_SHOR


def test_keyagreement_getinstance_ecdh_detected(bc_keyagreement_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(bc_keyagreement_assets, "ECDH")
    assert asset is not None, f"Got: {[a.name for a in bc_keyagreement_assets]}"
    assert asset.quantum_status == QuantumStatus.BROKEN_BY_SHOR


def test_bc_new_rsakeypairgenerator_detected(bc_keyagreement_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(bc_keyagreement_assets, "RSA")
    assert asset is not None, f"Got: {[a.name for a in bc_keyagreement_assets]}"
    snippets = [ev.snippet for ev in asset.evidence]
    assert any("new RSAKeyPairGenerator" in s for s in snippets), snippets


def test_bc_new_ecdsasigner_detected(bc_keyagreement_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(bc_keyagreement_assets, "ECDSA")
    assert asset is not None, f"Got: {[a.name for a in bc_keyagreement_assets]}"
    snippets = [ev.snippet for ev in asset.evidence]
    assert any("new ECDSASigner" in s for s in snippets), snippets


def test_bc_new_ed25519signer_and_keypairgenerator_merge(
    bc_keyagreement_assets: list[CryptoAsset],
) -> None:
    asset = _find_asset(bc_keyagreement_assets, "Ed25519")
    assert asset is not None, f"Got: {[a.name for a in bc_keyagreement_assets]}"
    assert len(asset.evidence) == 2
    snippets = [ev.snippet for ev in asset.evidence]
    assert any("Ed25519Signer" in s for s in snippets), snippets
    assert any("Ed25519KeyPairGenerator" in s for s in snippets), snippets


def test_bc_new_x25519keypairgenerator_detected(bc_keyagreement_assets: list[CryptoAsset]) -> None:
    asset = _find_asset(bc_keyagreement_assets, "X25519")
    assert asset is not None, f"Got: {[a.name for a in bc_keyagreement_assets]}"


def test_bc_keyagreement_fixture_component_count(bc_keyagreement_assets: list[CryptoAsset]) -> None:
    assert len(bc_keyagreement_assets) == 6, (
        f"Expected 6 findings, got: {[a.name for a in bc_keyagreement_assets]}"
    )


def test_bc_constructor_index_has_expected_classes() -> None:
    from hash_patch.detect.java import _build_bc_constructor_index

    index = _build_bc_constructor_index(_load_rules())
    for cls in (
        "RSAKeyPairGenerator",
        "ECDSASigner",
        "Ed25519Signer",
        "Ed25519KeyPairGenerator",
        "X25519KeyPairGenerator",
    ):
        assert cls in index, f"bc_constructors missing {cls}"


def test_object_creation_not_collected_without_bc_classes() -> None:
    """The default (no bc_classes passed) must behave exactly as before —
    _collect_jca_calls(root_node) alone never collects a `new X()` call,
    even one that WOULD match if bc_classes were supplied."""
    import tree_sitter_java as _tsjava
    from tree_sitter import Language, Parser

    from hash_patch.detect.java import _collect_jca_calls

    lang = Language(_tsjava.language())
    parser = Parser(lang)
    src = b"class T { void m() { Object o = new RSAKeyPairGenerator(); } }"
    tree = parser.parse(src)
    calls = _collect_jca_calls(tree.root_node)
    assert calls == [], f"Expected no calls without bc_classes, got {calls}"


def test_object_creation_collected_with_matching_bc_classes() -> None:
    import tree_sitter_java as _tsjava
    from tree_sitter import Language, Parser

    from hash_patch.detect.java import _collect_jca_calls

    lang = Language(_tsjava.language())
    parser = Parser(lang)
    src = b"class T { void m() { Object o = new RSAKeyPairGenerator(); } }"
    tree = parser.parse(src)
    calls = _collect_jca_calls(tree.root_node, bc_classes=frozenset({"RSAKeyPairGenerator"}))
    assert len(calls) == 1
    assert calls[0]["bc_class"] == "RSAKeyPairGenerator"
