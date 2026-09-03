"""tests/unit/test_python_detector.py

Unit tests for hash_patch.detect.python.PythonCryptoDetector.

Design notes:
  - No algorithm names are hardcoded in this file (CLAUDE.md constraint).
    Expected canonical names and quantum statuses are read from
    rules/python_crypto.yaml via helper functions.
  - Every assertion about a CryptoAsset verifies that at least one Evidence
    entry has a real locator, line, column, byte_offset, and snippet.
  - Determinism is verified by running the detector twice over the same file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from hash_patch.detect.python import (
    PythonCryptoDetector,
    _build_pyca_index,
    _build_pycryptodome_index,
    _collect_calls,
)
from hash_patch.model.assets import AssetType, CryptoAsset, QuantumStatus
from hash_patch.model.evidence import Evidence

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA_PY = REPO_ROOT / "testdata" / "python"
RULES_PATH = REPO_ROOT / "rules" / "python_crypto.yaml"
POSITIVE_FIXTURE = TESTDATA_PY / "crypto_pyca.py"
NEGATIVE_FIXTURE = TESTDATA_PY / "negative_rsa_mention.py"


# ---------------------------------------------------------------------------
# Rules helpers (no hardcoded algo names)
# ---------------------------------------------------------------------------


def _load_rules() -> dict[str, Any]:
    with RULES_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _canonical_to_status(canonical: str) -> str | None:
    """Look up the quantum_status for a canonical algorithm name from rules."""
    rules = _load_rules()
    pyca = _build_pyca_index(rules)
    pycrypto = _build_pycryptodome_index(rules)

    # Search pyca modules
    for ns_attrs in pyca.values():
        for entry in ns_attrs.values():
            if entry.get("canonical", "").upper() == canonical.upper():
                return entry.get("quantum_status")
    # Search pycryptodome
    for entry in pycrypto.values():
        if entry.get("canonical", "").upper() == canonical.upper():
            return entry.get("quantum_status")
    return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def detector() -> PythonCryptoDetector:
    return PythonCryptoDetector()


@pytest.fixture(scope="module")
def positive_assets(detector: PythonCryptoDetector) -> list[CryptoAsset]:
    return detector.detect(POSITIVE_FIXTURE)


@pytest.fixture(scope="module")
def negative_assets(detector: PythonCryptoDetector) -> list[CryptoAsset]:
    return detector.detect(NEGATIVE_FIXTURE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_assets(assets: list[CryptoAsset], canonical: str) -> list[CryptoAsset]:
    return [a for a in assets if a.name.upper() == canonical.upper()]


def _assert_evidence_populated(ev: Evidence, fixture_path: Path) -> None:
    assert ev.source_type == "source"
    assert ev.locator == str(fixture_path)
    assert ev.line is not None and ev.line > 0, "line must be ≥ 1"
    assert ev.column is not None and ev.column >= 0
    assert ev.byte_offset is not None and ev.byte_offset >= 0
    assert ev.snippet is not None and len(ev.snippet) > 0
    assert ev.detector_id == "python-crypto"
    assert ev.detector_version == "0.1.0"


# ---------------------------------------------------------------------------
# Fixture existence
# ---------------------------------------------------------------------------


def test_positive_fixture_exists() -> None:
    assert POSITIVE_FIXTURE.is_file()


def test_negative_fixture_exists() -> None:
    assert NEGATIVE_FIXTURE.is_file()


def test_rules_file_exists() -> None:
    assert RULES_PATH.is_file()


# ---------------------------------------------------------------------------
# supports()
# ---------------------------------------------------------------------------


def test_supports_py_file(detector: PythonCryptoDetector) -> None:
    assert detector.supports(POSITIVE_FIXTURE) is True


def test_does_not_support_java_file(detector: PythonCryptoDetector) -> None:
    java_fixture = REPO_ROOT / "testdata" / "java" / "crypto_examples.java"
    assert detector.supports(java_fixture) is False


def test_does_not_support_directory(detector: PythonCryptoDetector) -> None:
    assert detector.supports(TESTDATA_PY) is False


def test_does_not_support_non_py_file(detector: PythonCryptoDetector, tmp_path: Path) -> None:
    f = tmp_path / "config.yaml"
    f.write_text("key: value\n")
    assert detector.supports(f) is False


# ---------------------------------------------------------------------------
# Negative fixture
# ---------------------------------------------------------------------------


def test_negative_fixture_produces_no_assets(negative_assets: list[CryptoAsset]) -> None:
    """RSA/AES/MD5 in comments, plain strings, and non-crypto calls must yield 0 assets."""
    assert negative_assets == [], (
        f"Expected 0 assets from negative fixture, got: {[a.name for a in negative_assets]}"
    )


# ---------------------------------------------------------------------------
# Positive fixture — expected algorithms
# ---------------------------------------------------------------------------


def test_positive_fixture_produces_nonzero_assets(positive_assets: list[CryptoAsset]) -> None:
    assert len(positive_assets) > 0


def test_rsa_detected_via_pyca(positive_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(positive_assets, "RSA")
    assert hits, "RSA not found in detected assets"
    assert any(a.quantum_status == QuantumStatus(_canonical_to_status("RSA")) for a in hits)


def test_aes_detected_via_pyca(positive_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(positive_assets, "AES")
    assert hits, "AES not found in detected assets"


def test_md5_detected_via_pyca(positive_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(positive_assets, "MD5")
    assert hits, "MD5 not found"
    status = _canonical_to_status("MD5")
    assert status is not None
    assert all(a.quantum_status == QuantumStatus(status) for a in hits)


def test_sha1_detected_via_pyca(positive_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(positive_assets, "SHA-1")
    assert hits, "SHA-1 not found"
    status = _canonical_to_status("SHA-1")
    assert status is not None
    assert all(a.quantum_status == QuantumStatus(status) for a in hits)


def test_sha256_detected_via_pyca(positive_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(positive_assets, "SHA-256")
    assert hits, "SHA-256 not found"


def test_ecdsa_detected_via_pyca(positive_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(positive_assets, "ECDSA")
    assert hits, "ECDSA not found"
    assert all(a.quantum_status == QuantumStatus.BROKEN_BY_SHOR for a in hits)


# ---------------------------------------------------------------------------
# Positive fixture — pycryptodome calls specifically
# ---------------------------------------------------------------------------


def test_pycryptodome_aes_detected(positive_assets: list[CryptoAsset]) -> None:
    """AES.new() from pycryptodome must contribute evidence to the AES asset."""
    aes_assets = _find_assets(positive_assets, "AES")
    assert aes_assets, "AES not found"
    all_snippets = [e.snippet for a in aes_assets for e in a.evidence]
    pycrypto_hits = [s for s in all_snippets if "AES.new" in s]
    assert pycrypto_hits, (
        "No pycryptodome AES.new evidence found. Snippets: " + str(all_snippets)
    )


def test_pycryptodome_rsa_detected(positive_assets: list[CryptoAsset]) -> None:
    """RSA.generate() from pycryptodome must contribute evidence to the RSA asset."""
    rsa_assets = _find_assets(positive_assets, "RSA")
    assert rsa_assets
    all_snippets = [e.snippet for a in rsa_assets for e in a.evidence]
    pycrypto_hits = [s for s in all_snippets if "RSA.generate" in s]
    assert pycrypto_hits, (
        "No pycryptodome RSA.generate evidence found. Snippets: " + str(all_snippets)
    )


def test_pycryptodome_md5_detected(positive_assets: list[CryptoAsset]) -> None:
    """MD5.new() from pycryptodome must contribute evidence to the MD5 asset."""
    md5_assets = _find_assets(positive_assets, "MD5")
    assert md5_assets
    all_snippets = [e.snippet for a in md5_assets for e in a.evidence]
    pycrypto_hits = [s for s in all_snippets if "MD5.new" in s]
    assert pycrypto_hits, (
        "No pycryptodome MD5.new evidence found. Snippets: " + str(all_snippets)
    )


def test_md5_has_two_evidence_entries_pyca_and_pycryptodome(
    positive_assets: list[CryptoAsset],
) -> None:
    """MD5 is referenced twice (hashes.MD5() + MD5.new()) — evidence should be merged."""
    md5_assets = _find_assets(positive_assets, "MD5")
    total_ev = sum(len(a.evidence) for a in md5_assets)
    assert total_ev >= 2, f"Expected ≥2 MD5 evidence entries, got {total_ev}"


def test_rsa_has_two_evidence_entries_pyca_and_pycryptodome(
    positive_assets: list[CryptoAsset],
) -> None:
    rsa_assets = _find_assets(positive_assets, "RSA")
    total_ev = sum(len(a.evidence) for a in rsa_assets)
    assert total_ev >= 2, f"Expected ≥2 RSA evidence entries, got {total_ev}"


# ---------------------------------------------------------------------------
# Evidence fields — hard constraint #3
# ---------------------------------------------------------------------------


def test_every_asset_has_evidence(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        assert len(asset.evidence) >= 1, f"Asset {asset.name!r} has no evidence"


def test_evidence_fields_populated_for_all_assets(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        for ev in asset.evidence:
            _assert_evidence_populated(ev, POSITIVE_FIXTURE)


def test_evidence_line_numbers_positive(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        for ev in asset.evidence:
            assert ev.line is not None and ev.line > 0


def test_evidence_byte_offsets_nonnegative(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        for ev in asset.evidence:
            assert ev.byte_offset is not None and ev.byte_offset >= 0


def test_evidence_snippets_nonempty(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        for ev in asset.evidence:
            assert ev.snippet and len(ev.snippet.strip()) > 0


# ---------------------------------------------------------------------------
# Asset type and structure
# ---------------------------------------------------------------------------


def test_all_assets_are_algorithm_type(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        assert asset.asset_type == AssetType.ALGORITHM, (
            f"Expected ALGORITHM asset type for {asset.name!r}, got {asset.asset_type}"
        )


def test_all_assets_have_valid_quantum_status(positive_assets: list[CryptoAsset]) -> None:
    valid = {qs.value for qs in QuantumStatus}
    for asset in positive_assets:
        assert asset.quantum_status.value in valid


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_detector_is_deterministic(detector: PythonCryptoDetector) -> None:
    a_assets = detector.detect(POSITIVE_FIXTURE)
    b_assets = detector.detect(POSITIVE_FIXTURE)
    assert len(a_assets) == len(b_assets)
    for a, b in zip(a_assets, b_assets):
        assert a.id == b.id
        assert a.name == b.name
        assert len(a.evidence) == len(b.evidence)
        for ea, eb in zip(a.evidence, b.evidence):
            assert ea.key() == eb.key()


def test_asset_ids_stable_across_runs(detector: PythonCryptoDetector) -> None:
    ids_a = sorted(a.id for a in detector.detect(POSITIVE_FIXTURE))
    ids_b = sorted(a.id for a in detector.detect(POSITIVE_FIXTURE))
    assert ids_a == ids_b


# ---------------------------------------------------------------------------
# Rules structure tests
# ---------------------------------------------------------------------------


def test_pyca_index_has_hashes_namespace() -> None:
    rules = _load_rules()
    index = _build_pyca_index(rules)
    assert "hashes" in index, "pyca_modules must contain 'hashes' namespace"
    assert "SHA256" in index["hashes"], "hashes must map SHA256"


def test_pycryptodome_index_has_aes_new() -> None:
    rules = _load_rules()
    index = _build_pycryptodome_index(rules)
    assert "AES.new" in index, "pycryptodome_classes must contain 'AES.new'"


def test_all_rules_entries_have_required_fields() -> None:
    rules = _load_rules()
    pyca = _build_pyca_index(rules)
    pycrypto = _build_pycryptodome_index(rules)
    required = {"canonical", "primitive", "quantum_status"}

    for ns, attrs in pyca.items():
        for attr, entry in attrs.items():
            missing = required - set(entry.keys())
            assert not missing, f"pyca_modules.{ns}.{attr} missing fields: {missing}"

    for key, entry in pycrypto.items():
        missing = required - set(entry.keys())
        assert not missing, f"pycryptodome_classes.{key} missing fields: {missing}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def test_collect_calls_finds_attribute_calls() -> None:
    """_collect_calls must find attribute-based calls like hashes.SHA256()."""
    import tree_sitter_python as _tspy
    from tree_sitter import Language, Parser

    lang = Language(_tspy.language())
    parser = Parser(lang)
    src = b"hashes.SHA256()\nRSA.generate(2048)\n"
    tree = parser.parse(src)
    calls = _collect_calls(tree.root_node)
    assert len(calls) == 2
    objs = {c["obj"] for c in calls}
    attrs = {c["attr"] for c in calls}
    assert "hashes" in objs
    assert "SHA256" in attrs
    assert "RSA" in objs
    assert "generate" in attrs


def test_collect_calls_ignores_plain_function_calls() -> None:
    """_collect_calls must ignore plain function calls (no attribute receiver)."""
    import tree_sitter_python as _tspy
    from tree_sitter import Language, Parser

    lang = Language(_tspy.language())
    parser = Parser(lang)
    src = b"print('hello')\nsome_function(42)\n"
    tree = parser.parse(src)
    calls = _collect_calls(tree.root_node)
    assert calls == [], f"Expected no attribute calls, got {calls}"
