"""tests/unit/test_go_detector.py

Unit tests for hash_patch.detect.go.GoCryptoDetector.

Design notes:
  - No algorithm names are hardcoded in this file (CLAUDE.md constraint).
    Expected canonical names and quantum statuses are read from
    rules/go_crypto.yaml via helper functions.
  - Every assertion about a CryptoAsset verifies that at least one Evidence
    entry has a real locator, line, column, byte_offset, and snippet.
  - Determinism is verified by running the detector twice over the same file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from hash_patch.detect.go import (
    GoCryptoDetector,
    _build_function_index,
    _collect_calls,
)
from hash_patch.model.assets import AssetType, CryptoAsset, QuantumStatus
from hash_patch.model.evidence import Evidence

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA_GO = REPO_ROOT / "testdata" / "go"
RULES_PATH = REPO_ROOT / "rules" / "go_crypto.yaml"
POSITIVE_FIXTURE = TESTDATA_GO / "crypto_examples.go"
NEGATIVE_FIXTURE = TESTDATA_GO / "negative_rsa_mention.go"
BCRYPT_FIXTURE = TESTDATA_GO / "bcrypt_examples.go"


# ---------------------------------------------------------------------------
# Rules helpers (no hardcoded algo names in assertions)
# ---------------------------------------------------------------------------


def _load_rules() -> dict[str, Any]:
    with RULES_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _expected_quantum_status_for_func(func_key: str) -> str:
    rules = _load_rules()
    funcs = _build_function_index(rules)
    assert func_key in funcs, f"Function {func_key!r} not in rules"
    return funcs[func_key]["quantum_status"]


def _canonical_name_for_func(func_key: str) -> str:
    rules = _load_rules()
    funcs = _build_function_index(rules)
    assert func_key in funcs, f"Function {func_key!r} not in rules"
    return funcs[func_key]["canonical"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def detector() -> GoCryptoDetector:
    return GoCryptoDetector()


@pytest.fixture(scope="module")
def positive_assets(detector: GoCryptoDetector) -> list[CryptoAsset]:
    return detector.detect(POSITIVE_FIXTURE)


@pytest.fixture(scope="module")
def negative_assets(detector: GoCryptoDetector) -> list[CryptoAsset]:
    return detector.detect(NEGATIVE_FIXTURE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_assets(assets: list[CryptoAsset], canonical: str) -> list[CryptoAsset]:
    return [a for a in assets if a.name.upper() == canonical.upper()]


def _assert_evidence_populated(ev: Evidence, fixture_path: Path) -> None:
    assert ev.source_type == "source"
    assert ev.locator == str(fixture_path)
    assert ev.line is not None and ev.line > 0, "line must be >= 1"
    assert ev.column is not None and ev.column >= 0
    assert ev.byte_offset is not None and ev.byte_offset >= 0
    assert ev.snippet is not None and len(ev.snippet) > 0
    assert ev.detector_id == "go-crypto"
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


def test_supports_go_file(detector: GoCryptoDetector) -> None:
    assert detector.supports(POSITIVE_FIXTURE) is True


def test_does_not_support_java_file(detector: GoCryptoDetector) -> None:
    java_fixture = REPO_ROOT / "testdata" / "java" / "crypto_examples.java"
    assert detector.supports(java_fixture) is False


def test_does_not_support_python_file(detector: GoCryptoDetector) -> None:
    py_fixture = REPO_ROOT / "testdata" / "python" / "crypto_pyca.py"
    assert detector.supports(py_fixture) is False


def test_does_not_support_directory(detector: GoCryptoDetector) -> None:
    assert detector.supports(TESTDATA_GO) is False


def test_does_not_support_non_go_file(detector: GoCryptoDetector, tmp_path: Path) -> None:
    f = tmp_path / "main.txt"
    f.write_text("package main\n")
    assert detector.supports(f) is False


# ---------------------------------------------------------------------------
# Negative fixture
# ---------------------------------------------------------------------------


def test_negative_fixture_produces_no_assets(negative_assets: list[CryptoAsset]) -> None:
    """Algorithm mentions in comments, strings, and non-crypto structs must yield 0 assets."""
    assert negative_assets == [], (
        f"Expected 0 assets from negative fixture, got: {[a.name for a in negative_assets]}"
    )


# ---------------------------------------------------------------------------
# Positive fixture — expected algorithms
# ---------------------------------------------------------------------------


def test_positive_fixture_produces_nonzero_assets(positive_assets: list[CryptoAsset]) -> None:
    assert len(positive_assets) > 0


def test_rsa_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("rsa.GenerateKey")
    expected_status = _expected_quantum_status_for_func("rsa.GenerateKey")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found in detected assets"
    assert any(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_aes_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("aes.NewCipher")
    expected_status = _expected_quantum_status_for_func("aes.NewCipher")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found in detected assets"
    assert any(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_aes_gcm_mode_detected(positive_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(positive_assets, "AES")
    gcm_hits = [a for a in hits if a.mode == "gcm"]
    assert len(gcm_hits) == 1, "Expected 1 AES asset with mode=gcm"


def test_md5_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("md5.New")
    expected_status = _expected_quantum_status_for_func("md5.New")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_sha1_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("sha1.New")
    expected_status = _expected_quantum_status_for_func("sha1.New")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_sha256_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("sha256.Sum256")
    expected_status = _expected_quantum_status_for_func("sha256.Sum256")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_ecdsa_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("ecdsa.GenerateKey")
    expected_status = _expected_quantum_status_for_func("ecdsa.GenerateKey")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_3des_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("des.NewTripleDESCipher")
    expected_status = _expected_quantum_status_for_func("des.NewTripleDESCipher")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


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
# Asset structure & determinism
# ---------------------------------------------------------------------------


def test_all_assets_are_algorithm_type(positive_assets: list[CryptoAsset]) -> None:
    for asset in positive_assets:
        assert asset.asset_type == AssetType.ALGORITHM


def test_all_assets_have_valid_quantum_status(positive_assets: list[CryptoAsset]) -> None:
    valid = {qs.value for qs in QuantumStatus}
    for asset in positive_assets:
        assert asset.quantum_status.value in valid


def test_detector_is_deterministic(detector: GoCryptoDetector) -> None:
    a_assets = detector.detect(POSITIVE_FIXTURE)
    b_assets = detector.detect(POSITIVE_FIXTURE)
    assert len(a_assets) == len(b_assets)
    for a, b in zip(a_assets, b_assets):
        assert a.id == b.id
        assert a.name == b.name
        assert len(a.evidence) == len(b.evidence)
        for ea, eb in zip(a.evidence, b.evidence):
            assert ea.key() == eb.key()


def test_asset_ids_stable_across_runs(detector: GoCryptoDetector) -> None:
    ids_a = sorted(a.id for a in detector.detect(POSITIVE_FIXTURE))
    ids_b = sorted(a.id for a in detector.detect(POSITIVE_FIXTURE))
    assert ids_a == ids_b


# ---------------------------------------------------------------------------
# Rules structure tests
# ---------------------------------------------------------------------------


def test_rules_have_required_fields() -> None:
    rules = _load_rules()
    funcs = _build_function_index(rules)
    required = {"canonical", "primitive", "quantum_status"}

    for key, entry in funcs.items():
        missing = required - set(entry.keys())
        assert not missing, f"functions.{key} missing fields: {missing}"


# ---------------------------------------------------------------------------
# Internal AST helpers
# ---------------------------------------------------------------------------


def test_collect_calls_finds_selector_calls() -> None:
    import tree_sitter_go as _tsgo
    from tree_sitter import Language, Parser

    lang = Language(_tsgo.language())
    parser = Parser(lang)
    src = b"package main\nfunc main() {\n\trsa.GenerateKey(nil, 2048)\n\taes.NewCipher(nil)\n}\n"
    tree = parser.parse(src)
    calls = _collect_calls(tree.root_node)
    assert len(calls) == 2
    targets = {c["target"] for c in calls}
    assert "rsa.GenerateKey" in targets
    assert "aes.NewCipher" in targets


def test_collect_calls_ignores_plain_function_calls() -> None:
    import tree_sitter_go as _tsgo
    from tree_sitter import Language, Parser

    lang = Language(_tsgo.language())
    parser = Parser(lang)
    src = b"package main\nfunc main() {\n\tprintln(42)\n\tmyFunc()\n}\n"
    tree = parser.parse(src)
    calls = _collect_calls(tree.root_node)
    assert calls == []


# ---------------------------------------------------------------------------
# golang.org/x/crypto/bcrypt (found via the post-hashlib-fix audit — see
# docs/COVERAGE.md)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def bcrypt_assets(detector: GoCryptoDetector) -> list[CryptoAsset]:
    return detector.detect(BCRYPT_FIXTURE)


def test_bcrypt_fixture_exists() -> None:
    assert BCRYPT_FIXTURE.is_file()


def test_bcrypt_generate_from_password_detected(bcrypt_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(bcrypt_assets, "bcrypt")
    assert hits, f"bcrypt.GenerateFromPassword not detected. Got: {[a.name for a in bcrypt_assets]}"
    assert all(a.quantum_status == QuantumStatus.WEAKENED_BY_GROVER for a in hits)
    snippets = [e.snippet for a in hits for e in a.evidence]
    assert any("GenerateFromPassword" in s for s in snippets), snippets


def test_bcrypt_compare_hash_and_password_merged(bcrypt_assets: list[CryptoAsset]) -> None:
    hits = _find_assets(bcrypt_assets, "bcrypt")
    assert hits
    total_ev = sum(len(a.evidence) for a in hits)
    assert total_ev == 2, f"Expected 2 evidence entries (both bcrypt calls merged), got {total_ev}"
    snippets = [e.snippet for a in hits for e in a.evidence]
    assert any("CompareHashAndPassword" in s for s in snippets), snippets


def test_function_index_has_bcrypt_entries() -> None:
    index = _build_function_index(_load_rules())
    assert "bcrypt.GenerateFromPassword" in index
    assert "bcrypt.CompareHashAndPassword" in index
