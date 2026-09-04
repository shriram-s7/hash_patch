"""tests/unit/test_c_detector.py

Unit tests for hash_patch.detect.c.COpenSSLDetector.

Design notes:
  - No algorithm names are hardcoded in this file (CLAUDE.md constraint).
    Expected canonical names and quantum statuses are read from
    rules/c_openssl.yaml via helper functions.
  - Every assertion about a CryptoAsset verifies that at least one Evidence
    entry has a real locator, line, column, byte_offset, and snippet.
  - Determinism is verified by running the detector twice over the same file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from hash_patch.detect.c import (
    COpenSSLDetector,
    _collect_matches,
)
from hash_patch.model.assets import AssetType, CryptoAsset, QuantumStatus
from hash_patch.model.evidence import Evidence

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA_C = REPO_ROOT / "testdata" / "c"
RULES_PATH = REPO_ROOT / "rules" / "c_openssl.yaml"
POSITIVE_FIXTURE = TESTDATA_C / "crypto_examples.c"
EVP_HMAC_FIXTURE = TESTDATA_C / "evp_digest_and_hmac_examples.c"
NEGATIVE_FIXTURE = TESTDATA_C / "negative_rsa_mention.c"


# ---------------------------------------------------------------------------
# Rules helpers (no hardcoded algo names in assertions)
# ---------------------------------------------------------------------------


def _load_rules() -> dict[str, Any]:
    with RULES_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _expected_quantum_status_for_func(func_key: str) -> str:
    rules = _load_rules()
    funcs = rules.get("functions", {})
    assert func_key in funcs, f"Function {func_key!r} not in rules"
    return funcs[func_key]["quantum_status"]


def _canonical_name_for_func(func_key: str) -> str:
    rules = _load_rules()
    funcs = rules.get("functions", {})
    assert func_key in funcs, f"Function {func_key!r} not in rules"
    return funcs[func_key]["canonical"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def detector() -> COpenSSLDetector:
    return COpenSSLDetector()


@pytest.fixture(scope="module")
def positive_assets(detector: COpenSSLDetector) -> list[CryptoAsset]:
    return detector.detect(POSITIVE_FIXTURE)


@pytest.fixture(scope="module")
def negative_assets(detector: COpenSSLDetector) -> list[CryptoAsset]:
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
    assert ev.detector_id == "c-openssl"
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


def test_supports_c_file(detector: COpenSSLDetector) -> None:
    assert detector.supports(POSITIVE_FIXTURE) is True


def test_supports_cpp_file(detector: COpenSSLDetector, tmp_path: Path) -> None:
    cpp_file = tmp_path / "main.cpp"
    cpp_file.write_text("#include <iostream>\n")
    assert detector.supports(cpp_file) is True


def test_supports_header_file(detector: COpenSSLDetector, tmp_path: Path) -> None:
    h_file = tmp_path / "crypto.h"
    h_file.write_text("#pragma once\n")
    assert detector.supports(h_file) is True


def test_does_not_support_java_file(detector: COpenSSLDetector) -> None:
    java_fixture = REPO_ROOT / "testdata" / "java" / "crypto_examples.java"
    assert detector.supports(java_fixture) is False


def test_does_not_support_python_file(detector: COpenSSLDetector) -> None:
    py_fixture = REPO_ROOT / "testdata" / "python" / "crypto_pyca.py"
    assert detector.supports(py_fixture) is False


def test_does_not_support_directory(detector: COpenSSLDetector) -> None:
    assert detector.supports(TESTDATA_C) is False


def test_does_not_support_non_c_file(detector: COpenSSLDetector, tmp_path: Path) -> None:
    f = tmp_path / "main.rs"
    f.write_text("fn main() {}\n")
    assert detector.supports(f) is False


# ---------------------------------------------------------------------------
# Negative fixture
# ---------------------------------------------------------------------------


def test_negative_fixture_produces_no_assets(negative_assets: list[CryptoAsset]) -> None:
    """Algorithm mentions in comments, strings, and non-crypto types must yield 0 assets."""
    assert negative_assets == [], (
        f"Expected 0 assets from negative fixture, got: {[a.name for a in negative_assets]}"
    )


# ---------------------------------------------------------------------------
# Positive fixture — expected algorithms
# ---------------------------------------------------------------------------


def test_positive_fixture_produces_nonzero_assets(positive_assets: list[CryptoAsset]) -> None:
    assert len(positive_assets) > 0


def test_rsa_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("RSA_generate_key_ex")
    expected_status = _expected_quantum_status_for_func("RSA_generate_key_ex")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found in detected assets"
    assert any(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_rsa_has_multiple_evidence_entries_evp_and_legacy(
    positive_assets: list[CryptoAsset],
) -> None:
    hits = _find_assets(positive_assets, "RSA")
    assert hits
    total_ev = sum(len(a.evidence) for a in hits)
    assert total_ev >= 2, f"Expected >=2 evidence entries for RSA, got {total_ev}"


def test_aes_gcm_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("EVP_aes_256_gcm")
    expected_status = _expected_quantum_status_for_func("EVP_aes_256_gcm")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found in detected assets"
    gcm_hits = [a for a in hits if a.mode == "gcm"]
    assert len(gcm_hits) == 1, "Expected 1 AES asset with mode=gcm"
    assert gcm_hits[0].quantum_status == QuantumStatus(expected_status)


def test_md5_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("MD5_Init")
    expected_status = _expected_quantum_status_for_func("MD5_Init")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_sha1_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("SHA1_Init")
    expected_status = _expected_quantum_status_for_func("SHA1_Init")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_sha256_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("EVP_sha256")
    expected_status = _expected_quantum_status_for_func("EVP_sha256")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_ecdsa_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("EC_KEY_generate_key")
    expected_status = _expected_quantum_status_for_func("EC_KEY_generate_key")
    hits = _find_assets(positive_assets, canonical)
    assert hits, f"{canonical} not found"
    assert all(a.quantum_status == QuantumStatus(expected_status) for a in hits)


def test_3des_detected(positive_assets: list[CryptoAsset]) -> None:
    canonical = _canonical_name_for_func("DES_ede3_cbc_encrypt")
    expected_status = _expected_quantum_status_for_func("DES_ede3_cbc_encrypt")
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


def test_detector_is_deterministic(detector: COpenSSLDetector) -> None:
    a_assets = detector.detect(POSITIVE_FIXTURE)
    b_assets = detector.detect(POSITIVE_FIXTURE)
    assert len(a_assets) == len(b_assets)
    for a, b in zip(a_assets, b_assets):
        assert a.id == b.id
        assert a.name == b.name
        assert len(a.evidence) == len(b.evidence)
        for ea, eb in zip(a.evidence, b.evidence):
            assert ea.key() == eb.key()


def test_asset_ids_stable_across_runs(detector: COpenSSLDetector) -> None:
    ids_a = sorted(a.id for a in detector.detect(POSITIVE_FIXTURE))
    ids_b = sorted(a.id for a in detector.detect(POSITIVE_FIXTURE))
    assert ids_a == ids_b


# ---------------------------------------------------------------------------
# Rules structure tests
# ---------------------------------------------------------------------------


def test_rules_have_required_fields() -> None:
    rules = _load_rules()
    required = {"canonical", "primitive", "quantum_status"}

    for section in ("functions", "macro_args", "string_args"):
        for key, entry in rules.get(section, {}).items():
            missing = required - set(entry.keys())
            assert not missing, f"{section}.{key} missing fields: {missing}"


# ---------------------------------------------------------------------------
# Internal AST helpers
# ---------------------------------------------------------------------------


def test_collect_matches_finds_openssl_calls() -> None:
    import tree_sitter_c as _tsc
    from tree_sitter import Language, Parser

    lang = Language(_tsc.language())
    parser = Parser(lang)
    src = b"void f() { RSA_new(); EVP_aes_256_gcm(); }\n"
    tree = parser.parse(src)
    rules = _load_rules()
    matches = _collect_matches(
        tree.root_node,
        rules.get("functions", {}),
        rules.get("macro_args", {}),
        rules.get("string_args", {}),
        set(rules.get("macro_arg_functions", [])),
        set(rules.get("string_arg_functions", [])),
    )
    assert len(matches) == 2
    matched_names = {r["canonical"] for _, _, r in matches}
    assert "RSA" in matched_names
    assert "AES" in matched_names


def test_collect_matches_ignores_non_crypto_calls() -> None:
    import tree_sitter_c as _tsc
    from tree_sitter import Language, Parser

    lang = Language(_tsc.language())
    parser = Parser(lang)
    src = b"void f() { printf(\"hello\\n\"); malloc(100); }\n"
    tree = parser.parse(src)
    rules = _load_rules()
    matches = _collect_matches(
        tree.root_node,
        rules.get("functions", {}),
        rules.get("macro_args", {}),
        rules.get("string_args", {}),
        set(rules.get("macro_arg_functions", [])),
        set(rules.get("string_arg_functions", [])),
    )
    assert matches == []


# ---------------------------------------------------------------------------
# EVP_DigestInit_ex/EVP_MD selector (regression lock) + HMAC (real gap) —
# both checked in the post-hashlib-fix audit (see docs/COVERAGE.md).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def evp_hmac_assets(detector: COpenSSLDetector) -> list[CryptoAsset]:
    return detector.detect(EVP_HMAC_FIXTURE)


def test_evp_hmac_fixture_exists() -> None:
    assert EVP_HMAC_FIXTURE.is_file()


def test_evp_digestinit_ex_sha256_selector_detected(evp_hmac_assets: list[CryptoAsset]) -> None:
    """EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) — regression lock: this
    already worked before evp_digest_and_hmac_examples.c existed, since
    EVP_sha256() is matched independently of its enclosing call."""
    hits = _find_assets(evp_hmac_assets, "SHA-256")
    assert hits, f"EVP_sha256() selector not detected. Got: {[a.name for a in evp_hmac_assets]}"
    assert all(a.quantum_status == QuantumStatus.WEAKENED_BY_GROVER for a in hits)


def test_hmac_init_ex_detected(evp_hmac_assets: list[CryptoAsset]) -> None:
    """HMAC_Init_ex(...) must ALSO produce a distinct HMAC finding, additive
    to the SHA-256 finding its own EVP_sha256() selector argument produces —
    this file had zero HMAC coverage before this fix."""
    hits = _find_assets(evp_hmac_assets, "HMAC")
    assert hits, f"HMAC_Init_ex not detected. Got: {[a.name for a in evp_hmac_assets]}"
    assert all(a.quantum_status == QuantumStatus.WEAKENED_BY_GROVER for a in hits)
    assert all(a.primitive.value == "mac" for a in hits)


def test_evp_hmac_fixture_component_count(evp_hmac_assets: list[CryptoAsset]) -> None:
    assert len(evp_hmac_assets) == 2, f"Expected 2 findings, got: {[a.name for a in evp_hmac_assets]}"


def test_functions_index_has_hmac_entries() -> None:
    rules = _load_rules()
    functions = rules.get("functions", {})
    for name in ("HMAC_Init_ex", "HMAC_Init", "HMAC"):
        assert name in functions, f"functions missing {name}"
        assert functions[name]["primitive"] == "mac"
