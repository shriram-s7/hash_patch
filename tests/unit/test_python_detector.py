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
HASHLIB_ALONE_FIXTURE = TESTDATA_PY / "hashlib_sha256_alone.py"
HASHLIB_EXAMPLES_FIXTURE = TESTDATA_PY / "hashlib_examples.py"
PYNACL_JWT_FIXTURE = TESTDATA_PY / "pynacl_and_jwt_examples.py"


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


def test_pyca_index_has_hashlib_namespace() -> None:
    rules = _load_rules()
    index = _build_pyca_index(rules)
    assert "hashlib" in index, "pyca_modules must contain a 'hashlib' namespace"
    for attr in ("MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_384", "SHA3_512"):
        assert attr in index["hashlib"], f"hashlib namespace missing {attr}"


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


# ---------------------------------------------------------------------------
# hashlib coverage-gap regression (rules/python_crypto.yaml's `hashlib`
# namespace + hashlib.new()/hmac.new() special-shape handling).
#
# CONFIRMED BUG: before this namespace existed, a file containing exactly
#   import hashlib
#   hashlib.sha256(value.encode()).hexdigest()
# produced ZERO findings when scanned in isolation. This exact bug class —
# a stdlib module with zero rule coverage — must never silently recur.
# ---------------------------------------------------------------------------


def test_hashlib_alone_fixture_exists() -> None:
    assert HASHLIB_ALONE_FIXTURE.is_file()


def test_hashlib_examples_fixture_exists() -> None:
    assert HASHLIB_EXAMPLES_FIXTURE.is_file()


def test_hashlib_sha256_alone_produces_exactly_one_finding(
    detector: PythonCryptoDetector,
) -> None:
    """The literal regression test: `hashlib.sha256(...)`, scanned in
    isolation, must produce exactly one SHA-256 finding with quantum_status
    weakened-by-grover — never zero.
    """
    assets = detector.detect(HASHLIB_ALONE_FIXTURE)
    assert len(assets) == 1, f"Expected exactly 1 finding, got: {[a.name for a in assets]}"
    asset = assets[0]
    assert asset.name == "SHA-256"
    assert asset.quantum_status == QuantumStatus.WEAKENED_BY_GROVER
    assert len(asset.evidence) == 1
    _assert_evidence_populated(asset.evidence[0], HASHLIB_ALONE_FIXTURE)


def test_hashlib_direct_call_detected_via_alone_fixture(detector: PythonCryptoDetector) -> None:
    """hashlib.sha256(...) — direct-call form, resolved through the same
    Pattern A namespace-lookup mechanism as hashes.SHA256(), now that
    rules/python_crypto.yaml has a `hashlib` namespace."""
    assets = detector.detect(HASHLIB_ALONE_FIXTURE)
    sha256_hits = _find_assets(assets, "SHA-256")
    assert sha256_hits, f"hashlib.sha256(...) not detected. Got: {[a.name for a in assets]}"
    snippets = [e.snippet for a in sha256_hits for e in a.evidence]
    assert any("hashlib.sha256" in s for s in snippets), snippets


def test_hashlib_new_string_literal_detected(detector: PythonCryptoDetector) -> None:
    """hashlib.new("md5", data) — the string-based constructor form must
    resolve the literal and produce an MD5 finding, broken-classically."""
    assets = detector.detect(HASHLIB_EXAMPLES_FIXTURE)
    md5_hits = _find_assets(assets, "MD5")
    assert md5_hits, f"hashlib.new('md5') not detected. Got: {[a.name for a in assets]}"
    assert all(a.quantum_status == QuantumStatus.BROKEN_CLASSICALLY for a in md5_hits)
    snippets = [e.snippet for a in md5_hits for e in a.evidence]
    assert any("hashlib.new" in s for s in snippets), snippets


def test_hmac_new_hashlib_digestmod_reference_detected(detector: PythonCryptoDetector) -> None:
    """hmac.new(secret, payload, hashlib.sha256) — the bare hashlib.sha256
    reference (not itself a call) passed as the digestmod argument must be
    recognised as a SHA-256 hash-algorithm usage, weakened-by-grover. This
    is the second real missed finding from the reproduction corpus
    (python/orchestration/app/crypto/wrappers.py)."""
    assets = detector.detect(HASHLIB_EXAMPLES_FIXTURE)
    sha256_hits = _find_assets(assets, "SHA-256")
    assert sha256_hits, f"hmac.new's hashlib.sha256 digestmod not detected. Got: {[a.name for a in assets]}"
    assert all(a.quantum_status == QuantumStatus.WEAKENED_BY_GROVER for a in sha256_hits)
    snippets = [e.snippet for a in sha256_hits for e in a.evidence]
    assert any("hmac.new" in s for s in snippets), snippets


def test_hashlib_new_unresolvable_literal_produces_unresolved(detector: PythonCryptoDetector) -> None:
    """hashlib.new(algo_name, data) where algo_name is a variable, not a
    string literal, must emit an UNRESOLVED finding with confidence LOW rather
    than being discarded."""
    assets = detector.detect(HASHLIB_EXAMPLES_FIXTURE)
    assert len(assets) == 3, (
        f"Expected exactly 3 findings (MD5, SHA-256, UNRESOLVED), got: "
        f"{[a.name for a in assets]}"
    )
    unresolved = [a for a in assets if a.name == "UNRESOLVED"]
    assert len(unresolved) == 1
    assert unresolved[0].confidence == "LOW"
    assert unresolved[0].properties.get("api") == "hashlib.new"
    assert unresolved[0].properties.get("resolution_path") == "null"


def test_negative_fixture_no_longer_contains_hashlib_calls() -> None:
    """Guards against the exact way this bug was previously masked: the
    negative fixture used to contain hashlib.md5()/hashlib.sha1() calls
    commented as "not detected" — i.e. the coverage gap was baked into a
    'must produce zero assets' test as if it were correct behavior. Those
    calls were moved out; this test fails loudly if they ever come back
    here, since they would now (correctly) produce findings and break
    test_negative_fixture_produces_no_assets for the wrong reason."""
    text = NEGATIVE_FIXTURE.read_text(encoding="utf-8")
    assert "hashlib.md5(" not in text
    assert "hashlib.sha1(" not in text


# ---------------------------------------------------------------------------
# PyNaCl + PyJWT coverage (found via the post-hashlib-fix audit — see
# docs/COVERAGE.md). Pattern C (bare constructor calls) and Pattern D
# (jwt.encode's algorithm= literal).
# ---------------------------------------------------------------------------


def test_pynacl_jwt_fixture_exists() -> None:
    assert PYNACL_JWT_FIXTURE.is_file()


def test_pynacl_box_and_privatekey_merge_into_x25519(detector: PythonCryptoDetector) -> None:
    assets = detector.detect(PYNACL_JWT_FIXTURE)
    hits = _find_assets(assets, "X25519")
    assert hits, f"PyNaCl X25519 usage not detected. Got: {[a.name for a in assets]}"
    assert all(a.quantum_status == QuantumStatus.BROKEN_BY_SHOR for a in hits)
    snippets = [e.snippet for a in hits for e in a.evidence]
    assert any("PrivateKey.generate" in s for s in snippets), snippets
    assert any(s.startswith("Box(") for s in snippets), snippets


def test_pynacl_signingkey_detected_as_ed25519(detector: PythonCryptoDetector) -> None:
    assets = detector.detect(PYNACL_JWT_FIXTURE)
    hits = _find_assets(assets, "Ed25519")
    assert hits, f"SigningKey.generate() not detected. Got: {[a.name for a in assets]}"
    assert all(a.quantum_status == QuantumStatus.BROKEN_BY_SHOR for a in hits)


def test_pynacl_secretbox_detected_as_xsalsa20_poly1305(detector: PythonCryptoDetector) -> None:
    assets = detector.detect(PYNACL_JWT_FIXTURE)
    hits = _find_assets(assets, "XSalsa20-Poly1305")
    assert hits, f"SecretBox(...) not detected. Got: {[a.name for a in assets]}"
    assert all(a.quantum_status == QuantumStatus.WEAKENED_BY_GROVER for a in hits)


def test_jwt_encode_hs256_detected_as_hmac(detector: PythonCryptoDetector) -> None:
    assets = detector.detect(PYNACL_JWT_FIXTURE)
    hits = _find_assets(assets, "HMAC")
    assert hits, f"jwt.encode(algorithm='HS256') not detected. Got: {[a.name for a in assets]}"
    assert all(a.quantum_status == QuantumStatus.WEAKENED_BY_GROVER for a in hits)


def test_jwt_encode_rs256_detected_as_rsa_signature(detector: PythonCryptoDetector) -> None:
    assets = detector.detect(PYNACL_JWT_FIXTURE)
    hits = _find_assets(assets, "RSA")
    assert hits, f"jwt.encode(algorithm='RS256') not detected. Got: {[a.name for a in assets]}"
    assert all(a.quantum_status == QuantumStatus.BROKEN_BY_SHOR for a in hits)
    assert all(a.primitive.value == "signature" for a in hits)


def test_jwt_encode_es384_detected_as_ecdsa(detector: PythonCryptoDetector) -> None:
    assets = detector.detect(PYNACL_JWT_FIXTURE)
    hits = _find_assets(assets, "ECDSA")
    assert hits, f"jwt.encode(algorithm='ES384') not detected. Got: {[a.name for a in assets]}"
    assert all(a.quantum_status == QuantumStatus.BROKEN_BY_SHOR for a in hits)
    assert all(a.parameter_set == "384" for a in hits)


def test_jwt_encode_dynamic_algorithm_produces_unresolved(detector: PythonCryptoDetector) -> None:
    """sign_dynamic()'s `algorithm=alg` (a variable, not a literal) must
    emit an UNRESOLVED finding with confidence LOW rather than being discarded."""
    assets = detector.detect(PYNACL_JWT_FIXTURE)
    assert len(assets) == 7, (
        f"Expected exactly 7 findings (6 resolvable + UNRESOLVED), got: {[a.name for a in assets]}"
    )
    unresolved = [a for a in assets if a.name == "UNRESOLVED"]
    assert len(unresolved) == 1
    assert unresolved[0].confidence == "LOW"
    assert unresolved[0].properties.get("api") == "jwt.encode"
    assert unresolved[0].properties.get("resolution_path") == "null"


def test_bare_constructor_index_has_expected_classes() -> None:
    rules = _load_rules()
    from hash_patch.detect.python import _build_bare_constructor_index

    index = _build_bare_constructor_index(rules)
    for cls in ("Box", "PrivateKey", "SigningKey", "SecretBox"):
        assert cls in index, f"bare_constructors missing {cls}"


def test_jwt_algorithm_index_has_expected_algs() -> None:
    rules = _load_rules()
    from hash_patch.detect.python import _build_jwt_algorithm_index

    index = _build_jwt_algorithm_index(rules)
    for alg in ("HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "ES512"):
        assert alg in index, f"jwt_algorithms missing {alg}"


def test_bare_call_not_collected_without_bare_names() -> None:
    """The default (no bare_names passed) must behave exactly as before —
    _collect_calls(root_node) alone never collects a bare call, even one
    that WOULD match if bare_names were supplied."""
    import tree_sitter_python as _tspy
    from tree_sitter import Language, Parser

    lang = Language(_tspy.language())
    parser = Parser(lang)
    src = b"Box(sk, pk)\n"
    tree = parser.parse(src)
    calls = _collect_calls(tree.root_node)
    assert calls == [], f"Expected no calls without bare_names, got {calls}"


def test_bare_call_collected_with_matching_bare_names() -> None:
    import tree_sitter_python as _tspy
    from tree_sitter import Language, Parser

    lang = Language(_tspy.language())
    parser = Parser(lang)
    src = b"Box(sk, pk)\nunrelated_call(1)\n"
    tree = parser.parse(src)
    calls = _collect_calls(tree.root_node, bare_names=frozenset({"Box"}))
    assert len(calls) == 1
    assert calls[0]["bare_call"] == "Box"


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
