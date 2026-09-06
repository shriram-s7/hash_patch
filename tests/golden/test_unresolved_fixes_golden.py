"""tests/golden/test_unresolved_fixes_golden.py

Golden tests for the three resolved detection bugs:
1. Go chained/fluent method call decomposition (Issue 1)
2. C dual-registered function branch fallback (Issue 2)
3. C EVP_EC_gen OpenSSL 3.0 one-shot API (Issue 3)
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hash_patch.detect.c import COpenSSLDetector
from hash_patch.detect.go import GoCryptoDetector
from hash_patch.model.assets import Primitive, QuantumStatus

REPO_ROOT = Path(__file__).resolve().parents[2]
AGREEMENT_GO = REPO_ROOT / "test2" / "go" / "internal" / "keys" / "agreement.go"
HANDSHAKE_C = REPO_ROOT / "test2" / "c" / "src" / "handshake.c"


def test_go_chained_call_resolves_through_multiple_hops() -> None:
    """Issue 1: Chained method calls in Go (e.g. ecdh.P256().GenerateKey(nil)) must

    decompose through each hop and resolve as a real cryptographic operation (ECDH P-256)
    rather than producing a garbled synthetic target that falls back to UNRESOLVED.
    """
    assert AGREEMENT_GO.is_file(), f"Fixture missing: {AGREEMENT_GO}"
    detector = GoCryptoDetector()
    assets = detector.detect(AGREEMENT_GO)

    # Must contain ECDH P-256
    ecdh_assets = [a for a in assets if a.name == "ECDH" and a.parameter_set == "256"]
    assert len(ecdh_assets) == 1, f"Expected 1 ECDH P-256 asset, got {ecdh_assets}"

    ecdh = ecdh_assets[0]
    assert ecdh.confidence == "confirmed"
    assert ecdh.primitive == Primitive.KEY_AGREE
    assert ecdh.quantum_status == QuantumStatus.BROKEN_BY_SHOR

    # Must cover both line 6 and line 7
    lines = {e.line for e in ecdh.evidence}
    assert 6 in lines and 7 in lines, f"Expected evidence on lines 6 and 7, got {lines}"

    # Must have ZERO UNRESOLVED assets
    unresolved = [a for a in assets if a.name == "UNRESOLVED"]
    assert len(unresolved) == 0, f"Expected 0 UNRESOLVED assets, found: {unresolved}"

    # Verify synthetic multi-hop chained calls in temporary Go file
    with tempfile.NamedTemporaryFile(suffix=".go", mode="w", delete=False, encoding="utf-8") as f:
        f.write(
            "package test\n"
            "import \"crypto/ecdh\"\n"
            "func testHops() {\n"
            "    k1, _ := ecdh.P384().GenerateKey(nil)\n"
            "    k2, _ := ecdh.X25519().GenerateKey(nil)\n"
            "    _ = k1\n"
            "    _ = k2\n"
            "}\n"
        )
        tmp_path = Path(f.name)

    try:
        tmp_assets = detector.detect(tmp_path)
        tmp_names = {(a.name, a.parameter_set) for a in tmp_assets}
        assert ("ECDH", "384") in tmp_names, f"Expected ECDH 384, got {tmp_names}"
        assert ("X25519", "255") in tmp_names, f"Expected X25519 255, got {tmp_names}"
        assert not any(a.name == "UNRESOLVED" for a in tmp_assets)
    finally:
        tmp_path.unlink(missing_ok=True)


def test_c_dual_registered_function_tries_both_branches() -> None:
    """Issue 2: EVP_PKEY_Q_keygen registered in both macro_arg_functions and string_arg_functions

    must try both branches before falling back to UNRESOLVED.
    For EVP_PKEY_Q_keygen(NULL, "DH", 2048), NULL fails macro resolution, but the string_arg
    branch succeeds with "DH" and extracts key size 2048.
    """
    assert HANDSHAKE_C.is_file(), f"Fixture missing: {HANDSHAKE_C}"
    detector = COpenSSLDetector()
    assets = detector.detect(HANDSHAKE_C)

    # Must find DH-2048 from line 6
    dh_assets = [a for a in assets if a.name == "DH" and a.parameter_set == "2048"]
    assert len(dh_assets) == 1, f"Expected 1 DH-2048 asset, got {dh_assets}"

    dh = dh_assets[0]
    assert dh.confidence == "confirmed"
    assert dh.primitive == Primitive.KEY_AGREE
    assert dh.quantum_status == QuantumStatus.BROKEN_BY_SHOR

    lines = {e.line for e in dh.evidence}
    assert 6 in lines, f"Expected line 6 in DH evidence, got {lines}"

    # Line 6 must NOT produce an UNRESOLVED asset
    unresolved_at_6 = [
        a for a in assets if a.name == "UNRESOLVED" and any(e.line == 6 for e in a.evidence)
    ]
    assert len(unresolved_at_6) == 0, f"Line 6 must not produce UNRESOLVED, got {unresolved_at_6}"


def test_c_evp_ec_gen_resolves_correctly() -> None:
    """Issue 3: OpenSSL 3.0 one-shot API EVP_EC_gen("prime256v1") at line 12 must resolve

    to ECDH P-256 rather than producing 0 findings.
    """
    assert HANDSHAKE_C.is_file(), f"Fixture missing: {HANDSHAKE_C}"
    detector = COpenSSLDetector()
    assets = detector.detect(HANDSHAKE_C)

    # Must find ECDH P-256 from line 12
    ecdh_assets = [a for a in assets if a.name == "ECDH" and a.parameter_set == "256"]
    assert len(ecdh_assets) == 1, f"Expected 1 ECDH P-256 asset, got {ecdh_assets}"

    ecdh = ecdh_assets[0]
    assert ecdh.confidence == "confirmed"
    assert ecdh.primitive == Primitive.KEY_AGREE
    assert ecdh.quantum_status == QuantumStatus.BROKEN_BY_SHOR

    lines = {e.line for e in ecdh.evidence}
    assert 12 in lines, f"Expected line 12 in ECDH evidence, got {lines}"

    # Overall handshake.c must have 0 UNRESOLVED assets
    unresolved = [a for a in assets if a.name == "UNRESOLVED"]
    assert len(unresolved) == 0, f"Expected 0 UNRESOLVED assets in handshake.c, got {unresolved}"
