"""tests/unit/test_shared_canonical_registry.py

Tests for the shared canonical algorithm registry across all four language detectors
(Python, Java, Go, C).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hash_patch.detect.c import COpenSSLDetector
from hash_patch.detect.canonical_registry import (
    lookup_canonical_algorithm,
    register_canonical_algorithm,
    reset_canonical_registry,
)
from hash_patch.detect.go import GoCryptoDetector
from hash_patch.detect.java import JavaJcaDetector
from hash_patch.detect.python import PythonCryptoDetector


def test_reference_detection_uses_shared_canonical_registry_all_languages(
    tmp_path: Path,
) -> None:
    """Adding a new algorithm name to the shared canonical registry makes it
    detectable as a CRYPTO_REFERENCE in all four language detectors (C, Go, Java, Python)
    without requiring edits to language-specific rule files.
    """
    synthetic_algo = "QUANTUM-XYZ-CUSTOM-999"
    synthetic_rule = {
        "canonical": synthetic_algo,
        "primitive": "signature",
        "parameter_set": "512",
        "mode": None,
        "quantum_status": "quantum-safe",
        "oid": "1.2.3.4.5.6.7.8",
    }

    register_canonical_algorithm(synthetic_algo, synthetic_rule)
    try:
        # 1. Python source
        py_file = tmp_path / "custom.py"
        py_file.write_text(
            f'''ALGO = "{synthetic_algo}"
def get_algo():
    return "{synthetic_algo}"
''',
            encoding="utf-8",
        )
        py_assets = PythonCryptoDetector().detect(py_file)
        py_refs = [a for a in py_assets if a.finding_type == "CRYPTO_REFERENCE" and a.name == synthetic_algo]
        assert len(py_refs) == 1, f"Expected 1 Python reference for {synthetic_algo}, got {py_refs}"
        assert py_refs[0].quantum_status.value == "quantum-safe"

        # 2. Java source
        java_file = tmp_path / "Custom.java"
        java_file.write_text(
            f'''package com.test;
public class Custom {{
    private static final String PROTOCOL = "{synthetic_algo}";
    public String getProtocol() {{
        return "{synthetic_algo}";
    }}
}}
''',
            encoding="utf-8",
        )
        java_assets = JavaJcaDetector().detect(java_file)
        java_refs = [a for a in java_assets if a.finding_type == "CRYPTO_REFERENCE" and a.name == synthetic_algo]
        assert len(java_refs) == 1, f"Expected 1 Java reference for {synthetic_algo}, got {java_refs}"

        # 3. Go source
        go_file = tmp_path / "custom.go"
        go_file.write_text(
            f'''package main

var Config = map[string]string{{
    "target": "{synthetic_algo}",
}}

func GetTarget() string {{
    return "{synthetic_algo}"
}}
''',
            encoding="utf-8",
        )
        go_assets = GoCryptoDetector().detect(go_file)
        go_refs = [a for a in go_assets if a.finding_type == "CRYPTO_REFERENCE" and a.name == synthetic_algo]
        assert len(go_refs) == 1, f"Expected 1 Go reference for {synthetic_algo}, got {go_refs}"

        # 4. C source
        c_file = tmp_path / "custom.c"
        c_file.write_text(
            f'''const char *custom_algorithm(void) {{
    return "{synthetic_algo}";
}}
''',
            encoding="utf-8",
        )
        c_assets = COpenSSLDetector().detect(c_file)
        c_refs = [a for a in c_assets if a.finding_type == "CRYPTO_REFERENCE" and a.name == synthetic_algo]
        assert len(c_refs) == 1, f"Expected 1 C reference for {synthetic_algo}, got {c_refs}"

    finally:
        reset_canonical_registry()


def test_test2_specific_references_detected() -> None:
    """Verify specific test2 confirmed cases are detected across languages."""
    repo_root = Path(__file__).resolve().parents[2]
    test2_dir = repo_root / "test2"
    if not test2_dir.is_dir():
        pytest.skip("test2 directory not found")

    # Python: RC4 in crypto_policy.py
    py_file = test2_dir / "python" / "freight_api" / "crypto_policy.py"
    py_assets = PythonCryptoDetector().detect(py_file)
    rc4_refs = [
        a for a in py_assets
        if a.finding_type == "CRYPTO_REFERENCE" and a.name == "RC4"
    ]
    assert len(rc4_refs) == 1, f"Expected RC4 reference in {py_file}"
    assert any(e.line == 9 for e in rc4_refs[0].evidence)

    # Java: SHA256withECDSA in PaymentSigner.java
    java_file = test2_dir / "java" / "src" / "main" / "java" / "com" / "harborline" / "payments" / "PaymentSigner.java"
    java_assets = JavaJcaDetector().detect(java_file)
    ecdsa_refs = [
        a for a in java_assets
        if a.finding_type == "CRYPTO_REFERENCE" and a.name == "ECDSA"
    ]
    assert len(ecdsa_refs) == 1, f"Expected ECDSA reference in {java_file}"
    lines = {e.line for e in ecdsa_refs[0].evidence}
    assert 8 in lines or 41 in lines

    # Go: RC4-SHA in transport.go
    go_file = test2_dir / "go" / "internal" / "transport" / "transport.go"
    go_assets = GoCryptoDetector().detect(go_file)
    rc4_sha_refs = [
        a for a in go_assets
        if a.finding_type == "CRYPTO_REFERENCE" and a.name == "RC4-SHA"
    ]
    assert len(rc4_sha_refs) == 1, f"Expected RC4-SHA reference in {go_file}"
    assert any(e.line == 18 for e in rc4_sha_refs[0].evidence)


def test_txt_fixture_remains_unparsed() -> None:
    """c/tests/fixtures/algorithm_names.txt produces 0 findings because .txt is not parsed."""
    repo_root = Path(__file__).resolve().parents[2]
    txt_file = repo_root / "test2" / "c" / "tests" / "fixtures" / "algorithm_names.txt"
    if not txt_file.is_file():
        pytest.skip("algorithm_names.txt not found")

    assert not COpenSSLDetector().supports(txt_file)
    assert not PythonCryptoDetector().supports(txt_file)
    assert not GoCryptoDetector().supports(txt_file)
    assert not JavaJcaDetector().supports(txt_file)


def test_compound_form_tokenization_lookup() -> None:
    """Verify compound-form tokenization decomposes algorithm names into base
    algorithm + key-size parameter_set and/or mode, while preserving matched_text.
    """
    # 1. AES compounds
    aes_gcm = lookup_canonical_algorithm("AES-256-GCM")
    assert aes_gcm is not None
    assert aes_gcm["canonical"] == "AES"
    assert aes_gcm["parameter_set"] == "256"
    assert aes_gcm["mode"] == "GCM"
    assert aes_gcm["matched_text"] == "AES-256-GCM"
    assert aes_gcm["primitive"] == "block-cipher"

    aes_cbc = lookup_canonical_algorithm("AES-128-CBC")
    assert aes_cbc is not None
    assert aes_cbc["canonical"] == "AES"
    assert aes_cbc["parameter_set"] == "128"
    assert aes_cbc["mode"] == "CBC"
    assert aes_cbc["matched_text"] == "AES-128-CBC"

    # Underscore syntax
    aes_under = lookup_canonical_algorithm("AES_256_GCM")
    assert aes_under is not None
    assert aes_under["canonical"] == "AES"
    assert aes_under["parameter_set"] == "256"
    assert aes_under["mode"] == "GCM"
    assert aes_under["matched_text"] == "AES_256_GCM"

    # 2. RSA key-size compounds
    rsa_2048 = lookup_canonical_algorithm("RSA-2048")
    assert rsa_2048 is not None
    assert rsa_2048["canonical"] == "RSA"
    assert rsa_2048["parameter_set"] == "2048"
    assert rsa_2048["matched_text"] == "RSA-2048"
    assert rsa_2048["quantum_status"] == "broken-by-shor"

    rsa_4096 = lookup_canonical_algorithm("RSA-4096")
    assert rsa_4096 is not None
    assert rsa_4096["canonical"] == "RSA"
    assert rsa_4096["parameter_set"] == "4096"
    assert rsa_4096["matched_text"] == "RSA-4096"

    # 3. Multi-token base algorithm
    sha_raw = lookup_canonical_algorithm("SHA-256-RAW")
    assert sha_raw is not None
    assert sha_raw["canonical"] == "SHA-256"
    assert sha_raw["matched_text"] == "SHA-256-RAW"

    # 4. Deliberate negatives: non-crypto or collided prefixes with non-qualifier suffixes
    assert lookup_canonical_algorithm("USER-256-LOGIN") is None
    assert lookup_canonical_algorithm("AES-256-LOGIN") is None
    assert lookup_canonical_algorithm("BOX-SHADOW") is None
    assert lookup_canonical_algorithm("IDEA-PROJECT") is None
    assert lookup_canonical_algorithm("SEED-DATA") is None
    assert lookup_canonical_algorithm("CAST-VOTE") is None
    assert lookup_canonical_algorithm("CUSTOM-ALGO-NONEXISTENT") is None
    assert lookup_canonical_algorithm("This application supports RSA, ECDSA and SHA-512.") is None


def test_compound_form_reference_detection_all_languages(tmp_path: Path) -> None:
    """Verify compound algorithm references in code are detected as CRYPTO_REFERENCE
    with correct base algorithm, parameter_set, mode, and matched_text across languages.
    """
    # 1. Python
    py_file = tmp_path / "app_config.py"
    py_file.write_text(
        'algorithm_name = "AES-256-GCM"\n'
        'rsa_key_spec = "RSA-2048"\n'
        'rsa_high_spec = "RSA-4096"\n',
        encoding="utf-8",
    )
    py_assets = PythonCryptoDetector().detect(py_file)
    py_refs = [a for a in py_assets if a.finding_type == "CRYPTO_REFERENCE"]
    assert len(py_refs) == 3

    aes_ref = next(a for a in py_refs if a.name == "AES")
    assert aes_ref.parameter_set == "256"
    assert aes_ref.mode == "GCM"
    assert aes_ref.properties.get("matched_text") == "AES-256-GCM"

    rsa_refs = [a for a in py_refs if a.name == "RSA"]
    assert len(rsa_refs) == 2
    rsa_params = {a.parameter_set for a in rsa_refs}
    assert rsa_params == {"2048", "4096"}

    # 2. Java
    java_file = tmp_path / "CryptoConstants.java"
    java_file.write_text(
        "package com.example;\n"
        "public class CryptoConstants {\n"
        '    public static final String CIPHER = "AES-256-GCM";\n'
        '    public static final String KEY_ALGO = "RSA-2048";\n'
        "}\n",
        encoding="utf-8",
    )
    java_assets = JavaJcaDetector().detect(java_file)
    java_refs = [a for a in java_assets if a.finding_type == "CRYPTO_REFERENCE"]
    assert len(java_refs) == 2
    j_aes = next(a for a in java_refs if a.name == "AES")
    assert j_aes.parameter_set == "256"
    assert j_aes.mode == "GCM"
    assert j_aes.properties.get("matched_text") == "AES-256-GCM"

    # 3. Go
    go_file = tmp_path / "cipher_spec.go"
    go_file.write_text(
        "package main\n"
        "var DefaultCipher = map[string]string{\n"
        '    "algo": "AES-256-GCM",\n'
        '    "asym": "RSA-2048",\n'
        "}\n",
        encoding="utf-8",
    )
    go_assets = GoCryptoDetector().detect(go_file)
    go_refs = [a for a in go_assets if a.finding_type == "CRYPTO_REFERENCE"]
    assert len(go_refs) == 2
    g_aes = next(a for a in go_refs if a.name == "AES")
    assert g_aes.parameter_set == "256"
    assert g_aes.mode == "GCM"

    # 4. C
    c_file = tmp_path / "spec.c"
    c_file.write_text(
        'const char *cipher_name(void) { return "AES-256-GCM"; }\n'
        'const char *key_name(void) { return "RSA-2048"; }\n',
        encoding="utf-8",
    )
    c_assets = COpenSSLDetector().detect(c_file)
    c_refs = [a for a in c_assets if a.finding_type == "CRYPTO_REFERENCE"]
    assert len(c_refs) == 2
    c_aes = next(a for a in c_refs if a.name == "AES")
    assert c_aes.parameter_set == "256"
    assert c_aes.mode == "GCM"


def test_compound_form_deliberate_negatives_produce_zero_findings(tmp_path: Path) -> None:
    """Deliberate negative cases: non-crypto identifiers with dashes, line comments,
    and sentences must produce 0 findings across AST gating and registry lookup.
    """
    test_file = tmp_path / "negative_test.py"
    test_file.write_text(
        '# Line comment mentioning MD5, SHA-1, AES-256-GCM, RSA-2048\n'
        '"""Bare docstring mentioning AES-256-GCM and RSA-4096"""\n'
        'username = "USER-256-LOGIN"\n'
        'invalid_suffix = "AES-256-LOGIN"\n'
        'css_box = "BOX-SHADOW"\n'
        'sentence_desc = "This application supports RSA-2048 and AES-256-GCM."\n',
        encoding="utf-8",
    )
    assets = PythonCryptoDetector().detect(test_file)
    assert len(assets) == 0, f"Expected 0 findings for negative cases, got: {assets}"

