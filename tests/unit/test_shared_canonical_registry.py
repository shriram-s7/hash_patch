"""tests/unit/test_shared_canonical_registry.py

Tests for the shared canonical algorithm registry across all four language detectors
(Python, Java, Go, C).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hash_patch.detect.c import COpenSSLDetector
from hash_patch.detect.canonical_registry import (
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
