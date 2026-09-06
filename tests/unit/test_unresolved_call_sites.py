from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hash_patch.detect.c import COpenSSLDetector
from hash_patch.detect.go import GoCryptoDetector
from hash_patch.detect.java import JavaJcaDetector
from hash_patch.detect.python import PythonCryptoDetector
from hash_patch.emit import render_cbom_json, to_cyclonedx, validate_cbom
from hash_patch.model.assets import Primitive, QuantumStatus
from hash_patch.model.findings import ScanResult


def test_java_unresolved_call_site_emits_low_confidence(tmp_path: Path) -> None:
    java_file = tmp_path / "UnresolvedCrypto.java"
    java_file.write_text(
        """package com.test;
import javax.crypto.Cipher;

public class UnresolvedCrypto {
    public void doCrypto(String algo) throws Exception {
        Cipher c = Cipher.getInstance(algo);
    }
}
""",
        encoding="utf-8",
    )
    detector = JavaJcaDetector()
    assets = detector.detect(java_file)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.name == "UNRESOLVED"
    assert asset.confidence == "LOW"
    assert asset.primitive == Primitive.UNKNOWN
    assert asset.quantum_status == QuantumStatus.UNKNOWN
    assert asset.properties.get("api") == "Cipher.getInstance"
    assert asset.properties.get("resolution_path") == "null"
    assert len(asset.evidence) == 1
    assert asset.evidence[0].line == 6

    # Verify that emitting CBOM succeeds and validates against schema
    scan_result = ScanResult(
        target=str(java_file),
        assets=assets,
        scan_started_at=datetime.now(UTC),
        tool_version="0.1.0",
    )
    doc = to_cyclonedx(scan_result)
    errs = validate_cbom(doc)
    assert errs == []
    json_text = render_cbom_json(doc)
    assert "UNRESOLVED" in json_text
    assert '"value": "LOW"' in json_text


def test_python_unresolved_call_site_emits_low_confidence(tmp_path: Path) -> None:
    py_file = tmp_path / "unresolved_crypto.py"
    py_file.write_text(
        """import hashlib
import hmac

def hash_data(algo_name, data):
    return hashlib.new(algo_name, data)

def mac_data(key, msg, digest):
    return hmac.new(key, msg, digest)
""",
        encoding="utf-8",
    )
    detector = PythonCryptoDetector()
    assets = detector.detect(py_file)
    # Both hashlib.new(variable) and hmac.new(..., variable) should be detected as UNRESOLVED
    unresolved = [a for a in assets if a.name == "UNRESOLVED"]
    assert len(unresolved) >= 1
    for a in unresolved:
        assert a.confidence == "LOW"
        assert a.primitive == Primitive.UNKNOWN
        assert a.properties.get("resolution_path") == "null"

    scan_result = ScanResult(
        target=str(py_file),
        assets=assets,
        scan_started_at=datetime.now(UTC),
        tool_version="0.1.0",
    )
    doc = to_cyclonedx(scan_result)
    errs = validate_cbom(doc)
    assert errs == []


def test_go_unresolved_call_site_emits_low_confidence(tmp_path: Path) -> None:
    go_file = tmp_path / "unresolved.go"
    go_file.write_text(
        """package main
import "crypto/rsa"

func test() {
    rsa.SomeUnknownFunction()
}
""",
        encoding="utf-8",
    )
    detector = GoCryptoDetector()
    assets = detector.detect(go_file)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.name == "UNRESOLVED"
    assert asset.confidence == "LOW"
    assert asset.properties.get("api") == "rsa.SomeUnknownFunction"

    scan_result = ScanResult(
        target=str(go_file),
        assets=assets,
        scan_started_at=datetime.now(UTC),
        tool_version="0.1.0",
    )
    doc = to_cyclonedx(scan_result)
    errs = validate_cbom(doc)
    assert errs == []


def test_c_unresolved_call_site_emits_low_confidence(tmp_path: Path) -> None:
    c_file = tmp_path / "unresolved.c"
    c_file.write_text(
        """#include <openssl/evp.h>

void do_crypto(const char *name) {
    const EVP_CIPHER *c = EVP_get_cipherbyname(name);
}
""",
        encoding="utf-8",
    )
    detector = COpenSSLDetector()
    assets = detector.detect(c_file)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.name == "UNRESOLVED"
    assert asset.confidence == "LOW"
    assert asset.properties.get("api") == "EVP_get_cipherbyname"

    scan_result = ScanResult(
        target=str(c_file),
        assets=assets,
        scan_started_at=datetime.now(UTC),
        tool_version="0.1.0",
    )
    doc = to_cyclonedx(scan_result)
    errs = validate_cbom(doc)
    assert errs == []
