"""tests/unit/test_crypto_reference.py

Regression tests for the OPERATION / CRYPTO_REFERENCE finding-type split.

A CRYPTO_REFERENCE is a string literal that merely looks like an algorithm or
cipher-suite name (a TLS-suite getter, a certificate-family getter, an unused
algorithm-name map/const value) but is never passed as an argument to any
recognized crypto API call anywhere in the file. It must never be reported as
an OPERATION (a real, observed crypto call) — see CLAUDE.md's "Name" section
and hash_patch/detect/c.py::_try_collect_reference for the rationale that
first established this for C; hash_patch/detect/java.py and
hash_patch/detect/go.py mirror the same logic.
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.detect.c import COpenSSLDetector
from hash_patch.detect.go import GoCryptoDetector
from hash_patch.detect.java import JavaJcaDetector
from hash_patch.model.assets import QuantumStatus


def test_tls_suite_getter_is_reference_not_operation_java(tmp_path: Path) -> None:
    java_file = tmp_path / "PartnerTlsProfile.java"
    java_file.write_text(
        """package com.test;

public final class PartnerTlsProfile {
    public String suite() { return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"; }
    public String certificateFamily() { return "RSA"; }
}
""",
        encoding="utf-8",
    )
    assets = JavaJcaDetector().detect(java_file)

    assert len(assets) == 2
    operation_assets = [a for a in assets if a.finding_type == "OPERATION"]
    reference_assets = [a for a in assets if a.finding_type == "CRYPTO_REFERENCE"]
    assert operation_assets == []
    assert {a.name for a in reference_assets} == {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA"}


def test_tls_suite_getter_is_reference_not_operation_c(tmp_path: Path) -> None:
    c_file = tmp_path / "profile.c"
    c_file.write_text(
        """const char *tls_profile(void) {
    return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
}

const char *certificate_key_family(void) {
    return "RSA";
}
""",
        encoding="utf-8",
    )
    assets = COpenSSLDetector().detect(c_file)

    assert len(assets) == 2
    operation_assets = [a for a in assets if a.finding_type == "OPERATION"]
    reference_assets = [a for a in assets if a.finding_type == "CRYPTO_REFERENCE"]
    assert operation_assets == []
    assert {a.name for a in reference_assets} == {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA"}


def test_unused_algorithm_map_values_are_reference_not_operation_go(tmp_path: Path) -> None:
    go_file = tmp_path / "registry.go"
    go_file.write_text(
        """package compat

var Profiles = map[string]string{
    "default": "RSA",
    "legacy":  "DSA",
    "elliptic": "ECDSA",
}

func Resolve(name string) string {
    if x, ok := Profiles[name]; ok {
        return x
    }
    return Profiles["default"]
}
""",
        encoding="utf-8",
    )
    assets = GoCryptoDetector().detect(go_file)

    assert len(assets) == 3
    operation_assets = [a for a in assets if a.finding_type == "OPERATION"]
    reference_assets = [a for a in assets if a.finding_type == "CRYPTO_REFERENCE"]
    assert operation_assets == []
    assert {a.name for a in reference_assets} == {"RSA", "DSA", "ECDSA"}
    # DSA must never appear as an OPERATION-level algorithm from this file —
    # nothing here invokes a DSA operation, it is only an unused map value.
    assert all(a.name != "DSA" or a.finding_type == "CRYPTO_REFERENCE" for a in assets)


def test_sha1withrsa_classified_as_shor_broken_via_rsa_component(tmp_path: Path) -> None:
    java_file = tmp_path / "DeadCrypto.java"
    java_file.write_text(
        """package com.test;
import java.security.Signature;

public class DeadCrypto {
    public void verify() throws Exception {
        Signature sig = Signature.getInstance("SHA1withRSA");
    }
}
""",
        encoding="utf-8",
    )
    assets = JavaJcaDetector().detect(java_file)

    assert len(assets) == 1
    asset = assets[0]
    # SHA1withRSA is fundamentally an RSA signature operation with SHA-1 as
    # its digest — it must be classified quantum-status by its RSA
    # component (broken by Shor), never solely by its hash component (which
    # would understate the risk as merely broken-classically).
    assert asset.name == "RSA"
    assert asset.finding_type == "OPERATION"
    assert asset.quantum_status == QuantumStatus.BROKEN_BY_SHOR
