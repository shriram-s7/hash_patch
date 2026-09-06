"""tests/unit/test_indirection_resolvers.py

Focused unit tests for argument resolution across indirection patterns:
- test_java_constant_field_indirection
- test_java_map_lookup_indirection
- test_java_parameter_passthrough_indirection
- test_java_ternary_branch_indirection
- test_python_ternary_attribute_ref
- test_python_attribute_ref_as_bare_argument
- test_unresolved_call_site_still_emits_finding (cross-language)
- test_comment_and_dead_string_never_becomes_finding
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.detect.c import COpenSSLDetector
from hash_patch.detect.go import GoCryptoDetector
from hash_patch.detect.java import JavaJcaDetector
from hash_patch.detect.python import PythonCryptoDetector

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA = REPO_ROOT / "testdata"


# ---------------------------------------------------------------------------
# Java Resolution Tests
# ---------------------------------------------------------------------------


def test_java_constant_field_indirection() -> None:
    target = TESTDATA / "java" / "indirection" / "ConstantIndirection.java"
    detector = JavaJcaDetector()
    assets = detector.detect(target)
    assert len(assets) == 1
    assert assets[0].name == "AES"
    assert assets[0].confidence == "HIGH"
    assert "AlgorithmId.STORE_CIPHER" in assets[0].properties.get("resolution_path", "")


def test_java_map_lookup_indirection() -> None:
    target = TESTDATA / "java" / "indirection" / "MapPolicy.java"
    detector = JavaJcaDetector()
    assets = detector.detect(target)
    assert len(assets) == 1
    assert assets[0].name == "RSA"
    assert assets[0].confidence == "HIGH"
    assert "AlgorithmId.LEGACY_SIGN" in assets[0].properties.get("resolution_path", "")


def test_java_parameter_passthrough_indirection() -> None:
    target = TESTDATA / "java" / "indirection" / "ParameterPassthrough.java"
    detector = JavaJcaDetector()
    assets = detector.detect(target)
    assert len(assets) == 1
    assert assets[0].name == "ECDSA"
    assert assets[0].confidence == "HIGH"
    assert "AlgorithmId.EC_SIGN" in assets[0].properties.get("resolution_path", "")


def test_java_ternary_branch_indirection() -> None:
    target = TESTDATA / "java" / "indirection" / "TernaryIndirection.java"
    detector = JavaJcaDetector()
    assets = detector.detect(target)
    names = {a.name for a in assets}
    assert "DH" in names
    assert "ECDH" in names
    conditions = {a.properties.get("branch_condition") for a in assets}
    assert "compat == true" in conditions
    assert "compat == false" in conditions


def test_java_three_hop_parameter_passthrough() -> None:
    """Track A hardening: testdata/java/indirection/ParameterPassthrough.java
    only exercises ONE hop. This fixture (testdata/java/passthrough_depth/
    PassthroughDepth3.java) exercises the full 3-hop depth
    resolve_parameter_passthrough claims to support: Cipher.getInstance(algo)
    in hop3() -> hop2's call site -> hop1's call site -> the literal
    "AES/GCM/NoPadding" in topLevelEntry().
    """
    target = TESTDATA / "java" / "passthrough_depth" / "PassthroughDepth3.java"
    assets = JavaJcaDetector().detect(target)
    assert len(assets) == 1
    assert assets[0].name == "AES"
    assert assets[0].mode == "gcm"
    assert assets[0].confidence == "HIGH"


def test_java_interface_dispatch_resolves_every_implementation() -> None:
    """Track A hardening: Strategy 6 (interface-based dispatch,
    hash_patch/detect/java_resolver.py::resolve_interface_dispatch).
    `provider`'s static type in InterfaceDispatchExample.java is the
    AlgorithmProvider INTERFACE, not a concrete class -- both
    ProdAlgorithmProvider and LegacyAlgorithmProvider implement it in the
    same project, and BOTH must be resolved, never just one arbitrarily.
    """
    target = TESTDATA / "java" / "interface_dispatch" / "InterfaceDispatchExample.java"
    assets = JavaJcaDetector().detect(target)
    names_modes = {(a.name, a.mode) for a in assets}
    assert ("AES", "gcm") in names_modes
    assert ("DES", "ecb") in names_modes
    assert all(a.confidence == "HIGH" for a in assets)


def test_java_interface_dispatch_never_crosses_into_genuine_runtime_dispatch() -> None:
    """The boundary Strategy 6 must NOT cross: RuntimeDynamicDispatch.java's
    concrete implementation is chosen at runtime via Class.forName from an
    environment variable, not statically known from the project's own
    source -- must produce NO finding at all (mirrors test2's real
    RuntimeProvider.java::sign(), which also produces zero JavaJcaDetector
    findings), never a guessed resolution.
    """
    target = TESTDATA / "java" / "interface_dispatch" / "RuntimeDynamicDispatch.java"
    assets = JavaJcaDetector().detect(target)
    assert assets == []


# ---------------------------------------------------------------------------
# Python Resolution Tests
# ---------------------------------------------------------------------------


def test_python_ternary_attribute_ref() -> None:
    target = TESTDATA / "python" / "indirection" / "indirection_examples.py"
    detector = PythonCryptoDetector()
    assets = detector.detect(target)
    names = {a.name for a in assets}
    assert "SHA-1" in names
    assert "SHA-256" in names
    conditions = {a.properties.get("branch_condition") for a in assets if a.properties.get("branch_condition")}
    assert "legacy == true" in conditions
    assert "legacy == false" in conditions


def test_python_attribute_ref_as_bare_argument() -> None:
    target = TESTDATA / "python" / "indirection" / "indirection_examples.py"
    detector = PythonCryptoDetector()
    assets = detector.detect(target)
    names = {a.name for a in assets}
    # config.algo is unknown dynamically -> emits UNRESOLVED with LOW confidence
    assert "UNRESOLVED" in names
    unres = [a for a in assets if a.name == "UNRESOLVED"][0]
    assert unres.confidence == "LOW"
    assert unres.properties.get("api") == "hmac.new"


# ---------------------------------------------------------------------------
# Cross-Language UNRESOLVED Tests
# ---------------------------------------------------------------------------


def test_unresolved_call_site_still_emits_finding(tmp_path: Path) -> None:
    # 1. Java
    java_file = tmp_path / "UnresolvedJava.java"
    java_file.write_text(
        """package com.example;
import javax.crypto.Cipher;
public class UnresolvedJava {
    public void test(String dynamicAlgo) throws Exception {
        Cipher.getInstance(dynamicAlgo);
    }
}
""",
        encoding="utf-8",
    )
    java_assets = JavaJcaDetector().detect(java_file)
    assert any(a.name == "UNRESOLVED" and a.confidence == "LOW" for a in java_assets)

    # 2. Python
    py_file = tmp_path / "unresolved_py.py"
    py_file.write_text(
        """import hashlib
def test(unknown_algo):
    hashlib.new(unknown_algo)
""",
        encoding="utf-8",
    )
    py_assets = PythonCryptoDetector().detect(py_file)
    assert any(a.name == "UNRESOLVED" and a.confidence == "LOW" for a in py_assets)

    # 3. Go
    go_file = tmp_path / "unresolved_go.go"
    go_file.write_text(
        """package crypto
func Test(dyn string) {
    signature.New(dyn)
}
""",
        encoding="utf-8",
    )
    go_assets = GoCryptoDetector().detect(go_file)
    assert any(a.name == "UNRESOLVED" and a.confidence == "LOW" for a in go_assets)

    # 4. C
    c_file = tmp_path / "unresolved_c.c"
    c_file.write_text(
        """#include <openssl/evp.h>
void test(const char *dyn) {
    EVP_get_cipherbyname(dyn);
}
""",
        encoding="utf-8",
    )
    c_assets = COpenSSLDetector().detect(c_file)
    assert any(a.name == "UNRESOLVED" and a.confidence == "LOW" for a in c_assets)


# ---------------------------------------------------------------------------
# Comments and Dead Strings Stay 0
# ---------------------------------------------------------------------------


def test_comment_and_dead_string_never_becomes_finding() -> None:
    # 1. Java comments and dead string
    java_file = TESTDATA / "java" / "indirection" / "DeadStringAndComments.java"
    assert [a for a in JavaJcaDetector().detect(java_file) if a.finding_type == "OPERATION"] == []

    # 2. Python comments and dead string
    py_file = TESTDATA / "python" / "indirection" / "comments_only.py"
    assert [a for a in PythonCryptoDetector().detect(py_file) if a.finding_type == "OPERATION"] == []

    # 3. C comments and dead string
    c_file = TESTDATA / "c" / "indirection" / "comments_and_dead.c"
    assert [a for a in COpenSSLDetector().detect(c_file) if a.finding_type == "OPERATION"] == []
