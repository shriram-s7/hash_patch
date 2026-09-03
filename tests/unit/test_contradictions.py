"""tests/unit/test_contradictions.py — Comprehensive unit tests for Pillar 4 (Contradictions)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from hash_patch.analyze.contradictions import run_contradiction_analysis
from hash_patch.cli import app, run_scan
from hash_patch.detect.config.source_tls_intent import detect_source_tls_intent
from hash_patch.detect.config.tls_config import detect_tls_config_file
from hash_patch.emit import to_cyclonedx, validate_cbom
from hash_patch.model.config_finding import TlsConfigFinding
from hash_patch.model.evidence import Evidence

runner = CliRunner()
_TESTDATA_DIR = Path(__file__).resolve().parents[2] / "testdata" / "contradictions"


def test_nginx_parser_ssl_protocols(tmp_path: Path) -> None:
    nginx_file = tmp_path / "nginx.conf"
    nginx_file.write_text("ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n", encoding="utf-8")

    findings = detect_tls_config_file(nginx_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "protocol_version"
    assert f.config_format == "nginx"
    assert f.allows_legacy is True
    assert any("TLSv1.0" in r or "TLSv1" in r for r in f.legacy_reasons)
    assert any("TLSv1.1" in r for r in f.legacy_reasons)
    assert f.severity == "medium"
    assert len(f.evidence) == 1
    assert f.evidence[0].line == 1


def test_nginx_parser_strict_protocols(tmp_path: Path) -> None:
    nginx_file = tmp_path / "nginx.conf"
    nginx_file.write_text("ssl_protocols TLSv1.2 TLSv1.3;\n", encoding="utf-8")

    findings = detect_tls_config_file(nginx_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.allows_legacy is False
    assert f.legacy_reasons == []
    assert f.severity == "none"


def test_nginx_parser_ciphers_high_severity(tmp_path: Path) -> None:
    nginx_file = tmp_path / "nginx.conf"
    nginx_file.write_text("ssl_ciphers RC4-SHA:AES128-SHA;\n", encoding="utf-8")

    findings = detect_tls_config_file(nginx_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "cipher_suite"
    assert f.allows_legacy is True
    assert any("RC4" in r for r in f.legacy_reasons)
    assert f.severity == "high"


def test_apache_parser(tmp_path: Path) -> None:
    httpd_file = tmp_path / "httpd.conf"
    httpd_file.write_text("SSLProtocol all -SSLv3\n", encoding="utf-8")

    findings = detect_tls_config_file(httpd_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "protocol_version"
    assert f.config_format == "apache"
    assert f.allows_legacy is True
    # Still permits TLS 1.0 and 1.1
    assert any("TLSv1.0" in r for r in f.legacy_reasons)


def test_java_properties_parser(tmp_path: Path) -> None:
    prop_file = tmp_path / "tls.properties"
    prop_file.write_text("tls.protocols=TLSv1.0,TLSv1.2\n", encoding="utf-8")

    findings = detect_tls_config_file(prop_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "protocol_version"
    assert f.config_format == "java-properties"
    assert f.allows_legacy is True


def test_unrecognized_config_format_is_skipped(tmp_path: Path) -> None:
    other_file = tmp_path / "other.txt"
    other_file.write_text("some random content\n", encoding="utf-8")

    findings = detect_tls_config_file(other_file)
    assert findings == []


def test_python_source_tls_intent(tmp_path: Path) -> None:
    py_file = tmp_path / "app.py"
    py_file.write_text(
        "import ssl\nctx = ssl.create_default_context()\nctx.minimum_version = ssl.TLSVersion.TLSv1_3\n",
        encoding="utf-8",
    )

    findings = detect_source_tls_intent(py_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.value == "TLSv1.3"
    assert f.allows_legacy is False
    assert f.config_format == "source-code-intent"
    assert f.evidence[0].line == 3


def test_java_source_tls_intent(tmp_path: Path) -> None:
    java_file = tmp_path / "App.java"
    java_file.write_text(
        "import javax.net.ssl.SSLContext;\nclass App { void init() throws Exception { SSLContext ctx = SSLContext.getInstance(\"TLSv1.3\"); } }\n",
        encoding="utf-8",
    )

    findings = detect_source_tls_intent(java_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.value == "TLSv1.3"
    assert f.allows_legacy is False
    assert f.config_format == "source-code-intent"


def test_no_contradiction_when_config_alone(tmp_path: Path) -> None:
    """Config with legacy TLS, but NO source code intent in target -> no contradiction."""
    cfg_ev = Evidence(
        locator=str(tmp_path / "nginx.conf"),
        line=1,
        column=1,
        byte_offset=0,
        snippet="ssl_protocols TLSv1;",
        source_type="config",
        detector_id="test",
        detector_version="0.1.0",
    )
    cfg = TlsConfigFinding(
        kind="protocol_version",
        value="TLSv1",
        allows_legacy=True,
        legacy_reasons=["TLSv1.0"],
        severity="medium",
        evidence=[cfg_ev],
        source_file=str(tmp_path / "nginx.conf"),
        config_format="nginx",
    )

    contradictions = run_contradiction_analysis([cfg], target_root=tmp_path)
    assert contradictions == []


def test_no_contradiction_when_source_intent_alone(tmp_path: Path) -> None:
    """Source intent with strict TLS, but NO deployed config in target -> no contradiction."""
    src_ev = Evidence(
        locator=str(tmp_path / "app.py"),
        line=1,
        column=1,
        byte_offset=0,
        snippet="ssl.TLSVersion.TLSv1_3",
        source_type="source",
        detector_id="test",
        detector_version="0.1.0",
    )
    src = TlsConfigFinding(
        kind="protocol_version",
        value="TLSv1.3",
        allows_legacy=False,
        evidence=[src_ev],
        source_file=str(tmp_path / "app.py"),
        config_format="source-code-intent",
    )

    contradictions = run_contradiction_analysis([src], target_root=tmp_path)
    assert contradictions == []


def test_no_contradiction_when_both_strict(tmp_path: Path) -> None:
    """Both source intent and deployed config enforce strict TLS -> no contradiction."""
    src_ev = Evidence(
        locator=str(tmp_path / "app.py"),
        line=1,
        column=1,
        byte_offset=0,
        snippet="ssl.TLSVersion.TLSv1_3",
        source_type="source",
        detector_id="test",
        detector_version="0.1.0",
    )
    src = TlsConfigFinding(
        kind="protocol_version",
        value="TLSv1.3",
        allows_legacy=False,
        evidence=[src_ev],
        source_file=str(tmp_path / "app.py"),
        config_format="source-code-intent",
    )
    cfg_ev = Evidence(
        locator=str(tmp_path / "nginx.conf"),
        line=1,
        column=1,
        byte_offset=0,
        snippet="ssl_protocols TLSv1.3;",
        source_type="config",
        detector_id="test",
        detector_version="0.1.0",
    )
    cfg = TlsConfigFinding(
        kind="protocol_version",
        value="TLSv1.3",
        allows_legacy=False,
        evidence=[cfg_ev],
        source_file=str(tmp_path / "nginx.conf"),
        config_format="nginx",
    )

    contradictions = run_contradiction_analysis([src, cfg], target_root=tmp_path)
    assert contradictions == []


def test_high_severity_contradiction(tmp_path: Path) -> None:
    """When deployed config allows critically broken SSLv3, contradiction severity is high."""
    src_ev = Evidence(
        locator=str(tmp_path / "app.py"),
        line=5,
        column=1,
        byte_offset=50,
        snippet="ssl.TLSVersion.TLSv1_3",
        source_type="source",
        detector_id="test",
        detector_version="0.1.0",
    )
    src = TlsConfigFinding(
        kind="protocol_version",
        value="TLSv1.3",
        allows_legacy=False,
        evidence=[src_ev],
        source_file=str(tmp_path / "app.py"),
        config_format="source-code-intent",
    )
    cfg_ev = Evidence(
        locator=str(tmp_path / "nginx.conf"),
        line=10,
        column=1,
        byte_offset=100,
        snippet="ssl_protocols SSLv3 TLSv1.2;",
        source_type="config",
        detector_id="test",
        detector_version="0.1.0",
    )
    cfg = TlsConfigFinding(
        kind="protocol_version",
        value="SSLv3 TLSv1.2",
        allows_legacy=True,
        legacy_reasons=["SSLv3 (SSL 3.0)"],
        severity="high",
        evidence=[cfg_ev],
        source_file=str(tmp_path / "nginx.conf"),
        config_format="nginx",
    )

    contradictions = run_contradiction_analysis([src, cfg], target_root=tmp_path)
    assert len(contradictions) == 1
    assert contradictions[0].severity == "high"


def test_cyclonedx_schema_validity_with_contradictions(tmp_path: Path) -> None:
    """An emitted CBOM containing contradiction findings must validate cleanly against CycloneDX 1.6."""
    target_path = _TESTDATA_DIR / "scenario1_conflict"
    result = run_scan(target_path)
    assert len(result.contradiction_findings) == 1

    doc = to_cyclonedx(result)
    # Validate against official CycloneDX 1.6 schema
    validation_errors = validate_cbom(doc)
    assert validation_errors == [], f"Schema validation failed: {validation_errors}"

    # Verify metadata properties contain the contradiction
    meta_props = doc.get("metadata", {}).get("properties", [])
    contra_props = [p for p in meta_props if p["name"].startswith("hash_patch:contradiction.")]
    assert len(contra_props) == 1
    parsed_contra = json.loads(contra_props[0]["value"])
    assert parsed_contra["severity"] == "medium"
    assert parsed_contra["sourceIntent"]["value"] == "TLSv1.3"


def test_scan_determinism_with_contradictions() -> None:
    """Repeated scans of the same target with contradictions produce byte-identical JSON."""
    target_path = _TESTDATA_DIR / "scenario1_conflict"
    res1 = run_scan(target_path)
    res2 = run_scan(target_path)

    doc1 = to_cyclonedx(res1)
    doc2 = to_cyclonedx(res2)

    # Serial number and contradiction findings must be identical
    assert doc1["serialNumber"] == doc2["serialNumber"]
    assert doc1["metadata"]["properties"] == doc2["metadata"]["properties"]


def test_cli_scan_contradictions_summary_line() -> None:
    """pratyaksha scan PATH outputs the contradiction summary line."""
    target_path = str(_TESTDATA_DIR / "scenario1_conflict")
    res = runner.invoke(app, ["scan", target_path])
    assert res.exit_code == 0
    assert "1 cross-layer contradictions found (0 high severity)" in res.stdout
