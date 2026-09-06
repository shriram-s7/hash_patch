"""tests/golden/test_blast_radius_golden.py

Golden-corpus test for Pillar 3 (Blast Radius). Runs the real detection +
correlation pipeline over testdata/c/blast_radius_examples.c,
testdata/python/blast_radius_examples.py, and testdata/sql/schema.sql and
checks every entry in tests/golden/blast_radius_manifest.json — so each
seeded scenario is regression-tested, not just eyeballed once.
"""

from __future__ import annotations

import json
from pathlib import Path

from hash_patch.analyze.blast_radius import compute_blast_radius
from hash_patch.cli import run_scan
from hash_patch.detect.blast_radius.c_buffers import CBufferBlastRadiusDetector
from hash_patch.detect.blast_radius.python_buffers import PythonBufferBlastRadiusDetector
from hash_patch.detect.blast_radius.sql_ddl import SqlDdlBlastRadiusDetector
from hash_patch.detect.c import COpenSSLDetector
from hash_patch.detect.python import PythonCryptoDetector
from hash_patch.emit import to_cyclonedx

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_FILE = REPO_ROOT / "tests" / "golden" / "blast_radius_manifest.json"
C_FIXTURE = REPO_ROOT / "testdata" / "c" / "blast_radius_examples.c"
PYTHON_FIXTURE = REPO_ROOT / "testdata" / "python" / "blast_radius_examples.py"
SQL_FIXTURE = REPO_ROOT / "testdata" / "sql" / "schema.sql"
SQL_DIR = REPO_ROOT / "testdata" / "sql"


def _load_manifest() -> dict:
    with MANIFEST_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _finding_for(findings, name: str, line: int):
    for f in findings:
        ev = f.size_constraint.evidence[0]
        if f.size_constraint.name == name and ev.line == line:
            return f
    return None


def test_blast_radius_manifest_file_exists() -> None:
    assert MANIFEST_FILE.is_file()


def test_c_corpus_matches_manifest() -> None:
    manifest = _load_manifest()
    assets = COpenSSLDetector().detect(C_FIXTURE)
    constraints = CBufferBlastRadiusDetector().detect(C_FIXTURE)
    findings = compute_blast_radius(assets, constraints)

    for entry in manifest["c"]:
        finding = _finding_for(findings, entry["name"], entry["line"])
        if entry["overflow_sign"] == 1:
            assert finding is not None, f"expected a finding for {entry}"
            assert finding.overflow_bytes > 0
            assert finding.size_constraint.declared_bytes == entry["declared_bytes"]
        else:
            assert finding is None, f"expected NO finding for {entry}, got {finding}"


def test_c_unresolved_define_produces_no_size_constraint() -> None:
    manifest = _load_manifest()
    constraints = CBufferBlastRadiusDetector().detect(C_FIXTURE)
    names = {c.name for c in constraints}
    assert manifest["c_unresolved_name"] not in names


def test_python_corpus_matches_manifest() -> None:
    manifest = _load_manifest()
    assets = PythonCryptoDetector().detect(PYTHON_FIXTURE)
    constraints = PythonBufferBlastRadiusDetector().detect(PYTHON_FIXTURE)
    findings = compute_blast_radius(assets, constraints)

    for entry in manifest["python"]:
        finding = _finding_for(findings, entry["name"], entry["line"])
        if entry["overflow_sign"] == 1:
            assert finding is not None, f"expected a finding for {entry}"
            assert finding.overflow_bytes > 0
            assert finding.size_constraint.declared_bytes == entry["declared_bytes"]
        else:
            assert finding is None, f"expected NO finding for {entry}, got {finding}"


def test_python_unrelated_buffer_produces_no_size_constraint() -> None:
    manifest = _load_manifest()
    constraints = PythonBufferBlastRadiusDetector().detect(PYTHON_FIXTURE)
    names = {c.name for c in constraints}
    assert manifest["python_unresolved_name"] not in names


def test_sql_corpus_matches_manifest() -> None:
    manifest = _load_manifest()
    assets = COpenSSLDetector().detect(C_FIXTURE)  # empty for a .sql target; kept for API symmetry
    constraints = SqlDdlBlastRadiusDetector().detect(SQL_FIXTURE)
    findings = compute_blast_radius(assets, constraints)

    for entry in manifest["sql"]:
        finding = _finding_for(findings, entry["name"], entry["line"])
        assert finding is not None, f"expected a finding for {entry}"
        assert finding.overflow_bytes > 0
        assert finding.size_constraint.declared_bytes == entry["declared_bytes"]
        assert finding.asset_id.startswith("blast-radius-inferred:")


def test_sql_no_size_no_crypto_name_column_produces_no_constraint() -> None:
    manifest = _load_manifest()
    constraints = SqlDdlBlastRadiusDetector().detect(SQL_FIXTURE)
    names = {c.name for c in constraints}
    assert manifest["sql_no_fire_column"] not in names


def test_sql_inferred_finding_is_emitted_as_a_synthetic_cbom_component() -> None:
    """Regression for BUG 2: a db_column blast-radius finding with no real
    correlated CryptoAsset (the SQL-only fallback path, see
    hash_patch/analyze/blast_radius.py's module docstring) must still show
    up as an actual component in the emitted CBOM -- not just a console
    summary line -- so it's visible to anyone reading the report.
    """
    result = run_scan(SQL_DIR)

    assert len(result.blast_radius_findings) == 1
    assert result.blast_radius_findings[0].asset_id.startswith("blast-radius-inferred:")

    assert len(result.assets) >= 1, "the inferred finding must produce at least one CBOM component"
    inferred_assets = [a for a in result.assets if a.confidence == "inferred"]
    assert len(inferred_assets) == 1, f"expected exactly one inferred asset, got: {result.assets}"
    asset = inferred_assets[0]

    assert asset.name == "ML-DSA-65 (inferred)"
    blast_radius_props = {k: v for k, v in asset.properties.items() if k.startswith("blastRadius.")}
    assert len(blast_radius_props) == 1
    (prop_value,) = blast_radius_props.values()
    parsed = json.loads(prop_value)
    assert parsed["declaredBytes"] == 512
    assert parsed["pqcReplacement"] == "ML-DSA-65"
    assert parsed["overflowBytes"] > 0
    assert parsed["locator"].replace("\\", "/").endswith("testdata/sql/schema.sql")

    assert asset.evidence, "the synthetic asset must carry real evidence (CLAUDE.md hard constraint #3)"
    assert any(ev.locator.replace("\\", "/").endswith("testdata/sql/schema.sql") for ev in asset.evidence)

    doc = to_cyclonedx(result)
    components = doc.get("components", [])
    assert len(components) >= 1, "the CBOM itself must contain the inferred finding, not just the finding list"

    inferred_components = [
        c
        for c in components
        if any(p["name"] == "hash_patch:confidence" and p["value"] == "inferred" for p in c.get("properties", []))
    ]
    assert len(inferred_components) == 1, f"expected exactly one inferred CBOM component, got: {components}"
    component = inferred_components[0]
    assert component["type"] == "cryptographic-asset"
    assert component["name"] == "ML-DSA-65 (inferred)"
    confirmed_components = [
        c
        for c in components
        if any(p["name"] == "hash_patch:confidence" and p["value"] == "confirmed" for p in c.get("properties", []))
    ]
    assert confirmed_components == [], "an inferred finding must never be labelled confirmed"


def test_c_buffer_as_function_parameter_detected() -> None:
    custody_file = REPO_ROOT / "test2" / "c" / "src" / "custody.c"
    storage_file = REPO_ROOT / "test2" / "c" / "src" / "storage.c"
    detector = CBufferBlastRadiusDetector()

    custody_constraints = detector.detect(custody_file)
    param_out = [c for c in custody_constraints if c.name == "out" and c.evidence[0].line == 19]
    assert len(param_out) == 1, "Expected function parameter out[64] in sign_terminal_receipt to be detected"
    assert param_out[0].declared_bytes == 64
    assert param_out[0].inferred_field == "signature"

    storage_constraints = detector.detect(storage_file)
    param_db = [c for c in storage_constraints if c.name == "db_value" and c.evidence[0].line == 9]
    assert len(param_db) == 1, "Expected function parameter db_value[64] in store_pan to be detected"
    assert param_db[0].declared_bytes == 64


def test_buffer_size_correlation_without_relying_on_name() -> None:
    custody_file = REPO_ROOT / "test2" / "c" / "src" / "custody.c"
    detector = CBufferBlastRadiusDetector()
    constraints = detector.detect(custody_file)

    receipt = [c for c in constraints if c.name == "receipt" and c.evidence[0].line == 44]
    assert len(receipt) == 1, "Expected local buffer receipt[64] in seal_biometric to be detected"
    assert receipt[0].declared_bytes == 64
    assert receipt[0].inferred_field == "signature"

    # Correlate against custody.c assets (Ed25519)
    from hash_patch.detect.c import COpenSSLDetector

    assets = COpenSSLDetector().detect(custody_file)
    findings = compute_blast_radius(assets, constraints)
    receipt_finding = [f for f in findings if f.size_constraint.name == "receipt"]
    assert len(receipt_finding) == 1
    assert receipt_finding[0].pqc_replacement_name == "ML-DSA-65"
    assert receipt_finding[0].overflow_bytes == 3245


def test_go_fixed_size_buffer_detected() -> None:
    from hash_patch.detect.blast_radius.go_buffers import GoBufferBlastRadiusDetector
    from hash_patch.detect.go import GoCryptoDetector

    issue_file = REPO_ROOT / "test2" / "go" / "internal" / "tokens" / "issue.go"
    detector = GoBufferBlastRadiusDetector()
    constraints = detector.detect(issue_file)

    wire = [c for c in constraints if c.name == "wire" and c.evidence[0].line == 19]
    assert len(wire) == 1, "Expected var wire [64]byte in issue.go to be detected"
    assert wire[0].declared_bytes == 64
    assert wire[0].language == "go"
    assert wire[0].inferred_field == "signature"

    assets = GoCryptoDetector().detect(issue_file)
    findings = compute_blast_radius(assets, constraints)
    wire_finding = [f for f in findings if f.size_constraint.name == "wire"]
    assert len(wire_finding) == 1
    assert wire_finding[0].pqc_replacement_name == "ML-DSA-65"
    assert wire_finding[0].overflow_bytes == 3245


def test_java_fixed_size_array_detected() -> None:
    from hash_patch.detect.blast_radius.java_buffers import JavaBufferBlastRadiusDetector
    from hash_patch.detect.java import JavaJcaDetector

    sensitive_store = (
        REPO_ROOT
        / "test2"
        / "java"
        / "src"
        / "main"
        / "java"
        / "com"
        / "harborline"
        / "payments"
        / "SensitiveStore.java"
    )
    health_case = (
        REPO_ROOT
        / "test2"
        / "java"
        / "src"
        / "main"
        / "java"
        / "com"
        / "harborline"
        / "payments"
        / "HealthCase.java"
    )
    detector = JavaBufferBlastRadiusDetector()

    constraints = detector.detect(sensitive_store)
    out_buf = [c for c in constraints if c.name == "out" and c.evidence[0].line == 23]
    assert len(out_buf) == 1, "Expected new byte[64] in SensitiveStore.java to be detected"
    assert out_buf[0].declared_bytes == 64
    assert out_buf[0].language == "java"
    assert out_buf[0].inferred_field == "signature"

    # HealthCase is comment-only / int constant, zero buffer findings
    hc_constraints = detector.detect(health_case)
    assert len(hc_constraints) == 0, "HealthCase.java has only a comment and int constant, expected 0 buffer findings"

    assets = JavaJcaDetector().detect(sensitive_store)
    findings = compute_blast_radius(assets, constraints)
    out_finding = [f for f in findings if f.size_constraint.name == "out"]
    assert len(out_finding) == 1
    assert out_finding[0].pqc_replacement_name == "ML-DSA-65"
    assert out_finding[0].overflow_bytes == 3245


def test_blast_radius_explanation_reflects_actual_scan_languages() -> None:
    from hash_patch.analyze.blast_radius import blast_radius_explanation

    # Case A: Pure-Python scan with 0 findings -> accurately explains dynamic runtime allocation
    py_files = [REPO_ROOT / "testdata" / "python" / "hashlib_examples.py"]
    py_exp = blast_radius_explanation(py_files, [])
    assert "Pure-Python" in py_exp
    assert "dynamically" in py_exp

    # Case B: Multi-language or C/Go/Java scan with 0 findings -> does NOT claim pure-Python
    c_files = [REPO_ROOT / "test2" / "c" / "src" / "storage.c"]
    c_exp = blast_radius_explanation(c_files, [])
    assert "Pure-Python" not in c_exp
    assert "C, Go, Java" in c_exp
    assert "detected no static buffer overflows" in c_exp

    # Case C: Scan with findings -> reports findings count
    mix_files = [REPO_ROOT / "test2" / "c" / "src" / "custody.c"]
    from hash_patch.analyze.blast_radius import run_blast_radius
    from hash_patch.detect.c import COpenSSLDetector

    findings = run_blast_radius(COpenSSLDetector().detect(mix_files[0]), mix_files)
    finding_exp = blast_radius_explanation(mix_files, findings)
    assert "Detected 2 fixed-size buffer" in finding_exp

