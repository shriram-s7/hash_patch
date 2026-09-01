"""tests/golden/test_blast_radius_golden.py

Golden-corpus test for Pillar 3 (Blast Radius). Runs the real detection +
correlation pipeline over testdata/c/blast_radius_examples.c and
testdata/sql/schema.sql and checks every entry in
tests/golden/blast_radius_manifest.json — so each seeded scenario is
regression-tested, not just eyeballed once.
"""

from __future__ import annotations

import json
from pathlib import Path

from pratyaksha.analyze.blast_radius import compute_blast_radius
from pratyaksha.cli import run_scan
from pratyaksha.detect.blast_radius.c_buffers import CBufferBlastRadiusDetector
from pratyaksha.detect.blast_radius.sql_ddl import SqlDdlBlastRadiusDetector
from pratyaksha.detect.c import COpenSSLDetector
from pratyaksha.emit import to_cyclonedx

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_FILE = REPO_ROOT / "tests" / "golden" / "blast_radius_manifest.json"
C_FIXTURE = REPO_ROOT / "testdata" / "c" / "blast_radius_examples.c"
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
    pratyaksha/analyze/blast_radius.py's module docstring) must still show
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
        if any(p["name"] == "pratyaksha:confidence" and p["value"] == "inferred" for p in c.get("properties", []))
    ]
    assert len(inferred_components) == 1, f"expected exactly one inferred CBOM component, got: {components}"
    component = inferred_components[0]
    assert component["type"] == "cryptographic-asset"
    assert component["name"] == "ML-DSA-65 (inferred)"
    confirmed_components = [
        c
        for c in components
        if any(p["name"] == "pratyaksha:confidence" and p["value"] == "confirmed" for p in c.get("properties", []))
    ]
    assert confirmed_components == [], "an inferred finding must never be labelled confirmed"
