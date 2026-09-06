"""tests/unit/test_shelf_life.py

Unit tests for Pillar 2 (Shelf-Life Inference):
  hash_patch/detect/shelf_life/{ontology,data_context}.py
  hash_patch/analyze/shelf_life.py

Section 1: the three seeded corpus cases (aadhaar via call_argument, no
signal, and the aadhaar-vs-financial_account tie-break), asserted directly
against the detection + correlation pipeline (see also
tests/golden/test_shelf_life_golden.py, which drives the same corpus off
tests/golden/shelf_life_manifest.json).

Section 2: cross-file correlation must NEVER happen — the same honesty rule
hash_patch/analyze/blast_radius.py enforces (CLAUDE.md's "Blast Radius"
section), applied here to DataContextMatch <-> CryptoAsset correlation.

Section 3: "no signal found" must produce no finding at all — never a
silent generic_pii default.

Section 4: determinism, following the existing test pattern
(tests/unit/test_blast_radius.py's `test_*_is_deterministic` tests).

Section 5: the longest-shelf-life-wins fail-safe rule is actually exercised
(not just coincidentally correct) — order-independence is asserted
explicitly, not just a single hardcoded outcome.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from hash_patch.analyze.shelf_life import compute_shelf_life, run_shelf_life
from hash_patch.detect.java import JavaJcaDetector
from hash_patch.detect.python import PythonCryptoDetector
from hash_patch.detect.shelf_life.data_context import find_data_context_matches
from hash_patch.detect.shelf_life.ontology import (
    SensitivityCategory,
    load_sensitivity_categories,
    match_categories,
)
from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, QuantumStatus
from hash_patch.model.evidence import Evidence
from hash_patch.model.shelf_life import DataContextMatch

REPO_ROOT = Path(__file__).resolve().parents[2]
PY_FIXTURE = REPO_ROOT / "testdata" / "python" / "shelf_life_examples.py"
JAVA_FIXTURE = REPO_ROOT / "testdata" / "java" / "ShelfLifeExamples.java"

_SCAN_DATE = date(2026, 1, 1)


def _finding_for(findings, algorithm: str):
    for f in findings:
        if f.asset_name == algorithm:
            return f
    return None


# ===========================================================================
# Section 1 — the three seeded corpus cases.
# ===========================================================================


def test_python_aadhaar_call_argument_produces_finding() -> None:
    assets = PythonCryptoDetector().detect(PY_FIXTURE)
    matches = find_data_context_matches(assets)
    findings = compute_shelf_life(assets, matches, _SCAN_DATE)

    finding = _finding_for(findings, "SHA-256")
    assert finding is not None
    assert finding.category == "aadhaar"
    assert finding.shelf_life_years == 27
    assert "2053" in finding.mosca_note  # 2026 + 27


def test_python_generic_name_produces_no_finding() -> None:
    assets = PythonCryptoDetector().detect(PY_FIXTURE)
    matches = find_data_context_matches(assets)
    findings = compute_shelf_life(assets, matches, _SCAN_DATE)

    assert _finding_for(findings, "SHA-512") is None, (
        "cache_temp_value()/SHA512.new(temp_cache_value) has no crypto-suggestive "
        "signal anywhere -- must produce NO finding, not a generic_pii guess"
    )


def test_python_tie_break_resolves_to_longer_shelf_life() -> None:
    categories = {c.category_name: c for c in load_sensitivity_categories()}
    assert categories["aadhaar"].shelf_life_years > categories["financial_account"].shelf_life_years

    assets = PythonCryptoDetector().detect(PY_FIXTURE)
    matches = find_data_context_matches(assets)
    findings = compute_shelf_life(assets, matches, _SCAN_DATE)

    finding = _finding_for(findings, "SHA3-256")
    assert finding is not None
    assert finding.category == "aadhaar", (
        "CustomerRecord has both an aadhaar_number and an account_number field; "
        "the longer-shelf-life category (aadhaar) must win"
    )


def test_java_corpus_matches_python_corpus_shape() -> None:
    """Same three scenarios, Java side (enclosing_function instead of
    call_argument for scenario 1 -- see testdata/java/ShelfLifeExamples.java's
    module docstring for why).
    """
    assets = JavaJcaDetector().detect(JAVA_FIXTURE)
    matches = find_data_context_matches(assets)
    findings = compute_shelf_life(assets, matches, _SCAN_DATE)

    aadhaar_finding = _finding_for(findings, "SHA-256")
    assert aadhaar_finding is not None
    assert aadhaar_finding.category == "aadhaar"

    assert _finding_for(findings, "SHA-512") is None

    tie_break_finding = _finding_for(findings, "SHA3-256")
    assert tie_break_finding is not None
    assert tie_break_finding.category == "aadhaar"


# ===========================================================================
# Section 2 — cross-file correlation must never happen.
# ===========================================================================


def _ev(locator: str, line: int) -> Evidence:
    return Evidence(source_type="source", locator=locator, line=line, detector_id="d", detector_version="0")


def test_cross_file_correlation_never_happens() -> None:
    """A DataContextMatch in file A must NEVER correlate with a CryptoAsset
    whose only evidence is in file B, even if both use the same line number.
    """
    asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="SHA-256",
        primitive=Primitive.HASH,
        quantum_status=QuantumStatus.WEAKENED_BY_GROVER,
        evidence=[_ev("b.py", 10)],
    )
    match = DataContextMatch(
        category="aadhaar",
        matched_identifier="aadhaar_number",
        matched_pattern="aadhaar",
        candidate_kind="call_argument",
        language="python",
        evidence=[_ev("a.py", 10)],  # same line number, DIFFERENT file
    )

    findings = compute_shelf_life([asset], [match], _SCAN_DATE)
    assert findings == [], (
        "cross-file correlation produced a finding -- same-file rule is broken:\n" f"{findings}"
    )


def test_cross_file_correlation_never_happens_via_run_shelf_life() -> None:
    """Same as above, exercised through the actual entry point
    hash_patch/cli.py::run_scan calls (run_shelf_life -> find_data_context_matches),
    using two real files in a temp directory.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "aadhaar_field.py").write_text(
            "def unrelated_helper(aadhaar_number):\n    return aadhaar_number\n",
            encoding="utf-8",
        )
        signing_file = tmp_path / "hashing.py"
        signing_file.write_text(
            "from Crypto.Hash import SHA256\n\n"
            "def cache_temp_value(temp_cache_value):\n"
            "    digest = SHA256.new(temp_cache_value)\n"
            "    return digest.hexdigest()\n",
            encoding="utf-8",
        )

        assets = PythonCryptoDetector().detect(signing_file)
        findings = run_shelf_life(assets, _SCAN_DATE)
        assert findings == [], (
            "an aadhaar-pattern identifier in an unrelated file must never correlate "
            f"with a crypto call in a different file:\n{findings}"
        )


# ===========================================================================
# Section 3 — "no signal found" produces no finding, never a default.
# ===========================================================================


def test_no_data_context_matches_produces_no_findings() -> None:
    asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="AES",
        primitive=Primitive.BLOCK_CIPHER,
        quantum_status=QuantumStatus.WEAKENED_BY_GROVER,
        evidence=[_ev("x.py", 5)],
    )
    findings = compute_shelf_life([asset], [], _SCAN_DATE)
    assert findings == []


def test_shelf_life_finding_never_has_zero_years() -> None:
    """A ShelfLifeFinding's shelf_life_years must never be 0 -- every entry
    in ontology/data_sensitivity.yaml carries a positive figure, and
    "no signal" must produce no ShelfLifeFinding at all (see
    test_no_data_context_matches_produces_no_findings above), never a
    finding with shelf_life_years=0. A UI (or any consumer) that sees 0
    would misread it as "expires immediately" -- a different, misleading
    claim from "unknown" (absence of a finding).
    """
    assets = PythonCryptoDetector().detect(PY_FIXTURE) + JavaJcaDetector().detect(JAVA_FIXTURE)
    findings = run_shelf_life(assets, _SCAN_DATE)
    assert findings, "expected at least one real shelf-life finding from the fixtures"
    assert all(f.shelf_life_years > 0 for f in findings)


def test_adversarial_corpus_produces_no_findings_not_a_crash() -> None:
    """The cbom_adversarial_corpus fixture (if present locally) has no
    identifier anywhere that matches ontology/data_sensitivity.yaml's
    name_patterns near a crypto call site -- genuinely zero signal, not a
    bug. This must run to completion and return an empty list, never raise.
    """
    corpus_root = Path(r"D:\cbom_adversarial_corpus")
    if not corpus_root.is_dir():
        pytest.skip(f"Adversarial corpus directory not found at {corpus_root}")

    from hash_patch.cli import run_scan

    result = run_scan(corpus_root)
    findings = run_shelf_life(result.assets, _SCAN_DATE)
    assert findings == []


def test_generic_pii_is_never_a_silent_fallback() -> None:
    """An asset with real DataContextMatch signal that matches NOTHING in the
    ontology must not somehow still get a generic_pii finding -- the
    detection layer (find_data_context_matches) simply never emits a
    DataContextMatch for an unmatched identifier in the first place, so
    there is nothing for analyze/shelf_life.py to fall back to.
    """
    assets = PythonCryptoDetector().detect(PY_FIXTURE)
    matches = find_data_context_matches(assets)
    assert all(m.category != "generic_pii" for m in matches), (
        "no scenario in the corpus should trigger generic_pii; if this fails, "
        "check whether a name-pattern is too broad"
    )


def test_hash_naming_convention_fingerprint_does_not_match_biometric() -> None:
    """REGRESSION: 'fingerprint' as a hash-naming-convention method name
    (a short hash used to identify/verify something -- a partner
    fingerprint, a certificate fingerprint) must never match the
    `biometric` category. Confirmed false positives on real code before
    this fix: test2/java/.../LegacyGateway.java's `partnerFingerprint()`
    (an MD5 digest of a partner id) and PolicyDigest.java's `fingerprint()`
    (a SHA-1 digest) -- both matched purely because the bare substring
    "fingerprint" was listed in ontology/data_sensitivity.yaml's biometric
    category, with zero actual biometric content involved. See
    tests/golden/shelf_life_manifest.json's "MD5"/ShelfLifeExamples.java
    entry for the end-to-end regression test.
    """
    categories = load_sensitivity_categories()
    for identifier in ("partnerFingerprint", "fingerprint"):
        matches = match_categories(identifier, categories)
        biometric_matches = [c for c, _ in matches if c.category_name == "biometric"]
        assert biometric_matches == [], (
            f"{identifier!r} should never match the biometric category "
            f"(hash-naming-convention 'fingerprint', not biometric data)"
        )


def test_genuine_biometric_fingerprint_artifact_still_matches() -> None:
    """The fix must not introduce a false negative: an identifier that
    actually names biometric fingerprint DATA (a scan/image/template/
    sensor reading), not just reuses the word as a hash-naming metaphor,
    must still match the biometric category.
    """
    categories = load_sensitivity_categories()
    for identifier in ("fingerprint_scan", "fingerprintTemplate", "fingerprint_sensor_reading"):
        matches = match_categories(identifier, categories)
        biometric_matches = [c for c, _ in matches if c.category_name == "biometric"]
        assert biometric_matches != [], f"{identifier!r} should still match the biometric category"


# ===========================================================================
# Section 4 — determinism.
# ===========================================================================


def test_shelf_life_is_deterministic() -> None:
    assets_a = PythonCryptoDetector().detect(PY_FIXTURE)
    assets_b = PythonCryptoDetector().detect(PY_FIXTURE)

    findings_a = run_shelf_life(assets_a, _SCAN_DATE)
    findings_b = run_shelf_life(assets_b, _SCAN_DATE)

    def _key(f):
        ev = f.evidence[0]
        return (f.asset_id, f.category, ev.locator, ev.line, f.shelf_life_years, f.mosca_note)

    assert [_key(f) for f in findings_a] == [_key(f) for f in findings_b]


def test_java_shelf_life_is_deterministic() -> None:
    assets_a = JavaJcaDetector().detect(JAVA_FIXTURE)
    assets_b = JavaJcaDetector().detect(JAVA_FIXTURE)

    findings_a = run_shelf_life(assets_a, _SCAN_DATE)
    findings_b = run_shelf_life(assets_b, _SCAN_DATE)

    def _key(f):
        ev = f.evidence[0]
        return (f.asset_id, f.category, ev.locator, ev.line, f.shelf_life_years, f.mosca_note)

    assert [_key(f) for f in findings_a] == [_key(f) for f in findings_b]


# ===========================================================================
# Section 5 — longest-shelf-life-wins is actually exercised, order-independent.
# ===========================================================================


def _synthetic_categories() -> list[SensitivityCategory]:
    return [
        SensitivityCategory(
            category_name="short_cat",
            name_patterns=("short_pattern",),
            shelf_life_years=3,
            statutory_basis="test fixture",
            confidence="medium",
        ),
        SensitivityCategory(
            category_name="long_cat",
            name_patterns=("long_pattern",),
            shelf_life_years=99,
            statutory_basis="test fixture",
            confidence="high",
        ),
    ]


def test_longest_shelf_life_wins_regardless_of_candidate_order() -> None:
    """Two DataContextMatch objects, same call site, different categories
    with clearly different shelf_life_years (3 vs 99) -- the longer one
    (long_cat, 99yr) must win regardless of which order they're passed in,
    proving the outcome isn't a coincidence of iteration order.
    """
    asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="AES",
        primitive=Primitive.BLOCK_CIPHER,
        quantum_status=QuantumStatus.WEAKENED_BY_GROVER,
        evidence=[_ev("x.py", 5)],
    )
    short_match = DataContextMatch(
        category="short_cat",
        matched_identifier="short_pattern_value",
        matched_pattern="short_pattern",
        candidate_kind="call_argument",
        language="python",
        evidence=[_ev("x.py", 5)],
    )
    long_match = DataContextMatch(
        category="long_cat",
        matched_identifier="long_pattern_value",
        matched_pattern="long_pattern",
        candidate_kind="enclosing_function",
        language="python",
        evidence=[_ev("x.py", 5)],
    )
    cats = _synthetic_categories()

    findings_short_first = compute_shelf_life([asset], [short_match, long_match], _SCAN_DATE, categories=cats)
    findings_long_first = compute_shelf_life([asset], [long_match, short_match], _SCAN_DATE, categories=cats)

    assert len(findings_short_first) == 1
    assert len(findings_long_first) == 1
    assert findings_short_first[0].category == "long_cat"
    assert findings_long_first[0].category == "long_cat"
    assert findings_short_first[0].shelf_life_years == 99


def test_longest_shelf_life_wins_source_order_independence_via_real_files(tmp_path: Path) -> None:
    """Same rule, exercised through the real detection pipeline: build two
    source files where the aadhaar-pattern field is declared BEFORE the
    financial_account-pattern field in one, and AFTER it in the other --
    aadhaar (27yr) must win both times, proving the winner is picked by
    shelf-life length, not by which pattern the parser happens to visit
    first.
    """
    template_aadhaar_first = (
        "from Crypto.Hash import SHA3_256\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class Record:\n"
        "    aadhaar_number: str\n"
        "    account_number: str\n\n"
        "    def hash_it(self, record_bytes):\n"
        "        digest = SHA3_256.new(record_bytes)\n"
        "        return digest.hexdigest()\n"
    )
    template_account_first = (
        "from Crypto.Hash import SHA3_256\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class Record:\n"
        "    account_number: str\n"
        "    aadhaar_number: str\n\n"
        "    def hash_it(self, record_bytes):\n"
        "        digest = SHA3_256.new(record_bytes)\n"
        "        return digest.hexdigest()\n"
    )

    f1 = tmp_path / "aadhaar_first.py"
    f1.write_text(template_aadhaar_first, encoding="utf-8")
    f2 = tmp_path / "account_first.py"
    f2.write_text(template_account_first, encoding="utf-8")

    assets1 = PythonCryptoDetector().detect(f1)
    findings1 = run_shelf_life(assets1, _SCAN_DATE)
    assets2 = PythonCryptoDetector().detect(f2)
    findings2 = run_shelf_life(assets2, _SCAN_DATE)

    assert len(findings1) == 1 and findings1[0].category == "aadhaar"
    assert len(findings2) == 1 and findings2[0].category == "aadhaar"
