"""tests/unit/test_blast_radius.py

Unit tests for Pillar 3 (Blast Radius):
  pratyaksha/detect/blast_radius/{names,c_buffers,sql_ddl}.py
  pratyaksha/analyze/blast_radius.py

Section 1: cross-file correlation must NEVER happen (the single most
important safety property this pillar has, per CLAUDE.md's "Blast Radius"
section — same-file correlation is what keeps this from being a
false-positive machine).

Section 2: unresolved sizes (a #define never defined in the file) must
produce no SizeConstraint at all — never a guessed one.

Section 3: determinism, following the existing test pattern
(tests/integration/test_cli_scan.py's *_is_deterministic tests).

Section 4: smaller focused unit tests for the detectors and the
correlation/severity/effort helpers.
"""

from __future__ import annotations

from pathlib import Path

from pratyaksha.analyze.blast_radius import (
    _estimate_effort_days,
    _severity_for_overflow,
    compute_blast_radius,
    primitive_for_replacement,
    run_blast_radius,
)
from pratyaksha.detect.blast_radius.c_buffers import CBufferBlastRadiusDetector
from pratyaksha.detect.blast_radius.names import load_name_patterns, match_name_pattern
from pratyaksha.detect.blast_radius.sql_ddl import SqlDdlBlastRadiusDetector
from pratyaksha.detect.c import COpenSSLDetector
from pratyaksha.model.assets import AssetType, CryptoAsset, Primitive, QuantumStatus
from pratyaksha.model.blast_radius import SizeConstraint
from pratyaksha.model.evidence import Evidence

REPO_ROOT = Path(__file__).resolve().parents[2]
C_FIXTURE = REPO_ROOT / "testdata" / "c" / "blast_radius_examples.c"
SQL_FIXTURE = REPO_ROOT / "testdata" / "sql" / "schema.sql"


# ===========================================================================
# Section 1 — cross-file correlation must never happen.
# ===========================================================================


def test_cross_file_correlation_never_happens(tmp_path: Path) -> None:
    """Two files, matching crypto-shaped names, in the same scan target —
    a `signature` buffer in file A and an RSA_sign() call in file B — must
    NEVER produce a BlastRadiusFinding, because they are not the same file.
    """
    (tmp_path / "buffers.c").write_text(
        "void alloc_sig(void) {\n    unsigned char signature[32];\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "signing.c").write_text(
        "void do_sign(RSA *key, const unsigned char *msg, unsigned int len) {\n"
        "    unsigned int sig_len = 0;\n"
        "    unsigned char *out = 0;\n"
        "    RSA_sign(0, msg, len, out, &sig_len, key);\n"
        "}\n",
        encoding="utf-8",
    )

    files = [tmp_path / "buffers.c", tmp_path / "signing.c"]
    assets = []
    constraints = []
    detector = COpenSSLDetector()
    buf_detector = CBufferBlastRadiusDetector()
    for f in files:
        assets.extend(detector.detect(f))
        constraints.extend(buf_detector.detect(f))

    assert len(constraints) == 1  # the "signature" buffer in buffers.c
    assert any(a.name == "RSA" for a in assets)  # the RSA_sign call in signing.c

    findings = compute_blast_radius(assets, constraints)
    assert findings == [], (
        "cross-file correlation produced a finding — same-file-only rule is broken:\n"
        f"{findings}"
    )


def test_cross_file_correlation_never_happens_via_run_blast_radius(tmp_path: Path) -> None:
    """Same as above, exercised through the actual entry point
    pratyaksha/cli.py::run_scan calls (run_blast_radius), not the lower-level
    compute_blast_radius directly.
    """
    (tmp_path / "buffers.c").write_text(
        "void alloc_sig(void) {\n    unsigned char signature[32];\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "signing.c").write_text(
        "void do_sign(RSA *key, const unsigned char *msg, unsigned int len) {\n"
        "    unsigned int sig_len = 0;\n"
        "    unsigned char *out = 0;\n"
        "    RSA_sign(0, msg, len, out, &sig_len, key);\n"
        "}\n",
        encoding="utf-8",
    )
    files = [tmp_path / "buffers.c", tmp_path / "signing.c"]
    assets = []
    detector = COpenSSLDetector()
    for f in files:
        assets.extend(detector.detect(f))

    findings = run_blast_radius(assets, files)
    assert findings == []


# ===========================================================================
# Section 2 — unresolved sizes produce no SizeConstraint at all.
# ===========================================================================


def test_unresolved_define_produces_no_size_constraint(tmp_path: Path) -> None:
    src = (
        "void f(void) {\n"
        "    unsigned char signature[UNDEFINED_SIG_LEN];\n"
        "}\n"
    )
    f = tmp_path / "unresolved.c"
    f.write_text(src, encoding="utf-8")

    constraints = CBufferBlastRadiusDetector().detect(f)
    assert constraints == [], (
        "an unresolved #define size must never produce a guessed SizeConstraint"
    )


def test_unresolved_variable_size_produces_no_size_constraint(tmp_path: Path) -> None:
    """A buffer sized by a plain variable (not a literal or a #define) is
    also unresolved — one level of #define resolution only, no data-flow.
    """
    src = (
        "void f(int n) {\n"
        "    unsigned char signature[n];\n"
        "}\n"
    )
    f = tmp_path / "var_size.c"
    f.write_text(src, encoding="utf-8")

    constraints = CBufferBlastRadiusDetector().detect(f)
    assert constraints == []


def test_resolved_define_does_produce_a_size_constraint(tmp_path: Path) -> None:
    """Sanity counterpart: a #define IS resolved one level."""
    src = (
        "#define SIG_LEN 128\n"
        "void f(void) {\n"
        "    unsigned char signature[SIG_LEN];\n"
        "}\n"
    )
    f = tmp_path / "resolved.c"
    f.write_text(src, encoding="utf-8")

    constraints = CBufferBlastRadiusDetector().detect(f)
    assert len(constraints) == 1
    assert constraints[0].declared_bytes == 128


# ===========================================================================
# Section 3 — determinism.
# ===========================================================================


def test_blast_radius_is_deterministic() -> None:
    c_assets_a = COpenSSLDetector().detect(C_FIXTURE)
    c_assets_b = COpenSSLDetector().detect(C_FIXTURE)
    constraints_a = CBufferBlastRadiusDetector().detect(C_FIXTURE)
    constraints_b = CBufferBlastRadiusDetector().detect(C_FIXTURE)

    findings_a = compute_blast_radius(c_assets_a, constraints_a)
    findings_b = compute_blast_radius(c_assets_b, constraints_b)

    def _key(f):
        ev = f.size_constraint.evidence[0]
        return (f.asset_id, f.size_constraint.name, ev.locator, ev.line, f.overflow_bytes, f.severity)

    assert [_key(f) for f in findings_a] == [_key(f) for f in findings_b]


def test_sql_blast_radius_is_deterministic() -> None:
    constraints_a = SqlDdlBlastRadiusDetector().detect(SQL_FIXTURE)
    constraints_b = SqlDdlBlastRadiusDetector().detect(SQL_FIXTURE)
    findings_a = compute_blast_radius([], constraints_a)
    findings_b = compute_blast_radius([], constraints_b)

    def _key(f):
        ev = f.size_constraint.evidence[0]
        return (f.asset_id, f.size_constraint.name, ev.locator, ev.line, f.overflow_bytes, f.severity)

    assert [_key(f) for f in findings_a] == [_key(f) for f in findings_b]


# ===========================================================================
# Section 4 — focused unit tests.
# ===========================================================================


def test_name_pattern_longest_match_wins() -> None:
    patterns = load_name_patterns()
    assert match_name_pattern("rsa_private_key_buf", patterns) == ("private_key", None)
    assert match_name_pattern("session_key", patterns) == ("key", "pubkey")
    assert match_name_pattern("digest_buf", patterns) == ("digest", None)
    assert match_name_pattern("totally_unrelated", patterns) is None


def test_privkey_and_cert_and_hash_patterns_never_fire(tmp_path: Path) -> None:
    """Name patterns with field=null (privkey, cert, digest, hash) match as
    crypto-suggestive but must never produce a BlastRadiusFinding — there is
    no PQC field to compare them against.
    """
    src = (
        "void f(RSA *key, const unsigned char *msg, unsigned int len) {\n"
        "    unsigned char privkey[32];\n"
        "    unsigned char cert_buf[32];\n"
        "    unsigned char digest_buf[32];\n"
        "    unsigned int sig_len = 0;\n"
        "    unsigned char *out = 0;\n"
        "    RSA_sign(0, msg, len, out, &sig_len, key);\n"
        "}\n"
    )
    f = tmp_path / "nullfield.c"
    f.write_text(src, encoding="utf-8")

    assets = COpenSSLDetector().detect(f)
    constraints = CBufferBlastRadiusDetector().detect(f)
    assert {c.name for c in constraints} == {"privkey", "cert_buf", "digest_buf"}

    findings = compute_blast_radius(assets, constraints)
    assert findings == []


def test_heap_alloc_malloc_detected(tmp_path: Path) -> None:
    src = (
        "#include <stdlib.h>\n"
        "void f(void) {\n"
        "    unsigned char *signature = malloc(64);\n"
        "}\n"
    )
    f = tmp_path / "heap.c"
    f.write_text(src, encoding="utf-8")

    constraints = CBufferBlastRadiusDetector().detect(f)
    assert len(constraints) == 1
    assert constraints[0].kind == "heap_alloc"
    assert constraints[0].declared_bytes == 64


def test_heap_alloc_calloc_multiplies_args(tmp_path: Path) -> None:
    src = (
        "#include <stdlib.h>\n"
        "unsigned char *g_signature;\n"
        "void f(void) {\n"
        "    g_signature = calloc(4, 64);\n"
        "}\n"
    )
    f = tmp_path / "heap_calloc.c"
    f.write_text(src, encoding="utf-8")

    constraints = CBufferBlastRadiusDetector().detect(f)
    assert len(constraints) == 1
    assert constraints[0].declared_bytes == 256


def test_severity_thresholds() -> None:
    assert _severity_for_overflow(1) == "low"
    assert _severity_for_overflow(255) == "low"
    assert _severity_for_overflow(256) == "medium"
    assert _severity_for_overflow(1023) == "medium"
    assert _severity_for_overflow(1024) == "high"
    assert _severity_for_overflow(4095) == "high"
    assert _severity_for_overflow(4096) == "critical"


def test_estimated_effort_days() -> None:
    ev = Evidence(
        source_type="source", locator="x.c", line=1, detector_id="d", detector_version="0"
    )
    buf = SizeConstraint(kind="stack_buffer", name="sig", declared_bytes=1, evidence=[ev], language="c")
    col = SizeConstraint(kind="db_column", name="sig", declared_bytes=1, evidence=[ev], language="sql")

    assert _estimate_effort_days(buf) == 0.5
    assert _estimate_effort_days(col) == 1.0


# ===========================================================================
# Section 5 — cross-asset correlation regression (BUG 1).
#
# testdata/c/blast_radius_examples.c has one `signature` buffer (256 bytes,
# next to the RSA_sign() call, line 20) and one `pubkey` buffer (32 bytes,
# next to the Ed25519 keygen, line 30). Before the fix, compute_blast_radius
# cross-joined every same-file BROKEN_BY_SHOR asset against every same-file
# constraint: since RSA_sign's primitive is "signature" (rules/c_openssl.yaml)
# and Ed25519's primitive is also "signature", BOTH asset families' field_map
# includes both the "signature" and "pubkey" fields, so RSA was incorrectly
# credited with Ed25519's 32-byte pubkey buffer and Ed25519 was incorrectly
# credited with RSA's 256-byte signature buffer. The fix picks, per
# constraint, only the NEAREST same-file plausible asset by line distance.
# ===========================================================================


def _finding_for(findings, asset_name: str, constraint_name: str):
    for f in findings:
        if f.asset_name == asset_name and f.size_constraint.name == constraint_name:
            return f
    return None


def test_rsa_signature_and_ed25519_pubkey_do_not_cross_contaminate() -> None:
    """Regression for BUG 1: RSA must only be credited with its own 256-byte
    signature buffer (never Ed25519's 32-byte pubkey buffer), and Ed25519
    must only be credited with its own 32-byte pubkey buffer (never RSA's
    256-byte signature buffer).
    """
    assets = COpenSSLDetector().detect(C_FIXTURE)
    constraints = CBufferBlastRadiusDetector().detect(C_FIXTURE)
    findings = compute_blast_radius(assets, constraints)

    rsa_finding = _finding_for(findings, "RSA", "signature")
    assert rsa_finding is not None, f"expected an RSA/signature finding, got: {findings}"
    assert rsa_finding.size_constraint.declared_bytes == 256, (
        "RSA's finding must be its own 256-byte signature buffer, not Ed25519's 32-byte pubkey buffer"
    )
    assert rsa_finding.pqc_replacement_name == "ML-DSA-65", (
        "RSA_sign's primitive is 'signature' (rules/c_openssl.yaml) -> ML-DSA-65, per its OWN "
        "correlated primitive, never a hardcoded default"
    )

    ed25519_finding = _finding_for(findings, "Ed25519", "pubkey")
    assert ed25519_finding is not None, f"expected an Ed25519/pubkey finding, got: {findings}"
    assert ed25519_finding.size_constraint.declared_bytes == 32, (
        "Ed25519's finding must be its own 32-byte pubkey buffer, not RSA's 256-byte signature buffer"
    )
    assert ed25519_finding.pqc_replacement_name == "ML-DSA-65"

    # The bug's exact symptom: RSA credited with the pubkey buffer, and/or
    # Ed25519 credited with the signature buffer.
    assert _finding_for(findings, "RSA", "pubkey") is None, (
        "RSA must never be credited with Ed25519's pubkey buffer (cross-asset contamination)"
    )
    assert _finding_for(findings, "Ed25519", "signature") is None, (
        "Ed25519 must never be credited with RSA's signature buffer (cross-asset contamination)"
    )

    # Every RSA-attributed finding must carry RSA's own 256-byte constraint
    # only (plus the generously-sized 8192-byte non-firing buffer, which
    # never produces a finding at all -- see the golden manifest).
    rsa_declared_bytes = {f.size_constraint.declared_bytes for f in findings if f.asset_name == "RSA"}
    assert rsa_declared_bytes == {256}, f"RSA's findings must only be its own buffer(s): {rsa_declared_bytes}"

    ed25519_declared_bytes = {f.size_constraint.declared_bytes for f in findings if f.asset_name == "Ed25519"}
    assert ed25519_declared_bytes == {32}, f"Ed25519's findings must only be its own buffer(s): {ed25519_declared_bytes}"


def test_pqc_family_comes_from_correlated_assets_own_primitive() -> None:
    """Regression for BUG 1's second half: the PQC replacement family must
    come from the CORRELATED asset's own primitive, never a hardcoded
    default. A pke-primitive RSA (e.g. RSA_generate_key_ex/RSA_public_encrypt
    in rules/c_openssl.yaml) must be checked against ML-KEM-768 (pubkey/
    ciphertext sizes, rules/pqc_sizes.yaml), never ML-DSA -- that's reserved
    for signature-primitive assets (ECDSA, Ed25519, RSA used for signing).
    """

    def _ev(line: int) -> Evidence:
        return Evidence(source_type="source", locator="x.c", line=line, detector_id="d", detector_version="0")

    rsa_pke = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.PKE,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[_ev(5)],
    )
    ecdsa_signature = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="ECDSA",
        primitive=Primitive.SIGNATURE,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[_ev(50)],
    )
    pubkey_constraint = SizeConstraint(
        kind="stack_buffer", name="pubkey", declared_bytes=270, evidence=[_ev(6)], language="c"
    )
    signature_constraint = SizeConstraint(
        kind="stack_buffer", name="signature", declared_bytes=72, evidence=[_ev(51)], language="c"
    )

    findings = compute_blast_radius([rsa_pke, ecdsa_signature], [pubkey_constraint, signature_constraint])

    rsa_finding = _finding_for(findings, "RSA", "pubkey")
    assert rsa_finding is not None
    assert rsa_finding.pqc_replacement_name == "ML-KEM-768"

    ecdsa_finding = _finding_for(findings, "ECDSA", "signature")
    assert ecdsa_finding is not None
    assert ecdsa_finding.pqc_replacement_name == "ML-DSA-65"


def test_primitive_for_replacement_helper() -> None:
    assert primitive_for_replacement("ML-DSA-65") == Primitive.SIGNATURE
    assert primitive_for_replacement("ML-KEM-768") == Primitive.KEM
    assert primitive_for_replacement("unknown-family") == Primitive.UNKNOWN
