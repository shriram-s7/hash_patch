"""tests/unit/test_algorithm_contradictions.py

Unit tests for Pillar 4's second contradiction shape:
  hash_patch/analyze/algorithm_contradictions.py

Section 1: the fixture this module was built and verified against —
testdata/go/policy_divergence/{policy.go,signer.go} — a self-contained copy
of the exact scenario reported against the adversarial corpus: a policy
function declares ECDSA for one partner branch, but the caller unconditionally
signs with RSA on that same, unguarded path.

Section 2: negative cases — a policy value that IS actually implemented, or
that's explicitly guarded away, must never fire.
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.analyze.algorithm_contradictions import compute_algorithm_contradictions
from hash_patch.detect.go import GoCryptoDetector

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "testdata" / "go" / "policy_divergence"
POLICY_FILE = FIXTURE_DIR / "policy.go"
SIGNER_FILE = FIXTURE_DIR / "signer.go"


def _scan_fixture() -> tuple[list, list[Path]]:
    detector = GoCryptoDetector()
    files = [POLICY_FILE, SIGNER_FILE]
    assets = []
    for f in files:
        assets.extend(detector.detect(f))
    return assets, files


# ===========================================================================
# Section 1 — the verification fixture: declared ECDSA, implemented RSA.
# ===========================================================================


def test_declared_ecdsa_implemented_rsa_is_flagged() -> None:
    assets, files = _scan_fixture()
    findings = compute_algorithm_contradictions(assets, files)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.declared_algorithm == "ECDSA"
    assert finding.implemented_algorithm == "RSASSA-PKCS1v15"
    assert finding.declaring_function == "SignatureFamily"
    assert finding.call_site_function == "Sign"

    # Evidence must point at BOTH real locations: the declaring line in
    # policy.go (where "ECDSA" is actually declared) and the diverging call
    # site in signer.go (where RSA is actually invoked) — never the same
    # file/line for both, and never a fabricated position.
    assert Path(finding.declaring_evidence.locator).name == "policy.go"
    assert Path(finding.call_site_evidence.locator).name == "signer.go"
    assert finding.declaring_evidence.line == 6  # `EllipticSignature = "ECDSA"`
    assert finding.call_site_evidence.line == 26  # `rsa.SignPKCS1v15(...)`
    assert "policy.go:6" in finding.description
    assert "signer.go:26" in finding.description


def test_finding_is_deterministic() -> None:
    assets_a, files = _scan_fixture()
    assets_b, _ = _scan_fixture()
    findings_a = compute_algorithm_contradictions(assets_a, files)
    findings_b = compute_algorithm_contradictions(assets_b, files)
    assert [f.id for f in findings_a] == [f.id for f in findings_b]


# ===========================================================================
# Section 2 — negative cases.
# ===========================================================================


def test_no_size_signal_no_findings_when_no_go_files() -> None:
    assert compute_algorithm_contradictions([], []) == []


def test_matching_declared_and_implemented_is_not_flagged(tmp_path: Path) -> None:
    """When the policy declares RSA and the call site also does RSA, that's
    consistent -- never a contradiction.
    """
    (tmp_path / "policy.go").write_text(
        'package crypto\n\nconst Family = "RSA"\n\n'
        "func SelectFamily() string {\n    return Family\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "signer.go").write_text(
        'package crypto\n\nimport "crypto/rsa"\n\n'
        "func Sign(key *rsa.PrivateKey) {\n"
        "    _ = SelectFamily()\n"
        "    rsa.GenerateKey(nil, 2048)\n"
        "}\n",
        encoding="utf-8",
    )
    files = [tmp_path / "policy.go", tmp_path / "signer.go"]
    detector = GoCryptoDetector()
    assets = []
    for f in files:
        assets.extend(detector.detect(f))

    findings = compute_algorithm_contradictions(assets, files)
    assert findings == []


def test_guarded_branch_is_not_flagged(tmp_path: Path) -> None:
    """When the operation call is explicitly excluded for the declared value
    (nested in the ALTERNATIVE of an `if` naming it), that branch is
    considered handled elsewhere and must not be flagged.
    """
    (tmp_path / "policy.go").write_text(
        'package crypto\n\nconst Family = "ECDSA"\n\n'
        "func SelectFamily() string {\n    return Family\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "signer.go").write_text(
        'package crypto\n\nimport "crypto/rsa"\n\n'
        "func Sign(key *rsa.PrivateKey) {\n"
        "    family := SelectFamily()\n"
        '    if family == "ECDSA" {\n'
        "        return\n"
        "    } else {\n"
        "        rsa.GenerateKey(nil, 2048)\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    files = [tmp_path / "policy.go", tmp_path / "signer.go"]
    detector = GoCryptoDetector()
    assets = []
    for f in files:
        assets.extend(detector.detect(f))

    findings = compute_algorithm_contradictions(assets, files)
    assert findings == []
