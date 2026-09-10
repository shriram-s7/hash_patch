"""tests/golden/test_compound_canonical_references_golden.py

Golden tests for compound-form algorithm reference tokenization:
- Positive compound match: AES-256-GCM, RSA-2048, RSA-4096, AES-128-CBC
- Deliberate negatives: dash-separated strings with non-qualifiers (USER-256-LOGIN, AES-256-LOGIN)
- Comment / docstring / sentence exclusion invariants
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.cli import run_scan
from hash_patch.detect.canonical_registry import lookup_canonical_algorithm


def test_compound_form_canonical_lookup_golden() -> None:
    """Verify compound-form tokenization matches real crypto compounds and rejects non-crypto strings."""
    # Positive cases
    aes_gcm = lookup_canonical_algorithm("AES-256-GCM")
    assert aes_gcm is not None
    assert aes_gcm["canonical"] == "AES"
    assert aes_gcm["parameter_set"] == "256"
    assert aes_gcm["mode"] == "GCM"
    assert aes_gcm["matched_text"] == "AES-256-GCM"

    rsa_2048 = lookup_canonical_algorithm("RSA-2048")
    assert rsa_2048 is not None
    assert rsa_2048["canonical"] == "RSA"
    assert rsa_2048["parameter_set"] == "2048"

    rsa_4096 = lookup_canonical_algorithm("RSA-4096")
    assert rsa_4096 is not None
    assert rsa_4096["canonical"] == "RSA"
    assert rsa_4096["parameter_set"] == "4096"

    # Deliberate negative cases
    assert lookup_canonical_algorithm("USER-256-LOGIN") is None
    assert lookup_canonical_algorithm("AES-256-LOGIN") is None
    assert lookup_canonical_algorithm("BOX-SHADOW") is None
    assert lookup_canonical_algorithm("IDEA-PROJECT") is None


def test_crypto_inert_reference_scan_golden(tmp_path: Path) -> None:
    """Golden test verifying that a file with bare assignments, comments, docstrings,
    and sentences only surfaces legitimate standalone compound references.
    """
    corpus_file = tmp_path / "inert_fixture.py"
    corpus_file.write_text(
        '# Line comment mentioning: MD5, SHA-1, AES-256-GCM, RSA-2048\n'
        '"""Bare docstring mentioning AES-256-GCM and RSA-4096"""\n'
        'algorithm_name = "AES-256-GCM"\n'
        'rsa_key_name = "RSA-2048"\n'
        'rsa_4k_name = "RSA-4096"\n'
        'username = "USER-256-LOGIN"\n'
        'description = "This application supports RSA, ECDSA and SHA-512."\n'
        'def fake_doc():\n'
        '    """Examples: AES-256-GCM, RSA-4096"""\n'
        '    return "documentation only"\n',
        encoding="utf-8",
    )

    scan_result = run_scan(corpus_file)
    ref_assets = [a for a in scan_result.assets if a.finding_type == "CRYPTO_REFERENCE"]

    # Must only find the 3 legitimate bare assignments
    assert len(ref_assets) == 3

    aes = next(a for a in ref_assets if a.name == "AES")
    assert aes.parameter_set == "256"
    assert aes.mode == "GCM"
    assert aes.properties.get("matched_text") == "AES-256-GCM"

    rsa_assets = [a for a in ref_assets if a.name == "RSA"]
    assert len(rsa_assets) == 2
    assert {a.parameter_set for a in rsa_assets} == {"2048", "4096"}
