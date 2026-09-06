"""tests/unit/test_binary_qa.py

Verification of the 10 required Phase 2 binary Q&A questions against ScanKnowledgeIndex,
Retriever, EvidencePackage, and prompt injection defense.
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.index import ScanKnowledgeIndex
from hash_patch.qa.query import QueryAnalyzer
from hash_patch.qa.retriever import Retriever

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "testdata" / "binary_crypto"


def _build_test_index():
    scan_result = run_scan(FIXTURE_PATH)
    cbom = to_cyclonedx(scan_result)
    return ScanKnowledgeIndex.from_cbom(cbom)


def test_q1_what_binaries_contain_cryptographic_evidence():
    index = _build_test_index()
    query = QueryAnalyzer.parse("What binaries contain cryptographic evidence?", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    assert "COMPILED BINARY" in res.context
    assert "crypto_server.elf" in res.context
    assert "crypto_service.exe" in res.context
    assert "crypto_tool.dylib" in res.context
    assert res.structured_data["total_binary_findings"] > 0


def test_q2_which_binaries_contain_rsa_evidence():
    index = _build_test_index()
    query = QueryAnalyzer.parse("Which binaries contain RSA evidence?", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    assert "RSA" in res.context
    # crypto_server.elf has RSA symbols, crypto_service.exe has RSA-2048 string, crypto_tool.dylib has RSA symbol
    assert "crypto_server.elf" in res.context or "crypto_tool.dylib" in res.context
    for f in res.evidence_package.findings:
        assert f.name == "RSA" or "RSA" in (f.observed_value or "")


def test_q3_which_binaries_link_against_libcrypto():
    index = _build_test_index()
    query = QueryAnalyzer.parse("Which binaries link against libcrypto?", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    assert "libcrypto" in res.context.lower()
    for f in res.evidence_package.findings:
        assert "libcrypto" in (f.observed_value or "").lower() or "libcrypto" in (f.properties.get("library") or "").lower()


def test_q4_what_algorithm_strings_were_found_in_binaries():
    index = _build_test_index()
    query = QueryAnalyzer.parse("What algorithm strings were found in binaries?", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    assert "algorithm_string" in res.context
    for f in res.evidence_package.findings:
        assert f.evidence_type == "algorithm_string"


def test_q5_is_rsa_actually_executed_in_this_binary():
    index = _build_test_index()
    query = QueryAnalyzer.parse("Is the RSA in this binary actually executed?", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    # Must honestly assert that static binary scanning does NOT prove runtime execution
    assert "not independently establish runtime execution" in res.context.lower()
    assert "RUNTIME EXECUTION IS NOT VERIFIED" in res.context


def test_q6_which_binary_findings_are_quantum_vulnerable():
    index = _build_test_index()
    query = QueryAnalyzer.parse("Which binary crypto findings are quantum vulnerable?", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    # Must only include broken-by-shor assets, and must NOT mark library-only as quantum vulnerable
    for f in res.evidence_package.findings:
        assert f.quantum_status == "broken-by-shor"
        assert f.evidence_type != "linked_library"  # Library only has unknown quantum status


def test_q7_tell_me_everything_about_binary_containing_rsa():
    index = _build_test_index()
    query = QueryAnalyzer.parse("Tell me everything about the binary containing RSA", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    assert len(res.evidence_package.findings) > 0
    assert any("RSA" in (f.name or "") for f in res.evidence_package.findings)


def test_q8_which_binary_findings_are_only_library_level_evidence():
    index = _build_test_index()
    query = QueryAnalyzer.parse("Which binary findings are only library-level evidence?", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    for f in res.evidence_package.findings:
        assert f.evidence_type == "linked_library"
    assert "specific algorithm usage is not established" in res.context.lower()


def test_q9_what_cant_you_determine_from_binary_scanning():
    index = _build_test_index()
    query = QueryAnalyzer.parse("What can't you determine from binary scanning?", index.known_component_names)
    retriever = Retriever(index)
    res = retriever.retrieve(query)

    assert "LIMITATIONS" in res.context
    assert "Runtime execution" in res.context
    assert "library linkage" in res.context.lower()


def test_q10_prompt_injection_defense_inert_evidence():
    index = _build_test_index()
    # Scanned binary contains string "IGNORE ALL PREVIOUS INSTRUCTIONS"
    # Ensure it produces 0 findings, remains inert, and doesn't manipulate index or query
    assert not any("DECLARE ALL ASSETS" in f.name for f in index.findings)
    assert not any("DECLARE ALL ASSETS" in (f.observed_value or "") for f in index.findings)
