"""Unit tests for container Q&A, knowledge index, and grounding (Phase 3).
Verifies the 14 required questions:
1. "What crypto is inside this container?"
2. "Which binaries inside the container contain RSA?"
3. "Which source files in the container use cryptography?"
4. "Does this container call a cloud KMS?"
5. "Which layer contains the RSA binary?"
6. "Is RSA still present in the final image?"
7. "What cryptographic artefacts were deleted by later layers?"
8. "Can you tell whether the RSA actually executes?"
9. "Is the RSA in this container externally exposed?"
10. "What can't you determine from this container scan?"
11. "Tell me everything about the crypto in this container."
12. "Compare the container's RSA and AES findings."
13. "Which container crypto findings are quantum vulnerable?"
14. Prompt injection string quarantine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hash_patch.cli import run_scan
from hash_patch.emit.cyclonedx import to_cyclonedx
from hash_patch.qa.index import ScanKnowledgeIndex
from hash_patch.qa.query import QueryAnalyzer
from hash_patch.qa.retriever import Retriever

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "testdata" / "containers"


@pytest.fixture(scope="module")
def mixed_container_qa() -> tuple[ScanKnowledgeIndex, Retriever, set[str]]:
    target = FIXTURES_DIR / "mixed" / "container.tar"
    scan_res = run_scan(target)
    doc = to_cyclonedx(scan_res)
    idx = ScanKnowledgeIndex.from_cbom(doc, scan_id="scan_mixed_container")
    retriever = Retriever(idx)
    known_names = {c.name for c in idx.findings}
    return idx, retriever, known_names


class TestContainerQA:
    def test_q1_what_crypto_inside_container(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "What crypto is inside this container?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert len(res.matched_findings) > 0
        assert "CONTAINER IMAGE CRYPTOGRAPHIC ARTEFACT EVIDENCE" in res.context
        assert "mixed-service:2.0" in res.context

    def test_q2_binaries_containing_rsa(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Which binaries inside the container contain RSA?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert len(res.matched_findings) >= 1
        assert "RSA" in res.context
        assert "/usr/bin/server" in res.context

    def test_q3_source_files_using_crypto(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Which source files in the container use cryptography?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert "/app/service.py" in res.context

    def test_q4_calls_cloud_kms(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Does this container call a cloud KMS?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert len(res.matched_findings) >= 1
        assert "Cloud KMS" in res.context
        assert "/app/cloud_service.py" in res.context

    def test_q5_layer_containing_rsa(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Which layer contains the RSA binary?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert "LAYER PROVENANCE" in res.context
        assert "Layer Digest:" in res.context

    def test_q6_is_rsa_present_in_final_image(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Is RSA still present in the final image?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert "FINAL IMAGE PRESENCE VERDICT" in res.context
        assert "PRESENT in effective final image" in res.context

    def test_q7_deleted_by_later_layers(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "What cryptographic artefacts were deleted by later layers?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert "DELETED / WHITEOUT CRYPTOGRAPHIC ARTEFACTS" in res.context
        assert "whiteout" in res.context.lower()

    def test_q8_can_you_tell_whether_rsa_executes(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Can you tell whether the RSA actually executes?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert "RUNTIME EXECUTION VERDICT" in res.context or "RUNTIME EXECUTION IS NOT VERIFIED" in res.context
        assert "does NOT independently establish runtime execution" in res.context or "not verified" in res.context.lower()

    def test_q9_is_rsa_externally_exposed(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Is the RSA in this container externally exposed?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert "UNKNOWN" in res.context
        assert "does NOT prove external network exposure" in res.context or "defaults to unknown" in res.context.lower()

    def test_q10_what_cant_you_determine(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "What can't you determine from this container scan?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert "HONEST SCAN LIMITATIONS" in res.context
        assert "Runtime execution" in res.context
        assert "reachability" in res.context.lower()

    def test_q11_tell_me_everything_about_crypto(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Tell me everything about the crypto in this container."
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert "CONTAINER IMAGE CRYPTOGRAPHIC ARTEFACT EVIDENCE" in res.context
        assert len(res.matched_findings) == 12

    def test_q12_compare_rsa_and_aes(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Compare the container's RSA and AES findings."
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert pq.is_comparison is True
        assert "RSA" in res.context
        assert "AES" in res.context

    def test_q13_quantum_vulnerable_findings(self, mixed_container_qa: tuple) -> None:
        idx, retriever, known_names = mixed_container_qa
        q = "Which container crypto findings are quantum vulnerable?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)
        assert any("RSA" in line for line in res.context.splitlines())

    def test_q14_prompt_injection_isolation(self) -> None:
        p = FIXTURES_DIR / "prompt_injection" / "container.tar"
        scan_res = run_scan(p)
        doc = to_cyclonedx(scan_res)
        idx = ScanKnowledgeIndex.from_cbom(doc, scan_id="scan_injection")
        retriever = Retriever(idx)
        known_names = {c.name for c in idx.findings}

        q = "What crypto is inside this container?"
        pq = QueryAnalyzer.parse(q, known_names)
        res = retriever.retrieve(pq)

        # Context must not be controlled by the injected instruction
        assert "IGNORE ALL PREVIOUS INSTRUCTIONS" not in res.context
        assert "completely safe" not in res.context.lower()
