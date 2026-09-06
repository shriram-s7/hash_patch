"""tests/unit/test_qa_natural_language.py — Natural-language query understanding tests.

Phase 4 verification:
Validates that Hash Patch reliably translates ordinary human English into structured
NormalizedQueries and retrieves grounded EvidencePackages without requiring internal
intent names or exact database identifiers.

Categories tested:
1. Overview ("what did you find?", "what's going on?", "what's the big picture?", "what's the bad stuff?", "what should I care about?")
2. Usage ("what's actually being used?", "what crypto is live?", "what crypto is dead?", "what's exposed externally?")
3. Quantum ("what's broken by Shor?", "what is quantum vulnerable?", "what survives quantum?")
4. Entity ("tell me about RSA", "tell me about RSA crypto", "where is SHA 256?", "what AES modes are present?", "tell me about elliptic curve crypto")
5. Relationships ("who calls RSA?", "what depends on RSA?", "what calls it?")
6. Migration ("what should I fix first?", "where should I start?", "what will be hardest to migrate?")
7. Blast radius ("what will break if RSA changes?", "what gets affected if I replace RSA?")
8. Sensitivity ("which crypto protects financial data?", "what has the longest shelf life?")
9. References ("where is RSA only mentioned?", "show me crypto references")
10. Comparison ("RSA vs ECDSA", "which is worse, RSA or ECDSA?", "which is more exposed?")
11. Conversation multi-turn sequence:
    - "tell me about RSA" -> "is it live?" -> "where is it used?" -> "who calls it?" -> "what about ECDSA?" -> "which one should I fix first?"
12. Negative & Out of scope:
    - "tell me about Kyber" (when Kyber is absent)
    - Unrelated non-scan questions
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.index import ScanKnowledgeIndex
from hash_patch.qa.query import ConversationContext, QueryAnalyzer
from hash_patch.qa.retriever import Retriever

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def test2_index() -> ScanKnowledgeIndex:
    scan_res = run_scan(REPO_ROOT / "test2")
    cbom = to_cyclonedx(scan_res)
    sample_plan = {
        "budget_days": 60.0,
        "scenarios": [
            {
                "scenario_name": "Risk-Optimal PQC Migration",
                "probability_weight": 1.0,
                "estimated_year": 2030,
                "headline_message": "Eliminates 92.4% of total quantum exposure",
                "optimizer_plan": {
                    "eliminated_risk": 92.4,
                    "schedule": [
                        {"name": "RSA", "start_day": 0, "end_day": 12, "cost_days": 12.0},
                        {"name": "ECDSA", "start_day": 12, "end_day": 20, "cost_days": 8.0},
                    ],
                    "unmigrated_finding_ids": [],
                },
                "naive_plan": {"eliminated_risk": 55.0},
            }
        ],
    }
    return ScanKnowledgeIndex.from_cbom(cbom, plan=sample_plan, scan_id="test2_scan")


# ---------------------------------------------------------------------------
# 1. Overview
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "question",
    [
        "what did you find?",
        "what's going on?",
        "what's going on here?",
        "give me the big picture",
        "what's the bad stuff?",
        "what should I care about?",
        "what actually matters?",
    ],
)
def test_overview_queries(test2_index: ScanKnowledgeIndex, question: str):
    parsed = QueryAnalyzer.parse(question, test2_index.known_component_names)
    assert parsed.intent in ("OVERVIEW", "GENERAL")
    if "bad stuff" in question:
        assert parsed.ranking == "risk"
    retriever = Retriever(test2_index)
    res = retriever.retrieve(parsed)
    assert res.context is not None
    assert "===" in res.context


# ---------------------------------------------------------------------------
# 2. Usage & Reachability
# ---------------------------------------------------------------------------


def test_usage_live_and_dead(test2_index: ScanKnowledgeIndex):
    # what is actually being used
    q_used = QueryAnalyzer.parse("what's actually being used?", test2_index.known_component_names)
    assert q_used.intent == "REACHABILITY"
    assert q_used.reachability_filter == "live"
    res_used = Retriever(test2_index).retrieve(q_used)
    assert "Live" in res_used.context

    # what crypto is live
    q_live = QueryAnalyzer.parse("what crypto is live?", test2_index.known_component_names)
    assert q_live.intent == "REACHABILITY"
    assert q_live.reachability_filter == "live"

    # what crypto is dead
    q_dead = QueryAnalyzer.parse("what crypto is dead?", test2_index.known_component_names)
    assert q_dead.intent == "REACHABILITY"
    assert q_dead.reachability_filter == "inert"
    res_dead = Retriever(test2_index).retrieve(q_dead)
    assert "Inert Findings" in res_dead.context

    # what's exposed externally
    q_ext = QueryAnalyzer.parse("what's exposed externally?", test2_index.known_component_names)
    assert q_ext.intent == "REACHABILITY"
    assert q_ext.reachability_filter == "live-external"
    res_ext = Retriever(test2_index).retrieve(q_ext)
    assert "External" in res_ext.context


# ---------------------------------------------------------------------------
# 3. Quantum
# ---------------------------------------------------------------------------


def test_quantum_queries(test2_index: ScanKnowledgeIndex):
    # what's broken by Shor
    q_shor = QueryAnalyzer.parse("what's broken by Shor?", test2_index.known_component_names)
    assert q_shor.intent == "VULNERABILITY"
    assert q_shor.quantum_filter == "broken-by-shor"
    res_shor = Retriever(test2_index).retrieve(q_shor)
    assert "Broken by Shor" in res_shor.context

    # what is quantum vulnerable
    q_vuln = QueryAnalyzer.parse("what is quantum vulnerable?", test2_index.known_component_names)
    assert q_vuln.intent == "VULNERABILITY"

    # what survives quantum
    q_safe = QueryAnalyzer.parse("what survives quantum?", test2_index.known_component_names)
    assert q_safe.intent == "VULNERABILITY"
    assert q_safe.quantum_filter == "quantum-safe"
    res_safe = Retriever(test2_index).retrieve(q_safe)
    assert "Quantum-Safe" in res_safe.context


# ---------------------------------------------------------------------------
# 4. Entity & Family Resolution
# ---------------------------------------------------------------------------


def test_entity_queries(test2_index: ScanKnowledgeIndex):
    # tell me about RSA
    q_rsa = QueryAnalyzer.parse("tell me about RSA", test2_index.known_component_names)
    assert q_rsa.intent == "FINDINGS_LOOKUP"
    assert "RSA" in q_rsa.entities

    # tell me about RSA crypto
    q_rsa_crypto = QueryAnalyzer.parse("tell me about RSA crypto", test2_index.known_component_names)
    assert "RSA" in q_rsa_crypto.entities

    # where is SHA 256?
    q_sha = QueryAnalyzer.parse("where is SHA 256?", test2_index.known_component_names)
    assert "SHA-256" in q_sha.entities

    # what AES modes are present?
    q_aes = QueryAnalyzer.parse("what AES modes are present?", test2_index.known_component_names)
    assert any("AES" in ent for ent in q_aes.entities)

    # tell me about elliptic curve crypto (family query)
    q_ec = QueryAnalyzer.parse("tell me about elliptic curve crypto", test2_index.known_component_names)
    assert q_ec.intent == "FINDINGS_LOOKUP"
    # Should resolve to all EC family entities present in test2
    assert "ECDSA" in q_ec.entities
    assert "ECDH" in q_ec.entities
    assert "Ed25519" in q_ec.entities


# ---------------------------------------------------------------------------
# 5. Relationships
# ---------------------------------------------------------------------------


def test_relationship_queries(test2_index: ScanKnowledgeIndex):
    # who calls RSA?
    q_who = QueryAnalyzer.parse("who calls RSA?", test2_index.known_component_names)
    assert q_who.intent == "RELATIONSHIPS"
    assert "RSA" in q_who.entities
    res_who = Retriever(test2_index).retrieve(q_who)
    assert "CALL GRAPH" in res_who.context or "Callers" in res_who.context

    # what depends on RSA?
    q_dep = QueryAnalyzer.parse("what depends on RSA?", test2_index.known_component_names)
    assert q_dep.intent == "RELATIONSHIPS"
    assert "RSA" in q_dep.entities


# ---------------------------------------------------------------------------
# 6. Migration
# ---------------------------------------------------------------------------


def test_migration_queries(test2_index: ScanKnowledgeIndex):
    # what should I fix first?
    q_first = QueryAnalyzer.parse("what should I fix first?", test2_index.known_component_names)
    assert q_first.intent == "MIGRATION"
    assert q_first.ranking == "risk"
    res_first = Retriever(test2_index).retrieve(q_first)
    assert "MIGRATION PRIORITIZATION" in res_first.context

    # where should I start?
    q_start = QueryAnalyzer.parse("where should I start?", test2_index.known_component_names)
    assert q_start.intent == "MIGRATION"

    # what will be hardest to migrate?
    q_hard = QueryAnalyzer.parse("what will be hardest to migrate?", test2_index.known_component_names)
    assert q_hard.intent == "MIGRATION"
    assert q_hard.ranking == "cost"
    res_hard = Retriever(test2_index).retrieve(q_hard)
    assert "Largest Individual Migration Effort" in res_hard.context


# ---------------------------------------------------------------------------
# 7. Blast Radius
# ---------------------------------------------------------------------------


def test_blast_radius_queries(test2_index: ScanKnowledgeIndex):
    # what will break if RSA changes?
    q_break = QueryAnalyzer.parse("what will break if RSA changes?", test2_index.known_component_names)
    assert q_break.intent == "BLAST_RADIUS"
    assert "RSA" in q_break.entities

    # what gets affected if I replace RSA?
    q_rep = QueryAnalyzer.parse("what gets affected if I replace RSA?", test2_index.known_component_names)
    assert q_rep.intent == "BLAST_RADIUS"
    assert "RSA" in q_rep.entities

    # what depends on RSA changing?
    q_dep_ch = QueryAnalyzer.parse("what depends on RSA changing?", test2_index.known_component_names)
    assert q_dep_ch.intent == "BLAST_RADIUS"
    assert "RSA" in q_dep_ch.entities

    # what has the biggest blast radius?
    q_big = QueryAnalyzer.parse("what has the biggest blast radius?", test2_index.known_component_names)
    assert q_big.intent == "BLAST_RADIUS"
    assert q_big.ranking == "blast_radius"


# ---------------------------------------------------------------------------
# 8. Sensitivity & Shelf-Life
# ---------------------------------------------------------------------------


def test_sensitivity_queries(test2_index: ScanKnowledgeIndex):
    # which crypto protects financial data?
    q_fin = QueryAnalyzer.parse("which crypto protects financial data?", test2_index.known_component_names)
    assert q_fin.intent == "SENSITIVE_DATA"
    assert q_fin.filters.get("sensitivity_category") == "financial"
    res_fin = Retriever(test2_index).retrieve(q_fin)
    assert "SHELF-LIFE" in res_fin.context

    # what has the longest shelf life?
    q_sl = QueryAnalyzer.parse("what has the longest shelf life?", test2_index.known_component_names)
    assert q_sl.intent == "SENSITIVE_DATA"
    assert q_sl.ranking == "shelf_life"
    res_sl = Retriever(test2_index).retrieve(q_sl)
    assert "SHELF-LIFE" in res_sl.context


# ---------------------------------------------------------------------------
# 9. References
# ---------------------------------------------------------------------------


def test_references_queries(test2_index: ScanKnowledgeIndex):
    # where is RSA only mentioned?
    q_ref_rsa = QueryAnalyzer.parse("where is RSA only mentioned?", test2_index.known_component_names)
    assert q_ref_rsa.intent == "REFERENCES"
    assert "RSA" in q_ref_rsa.entities
    assert q_ref_rsa.filters.get("finding_type") == "CRYPTO_REFERENCE"

    # show me crypto references
    q_refs = QueryAnalyzer.parse("show me crypto references", test2_index.known_component_names)
    assert q_refs.intent == "REFERENCES"
    res_refs = Retriever(test2_index).retrieve(q_refs)
    assert "CRYPTO_REFERENCE" in res_refs.context

    # how many crypto references are there?
    q_cnt = QueryAnalyzer.parse("how many crypto references are there?", test2_index.known_component_names)
    assert q_cnt.intent == "REFERENCES"
    assert q_cnt.aggregation_type == "count"

    # are there any SHA1 references?
    q_sha1 = QueryAnalyzer.parse("are there any SHA1 references?", test2_index.known_component_names)
    assert q_sha1.intent == "REFERENCES"
    assert "SHA-1" in q_sha1.entities


# ---------------------------------------------------------------------------
# 10. Comparison
# ---------------------------------------------------------------------------


def test_comparison_queries(test2_index: ScanKnowledgeIndex):
    # RSA vs ECDSA
    q_vs = QueryAnalyzer.parse("RSA vs ECDSA", test2_index.known_component_names)
    assert q_vs.intent == "COMPARISON"
    assert set(q_vs.comparison_targets) == {"RSA", "ECDSA"}

    # which is worse, RSA or ECDSA?
    q_worse = QueryAnalyzer.parse("which is worse, RSA or ECDSA?", test2_index.known_component_names)
    assert q_worse.intent == "COMPARISON"
    assert set(q_worse.comparison_targets) == {"RSA", "ECDSA"}
    assert q_worse.ranking == "risk"
    res_worse = Retriever(test2_index).retrieve(q_worse)
    assert "COMPARISON: " in res_worse.context
    assert "RSA" in res_worse.context and "ECDSA" in res_worse.context

    # which is more exposed? (with targets in query)
    q_exp = QueryAnalyzer.parse("which is more exposed, RSA or ECDSA?", test2_index.known_component_names)
    assert q_exp.intent == "COMPARISON"
    assert set(q_exp.comparison_targets) == {"RSA", "ECDSA"}


# ---------------------------------------------------------------------------
# 11. Multi-turn Conversational Coreference
# ---------------------------------------------------------------------------


def test_multiturn_conversational_coreference(test2_index: ScanKnowledgeIndex):
    conv = ConversationContext(scan_id=test2_index.scan_id)
    retriever = Retriever(test2_index)

    # Turn 1: "Tell me about RSA."
    t1 = QueryAnalyzer.parse("Tell me about RSA.", test2_index.known_component_names, conv, scan_id=test2_index.scan_id)
    assert t1.intent == "FINDINGS_LOOKUP"
    assert "RSA" in t1.entities
    res1 = retriever.retrieve(t1)
    conv.update("Tell me about RSA.", res1.context, t1)
    assert conv.active_findings == ["RSA"]

    # Turn 2: "Is it live?"
    t2 = QueryAnalyzer.parse("Is it live?", test2_index.known_component_names, conv, scan_id=test2_index.scan_id)
    assert t2.intent == "FINDINGS_LOOKUP"
    assert "RSA" in t2.entities
    res2 = retriever.retrieve(t2)
    conv.update("Is it live?", res2.context, t2)
    assert "RSA" in res2.context

    # Turn 3: "Where is it used?"
    t3 = QueryAnalyzer.parse("Where is it used?", test2_index.known_component_names, conv, scan_id=test2_index.scan_id)
    assert t3.intent == "FINDINGS_LOOKUP"
    assert "RSA" in t3.entities
    res3 = retriever.retrieve(t3)
    conv.update("Where is it used?", res3.context, t3)

    # Turn 4: "Who calls it?"
    t4 = QueryAnalyzer.parse("Who calls it?", test2_index.known_component_names, conv, scan_id=test2_index.scan_id)
    assert t4.intent == "RELATIONSHIPS"
    assert "RSA" in t4.entities
    res4 = retriever.retrieve(t4)
    conv.update("Who calls it?", res4.context, t4)

    # Turn 5: "What happens if I replace it?"
    t5 = QueryAnalyzer.parse("What happens if I replace it?", test2_index.known_component_names, conv, scan_id=test2_index.scan_id)
    assert t5.intent == "BLAST_RADIUS"
    assert "RSA" in t5.entities
    res5 = retriever.retrieve(t5)
    conv.update("What happens if I replace it?", res5.context, t5)

    # Turn 6: "What about ECDSA?"
    t6 = QueryAnalyzer.parse("What about ECDSA?", test2_index.known_component_names, conv, scan_id=test2_index.scan_id)
    assert t6.intent == "FINDINGS_LOOKUP"
    assert "ECDSA" in t6.entities
    res6 = retriever.retrieve(t6)
    conv.update("What about ECDSA?", res6.context, t6)
    assert conv.active_findings == ["ECDSA"]
    assert "RSA" in conv.comparison_findings and "ECDSA" in conv.comparison_findings

    # Turn 7: "Which one should I fix first?"
    t7 = QueryAnalyzer.parse("Which one should I fix first?", test2_index.known_component_names, conv, scan_id=test2_index.scan_id)
    assert t7.intent == "COMPARISON"
    assert set(t7.comparison_targets) == {"RSA", "ECDSA"}
    res7 = retriever.retrieve(t7)
    assert "COMPARISON: " in res7.context


# ---------------------------------------------------------------------------
# 12. Negative, Absent Entities & Out-of-Scope
# ---------------------------------------------------------------------------


def test_absent_entity_not_hallucinated():
    # When scan only contains RSA and ECDSA, asking for Kyber must NOT resolve to a known entity
    known_names = {"RSA", "ECDSA"}
    q_kyber = QueryAnalyzer.parse("tell me about Kyber", known_names)
    assert q_kyber.entities == []
    assert len(q_kyber.unresolved_entities) > 0


def test_out_of_scope_rejection(test2_index: ScanKnowledgeIndex):
    q_code = QueryAnalyzer.parse("write me a Python web server", test2_index.known_component_names)
    assert q_code.is_out_of_scope is True

    q_weather = QueryAnalyzer.parse("what is today's weather?", test2_index.known_component_names)
    assert q_weather.is_out_of_scope is True

    q_cricket = QueryAnalyzer.parse("who won the cricket match?", test2_index.known_component_names)
    assert q_cricket.is_out_of_scope is True


def test_contradictions_and_unknowns(test2_index: ScanKnowledgeIndex):
    q_contra = QueryAnalyzer.parse("what are the contradictions?", test2_index.known_component_names)
    assert q_contra.intent == "REPORT"
    res_contra = Retriever(test2_index).retrieve(q_contra)
    assert "CONTRADICTIONS" in res_contra.context

    q_unknown = QueryAnalyzer.parse("what couldn't you determine?", test2_index.known_component_names)
    assert q_unknown.intent == "REPORT"
    res_unknown = Retriever(test2_index).retrieve(q_unknown)
    assert "LIMITATIONS" in res_unknown.context or "Undetermined" in res_unknown.context
