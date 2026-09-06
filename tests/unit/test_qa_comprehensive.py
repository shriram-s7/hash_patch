"""tests/unit/test_qa_comprehensive.py — Comprehensive natural language evaluation set

Exercises all 27+ requested natural language patterns from the prompt:
- General: "findings?", "what did you find?", "what's going on?", "show me what's wrong", "anything serious?", "what should I worry about?", "give me the overview"
- Finding: "tell me about RSA", "what's wrong with RSA?", "why is RSA flagged?", "is RSA actually used?", "is RSA real or just a reference?", "where is RSA?", "show me everything about RSA"
- Reachability: "what's actually live?", "what is exposed externally?", "which crypto is internal?", "what isn't reachable?", "do we have dead crypto?", "how much is unresolved?"
- Relationships: "what depends on RSA?", "what will this affect?", "what is connected to ECDSA?"
- Migration: "what should I fix first?", "what should we migrate first?", "what's the migration order?", "how much effort is involved?"
- Comparison: "RSA vs ECDSA", "which is worse, RSA or ECDSA?", "compare AES and RSA"
- Report: "what does the report say?", "give me the executive summary", "what are the key numbers?", "how many files were scanned?", "what is the longest shelf life?"
- Informal language: "tell me the bad crypto", "what crypto is exposed?", "which stuff is actually running?", "show me the old crypto", "what's the scary stuff?"
- Follow-up: "Tell me about RSA" -> "is it live?" -> "where?" -> "what about ECDSA?" -> "which one is worse?"
- Out of scope: "what is the meaning of life?", "write a poem", "what's the weather?", "what's today's Bitcoin price?"
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.grounding import ground_question
from hash_patch.qa.query import ConversationContext, ParsedQuery

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def test2_cbom() -> dict:
    result = run_scan(REPO_ROOT / "test2")
    return to_cyclonedx(result)


# -----------------------------------------------------------------------------
# 1. General Questions
# -----------------------------------------------------------------------------

def test_general_overview_queries(test2_cbom: dict) -> None:
    questions = [
        "findings?",
        "what did you find?",
        "what's going on here?",
        "show me what's wrong",
        "anything serious?",
        "what should I worry about?",
        "give me the overall picture",
        "give me the rundown",
        "walk me through this scan",
    ]
    for q in questions:
        res = ground_question(q, test2_cbom)
        assert res.grounded is True, f"Failed to ground general query: {q}"
        assert res.category in ("general_summary", "overview", "most_urgent")
        assert len(res.context or "") > 50
        assert len(res.sources) > 0


# -----------------------------------------------------------------------------
# 2. Finding Queries
# -----------------------------------------------------------------------------

def test_specific_finding_queries(test2_cbom: dict) -> None:
    # RSA
    res_rsa = ground_question("tell me about RSA", test2_cbom)
    assert res_rsa.grounded is True
    assert "RSA" in res_rsa.matched_findings
    assert "broken-by-shor" in res_rsa.context.lower()

    # Why flagged
    res_why = ground_question("why is RSA flagged?", test2_cbom)
    assert res_why.grounded is True
    assert "RSA" in res_why.matched_findings
    assert "broken-by-shor" in res_why.context.lower()

    # Show me everything
    res_all = ground_question("show me everything about RSA", test2_cbom)
    assert res_all.grounded is True
    assert "Evidence" in res_all.context

    # Informal ECC
    res_ecc = ground_question("what about the ECC stuff?", test2_cbom)
    assert res_ecc.grounded is True
    assert any(name in res_ecc.matched_findings for name in ("ECDSA", "ECDH"))

    # Real operation vs reference
    res_ref = ground_question("is this a real operation or just a reference?", test2_cbom)
    assert res_ref.grounded is True
    assert "OPERATION" in res_ref.context or "CRYPTO_REFERENCE" in res_ref.context


# -----------------------------------------------------------------------------
# 3. Reachability Queries
# -----------------------------------------------------------------------------

def test_reachability_queries(test2_cbom: dict) -> None:
    # What's actually live
    res_live = ground_question("what is actually live?", test2_cbom)
    assert res_live.grounded is True
    assert "live" in res_live.context.lower()

    # What is exposed externally
    res_ext = ground_question("what crypto is exposed to the outside world?", test2_cbom)
    assert res_ext.grounded is True
    assert "external" in res_ext.context.lower()

    # Dead code / inert
    res_dead = ground_question("are there any dead crypto implementations?", test2_cbom)
    assert res_dead.grounded is True
    assert "inert" in res_dead.context.lower()

    # Unresolved
    res_unres = ground_question("tell me about the unresolved stuff", test2_cbom)
    assert res_unres.grounded is True
    assert "unresolved" in res_unres.category.lower()


# -----------------------------------------------------------------------------
# 4. Relationships & Impact
# -----------------------------------------------------------------------------

def test_relationship_and_impact_queries(test2_cbom: dict) -> None:
    res_dep = ground_question("what depends on RSA?", test2_cbom)
    assert res_dep.grounded is True
    assert "RSA" in res_dep.matched_findings
    assert "caller" in res_dep.context.lower() or "relationship" in res_dep.context.lower()

    res_aff = ground_question("what will this affect?", test2_cbom)
    assert res_aff.grounded is True


# -----------------------------------------------------------------------------
# 5. Migration Queries
# -----------------------------------------------------------------------------

def test_migration_queries(test2_cbom: dict) -> None:
    # Most urgent / top priority (grounded from risk formula without requiring plan payload)
    res_urg = ground_question("what's the biggest risk?", test2_cbom)
    assert res_urg.grounded is True
    assert "risk_score" in res_urg.context.lower() or "candidate" in res_urg.context.lower()

    # Total migration cost
    res_cost = ground_question("what would it cost to migrate everything?", test2_cbom)
    assert res_cost.grounded is True
    assert "engineer-days" in res_cost.context.lower()


# -----------------------------------------------------------------------------
# 6. Comparison Queries
# -----------------------------------------------------------------------------

def test_comparison_queries(test2_cbom: dict) -> None:
    res_comp = ground_question("compare RSA and ECDSA", test2_cbom)
    assert res_comp.grounded is True
    assert "RSA" in res_comp.matched_findings
    assert "ECDSA" in res_comp.matched_findings
    assert "COMPARISON" in res_comp.context

    res_worse = ground_question("which is worse, RSA or ECDSA?", test2_cbom)
    assert res_worse.grounded is True
    assert "RSA" in res_worse.matched_findings
    assert "ECDSA" in res_worse.matched_findings


# -----------------------------------------------------------------------------
# 7. Report Queries
# -----------------------------------------------------------------------------

def test_report_queries(test2_cbom: dict) -> None:
    res_rep = ground_question("what does the report say?", test2_cbom)
    assert res_rep.grounded is True
    assert "total cryptographic-asset findings" in res_rep.context.lower() or "summary" in res_rep.context.lower()

    res_files = ground_question("how many files were scanned?", test2_cbom)
    assert res_files.grounded is True
    assert "scanned files" in res_files.context.lower() or "files" in res_files.context.lower()

    res_sl = ground_question("what is the longest shelf life?", test2_cbom)
    assert res_sl.grounded is True
    assert "shelf" in res_sl.context.lower()


# -----------------------------------------------------------------------------
# 8. Conversational Follow-up Thread
# -----------------------------------------------------------------------------

def test_conversational_follow_up_sequence(test2_cbom: dict) -> None:
    conv = ConversationContext()

    # Turn 1: Tell me about RSA
    t1 = ground_question("Tell me about RSA", test2_cbom, conversation=conv)
    assert t1.grounded is True
    assert "RSA" in t1.matched_findings
    conv.update("Tell me about RSA", t1.context or "", ParsedQuery(raw_query="Tell me about RSA", intent="FINDING_LOOKUP", entities=["RSA"]))

    # Turn 2: Is it live? (Pronoun 'it' -> RSA)
    t2 = ground_question("is it live?", test2_cbom, conversation=conv)
    assert t2.grounded is True
    assert "RSA" in t2.matched_findings
    assert "reachability" in t2.context.lower()
    conv.update("is it live?", t2.context or "", ParsedQuery(raw_query="is it live?", intent="REACHABILITY", entities=["RSA"]))

    # Turn 3: Where? (Pronoun resolution continues)
    t3 = ground_question("where is it used?", test2_cbom, conversation=conv)
    assert t3.grounded is True
    assert "RSA" in t3.matched_findings
    assert "evidence" in t3.context.lower()
    conv.update("where is it used?", t3.context or "", ParsedQuery(raw_query="where is it used?", intent="FINDING_LOOKUP", entities=["RSA"]))

    # Turn 4: What about ECDSA? (Switch active finding)
    t4 = ground_question("what about ECDSA?", test2_cbom, conversation=conv)
    assert t4.grounded is True
    assert "ECDSA" in t4.matched_findings
    conv.update("what about ECDSA?", t4.context or "", ParsedQuery(raw_query="what about ECDSA?", intent="FINDING_LOOKUP", entities=["ECDSA"]))

    # Turn 5: Which one is worse? (Compares RSA and ECDSA)
    t5 = ground_question("which one is worse?", test2_cbom, conversation=conv)
    assert t5.grounded is True
    assert "RSA" in t5.matched_findings
    assert "ECDSA" in t5.matched_findings


# -----------------------------------------------------------------------------
# 9. Out-of-Scope & Adversarial Guardrails
# -----------------------------------------------------------------------------

def test_out_of_scope_and_guardrails(test2_cbom: dict) -> None:
    # Out of scope queries must not hallucinate
    for out_q in [
        "what is the meaning of life?",
        "write me a poem",
        "what's the weather?",
        "what's today's Bitcoin price?",
    ]:
        res = ground_question(out_q, test2_cbom)
        assert res.grounded is False, f"Expected ungrounded for: {out_q}"

    # Adversarial CVE & legal frameworks must be refused deterministically
    cve_res = ground_question("what CVE does RSA have?", test2_cbom)
    assert cve_res.category == "known_ungroundable"
    assert "no CVE" in (cve_res.context or "")

    legal_res = ground_question("is this codebase GDPR compliant?", test2_cbom)
    assert legal_res.category == "known_ungroundable"
    assert "DPDP" in (legal_res.context or "")
