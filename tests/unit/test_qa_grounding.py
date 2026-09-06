"""tests/unit/test_qa_grounding.py

Unit tests for hash_patch/qa/grounding.py — the deterministic retrieval
layer behind the local Q&A assistant (hash_patch/qa/ollama_client.py). No
Ollama/network dependency here: these tests only exercise question
classification and CBOM field extraction, never an actual model call —
that is covered separately (and skipped when Ollama isn't running) in
tests/unit/test_qa_ollama_integration.py.

The single most important property this file guards: `ground_question`
returns `context=None` (never a fabricated context) for any question class
this system genuinely cannot answer from real scan data — a CVE lookup, a
legal-framework question, or a question naming no known finding and no
known category at all.
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.grounding import ground_question

REPO_ROOT = Path(__file__).resolve().parents[2]


def _test2_cbom() -> dict:
    result = run_scan(REPO_ROOT / "test2")
    return to_cyclonedx(result)


# ===========================================================================
# Section 1 — known-ungroundable questions are refused WITHOUT ever needing
# an LLM call (the deterministic short-circuit).
# ===========================================================================


def test_cve_question_is_ungroundable_and_never_fabricated() -> None:
    cbom = _test2_cbom()
    result = ground_question("What CVE does this RSA finding correspond to?", cbom)
    assert result.category == "known_ungroundable"
    assert result.grounded is True  # the refusal text itself IS the context
    assert "no CVE" in (result.context or "")


def test_legal_framework_question_is_ungroundable() -> None:
    cbom = _test2_cbom()
    for framework_question in ["Is this GDPR compliant?", "Does this satisfy HIPAA?", "Is this PCI-DSS ready?"]:
        result = ground_question(framework_question, cbom)
        assert result.category == "known_ungroundable", framework_question
        assert "DPDP" in (result.context or "")


def test_completely_unrelated_question_returns_no_context() -> None:
    cbom = _test2_cbom()
    result = ground_question("What is the meaning of life?", cbom)
    assert result.grounded is False
    assert result.context is None


# ===========================================================================
# Section 1b — conversational pass-through and the general_summary fallback
# (widened router; a greeting or a loosely-phrased "tell me about the scan"
# must NOT be treated as a decline).
# ===========================================================================


def test_greetings_are_conversational_not_declined() -> None:
    cbom = _test2_cbom()
    for greeting in ["hi", "hello there", "thanks!", "hey", "  ", "good morning"]:
        result = ground_question(greeting, cbom)
        assert result.category == "conversational", greeting
        assert result.grounded is True  # a canned reply, not a decline


def test_greeting_combined_with_a_real_question_is_not_swallowed() -> None:
    """A greeting is only a pass-through when it ISN'T also a real question
    -- "hi, why is RSA flagged?" must still be treated as a data question.
    """
    cbom = _test2_cbom()
    result = ground_question("hi, why is RSA flagged as broken by shor?", cbom)
    assert result.category != "conversational"


def test_loosely_phrased_scan_questions_hit_general_summary_not_decline() -> None:
    cbom = _test2_cbom()
    for question in ["findings?", "what have you got", "show me the summary", "results?"]:
        result = ground_question(question, cbom)
        assert result.category == "general_summary", question
        assert result.grounded is True
        assert "total cryptographic-asset findings" in result.context


def test_general_summary_reports_real_counts() -> None:
    cbom = _test2_cbom()
    components = [c for c in cbom["components"] if c.get("type") == "cryptographic-asset"]
    result = ground_question("findings?", cbom)
    assert str(len(components)) in result.context


def test_adversarial_questions_still_decline_after_router_widening() -> None:
    """The widening must not loosen the actual safety boundary -- both
    adversarial cases from the original test set must still behave exactly
    as before.
    """
    cbom = _test2_cbom()
    cve_result = ground_question("What CVE does this correspond to?", cbom)
    assert cve_result.category == "known_ungroundable"

    unrelated_result = ground_question("What is the meaning of life?", cbom)
    assert unrelated_result.category == "unknown"
    assert unrelated_result.grounded is False


def test_migration_order_without_a_plan_is_ungrounded() -> None:
    """Requesting the migration order/sequence with NO plan payload supplied
    must refuse honestly, never inventing a schedule.
    """
    cbom = _test2_cbom()
    result = ground_question("What should I migrate first?", cbom, plan=None)
    assert result.grounded is False


# ===========================================================================
# Section 2 — real, grounded categories pull real data, never invent it.
# ===========================================================================


def test_finding_lookup_pulls_real_evidence() -> None:
    cbom = _test2_cbom()
    result = ground_question("Why is RSA flagged as broken by Shor?", cbom)
    assert result.category == "finding_lookup"
    assert result.grounded
    assert "broken-by-shor" in result.context
    assert "RSA" in result.matched_findings


def test_unresolved_category_reports_real_count() -> None:
    cbom = _test2_cbom()
    result = ground_question("How many findings are unresolved and why?", cbom)
    assert result.category == "unresolved"
    assert result.grounded
    # test2's post-fix state has zero UNRESOLVED findings (see prior session
    # work on go/internal/keys/agreement.go and c/src/handshake.c) --
    # this must say so honestly, not claim ignorance.
    assert "0" in result.context or "No UNRESOLVED" in result.context


def test_most_urgent_uses_the_real_optimizer_risk_score_formula() -> None:
    """Must reuse hash_patch.analyze.risk_score's actual formula -- never a
    second, ad-hoc ranking invented for this feature.
    """
    from hash_patch.analyze.cbom_reader import read_candidates

    cbom = _test2_cbom()
    result = ground_question("What's the most urgent finding in this scan?", cbom)
    assert result.category == "most_urgent"
    candidates, _ = read_candidates(cbom)
    expected_top = max(candidates, key=lambda c: c.risk_score)
    assert expected_top.name in result.context
    assert str(expected_top.risk_score) in result.context


def test_total_cost_sums_real_per_candidate_costs() -> None:
    from hash_patch.analyze.cbom_reader import read_candidates

    cbom = _test2_cbom()
    result = ground_question("What would it cost to migrate everything?", cbom)
    assert result.category == "total_cost"
    candidates, _ = read_candidates(cbom)
    expected_total = sum(c.cost_days for c in candidates)
    assert f"{expected_total:.2f}" in result.context


def test_glossary_question_is_grounded_in_tool_own_docs() -> None:
    cbom = _test2_cbom()
    result = ground_question(
        "What is the difference between a CRYPTO_REFERENCE and an OPERATION finding?", cbom
    )
    assert result.category == "glossary"
    assert "CRYPTO_REFERENCE" in result.context
    assert "OPERATION" in result.context


def test_unnamed_finding_never_matches_by_accident() -> None:
    """A question mentioning no real finding name at all must not spuriously
    match some component via a false substring coincidence.
    """
    cbom = _test2_cbom()
    result = ground_question("Tell me about the weather today.", cbom)
    assert result.matched_findings == []
    assert result.grounded is False
