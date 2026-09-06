"""tests/unit/test_qa_query.py — Tests for QueryAnalyzer, domain thesaurus, and conversation context."""

from __future__ import annotations

from hash_patch.qa.query import ConversationContext, QueryAnalyzer

KNOWN_NAMES = {"RSA", "ECDSA", "ECDH", "Ed25519", "AES", "DSA", "DH", "SHA-256", "MD5"}


def test_domain_thesaurus_entity_extraction() -> None:
    # "ECC stuff" -> ECDSA, ECDH
    q1 = QueryAnalyzer.parse("what about the ECC stuff?", KNOWN_NAMES)
    assert "ECDSA" in q1.entities or "ECDH" in q1.entities

    # "the AES stuff" -> AES
    q2 = QueryAnalyzer.parse("show me everything related to AES", KNOWN_NAMES)
    assert "AES" in q2.entities

    # "the old hashes" -> SHA-256 or MD5
    q3 = QueryAnalyzer.parse("what about the old hashes?", KNOWN_NAMES)
    assert "MD5" in q3.entities


def test_reachability_queries() -> None:
    q1 = QueryAnalyzer.parse("what crypto stuff is exposed to the outside world?", KNOWN_NAMES)
    assert q1.reachability_filter == "live-external"

    q2 = QueryAnalyzer.parse("are there any dead crypto implementations?", KNOWN_NAMES)
    assert q2.reachability_filter == "inert"

    q3 = QueryAnalyzer.parse("what is actually live?", KNOWN_NAMES)
    assert q3.reachability_filter == "live"


def test_comparison_parsing() -> None:
    q1 = QueryAnalyzer.parse("compare RSA and ECDSA", KNOWN_NAMES)
    assert q1.is_comparison is True
    assert "RSA" in q1.comparison_targets
    assert "ECDSA" in q1.comparison_targets

    q2 = QueryAnalyzer.parse("which is worse, RSA or ECDSA?", KNOWN_NAMES)
    assert q2.is_comparison is True
    assert "RSA" in q2.comparison_targets
    assert "ECDSA" in q2.comparison_targets


def test_conversation_followup_pronoun_resolution() -> None:
    context = ConversationContext()

    # Turn 1: Tell me about RSA
    q1 = QueryAnalyzer.parse("tell me about RSA", KNOWN_NAMES, context)
    assert "RSA" in q1.entities
    context.update("tell me about RSA", "RSA is broken by Shor...", q1)
    assert context.active_findings == ["RSA"]

    # Turn 2: Is it actually live? -> "it" resolves to RSA
    q2 = QueryAnalyzer.parse("is it actually live?", KNOWN_NAMES, context)
    assert "RSA" in q2.entities
    assert q2.reachability_filter == "live"
    context.update("is it actually live?", "Yes, RSA is live...", q2)

    # Turn 3: Where is it used? -> "it" resolves to RSA
    q3 = QueryAnalyzer.parse("where is it?", KNOWN_NAMES, context)
    assert "RSA" in q3.entities
    context.update("where is it?", "RSA is found in...", q3)

    # Turn 4: What about ECDSA? -> switches active finding to ECDSA
    q4 = QueryAnalyzer.parse("what about ECDSA?", KNOWN_NAMES, context)
    assert "ECDSA" in q4.entities
    context.update("what about ECDSA?", "ECDSA is...", q4)
    assert context.active_findings == ["ECDSA"]

    # Turn 5: Which one is worse? -> compares RSA and ECDSA
    q5 = QueryAnalyzer.parse("which one is worse?", KNOWN_NAMES, context)
    assert q5.is_comparison is True
    assert "RSA" in q5.comparison_targets
    assert "ECDSA" in q5.comparison_targets


def test_out_of_scope_and_greetings() -> None:
    # Conversational
    assert QueryAnalyzer.parse("hi", KNOWN_NAMES).is_conversational is True
    assert QueryAnalyzer.parse("thanks!", KNOWN_NAMES).is_conversational is True

    # Out of scope
    assert QueryAnalyzer.parse("what is the meaning of life?", KNOWN_NAMES).is_out_of_scope is True
    assert QueryAnalyzer.parse("write me a poem", KNOWN_NAMES).is_out_of_scope is True
    assert QueryAnalyzer.parse("what's the weather today?", KNOWN_NAMES).is_out_of_scope is True

    # Adversarial CVE / compliance
    assert QueryAnalyzer.parse("what CVE does this have?", KNOWN_NAMES).intent == "KNOWN_UNGROUNDABLE"
    assert QueryAnalyzer.parse("is this GDPR compliant?", KNOWN_NAMES).intent == "KNOWN_UNGROUNDABLE"
