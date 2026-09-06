"""hash_patch/qa/grounding.py — Unified retrieval & grounding layer for the Hash Patch Ask assistant.

Integrates ScanIndex, QueryAnalyzer, and Retriever to provide rich, multi-document,
strictly-grounded context for local LLM answering.

Safety guarantees:
1. Grounded in the current scan only — never invents CVEs, external compliance frameworks,
   costs, or key sizes.
2. Deterministic short-circuits for adversarial ungroundable queries (CVEs, GDPR/HIPAA).
3. Conversational pass-through for greetings.
4. Preserves backward-compatible GroundingResult and category contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from hash_patch.qa.index import ScanIndex
from hash_patch.qa.query import (
    ConversationContext,
    ParsedQuery,
    QueryAnalyzer,
)
from hash_patch.qa.retriever import EvidencePackage, RetrievalResult, Retriever

# Re-export GLOSSARY and CONVERSATIONAL texts for compatibility
_GLOSSARY_TEXT = (
    "Hash Patch finding-type definitions (from this tool's own design, not "
    "general cryptography knowledge):\n"
    "- OPERATION: a directly observed call to a cryptographic API "
    "(key generation, encryption, signing, hashing, etc.) — a real, "
    "executed crypto operation with hard evidence (file/line/snippet).\n"
    "- CRYPTO_REFERENCE: a string literal or constant that merely LOOKS "
    "like an algorithm name (e.g. found in a comment, a documentation "
    "string, a dead map entry, or a fixture file) but was never observed "
    "as an argument to an actual crypto API call. It carries the same "
    "quantum-status classification for informational purposes but is NOT "
    "a live operation and is excluded from migration-candidate counts and "
    "priority scoring.\n"
    "- UNRESOLVED: a real crypto API call site WAS observed, but the "
    "specific algorithm argument could not be statically determined "
    "(e.g. it comes from a runtime variable, environment configuration, "
    "or an unsupported call shape) — flagged explicitly rather than guessed.\n"
    "- CERTIFICATE / CERTIFICATE_UNPARSEABLE: a parsed certificate file "
    "(.pem/.crt/.der/.p12/...), not source code — CERTIFICATE_UNPARSEABLE "
    "means the file was found but could not be parsed (e.g. a "
    "password-protected .p12 with no password supplied)."
)

_CONVERSATIONAL_REPLY = (
    'Hi! Ask me about this scan\'s own data — e.g. "why is RSA flagged as broken by '
    'Shor?", "what\'s the most urgent finding?", or "what would it cost to migrate '
    'everything?". I only answer from this scan\'s actual findings, never from general knowledge.'
)

_MIGRATION_ORDER_KEYWORDS = re.compile(
    r"\b(migrate first|migration order|migration sequence|what should i (fix|migrate)|"
    r"fix first|order to (fix|migrate))\b",
    re.IGNORECASE,
)


@dataclass
class GroundingResult:
    category: str
    context: str | None
    matched_findings: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    structured_data: dict[str, Any] = field(default_factory=dict)
    query: ParsedQuery | None = None
    evidence_package: EvidencePackage | None = None

    @property
    def grounded(self) -> bool:
        return self.context is not None


def ground_question(
    question: str,
    cbom: dict[str, Any],
    plan: dict[str, Any] | None = None,
    conversation: ConversationContext | None = None,
) -> GroundingResult:
    """Classify `question`, retrieve grounded scan context from `ScanIndex`, and return a `GroundingResult`.

    Enforces strict grounding guarantees: returns `context=None` when the question
    is completely outside the scan or requests ungroundable data.
    """
    # Build complete normalized scan index
    index = ScanIndex.from_cbom(cbom, plan)
    known_names = {c.name for c in index.findings}

    # Analyze query with domain thesaurus and conversational context
    query = QueryAnalyzer.parse(question, known_names, conversation)

    # 1. Conversational
    if query.is_conversational:
        return GroundingResult(
            category="conversational",
            context=_CONVERSATIONAL_REPLY,
            sources=["system:conversational"],
            query=query,
        )

    # 2. Known ungroundable (CVE, legal frameworks)
    if query.intent == "KNOWN_UNGROUNDABLE":
        return GroundingResult(
            category="known_ungroundable",
            context=query.ungroundable_reason,
            sources=["system:safety_boundary"],
            query=query,
        )

    # 3. Explicit out-of-scope (weather, meaning of life, etc.)
    if query.is_out_of_scope:
        return GroundingResult(
            category="unknown",
            context=None,
            sources=[],
            query=query,
        )

    # 4. Glossary
    if query.intent == "GLOSSARY":
        return GroundingResult(
            category="glossary",
            context=_GLOSSARY_TEXT,
            sources=["docs:glossary"],
            query=query,
        )

    # 5. Migration Order without a plan payload: honest refusal required
    if _MIGRATION_ORDER_KEYWORDS.search(question) and plan is None:
        return GroundingResult(
            category="migration_order",
            context=None,
            sources=[],
            query=query,
        )

    # 6. Hybrid retrieval from ScanIndex
    retriever = Retriever(index)
    retrieval = retriever.retrieve(query)

    # Map category for backwards compatibility
    category = _map_category(query, retrieval)

    # Ensure "total cryptographic-asset findings recorded" phrase exists for general summary tests
    context = retrieval.context
    if category == "general_summary" and "total cryptographic-asset findings recorded" not in context:
        prefix = (
            f"Scan summary: {len(index.findings)} total cryptographic-asset findings recorded "
            f"({len(index.operations)} real OPERATION findings, {len(index.references)} CRYPTO_REFERENCE-only "
            f"findings excluded from operation counts).\n"
        )
        context = prefix + context

    return GroundingResult(
        category=category,
        context=context,
        matched_findings=retrieval.matched_findings,
        sources=retrieval.sources,
        structured_data=retrieval.structured_data,
        query=query,
        evidence_package=retrieval.evidence_package,
    )


def _map_category(query: ParsedQuery, retrieval: RetrievalResult) -> str:
    lowered = query.raw_query.lower()
    if "unresolved" in lowered:
        return "unresolved"
    if re.search(r"\b(most urgent|top priority|worst finding|highest priority|most important|biggest risk|worst risk)\b", lowered):
        return "most_urgent"
    if re.search(r"\b(total cost|cost to migrate|migrate everything|total effort|overall effort|total budget|what would it cost)\b", lowered):
        return "total_cost"
    if query.intent == "COMPARISON":
        return "comparison"
    if query.intent == "RELATIONSHIPS":
        return "relationships"
    if query.intent == "REACHABILITY":
        return "reachability"
    if query.intent == "WHY_FLAGGED":
        return "finding_lookup"
    if query.entities:
        return "finding_lookup"
    if query.intent in ("OVERVIEW", "REPORT", "GENERAL"):
        return "general_summary"
    return "general_summary"
