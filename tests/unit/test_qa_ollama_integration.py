"""tests/unit/test_qa_ollama_integration.py

Integration tests against a REAL running local Ollama instance
(hash_patch/qa/ollama_client.py) — skipped entirely when Ollama isn't
reachable on this machine (CI, a fresh checkout, a machine without the
model pulled), since this feature is local-model-dependent by design and
must never block the rest of the suite.

Covers the exact anticipated question set from the Q&A assistant's own
design brief, including the required adversarial case: a question with no
grounded answer available must be honestly refused, not fabricated.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.grounding import ground_question
from hash_patch.qa.ollama_client import DEFAULT_MODEL, REFUSAL_MESSAGE, ask_ollama

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ollama_available() -> bool:
    try:
        resp = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
        if resp.status_code != 200:
            return False
        models = {m.get("model") for m in resp.json().get("models", [])}
        return DEFAULT_MODEL in models
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(
    not _ollama_available(),
    reason=f"Ollama not running locally or {DEFAULT_MODEL} not pulled -- skipping live-model integration tests",
)


@pytest.fixture(scope="module")
def test2_cbom() -> dict:
    result = run_scan(REPO_ROOT / "test2")
    return to_cyclonedx(result)


def _answer(question: str, cbom: dict) -> tuple[str, bool, str]:
    result = ground_question(question, cbom)
    if not result.grounded:
        return REFUSAL_MESSAGE, False, result.category
    if result.category in ("known_ungroundable", "conversational"):
        return result.context or REFUSAL_MESSAGE, True, result.category
    return ask_ollama(
        question,
        result.context or "",
        evidence_package=result.evidence_package,
        query=result.query,
    ), True, result.category


def test_why_flagged_question(test2_cbom: dict) -> None:
    answer, grounded, category = _answer("Why is RSA flagged as broken by Shor?", test2_cbom)
    assert grounded
    assert "shor" in answer.lower()


def test_most_urgent_finding_question(test2_cbom: dict) -> None:
    answer, grounded, category = _answer("What's the single most urgent finding in this scan?", test2_cbom)
    assert grounded
    assert len(answer) > 0


def test_unresolved_count_question(test2_cbom: dict) -> None:
    answer, grounded, category = _answer("How many findings are unresolved and why?", test2_cbom)
    assert grounded
    assert len(answer) > 0


def test_total_migration_cost_question(test2_cbom: dict) -> None:
    answer, grounded, category = _answer("What would it cost to migrate everything?", test2_cbom)
    assert grounded
    assert len(answer) > 0


def test_reference_vs_operation_glossary_question(test2_cbom: dict) -> None:
    answer, grounded, category = _answer(
        "What's the difference between a CRYPTO_REFERENCE and an OPERATION finding?", test2_cbom
    )
    assert grounded
    assert "reference" in answer.lower() or "operation" in answer.lower()


def test_adversarial_cve_question_is_refused_not_fabricated(test2_cbom: dict) -> None:
    """The required adversarial case: asking for a CVE when none exists
    anywhere in the system must produce an honest refusal, never a
    fabricated CVE identifier (a string matching CVE-YYYY-NNNNN).
    """
    import re

    answer, grounded, category = _answer("What CVE does this RSA finding correspond to?", test2_cbom)
    assert grounded  # the refusal itself IS the (deterministic) answer
    assert not re.search(r"CVE-\d{4}-\d+", answer), f"model fabricated a CVE identifier: {answer}"
    assert "cve" not in answer.lower() or "no cve" in answer.lower() or "not track" in answer.lower()


def test_adversarial_unrelated_question_is_refused(test2_cbom: dict) -> None:
    answer, grounded, category = _answer("What is the meaning of life?", test2_cbom)
    assert not grounded
    assert answer == REFUSAL_MESSAGE


# ===========================================================================
# Router-widening regression: greetings and loosely-phrased scan questions
# must be recognized as legitimate (or conversational), not falsely declined
# -- and the two adversarial cases above must still decline exactly as
# before, proving the widening didn't loosen the safety boundary.
# ===========================================================================


@pytest.mark.parametrize("greeting", ["hi", "hello there", "thanks!"])
def test_greeting_is_conversational_not_declined(test2_cbom: dict, greeting: str) -> None:
    answer, grounded, category = _answer(greeting, test2_cbom)
    assert grounded
    assert category == "conversational"
    assert answer != REFUSAL_MESSAGE


@pytest.mark.parametrize("question", ["findings?", "what have you got", "show me the summary", "results?"])
def test_loosely_phrased_scan_question_is_grounded_not_declined(test2_cbom: dict, question: str) -> None:
    answer, grounded, category = _answer(question, test2_cbom)
    assert grounded
    assert category == "general_summary"
    assert answer != REFUSAL_MESSAGE
