"""tests/unit/test_qa_retrieval_deterministic.py — Deterministic retrieval tests.

Validates query understanding, entity resolution, deterministic Python aggregations,
and EvidencePackage extraction across all 10 specified query categories:
1. Summary ("what did you find?", "how many findings?", "give me the big picture")
2. Vulnerability ("what is broken by Shor?", "what is classically broken?", "what is weakened by Grover?")
3. Reachability ("what is externally reachable?", "what is internal?", "what is dead?", "what is unknown?")
4. References ("how many references?", "where is RSA only mentioned?")
5. Entity ("tell me about RSA", "where is ECDSA?", "what AES modes are present?")
6. Relationships ("what depends on RSA?", "where is this finding called from?")
7. Migration ("what should I fix first?", "what does the migration plan recommend?", "what is the largest migration effort?")
8. Blast radius ("what has a blast radius?", "what will break if this crypto changes?")
9. Sensitive data ("which crypto protects financial data?", "which finding has the longest confidentiality requirement?")
10. Natural language ("what's the scary stuff?", "what actually matters?", "what should I care about?", "what's going on here?")

Also tests:
- Strict scan isolation
- Diagnostic trace inspection
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.index import ScanKnowledgeIndex
from hash_patch.qa.query import QueryAnalyzer
from hash_patch.qa.registry import ScanRegistry
from hash_patch.qa.retriever import Retriever

REPO_ROOT = Path(__file__).resolve().parents[2]


def _build_test2_index() -> ScanKnowledgeIndex:
    scan_res = run_scan(REPO_ROOT / "test2")
    cbom = to_cyclonedx(scan_res)
    # Include a realistic sample optimizer plan for migration plan testing
    sample_plan = {
        "budget_days": 60.0,
        "scenarios": [
            {
                "scenario_name": "Risk-Optimal PQC Migration",
                "probability_weight": 1.0,
                "estimated_year": 2030,
                "headline_message": "Eliminates 92.4% of total quantum exposure within 60 engineer-days",
                "optimizer_plan": {
                    "eliminated_risk": 92.4,
                    "schedule": [
                        {"name": "RSA", "start_day": 0, "end_day": 12, "cost_days": 12.0},
                        {"name": "ECDSA", "start_day": 12, "end_day": 20, "cost_days": 8.0},
                    ],
                    "unmigrated_finding_ids": [],
                },
                "naive_plan": {
                    "eliminated_risk": 55.0,
                },
            }
        ],
    }
    return ScanKnowledgeIndex.from_cbom(cbom, sample_plan)


# =============================================================================
# 1. Summary Tests
# =============================================================================


def test_summary_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "what did you find?"
    q1 = QueryAnalyzer.parse("what did you find?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "OVERVIEW"
    assert res1.evidence_package is not None
    assert res1.evidence_package.summary["total_findings"] == len(idx.findings)
    assert res1.structured_data["total_operations"] == len(idx.operations)
    assert res1.structured_data["total_references"] == len(idx.references)
    assert "Target:" in res1.context

    # "how many findings?"
    q2 = QueryAnalyzer.parse("how many findings?", known)
    res2 = retriever.retrieve(q2)
    assert res2.structured_data["total_findings"] == len(idx.findings)
    assert str(len(idx.findings)) in res2.context

    # "give me the big picture"
    q3 = QueryAnalyzer.parse("give me the big picture", known)
    res3 = retriever.retrieve(q3)
    assert q3.intent == "OVERVIEW"
    assert "EXECUTIVE SUMMARY" in res3.context
    assert "QUANTUM VULNERABILITY BREAKDOWN" in res3.context
    assert "RUNTIME REACHABILITY DISTRIBUTION" in res3.context
    assert res3.evidence_package.aggregations["broken_by_shor"] == len(idx.broken_by_shor)


# =============================================================================
# 2. Vulnerability Tests
# =============================================================================


def test_vulnerability_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "what is broken by Shor?"
    q1 = QueryAnalyzer.parse("what is broken by Shor?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "VULNERABILITY"
    assert q1.quantum_filter == "broken-by-shor"
    assert res1.structured_data["count"] == len(idx.broken_by_shor)
    assert "Broken by Shor" in res1.context
    assert any("RSA" in f.name for f in res1.evidence_package.findings)

    # "what is classically broken?"
    q2 = QueryAnalyzer.parse("what is classically broken?", known)
    res2 = retriever.retrieve(q2)
    assert q2.intent == "VULNERABILITY"
    assert q2.quantum_filter == "broken-classically"
    assert res2.structured_data["count"] == len(idx.broken_classically)
    assert "Classically Broken" in res2.context

    # "what is weakened by Grover?"
    q3 = QueryAnalyzer.parse("what is weakened by Grover?", known)
    res3 = retriever.retrieve(q3)
    assert q3.intent == "VULNERABILITY"
    assert q3.quantum_filter == "weakened-by-grover"
    assert res3.structured_data["count"] == len(idx.weakened_by_grover)
    assert "Weakened by Grover" in res3.context


# =============================================================================
# 3. Reachability Tests
# =============================================================================


def test_reachability_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "what is externally reachable?"
    q1 = QueryAnalyzer.parse("what is externally reachable?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "REACHABILITY"
    assert q1.reachability_filter == "live-external"
    assert res1.structured_data["count"] == len(idx.live_external)
    assert "Live · External" in res1.context

    # "what is internal?"
    q2 = QueryAnalyzer.parse("what is internal?", known)
    res2 = retriever.retrieve(q2)
    assert q2.intent == "REACHABILITY"
    assert q2.reachability_filter == "live-internal"
    assert res2.structured_data["count"] == len(idx.live_internal)

    # "what is dead?"
    q3 = QueryAnalyzer.parse("what is dead?", known)
    res3 = retriever.retrieve(q3)
    assert q3.intent == "REACHABILITY"
    assert q3.reachability_filter == "inert"
    assert res3.structured_data["count"] == len(idx.inert)

    # "what is unknown?"
    q4 = QueryAnalyzer.parse("what is unknown reachability?", known)
    res4 = retriever.retrieve(q4)
    assert q4.intent == "REACHABILITY"
    assert q4.reachability_filter == "unknown"
    assert res4.structured_data["count"] == len(idx.unknown_reachability)


# =============================================================================
# 4. References Tests
# =============================================================================


def test_references_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "how many references?"
    q1 = QueryAnalyzer.parse("how many references?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "REFERENCES" or q1.intent == "AGGREGATION"
    assert res1.structured_data["references"] == len(idx.references)
    assert str(len(idx.references)) in res1.context

    # "where is RSA only mentioned?"
    q2 = QueryAnalyzer.parse("where is RSA only mentioned?", known)
    res2 = retriever.retrieve(q2)
    assert q2.intent == "REFERENCES"
    assert "RSA" in q2.entities
    assert res2.evidence_package is not None
    assert "REFERENCES FOR RSA" in res2.context
    assert res2.structured_data["operations_count"] > 0


# =============================================================================
# 5. Entity Tests
# =============================================================================


def test_entity_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "tell me about RSA"
    q1 = QueryAnalyzer.parse("tell me about RSA", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "FINDINGS_LOOKUP"
    assert "RSA" in q1.entities
    assert any("RSA" in f for f in res1.matched_findings)
    assert "FINDING: RSA" in res1.context
    assert any(s.startswith("finding:") for s in res1.sources)

    # "where is ECDSA?"
    q2 = QueryAnalyzer.parse("where is ECDSA?", known)
    res2 = retriever.retrieve(q2)
    assert "ECDSA" in q2.entities
    assert any("ECDSA" in f for f in res2.matched_findings)

    # "what AES modes are present?"
    q3 = QueryAnalyzer.parse("what AES modes are present?", known)
    res3 = retriever.retrieve(q3)
    assert "AES" in q3.entities or any("AES" in e for e in q3.entities)
    assert "AES" in res3.context
    assert "Mode:" in res3.context or "Primitive:" in res3.context


# =============================================================================
# 6. Relationships Tests
# =============================================================================


def test_relationships_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "what depends on RSA?"
    q1 = QueryAnalyzer.parse("what depends on RSA?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "RELATIONSHIPS"
    assert "RSA" in q1.entities
    assert "DEPENDENCY GRAPH" in res1.context
    assert "RSA" in res1.context

    # "where is this finding called from?"
    q2 = QueryAnalyzer.parse("who calls RSA?", known)
    res2 = retriever.retrieve(q2)
    assert q2.intent == "RELATIONSHIPS"
    assert q2.relationship_direction == "callers" or "callers" in q2.raw_query.lower()
    assert "Incoming Callers" in res2.context


# =============================================================================
# 7. Migration Tests
# =============================================================================


def test_migration_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "what should I fix first?"
    q1 = QueryAnalyzer.parse("what should I fix first?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "MIGRATION"
    assert q1.ranking == "risk"
    assert "MIGRATION PRIORITIZATION" in res1.context
    assert "1. " in res1.context
    top_cand = idx.migration_candidates[0]
    assert top_cand.name in res1.context

    # "what does the migration plan recommend?"
    q2 = QueryAnalyzer.parse("what does the migration plan recommend?", known)
    res2 = retriever.retrieve(q2)
    assert q2.intent == "MIGRATION"
    assert "OPTIMIZER SCHEDULE" in res2.context
    assert "Eliminated Risk: 92.4%" in res2.context

    # "what is the largest migration effort?"
    q3 = QueryAnalyzer.parse("what is the largest migration effort?", known)
    res3 = retriever.retrieve(q3)
    assert q3.intent == "MIGRATION"
    assert "Largest Individual Migration Effort:" in res3.context
    assert res3.structured_data["largest_effort_days"] > 0


# =============================================================================
# 8. Blast Radius Tests
# =============================================================================


def test_blast_radius_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "what has a blast radius?"
    q1 = QueryAnalyzer.parse("what has a blast radius?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "BLAST_RADIUS"
    assert "BLAST RADIUS BUFFER CONSTRAINTS" in res1.context
    assert res1.evidence_package is not None
    assert len(res1.evidence_package.blast_radius) > 0
    assert any(b.has_overflow for b in res1.evidence_package.blast_radius)

    # "what will break if this crypto changes?"
    q2 = QueryAnalyzer.parse("what will break if RSA changes?", known)
    res2 = retriever.retrieve(q2)
    assert q2.intent == "BLAST_RADIUS"
    assert "RSA" in q2.entities
    assert "Filtering to asset: RSA" in res2.context or "Buffer:" in res2.context


# =============================================================================
# 9. Sensitive Data Tests
# =============================================================================


def test_sensitive_data_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "which crypto protects financial data?"
    q1 = QueryAnalyzer.parse("which crypto protects financial data?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "SENSITIVE_DATA"
    assert q1.sensitivity_category == "financial"
    assert "Category Filter: financial" in res1.context
    assert res1.evidence_package is not None
    assert any(s.category in ("financial", "pan") for s in res1.evidence_package.sensitivity)

    # "which finding has the longest confidentiality requirement?"
    q2 = QueryAnalyzer.parse("which finding has the longest confidentiality requirement?", known)
    res2 = retriever.retrieve(q2)
    assert q2.intent == "SENSITIVE_DATA"
    assert q2.ranking == "shelf_life"
    assert "SENSITIVE DATA CONTEXT" in res2.context
    assert res2.structured_data["longest_shelf_life_years"] is not None
    assert res2.structured_data["longest_shelf_life_years"] >= 10


# =============================================================================
# 10. Natural Language Queries
# =============================================================================


def test_natural_language_queries() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    # "what's the scary stuff?"
    q1 = QueryAnalyzer.parse("what's the scary stuff?", known)
    res1 = retriever.retrieve(q1)
    assert q1.intent == "VULNERABILITY"
    assert q1.quantum_filter == "broken-by-shor"
    assert "Broken by Shor" in res1.context

    # "what actually matters?"
    q2 = QueryAnalyzer.parse("what actually matters?", known)
    res2 = retriever.retrieve(q2)
    assert q2.intent == "OVERVIEW"
    assert "EXECUTIVE SUMMARY" in res2.context

    # "what should I care about?"
    q3 = QueryAnalyzer.parse("what should I care about?", known)
    res3 = retriever.retrieve(q3)
    assert q3.intent == "OVERVIEW"
    assert "QUANTUM VULNERABILITY BREAKDOWN" in res3.context

    # "what's going on here?"
    q4 = QueryAnalyzer.parse("what's going on here?", known)
    res4 = retriever.retrieve(q4)
    assert q4.intent == "OVERVIEW"
    assert "Total Scanned Files:" in res4.context


# =============================================================================
# 11. Strict Scan Isolation Test (Requirement 17)
# =============================================================================


def test_strict_scan_isolation() -> None:
    registry = ScanRegistry()

    scan1_cbom = {
        "serialNumber": "urn:uuid:scan-1111",
        "components": [
            {
                "bom-ref": "rsa-1",
                "name": "RSA",
                "type": "cryptographic-asset",
                "properties": [{"name": "hash_patch:findingType", "value": "OPERATION"}],
            }
        ],
    }

    scan2_cbom = {
        "serialNumber": "urn:uuid:scan-2222",
        "components": [
            {
                "bom-ref": "ecdsa-2",
                "name": "ECDSA",
                "type": "cryptographic-asset",
                "properties": [{"name": "hash_patch:findingType", "value": "OPERATION"}],
            }
        ],
    }

    rec1 = registry.register_scan(scan1_cbom, scan_id="scan-1111")
    rec2 = registry.register_scan(scan2_cbom, scan_id="scan-2222")

    idx1 = rec1.get_or_build_index()
    idx2 = rec2.get_or_build_index()

    # Verify scan1 only contains RSA
    assert "RSA" in idx1.findings_by_name
    assert "ECDSA" not in idx1.findings_by_name
    assert idx1.scan_id == "scan-1111"

    # Verify scan2 only contains ECDSA
    assert "ECDSA" in idx2.findings_by_name
    assert "RSA" not in idx2.findings_by_name
    assert idx2.scan_id == "scan-2222"

    # Verify retriever for scan1 cannot see ECDSA
    ret1 = Retriever(idx1)
    q = QueryAnalyzer.parse("tell me about ECDSA", {"ECDSA"})
    res1 = ret1.retrieve(q)
    assert "No findings matching 'ECDSA'" in res1.context

    # Unknown scan must return None, never fallback to another scan
    assert registry.get_scan("scan-nonexistent") is None


# =============================================================================
# 12. Retrieval Diagnostics Inspection (Requirement 18)
# =============================================================================


def test_retrieval_diagnostics_trace() -> None:
    idx = _build_test2_index()
    retriever = Retriever(idx)
    known = {c.name for c in idx.findings}

    query = QueryAnalyzer.parse("tell me about RSA crypto", known)
    res = retriever.retrieve(query)

    assert res.evidence_package is not None
    trace = res.evidence_package.diagnostic_trace

    # Trace must include the full pipeline breakdown:
    # QUESTION -> NORMALIZED QUERY -> RESOLVED ENTITIES -> FILTERS -> RETRIEVAL SCOPE -> AGGREGATIONS -> SOURCE RECORDS
    assert trace["question"] == "tell me about RSA crypto"
    assert trace["normalized_query"]["intent"] == "FINDINGS_LOOKUP"
    assert "RSA" in trace["resolved_entities"]
    assert "filters" in trace
    assert trace["retrieval_scope"] == "entity"
    assert "aggregations" in trace
    assert len(trace["source_records"]) > 0
    assert any("finding:" in s for s in trace["source_records"])
