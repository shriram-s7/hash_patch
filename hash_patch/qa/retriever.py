"""hash_patch/qa/retriever.py — Deterministic retrieval, Python aggregation,
and EvidencePackage builder for Hash Patch.

Key principles:
1. Python deterministically computes counts, sums, rankings, distributions, and comparisons;
   the LLM is never tasked with manual counting.
2. Hybrid retrieval covers all 5 pillars:
   - Pillar 1: Discovery, Operational findings vs static string references, Call graph relationships
   - Pillar 2: Data-context sensitivity and Mosca shelf-life requirements
   - Pillar 3: Blast-radius fixed-size memory buffer constraints and overflows
   - Pillar 4: Cross-layer TLS policy contradictions and algorithm divergence
   - Pillar 5: Migration candidate prioritization, effort estimation, and optimizer schedules
3. Every factual record in the EvidencePackage is traceable to its source file, line number,
   or report section.
4. Complete diagnostic trace available for debugging query understanding, entity resolution,
   retrieval scope, aggregations, and evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from hash_patch.qa.index import (
    BlastRadiusRecord,
    ContradictionRecord,
    FindingRecord,
    GraphEdge,
    ScanIndex,
    ShelfLifeRecord,
)
from hash_patch.qa.query import NormalizedQuery


@dataclass
class EvidencePackage:
    """Structured evidence package retrieved for a query.

    Provenance is explicit: every factual record remains traceable to its underlying
    scan finding, relationship edge, shelf-life record, or report metric.
    """

    query: NormalizedQuery
    scan_identity: dict[str, Any]
    summary: dict[str, Any]
    findings: list[FindingRecord] = field(default_factory=list)
    references: list[FindingRecord] = field(default_factory=list)
    relationships: list[GraphEdge] = field(default_factory=list)
    migration: dict[str, Any] = field(default_factory=dict)
    sensitivity: list[ShelfLifeRecord] = field(default_factory=list)
    blast_radius: list[BlastRadiusRecord] = field(default_factory=list)
    contradictions: list[ContradictionRecord] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)
    aggregations: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    diagnostic_trace: dict[str, Any] = field(default_factory=dict)


@dataclass
class RetrievalResult:
    """Wrapped retrieval result providing formatted context string and structured data."""

    context: str
    sources: list[str] = field(default_factory=list)
    matched_findings: list[str] = field(default_factory=list)
    structured_data: dict[str, Any] = field(default_factory=dict)
    evidence_package: EvidencePackage | None = None


class Retriever:
    """Retrieves relevant scan documents and computes deterministic aggregates."""

    def __init__(self, index: ScanIndex) -> None:
        self.index = index

    def retrieve(self, query: NormalizedQuery) -> RetrievalResult:
        # Route deterministically according to classified intent
        if query.is_comparison and len(query.comparison_targets) >= 2:
            return self._handle_comparison(query.comparison_targets, query)

        if query.intent == "CROSS_PILLAR" or query.is_cross_pillar:
            return self._handle_cross_pillar(query)

        if query.intent == "BLAST_RADIUS":
            return self._handle_blast_radius(query)

        if query.intent == "SENSITIVE_DATA":
            return self._handle_sensitive_data(query)

        if query.intent == "MIGRATION":
            return self._handle_migration(query)

        if query.intent == "RELATIONSHIPS":
            return self._handle_relationships(query)

        if query.intent == "REFERENCES":
            return self._handle_references(query)

        if query.intent == "CONTAINER_CRYPTO":
            return self._handle_container_crypto(query)

        if query.intent == "BINARY_CRYPTO":
            return self._handle_binary_crypto(query)

        if query.intent == "REACHABILITY":
            return self._handle_reachability(query)

        if query.intent == "IAC_EXPOSURE":
            return self._handle_iac_exposure(query)

        if query.intent == "VULNERABILITY":
            return self._handle_vulnerability(query)

        if query.intent == "REPORT":
            return self._handle_report(query)

        if query.intent == "AGGREGATION" or query.is_aggregation:
            return self._handle_aggregation(query)

        if query.intent in ("FINDINGS_LOOKUP", "WHY_FLAGGED") or query.entities:
            return self._handle_findings_lookup(query)

        # Fallback to broad overview
        return self._handle_overview(query)

    # -------------------------------------------------------------------------
    # 1. Broad Overview / Big Picture
    # -------------------------------------------------------------------------

    def _handle_overview(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["report:scan_summary", "report:distributions"]

        # Deterministic counts
        total_comps = len(idx.findings)
        total_ops = len(idx.operations)
        total_refs = len(idx.references)
        shor_count = len(idx.broken_by_shor)
        class_broken_count = len(idx.broken_classically)
        grover_count = len(idx.weakened_by_grover)
        quantum_safe_count = len(idx.quantum_safe)

        live_ext = len(idx.live_external)
        live_int = len(idx.live_internal)
        inert = len(idx.inert)
        unknown_r = len(idx.unknown_reachability)

        top_cand = idx.migration_candidates[0] if idx.migration_candidates else None
        longest_sl = idx.longest_shelf_life_finding
        blast_with_overflow = [b for b in idx.blast_radius_findings if b.has_overflow]

        parts = [
            "=== SCAN EXECUTIVE SUMMARY ===",
            f"Target: {idx.target}",
            f"Scan ID / Serial: {idx.scan_id}",
            f"Total Scanned Files: {idx.total_scanned_files_count} ({len(idx.files_with_findings)} with cryptographic findings)",
            f"Total Cryptographic Assets: {total_comps} ({total_ops} active operations, {total_refs} static string references)",
            "",
            "=== QUANTUM VULNERABILITY BREAKDOWN ===",
            f"- Broken by Shor (asymmetric, CRQC vulnerable): {shor_count} operations",
            f"- Classically Broken (already broken today): {class_broken_count} operations",
            f"- Weakened by Grover (symmetric/hash, effective key halved): {grover_count} operations",
            f"- Believed Quantum-Safe: {quantum_safe_count} operations",
            "",
            "=== RUNTIME REACHABILITY DISTRIBUTION ===",
            f"- Live · External (accessible from outside/network): {live_ext}",
            f"- Live · Internal (active internal call graph): {live_int}",
            f"- Unknown (reachability unverified or default): {unknown_r}",
            f"- Inert (dead code / uncalled): {inert}",
        ]

        if top_cand:
            sources.append(f"migration:candidate:{top_cand.name}")
            parts.extend([
                "",
                "=== HIGHEST MIGRATION RISK (Pillar 5) ===",
                f"- Top Candidate: {top_cand.name} (Risk Score: {top_cand.risk_score:.2f})",
                f"  Reachability: {top_cand.reachability}, Estimated Effort: {top_cand.cost_days}d ({top_cand.cost_source})",
            ])

        if blast_with_overflow:
            sources.append("blast_radius:summary")
            top_br = max(blast_with_overflow, key=lambda b: b.overflow_bytes)
            parts.extend([
                "",
                "=== BLAST RADIUS BUFFER CONSTRAINTS (Pillar 3) ===",
                f"- Fixed-size buffers with PQC overflow: {len(blast_with_overflow)}",
                f"- Largest Overflow: {top_br.buffer_name} for {top_br.asset_name} (+{top_br.overflow_bytes}B required for {top_br.pqc_replacement or 'PQC'})",
            ])

        if longest_sl and longest_sl.shelf_life_years:
            sources.append(f"shelflife:{longest_sl.name}")
            parts.extend([
                "",
                "=== LONGEST DATA SHELF-LIFE (Pillar 2) ===",
                f"- Asset: {longest_sl.name} ({longest_sl.shelf_life_years} years, category: {longest_sl.shelf_life_category or 'unknown'})",
                f"  Note: {longest_sl.shelf_life_note or 'Data retention outlives quantum migration timeline'}",
            ])

        if idx.contradictions:
            sources.append("contradictions:summary")
            parts.append(f"\nPolicy Contradictions Detected: {len(idx.contradictions)}")

        aggregations = {
            "total_findings": total_comps,
            "total_operations": total_ops,
            "total_references": total_refs,
            "broken_by_shor": shor_count,
            "broken_classically": class_broken_count,
            "weakened_by_grover": grover_count,
            "quantum_safe": quantum_safe_count,
            "live_external": live_ext,
            "live_internal": live_int,
            "inert": inert,
            "unknown_reachability": unknown_r,
            "blast_radius_overflows": len(blast_with_overflow),
            "contradictions_count": len(idx.contradictions),
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target, "serial_number": idx.serial_number},
            summary={"total_findings": total_comps, "total_operations": total_ops, "total_references": total_refs},
            findings=idx.operations[:15],
            references=idx.references[:5],
            relationships=idx.graph_edges[:10],
            migration={"top_candidate": top_cand.name if top_cand else None},
            sensitivity=idx.shelf_life_findings[:5],
            blast_radius=blast_with_overflow[:5],
            contradictions=idx.contradictions,
            report={"scanned_files_count": idx.total_scanned_files_count},
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(idx.findings)),
        )

        return RetrievalResult(
            context="\n".join(parts),
            sources=sources,
            matched_findings=[top_cand.name] if top_cand else [],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 2. Quantum / Vulnerability Classification (Pillars 1 & 5)
    # -------------------------------------------------------------------------

    def _handle_vulnerability(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["vulnerability:breakdown"]
        lowered = query.raw_query.lower()

        if query.quantum_filter == "broken-by-shor" or "shor" in lowered or "scary" in lowered or "bad" in lowered:
            items = idx.broken_by_shor
            title = f"Broken by Shor (Asymmetric / CRQC Vulnerable) — {len(items)} Operations:"
            cat_key = "broken-by-shor"
        elif query.quantum_filter == "broken-classically" or "classically" in lowered:
            items = idx.broken_classically
            title = f"Classically Broken (Insecure Today) — {len(items)} Operations:"
            cat_key = "broken-classically"
        elif query.quantum_filter == "weakened-by-grover" or "grover" in lowered:
            items = idx.weakened_by_grover
            title = f"Weakened by Grover (Symmetric / Halved Effective Key) — {len(items)} Operations:"
            cat_key = "weakened-by-grover"
        elif query.quantum_filter == "quantum-safe" or "safe" in lowered:
            items = idx.quantum_safe
            title = f"Quantum-Safe Operations — {len(items)} Operations:"
            cat_key = "quantum-safe"
        else:
            items = idx.broken_by_shor
            title = f"Quantum Vulnerable Operations — {len(items)} Operations:"
            cat_key = "broken-by-shor"

        lines = ["=== QUANTUM VULNERABILITY INVENTORY ===", title]
        for it in items[:12]:
            loc = it.evidence[0].display_location if it.evidence else "unknown"
            sources.append(f"finding:{it.id}:{loc}")
            lines.append(f"- {it.name} [{it.reachability}] at {loc}")

        aggregations = {
            "category": cat_key,
            "count": len(items),
            "percentage_of_operations": round((len(items) / len(idx.operations) * 100), 1) if idx.operations else 0.0,
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"category": cat_key, "count": len(items)},
            findings=items,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(items)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=[it.name for it in items],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 3. Reachability (Pillar 1)
    # -------------------------------------------------------------------------

    def _handle_reachability(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["reachability:inventory"]
        lowered = query.raw_query.lower()

        filt = query.reachability_filter
        if filt == "live-external" or "external" in lowered or "exposed" in lowered:
            items = idx.live_external
            title = f"Live · External Findings ({len(items)} operations — accessible from outside / network entrypoints):"
            r_key = "live-external"
        elif filt == "live-internal" or "internal" in lowered:
            items = idx.live_internal
            title = f"Live · Internal Findings ({len(items)} operations — called within internal services):"
            r_key = "live-internal"
        elif filt == "inert" or "dead" in lowered:
            items = idx.inert
            title = f"Inert Findings ({len(items)} operations — uncalled dead code):"
            r_key = "inert"
        elif filt == "unknown" or "unknown" in lowered:
            items = idx.unknown_reachability
            title = f"Unknown Reachability Findings ({len(items)} operations — reachability undetermined):"
            r_key = "unknown"
        else:
            items = idx.live_external + idx.live_internal
            title = f"All Live Operations ({len(items)} operations):"
            r_key = "live"

        lines = ["=== RUNTIME REACHABILITY INVENTORY ===", title]
        if not items:
            lines.append("  (No findings matching this reachability state)")
        else:
            for it in items[:15]:
                loc = it.evidence[0].display_location if it.evidence else "unknown"
                sources.append(f"finding:{it.id}:{loc}")
                lines.append(f"- {it.name} [{it.quantum_status}] at {loc}")

        aggregations = {
            "reachability_state": r_key,
            "count": len(items),
            "percentage_of_operations": round((len(items) / len(idx.operations) * 100), 1) if idx.operations else 0.0,
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"reachability_state": r_key, "count": len(items)},
            findings=items,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(items)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=[it.name for it in items],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 3b. IaC Exposure (Phase 4)
    # -------------------------------------------------------------------------

    def _handle_iac_exposure(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["iac:exposure"]
        lowered = query.raw_query.lower()

        # Phase 4 honesty rule: if this scan target carried no IaC /
        # deployment-topology evidence at all, exposure defaults to UNKNOWN
        # and the inventory must say exactly that — never present a
        # synthetic zero-count verdict as if topology had been inspected.
        has_topology_evidence = any(f.evidence_chain for f in idx.operations)

        filt = query.reachability_filter
        if filt == "external" or "external" in lowered or "exposed" in lowered or "internet" in lowered:
            items = idx.external_exposure
            title = f"Externally Exposed Findings ({len(items)} operations — deployment topology indicates external exposure):"
            e_key = "external"
        elif filt == "internal" or "internal" in lowered:
            items = idx.internal_exposure
            title = f"Internally Only Findings ({len(items)} operations — deployment topology indicates internal-only):"
            e_key = "internal"
        elif filt == "mixed" or "mixed" in lowered:
            items = idx.mixed_exposure
            title = f"Mixed Exposure Findings ({len(items)} operations — both internal and external paths):"
            e_key = "mixed"
        elif filt == "unknown" or "unknown" in lowered:
            items = idx.unknown_exposure
            title = f"Unknown Exposure Findings ({len(items)} operations — no deployment topology evidence):"
            e_key = "unknown"
        else:
            items = idx.external_exposure + idx.internal_exposure + idx.mixed_exposure + idx.unknown_exposure
            title = f"All Findings by Deployment Exposure ({len(items)} operations):"
            e_key = "all"

        if not has_topology_evidence:
            lines = [
                "=== DEPLOYMENT TOPOLOGY EXPOSURE INVENTORY ===",
                f"No IaC / deployment topology evidence was found for scan target '{idx.target}'.",
                f"All {len(idx.operations)} cryptographic operations therefore default to exposure state UNKNOWN.",
            ]
            if re.search(r"\b(container|container image|docker|oci|inside this container|in the image|final image)\b", lowered):
                lines.append("Reachability is UNKNOWN. Static container image inspection does NOT prove external network exposure.")
            lines.append("Deployment manifests and network topology are required to verify whether any finding is externally exposed.")
            items = []
            e_key = "unknown"
        else:
            lines = ["=== DEPLOYMENT TOPOLOGY EXPOSURE INVENTORY ===", title]
            if not items:
                lines.append("  (No findings matching this exposure state)")
            else:
                for it in items[:15]:
                    loc = it.evidence[0].display_location if it.evidence else "unknown"
                    sources.append(f"finding:{it.id}:{loc}")
                    evidence_chain = it.evidence_chain or "no topology evidence"
                    lines.append(f"- {it.name} [{it.exposure_state}] at {loc}")
                    if it.workload:
                        lines.append(f"    Workload: {it.workload}")
                    if it.service:
                        lines.append(f"    Service: {it.service}")
                    if it.ingress:
                        lines.append(f"    Ingress: {it.ingress}")
                    if it.namespace:
                        lines.append(f"    Namespace: {it.namespace}")
                    lines.append(f"    Evidence: {evidence_chain}")

        aggregations = {
            "exposure_state": e_key,
            "count": len(items),
            "percentage_of_operations": round((len(items) / len(idx.operations) * 100), 1) if idx.operations else 0.0,
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"exposure_state": e_key, "count": len(items)},
            findings=items,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(items)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=[it.name for it in items],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 4. References vs. Operations (Pillar 1)
    # -------------------------------------------------------------------------

    def _handle_references(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["references:inventory"]

        target_ent = query.entities[0].upper() if query.entities else None

        if target_ent:
            # Check where this specific entity is only mentioned as a reference
            all_for_ent = idx.findings_by_name.get(target_ent, [])
            refs_for_ent = [f for f in all_for_ent if f.is_reference]
            ops_for_ent = [f for f in all_for_ent if f.is_operation]

            lines = [
                f"=== REFERENCES FOR {target_ent} ===",
                f"Algorithm: {target_ent}",
                f"Real OPERATIONS: {len(ops_for_ent)}",
                f"Static String REFERENCES: {len(refs_for_ent)}",
                "",
            ]
            if refs_for_ent:
                lines.append("Reference Occurrences (comments, strings, documentation, fixtures):")
                for r in refs_for_ent:
                    loc = r.evidence[0].display_location if r.evidence else "unknown"
                    sources.append(f"reference:{r.id}:{loc}")
                    snip = f' (text: "{r.evidence[0].snippet}")' if r.evidence and r.evidence[0].snippet else ""
                    lines.append(f"- {loc}{snip}")
            else:
                lines.append(f"No static string references recorded for {target_ent}; all occurrences are real operations.")

            aggregations = {
                "entity": target_ent,
                "references_count": len(refs_for_ent),
                "operations_count": len(ops_for_ent),
            }

            pkg = EvidencePackage(
                query=query,
                scan_identity={"scan_id": idx.scan_id, "target": idx.target},
                summary={"entity": target_ent, "references": len(refs_for_ent)},
                references=refs_for_ent,
                findings=ops_for_ent,
                aggregations=aggregations,
                sources=sources,
                diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(refs_for_ent)),
            )

            return RetrievalResult(
                context="\n".join(lines),
                sources=sources,
                matched_findings=[target_ent],
                structured_data=aggregations,
                evidence_package=pkg,
            )

        # General references summary
        refs = idx.references
        distinct_ref_algos = sorted({r.name for r in refs})

        lines = [
            "=== STATIC STRING REFERENCES (Pillar 1) ===",
            f"Total Static References: {len(refs)}",
            f"Total Real Operations: {len(idx.operations)}",
            f"Distinct Algorithms Appearing As References: {', '.join(distinct_ref_algos) if distinct_ref_algos else 'None'}",
            "",
            "A CRYPTO_REFERENCE is a string literal, constant, or comment that looks like an algorithm name but was never observed as a live API call.",
            "References are excluded from migration planning and operation risk counts.",
            "",
            "Sample Reference Mentions:",
        ]
        for r in refs[:10]:
            loc = r.evidence[0].display_location if r.evidence else "unknown"
            sources.append(f"reference:{r.id}:{loc}")
            lines.append(f"- {r.name} at {loc}")

        aggregations = {
            "total_references": len(refs),
            "references": len(refs),
            "total_operations": len(idx.operations),
            "operations": len(idx.operations),
            "distinct_reference_algorithms": len(distinct_ref_algos),
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"total_references": len(refs)},
            references=refs,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(refs)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=distinct_ref_algos,
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 5. Specific Finding Lookup / Entity Resolution (All Pillars)
    # -------------------------------------------------------------------------

    def _handle_findings_lookup(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        matched: list[FindingRecord] = []
        sources: list[str] = []

        # Find all records matching query entities
        for ent in query.entities:
            records = idx.findings_by_name.get(ent.upper(), [])
            for r in records:
                if r not in matched:
                    matched.append(r)

        # Apply filters if present
        if query.reachability_filter:
            if query.reachability_filter == "live":
                matched = [r for r in matched if r.reachability in ("live-external", "live-internal")]
            else:
                matched = [r for r in matched if r.reachability == query.reachability_filter]

        if query.quantum_filter:
            matched = [r for r in matched if r.quantum_status == query.quantum_filter]

        if query.finding_type_filter:
            matched = [r for r in matched if r.finding_type == query.finding_type_filter]

        if query.language_filter:
            matched = [r for r in matched if (r.primary_language or "").lower() == query.language_filter.lower()]

        if not matched:
            names_present = ", ".join(sorted({f.name for f in idx.findings}))
            target_str = ", ".join(query.entities) if query.entities else ", ".join(query.unresolved_entities)
            msg = (
                f"No findings matching '{target_str}' with the specified filters were found in this scan. "
                f"Algorithms present in this scan include: {names_present}."
            )
            return RetrievalResult(
                context=msg,
                sources=[],
                matched_findings=[],
                evidence_package=EvidencePackage(
                    query=query,
                    scan_identity={"scan_id": idx.scan_id, "target": idx.target},
                    summary={"matched_count": 0},
                    diagnostic_trace=self._build_diagnostic_trace(query, {"matched_count": 0}, [], 0),
                ),
            )

        cards = []
        for r in matched:
            loc = r.evidence[0].display_location if r.evidence else (r.primary_file or "unknown")
            sources.append(f"finding:{r.id}:{loc}")
            is_live_str = "Yes (active execution in call graph)" if r.reachability in ("live-external", "live-internal") else f"No ({r.reachability})"
            card = [
                f"=== FINDING: {r.name} (ID: {r.id}) ===",
                f"Finding Type: {r.finding_type}",
                f"Primitive: {r.primitive}",
                f"Parameter Set / Key Size: {r.parameter_set or 'not specified'}",
                f"Mode: {r.mode or 'default'}",
                f"Quantum Vulnerability Status: {r.quantum_status}",
                f"Runtime Reachability: {r.reachability}",
                f"Is Actually Used / Live: {is_live_str}",
                f"Confidence: {r.confidence}",
                f"Detector: {r.detector_id or 'unknown'} (v{r.detector_version or '0.1.0'})",
            ]

            if r.risk_score is not None:
                card.append(f"Risk Score: {r.risk_score:.2f}")
            if r.cost_days is not None:
                card.append(f"Estimated Migration Cost: {r.cost_days} engineer-days ({r.cost_source})")

            if r.shelf_life_years is not None:
                card.append(f"Shelf-Life: {r.shelf_life_years} years (category: {r.shelf_life_category or 'default'})")
                if r.shelf_life_note:
                    card.append(f"Shelf-Life Mosca Note: {r.shelf_life_note}")

            if r.blast_radius_records:
                card.append("Blast Radius Buffer Constraints:")
                for b in r.blast_radius_records:
                    card.append(
                        f"  - Buffer: {b.buffer_name} ({b.kind}) declared {b.declared_bytes}B, "
                        f"needs {b.pqc_bytes}B ({b.overflow_bytes}B overflow, replacement: {b.pqc_replacement}, severity: {b.severity})"
                    )

            if r.callers:
                card.append(f"Direct Callers: {', '.join(r.callers)}")
            if r.callees:
                card.append(f"Direct Callees: {', '.join(r.callees)}")

            card.append("Evidence Occurrences:")
            if r.evidence:
                for ev in r.evidence:
                    disp = ev.display_location
                    snip = f' -> code: `{ev.snippet}`' if ev.snippet else ''
                    card.append(f"  - {disp}{snip}")
            else:
                card.append("  (no direct occurrences recorded)")

            cards.append("\n".join(card))

        aggregations = {
            "matched_count": len(matched),
            "operations_count": len([r for r in matched if r.is_operation]),
            "references_count": len([r for r in matched if r.is_reference]),
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"matched_count": len(matched)},
            findings=[r for r in matched if r.is_operation],
            references=[r for r in matched if r.is_reference],
            relationships=[edge for edge in idx.graph_edges if edge.source_id in {r.id for r in matched}],
            sensitivity=[sl for r in matched for sl in r.shelf_life_records],
            blast_radius=[br for r in matched for br in r.blast_radius_records],
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(matched)),
        )

        return RetrievalResult(
            context="\n\n".join(cards),
            sources=sources,
            matched_findings=[r.name for r in matched],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 6. Relationships & Dependency Graph (Pillar 1)
    # -------------------------------------------------------------------------

    def _handle_relationships(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["relationships:graph"]
        lines = ["=== CRYPTOGRAPHIC RELATIONSHIPS & DEPENDENCY GRAPH ==="]

        target_name = query.entities[0].upper() if query.entities else None

        if target_name:
            matching_recs = idx.findings_by_name.get(target_name, [])
            if not matching_recs:
                return RetrievalResult(
                    context=f"No findings matching '{target_name}' were found in the dependency graph.",
                    sources=[],
                    matched_findings=[],
                )
            rec = matching_recs[0]
            loc = rec.evidence[0].display_location if rec.evidence else (rec.primary_file or "unknown")
            sources.append(f"finding:{rec.id}:{loc}")

            lines.append(f"Asset: {rec.name} [{rec.reachability}, {rec.quantum_status}] at {loc}")

            if rec.callers:
                lines.append("Incoming Callers (Functions reaching this crypto):")
                for c in rec.callers:
                    lines.append(f"  - {c}")
            else:
                lines.append("Incoming Callers: None directly recorded in static call graph")

            if rec.callees:
                lines.append("Outgoing Callees (Functions called by this crypto):")
                for c in rec.callees:
                    lines.append(f"  - {c}")

            if rec.blast_radius_records:
                lines.append("Blast Radius Constraints:")
                for b in rec.blast_radius_records:
                    lines.append(
                        f"  - Buffer '{b.buffer_name}' overflows by {b.overflow_bytes}B upon migrating to {b.pqc_replacement or 'PQC'}"
                    )

            related_edges = [
                e for e in idx.graph_edges
                if e.source_name.upper() == target_name or e.target_name.upper() == target_name
                or (e.caller_function and e.caller_function in rec.callers)
            ]

            aggregations = {
                "asset": rec.name,
                "callers_count": len(rec.callers),
                "callees_count": len(rec.callees),
                "blast_radius_count": len(rec.blast_radius_records),
            }

            pkg = EvidencePackage(
                query=query,
                scan_identity={"scan_id": idx.scan_id, "target": idx.target},
                summary={"target_asset": rec.name},
                findings=[rec],
                relationships=related_edges,
                blast_radius=rec.blast_radius_records,
                aggregations=aggregations,
                sources=sources,
                diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(related_edges)),
            )

            return RetrievalResult(
                context="\n".join(lines),
                sources=sources,
                matched_findings=[rec.name],
                structured_data=aggregations,
                evidence_package=pkg,
            )

        # General graph summary
        lines.append(f"Total Recorded Call Relations / Edges: {len(idx.graph_edges)}")
        for edge in idx.graph_edges[:12]:
            loc = edge.locator or "unknown"
            sources.append(f"call_relation:{edge.source_name}->{edge.target_name}:{loc}")
            lines.append(f"- {edge.caller_function or edge.source_name} -> {edge.callee_function or edge.target_name} ({loc})")

        aggregations = {"total_edges": len(idx.graph_edges)}
        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"total_edges": len(idx.graph_edges)},
            relationships=idx.graph_edges,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(idx.graph_edges)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=[],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 6b. Compiled Binary / Static Artifact Cryptography
    # -------------------------------------------------------------------------

    def _handle_binary_crypto(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        lowered = query.raw_query.lower()
        binary_findings = list(idx.binary_findings)
        if not binary_findings:
            binary_findings = [f for f in idx.findings if f.is_binary]

        # Entity filter (e.g. RSA)
        if query.entities:
            target_ents = {e.upper() for e in query.entities}
            matched = [
                f for f in binary_findings
                if f.name.upper() in target_ents
                or (f.observed_value and any(e in f.observed_value.upper() for e in target_ents))
                or (f.properties.get("algorithm") and f.properties["algorithm"].upper() in target_ents)
            ]
        elif "libcrypto" in lowered:
            matched = [
                f for f in binary_findings
                if "libcrypto" in (f.observed_value or "").lower()
                or "libcrypto" in (f.properties.get("library") or "").lower()
            ]
        elif "library" in lowered and ("only" in lowered or "level" in lowered or "link" in lowered):
            matched = [
                f for f in binary_findings
                if f.evidence_type == "linked_library"
            ]
        elif "string" in lowered:
            matched = [
                f for f in binary_findings
                if f.evidence_type == "algorithm_string"
            ]
        elif query.quantum_filter == "broken-by-shor" or "quantum vulnerable" in lowered or "vulnerable" in lowered:
            matched = [
                f for f in binary_findings
                if f.quantum_status == "broken-by-shor"
            ]
        else:
            matched = binary_findings

        # Execution check question
        is_execution_query = bool(
            re.search(r"\b(actually executed|actually execute|actually executes|runtime execution|definitely executed|executed at runtime)\b", lowered)
        )
        is_limitation_query = bool(
            re.search(r"\b(can'?t you determine|cannot you determine|limitation|limitations|unknowns)\b", lowered)
        )

        sources = ["binary_scanner:static_inspection"]
        for m in matched:
            loc = m.evidence[0].display_location if m.evidence else (m.primary_file or "unknown")
            sources.append(f"binary_finding:{m.id}:{loc}")

        # Deterministic aggregations
        binaries_seen = sorted({f.primary_file for f in binary_findings if f.primary_file})
        by_ev_type: dict[str, int] = {}
        for f in binary_findings:
            et = f.evidence_type or "unknown"
            by_ev_type[et] = by_ev_type.get(et, 0) + 1

        lib_only = [f for f in binary_findings if f.evidence_type == "linked_library"]
        algo_strings = [f for f in binary_findings if f.evidence_type == "algorithm_string"]
        symbols = [f for f in binary_findings if f.evidence_type == "symbol"]
        shor_vulnerable = [f for f in binary_findings if f.quantum_status == "broken-by-shor"]

        # Build context
        lines: list[str] = [
            "=== COMPILED BINARY / STATIC ARTIFACT CRYPTOGRAPHY EVIDENCE ===",
            f"Total Binary Findings: {len(binary_findings)}",
            f"Binaries Containing Cryptographic Evidence: {len(binaries_seen)} ({', '.join(binaries_seen) if binaries_seen else 'None'})",
            f"Evidence Breakdown: {', '.join(f'{k}={v}' for k, v in sorted(by_ev_type.items()))}",
            "",
            "CRITICAL HONEST-FRAMING GUARANTEES:",
            "- STATIC OBSERVATION ONLY: Observable symbols, linked libraries, algorithm strings, and certificates are detected statically.",
            "- RUNTIME EXECUTION IS NOT VERIFIED: Mere presence of a symbol, string, or library dependency does NOT prove execution at runtime.",
            "- LIBRARY LINKAGE DOES NOT PROVE ALGORITHM USAGE: Linking against libcrypto/libssl does not establish which specific algorithms are executed. Library-only findings have quantum status UNKNOWN.",
            "- REACHABILITY UNKNOWN: Static binary scanning does not establish runtime call graph reachability.",
        ]

        if is_execution_query:
            lines.extend([
                "",
                "=== RUNTIME EXECUTION VERDICT ===",
                "Answer: Static binary scanning observes cryptographic evidence (such as symbols and algorithm strings), but does NOT independently establish runtime execution.",
                "Static binary analysis proves that the compiled artifact references or defines the symbol/string; it does not prove whether the function is ever called at runtime or what code paths execute in production.",
            ])

        if is_limitation_query:
            lines.extend([
                "",
                "=== BINARY SCANNING LIMITATIONS ===",
                "What CANNOT be determined from static binary scanning:",
                "1. Runtime execution: We cannot prove whether an observed symbol or algorithm string is ever executed during actual runtime operation.",
                "2. Full algorithm usage from library linkage: Detecting a shared library (like libcrypto.so) proves linkage, but cannot determine which of the hundreds of library algorithms are actually called.",
                "3. Dynamic key material: Static scanning cannot extract ephemeral session keys or prove runtime key management behavior.",
                "4. Cloud/Server-side execution: API calls or client stubs cannot prove what happens on the provider's server side.",
                "5. Reachability: Binary findings cannot inherit source-level call graph reachability without dynamic profiling.",
            ])

        if matched:
            lines.append("")
            lines.append(f"=== MATCHED BINARY FINDINGS ({len(matched)}) ===")
            for f in matched:
                loc = f.evidence[0].display_location if f.evidence else (f.primary_file or "unknown")
                lines.append(f"Finding: {f.name} (ID: {f.id})")
                lines.append(f"  Artifact Path: {loc}")
                lines.append(f"  Binary Format: {f.binary_format or 'unknown'}")
                lines.append(f"  Architecture: {f.architecture or 'unknown'}")
                lines.append(f"  Evidence Type: {f.evidence_type or 'unknown'}")
                lines.append(f"  Observed Value: {f.observed_value or 'unknown'}")
                lines.append(f"  Cryptographic Library: {f.library or 'unknown'}")
                lines.append(f"  Algorithm: {f.properties.get('algorithm', f.name)}")
                lines.append(f"  Operation: {f.operation or 'unknown'}")
                lines.append(f"  Verification Scope: {f.verification_scope or 'static_binary_observation'}")
                lines.append(f"  Quantum Status: {f.quantum_status}")
                lines.append(f"  Reachability: {f.reachability} (static binary observation does not establish runtime reachability)")
                lines.append(f"  Confidence: {f.confidence}")
                lines.append(f"  Honest Framing: {f.honest_framing or 'Static binary evidence — runtime execution is not verified.'}")
                lines.append("")
        else:
            lines.append("No matching binary findings found.")

        context_str = "\n".join(lines)
        aggregations = {
            "total_binary_findings": len(binary_findings),
            "matched_binary_findings": len(matched),
            "binaries_scanned": binaries_seen,
            "evidence_type_breakdown": by_ev_type,
            "library_only_count": len(lib_only),
            "algorithm_strings_count": len(algo_strings),
            "symbols_count": len(symbols),
            "shor_vulnerable_count": len(shor_vulnerable),
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"matched_count": len(matched)},
            findings=matched,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(matched)),
        )

        return RetrievalResult(
            context=context_str,
            sources=sources,
            matched_findings=[f.id for f in matched],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 6c. Container Image Cryptographic Artefact Scanning
    # -------------------------------------------------------------------------

    def _handle_container_crypto(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        lowered = query.raw_query.lower()
        container_findings = list(idx.container_findings)
        if not container_findings:
            container_findings = [f for f in idx.findings if f.is_container]

        # Specific question intent checks
        is_binary_query = bool(re.search(r"\b(binary|binaries|compiled|elf|pe|executable)\b", lowered))
        is_source_query = bool(re.search(r"\b(source|source file|source files|python|java|go|c file)\b", lowered))
        is_cloud_kms_query = bool(re.search(r"\b(cloud kms|cloud key|kms|hsm|boto3|aws kms)\b", lowered))
        is_layer_query = bool(re.search(r"\b(which layer|what layer|layer contains|layer digest|which layer contains)\b", lowered))
        is_final_image_query = bool(re.search(r"\b(final image|still present|effective filesystem|effective image|is .* still present)\b", lowered))
        is_deleted_query = bool(re.search(r"\b(deleted|deleted by|whiteout|hidden by later|removed by later|what cryptographic artefacts were deleted)\b", lowered))
        is_execution_query = bool(re.search(r"\b(actually execute|actually executes|runtime execution|definitely execute|does the .* actually run|does it run|can you tell whether .* executes|can you tell whether .* actually executes)\b", lowered))
        is_reachability_query = bool(re.search(r"\b(externally exposed|exposed externally|reachable|network|internet|live external|is the .* externally exposed)\b", lowered))
        is_limitation_query = bool(re.search(r"\b(can'?t you determine|cannot you determine|limitation|limitations|unknowns|what don't you know|what can't you determine)\b", lowered))
        is_quantum_query = bool(re.search(r"\b(quantum vulnerable|broken by shor|shor|quantum risk|which .* quantum vulnerable)\b", lowered)) or query.quantum_filter == "broken-by-shor"

        matched = list(container_findings)

        # Entity filter (e.g. RSA, AES)
        if query.entities:
            target_ents = {e.upper() for e in query.entities}
            matched = [
                f for f in matched
                if f.name.upper() in target_ents
                or (f.observed_value and any(e in f.observed_value.upper() for e in target_ents))
                or (f.properties.get("algorithm") and f.properties["algorithm"].upper() in target_ents)
            ]

        # Sub-category filter
        if is_binary_query:
            matched = [f for f in matched if f.is_binary]
        elif is_source_query:
            matched = [f for f in matched if not f.is_binary and f.finding_type != "CLOUD_KEY_OPERATION"]
        elif is_cloud_kms_query:
            matched = [f for f in matched if f.finding_type == "CLOUD_KEY_OPERATION"]
        elif is_quantum_query:
            matched = [f for f in matched if f.quantum_status == "broken-by-shor"]

        sources = ["container_scanner:static_overlay_inspection"]
        for m in matched:
            loc = m.path_inside_container or (m.evidence[0].display_location if m.evidence else (m.primary_file or "unknown"))
            sources.append(f"container_finding:{m.id}:{loc}")

        # Unique images and layers
        images_seen = sorted({f.container_image for f in container_findings if f.container_image})
        layers_seen = sorted({f.layer_digest for f in container_findings if f.layer_digest})
        files_seen = sorted({f.path_inside_container for f in container_findings if f.path_inside_container})

        lines: list[str] = [
            "=== CONTAINER IMAGE CRYPTOGRAPHIC ARTEFACT EVIDENCE ===",
            f"Container Images Inspected: {len(images_seen)} ({', '.join(images_seen) if images_seen else 'container_image'})",
            f"Total Effective Container Crypto Findings: {len(container_findings)}",
            f"Layers With Cryptographic Artefacts: {len(layers_seen)}",
            f"Container Files Containing Crypto: {len(files_seen)}",
            "",
            "CRITICAL HONEST-FRAMING GUARANTEES FOR CONTAINER SCANNING:",
            "1. STATIC INSPECTION ONLY: Cryptographic artefacts are statically observed inside container layers. Runtime execution is NOT verified.",
            "2. REACHABILITY IS UNKNOWN: Container image presence alone does NOT establish external reachability, network exposure, or live execution without deployment/topology evidence.",
            "3. EFFECTIVE FILESYSTEM FOCUS: Findings reflect the reconstructed effective final filesystem. Files deleted or overridden in subsequent layers (AUFS whiteouts) are excluded from active findings.",
            "4. LIBRARY-ONLY EVIDENCE IS ALGORITHM-UNKNOWN: Linking against libcrypto/libssl does not prove specific algorithm usage or quantum risk unless concrete algorithm symbols/constants are identified.",
        ]

        if is_execution_query:
            lines.extend([
                "",
                "=== RUNTIME EXECUTION VERDICT ===",
                "Answer: Static inspection identifies cryptographic evidence inside the container image, but does NOT independently prove runtime execution.",
                "The scanner proves that the binary or source artifact is present within the container layer; it does not and cannot determine whether the container is executed, whether the binary is launched, or whether the cryptographic routine is invoked in production.",
            ])

        if is_reachability_query:
            lines.extend([
                "",
                "=== CONTAINER REACHABILITY VERDICT ===",
                "Answer: Reachability is UNKNOWN. Static container image inspection does NOT prove external network exposure.",
                "Container presence alone does not establish whether the container has open ports, is bound to an external network interface, is exposed behind an ingress/load balancer, or is reachable over the internet. Deployment manifests and network topology are required to verify external exposure.",
            ])

        if is_limitation_query:
            lines.extend([
                "",
                "=== HONEST SCAN LIMITATIONS FOR CONTAINER IMAGES ===",
                "What this scan CANNOT determine:",
                "1. Runtime execution — cannot verify whether the container is running or whether cryptographic functions are invoked.",
                "2. Network reachability & exposure — cannot determine whether services/ports are externally accessible or internet-facing without Kubernetes/IaC topology.",
                "3. In-flight / dynamic secrets — cannot observe encryption keys or tokens injected at runtime via environment variables or secret vaults.",
                "4. Dynamically loaded plugins — cannot inspect binaries or libraries downloaded or mounted dynamically during container execution.",
                "5. Encrypted or packed binaries — cannot inspect encrypted or obfuscated binaries without unpacking keys.",
                "6. Inaccessible remote registry state — only scans the provided local image archive or layout.",
            ])

        if is_layer_query:
            lines.extend([
                "",
                "=== LAYER PROVENANCE FOR FINDINGS ===",
            ])
            for f in matched:
                lines.append(
                    f"- Finding: {f.name} in file {f.path_inside_container or f.primary_file} -> Layer Digest: {f.layer_digest or 'unknown'} (Image: {f.container_image or 'unknown'})"
                )

        if is_final_image_query:
            lines.extend([
                "",
                "=== FINAL IMAGE PRESENCE VERDICT ===",
            ])
            for f in matched:
                status = "PRESENT in effective final image" if f.effective_fs else "HISTORICAL ONLY (deleted by subsequent layer)"
                lines.append(f"- Finding: {f.name} at {f.path_inside_container or f.primary_file} -> {status}")

        if is_deleted_query:
            lines.extend([
                "",
                "=== DELETED / WHITEOUT CRYPTOGRAPHIC ARTEFACTS ===",
                "Container overlay processing applies AUFS/OverlayFS whiteout semantics (.wh.<file> and .wh..wh..opq).",
                "Cryptographic artefacts deleted or replaced by later layers are excluded from the effective final image findings.",
            ])
            # If any findings were deleted, list them; otherwise note that all reported findings survive in the final image
            lines.append("Active findings in this scan reflect the reconstructed effective final filesystem.")

        if matched:
            lines.append("")
            lines.append(f"=== MATCHED CONTAINER FINDINGS ({len(matched)}) ===")
            for f in matched:
                loc = f.path_inside_container or (f.evidence[0].display_location if f.evidence else (f.primary_file or "unknown"))
                lines.append(f"Finding: {f.name} (ID: {f.id})")
                lines.append(f"  Container Image: {f.container_image or 'unknown'}")
                lines.append(f"  Layer Digest: {f.layer_digest or 'unknown'}")
                lines.append(f"  Path Inside Container: {loc}")
                lines.append(f"  Finding Type: {f.finding_type}")
                lines.append(f"  Quantum Status: {f.quantum_status}")
                lines.append(f"  Reachability: {f.reachability} (defaults to unknown; container presence does not establish reachability)")
                if f.is_binary:
                    lines.append(f"  Binary Format: {f.binary_format or 'unknown'}")
                    lines.append(f"  Evidence Type: {f.evidence_type or 'unknown'}")
                    lines.append(f"  Observed Value: {f.observed_value or 'unknown'}")
                elif f.finding_type == "CLOUD_KEY_OPERATION":
                    lines.append(f"  Cloud KMS Operation: {f.operation or f.observed_value or 'client_call'}")
                    lines.append(f"  Verification Scope: {f.verification_scope or 'client_call_only'}")
                lines.append(f"  Honest Framing: {f.honest_framing or 'Static inspection of container image; runtime execution is not verified.'}")
                lines.append("")
        else:
            lines.append("No matching container findings found.")

        context_str = "\n".join(lines)
        aggregations = {
            "total_container_findings": len(container_findings),
            "matched_container_findings": len(matched),
            "container_images": images_seen,
            "layers_seen": layers_seen,
            "container_files": files_seen,
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"matched_count": len(matched)},
            findings=matched,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(matched)),
        )

        return RetrievalResult(
            context=context_str,
            sources=sources,
            matched_findings=[f.id for f in matched],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    def _handle_blast_radius(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["blast_radius:inventory"]
        lines = ["=== BLAST RADIUS BUFFER CONSTRAINTS (Pillar 3) ==="]

        records = idx.blast_radius_findings
        with_overflow = [b for b in records if b.has_overflow]

        target_name = query.entities[0].upper() if query.entities else None
        if target_name:
            records = [b for b in records if b.asset_name.upper() == target_name]
            with_overflow = [b for b in records if b.has_overflow]
            lines.append(f"Filtering to asset: {target_name}")

        lines.append(f"Total Blast Radius Constraints: {len(records)} ({len(with_overflow)} with memory overflows)")
        lines.append("")

        if not records:
            lines.append("No fixed-size buffer overflows detected for this scan.")
        else:
            for b in sorted(records, key=lambda x: x.overflow_bytes, reverse=True)[:10]:
                loc = f"{b.locator}:{b.line}" if b.locator and b.line else (b.locator or "unknown")
                sources.append(f"blast_radius:{b.asset_name}:{b.buffer_name}:{loc}")
                lines.append(
                    f"- Buffer: '{b.buffer_name}' ({b.kind}) in {loc}\n"
                    f"  Asset: {b.asset_name} -> Replacement: {b.pqc_replacement or 'PQC'}\n"
                    f"  Declared: {b.declared_bytes}B | Classical: {b.classical_bytes}B | PQC: {b.pqc_bytes}B | Overflow: +{b.overflow_bytes}B\n"
                    f"  Severity: {b.severity} | Estimated Fix Effort: {b.estimated_effort_days or 1.0}d"
                )

        max_overflow = max((b.overflow_bytes for b in records), default=0)
        aggregations = {
            "total_constraints": len(records),
            "overflow_constraints": len(with_overflow),
            "max_overflow_bytes": max_overflow,
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary=aggregations,
            blast_radius=records,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(records)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=sorted({b.asset_name for b in records}),
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 8. Shelf-Life & Sensitive Data (Pillar 2)
    # -------------------------------------------------------------------------

    def _handle_sensitive_data(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["shelflife:inventory"]
        lines = ["=== SENSITIVE DATA CONTEXT & MOSCA SHELF-LIFE (Pillar 2) ==="]

        records = idx.shelf_life_findings
        cat_filter = query.sensitivity_category

        if cat_filter:
            c_low = cat_filter.lower()
            if c_low == "financial":
                records = [s for s in records if s.category.lower() in ("financial", "financial_transaction", "pan", "payment")]
            elif c_low == "biometric":
                records = [s for s in records if "biometric" in s.category.lower()]
            elif c_low in ("health_record", "health"):
                records = [s for s in records if "health" in s.category.lower() or "medical" in s.category.lower()]
            else:
                records = [s for s in records if s.category.lower() == c_low]
            lines.append(f"Category Filter: {cat_filter}")

        target_name = query.entities[0].upper() if query.entities else None
        if target_name:
            records = [s for s in records if s.asset_name.upper() == target_name]
            lines.append(f"Asset Filter: {target_name}")

        lines.append(f"Total Shelf-Life Inferences: {len(records)}")
        lines.append("")

        if not records:
            lines.append("No sensitive data shelf-life requirements recorded for this query.")
        else:
            sorted_records = sorted(records, key=lambda s: s.years, reverse=True)
            for s in sorted_records[:10]:
                loc = f"{s.locator}:{s.line}" if s.locator and s.line else (s.locator or "unknown")
                sources.append(f"shelflife:{s.asset_name}:{s.category}:{loc}")
                lines.append(
                    f"- Asset: {s.asset_name} at {loc}\n"
                    f"  Category: {s.category} | Shelf-Life: {s.years} years | Confidence: {s.confidence or 'heuristic'}\n"
                    f"  Statutory Basis: {s.statutory_basis or 'DPDP Act default'}\n"
                    f"  Mosca Theorem Note: {s.mosca_note or 'Long retention requirement requires early PQC migration'}"
                )

        longest = max(records, key=lambda s: s.years) if records else None
        aggregations = {
            "total_inferences": len(records),
            "longest_shelf_life_years": longest.years if longest else None,
            "longest_asset": longest.asset_name if longest else None,
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary=aggregations,
            sensitivity=records,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(records)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=[s.asset_name for s in records],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 9. Migration & Priority (Pillar 5)
    # -------------------------------------------------------------------------

    def _handle_migration(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["migration:candidates"]

        if not idx.migration_candidates:
            return RetrievalResult(
                context="No BROKEN_BY_SHOR migration candidates were found in this scan. No migration ordering is required.",
                sources=sources,
                matched_findings=[],
            )

        lines = [
            "=== MIGRATION PRIORITIZATION (Pillar 5) ===",
            f"Total Broken-by-Shor Migration Candidates: {len(idx.migration_candidates)}",
            "Prioritized by authoritative risk_score = shelf_life_magnitude * reachability_multiplier:",
            "",
        ]

        total_cost = sum(c.cost_days for c in idx.migration_candidates)
        top_candidates = idx.migration_candidates[:10]
        for c in top_candidates:
            sources.append(f"migration:candidate:{c.name}")
            lines.append(
                f"{c.rank}. {c.name} — Risk Score: {c.risk_score:.2f}, Reachability: {c.reachability}, "
                f"Effort: {c.cost_days}d ({c.cost_source}), Shelf-life: {c.shelf_life_years}y"
            )

        lines.append(f"\nTotal Estimated Migration Effort: {total_cost:.2f} engineer-days")

        # Largest effort candidate calculation
        largest_effort = max(idx.migration_candidates, key=lambda c: c.cost_days)
        lines.append(f"Largest Individual Migration Effort: {largest_effort.name} ({largest_effort.cost_days}d)")

        # Optimizer plan details if loaded
        if idx.migration_plan.has_plan:
            sources.append("migration:optimizer_plan")
            plan = idx.migration_plan
            lines.extend([
                f"\n=== OPTIMIZER SCHEDULE ({plan.scenario_name or 'Default'}) ===",
                f"Budget: {plan.budget_days} days",
                f"Eliminated Risk: {plan.eliminated_risk_pct:.1f}% (vs {plan.naive_eliminated_risk_pct or 0.0:.1f}% naive)",
            ])
            if plan.schedule:
                lines.append("Scheduled Sequence:")
                for item in plan.schedule[:8]:
                    lines.append(f"  - {item.get('name')}: day {item.get('start_day')}–{item.get('end_day')} (cost: {item.get('cost_days')}d)")
            if plan.unmigrated_finding_ids:
                lines.append(f"Unmigrated Findings (over budget): {len(plan.unmigrated_finding_ids)}")
        else:
            lines.append("\n(Note: No reference plan payload supplied; rankings reflect risk-density order.)")

        aggregations = {
            "candidates_count": len(idx.migration_candidates),
            "total_cost_days": total_cost,
            "top_candidate": top_candidates[0].name if top_candidates else None,
            "largest_effort_candidate": largest_effort.name,
            "largest_effort_days": largest_effort.cost_days,
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary=aggregations,
            migration={
                "candidates": [c.name for c in top_candidates],
                "top_candidate": top_candidates[0].name if top_candidates else None,
                "total_effort_days": total_cost,
                "has_plan": idx.migration_plan.has_plan,
            },
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(idx.migration_candidates)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=[c.name for c in top_candidates],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 10. Aggregations (Deterministic Python Counting & Stats)
    # -------------------------------------------------------------------------

    def _handle_aggregation(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["aggregation:metrics"]
        lines = ["=== COMPUTED SCAN AGGREGATIONS ==="]
        lowered = query.raw_query.lower()

        # Multi-criteria: e.g. "both live external and Shor-vulnerable"
        if ("live external" in lowered or "external" in lowered) and ("shor" in lowered or "quantum" in lowered):
            combo = [f for f in idx.operations if f.is_live_external and f.is_shor_vulnerable]
            lines.append(f"Operations both Live · External and Broken-by-Shor: {len(combo)}")
            for it in combo:
                loc = it.evidence[0].display_location if it.evidence else "unknown"
                sources.append(f"finding:{it.id}:{loc}")
                lines.append(f"- {it.name} at {loc}")
            aggregations = {"live_external_shor_count": len(combo)}

        elif "language" in lowered:
            lines.append("Findings by Programming Language:")
            for lang, count in sorted(idx.language_distribution.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- {lang.capitalize()}: {count} findings")
            top_lang = max(idx.language_distribution.items(), key=lambda x: x[1])[0] if idx.language_distribution else "none"
            lines.append(f"\nLanguage with most findings: {top_lang.capitalize()}")
            aggregations = {"language_distribution": idx.language_distribution, "top_language": top_lang}

        elif "algorithm" in lowered and "most" in lowered:
            algo_counts = {name: len(recs) for name, recs in idx.findings_by_name.items()}
            top_algo, count = max(algo_counts.items(), key=lambda x: x[1]) if algo_counts else ("None", 0)
            lines.append(f"Algorithm appearing most often: {top_algo} ({count} occurrences)")
            lines.append("\nTop 5 Algorithms by Frequency:")
            for name, c in sorted(algo_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                lines.append(f"- {name}: {c} occurrences")
            aggregations = {"top_algorithm": top_algo, "top_count": count}

        elif "file" in lowered or "directory" in lowered:
            lines.append(f"Total Scanned Files: {idx.total_scanned_files_count}")
            lines.append(f"Files Containing Cryptographic Findings: {len(idx.files_with_findings)}")
            top_files = sorted(idx.findings_by_file.items(), key=lambda x: len(x[1]), reverse=True)[:5]
            lines.append("\nFiles with Most Findings:")
            for path, f_list in top_files:
                lines.append(f"- {path}: {len(f_list)} findings")
            aggregations = {
                "total_scanned_files": idx.total_scanned_files_count,
                "files_with_findings": len(idx.files_with_findings),
            }

        elif "reference" in lowered:
            lines.append(f"Total Static References: {len(idx.references)}")
            lines.append(f"Total Active Operations: {len(idx.operations)}")
            lines.append(f"Total Combined Assets: {len(idx.findings)}")
            aggregations = {"references": len(idx.references), "operations": len(idx.operations)}

        elif "shor" in lowered or "quantum" in lowered:
            lines.append(f"Broken by Shor: {len(idx.broken_by_shor)}")
            lines.append(f"Classically Broken: {len(idx.broken_classically)}")
            lines.append(f"Weakened by Grover: {len(idx.weakened_by_grover)}")
            lines.append(f"Quantum-Safe: {len(idx.quantum_safe)}")
            aggregations = {
                "broken_by_shor": len(idx.broken_by_shor),
                "broken_classically": len(idx.broken_classically),
                "weakened_by_grover": len(idx.weakened_by_grover),
                "quantum_safe": len(idx.quantum_safe),
            }

        elif "unresolved" in lowered:
            unresolved = idx.unresolved_findings
            lines.append(f"Total UNRESOLVED Findings: {len(unresolved)}")
            if unresolved:
                for u in unresolved:
                    lines.append(f"- {u.evidence[0].display_location if u.evidence else 'unknown'}")
            else:
                lines.append("All detected cryptographic call sites successfully resolved to static algorithms.")
            aggregations = {"unresolved_count": len(unresolved)}

        else:
            lines.append(f"Total Findings: {len(idx.findings)} ({len(idx.operations)} operations, {len(idx.references)} references)")
            lines.append(f"Broken by Shor: {len(idx.broken_by_shor)}")
            lines.append(f"Live External: {len(idx.live_external)}")
            aggregations = {
                "total_findings": len(idx.findings),
                "operations": len(idx.operations),
                "references": len(idx.references),
            }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary=aggregations,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(lines)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=[],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 11. Comparison (Deterministic side-by-side)
    # -------------------------------------------------------------------------

    def _handle_comparison(
        self,
        targets: list[str] | str,
        name2_or_query: Any = None,
        query: NormalizedQuery | None = None,
    ) -> RetrievalResult:
        if isinstance(targets, str) and isinstance(name2_or_query, str):
            target_list = [targets, name2_or_query]
            actual_query = query or NormalizedQuery(raw_query=f"{targets} vs {name2_or_query}", intent="COMPARISON")
        elif isinstance(targets, list):
            target_list = targets
            actual_query = name2_or_query if isinstance(name2_or_query, NormalizedQuery) else (query or NormalizedQuery(raw_query="compare", intent="COMPARISON"))
        else:
            target_list = [str(targets)]
            actual_query = query or NormalizedQuery(raw_query=str(targets), intent="COMPARISON")

        idx = self.index
        sources = [f"compare:{':'.join(target_list)}"]
        lines = [f"=== COMPARISON: {' vs '.join(target_list)} ==="]

        target_findings: dict[str, list[FindingRecord]] = {}
        for t in target_list:
            f_list = idx.findings_by_name.get(t.upper(), [])
            target_findings[t] = f_list
            if not f_list:
                lines.append(f"Note: {t} has no detected findings in this scan.")
            else:
                f0 = f_list[0]
                loc = f0.evidence[0].display_location if f0.evidence else "unknown"
                sources.append(f"finding:{f0.id}:{loc}")
                lines.extend([
                    f"\n--- {t} ---",
                    f"Finding Type: {f0.finding_type}",
                    f"Quantum Status: {f0.quantum_status}",
                    f"Reachability: {f0.reachability}",
                    f"Risk Score: {f0.risk_score if f0.risk_score is not None else 'not computed'}",
                    f"Shelf Life: {f0.shelf_life_years if f0.shelf_life_years is not None else 'default/unknown'}",
                    f"Occurrences: {len(f0.evidence)} locations",
                    f"Primary Location: {loc}",
                ])

        lines.append("\n=== COMPARATIVE ASSESSMENT ===")
        scores = [
            (t, target_findings[t][0].risk_score or 0.0 if target_findings[t] else 0.0)
            for t in target_list
        ]
        scores_sorted = sorted(scores, key=lambda x: x[1], reverse=True)
        lines.append("Risk Ranking (Authoritative Score):")
        for rank, (t, s) in enumerate(scores_sorted, 1):
            lines.append(f"  {rank}. {t}: {s:.2f}")

        if len(scores_sorted) >= 2:
            top_t, top_s = scores_sorted[0]
            next_t, next_s = scores_sorted[1]
            if top_s > next_s:
                lines.append(f"- Higher Risk: {top_t} (risk_score={top_s:.2f} vs {next_t} {next_s:.2f})")
            else:
                lines.append(f"- Both have comparable computed risk scores ({top_s:.2f})")

        reach_weight = {"live-external": 3, "live-internal": 2, "unknown": 1, "inert": 0}
        reach_scores = [
            (t, reach_weight.get(target_findings[t][0].reachability, 0) if target_findings[t] else 0)
            for t in target_list
        ]
        reach_sorted = sorted(reach_scores, key=lambda x: x[1], reverse=True)
        if len(reach_sorted) >= 2 and reach_sorted[0][1] > reach_sorted[1][1]:
            top_r_target = reach_sorted[0][0]
            top_r_val = target_findings[top_r_target][0].reachability
            next_r_val = target_findings[reach_sorted[1][0]][0].reachability
            lines.append(f"- More Exposed: {top_r_target} ({top_r_val} vs {reach_sorted[1][0]} {next_r_val})")
        else:
            lines.append("- Exposure: Targets have comparable reachability states")

        all_matched = [f for t in target_list for f in target_findings[t]]
        fix_first = scores_sorted[0][0] if scores_sorted else (target_list[0] if target_list else "None")
        lines.append(f"- Recommended to Migrate/Fix First: {fix_first}")

        aggregations = {
            "targets": target_list,
            "entity1": target_list[0] if target_list else None,
            "entity2": target_list[1] if len(target_list) > 1 else None,
            "higher_risk": scores_sorted[0][0] if scores_sorted else None,
            "recommended_first": fix_first,
        }

        pkg = EvidencePackage(
            query=actual_query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary=aggregations,
            findings=[f for f in all_matched if f.is_operation],
            references=[f for f in all_matched if f.is_reference],
            blast_radius=[b for f in all_matched for b in f.blast_radius_records],
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(actual_query, aggregations, sources, len(target_list)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=target_list,
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 12. Cross-Pillar Deterministic Intersections & Deep Analyst Mode
    # -------------------------------------------------------------------------

    def _handle_cross_pillar(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["cross_pillar:deterministic_retrieval"]
        lowered = query.raw_query.lower()

        # Step 1: Base candidates from real operations (EXCLUDE references from operational calculations)
        candidates = list(idx.operations)
        target_entities = [e.upper() for e in query.entities]

        if target_entities:
            candidates = [f for f in candidates if f.name.upper() in target_entities]

        # Step 2: Vulnerability dimension filtering
        shor_requested = "shor" in lowered or query.quantum_filter == "broken-by-shor"
        classically_requested = "classically" in lowered or query.quantum_filter == "broken-classically"
        grover_requested = "grover" in lowered or query.quantum_filter == "weakened-by-grover"
        quantum_safe_requested = "safe" in lowered or query.quantum_filter == "quantum-safe"

        if shor_requested:
            candidates = [f for f in candidates if f.is_shor_vulnerable]
        elif classically_requested:
            candidates = [f for f in candidates if f.is_classically_broken]
        elif grover_requested:
            candidates = [f for f in candidates if f.is_grover_weakened]
        elif quantum_safe_requested:
            candidates = [f for f in candidates if f.is_quantum_safe]
        elif "VULNERABILITY" in query.required_pillars:
            candidates = [f for f in candidates if f.is_shor_vulnerable or f.is_classically_broken or f.quantum_status != "quantum-safe"]

        # Step 3: Reachability dimension filtering
        ext_requested = bool(re.search(r"\b(external|externally|exposed|internet|network)\b", lowered)) or query.reachability_filter == "live-external"
        int_requested = bool(re.search(r"\b(internal)\b", lowered)) or query.reachability_filter == "live-internal"
        inert_requested = bool(re.search(r"\b(inert|dead)\b", lowered)) or query.reachability_filter == "inert"
        unknown_requested = bool(re.search(r"\b(unknown)\b", lowered)) or query.reachability_filter == "unknown"

        if ext_requested:
            candidates = [f for f in candidates if f.is_live_external]
        elif int_requested:
            candidates = [f for f in candidates if f.is_live_internal]
        elif inert_requested:
            candidates = [f for f in candidates if f.is_inert]
        elif unknown_requested:
            candidates = [f for f in candidates if f.reachability == "unknown"]
        elif "REACHABILITY" in query.required_pillars:
            candidates = [f for f in candidates if f.is_live_external or f.is_live_internal]

        # Step 4: Sensitive data dimension filtering
        if "SENSITIVE_DATA" in query.required_pillars:
            if query.sensitivity_category:
                candidates = [f for f in candidates if any(s.category == query.sensitivity_category for s in f.shelf_life_records)]
            else:
                candidates = [f for f in candidates if f.has_sensitive_data or f.shelf_life_years is not None]

        # Step 5: Contradictions dimension filtering
        if "CONTRADICTIONS" in query.required_pillars:
            contra_algos = {
                c.declared_algorithm.upper()
                for c in idx.contradictions
                if c.declared_algorithm
            } | {
                c.implemented_algorithm.upper()
                for c in idx.contradictions
                if c.implemented_algorithm
            }
            if contra_algos:
                candidates = [f for f in candidates if f.name.upper() in contra_algos]

        # Deterministic intersection
        intersected_findings = candidates
        intersected_names = sorted({f.name for f in intersected_findings})
        for f in intersected_findings[:10]:
            loc = f.evidence[0].display_location if f.evidence else (f.primary_file or "unknown")
            sources.append(f"finding:{f.id}:{loc}")

        # Authoritative migration sequence for intersected findings
        filtered_migration = [c for c in idx.migration_candidates if c.name in intersected_names]
        if ext_requested:
            filtered_migration = [c for c in filtered_migration if c.reachability == "live-external"]
        top_cand = filtered_migration[0] if filtered_migration else None
        if top_cand:
            sources.append(f"migration:candidate:{top_cand.name}")

        # Downstream dependency counts (Pillar 1)
        dep_counts = idx.get_downstream_dependency_counts(intersected_findings)
        sorted_by_deps = sorted(dep_counts.items(), key=lambda x: x[1], reverse=True)
        top_dep_asset = sorted_by_deps[0][0] if sorted_by_deps else None
        top_dep_count = sorted_by_deps[0][1] if sorted_by_deps else 0

        # Transitive call paths (Pillar 1)
        transitive_paths = []
        path_targets = target_entities or (intersected_names[:3])
        for tname in path_targets:
            paths = idx.find_transitive_call_paths(tname)
            for p in paths:
                transitive_paths.append(p)
                if p.get("locator"):
                    sources.append(f"call_path:{p['path_str']}:{p.get('locator')}")

        # Auditing unknown reachability (never assume unknown is internal)
        all_ops_in_scope = idx.operations
        if target_entities:
            all_ops_in_scope = [f for f in all_ops_in_scope if f.name.upper() in target_entities]
        unknown_reach_findings = [f for f in all_ops_in_scope if f.reachability == "unknown"]

        # References distinctly separated
        ref_findings = [r for r in idx.references if not target_entities or r.name.upper() in target_entities]
        for r in ref_findings[:5]:
            loc = r.evidence[0].display_location if r.evidence else "unknown"
            sources.append(f"reference:{r.id}:{loc}")

        # Blast radius and sensitivity records for intersected assets
        blast_records = [b for f in intersected_findings for b in f.blast_radius_records]
        for b in blast_records[:5]:
            sources.append(f"blast_radius:{b.buffer_name}:{b.asset_name}")

        shelf_records_dict = {
            (s.asset_name, s.category): s
            for f in intersected_findings for s in f.shelf_life_records
        }
        for s in idx.shelf_life_findings:
            if s.asset_name.upper() in intersected_names:
                shelf_records_dict[(s.asset_name, s.category)] = s
        shelf_records = list(shelf_records_dict.values())
        for s in shelf_records[:5]:
            sources.append(f"shelflife:{s.asset_name}:{s.category}")

        contradictions_in_scope = [
            c for c in idx.contradictions
            if not intersected_names
            or (c.declared_algorithm and c.declared_algorithm.upper() in intersected_names)
            or (c.implemented_algorithm and c.implemented_algorithm.upper() in intersected_names)
        ]
        if contradictions_in_scope:
            sources.append("contradictions:in_scope")

        # Format context lines
        dim_str = ", ".join(sorted(query.required_pillars)) if query.required_pillars else "CROSS-PILLAR"
        lines = [
            "=== CROSS-PILLAR DETERMINISTIC ANALYSIS ===",
            f"Query Scope: {query.scope} | Required Dimensions: {dim_str}",
            f"Deterministic Intersection: {len(intersected_findings)} operational findings across {len(intersected_names)} distinct algorithms: {', '.join(intersected_names) if intersected_names else 'None'}",
            "",
        ]

        if intersected_findings:
            lines.append("=== OPERATIONAL FINDINGS IN SCOPE ===")
            for f in intersected_findings[:10]:
                loc = f.evidence[0].display_location if f.evidence else (f.primary_file or "unknown")
                score_str = f" | Risk Score: {f.risk_score:.2f}" if f.risk_score is not None else ""
                effort_str = f" | Effort: {f.cost_days}d ({f.cost_source})" if f.cost_days is not None else ""
                lines.append(f"- {f.name} (ID: {f.id}) [{f.reachability}, {f.quantum_status}]{score_str}{effort_str} at {loc}")

        if filtered_migration:
            lines.append("\n=== AUTHORITATIVE MIGRATION PRIORITIZATION (Pillar 5) ===")
            lines.append("Ranked by authoritative risk score for findings matching intersection criteria:")
            for rank, c in enumerate(filtered_migration[:5], 1):
                lines.append(
                    f"  {rank}. {c.name} — Risk Score: {c.risk_score:.2f}, Reachability: {c.reachability}, "
                    f"Effort: {c.cost_days}d ({c.cost_source}), Shelf-life: {c.shelf_life_years}y"
                )

        if dep_counts:
            lines.append("\n=== DOWNSTREAM DEPENDENCIES & CALL GRAPH (Pillar 1) ===")
            for name, count in sorted_by_deps[:5]:
                lines.append(f"- {name}: {count} unique incoming caller(s)/dependency path(s)")

        if transitive_paths:
            lines.append("\n=== TRANSITIVE MULTI-HOP CALL CHAINS (Pillar 1) ===")
            multi_hops = [p for p in transitive_paths if p["is_multi_hop"]]
            direct_hops = [p for p in transitive_paths if p["is_direct"]]
            if multi_hops:
                lines.append("Proven Multi-Hop Call Paths (depth > 1):")
                for p in multi_hops[:5]:
                    lines.append(f"  - {p['path_str']} ({p['hop_count']} hops, locator: {p.get('locator') or 'unknown'})")
            if direct_hops:
                lines.append("Direct Call Sites (1 hop):")
                for p in direct_hops[:5]:
                    lines.append(f"  - {p['path_str']} (direct, locator: {p.get('locator') or 'unknown'})")

        if blast_records:
            lines.append("\n=== BLAST RADIUS BUFFER CONSTRAINTS (Pillar 3) ===")
            for b in blast_records[:5]:
                lines.append(
                    f"- Buffer '{b.buffer_name}' ({b.kind}) for {b.asset_name}: declared {b.declared_bytes}B -> needs {b.pqc_bytes}B "
                    f"(+{b.overflow_bytes}B OVERFLOW, replacement: {b.pqc_replacement or 'PQC'}, effort: {b.estimated_effort_days}d)"
                )

        if shelf_records:
            lines.append("\n=== DATA SENSITIVITY & MOSCA SHELF-LIFE (Pillar 2) ===")
            for s in shelf_records[:5]:
                stat = f" | Statutory Basis: {s.statutory_basis}" if s.statutory_basis else ""
                lines.append(f"- Asset {s.asset_name} ({s.category}): {s.years} years retention required{stat}")

        if contradictions_in_scope:
            lines.append("\n=== POLICY CONTRADICTIONS & DIVERGENCES (Pillar 4) ===")
            for c in contradictions_in_scope[:3]:
                lines.append(f"- Contradiction {c.id} ({c.kind}): declared {c.declared_algorithm} vs implemented {c.implemented_algorithm}")

        # Scan limitations and uncertainties
        lines.append("\n=== SCAN UNCERTAINTIES & LIMITATIONS ===")
        if unknown_reach_findings:
            lines.append(
                f"- Reachability Uncertainty: {len(unknown_reach_findings)} finding(s) have UNKNOWN reachability. "
                "These cannot be confidently classified as externally exposed, but must NOT be assumed to be internal."
            )
        else:
            lines.append("- Reachability: All evaluated assets in this scope have resolved reachability states.")

        # References distinctly separated
        if ref_findings:
            lines.append("\n=== CRYPTO_REFERENCE RECORDS (STATIC / NON-OPERATIONAL) ===")
            lines.append("Note: These are static string occurrences (comments/literals) and carry zero operational runtime risk:")
            for r in ref_findings[:4]:
                loc = r.evidence[0].display_location if r.evidence else "unknown"
                lines.append(f"- Reference: {r.name} at {loc}")

        aggregations = {
            "intersection_count": len(intersected_findings),
            "intersected_algorithms": intersected_names,
            "prioritized_candidate": top_cand.name if top_cand else None,
            "top_candidate_risk_score": top_cand.risk_score if top_cand else None,
            "top_candidate_cost_days": top_cand.cost_days if top_cand else None,
            "dependency_counts": dep_counts,
            "top_dependency_asset": top_dep_asset,
            "top_dependency_count": top_dep_count,
            "unknown_reachability_count": len(unknown_reach_findings),
            "transitive_paths_count": len(transitive_paths),
            "references_count": len(ref_findings),
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary={"intersection_count": len(intersected_findings), "algorithms": intersected_names},
            findings=intersected_findings,
            references=ref_findings,
            relationships=[
                e for e in idx.graph_edges
                if e.target_name.upper() in intersected_names or e.source_name.upper() in intersected_names
            ],
            migration={
                "candidates": [c.name for c in filtered_migration],
                "top_candidate": top_cand.name if top_cand else None,
                "total_effort_days": sum(c.cost_days for c in filtered_migration),
                "has_plan": idx.migration_plan.has_plan,
            },
            sensitivity=shelf_records,
            blast_radius=blast_records,
            contradictions=contradictions_in_scope,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(intersected_findings)),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=intersected_names,
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # 12. Report & Scanned Files (Report Metrics)
    # -------------------------------------------------------------------------

    def _handle_report(self, query: NormalizedQuery) -> RetrievalResult:
        idx = self.index
        sources = ["report:metadata"]
        lowered = query.raw_query.lower()
        if "contradiction" in lowered:
            lines = [
                "=== POLICY CONTRADICTIONS & DIVERGENCES (Pillar 4) ===",
                f"Total Policy Contradictions Detected: {len(idx.contradictions)}",
                "",
            ]
            if not idx.contradictions:
                lines.append("No policy contradictions or cross-layer algorithm divergences detected in this scan.")
            else:
                for c in idx.contradictions:
                    lines.append(
                        f"- Contradiction: {c.id} ({c.kind})\n"
                        f"  Description: {c.description or 'Algorithm mismatch between source code and deployed config'}\n"
                        f"  Source File: {c.source_file or 'N/A'}\n"
                        f"  Config File: {c.config_file or 'N/A'}"
                    )
            aggregations = {"contradictions_count": len(idx.contradictions)}
            pkg = EvidencePackage(
                query=query,
                scan_identity={"scan_id": idx.scan_id, "target": idx.target},
                summary=aggregations,
                contradictions=idx.contradictions,
                aggregations=aggregations,
                sources=sources,
                diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(idx.contradictions)),
            )
            return RetrievalResult(
                context="\n".join(lines),
                sources=sources,
                matched_findings=[],
                structured_data=aggregations,
                evidence_package=pkg,
            )

        if any(w in lowered for w in ("determine", "know", "limitation", "unknown")):
            unresolved = idx.unresolved_findings
            unknown_r = idx.unknown_reachability
            lines = [
                "=== SCANNER UNKNOWNS & STATED LIMITATIONS ===",
                f"Total UNRESOLVED Algorithm Call Sites: {len(unresolved)}",
                f"Findings with Unknown Reachability: {len(unknown_r)}",
                "",
                "Stated Scan Limitations:",
                "- Dynamic function pointers and callbacks in C/Go default to unknown reachability.",
                "- Shelf-life heuristic defaults to DPDP Act 2023 (10 years) for unannotated data.",
                "- Fixed-size buffer blast radius checks inspect stack/struct/parameter declarations.",
                "",
            ]
            if unresolved:
                lines.append("Unresolved Call Sites:")
                for u in unresolved:
                    lines.append(f"- {u.evidence[0].display_location if u.evidence else 'unknown'}")
            else:
                lines.append("Unresolved Call Sites: None (all detected cryptographic call sites resolved to static algorithms).")

            if unknown_r:
                lines.append("\nFindings with Unknown Reachability:")
                for uk in unknown_r[:8]:
                    loc = uk.evidence[0].display_location if uk.evidence else "unknown"
                    lines.append(f"- {uk.name} at {loc}")

            aggregations = {
                "unresolved_count": len(unresolved),
                "unknown_reachability_count": len(unknown_r),
            }
            pkg = EvidencePackage(
                query=query,
                scan_identity={"scan_id": idx.scan_id, "target": idx.target},
                summary=aggregations,
                aggregations=aggregations,
                sources=sources,
                diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, len(unknown_r)),
            )
            return RetrievalResult(
                context="\n".join(lines),
                sources=sources,
                matched_findings=[],
                structured_data=aggregations,
                evidence_package=pkg,
            )

        lines = [
            "=== SCAN & REPORT METRICS ===",
            f"Target Directory: {idx.target}",
            f"Scan Serial Number: {idx.serial_number or 'N/A'}",
            f"Scan Timestamp: {idx.timestamp or 'N/A'}",
            f"Total Files Scanned: {idx.total_scanned_files_count}",
            f"Files with Cryptographic Findings: {len(idx.files_with_findings)}",
            "",
            "Stated Scan Limitations:",
            "- Dynamic call graphs in C/Go default to unknown reachability.",
            "- Only DPDP Act 2023 is cited for shelf-life heuristics (default 10 years).",
            "- Fixed-size buffer blast radius checks inspect stack/struct/parameter declarations.",
        ]

        if idx.contradictions:
            lines.append(f"\nPolicy Contradictions Detected: {len(idx.contradictions)}")
            for c in idx.contradictions:
                lines.append(f"- {c.kind}: {c.description or 'Algorithm mismatch'} ({c.source_file} vs {c.config_file})")

        aggregations = {
            "total_files": idx.total_scanned_files_count,
            "files_with_findings": len(idx.files_with_findings),
            "contradictions": len(idx.contradictions),
        }

        pkg = EvidencePackage(
            query=query,
            scan_identity={"scan_id": idx.scan_id, "target": idx.target},
            summary=aggregations,
            contradictions=idx.contradictions,
            aggregations=aggregations,
            sources=sources,
            diagnostic_trace=self._build_diagnostic_trace(query, aggregations, sources, idx.total_scanned_files_count),
        )

        return RetrievalResult(
            context="\n".join(lines),
            sources=sources,
            matched_findings=[],
            structured_data=aggregations,
            evidence_package=pkg,
        )

    # -------------------------------------------------------------------------
    # Diagnostic Trace Builder (Requirement 18)
    # -------------------------------------------------------------------------

    def _build_diagnostic_trace(
        self,
        query: NormalizedQuery,
        aggregations: dict[str, Any],
        sources: list[str],
        result_count: int,
    ) -> dict[str, Any]:
        return {
            "question": query.raw_query,
            "normalized_query": {
                "intent": query.intent,
                "scope": query.scope,
                "aggregation_type": query.aggregation_type,
                "ranking": query.ranking,
                "limit": query.limit,
            },
            "resolved_entities": query.entities,
            "unresolved_entities": query.unresolved_entities,
            "filters": query.filters,
            "retrieval_scope": query.scope,
            "aggregations": aggregations,
            "result_count": result_count,
            "source_records": sources,
        }
