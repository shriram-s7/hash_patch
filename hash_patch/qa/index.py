"""hash_patch/qa/index.py — Complete normalized ScanKnowledgeIndex.

Indexes all 5 pillars of cryptographic discovery and post-quantum analysis from an
emitted CycloneDX 1.6 CBOM (and optional Pillar 5 migration plan):
- Scan level: target, serial number, timestamp, total files, scanned file paths,
  contradictions, headline numbers, and limitation metrics.
- Finding level: stable IDs (bom-ref), asset names, primitives, modes, parameter sets,
  finding types (OPERATION vs CRYPTO_REFERENCE), quantum statuses, reachabilities,
  confidences, detectors, evidence occurrences, source snippets, risk scores,
  shelf-life requirements, and blast-radius buffer constraints.
- Repository level: files scanned, files producing findings, language distributions,
  and directory finding breakdowns.
- Relationship level: direct caller/callee graph edges and dependency chains.
- Migration level: candidate ranking, risk densities, effort estimations, cost sources,
  and optimizer schedule intervals.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hash_patch.analyze.cbom_reader import read_candidates


@dataclass
class FindingEvidence:
    """One concrete source occurrence demonstrating where a finding was detected."""

    locator: str
    line: int | None
    offset: int | None = None
    column: int | None = None
    snippet: str | None = None
    source_type: str | None = None

    @property
    def display_location(self) -> str:
        if self.line is not None:
            return f"{self.locator}:{self.line}"
        return self.locator


@dataclass
class BlastRadiusRecord:
    """Pillar 3 blast-radius fixed-size buffer constraint."""

    finding_id: str
    asset_name: str
    buffer_name: str
    kind: str  # "stack_buffer", "struct_member", "parameter_declaration", "db_column"
    declared_bytes: int
    classical_bytes: int
    pqc_bytes: int
    overflow_bytes: int
    severity: str
    pqc_replacement: str | None = None
    estimated_effort_days: float | None = None
    locator: str | None = None
    line: int | None = None

    @property
    def has_overflow(self) -> bool:
        return self.overflow_bytes > 0


@dataclass
class ShelfLifeRecord:
    """Pillar 2 data-context shelf-life and sensitivity inference."""

    finding_id: str
    asset_name: str
    category: str  # "biometric", "health_record", "financial_transaction", etc.
    years: int
    statutory_basis: str | None = None
    confidence: str | None = None
    mosca_note: str | None = None
    locator: str | None = None
    line: int | None = None


@dataclass
class ContradictionRecord:
    """Pillar 4 cross-layer TLS policy contradiction or algorithm divergence."""

    id: str
    kind: str  # "tls_policy" or "algorithm_divergence"
    severity: str | None
    description: str | None
    declared_algorithm: str | None = None
    implemented_algorithm: str | None = None
    source_file: str | None = None
    config_file: str | None = None


@dataclass
class GraphEdge:
    """Direct caller/callee relationship edge between findings or functions."""

    source_id: str
    target_id: str
    source_name: str
    target_name: str
    caller_function: str | None = None
    callee_function: str | None = None
    call_site: str | None = None
    locator: str | None = None
    line: int | None = None
    confidence: str = "confirmed"


@dataclass
class MigrationCandidateInfo:
    """Pillar 5 migration candidate with computed risk and effort metrics."""

    finding_id: str
    name: str
    reachability: str
    shelf_life_years: int
    shelf_life_is_default: bool
    cost_days: float
    cost_source: str
    risk_score: float
    rank: int = 0


@dataclass
class MigrationPlanInfo:
    """Pillar 5 migration schedule and risk-curve outcomes."""

    has_plan: bool = False
    budget_days: float | None = None
    scenario_name: str | None = None
    estimated_year: int | None = None
    headline: str | None = None
    schedule: list[dict[str, Any]] = field(default_factory=list)
    unmigrated_finding_ids: list[str] = field(default_factory=list)
    eliminated_risk_pct: float | None = None
    naive_eliminated_risk_pct: float | None = None


@dataclass
class FindingRecord:
    """A distinct cryptographic finding in the scan.

    Distinct findings are NEVER collapsed merely because they share an algorithm name.
    """

    id: str  # CBOM bom-ref
    name: str  # Canonical algorithm / asset name
    finding_type: str  # "OPERATION" | "CRYPTO_REFERENCE"
    primitive: str
    parameter_set: str | None
    mode: str | None
    quantum_status: str  # "broken-by-shor", "broken-classically", "weakened-by-grover", "quantum-safe", "unknown"
    reachability: str  # "live-external", "live-internal", "inert", "unknown"
    confidence: str
    detector_id: str | None
    detector_version: str | None
    evidence: list[FindingEvidence]
    properties: dict[str, str]
    shelf_life_years: int | None = None
    shelf_life_category: str | None = None
    shelf_life_note: str | None = None
    shelf_life_records: list[ShelfLifeRecord] = field(default_factory=list)
    blast_radius_records: list[BlastRadiusRecord] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    risk_score: float | None = None
    cost_days: float | None = None
    cost_source: str | None = None
    primary_file: str | None = None
    primary_language: str | None = None
    binary_format: str | None = None
    architecture: str | None = None
    evidence_type: str | None = None
    observed_value: str | None = None
    library: str | None = None
    operation: str | None = None
    verification_scope: str | None = None
    honest_framing: str | None = None
    container_image: str | None = None
    image_digest: str | None = None
    layer_digest: str | None = None
    path_inside_container: str | None = None
    effective_fs: bool = True
    # Phase 4: IaC exposure enrichment
    exposure_state: str | None = None
    correlation_strength: str | None = None
    workload: str | None = None
    service: str | None = None
    ingress: str | None = None
    namespace: str | None = None
    tf_resources: str | None = None
    evidence_chain: str | None = None

    @property
    def is_container(self) -> bool:
        return bool(
            self.container_image
            or self.path_inside_container
            or (self.evidence and self.evidence[0].source_type == "container")
            or "containerImage" in self.properties
            or "hash_patch:property.containerImage" in self.properties
        )

    @property
    def is_binary(self) -> bool:
        return self.finding_type == "COMPILED_CRYPTO_ARTEFACT" or bool(
            self.evidence and self.evidence[0].source_type == "binary"
        )

    @property
    def is_operation(self) -> bool:
        return self.finding_type == "OPERATION"

    @property
    def is_reference(self) -> bool:
        return self.finding_type == "CRYPTO_REFERENCE"

    @property
    def is_shor_vulnerable(self) -> bool:
        return self.quantum_status == "broken-by-shor"

    @property
    def is_classically_broken(self) -> bool:
        return self.quantum_status == "broken-classically"

    @property
    def is_grover_weakened(self) -> bool:
        return self.quantum_status == "weakened-by-grover"

    @property
    def is_quantum_safe(self) -> bool:
        return self.quantum_status == "quantum-safe"

    @property
    def is_live_external(self) -> bool:
        return self.reachability == "live-external"

    @property
    def is_live_internal(self) -> bool:
        return self.reachability == "live-internal"

    @property
    def is_inert(self) -> bool:
        return self.reachability == "inert"

    @property
    def is_external_exposure(self) -> bool:
        return self.exposure_state == "external"

    @property
    def is_internal_exposure(self) -> bool:
        return self.exposure_state == "internal"

    @property
    def is_mixed_exposure(self) -> bool:
        return self.exposure_state == "mixed"

    @property
    def is_unknown_exposure(self) -> bool:
        return self.exposure_state in (None, "unknown")

    @property
    def has_blast_radius(self) -> bool:
        return any(br.has_overflow for br in self.blast_radius_records)

    @property
    def blast_radius_entries(self) -> list[dict[str, Any]]:
        return [
            {
                "bufferName": b.buffer_name,
                "variableName": b.buffer_name,
                "kind": b.kind,
                "declaredBytes": b.declared_bytes,
                "classicalBytes": b.classical_bytes,
                "pqcBytes": b.pqc_bytes,
                "overflowBytes": b.overflow_bytes,
                "severity": b.severity,
                "pqcReplacement": b.pqc_replacement,
                "estimatedEffortDays": b.estimated_effort_days,
            }
            for b in self.blast_radius_records
        ]

    @property
    def has_sensitive_data(self) -> bool:
        return len(self.shelf_life_records) > 0

    @property
    def display_locations(self) -> list[str]:
        return [ev.display_location for ev in self.evidence if ev.locator]


class ScanKnowledgeIndex:
    """Normalized, searchable scan-scoped knowledge index over the complete scan report.

    Provides high-speed, deterministic lookups and aggregations over:
    - Scan metadata, target, file lists, and contradictions
    - Operational findings vs. static string references
    - Algorithmic quantum vulnerability classifications
    - Runtime reachability statuses
    - Blast radius fixed-buffer constraints
    - Shelf-life and sensitive data inferences
    - Caller/callee relationship edges
    - Migration candidates, optimizer schedules, and trade-off curves
    """

    def __init__(
        self,
        cbom: dict[str, Any],
        plan: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> None:
        self.raw_cbom = cbom
        self.raw_plan = plan

        self.serial_number: str | None = cbom.get("serialNumber")
        self.scan_id: str = scan_id or self.serial_number or "unknown_scan"
        self.target: str = cbom.get("metadata", {}).get("component", {}).get("name") or "scan"
        self.timestamp: str | None = cbom.get("metadata", {}).get("timestamp")

        # Files
        meta_props = self._parse_meta_properties(cbom)
        self.scanned_files: list[str] = self._parse_scanned_files(meta_props)
        self.total_scanned_files_count: int = len(self.scanned_files)

        # Contradictions
        self.contradictions: list[ContradictionRecord] = self._parse_contradictions(meta_props)

        # Collections
        self.findings: list[FindingRecord] = []
        self.findings_by_id: dict[str, FindingRecord] = {}
        self.findings_by_name: dict[str, list[FindingRecord]] = {}
        self.findings_by_file: dict[str, list[FindingRecord]] = {}
        self.findings_by_language: dict[str, list[FindingRecord]] = {}
        self.findings_by_reachability: dict[str, list[FindingRecord]] = {}
        self.findings_by_quantum_status: dict[str, list[FindingRecord]] = {}

        self.blast_radius_findings: list[BlastRadiusRecord] = []
        self.shelf_life_findings: list[ShelfLifeRecord] = []
        self.binary_findings: list[FindingRecord] = []
        self.container_findings: list[FindingRecord] = []
        self.findings_by_container_image: dict[str, list[FindingRecord]] = {}
        self.findings_by_layer: dict[str, list[FindingRecord]] = {}
        self.graph_edges: list[GraphEdge] = []
        self.callers_by_finding_id: dict[str, list[GraphEdge]] = {}
        self.callees_by_finding_id: dict[str, list[GraphEdge]] = {}

        # Phase 4: IaC topology indexes
        self.findings_by_exposure_state: dict[str, list[FindingRecord]] = {}
        self.findings_by_workload: dict[str, list[FindingRecord]] = {}
        self.findings_by_service: dict[str, list[FindingRecord]] = {}
        self.findings_by_ingress: dict[str, list[FindingRecord]] = {}
        self.findings_by_namespace: dict[str, list[FindingRecord]] = {}
        self.findings_by_correlation_strength: dict[str, list[FindingRecord]] = {}

        # Index components
        self._index_components(cbom)

        # Repository-level metrics
        self.files_with_findings: set[str] = {
            ev.locator for f in self.findings for ev in f.evidence if ev.locator
        }

        self.language_distribution: dict[str, int] = {}
        for f in self.findings:
            lang = f.primary_language or "unknown"
            self.language_distribution[lang] = self.language_distribution.get(lang, 0) + 1

        # Migration candidates & plan
        self.migration_candidates: list[MigrationCandidateInfo] = self._index_migration_candidates(cbom)
        self.migration_plan: MigrationPlanInfo = self._index_migration_plan(plan)

    @classmethod
    def from_cbom(
        cls,
        cbom: dict[str, Any],
        plan: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> ScanKnowledgeIndex:
        return cls(cbom, plan, scan_id=scan_id)

    # -------------------------------------------------------------------------
    # Parsing Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _parse_meta_properties(cbom: dict[str, Any]) -> dict[str, str]:
        meta_props = cbom.get("metadata", {}).get("properties", [])
        return {p.get("name", ""): p.get("value", "") for p in meta_props if isinstance(p, dict)}

    @staticmethod
    def _parse_scanned_files(meta_props: dict[str, str]) -> list[str]:
        raw_files = meta_props.get("hash_patch:scanned_files") or meta_props.get("hash-patch:scanned_files")
        if raw_files:
            try:
                parsed = json.loads(raw_files)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
            except (json.JSONDecodeError, TypeError):
                pass
        return []

    @staticmethod
    def _parse_contradictions(meta_props: dict[str, str]) -> list[ContradictionRecord]:
        contradictions: list[ContradictionRecord] = []
        for key, val in meta_props.items():
            if key.startswith("hash_patch:contradiction.") or key.startswith("hash-patch:contradiction."):
                try:
                    data = json.loads(val)
                    if isinstance(data, dict):
                        kind = "algorithm_divergence" if "declaredAlgorithm" in data else "tls_policy"
                        contradictions.append(
                            ContradictionRecord(
                                id=data.get("id") or key.rsplit(".", 1)[-1],
                                kind=kind,
                                severity=data.get("severity"),
                                description=data.get("description"),
                                declared_algorithm=data.get("declaredAlgorithm"),
                                implemented_algorithm=data.get("implementedAlgorithm"),
                                source_file=data.get("sourceIntent", {}).get("locator") or data.get("declaringLocator"),
                                config_file=data.get("deployedConfig", {}).get("locator") or data.get("callSiteLocator"),
                            )
                        )
                except (json.JSONDecodeError, TypeError):
                    pass
        return contradictions

    def _index_components(self, cbom: dict[str, Any]) -> None:
        components = [c for c in cbom.get("components", []) if c.get("type") == "cryptographic-asset"]

        for comp in components:
            props = {p["name"]: p["value"] for p in comp.get("properties", []) if "name" in p and "value" in p}
            finding_id = comp.get("bom-ref") or comp.get("name") or ""
            name = comp.get("name") or "Unknown"

            # finding_type
            ft = (
                props.get("hash_patch:findingType")
                or props.get("hash-patch:findingType")
                or props.get("hash_patch:property.finding_type")
                or "OPERATION"
            )

            # crypto_properties
            crypto_props = comp.get("cryptoProperties", {})
            algo_props = crypto_props.get("algorithmProperties", {})
            primitive = algo_props.get("primitive") or props.get("hash_patch:primitive") or "unknown"
            param_set = algo_props.get("parameterSetIdentifier") or props.get("hash_patch:parameterSet")
            mode = algo_props.get("mode") or props.get("hash_patch:mode")

            quantum_status = (
                props.get("hash_patch:quantumStatus")
                or props.get("hash-patch:quantumStatus")
                or "unknown"
            )
            reachability = (
                props.get("hash_patch:reachability")
                or props.get("hash-patch:reachability")
                or "unknown"
            )
            confidence = (
                props.get("hash_patch:confidence")
                or props.get("hash-patch:confidence")
                or "confirmed"
            )
            detector_id = props.get("hash_patch:detectorId")
            detector_version = props.get("hash_patch:detectorVersion")

            # Evidence
            evidence_list: list[FindingEvidence] = []
            for occ in comp.get("evidence", {}).get("occurrences", []):
                loc = occ.get("location", "")
                line = occ.get("line")
                offset = occ.get("offset")
                ctx = {}
                if occ.get("additionalContext"):
                    try:
                        ctx = json.loads(occ["additionalContext"])
                    except Exception:
                        ctx = {}
                evidence_list.append(
                    FindingEvidence(
                        locator=loc,
                        line=line,
                        offset=offset,
                        column=ctx.get("column"),
                        snippet=ctx.get("snippet"),
                        source_type=ctx.get("source_type"),
                    )
                )

            # Shelf-life (Pillar 2)
            shelf_life_years = None
            shelf_life_cat = None
            shelf_life_note = None
            shelf_records: list[ShelfLifeRecord] = []
            for pk, pv in props.items():
                if ":property.shelfLife." in pk or pk.startswith("shelfLife."):
                    cat = pk.rsplit(".", 1)[-1]
                    try:
                        parsed_sl = json.loads(pv)
                        years = parsed_sl.get("shelfLifeYears")
                        note = parsed_sl.get("moscaNote")
                        basis = parsed_sl.get("statutoryBasis")
                        conf = parsed_sl.get("confidence")
                        loc = parsed_sl.get("locator") or (evidence_list[0].locator if evidence_list else None)
                        sl_rec = ShelfLifeRecord(
                            finding_id=finding_id,
                            asset_name=name,
                            category=cat,
                            years=years or 0,
                            statutory_basis=basis,
                            confidence=conf,
                            mosca_note=note,
                            locator=loc,
                            line=evidence_list[0].line if evidence_list else None,
                        )
                        shelf_records.append(sl_rec)
                        self.shelf_life_findings.append(sl_rec)
                        if shelf_life_years is None or (years and years > shelf_life_years):
                            shelf_life_years = years
                            shelf_life_cat = cat
                            shelf_life_note = note
                    except Exception:
                        pass

            # Blast-radius (Pillar 3)
            blast_records: list[BlastRadiusRecord] = []
            for pk, pv in props.items():
                if ":property.blastRadius." in pk or pk.startswith("blastRadius."):
                    try:
                        parsed_br = json.loads(pv)
                        if isinstance(parsed_br, dict):
                            parts = pk.split(".")
                            kind = parts[-3] if len(parts) >= 3 else "stack_buffer"
                            buf_name = parts[-2] if len(parts) >= 2 else "buffer"
                            br_rec = BlastRadiusRecord(
                                finding_id=finding_id,
                                asset_name=name,
                                buffer_name=buf_name,
                                kind=kind,
                                declared_bytes=parsed_br.get("declaredBytes", 0),
                                classical_bytes=parsed_br.get("classicalBytes", 0),
                                pqc_bytes=parsed_br.get("pqcBytes", 0),
                                overflow_bytes=parsed_br.get("overflowBytes", 0),
                                severity=parsed_br.get("severity", "medium"),
                                pqc_replacement=parsed_br.get("pqcReplacement"),
                                estimated_effort_days=parsed_br.get("estimatedEffortDays"),
                                locator=parsed_br.get("locator") or (evidence_list[0].locator if evidence_list else None),
                                line=evidence_list[0].line if evidence_list else None,
                            )
                            blast_records.append(br_rec)
                            self.blast_radius_findings.append(br_rec)
                    except Exception:
                        pass

            # Call relations / Graph edges
            callers: list[str] = []
            callees: list[str] = []
            for pk, pv in props.items():
                if ":property.callRelation." in pk or pk.startswith("callRelation."):
                    try:
                        c_rel = json.loads(pv)
                        caller_fn = c_rel.get("caller")
                        callee_fn = c_rel.get("callee")
                        if caller_fn:
                            callers.append(caller_fn)
                        if callee_fn:
                            callees.append(callee_fn)
                        edge = GraphEdge(
                            source_id=finding_id,
                            target_id=c_rel.get("target_id") or finding_id,
                            source_name=caller_fn or name,
                            target_name=callee_fn or name,
                            caller_function=caller_fn,
                            callee_function=callee_fn,
                            call_site=c_rel.get("callSite"),
                            locator=evidence_list[0].locator if evidence_list else None,
                            line=evidence_list[0].line if evidence_list else None,
                        )
                        self.graph_edges.append(edge)
                        self.callers_by_finding_id.setdefault(finding_id, []).append(edge)
                        self.callees_by_finding_id.setdefault(finding_id, []).append(edge)
                    except Exception:
                        pass

            # Primary file & language
            primary_file = evidence_list[0].locator if evidence_list else None
            primary_language = self._detect_language(primary_file)

            # Binary metadata
            b_fmt = props.get("hash_patch:property.binaryFormat") or props.get("binaryFormat")
            b_arch = props.get("hash_patch:property.architecture") or props.get("architecture")
            b_evtype = props.get("hash_patch:property.evidenceType") or props.get("evidenceType")
            b_val = props.get("hash_patch:property.observedValue") or props.get("observedValue")
            b_lib = props.get("hash_patch:property.library") or props.get("library")
            b_op = props.get("hash_patch:property.operation") or props.get("operation")
            b_scope = props.get("hash_patch:property.verificationScope") or props.get("verificationScope")
            b_framing = props.get("hash_patch:property.honestFraming") or props.get("honestFraming")

            # Container metadata
            c_img = props.get("hash_patch:property.containerImage") or props.get("containerImage")
            c_id = props.get("hash_patch:property.imageDigest") or props.get("imageDigest")
            c_layer = props.get("hash_patch:property.layerDigest") or props.get("layerDigest")
            c_path = props.get("hash_patch:property.pathInsideContainer") or props.get("pathInsideContainer")
            c_eff_raw = props.get("hash_patch:property.effectiveFs") or props.get("effectiveFs") or "true"
            c_eff = str(c_eff_raw).lower() != "false"

            # Phase 4: IaC exposure metadata
            exposure_state = props.get("hash_patch:exposureState")
            correlation_strength = props.get("hash_patch:correlationStrength")
            workload = props.get("hash_patch:workload")
            service = props.get("hash_patch:service")
            ingress = props.get("hash_patch:ingress")
            namespace = props.get("hash_patch:namespace")
            tf_resources = props.get("hash_patch:tfResources")
            evidence_chain = props.get("hash_patch:evidenceChain")

            record = FindingRecord(
                id=finding_id,
                name=name,
                finding_type=ft,
                primitive=primitive,
                parameter_set=str(param_set) if param_set is not None else None,
                mode=str(mode) if mode is not None else None,
                quantum_status=quantum_status,
                reachability=reachability,
                confidence=confidence,
                detector_id=detector_id,
                detector_version=detector_version,
                evidence=evidence_list,
                properties=props,
                shelf_life_years=shelf_life_years,
                shelf_life_category=shelf_life_cat,
                shelf_life_note=shelf_life_note,
                shelf_life_records=shelf_records,
                blast_radius_records=blast_records,
                callers=callers,
                callees=callees,
                primary_file=primary_file,
                primary_language=primary_language,
                binary_format=b_fmt,
                architecture=b_arch,
                evidence_type=b_evtype,
                observed_value=b_val,
                library=b_lib,
                operation=b_op,
                verification_scope=b_scope,
                honest_framing=b_framing,
                container_image=c_img,
                image_digest=c_id,
                layer_digest=c_layer,
                path_inside_container=c_path,
                effective_fs=c_eff,
                exposure_state=exposure_state,
                correlation_strength=correlation_strength,
                workload=workload,
                service=service,
                ingress=ingress,
                namespace=namespace,
                tf_resources=tf_resources,
                evidence_chain=evidence_chain,
            )

            self.findings.append(record)
            self.findings_by_id[finding_id] = record
            self.findings_by_name.setdefault(name.upper(), []).append(record)
            self.findings_by_reachability.setdefault(reachability.lower(), []).append(record)
            self.findings_by_quantum_status.setdefault(quantum_status.lower(), []).append(record)
            if record.is_binary:
                self.binary_findings.append(record)
            if record.is_container:
                self.container_findings.append(record)
                if record.container_image:
                    self.findings_by_container_image.setdefault(record.container_image.lower(), []).append(record)
                    tag_prefix = record.container_image.split(":")[0].lower()
                    self.findings_by_container_image.setdefault(tag_prefix, []).append(record)
                if record.layer_digest:
                    self.findings_by_layer.setdefault(record.layer_digest.lower(), []).append(record)
                    short_layer = record.layer_digest.split(":")[-1][:12].lower()
                    self.findings_by_layer.setdefault(short_layer, []).append(record)
            if primary_language:
                self.findings_by_language.setdefault(primary_language.lower(), []).append(record)
            if primary_file:
                self.findings_by_file.setdefault(primary_file, []).append(record)

            # Phase 4: IaC topology indexes
            if record.exposure_state:
                self.findings_by_exposure_state.setdefault(record.exposure_state.lower(), []).append(record)
            if record.workload:
                self.findings_by_workload.setdefault(record.workload, []).append(record)
            if record.service:
                self.findings_by_service.setdefault(record.service, []).append(record)
            if record.ingress:
                self.findings_by_ingress.setdefault(record.ingress, []).append(record)
            if record.namespace:
                self.findings_by_namespace.setdefault(record.namespace, []).append(record)
            if record.correlation_strength:
                self.findings_by_correlation_strength.setdefault(record.correlation_strength.lower(), []).append(record)

    @staticmethod
    def _detect_language(filepath: str | None) -> str:
        if not filepath:
            return "unknown"
        ext = Path(filepath).suffix.lower()
        if ext in (".py", ".pyw"):
            return "python"
        if ext in (".java", ".jar"):
            return "java"
        if ext in (".go",):
            return "go"
        if ext in (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"):
            return "c"
        if ext in (".sql",):
            return "sql"
        if ext in (".so", ".dll", ".dylib", ".exe", ".elf", ".o", ".bin"):
            return "binary"
        return "other"

    def _index_migration_candidates(self, cbom: dict[str, Any]) -> list[MigrationCandidateInfo]:
        try:
            candidates, _ = read_candidates(cbom)
        except Exception:
            return []

        sorted_candidates = sorted(candidates, key=lambda c: c.risk_score, reverse=True)
        results = []
        for i, c in enumerate(sorted_candidates, start=1):
            info = MigrationCandidateInfo(
                finding_id=c.finding_id,
                name=c.name,
                reachability=c.reachability,
                shelf_life_years=c.shelf_life_years,
                shelf_life_is_default=c.shelf_life_is_default,
                cost_days=c.cost_days,
                cost_source=c.cost_source,
                risk_score=c.risk_score,
                rank=i,
            )
            results.append(info)
            rec = self.findings_by_id.get(c.finding_id)
            if rec:
                rec.risk_score = c.risk_score
                rec.cost_days = c.cost_days
                rec.cost_source = c.cost_source

        return results

    def _index_migration_plan(self, plan: dict[str, Any] | None) -> MigrationPlanInfo:
        if not plan:
            return MigrationPlanInfo(has_plan=False)

        scenarios = plan.get("scenarios") or []
        if not scenarios:
            return MigrationPlanInfo(has_plan=False, budget_days=plan.get("budget_days"))

        default_scenario = max(scenarios, key=lambda s: s.get("probability_weight", 0.0))
        opt_plan = default_scenario.get("optimizer_plan") or {}
        naive_plan = default_scenario.get("naive_plan") or {}

        schedule = opt_plan.get("schedule") or []
        unmigrated = opt_plan.get("unmigrated_finding_ids") or []

        return MigrationPlanInfo(
            has_plan=True,
            budget_days=plan.get("budget_days"),
            scenario_name=default_scenario.get("scenario_name"),
            estimated_year=default_scenario.get("estimated_year"),
            headline=default_scenario.get("headline_message"),
            schedule=schedule,
            unmigrated_finding_ids=unmigrated,
            eliminated_risk_pct=opt_plan.get("eliminated_risk"),
            naive_eliminated_risk_pct=naive_plan.get("eliminated_risk"),
        )

    # -------------------------------------------------------------------------
    # Convenience Query Properties
    # -------------------------------------------------------------------------

    @property
    def operations(self) -> list[FindingRecord]:
        return [f for f in self.findings if f.is_operation]

    @property
    def references(self) -> list[FindingRecord]:
        return [f for f in self.findings if f.is_reference]

    @property
    def broken_by_shor(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_shor_vulnerable]

    @property
    def broken_classically(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_classically_broken]

    @property
    def weakened_by_grover(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_grover_weakened]

    @property
    def quantum_safe(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_quantum_safe]

    @property
    def live_external(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_live_external]

    @property
    def live_internal(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_live_internal]

    @property
    def inert(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_inert]

    @property
    def unknown_reachability(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.reachability == "unknown"]

    @property
    def external_exposure(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_external_exposure]

    @property
    def internal_exposure(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_internal_exposure]

    @property
    def mixed_exposure(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_mixed_exposure]

    @property
    def unknown_exposure(self) -> list[FindingRecord]:
        return [f for f in self.operations if f.is_unknown_exposure]

    @property
    def unresolved_findings(self) -> list[FindingRecord]:
        return [f for f in self.findings if f.name.upper() == "UNRESOLVED"]

    @property
    def longest_shelf_life_finding(self) -> FindingRecord | None:
        valid = [f for f in self.findings if f.shelf_life_years is not None]
        if not valid:
            return None
        return max(valid, key=lambda f: f.shelf_life_years or 0)

    @property
    def known_component_names(self) -> set[str]:
        return {f.name for f in self.findings}

    def find_transitive_call_paths(
        self,
        target_name: str,
        direction: str = "incoming",
        max_depth: int = 5,
    ) -> list[dict[str, Any]]:
        """Deterministically traces multi-hop call paths in the static call graph.

        Distinguishes DIRECT relationships (1 hop) from MULTI-HOP relationships (>1 hop).
        Never invents unproven graph edges. Returns proven paths with cycle detection.
        """
        paths: list[dict[str, Any]] = []
        target_upper = target_name.upper()

        target_finding_ids = {f.id for f in self.findings_by_name.get(target_upper, [])}

        # Identify all terminal edges directly calling or naming target
        terminal_edges: list[GraphEdge] = []
        for e in self.graph_edges:
            is_match = (
                e.target_name.upper() == target_upper
                or (e.callee_function and target_upper in e.callee_function.upper())
                or e.target_id in target_finding_ids
                or (target_upper in e.source_name.upper() and e.callee_function and target_upper in e.callee_function.upper())
            )
            if is_match:
                terminal_edges.append(e)

        for term in terminal_edges:
            callee = term.callee_function or term.target_name
            caller = term.caller_function or term.source_name
            initial_path = [caller, callee]

            # Direct 1-hop path
            paths.append({
                "path": initial_path,
                "path_str": " -> ".join(initial_path),
                "hop_count": 1,
                "is_direct": True,
                "is_multi_hop": False,
                "root_caller": caller,
                "target": target_name,
                "locator": term.locator,
                "line": term.line,
            })

            # DFS backwards to find transitive upstream callers
            def _traverse_backwards(current_node: str, current_path: list[str], visited_nodes: set[str], depth: int):
                if depth >= max_depth:
                    return
                for parent_edge in self.graph_edges:
                    p_callee = parent_edge.callee_function or parent_edge.target_name
                    p_caller = parent_edge.caller_function or parent_edge.source_name
                    if p_callee.lower() == current_node.lower() and p_caller not in visited_nodes:
                        new_path = [p_caller] + current_path
                        new_visited = visited_nodes | {p_caller}
                        paths.append({
                            "path": new_path,
                            "path_str": " -> ".join(new_path),
                            "hop_count": len(new_path) - 1,
                            "is_direct": False,
                            "is_multi_hop": True,
                            "root_caller": p_caller,
                            "target": target_name,
                            "locator": parent_edge.locator,
                            "line": parent_edge.line,
                        })
                        _traverse_backwards(p_caller, new_path, new_visited, depth + 1)

            _traverse_backwards(caller, initial_path, {caller, callee}, 1)

        # De-duplicate paths preserving ordering
        seen_str = set()
        deduped = []
        for p in paths:
            if p["path_str"] not in seen_str:
                seen_str.add(p["path_str"])
                deduped.append(p)

        return deduped

    def get_downstream_dependency_counts(
        self, candidate_findings: list[FindingRecord] | None = None
    ) -> dict[str, int]:
        """Deterministically calculates unique incoming callers/dependencies reaching each asset."""
        targets = candidate_findings if candidate_findings is not None else self.operations
        counts: dict[str, int] = {}
        for f in targets:
            name = f.name
            direct_callers = set(f.callers)
            edge_callers = {
                e.caller_function or e.source_name
                for e in self.callers_by_finding_id.get(f.id, [])
            }
            paths = self.find_transitive_call_paths(name)
            transitive_callers = {p["root_caller"] for p in paths if p.get("root_caller")}
            all_callers = direct_callers | edge_callers | transitive_callers
            counts[name] = max(len(all_callers), len(f.callers))
        return counts


# Backward-compatible alias
ScanIndex = ScanKnowledgeIndex
