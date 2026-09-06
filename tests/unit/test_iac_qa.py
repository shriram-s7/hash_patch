"""tests/unit/test_iac_qa.py

Phase 4: Q&A round-trip for IaC / deployment-topology exposure.

Builds a CBOM from IaC-enriched assets, indexes it, routes an IAC_EXPOSURE
query through the deterministic retriever, and asserts the honest exposure
inventory + evidence chain surface in the grounded context. Also verifies the
container-exposure regression guard: a container-only target must answer
"externally exposed" with UNKNOWN, never a fabricated verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hash_patch.detect.iac.scanner import apply_iac_enrichment, scan_iac_directory
from hash_patch.emit.cyclonedx import to_cyclonedx
from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, derive_asset_id
from hash_patch.model.evidence import Evidence
from hash_patch.model.findings import ScanResult
from hash_patch.qa.index import ScanKnowledgeIndex
from hash_patch.qa.query import QueryAnalyzer
from hash_patch.qa.retriever import Retriever

FIXTURES = Path(__file__).resolve().parents[2] / "testdata"
FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _make(index: ScanKnowledgeIndex, image: str) -> tuple[QueryAnalyzer, Retriever]:
    return QueryAnalyzer, Retriever(index)


def _enriched_scan_from(fixture: str) -> tuple[ScanKnowledgeIndex, Retriever]:
    iac = scan_iac_directory(FIXTURES / "iac" / "kubernetes" / fixture)
    assets = [
        CryptoAsset(
            id=derive_asset_id(AssetType.ALGORITHM, n, None, None),
            name=n,
            asset_type=AssetType.ALGORITHM,
            primitive=Primitive.SIGNATURE,
            evidence=[
                Evidence(
                    locator="container.tar",
                    source_type="container",
                    detector_id="test",
                    detector_version="0",
                    snippet="opaque",
                )
            ],
            properties={"containerImage": "payment-api:1.4"},
        )
        for n in ("RSA", "AES")
    ]
    apply_iac_enrichment(assets, iac)
    res = ScanResult(target=str(fixture), assets=assets, scan_started_at=FIXED_TS, tool_version="0.1.0")
    doc = to_cyclonedx(res)
    idx = ScanKnowledgeIndex.from_cbom(doc, scan_id="scan_iac_qa")
    return idx, Retriever(idx)


class TestIacQaExternallyExposed:
    def test_index_classifies_external(self) -> None:
        idx, _ = _enriched_scan_from("loadbalancer")
        assert len(idx.external_exposure) == 2
        assert idx.internal_exposure == []
        assert len(idx.operations) == 2

    def test_index_classifies_internal(self) -> None:
        idx, _ = _enriched_scan_from("internal")
        assert len(idx.internal_exposure) == 2
        assert idx.external_exposure == []

    def test_index_classifies_mixed(self) -> None:
        idx, _ = _enriched_scan_from("mixed")
        assert len(idx.mixed_exposure) == 2
        assert idx.external_exposure == [] and idx.internal_exposure == []

    def test_index_classifies_unknown(self) -> None:
        idx, _ = _enriched_scan_from("negative")
        assert len(idx.unknown_exposure) == 2
        assert idx.external_exposure == [] and idx.internal_exposure == []

    def test_external_query_returns_evidence_chain(self) -> None:
        idx, retriever = _enriched_scan_from("loadbalancer")
        pq = QueryAnalyzer.parse("Is the RSA in this deployment externally exposed?", idx.known_component_names)
        res = retriever.retrieve(pq)
        assert "DEPLOYMENT TOPOLOGY EXPOSURE INVENTORY" in res.context
        assert res.structured_data.get("exposure_state") == "external"
        assert res.structured_data.get("count") == 2
        assert "Workload: kubernetes:production:Deployment:payment-api" in res.context
        assert "Service: kubernetes:production:Service:payment-api (LoadBalancer)" in res.context
        assert "Namespace: production" in res.context

    def test_mixed_query_routes_to_mixed_inventory(self) -> None:
        idx, retriever = _enriched_scan_from("mixed")
        pq = QueryAnalyzer.parse("Which findings have mixed exposure?", idx.known_component_names)
        res = retriever.retrieve(pq)
        assert "DEPLOYMENT TOPOLOGY EXPOSURE INVENTORY" in res.context
        assert res.structured_data.get("exposure_state") == "mixed"
        assert res.structured_data.get("count") == 2
        assert "Mixed Exposure Findings" in res.context
        assert "Evidence: Workload: kubernetes:production:Deployment:payment-api" in res.context

    def test_input_always_grounded_deterministically(self) -> None:
        idx_a, ret_a = _enriched_scan_from("ingress")
        idx_b, ret_b = _enriched_scan_from("ingress")
        q = "Which deployments in this repo are externally exposed?"
        pq_a = QueryAnalyzer.parse(q, idx_a.known_component_names)
        pq_b = QueryAnalyzer.parse(q, idx_b.known_component_names)
        assert ret_a.retrieve(pq_a).context == ret_b.retrieve(pq_b).context


class TestContainerExposureStaysHonest:
    def test_container_without_iac_defaults_unknown(self) -> None:
        # Regression guard: Phase 3's Q9 must not regress into a fabricated
        # "deployment topology indicates external exposure" verdict when no
        # IaC data exists at all.
        iac = scan_iac_directory(FIXTURES / "iac" / "kubernetes" / "internal")
        assets = [
            CryptoAsset(
                id=derive_asset_id(AssetType.ALGORITHM, n, None, None),
                name=n,
                asset_type=AssetType.ALGORITHM,
                primitive=Primitive.SIGNATURE,
                evidence=[
                    Evidence(
                        locator="/usr/bin/server",
                        source_type="binary",
                        detector_id="container",
                        detector_version="0",
                        snippet="server binary",
                    )
                ],
                properties={"containerImage": "mixed-service:2.0", "pathInsideContainer": "/usr/bin/server"},
            )
            for n in ("RSA", "AES")
        ]
        # This fixture's workload runs payment-api:1.4, NOT mixed-service:2.0.
        apply_iac_enrichment(assets, iac)
        res = ScanResult(target="container.tar", assets=assets, scan_started_at=FIXED_TS, tool_version="0.1.0")
        doc = to_cyclonedx(res)
        idx = ScanKnowledgeIndex.from_cbom(doc, scan_id="scan_container_only")
        retriever = Retriever(idx)
        pq = QueryAnalyzer.parse("Is the RSA in this container externally exposed?", idx.known_component_names)
        rr = retriever.retrieve(pq)
        assert "UNKNOWN" in rr.context
        assert "does NOT prove external network exposure" in rr.context

    def test_no_ias_but_workload_missing_keeps_unknown(self) -> None:
        # A container image with NO matching workload in the manifest set must
        # stay UNKNOWN (mismatch / name-only resolution, never assumed).
        iac = scan_iac_directory(FIXTURES / "iac" / "kubernetes" / "internal")
        asset = CryptoAsset(
            id=derive_asset_id(AssetType.ALGORITHM, "X", None, None),
            name="X",
            asset_type=AssetType.ALGORITHM,
            primitive=Primitive.SIGNATURE,
            evidence=[Evidence(locator="x", source_type="binary", detector_id="d", detector_version="0", snippet="")],
            properties={"containerImage": "totally-unrelated:9.9"},
        )
        apply_iac_enrichment([asset], iac)
        assert asset.properties["hash_patch:exposureState"] == "unknown"
        assert asset.properties["hash_patch:correlationStrength"] == "none"


class TestEvidencePackageSerialization:
    def test_exposure_fields_reach_ollama_serialization(self) -> None:
        from hash_patch.qa.ollama_client import serialize_evidence_package

        idx, retriever = _enriched_scan_from("loadbalancer")
        pq = QueryAnalyzer.parse("Is the RSA in this deployment externally exposed?", idx.known_component_names)
        rr = retriever.retrieve(pq)
        assert rr.evidence_package is not None
        blob = serialize_evidence_package(rr.evidence_package, query=pq)
        assert "Deployment Topology Exposure: external" in blob
        assert "Workload: kubernetes:production:Deployment:payment-api" in blob
        assert "Service: kubernetes:production:Service:payment-api" in blob
        assert "Namespace: production" in blob
        assert "LoadBalancer" in blob
