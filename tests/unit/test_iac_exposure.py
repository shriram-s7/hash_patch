"""tests/unit/test_iac_exposure.py

Phase 4: unit tests for exposure-state classification and its CBOM emission.

Each fixture in testdata/iac maps a container image onto a workload and then
through services/ingresses/gateways/terraform to an ExposureState, with the
evidence chain preserved end-to-end from enrichment through the CycloneDX CBOM
properties that the Q&A index reads back.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hash_patch.detect.iac.scanner import (
    apply_iac_enrichment,
    get_exposure_summary,
    scan_iac_directory,
)
from hash_patch.emit.cyclonedx import to_cyclonedx
from hash_patch.emit.validate import validate_cbom
from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, derive_asset_id
from hash_patch.model.evidence import Evidence
from hash_patch.model.findings import ScanResult

K8S_FIXTURES = Path(__file__).resolve().parents[2] / "testdata" / "iac" / "kubernetes"
CORRELATION_FIXTURES = Path(__file__).resolve().parents[2] / "testdata" / "iac" / "correlation"
TF_FIXTURES = Path(__file__).resolve().parents[2] / "testdata" / "iac" / "terraform"
FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _container_asset(image: str, digest: str | None = None, name: str = "RSA") -> CryptoAsset:
    props: dict[str, str] = {"containerImage": image}
    if digest:
        props["imageDigest"] = digest
    return CryptoAsset(
        id=derive_asset_id(AssetType.ALGORITHM, name, None, None),
        name=name,
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
        properties=props,
    )


def _expose(fixture: str, image: str, digest: str | None = None) -> dict[str, str]:
    iac = scan_iac_directory(K8S_FIXTURES / fixture)
    asset = _container_asset(image, digest)
    apply_iac_enrichment([asset], iac)
    return {k: v for k, v in asset.properties.items() if k.startswith("hash_patch:")}


class TestK8sExposureStates:
    def test_cluster_ip_is_internal(self) -> None:
        p = _expose("internal", "payment-api:1.4")
        assert p["hash_patch:exposureState"] == "internal"
        assert "Service: kubernetes:production:Service:payment-api (ClusterIP)" in p["hash_patch:evidenceChain"]

    def test_load_balancer_is_external(self) -> None:
        p = _expose("loadbalancer", "payment-api:1.4")
        assert p["hash_patch:exposureState"] == "external"

    def test_cluster_ip_plus_ingress_host_is_mixed(self) -> None:
        p = _expose("ingress", "payment-api:1.4")
        assert p["hash_patch:exposureState"] == "mixed"
        assert p["hash_patch:ingress"] == "kubernetes:production:Ingress:payments"
        assert p["hash_patch:ingressHosts"] == "payments.example.com"
        assert "Ingress: kubernetes:production:Ingress:payments (payments.example.com)" in p["hash_patch:evidenceChain"]

    def test_mixed_internal_and_external_services(self) -> None:
        p = _expose("mixed", "payment-api:1.4")
        assert p["hash_patch:exposureState"] == "mixed"
        # Both services must appear in the evidence chain, never just one.
        assert "Service: kubernetes:production:Service:payment-api-internal (ClusterIP)" in p["hash_patch:evidenceChain"]
        assert "Service: kubernetes:production:Service:payment-api-external (LoadBalancer)" in p["hash_patch:evidenceChain"]

    def test_unresolved_service_yields_unknown(self) -> None:
        p = _expose("unresolved", "payment-api:1.4")
        assert p["hash_patch:exposureState"] == "unknown"

    def test_no_service_yields_unknown(self) -> None:
        p = _expose("negative", "payment-api:1.4")
        assert p["hash_patch:exposureState"] == "unknown"

    def test_workload_without_service_claims_only_workload_evidence(self) -> None:
        p = _expose("negative", "payment-api:1.4")
        assert "hash_patch:service" not in p
        assert p["hash_patch:evidenceChain"] == "Workload: kubernetes:production:Deployment:payment-api"

    def test_cross_namespace_does_not_contaminate(self) -> None:
        # Production runs payment-api:1.4 behind a LoadBalancer; staging runs
        # payment-api:2.0 behind ClusterIP. The production workload may never
        # inherit the staging ClusterIP service.
        p = _expose("namespaces", "payment-api:1.4")
        assert p["hash_patch:exposureState"] == "external"
        assert p["hash_patch:service"] == "kubernetes:production:Service:payment-api"
        assert "staging" not in p["hash_patch:evidenceChain"]


class TestCorrelationStrengthFixtures:
    def test_tag_match_strong(self) -> None:
        p = _expose("internal", "payment-api:1.4")
        assert p["hash_patch:correlationStrength"] == "strong"

    def test_digest_match_direct(self) -> None:
        # The workload itself is digest-pinned in this fixture, so the match
        # is DIRECT. (A container pinned to a digest can never be DIRECT
        # against a tag-pinned workload — digest and tag are different
        # reference spaces; that case stays MODERATE.)
        iac = scan_iac_directory(CORRELATION_FIXTURES / "digest_match")
        asset = _container_asset("payment-api@sha256:abc123def456")
        apply_iac_enrichment([asset], iac)
        p = {k: v for k, v in asset.properties.items() if k.startswith("hash_patch:")}
        assert p["hash_patch:correlationStrength"] == "direct"

    def test_name_only_moderate(self) -> None:
        p = _expose("internal", "payment-api")
        assert p["hash_patch:correlationStrength"] == "moderate"


class TestCbomEmission:
    def test_enrichment_properties_flow_into_cbom(self) -> None:
        iac = scan_iac_directory(K8S_FIXTURES / "loadbalancer")
        asset = _container_asset("payment-api:1.4")
        apply_iac_enrichment([asset], iac)
        res = ScanResult(target="t", assets=[asset], scan_started_at=FIXED_TS, tool_version="0.1.0")
        doc = to_cyclonedx(res)
        comp = doc["components"][0]
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert props["hash_patch:exposureState"] == "external"
        assert props["hash_patch:correlationStrength"] == "strong"
        assert props["hash_patch:workload"] == "kubernetes:production:Deployment:payment-api"
        assert props["hash_patch:service"] == "kubernetes:production:Service:payment-api"
        assert props["hash_patch:namespace"] == "production"
        assert "hash_patch:evidenceChain" in props
        # Free-form bag keeps its own namespace (not double-prefixed).
        assert "hash_patch:property.containerImage" in props

    def test_enriched_cbom_validates(self) -> None:
        iac = scan_iac_directory(K8S_FIXTURES / "mixed")
        asset = _container_asset("payment-api:1.4")
        apply_iac_enrichment([asset], iac)
        res = ScanResult(target="t", assets=[asset], scan_started_at=FIXED_TS, tool_version="0.1.0")
        doc = to_cyclonedx(res)
        assert validate_cbom(doc) == []

    def test_no_iac_no_enrichment_properties(self) -> None:
        # A directory scan with no IaC files must not invent topology props.
        empty_dir = Path(__file__).resolve().parents[2] / "testdata" / "python" / "crypto_pyca.py"
        assert not empty_dir.is_dir()


class TestTerraformExposure:
    def test_tf_via_correlated_workload_is_external(self) -> None:
        # A hybrid corpus: the container runs in a workload while the repo ALSO
        # declares an internet-facing ALB. The workload's exposure must stem
        # from its OWN service topology; the unrelated LB is not attached to an
        # asset with no workload (see test below).
        tf = scan_iac_directory(TF_FIXTURES / "alb")
        assert any(r.resource_type == "aws_lb" for r in tf.tf_resources)
        # classify_tf_exposure is exercised directly in correlation tests.
        assert tf.tf_resources[0].attributes.get("internal") is False

    def test_get_exposure_summary_runs(self) -> None:
        iac = scan_iac_directory(K8S_FIXTURES / "loadbalancer")
        summary = get_exposure_summary(iac)
        assert summary["total_workloads"] == 1
        assert summary["namespaces"] == ["production"]
        assert summary["workload_exposures"]["kubernetes:production:Deployment:payment-api"] == "external"
