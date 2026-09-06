"""hash_patch/detect/iac/correlation.py — Container-to-IaC Correlation.

Connects container image findings to Kubernetes workloads and Terraform resources
to enrich cryptographic findings with deployment topology evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from hash_patch.detect.iac.models import (
    ContainerSpec,
    CorrelationStrength,
    EnrichedFinding,
    ExposureState,
    IacScanResult,
    Service,
    ServiceType,
    TopologyEvidence,
    Workload,
)
from hash_patch.model.assets import CryptoAsset

logger = logging.getLogger(__name__)


@dataclass
class ImageIdentity:
    """Container image identity for correlation."""
    repository: str
    tag: str | None = None
    digest: str | None = None

    @classmethod
    def from_string(cls, image_ref: str) -> ImageIdentity:
        """Parse image reference string.

        A bare `payment-api` has NO tag (None), never an implicit `latest`:
        Docker's registry shorthand aside, collapsing a name-only reference
        to tag='latest' would make an unpinned container fuzzy-match (or
        wrongly reject against) every explicitly-tagged Deployment, which
        violates the Phase 4 rule that tag mismatches are rejected while
        name-only references are a weak/modest best-effort match."""
        if "@" in image_ref:
            repo_tag, digest = image_ref.split("@", 1)
            if ":" in repo_tag:
                repository, tag = repo_tag.rsplit(":", 1)
            else:
                repository, tag = repo_tag, None
            return cls(repository=repository, tag=tag, digest=digest)
        elif ":" in image_ref:
            repository, tag = image_ref.rsplit(":", 1)
            return cls(repository=repository, tag=tag)
        else:
            return cls(repository=image_ref, tag=None)

    def matches(self, other: ImageIdentity) -> tuple[bool, CorrelationStrength]:
        """Check if this image matches another, returning strength.

        Deterministic rejection rules (Phase 4 spec): digest mismatches and
        tag mismatches are REJECTED outright — never downgraded to a fuzzy
        match. A container pinned to `payment-api@sha256:…` whose digest
        differs is a different binary even when the repository name matches;
        a container pinned `payment-api:2.0` does not run from a Deployment
        that references `payment-api:1.4`. Only name-only references (no tag,
        no digest on either side) are a weak best-effort match.
        """
        if self.digest and other.digest:
            if self.digest == other.digest:
                return True, CorrelationStrength.DIRECT
            return False, CorrelationStrength.NONE
        if self.repository != other.repository:
            return False, CorrelationStrength.NONE
        if self.tag and other.tag:
            if self.tag == other.tag:
                return True, CorrelationStrength.STRONG
            return False, CorrelationStrength.NONE
        if self.tag or other.tag:
            return True, CorrelationStrength.MODERATE
        return True, CorrelationStrength.WEAK

    def __str__(self) -> str:
        if self.digest:
            return f"{self.repository}@{self.digest}"
        if self.tag:
            return f"{self.repository}:{self.tag}"
        return self.repository


# Correlation strengths are a str-enum; never order them by .value (that
# would be alphabetical: 'direct' < 'none'). Explicit numeric rank, strongest
# first, so "best match wins" is deterministic and correct.
_CORRELATION_RANK = {
    CorrelationStrength.DIRECT: 5,
    CorrelationStrength.STRONG: 4,
    CorrelationStrength.MODERATE: 3,
    CorrelationStrength.WEAK: 2,
    CorrelationStrength.UNRESOLVED: 1,
    CorrelationStrength.NONE: 0,
}


def find_workload_for_container(
    container: ContainerSpec,
    iac_result: IacScanResult,
) -> tuple[Workload | None, CorrelationStrength]:
    """Find the Kubernetes workload that runs this container image."""
    container_image = ImageIdentity.from_string(container.image)

    best_match: Workload | None = None
    best_strength = CorrelationStrength.NONE

    for workload in iac_result.workloads:
        for w_container in workload.containers:
            workload_image = ImageIdentity.from_string(w_container.image)
            matches, strength = container_image.matches(workload_image)
            if matches and _CORRELATION_RANK[strength] > _CORRELATION_RANK[best_strength]:
                best_match = workload
                best_strength = strength

    return best_match, best_strength


def find_services_for_workload(workload: Workload, iac_result: IacScanResult) -> list[Service]:
    """Find all Kubernetes services that select this workload."""
    return iac_result.find_services_for_workload(workload)


def find_ingresses_for_service(service: Service, iac_result: IacScanResult) -> list[Any]:
    """Find all ingresses that route to this service."""
    return iac_result.find_ingresses_for_service(service)


def classify_service_exposure(service: Service) -> ExposureState:
    """Classify exposure based on Kubernetes Service type."""
    if service.service_type == ServiceType.LOAD_BALANCER:
        return ExposureState.EXTERNAL
    elif service.service_type == ServiceType.NODE_PORT:
        return ExposureState.MIXED
    elif service.service_type == ServiceType.CLUSTER_IP:
        return ExposureState.INTERNAL
    else:
        return ExposureState.UNKNOWN


def classify_ingress_exposure(ingress: Any) -> ExposureState:
    """Classify exposure based on Ingress (has external hostname)."""
    for rule in ingress.rules:
        if rule.host:
            return ExposureState.EXTERNAL
    return ExposureState.MIXED


def classify_gateway_exposure(gateway: Any) -> ExposureState:
    """Classify exposure based on Gateway listeners."""
    for listener in gateway.listeners:
        if listener.hostname:
            return ExposureState.EXTERNAL
    return ExposureState.MIXED


def classify_tf_exposure(tf_resources: list[Any]) -> ExposureState:
    """Classify exposure based on Terraform resources."""
    has_external = False
    has_internal = False

    for resource in tf_resources:
        if resource.resource_type in ("aws_lb", "aws_alb", "aws_api_gateway", "aws_apigatewayv2_api", "aws_cloudfront_distribution"):
            scheme = resource.attributes.get("internal", False)
            if isinstance(scheme, bool) and not scheme or scheme is None:
                has_external = True
            else:
                has_internal = True
        elif resource.resource_type in ("aws_lb_listener",):
            protocol = resource.attributes.get("protocol", "")
            if protocol in ("HTTPS", "HTTP"):
                has_external = True

    if has_external and has_internal:
        return ExposureState.MIXED
    elif has_external:
        return ExposureState.EXTERNAL
    elif has_internal:
        return ExposureState.INTERNAL
    return ExposureState.UNKNOWN


def compute_exposure_state(
    workload: Workload | None,
    services: list[Service],
    ingresses: list[Any],
    gateways: list[Any],
    tf_resources: list[Any],
) -> ExposureState:
    """Compute overall exposure state from topology evidence."""
    states: set[ExposureState] = set()

    if workload:
        for service in services:
            states.add(classify_service_exposure(service))
        for ingress in ingresses:
            states.add(classify_ingress_exposure(ingress))
        for gateway in gateways:
            states.add(classify_gateway_exposure(gateway))

    for tf in tf_resources:
        states.add(classify_tf_exposure([tf]))

    states.discard(ExposureState.UNKNOWN)

    if not states:
        return ExposureState.UNKNOWN
    if ExposureState.EXTERNAL in states and ExposureState.INTERNAL in states:
        return ExposureState.MIXED
    if ExposureState.EXTERNAL in states:
        return ExposureState.EXTERNAL
    if ExposureState.INTERNAL in states:
        return ExposureState.INTERNAL
    if ExposureState.MIXED in states:
        return ExposureState.MIXED
    return ExposureState.UNKNOWN


def build_topology_evidence(
    asset: CryptoAsset,
    workload: Workload | None,
    services: list[Service],
    ingresses: list[Any],
    gateways: list[Any],
    tf_resources: list[Any],
    correlation_strength: CorrelationStrength,
) -> TopologyEvidence:
    """Build topology evidence for a crypto asset."""
    exposure_state = compute_exposure_state(workload, services, ingresses, gateways, tf_resources)

    evidence_chain: list[str] = []
    if workload:
        evidence_chain.append(f"Workload: {workload.identity.key()}")
    for svc in services:
        evidence_chain.append(f"Service: {svc.identity.key()} ({svc.service_type.value})")
    for ing in ingresses:
        hosts = [r.host for r in ing.rules if r.host]
        evidence_chain.append(f"Ingress: {ing.identity.key()} ({', '.join(hosts) if hosts else 'no host'})")
    for gw in gateways:
        evidence_chain.append(f"Gateway: {gw.identity.key()}")
    for tf in tf_resources:
        evidence_chain.append(f"Terraform: {tf.full_name}")

    return TopologyEvidence(
        workload=workload,
        service=services[0] if services else None,
        ingress=ingresses[0] if ingresses else None,
        gateway=gateways[0] if gateways else None,
        tf_resources=tf_resources,
        exposure_state=exposure_state,
        correlation_strength=correlation_strength,
        evidence_chain=evidence_chain,
    )


def enrich_crypto_asset(
    asset: CryptoAsset,
    iac_result: IacScanResult,
) -> EnrichedFinding:
    """Enrich a crypto asset with IaC topology evidence."""
    container_image = None
    image_digest = None

    for key in ("containerImage", "imageDigest", "pathInsideContainer"):
        if key in asset.properties:
            if key == "containerImage":
                container_image = asset.properties[key]
            elif key == "imageDigest":
                image_digest = asset.properties[key]

    workload = None
    correlation_strength = CorrelationStrength.NONE

    if container_image:
        container_spec = ContainerSpec(name="", image=container_image, image_digest=image_digest)
        workload, correlation_strength = find_workload_for_container(container_spec, iac_result)

    services = []
    ingresses = []
    gateways = []
    tf_resources = []

    if workload:
        services = find_services_for_workload(workload, iac_result)
        for svc in services:
            ingresses.extend(find_ingresses_for_service(svc, iac_result))

    # Terraform resources are only claimed as evidence when the asset is
    # already anchored to a correlating workload. Attaching every repo-level
    # `aws_lb` / `aws_cloudfront_distribution` to an unrelated source-file
    # finding would be a false-positive machine (any repo containing an
    # internet-facing LB would relabel every crypto finding EXTERNAL), so an
    # asset with no resolved workload keeps exposure UNKNOWN even if the repo
    # contains Terraform loads balancers.
    if workload:
        tf_resources = iac_result.tf_resources
    else:
        tf_resources = []

    topology = build_topology_evidence(
        asset=asset,
        workload=workload,
        services=services,
        ingresses=ingresses,
        gateways=gateways,
        tf_resources=tf_resources,
        correlation_strength=correlation_strength,
    )

    return EnrichedFinding(
        asset_id=asset.id,
        algorithm_name=asset.name,
        container_image=container_image,
        image_digest=image_digest,
        topology=topology,
        original_reachability=asset.reachability.value,
    )


def enrich_all_assets(assets: list[CryptoAsset], iac_result: IacScanResult) -> list[EnrichedFinding]:
    """Enrich all crypto assets with IaC topology evidence."""
    return [enrich_crypto_asset(asset, iac_result) for asset in assets]
