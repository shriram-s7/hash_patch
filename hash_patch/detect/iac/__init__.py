"""hash_patch/detect/iac — Infrastructure as Code Detection.

Static parsing of Kubernetes manifests and Terraform configurations to provide
deployment topology evidence for cryptographic exposure classification.
"""

from __future__ import annotations

from hash_patch.detect.iac.correlation import enrich_all_assets, enrich_crypto_asset
from hash_patch.detect.iac.models import (
    ContainerSpec,
    CorrelationStrength,
    EnrichedFinding,
    ExposureState,
    Gateway,
    GatewayListener,
    IacScanResult,
    IacType,
    Ingress,
    IngressBackend,
    IngressPath,
    IngressRule,
    ResourceIdentity,
    Service,
    ServicePort,
    ServiceType,
    TfResource,
    TopologyEvidence,
    Workload,
)
from hash_patch.detect.iac.scanner import (
    apply_iac_enrichment,
    get_exposure_summary,
    scan_iac_directory,
)

__all__ = [
    "ContainerSpec",
    "CorrelationStrength",
    "EnrichedFinding",
    "ExposureState",
    "Gateway",
    "GatewayListener",
    "IacScanResult",
    "IacType",
    "Ingress",
    "IngressBackend",
    "IngressPath",
    "IngressRule",
    "ResourceIdentity",
    "Service",
    "ServicePort",
    "ServiceType",
    "TfResource",
    "TopologyEvidence",
    "Workload",
    "apply_iac_enrichment",
    "enrich_all_assets",
    "enrich_crypto_asset",
    "get_exposure_summary",
    "scan_iac_directory",
]
