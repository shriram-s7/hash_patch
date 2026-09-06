"""hash_patch/detect/iac/scanner.py — IaC Scanner.

Main entry point for scanning IaC files and correlating with crypto findings.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from hash_patch.detect.iac.kubernetes import KubernetesParser
from hash_patch.detect.iac.models import ExposureState, IacScanResult
from hash_patch.detect.iac.terraform import parse_terraform_directory
from hash_patch.model.assets import CryptoAsset

logger = logging.getLogger(__name__)


def scan_iac_directory(root_path: Path) -> IacScanResult:
    """Scan a directory for Kubernetes and Terraform IaC files."""
    result = IacScanResult()

    k8s_parser = KubernetesParser()

    for k8s_file in sorted(root_path.rglob("*.yaml")):
        try:
            k8s_result = k8s_parser.parse_file(k8s_file)
            result.workloads.extend(k8s_result.workloads)
            result.services.extend(k8s_result.services)
            result.ingresses.extend(k8s_result.ingresses)
            result.gateways.extend(k8s_result.gateways)
            result.namespaces.update(k8s_result.namespaces)
            result.parse_errors.extend(k8s_result.parse_errors)
        except Exception as e:
            result.parse_errors.append(f"{k8s_file}: {e}")

    for k8s_file in sorted(root_path.rglob("*.yml")):
        try:
            k8s_result = k8s_parser.parse_file(k8s_file)
            result.workloads.extend(k8s_result.workloads)
            result.services.extend(k8s_result.services)
            result.ingresses.extend(k8s_result.ingresses)
            result.gateways.extend(k8s_result.gateways)
            result.namespaces.update(k8s_result.namespaces)
            result.parse_errors.extend(k8s_result.parse_errors)
        except Exception as e:
            result.parse_errors.append(f"{k8s_file}: {e}")

    tf_result = parse_terraform_directory(root_path)
    result.tf_resources.extend(tf_result.tf_resources)
    result.parse_errors.extend(tf_result.parse_errors)

    return result


def apply_iac_enrichment(assets: list[CryptoAsset], iac_result: IacScanResult) -> None:
    """Apply IaC enrichment to crypto assets in place."""
    from hash_patch.detect.iac.correlation import enrich_crypto_asset

    for asset in assets:
        enriched = enrich_crypto_asset(asset, iac_result)
        if enriched.topology:
            for key, value in enriched.topology.to_properties().items():
                asset.properties[key] = value


def get_exposure_summary(iac_result: IacScanResult) -> dict[str, Any]:
    """Get a summary of exposure states from IaC scan."""
    from hash_patch.detect.iac.correlation import (
        classify_ingress_exposure,
        classify_service_exposure,
    )

    workload_exposures: dict[str, str] = {}

    for workload in iac_result.workloads:
        services = [s for s in iac_result.services if s.matches_workload(workload)]
        ingresses = []
        for svc in services:
            ingresses.extend(iac_result.find_ingresses_for_service(svc))

        states = set()
        for svc in services:
            states.add(classify_service_exposure(svc))
        for ing in ingresses:
            states.add(classify_ingress_exposure(ing))

        if ExposureState.EXTERNAL in states and ExposureState.INTERNAL in states:
            state = ExposureState.MIXED
        elif ExposureState.EXTERNAL in states:
            state = ExposureState.EXTERNAL
        elif ExposureState.INTERNAL in states:
            state = ExposureState.INTERNAL
        elif ExposureState.MIXED in states:
            state = ExposureState.MIXED
        else:
            state = ExposureState.UNKNOWN

        workload_exposures[workload.identity.key()] = state.value

    return {
        "total_workloads": len(iac_result.workloads),
        "total_services": len(iac_result.services),
        "total_ingresses": len(iac_result.ingresses),
        "total_gateways": len(iac_result.gateways),
        "total_tf_resources": len(iac_result.tf_resources),
        "namespaces": sorted(iac_result.namespaces),
        "workload_exposures": workload_exposures,
        "parse_errors": iac_result.parse_errors,
    }
