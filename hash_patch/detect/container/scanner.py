"""hash_patch/detect/container/scanner.py

Container Image Cryptographic Artefact Scanner.
Reuses:
- Existing source detectors (Python, Java, Go, C)
- Phase 1 Cloud KMS detection
- Phase 2 BinaryDetector (ELF, PE, Mach-O)
- Existing Certificate detection

Preserves:
- containerImage
- imageDigest
- layerDigest
- pathInsideContainer
- effectiveFs ("true")
- honestFraming
- reachability = Reachability.UNKNOWN
"""

from __future__ import annotations

import hashlib
import logging
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from hash_patch.detect.base import registry
from hash_patch.detect.certificates import detect_certificates
from hash_patch.detect.container.formats import (
    ContainerImageMetadata,
    parse_docker_manifest,
    parse_oci_layout,
    probe_container_target,
)
from hash_patch.detect.container.overlay import (
    EffectiveFilesystem,
    OverlayBuilder,
)
from hash_patch.detect.container.safety import (
    ContainerSecurityError,
    validate_archive_size,
)
from hash_patch.model.assets import (
    CryptoAsset,
    Reachability,
)
from hash_patch.model.evidence import Evidence

logger = logging.getLogger(__name__)


@dataclass
class ContainerScanResult:
    metadata: ContainerImageMetadata
    effective_fs: EffectiveFilesystem
    assets: list[CryptoAsset] = field(default_factory=list)
    scanned_container_files: list[str] = field(default_factory=list)


def scan_container_image(
    target_path: Path,
    reference_date: date | None = None,
) -> ContainerScanResult:
    """Scan a container image archive or layout for cryptographic artefacts.

    Guarantees:
    - Pure static inspection (no containers or binaries executed)
    - Effective filesystem reconstruction with whiteout handling
    - Full reuse of source, binary, and cloud KMS detectors
    - Container provenance tagged onto all findings without disk leak
    """
    format_type = probe_container_target(target_path)
    if not format_type:
        raise ContainerSecurityError(f"Target is not a supported container archive: {target_path}")

    validate_archive_size(target_path)

    # Temporary controlled workspace for overlay reconstruction
    with tempfile.TemporaryDirectory(prefix="hp_container_scan_") as temp_dir:
        workspace_root = Path(temp_dir)
        overlay_builder = OverlayBuilder(workspace_root)

        # 1. Unpack layers into overlay
        if format_type == "docker_archive":
            mode = "r:gz" if target_path.suffix.lower() in (".tar.gz", ".tgz") else "r:*"
            with tarfile.open(target_path, mode=mode) as tar:
                meta, layer_names = parse_docker_manifest(tar)
                for layer_rel in layer_names:
                    # Find layer member in archive
                    clean_rel = layer_rel.replace("\\", "/").lstrip("./")
                    member = None
                    for m in tar.getmembers():
                        if m.name.replace("\\", "/").lstrip("./") == clean_rel:
                            member = m
                            break
                    if not member:
                        raise ContainerSecurityError(f"Missing layer {layer_rel} in Docker archive")

                    f = tar.extractfile(member)
                    if not f:
                        raise ContainerSecurityError(f"Cannot extract layer {layer_rel}")
                    layer_bytes = f.read()
                    layer_digest = f"sha256:{hashlib.sha256(layer_bytes).hexdigest()}"
                    overlay_builder.apply_layer_tar(layer_digest, layer_bytes)

        elif format_type == "oci_layout":
            meta, layer_digests = parse_oci_layout(target_path)
            for l_digest in layer_digests:
                algo, h = l_digest.split(":", 1) if ":" in l_digest else ("sha256", l_digest)
                blob_path = target_path / "blobs" / algo / h
                if not blob_path.is_file():
                    raise ContainerSecurityError(f"Missing layer blob in OCI layout: {l_digest}")
                layer_bytes = blob_path.read_bytes()
                overlay_builder.apply_layer_tar(l_digest, layer_bytes)

        elif format_type == "oci_archive":
            # Extract to temp dir and treat as OCI layout
            oci_dir = workspace_root / "oci_layout_extracted"
            oci_dir.mkdir(parents=True, exist_ok=True)
            with tarfile.open(target_path, mode="r:*") as tar:
                tar.extractall(oci_dir)
            meta, layer_digests = parse_oci_layout(oci_dir)
            for l_digest in layer_digests:
                algo, h = l_digest.split(":", 1) if ":" in l_digest else ("sha256", l_digest)
                blob_path = oci_dir / "blobs" / algo / h
                if not blob_path.is_file():
                    raise ContainerSecurityError(f"Missing layer blob in OCI layout: {l_digest}")
                layer_bytes = blob_path.read_bytes()
                overlay_builder.apply_layer_tar(l_digest, layer_bytes)
        else:
            raise ContainerSecurityError(f"Unsupported container format: {format_type}")

        effective_fs = overlay_builder.build()

        # 2. Run existing detector framework over effective filesystem
        detectors = registry.detectors()
        scanned_files_list: list[Path] = []
        container_assets: list[CryptoAsset] = []

        # Sort paths for deterministic output
        sorted_container_paths = sorted(effective_fs.effective_files.keys())

        for c_path in sorted_container_paths:
            entry = effective_fs.effective_files[c_path]
            file_disk_path = entry.local_path
            scanned_files_list.append(file_disk_path)

            file_assets: list[CryptoAsset] = []
            for detector in detectors:
                if detector.supports(file_disk_path):
                    for asset in detector.detect(file_disk_path):
                        file_assets.append(asset)

            # Certificates detector
            if reference_date:
                for cert_asset in detect_certificates([file_disk_path], reference_date):
                    file_assets.append(cert_asset)

            # 3. Decorate each asset with container provenance & honest framing
            for asset in file_assets:
                layer_short = entry.layer_digest.split(":")[-1][:12]
                new_loc = f"container://{meta.repo_tag}@{layer_short}{c_path}"
                new_evidence: list[Evidence] = []
                for ev in asset.evidence:
                    # Never expose temp directory paths to user or CBOM
                    # Use container source_type for source findings, retain binary for binary
                    s_type = "container" if ev.source_type == "source" else ev.source_type
                    new_ev = Evidence(
                        source_type=s_type,
                        locator=new_loc,
                        line=ev.line,
                        column=ev.column,
                        byte_offset=ev.byte_offset,
                        snippet=ev.snippet,
                        detector_id=ev.detector_id,
                        detector_version=ev.detector_version,
                    )
                    new_evidence.append(new_ev)
                asset.evidence = new_evidence

                # Container-specific properties
                asset.properties["containerImage"] = meta.repo_tag
                asset.properties["imageDigest"] = meta.image_id
                asset.properties["layerDigest"] = entry.layer_digest
                asset.properties["pathInsideContainer"] = c_path
                asset.properties["effectiveFs"] = "true"
                asset.properties["assetType"] = "container_image"

                # Maintain honest framing
                if asset.finding_type == "COMPILED_CRYPTO_ARTEFACT":
                    asset.properties["verificationScope"] = "container_binary_observation"
                    asset.properties["honestFraming"] = (
                        "Cryptographic binary evidence observed inside container image; "
                        "runtime execution is not independently verified."
                    )
                elif asset.finding_type == "CLOUD_KEY_OPERATION":
                    asset.properties["verificationScope"] = "container_cloud_kms_call"
                    if "cloudKey.operation" in asset.properties and "operation" not in asset.properties:
                        asset.properties["operation"] = asset.properties["cloudKey.operation"]
                    asset.properties["honestFraming"] = (
                        "Cloud KMS client call observed in container image source; "
                        "provider-side configuration is not verified."
                    )
                else:
                    asset.properties["verificationScope"] = "container_static_source"
                    asset.properties["honestFraming"] = (
                        "Cryptographic operation observed in source contained in the container image; "
                        "runtime execution is not verified."
                    )

                # Reachability remains unknown
                asset.reachability = Reachability.UNKNOWN

                container_assets.append(asset)

        return ContainerScanResult(
            metadata=meta,
            effective_fs=effective_fs,
            assets=container_assets,
            scanned_container_files=sorted_container_paths,
        )
