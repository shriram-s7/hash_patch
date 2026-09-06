"""hash_patch/detect/container/formats.py

Detects and parses container image archive formats (Docker archive, OCI layout).
Extracts:
- image identifier / repository / tag
- manifest digest & config digest
- architecture & OS
- layer count & ordered layer references
"""

from __future__ import annotations

import hashlib
import json
import logging
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from hash_patch.detect.container.safety import (
    ContainerSecurityError,
    validate_archive_size,
)

logger = logging.getLogger(__name__)


@dataclass
class ContainerImageMetadata:
    format_type: str  # "docker_archive", "oci_archive", "oci_layout"
    image_id: str
    repo_tag: str
    manifest_digest: str | None = None
    config_digest: str | None = None
    architecture: str | None = None
    os: str | None = None
    layer_count: int = 0
    layer_entries: list[str] = field(default_factory=list)


def probe_container_target(path: Path) -> str | None:
    """Fast check to determine if path is a container image target.

    Returns:
    - "docker_archive" if it is a tarball containing manifest.json
    - "oci_archive" if it is a tarball containing oci-layout
    - "oci_layout" if it is a directory containing oci-layout
    - None otherwise
    """
    try:
        if path.is_dir():
            if (path / "oci-layout").is_file():
                return "oci_layout"
            if (path / "manifest.json").is_file():
                return "docker_archive"
            return None

        if path.is_file():
            # Quick suffix check or tar header probe
            suffix = path.suffix.lower()
            if suffix not in (".tar", ".tar.gz", ".tgz") and not tarfile.is_tarfile(path):
                return None

            validate_archive_size(path)
            mode = "r:gz" if suffix in (".tar.gz", ".tgz") else "r:*"
            with tarfile.open(path, mode=mode) as tar:
                names = set()
                # Only check first 20 members to avoid reading whole tar
                for i, member in enumerate(tar):
                    names.add(member.name.replace("\\", "/").lstrip("./"))
                    if i >= 20:
                        break
                if "manifest.json" in names:
                    return "docker_archive"
                if "oci-layout" in names:
                    return "oci_archive"
    except Exception as e:
        logger.debug("Failed probing container target %s: %s", path, e)
        return None
    return None


def parse_docker_manifest(
    tar: tarfile.TarFile,
) -> tuple[ContainerImageMetadata, list[str]]:
    """Parse Docker archive (docker save tarball) manifest.json and config.json."""
    try:
        manifest_member = tar.getmember("manifest.json")
    except KeyError:
        # Try finding with leading ./
        manifest_member = None
        for m in tar.getmembers():
            if m.name.replace("\\", "/").lstrip("./") == "manifest.json":
                manifest_member = m
                break
        if not manifest_member:
            raise ContainerSecurityError("Docker archive missing manifest.json")

    f = tar.extractfile(manifest_member)
    if not f:
        raise ContainerSecurityError("Failed to extract manifest.json from Docker archive")

    raw_manifest_bytes = f.read()
    manifest_digest = f"sha256:{hashlib.sha256(raw_manifest_bytes).hexdigest()}"
    try:
        manifest_data = json.loads(raw_manifest_bytes.decode("utf-8"))
    except Exception as e:
        raise ContainerSecurityError(f"Malformed manifest.json in Docker archive: {e}")

    if not isinstance(manifest_data, list) or len(manifest_data) == 0:
        raise ContainerSecurityError("manifest.json in Docker archive must be a non-empty array")

    image_entry = manifest_data[0]
    repo_tags = image_entry.get("RepoTags") or []
    repo_tag = repo_tags[0] if repo_tags else "unknown:latest"
    config_filename = image_entry.get("Config")
    layers = image_entry.get("Layers") or []

    # Config JSON
    arch: str | None = None
    os_name: str | None = None
    config_digest: str | None = None
    if config_filename:
        try:
            config_member = None
            for m in tar.getmembers():
                if m.name.replace("\\", "/").lstrip("./") == config_filename.replace("\\", "/").lstrip("./"):
                    config_member = m
                    break
            if config_member:
                cf = tar.extractfile(config_member)
                if cf:
                    cfg_bytes = cf.read()
                    config_digest = f"sha256:{hashlib.sha256(cfg_bytes).hexdigest()}"
                    cfg_json = json.loads(cfg_bytes.decode("utf-8"))
                    arch = cfg_json.get("architecture")
                    os_name = cfg_json.get("os")
        except Exception as e:
            logger.warning("Could not parse config.json (%s): %s", config_filename, e)

    image_id = config_digest or manifest_digest

    meta = ContainerImageMetadata(
        format_type="docker_archive",
        image_id=image_id,
        repo_tag=repo_tag,
        manifest_digest=manifest_digest,
        config_digest=config_digest,
        architecture=arch,
        os=os_name,
        layer_count=len(layers),
        layer_entries=layers,
    )
    return meta, layers


def parse_oci_layout(
    root: Path,
) -> tuple[ContainerImageMetadata, list[str]]:
    """Parse OCI image layout directory."""
    index_file = root / "index.json"
    if not index_file.is_file():
        raise ContainerSecurityError("OCI image layout missing index.json")

    try:
        index_data = json.loads(index_file.read_text("utf-8"))
    except Exception as e:
        raise ContainerSecurityError(f"Malformed index.json in OCI layout: {e}")

    manifests = index_data.get("manifests") or []
    if not manifests:
        raise ContainerSecurityError("OCI index.json has no manifests")

    m_desc = manifests[0]
    m_digest = m_desc.get("digest", "")
    annotations = m_desc.get("annotations") or {}
    ref_name = annotations.get("org.opencontainers.image.ref.name") or "unknown:latest"

    # Locate manifest blob
    manifest_algo, manifest_hash = m_digest.split(":", 1) if ":" in m_digest else ("sha256", m_digest)
    m_blob_path = root / "blobs" / manifest_algo / manifest_hash
    if not m_blob_path.is_file():
        raise ContainerSecurityError(f"OCI manifest blob missing: {m_digest}")

    m_json = json.loads(m_blob_path.read_text("utf-8"))
    cfg_desc = m_json.get("config", {})
    cfg_digest = cfg_desc.get("digest")

    arch: str | None = None
    os_name: str | None = None
    if cfg_digest and ":" in cfg_digest:
        cfg_algo, cfg_hash = cfg_digest.split(":", 1)
        cfg_blob = root / "blobs" / cfg_algo / cfg_hash
        if cfg_blob.is_file():
            try:
                cfg_obj = json.loads(cfg_blob.read_text("utf-8"))
                arch = cfg_obj.get("architecture")
                os_name = cfg_obj.get("os")
            except Exception:
                pass

    layers = [layer.get("digest") for layer in m_json.get("layers", []) if layer.get("digest")]

    meta = ContainerImageMetadata(
        format_type="oci_layout",
        image_id=cfg_digest or m_digest,
        repo_tag=ref_name,
        manifest_digest=m_digest,
        config_digest=cfg_digest,
        architecture=arch,
        os=os_name,
        layer_count=len(layers),
        layer_entries=layers,
    )
    return meta, layers
