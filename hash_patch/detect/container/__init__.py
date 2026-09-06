"""hash_patch/detect/container/

Container Image Cryptographic Artefact Scanning (Phase 3).
"""

from __future__ import annotations

from hash_patch.detect.container.formats import (
    ContainerImageMetadata,
    probe_container_target,
)
from hash_patch.detect.container.overlay import (
    DeletedFileEntry,
    EffectiveFileEntry,
    EffectiveFilesystem,
)
from hash_patch.detect.container.safety import ContainerSecurityError
from hash_patch.detect.container.scanner import (
    ContainerScanResult,
    scan_container_image,
)

__all__ = [
    "ContainerImageMetadata",
    "ContainerScanResult",
    "ContainerSecurityError",
    "DeletedFileEntry",
    "EffectiveFileEntry",
    "EffectiveFilesystem",
    "probe_container_target",
    "scan_container_image",
]
