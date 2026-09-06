"""hash_patch/detect/container/overlay.py

Layer overlay reconstruction with standard AUFS/OverlayFS whiteout semantics:
1. Ordered layer application (base layer -> top layer)
2. Whiteout handling:
   - '.wh.<name>' hides/deletes '<name>' from lower layers.
   - '.wh..wh..opq' (opaque directory) deletes all lower layer contents in that directory.
3. Effective filesystem reconstruction:
   - Excludes deleted/hidden files from the final effective filesystem.
   - Tracks layer provenance for each effective file.
   - Tracks historically deleted files for diagnostic & Q&A inquiries.
4. Strict resource limits enforcement (total bytes, file counts, layer count).
"""

from __future__ import annotations

import io
import logging
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from hash_patch.detect.container.safety import (
    MAX_FILE_COUNT,
    MAX_LAYER_COUNT,
    MAX_TOTAL_EXTRACTED_BYTES,
    ContainerSecurityError,
    is_safe_tar_member,
    safe_resolve_target,
    sanitize_member_name,
)

logger = logging.getLogger(__name__)

WHITEOUT_PREFIX = ".wh."
OPAQUE_WHITEOUT = ".wh..wh..opq"


@dataclass
class EffectiveFileEntry:
    container_path: str       # Normalized path inside container, e.g. "/usr/bin/server"
    layer_digest: str         # Digest of layer that provided the effective file
    local_path: Path          # Path on disk inside the controlled temporary workspace
    size_bytes: int


@dataclass
class DeletedFileEntry:
    container_path: str       # e.g. "/usr/bin/crypto_server"
    created_in_layer: str     # Digest of layer where it was introduced
    deleted_in_layer: str     # Digest of layer that deleted it


@dataclass
class EffectiveFilesystem:
    effective_files: dict[str, EffectiveFileEntry] = field(default_factory=dict)
    deleted_files: dict[str, DeletedFileEntry] = field(default_factory=dict)
    total_extracted_bytes: int = 0
    total_files_extracted: int = 0


class OverlayBuilder:
    """Constructs the effective container filesystem by replaying layers with whiteout semantics."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.effective_files: dict[str, EffectiveFileEntry] = {}
        self.deleted_files: dict[str, DeletedFileEntry] = {}
        self.total_extracted_bytes: int = 0
        self.total_files_extracted: int = 0
        self.layer_count: int = 0

    def apply_layer_tar(self, layer_digest: str, layer_tar_bytes: bytes) -> None:
        """Apply a single layer tarball onto the overlay filesystem."""
        self.layer_count += 1
        if self.layer_count > MAX_LAYER_COUNT:
            raise ContainerSecurityError(
                f"Container image exceeds maximum layer count ({self.layer_count} > {MAX_LAYER_COUNT})"
            )

        layer_dir = self.workspace_root / f"layer_{self.layer_count:02d}"
        layer_dir.mkdir(parents=True, exist_ok=True)

        try:
            with tarfile.open(fileobj=io.BytesIO(layer_tar_bytes), mode="r:*") as tar:
                members = tar.getmembers()
                # Process members in order
                for member in members:
                    if not is_safe_tar_member(member, layer_dir):
                        continue

                    raw_name = sanitize_member_name(member.name)
                    posix_path = PurePosixPath(raw_name)
                    filename = posix_path.name
                    parent_dir = str(posix_path.parent) if str(posix_path.parent) != "." else ""

                    # 1. Check for Opaque Whiteout (.wh..wh..opq)
                    if filename == OPAQUE_WHITEOUT:
                        self._apply_opaque_whiteout(parent_dir, layer_digest)
                        continue

                    # 2. Check for Standard Whiteout (.wh.<name>)
                    if filename.startswith(WHITEOUT_PREFIX):
                        deleted_target = filename[len(WHITEOUT_PREFIX):]
                        target_container_path = (
                            f"/{parent_dir}/{deleted_target}" if parent_dir else f"/{deleted_target}"
                        )
                        self._apply_file_whiteout(target_container_path, layer_digest)
                        continue

                    # 3. Regular file or directory extraction
                    if member.isdir():
                        target_disk = safe_resolve_target(raw_name, layer_dir)
                        target_disk.mkdir(parents=True, exist_ok=True)
                        continue

                    if member.isfile():
                        self.total_files_extracted += 1
                        if self.total_files_extracted > MAX_FILE_COUNT:
                            raise ContainerSecurityError(
                                f"Total extracted files exceeded limit ({self.total_files_extracted} > {MAX_FILE_COUNT})"
                            )

                        self.total_extracted_bytes += member.size
                        if self.total_extracted_bytes > MAX_TOTAL_EXTRACTED_BYTES:
                            raise ContainerSecurityError(
                                f"Total extracted size exceeded limit ({self.total_extracted_bytes} > {MAX_TOTAL_EXTRACTED_BYTES} bytes)"
                            )

                        target_disk = safe_resolve_target(raw_name, layer_dir)
                        target_disk.parent.mkdir(parents=True, exist_ok=True)

                        # Extract content
                        f_in = tar.extractfile(member)
                        if f_in:
                            content = f_in.read()
                            target_disk.write_bytes(content)

                        container_path = f"/{raw_name}"
                        # If replacing an existing file from a lower layer, record replacement
                        self.effective_files[container_path] = EffectiveFileEntry(
                            container_path=container_path,
                            layer_digest=layer_digest,
                            local_path=target_disk,
                            size_bytes=member.size,
                        )

        except ContainerSecurityError:
            raise
        except Exception as e:
            logger.warning("Error processing layer %s: %s", layer_digest, e)
            raise ContainerSecurityError(f"Malformed layer archive ({layer_digest}): {e}")

    def _apply_file_whiteout(self, target_container_path: str, deleting_layer: str) -> None:
        """Process standard .wh.<target> whiteout."""
        # Check if file exists in current effective filesystem
        if target_container_path in self.effective_files:
            orig = self.effective_files.pop(target_container_path)
            self.deleted_files[target_container_path] = DeletedFileEntry(
                container_path=target_container_path,
                created_in_layer=orig.layer_digest,
                deleted_in_layer=deleting_layer,
            )
            logger.debug(
                "Whiteout applied: %s (from %s) deleted by %s",
                target_container_path,
                orig.layer_digest,
                deleting_layer,
            )
        else:
            # Also check if target_container_path represents a whole directory tree
            prefix = target_container_path.rstrip("/") + "/"
            matched_keys = [k for k in self.effective_files if k.startswith(prefix)]
            for k in matched_keys:
                orig = self.effective_files.pop(k)
                self.deleted_files[k] = DeletedFileEntry(
                    container_path=k,
                    created_in_layer=orig.layer_digest,
                    deleted_in_layer=deleting_layer,
                )

    def _apply_opaque_whiteout(self, directory_posix: str, deleting_layer: str) -> None:
        """Process .wh..wh..opq whiteout in directory."""
        dir_prefix = f"/{directory_posix}/" if directory_posix else "/"
        matched_keys = [k for k in self.effective_files if k.startswith(dir_prefix)]
        for k in matched_keys:
            orig = self.effective_files.pop(k)
            self.deleted_files[k] = DeletedFileEntry(
                container_path=k,
                created_in_layer=orig.layer_digest,
                deleted_in_layer=deleting_layer,
            )
            logger.debug("Opaque whiteout deleted: %s by %s", k, deleting_layer)

    def build(self) -> EffectiveFilesystem:
        return EffectiveFilesystem(
            effective_files=dict(self.effective_files),
            deleted_files=dict(self.deleted_files),
            total_extracted_bytes=self.total_extracted_bytes,
            total_files_extracted=self.total_files_extracted,
        )
