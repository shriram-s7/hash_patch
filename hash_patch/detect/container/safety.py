"""hash_patch/detect/container/safety.py

Security bounds and safe extraction protections for container image scanning.
Enforces:
1. Path traversal blocking (../../outside)
2. Absolute extraction path blocking (/etc/passwd)
3. Symlink escape blocking (links resolving outside sandbox root)
4. Resource quotas (archive size, extracted size, file count, layer count, file size)
5. Non-execution guarantees (device nodes, fifos, sockets, and executables treated strictly as inert data)
"""

from __future__ import annotations

import logging
import tarfile
from pathlib import Path, PurePosixPath

logger = logging.getLogger(__name__)

# Configurable resource limits
MAX_IMAGE_ARCHIVE_BYTES = 200 * 1024 * 1024  # 200 MB
MAX_TOTAL_EXTRACTED_BYTES = 250 * 1024 * 1024  # 250 MB
MAX_LAYER_COUNT = 20
MAX_FILE_COUNT = 10_000
MAX_INDIVIDUAL_FILE_BYTES = 50 * 1024 * 1024  # 50 MB


class ContainerSecurityError(Exception):
    """Raised when a container image violates safety boundaries or limits."""


def validate_archive_size(archive_path: Path) -> None:
    """Ensure image archive file does not exceed maximum allowable size."""
    if not archive_path.is_file():
        return
    size = archive_path.stat().st_size
    if size > MAX_IMAGE_ARCHIVE_BYTES:
        raise ContainerSecurityError(
            f"Image archive {archive_path.name} exceeds maximum size limit "
            f"({size} > {MAX_IMAGE_ARCHIVE_BYTES} bytes)"
        )


def sanitize_member_name(raw_name: str) -> str:
    """Check and sanitize an archive member name.

    Rejects absolute paths and traversal components ('..').
    Returns a clean, forward-slash normalized relative path string.
    """
    clean = raw_name.replace("\\", "/").strip()
    if clean.startswith("/") or (len(clean) >= 2 and clean[1] == ":"):
        raise ContainerSecurityError(f"Absolute extraction path blocked: {raw_name!r}")

    posix = PurePosixPath(clean)
    for part in posix.parts:
        if part == "..":
            raise ContainerSecurityError(f"Path traversal component '..' blocked: {raw_name!r}")
        if part.strip() == "":
            continue

    # Return normalized relative path without leading ./
    res = str(posix)
    while res.startswith("./"):
        res = res[2:]
    return res


def safe_resolve_target(rel_path: str, extraction_root: Path) -> Path:
    """Resolve a relative path against an extraction root and verify it does not escape."""
    clean_rel = sanitize_member_name(rel_path)
    root_resolved = extraction_root.resolve()
    target = (extraction_root / clean_rel).resolve()

    try:
        target.relative_to(root_resolved)
    except ValueError:
        raise ContainerSecurityError(
            f"Extracted path escapes containment root: {rel_path!r} -> {target}"
        )
    return target


def is_safe_tar_member(member: tarfile.TarInfo, extraction_root: Path) -> bool:
    """Inspect a tar member to ensure it is safe to extract."""
    # 1. Check for special device files, FIFOs, etc.
    if member.isblk() or member.ischr() or member.isfifo() or member.isdev():
        logger.warning("Skipping special device/FIFO member in container: %s", member.name)
        return False

    # 2. Check path sanity
    try:
        sanitized = sanitize_member_name(member.name)
    except ContainerSecurityError as e:
        raise ContainerSecurityError(f"Security check failed for member {member.name!r}: {e}")

    # 3. Check individual file size limit
    if member.size > MAX_INDIVIDUAL_FILE_BYTES:
        raise ContainerSecurityError(
            f"Archive member {member.name!r} exceeds individual size limit "
            f"({member.size} > {MAX_INDIVIDUAL_FILE_BYTES} bytes)"
        )

    # 4. Check symlink target if present
    if member.issym() or member.islnk():
        link_target = member.linkname.replace("\\", "/")
        if link_target.startswith("/") or ".." in link_target:
            # Check where link target resolves
            parent_dir = (extraction_root / sanitized).parent
            resolved_link = (parent_dir / link_target).resolve()
            try:
                resolved_link.relative_to(extraction_root.resolve())
            except ValueError:
                raise ContainerSecurityError(
                    f"Symlink {member.name!r} -> {member.linkname!r} points outside extraction root"
                )

    return True
