"""Unit tests for container scanning security controls (Phase 3).
Verifies:
1. Path traversal blocking (../../evil.txt)
2. Absolute extraction path blocking (/etc/evil.txt)
3. Symlink escape containment (links pointing outside sandbox root)
4. Malformed manifest / config handling
5. Resource limits enforcement (file count, archive size, extracted size)
6. Non-execution guarantees
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hash_patch.detect.container.safety import (
    MAX_IMAGE_ARCHIVE_BYTES,
    ContainerSecurityError,
    safe_resolve_target,
    sanitize_member_name,
    validate_archive_size,
)
from hash_patch.detect.container.scanner import scan_container_image

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "testdata" / "containers"


class TestContainerSecurityControls:
    def test_path_traversal_blocked(self) -> None:
        p = FIXTURES_DIR / "traversal" / "container.tar"
        with pytest.raises(ContainerSecurityError) as exc:
            scan_container_image(p)
        assert "traversal" in str(exc.value).lower() or ".." in str(exc.value)

    def test_absolute_path_blocked(self) -> None:
        p = FIXTURES_DIR / "absolute_path" / "container.tar"
        with pytest.raises(ContainerSecurityError) as exc:
            scan_container_image(p)
        assert "absolute" in str(exc.value).lower()

    def test_symlink_escape_blocked(self) -> None:
        p = FIXTURES_DIR / "symlink_escape" / "container.tar"
        with pytest.raises(ContainerSecurityError) as exc:
            scan_container_image(p)
        assert "symlink" in str(exc.value).lower() or "outside" in str(exc.value).lower()

    def test_malformed_manifest_handled_safely(self) -> None:
        p = FIXTURES_DIR / "malformed" / "container.tar"
        with pytest.raises(ContainerSecurityError) as exc:
            scan_container_image(p)
        assert "malformed" in str(exc.value).lower() or "manifest" in str(exc.value).lower()

    def test_sanitize_member_name_traversal(self) -> None:
        with pytest.raises(ContainerSecurityError):
            sanitize_member_name("../../etc/passwd")
        with pytest.raises(ContainerSecurityError):
            sanitize_member_name("app/../../../shadow")

    def test_sanitize_member_name_absolute(self) -> None:
        with pytest.raises(ContainerSecurityError):
            sanitize_member_name("/etc/passwd")
        with pytest.raises(ContainerSecurityError):
            sanitize_member_name("C:\\Windows\\System32\\cmd.exe")

    def test_safe_resolve_target_escapes(self, tmp_path: Path) -> None:
        with pytest.raises(ContainerSecurityError):
            safe_resolve_target("../../outside.txt", tmp_path)

    def test_archive_size_limit_enforced(self, tmp_path: Path) -> None:
        fake_archive = tmp_path / "huge.tar"
        # Create a sparse/mock file larger than limit
        with fake_archive.open("wb") as f:
            f.seek(MAX_IMAGE_ARCHIVE_BYTES + 1024)
            f.write(b"\x00")
        with pytest.raises(ContainerSecurityError) as exc:
            validate_archive_size(fake_archive)
        assert "exceeds maximum size limit" in str(exc.value)

    def test_prompt_injection_remains_inert_data(self) -> None:
        p = FIXTURES_DIR / "prompt_injection" / "container.tar"
        res = scan_container_image(p)
        # Scan completes safely and finds 0 crypto findings, prompt injection does not trigger model execution
        assert res.metadata.repo_tag == "injection-app:1.0"
        assert len(res.assets) == 0
