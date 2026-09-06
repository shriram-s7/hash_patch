"""Build explicit security fixtures for container scanning (path traversal, symlink escape, absolute path, bomb).
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent / "containers"

def make_security_fixtures() -> None:
    # 1. Path traversal: archive entry contains ../../evil.txt
    traversal_dir = FIXTURES_DIR / "traversal"
    traversal_dir.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # Layer 1 tar containing traversal
        layer_buf = io.BytesIO()
        with tarfile.open(fileobj=layer_buf, mode="w") as layer_tar:
            data = b"evil content"
            ti = tarfile.TarInfo(name="../../evil.txt")
            ti.size = len(data)
            layer_tar.addfile(ti, io.BytesIO(data))
        layer_data = layer_buf.getvalue()

        manifest = [{"Config": "config.json", "RepoTags": ["traversal:latest"], "Layers": ["layer.tar"]}]
        m_bytes = json.dumps(manifest).encode("utf-8")
        ti_m = tarfile.TarInfo(name="manifest.json")
        ti_m.size = len(m_bytes)
        tar.addfile(ti_m, io.BytesIO(m_bytes))

        ti_l = tarfile.TarInfo(name="layer.tar")
        ti_l.size = len(layer_data)
        tar.addfile(ti_l, io.BytesIO(layer_data))

    (traversal_dir / "container.tar").write_bytes(buf.getvalue())

    # 2. Absolute path: archive entry starts with /
    abs_dir = FIXTURES_DIR / "absolute_path"
    abs_dir.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        layer_buf = io.BytesIO()
        with tarfile.open(fileobj=layer_buf, mode="w") as layer_tar:
            data = b"evil absolute content"
            ti = tarfile.TarInfo(name="/etc/evil.txt")
            ti.size = len(data)
            layer_tar.addfile(ti, io.BytesIO(data))
        layer_data = layer_buf.getvalue()

        manifest = [{"Config": "config.json", "RepoTags": ["abs:latest"], "Layers": ["layer.tar"]}]
        m_bytes = json.dumps(manifest).encode("utf-8")
        ti_m = tarfile.TarInfo(name="manifest.json")
        ti_m.size = len(m_bytes)
        tar.addfile(ti_m, io.BytesIO(m_bytes))

        ti_l = tarfile.TarInfo(name="layer.tar")
        ti_l.size = len(layer_data)
        tar.addfile(ti_l, io.BytesIO(layer_data))

    (abs_dir / "container.tar").write_bytes(buf.getvalue())

    # 3. Symlink escape: symlink pointing outside extraction root
    symlink_dir = FIXTURES_DIR / "symlink_escape"
    symlink_dir.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        layer_buf = io.BytesIO()
        with tarfile.open(fileobj=layer_buf, mode="w") as layer_tar:
            ti = tarfile.TarInfo(name="app/evil_symlink")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "../../../outside"
            layer_tar.addfile(ti)
        layer_data = layer_buf.getvalue()

        manifest = [{"Config": "config.json", "RepoTags": ["symlink:latest"], "Layers": ["layer.tar"]}]
        m_bytes = json.dumps(manifest).encode("utf-8")
        ti_m = tarfile.TarInfo(name="manifest.json")
        ti_m.size = len(m_bytes)
        tar.addfile(ti_m, io.BytesIO(m_bytes))

        ti_l = tarfile.TarInfo(name="layer.tar")
        ti_l.size = len(layer_data)
        tar.addfile(ti_l, io.BytesIO(layer_data))

    (symlink_dir / "container.tar").write_bytes(buf.getvalue())

    print("Security fixtures successfully generated.")

if __name__ == "__main__":
    make_security_fixtures()
