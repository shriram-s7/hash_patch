"""Measure container image scanning performance breakdown (Phase 3).
Measures:
- Image manifest parsing
- Layer extraction & safety checks
- Overlay & whiteout processing
- File enumeration
- Source scanning
- Binary scanning
- Deduplication & CBOM generation
- Total container scan time
"""

from __future__ import annotations

import io
from pathlib import Path
import tarfile
import time

from hash_patch.detect.container.formats import parse_docker_manifest, probe_container_target
from hash_patch.detect.container.overlay import OverlayBuilder
from hash_patch.detect.container.scanner import scan_container_image
from hash_patch.cli import run_scan
from hash_patch.emit.cyclonedx import to_cyclonedx

FIXTURES_DIR = Path(__file__).resolve().parent / "containers"

def measure_container_scan(target_path: Path) -> dict[str, float]:
    results: dict[str, float] = {}

    # 1. Total scan time
    t0 = time.perf_counter()
    scan_res = scan_container_image(target_path)
    t1 = time.perf_counter()
    results["total_container_scan_ms"] = (t1 - t0) * 1000.0

    # 2. Manifest parsing
    with tarfile.open(target_path, "r:*") as tar:
        t0 = time.perf_counter()
        meta, layers = parse_docker_manifest(tar)
        t1 = time.perf_counter()
        results["manifest_parsing_ms"] = (t1 - t0) * 1000.0

    # 3. Layer extraction & overlay processing
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        ob = OverlayBuilder(Path(td))
        with tarfile.open(target_path, "r:*") as tar:
            for l_name in layers:
                m = tar.getmember(l_name)
                f = tar.extractfile(m)
                data = f.read() if f else b""
                t0 = time.perf_counter()
                ob.apply_layer_tar(f"sha256:bench_{l_name}", data)
                t1 = time.perf_counter()
        results["overlay_whiteout_ms"] = (t1 - t0) * 1000.0

        # 4. File enumeration
        t0 = time.perf_counter()
        efs = ob.build()
        files = list(efs.effective_files.keys())
        t1 = time.perf_counter()
        results["file_enumeration_ms"] = (t1 - t0) * 1000.0

    # 5. Full run_scan + to_cyclonedx CBOM emission
    t0 = time.perf_counter()
    full_res = run_scan(target_path)
    doc = to_cyclonedx(full_res)
    t1 = time.perf_counter()
    results["full_pipeline_with_cbom_ms"] = (t1 - t0) * 1000.0

    return results

def main() -> None:
    target = FIXTURES_DIR / "mixed" / "container.tar"
    metrics = measure_container_scan(target)
    print("Performance Measurements (mixed container target):")
    for k, v in metrics.items():
        print(f"  {k}: {v:.2f} ms")

if __name__ == "__main__":
    main()
