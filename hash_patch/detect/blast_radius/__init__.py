"""hash_patch/detect/blast_radius/ — Pillar 3 (Blast Radius) detectors.

These detectors do NOT emit CryptoAsset objects and are NOT registered into
hash_patch.detect.registry (that registry, and hash_patch.cli.run_scan's
main detection loop, are typed around CryptoAsset — see
hash_patch/detect/base.py). Instead they emit SizeConstraint objects
(hash_patch/model/blast_radius.py), which hash_patch/analyze/blast_radius.py
correlates against the already-detected CryptoAsset findings. They are
invoked directly from hash_patch/cli.py::run_scan alongside the ordinary
detector loop, not through the shared registry.

Scope for this pillar (see docs/BLAST_RADIUS.md): C, Go, Java, and Python
fixed-size buffers/heap allocations (c_buffers.py, go_buffers.py,
java_buffers.py, python_buffers.py) and SQL DDL fixed-width columns
(sql_ddl.py). Wire-format/protocol detection remains explicitly out of
scope.
"""

from __future__ import annotations
