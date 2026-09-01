"""pratyaksha/detect/blast_radius/ — Pillar 3 (Blast Radius) detectors.

These detectors do NOT emit CryptoAsset objects and are NOT registered into
pratyaksha.detect.registry (that registry, and pratyaksha.cli.run_scan's
main detection loop, are typed around CryptoAsset — see
pratyaksha/detect/base.py). Instead they emit SizeConstraint objects
(pratyaksha/model/blast_radius.py), which pratyaksha/analyze/blast_radius.py
correlates against the already-detected CryptoAsset findings. They are
invoked directly from pratyaksha/cli.py::run_scan alongside the ordinary
detector loop, not through the shared registry.

Scope for this pillar (see docs/BLAST_RADIUS.md): C fixed-size
buffers/heap allocations (c_buffers.py) and SQL DDL fixed-width columns
(sql_ddl.py) only. Java/Go/Python buffer detection and wire-format/protocol
detection are explicitly out of scope.
"""

from __future__ import annotations
