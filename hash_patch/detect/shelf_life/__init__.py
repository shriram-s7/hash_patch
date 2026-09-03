"""hash_patch/detect/shelf_life/ — Pillar 2 (Shelf-Life Inference) detection.

Like hash_patch/detect/blast_radius/, this package does NOT emit CryptoAsset
objects and is NOT registered into hash_patch.detect.registry (that registry
is typed around CryptoAsset — see hash_patch/detect/base.py). Instead
data_context.py emits DataContextMatch objects
(hash_patch/model/shelf_life.py), which hash_patch/analyze/shelf_life.py
correlates against the already-detected CryptoAsset findings. Invoked
directly from hash_patch/cli.py::run_scan (via
hash_patch.analyze.shelf_life.run_shelf_life), not through the shared
registry.

Scope (see docs/SHELF_LIFE.md): Python and Java only, source-code
name-pattern matching against ontology/data_sensitivity.yaml only — no live
database introspection, no real dataflow tracing across function
boundaries. That is future work.
"""

from __future__ import annotations
