"""tests/golden/test_adversarial_corpus_golden.py

Golden regression test for the multi-language adversarial corpus.

Verifies that scanning the adversarial corpus at D:\\cbom_adversarial_corpus
(or CBOM_ADVERSARIAL_CORPUS env var) produces the expected 18 assets across
C, Java, Python, and Go, covering all data-flow and reference indirections:
- Static final field resolution
- Map lookup patterns
- Parameter passthrough
- Ternary and conditional branching
- Attribute assignment indirection
- Named const blocks
- C crypto reference strings (excluding comments)
- Unreachable/dead code preservation
- Test fixture exclusion

To regenerate:
    HASH_PATCH_REGEN_GOLDEN=1 pytest tests/golden/test_adversarial_corpus_golden.py
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hash_patch.cli import run_scan
from hash_patch.emit import render_cbom_json, to_cyclonedx, validate_cbom

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_FILE = REPO_ROOT / "tests" / "golden" / "adversarial_corpus_expected.json"

CORPUS_PATH = Path(os.environ.get("CBOM_ADVERSARIAL_CORPUS", r"D:\cbom_adversarial_corpus"))

FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC)
FIXED_TIMESTAMP_STR = "2026-01-01T00:00:00+00:00"

REGEN = os.environ.get("HASH_PATCH_REGEN_GOLDEN", "").strip().lower() in ("1", "true", "yes")


def _build_doc(corpus_root: Path) -> dict:  # type: ignore[type-arg]
    result = run_scan(corpus_root)
    doc = to_cyclonedx(result)
    doc["metadata"]["timestamp"] = FIXED_TIMESTAMP_STR
    return doc


def _normalize_doc(doc: dict, corpus_root: Path) -> dict:  # type: ignore[type-arg]
    d = json.loads(json.dumps(doc))
    d.pop("serialNumber", None)
    c_root = corpus_root.resolve()
    for c in d.get("components", []):
        for occ in c.get("evidence", {}).get("occurrences", []):
            if "location" in occ:
                raw_loc = occ["location"].replace("\\", "/")
                try:
                    loc = Path(occ["location"]).resolve()
                    if c_root in loc.parents or loc == c_root:
                        occ["location"] = loc.relative_to(c_root).as_posix()
                    else:
                        occ["location"] = raw_loc
                except Exception:
                    occ["location"] = raw_loc
        if "evidence" in c and "occurrences" in c["evidence"]:
            c["evidence"]["occurrences"].sort(
                key=lambda o: (o.get("location", ""), o.get("line", 0), o.get("offset", 0))
            )
    # Sort components by bom-ref for deterministic comparison
    if "components" in d:
        d["components"].sort(key=lambda c: c.get("bom-ref", ""))
    return d



def test_golden_file_exists() -> None:
    if REGEN:
        pytest.skip("Regen mode — golden file may be overwritten by test")
    assert GOLDEN_FILE.is_file(), f"Missing golden file: {GOLDEN_FILE}"


def test_adversarial_corpus_golden() -> None:
    if not CORPUS_PATH.is_dir():
        pytest.skip(f"Adversarial corpus directory not found at {CORPUS_PATH}")

    doc = _build_doc(CORPUS_PATH)

    if REGEN:
        normalized = _normalize_doc(doc, CORPUS_PATH)
        GOLDEN_FILE.write_text(render_cbom_json(normalized), encoding="utf-8")
        pytest.skip("Golden file regenerated; re-run without HASH_PATCH_REGEN_GOLDEN to verify.")

    assert GOLDEN_FILE.is_file(), f"Missing golden file: {GOLDEN_FILE}"

    live_norm = _normalize_doc(doc, CORPUS_PATH)
    golden_parsed = json.loads(GOLDEN_FILE.read_text(encoding="utf-8"))
    golden_norm = _normalize_doc(golden_parsed, CORPUS_PATH)

    assert live_norm == golden_norm, (
        "Live adversarial corpus scan does not match golden file.\n"
        f"Live asset count: {len(live_norm.get('components', []))}\n"
        f"Golden asset count: {len(golden_norm.get('components', []))}"
    )


def test_adversarial_corpus_cyclonedx_schema() -> None:
    if not CORPUS_PATH.is_dir():
        pytest.skip(f"Adversarial corpus directory not found at {CORPUS_PATH}")

    doc = _build_doc(CORPUS_PATH)
    errors = validate_cbom(doc)
    assert errors == [], f"Schema validation errors: {errors}"
