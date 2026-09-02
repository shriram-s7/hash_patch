"""pratyaksha/detect/shelf_life/ontology.py — loads
ontology/data_sensitivity.yaml.

Shared by pratyaksha/detect/shelf_life/data_context.py (identifier-to-
category name-pattern matching) and pratyaksha/analyze/shelf_life.py
(shelf-life-years/statutory-basis/confidence lookup for the winning
category), so the ontology file is parsed in exactly one place — mirrors
pratyaksha/detect/blast_radius/names.py's role for
rules/blast_radius_names.yaml, the analogous existing pattern this follows.

See ontology/data_sensitivity.yaml's own header for the full honesty
disclaimer: the shelf_life_years figures here are reasonable-effort
defaults, NOT verified legal citations.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# layout: pratyaksha/detect/shelf_life/ontology.py -> ../../../ontology/data_sensitivity.yaml
_ONTOLOGY_PATH = Path(__file__).resolve().parents[3] / "ontology" / "data_sensitivity.yaml"


@dataclass(frozen=True)
class SensitivityCategory:
    category_name: str
    name_patterns: tuple[str, ...]
    shelf_life_years: int
    statutory_basis: str
    confidence: str  # "high" | "medium" — see ontology/data_sensitivity.yaml


def load_sensitivity_categories(path: Path = _ONTOLOGY_PATH) -> list[SensitivityCategory]:
    with path.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    raw: dict[str, Any] = data.get("categories", {})
    out: list[SensitivityCategory] = []
    for key, entry in raw.items():
        out.append(
            SensitivityCategory(
                category_name=entry.get("category_name", key),
                name_patterns=tuple(entry.get("name_patterns", [])),
                shelf_life_years=int(entry["shelf_life_years"]),
                statutory_basis=entry["statutory_basis"],
                confidence=entry["confidence"],
            )
        )
    return out


def match_categories(
    identifier: str, categories: list[SensitivityCategory]
) -> list[tuple[SensitivityCategory, str]]:
    """Return every (category, matched_pattern) pair whose name_patterns
    contain `identifier` as a case-insensitive substring.

    ALL matching categories are returned, never just the first — per
    docs/SHELF_LIFE.md, an identifier that plausibly suggests two different
    categories (e.g. one whose name happens to contain both an aadhaar- and
    a financial-pattern substring) must not have this function silently pick
    one; that ambiguity is pratyaksha/analyze/shelf_life.py's job (longest
    shelf life wins), not this function's. Within a single category, the
    LONGEST matching pattern is recorded (mirrors
    pratyaksha/detect/blast_radius/names.py's longest-pattern-first rule),
    but that only affects which pattern string is reported, never whether
    the category matches at all.
    """
    lowered = identifier.lower()
    out: list[tuple[SensitivityCategory, str]] = []
    for cat in categories:
        best_pattern: str | None = None
        for pattern in sorted(cat.name_patterns, key=lambda p: -len(p)):
            if pattern.lower() in lowered:
                best_pattern = pattern
                break
        if best_pattern is not None:
            out.append((cat, best_pattern))
    return out
