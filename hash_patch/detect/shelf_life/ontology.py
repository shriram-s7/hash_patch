"""hash_patch/detect/shelf_life/ontology.py — loads
ontology/data_sensitivity.yaml.

Shared by hash_patch/detect/shelf_life/data_context.py (identifier-to-
category name-pattern matching) and hash_patch/analyze/shelf_life.py
(shelf-life-years/statutory-basis/confidence lookup for the winning
category), so the ontology file is parsed in exactly one place — mirrors
hash_patch/detect/blast_radius/names.py's role for
rules/blast_radius_names.yaml, the analogous existing pattern this follows.

See ontology/data_sensitivity.yaml's own header for the full honesty
disclaimer: the shelf_life_years figures here are reasonable-effort
defaults, NOT verified legal citations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# layout: hash_patch/detect/shelf_life/ontology.py -> ../../../ontology/data_sensitivity.yaml
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


# Patterns at or below this length are common enough as a SUBSTRING of an
# unrelated word (e.g. "pan" embedded inside "expand", "span", "japan" —
# note "expand"/"key_expansion" is itself common CRYPTO terminology, e.g.
# HKDF-Expand, so this is not a hypothetical collision for this specific
# tool) that a raw substring match is too permissive. For a pattern this
# short, `_matches` instead requires it to appear as its own TOKEN
# (delimited by `_`/`-` or a camelCase boundary) — never embedded inside a
# longer word — rather than reintroducing fuzzy/stemmed matching generally.
# Longer/compound patterns (four characters is already the length of
# "iban"/"ifsc", both acronyms with negligible embedding risk) keep the
# original plain-substring behavior, unchanged.
_SHORT_PATTERN_MAX_LEN = 3

_CAMEL_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\b|$)|[A-Z]?[a-z0-9]+|[A-Z]+")


def _tokens(identifier: str) -> set[str]:
    """Split `identifier` into lowercase tokens on `_`/`-` and camelCase
    boundaries — "protect_pan" -> {"protect", "pan"}; "expand_key" ->
    {"expand", "key"} ("pan" is not a token of "expand_key", only a
    substring of "expand"); "panNumber" -> {"pan", "number"}.
    """
    tokens: set[str] = set()
    for part in re.split(r"[_\-]+", identifier):
        for m in _CAMEL_TOKEN_RE.finditer(part):
            if m.group(0):
                tokens.add(m.group(0).lower())
    return tokens


def _matches(pattern: str, lowered_identifier: str, identifier_tokens: set[str]) -> bool:
    if len(pattern) <= _SHORT_PATTERN_MAX_LEN:
        return pattern.lower() in identifier_tokens
    return pattern.lower() in lowered_identifier


def match_categories(
    identifier: str, categories: list[SensitivityCategory]
) -> list[tuple[SensitivityCategory, str]]:
    """Return every (category, matched_pattern) pair whose name_patterns
    contain `identifier` as a case-insensitive substring (or, for a SHORT
    pattern — see `_SHORT_PATTERN_MAX_LEN` — as its own delimited token,
    never merely embedded inside a longer word).

    ALL matching categories are returned, never just the first — per
    docs/SHELF_LIFE.md, an identifier that plausibly suggests two different
    categories (e.g. one whose name happens to contain both an aadhaar- and
    a financial-pattern substring) must not have this function silently pick
    one; that ambiguity is hash_patch/analyze/shelf_life.py's job (longest
    shelf life wins), not this function's. Within a single category, the
    LONGEST matching pattern is recorded (mirrors
    hash_patch/detect/blast_radius/names.py's longest-pattern-first rule),
    but that only affects which pattern string is reported, never whether
    the category matches at all.
    """
    lowered = identifier.lower()
    identifier_tokens = _tokens(identifier)
    out: list[tuple[SensitivityCategory, str]] = []
    for cat in categories:
        best_pattern: str | None = None
        for pattern in sorted(cat.name_patterns, key=lambda p: -len(p)):
            if _matches(pattern, lowered, identifier_tokens):
                best_pattern = pattern
                break
        if best_pattern is not None:
            out.append((cat, best_pattern))
    return out
