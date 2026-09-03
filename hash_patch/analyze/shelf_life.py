"""hash_patch/analyze/shelf_life.py — Pillar 2 (Shelf-Life Inference)
computation.

Correlates DataContextMatch findings
(hash_patch/detect/shelf_life/data_context.py) with CryptoAsset findings,
and assigns each correlated asset a ShelfLifeFinding — how long the data it
protects must plausibly remain confidential, per
ontology/data_sensitivity.yaml. See docs/SHELF_LIFE.md for the full method
and its honesty caveats (the ontology's shelf_life_years figures are
reasonable-effort defaults, NOT verified legal citations).

**Correlation is same-file AND same-call-site.** A DataContextMatch is only
ever correlated with a CryptoAsset when they share BOTH a locator (file
path) AND an exact evidence line — never cross-file (CLAUDE.md's same-file
correlation honesty rule, mirrored from hash_patch/analyze/blast_radius.py),
and never merely "somewhere else in the same file" either. This works
because hash_patch/detect/shelf_life/data_context.py always anchors a
DataContextMatch's own Evidence.line to the specific crypto call site it was
found near (see that module's and DataContextMatch's docstrings) — so exact
(locator, line) equality against the CryptoAsset's own evidence is both
simple AND precise, without needing blast radius's nearest-by-line distance
heuristic.

**Longest-shelf-life-wins fail-safe.** When more than one category matches
a single crypto call (Step 2's "keep ALL matches" rule), the category with
the LONGEST `shelf_life_years` is used — always assume the more sensitive/
longer-lived category on ambiguity, never the shorter one. See
`_pick_winning_match` below.

**No signal -> no finding.** An asset with zero same-file, same-call-site
DataContextMatch never gets a ShelfLifeFinding — this is NOT the same as
"assign the generic_pii default"; genuinely unmatched code produces no
opinion at all, per docs/SHELF_LIFE.md.

`mosca_note` is descriptive text only — this module does NOT implement
Mosca's full inequality (comparing X, the shelf-life computed here, against
Y + Z, migration time plus years-until-CRQC); that needs Pillar 5's Monte
Carlo work, planned separately.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import date

from hash_patch.detect.shelf_life.data_context import find_data_context_matches
from hash_patch.detect.shelf_life.ontology import SensitivityCategory, load_sensitivity_categories
from hash_patch.model.assets import CryptoAsset
from hash_patch.model.shelf_life import DataContextMatch, ShelfLifeFinding


def _normalize_locator(locator: str) -> str:
    return locator.replace("\\", "/")


def _evidence_keys(asset: CryptoAsset) -> set[tuple[str, int]]:
    keys: set[tuple[str, int]] = set()
    for ev in asset.evidence:
        if ev.source_type != "source" or ev.line is None:
            continue
        keys.add((_normalize_locator(ev.locator), ev.line))
    return keys


def _pick_winning_match(
    candidates: Sequence[DataContextMatch], cat_by_name: dict[str, SensitivityCategory]
) -> tuple[DataContextMatch, SensitivityCategory] | None:
    """Longest shelf_life_years wins, per the module docstring's fail-safe
    rule. This is deliberately order-independent: every candidate is
    compared, so the result never depends on which pattern happened to be
    matched first during detection. A deterministic tie-break (category
    name, then matched identifier) applies only when two categories share
    the exact same shelf_life_years, so the result is still reproducible.
    """
    best: tuple[DataContextMatch, SensitivityCategory] | None = None
    for match in candidates:
        cat = cat_by_name.get(match.category)
        if cat is None:
            continue
        if best is None:
            best = (match, cat)
            continue
        _, best_cat = best
        if cat.shelf_life_years > best_cat.shelf_life_years:
            best = (match, cat)
        elif cat.shelf_life_years == best_cat.shelf_life_years:
            key = (cat.category_name, match.matched_identifier)
            best_key = (best_cat.category_name, best[0].matched_identifier)
            if key < best_key:
                best = (match, cat)
    return best


def _mosca_note(category: SensitivityCategory, scan_date: date) -> str:
    target_year = scan_date.year + category.shelf_life_years
    return (
        f"Data must remain secret until ~{target_year} based on {category.category_name} "
        f"category ({category.shelf_life_years}yr shelf-life from scan date)."
    )


def compute_shelf_life(
    crypto_assets: Sequence[CryptoAsset],
    data_context_matches: Sequence[DataContextMatch],
    scan_date: date,
    categories: Sequence[SensitivityCategory] | None = None,
) -> list[ShelfLifeFinding]:
    """Correlate `data_context_matches` against `crypto_assets` (same file,
    same call-site line only) and emit a ShelfLifeFinding for every asset
    with at least one match.

    `scan_date` must come from the caller (hash_patch/cli.py::run_scan uses
    `ScanResult.scan_started_at.date()` — the one wall-clock read CLAUDE.md
    already permits, and only there). This function itself never reads the
    system clock: two calls with the same `scan_date` and inputs always
    produce byte-identical `mosca_note` text, preserving CLAUDE.md's
    determinism hard constraint.
    """
    if not data_context_matches:
        return []

    cats = list(categories) if categories is not None else load_sensitivity_categories()
    cat_by_name = {c.category_name: c for c in cats}

    matches_by_key: dict[tuple[str, int], list[DataContextMatch]] = defaultdict(list)
    for match in data_context_matches:
        for ev in match.evidence:
            if ev.source_type != "source" or ev.line is None:
                continue
            matches_by_key[(_normalize_locator(ev.locator), ev.line)].append(match)

    findings: list[ShelfLifeFinding] = []
    for asset in crypto_assets:
        candidates: list[DataContextMatch] = []
        for key in _evidence_keys(asset):
            candidates.extend(matches_by_key.get(key, ()))
        if not candidates:
            continue  # no signal found -- never guess, never default to generic_pii

        winner = _pick_winning_match(candidates, cat_by_name)
        if winner is None:
            continue
        match, category = winner

        findings.append(
            ShelfLifeFinding(
                asset_id=asset.id,
                asset_name=asset.name,
                category=category.category_name,
                shelf_life_years=category.shelf_life_years,
                statutory_basis=category.statutory_basis,
                confidence=category.confidence,  # type: ignore[arg-type]
                evidence=list(match.evidence),
                mosca_note=_mosca_note(category, scan_date),
            )
        )

    return sorted(findings, key=lambda f: (f.asset_id, f.category))


def run_shelf_life(
    crypto_assets: Sequence[CryptoAsset],
    scan_date: date,
    categories: Sequence[SensitivityCategory] | None = None,
) -> list[ShelfLifeFinding]:
    """End-to-end entry point used by hash_patch/cli.py::run_scan: detect
    DataContextMatches in the already-detected CryptoAsset findings, then
    correlate.
    """
    matches = find_data_context_matches(crypto_assets, categories=categories)
    if not matches:
        return []
    return compute_shelf_life(crypto_assets, matches, scan_date, categories=categories)
