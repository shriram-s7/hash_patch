"""hash_patch/analyze/cbom_reader.py — reads an already-emitted CBOM JSON
document back into OptimizerCandidate objects for Pillar 5 (Migration
Optimiser).

This is the inverse of hash_patch/emit/cyclonedx.py: rather than building a
CBOM from a fresh ScanResult, `pratyaksha optimize` (hash_patch/cli.py)
reads an EXISTING CBOM file (produced by a prior `pratyaksha scan`, possibly
run separately, possibly across multiple targets merged by hand) and pulls
out exactly the `pratyaksha:` properties P1/P2/P3 already attached —
`pratyaksha:quantumStatus`, `pratyaksha:reachability`, the
`pratyaksha:property.shelfLife.<category>` and
`pratyaksha:property.blastRadius.<kind>.<name>.<line>` free-form properties
— never re-deriving or inventing any of them. See CLAUDE.md's "Output
format" -> "Field mapping" for the exact property shapes this reads back.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from hash_patch.analyze.risk_score import (
    compute_risk_score,
    estimate_cost_days,
    estimate_shelf_life_magnitude,
    is_migration_candidate,
)
from hash_patch.model.assets import QuantumStatus, Reachability
from hash_patch.model.optimizer import OptimizerCandidate

_SHELF_LIFE_PREFIXES = (
    "hash_patch:property.shelfLife.",
    "hash-patch:property.shelfLife.",
    "pratyaksha:property.shelfLife.",
)
_BLAST_RADIUS_PREFIXES = (
    "hash_patch:property.blastRadius.",
    "hash-patch:property.blastRadius.",
    "pratyaksha:property.blastRadius.",
)


def _property_map(component: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def _get_prop(props: dict[str, str], suffix: str) -> str | None:
    return (
        props.get(f"hash_patch:{suffix}")
        or props.get(f"hash-patch:{suffix}")
        or props.get(f"pratyaksha:{suffix}")
    )


def _parse_quantum_status(value: str | None) -> QuantumStatus:
    if value is None:
        return QuantumStatus.UNKNOWN
    try:
        return QuantumStatus(value)
    except ValueError:
        return QuantumStatus.UNKNOWN


def _parse_reachability(value: str | None) -> Reachability:
    if value is None:
        return Reachability.UNKNOWN
    try:
        return Reachability(value)
    except ValueError:
        return Reachability.UNKNOWN


def _shelf_life_from_properties(props: dict[str, str]) -> tuple[int | None, str | None]:
    """Returns (shelf_life_years, category) from this component's own
    `hash_patch:property.shelfLife.<category>` properties, or (None, None)
    if it has none. `hash_patch/analyze/shelf_life.py` emits at most one
    ShelfLifeFinding per asset, but this reader does not assume that
    invariant holds forever — if more than one is present, the one with
    the LONGEST `shelfLifeYears` wins, mirroring
    `hash_patch/analyze/shelf_life.py`'s own longest-shelf-life-wins
    fail-safe rule rather than picking arbitrarily (e.g. by property name
    order).
    """
    best: tuple[int, str] | None = None
    for name, value in props.items():
        matched_prefix: str | None = None
        for prefix in _SHELF_LIFE_PREFIXES:
            if name.startswith(prefix):
                matched_prefix = prefix
                break
        if matched_prefix is None:
            continue
        category = name[len(matched_prefix) :]
        try:
            parsed = json.loads(value)
            years = int(parsed["shelfLifeYears"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        if best is None or years > best[0]:
            best = (years, category)
    if best is None:
        return None, None
    return best


def _blast_radius_effort_days(props: dict[str, str]) -> float | None:
    """Sum of `estimatedEffortDays` across every blast-radius finding
    correlated to this asset — an asset can have more than one
    size-constraint overflow to fix (e.g. two different buffers protecting
    the same algorithm). Returns None if this asset has no blast-radius
    properties at all, so the caller can fall back to the documented
    default rather than treating "no data" as "zero cost".
    """
    total = 0.0
    found = False
    for name, value in props.items():
        matched_prefix: str | None = None
        for prefix in _BLAST_RADIUS_PREFIXES:
            if name.startswith(prefix):
                matched_prefix = prefix
                break
        if matched_prefix is None:
            continue
        try:
            parsed = json.loads(value)
            total += float(parsed["estimatedEffortDays"])
            found = True
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
    return total if found else None


def read_reference_year(doc: dict[str, Any]) -> int:
    """The scan date embedded in the CBOM's own `metadata.timestamp` — the
    one place this pillar reads a "current date" from. It never reads the
    system clock itself; see CLAUDE.md hard constraint #2 and
    docs/OPTIMISER.md.
    """
    timestamp = doc.get("metadata", {}).get("timestamp")
    if not timestamp:
        raise ValueError("input CBOM has no metadata.timestamp; cannot determine a reference year")
    return datetime.fromisoformat(timestamp).year


def read_candidates(doc: dict[str, Any]) -> tuple[list[OptimizerCandidate], int]:
    """Parse every `cryptographic-asset` component in `doc` into an
    OptimizerCandidate, filtering to BROKEN_BY_SHOR only (see
    hash_patch.analyze.risk_score.is_migration_candidate).

    Returns (candidates, excluded_count): excluded_count is how many
    cryptographic-asset components were present but filtered out (not a
    migration candidate for this pillar), so callers can report it for
    transparency rather than silently shrinking the input.
    """
    candidates: list[OptimizerCandidate] = []
    excluded = 0

    for component in doc.get("components", []):
        if component.get("type") != "cryptographic-asset":
            continue
        props = _property_map(component)
        quantum_status = _parse_quantum_status(_get_prop(props, "quantumStatus"))
        if not is_migration_candidate(quantum_status):
            excluded += 1
            continue

        reachability = _parse_reachability(_get_prop(props, "reachability"))
        shelf_life_years, shelf_life_category = _shelf_life_from_properties(props)
        magnitude, is_default = estimate_shelf_life_magnitude(shelf_life_years)
        blast_radius_days = _blast_radius_effort_days(props)
        cost_days, cost_source = estimate_cost_days(blast_radius_days)
        risk = compute_risk_score(reachability, shelf_life_years)

        candidates.append(
            OptimizerCandidate(
                finding_id=component["bom-ref"],
                name=component.get("name", component["bom-ref"]),
                reachability=reachability.value,
                shelf_life_years=magnitude,
                shelf_life_category=shelf_life_category,
                shelf_life_is_default=is_default,
                cost_days=cost_days,
                cost_source=cost_source,  # type: ignore[arg-type]
                risk_score=risk,
            )
        )

    candidates.sort(key=lambda c: c.finding_id)  # deterministic regardless of CBOM component order
    return candidates, excluded
