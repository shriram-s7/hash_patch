"""pratyaksha/detect/blast_radius/names.py — shared crypto-name-pattern
matching for the blast-radius detectors.

Loads rules/blast_radius_names.yaml exactly once per call site and matches
a buffer/column identifier against it. Both c_buffers.py and sql_ddl.py
import this module rather than each loading/duplicating the pattern list,
per CLAUDE.md's "detection rules live in YAML, not Python".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# layout: pratyaksha/detect/blast_radius/names.py -> ../../../rules/blast_radius_names.yaml
_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "blast_radius_names.yaml"

NamePattern = tuple[str, "str | None"]


def load_name_patterns(path: Path = _RULES_PATH) -> list[NamePattern]:
    with path.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    raw = data.get("patterns", [])
    return [(entry["name"], entry.get("field")) for entry in raw]


def match_name_pattern(identifier: str, patterns: list[NamePattern]) -> NamePattern | None:
    """Return the (pattern_name, field) of the first matching pattern, or
    None if `identifier` doesn't plausibly name cryptographic material.

    Substring, case-insensitive. Checked longest-pattern-first so a more
    specific pattern (e.g. "private_key", field=null) wins over a shorter
    one it textually contains (e.g. "key", field="pubkey") — without this,
    iteration order could non-deterministically decide whether a private-key
    buffer gets (wrongly) compared against a public-key PQC size.
    """
    lowered = identifier.lower()
    for pattern_name, field in sorted(patterns, key=lambda p: -len(p[0])):
        if pattern_name.lower() in lowered:
            return (pattern_name, field)
    return None
