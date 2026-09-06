"""hash_patch/detect/cloud_kms/_rules.py — shared rules/cloud_kms.yaml
loader for all three language detectors in this package. Loaded once,
never duplicated per language, mirroring
hash_patch.detect.blast_radius.names.load_name_patterns's role for
rules/blast_radius_names.yaml.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "cloud_kms.yaml"

_CACHE: dict[str, Any] | None = None


def load_cloud_kms_rules(path: Path = _RULES_PATH) -> dict[str, Any]:
    global _CACHE
    if _CACHE is None:
        with path.open("r", encoding="utf-8") as fh:
            _CACHE = yaml.safe_load(fh) or {}
    return _CACHE
