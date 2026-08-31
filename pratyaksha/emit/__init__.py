from __future__ import annotations

from pathlib import Path
from typing import Any

from pratyaksha.emit.cyclonedx import render_cbom_json, to_cyclonedx
from pratyaksha.emit.validate import validate_cbom
from pratyaksha.model.findings import ScanResult

__all__ = ["render_cbom_json", "to_cyclonedx", "validate_cbom", "write_cbom"]


def write_cbom(result: ScanResult, path: Path) -> None:
    """Emit result as a CycloneDX 1.6 CBOM JSON document at path."""
    doc: dict[str, Any] = to_cyclonedx(result)
    path.write_text(render_cbom_json(doc), encoding="utf-8")
