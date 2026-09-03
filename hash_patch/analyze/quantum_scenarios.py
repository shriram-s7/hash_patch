"""hash_patch/analyze/quantum_scenarios.py — loads
ontology/quantum_arrival.yaml.

See that file's own header for the full honesty disclaimer: these are 3
illustrative named scenarios for demonstrating timeline sensitivity, NOT a
verified statistical model of quantum-computing arrival.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# layout: hash_patch/analyze/quantum_scenarios.py -> ../../ontology/quantum_arrival.yaml
_SCENARIOS_PATH = Path(__file__).resolve().parents[2] / "ontology" / "quantum_arrival.yaml"


@dataclass(frozen=True)
class QuantumArrivalScenario:
    scenario_name: str
    estimated_year: int
    probability_weight: float
    description: str


def load_quantum_arrival_scenarios(path: Path = _SCENARIOS_PATH) -> list[QuantumArrivalScenario]:
    """Returns all scenarios, sorted by estimated_year ascending (soonest
    first) for a stable, deterministic order regardless of YAML key order.
    """
    with path.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    raw: dict[str, Any] = data.get("scenarios", {})
    out = [
        QuantumArrivalScenario(
            scenario_name=entry.get("scenario_name", key),
            estimated_year=int(entry["estimated_year"]),
            probability_weight=float(entry["probability_weight"]),
            description=entry.get("description", ""),
        )
        for key, entry in raw.items()
    ]
    return sorted(out, key=lambda s: s.estimated_year)
