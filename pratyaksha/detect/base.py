from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from pratyaksha.model.assets import CryptoAsset


class Detector(ABC):
    """Base class for all crypto-asset detectors.

    Detectors must not make network calls at scan time, must derive every
    CryptoAsset.id deterministically, and must attach hard Evidence to every
    asset they emit. Detection rules (algorithm signatures, patterns, OIDs)
    belong in rules/ as YAML, never hardcoded here.
    """

    detector_id: str
    detector_version: str

    @abstractmethod
    def supports(self, target: Path) -> bool:
        """Return True if this detector can process the given target."""
        raise NotImplementedError

    @abstractmethod
    def detect(self, target: Path) -> list[CryptoAsset]:
        """Scan the target and return the crypto assets found, with evidence."""
        raise NotImplementedError


class DetectorRegistry:
    """Registry that detectors register themselves into."""

    def __init__(self) -> None:
        self._detectors: list[Detector] = []

    def register(self, detector: Detector) -> None:
        self._detectors.append(detector)

    def detectors(self) -> list[Detector]:
        return list(self._detectors)


registry = DetectorRegistry()
