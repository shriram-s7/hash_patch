"""hash_patch/detect/binary/__init__.py

Package initialization for binary crypto scanning.
Registers BinaryDetector into the detector registry.
"""

from __future__ import annotations

from hash_patch.detect.base import registry as detector_registry
from hash_patch.detect.binary.detector import BinaryDetector

binary_detector = BinaryDetector()
detector_registry.register(binary_detector)

__all__ = ["BinaryDetector", "binary_detector"]
