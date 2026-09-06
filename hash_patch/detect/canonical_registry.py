"""hash_patch/detect/canonical_registry.py — Single shared canonical algorithm registry.

Used across all four language detectors (C, Go, Java, Python) for:
  1. Resolving algorithm call arguments in operation detection.
  2. Detecting standalone string literals / map values / return values (CRYPTO_REFERENCE).

All algorithm knowledge is loaded from rules/canonical_algorithms.yaml.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "canonical_algorithms.yaml"

_TLS_PATTERN = re.compile(r"^(?:TLS|SSL)_[A-Z0-9_]+$")

_REGISTRY: dict[str, dict[str, Any]] | None = None
_UPPER_REGISTRY: dict[str, dict[str, Any]] | None = None


def _load_yaml(path: Path) -> dict[str, dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return {str(k): dict(v) for k, v in raw.items() if isinstance(v, dict)}


def load_canonical_registry(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load canonical algorithm rules from YAML into global in-memory registry."""
    global _REGISTRY, _UPPER_REGISTRY
    p = path or _RULES_PATH
    data = _load_yaml(p)
    _REGISTRY = dict(data)
    _UPPER_REGISTRY = {k.upper(): v for k, v in _REGISTRY.items()}
    return _REGISTRY


def get_canonical_registry() -> dict[str, dict[str, Any]]:
    """Return the global shared canonical algorithm registry, loading it if needed."""
    global _REGISTRY
    if _REGISTRY is None:
        load_canonical_registry()
    assert _REGISTRY is not None
    return _REGISTRY


def register_canonical_algorithm(name: str, rule: dict[str, Any]) -> None:
    """Register an algorithm entry into the shared registry.

    Enables testing dynamic addition where a new algorithm becomes detectable
    across all four languages without editing language-specific rule files.
    """
    global _REGISTRY, _UPPER_REGISTRY
    if _REGISTRY is None:
        load_canonical_registry()
    assert _REGISTRY is not None
    assert _UPPER_REGISTRY is not None
    _REGISTRY[name] = rule
    _UPPER_REGISTRY[name.upper()] = rule


def reset_canonical_registry() -> None:
    """Reset registry to default state reloaded from rules/canonical_algorithms.yaml."""
    global _REGISTRY, _UPPER_REGISTRY
    _REGISTRY = None
    _UPPER_REGISTRY = None
    load_canonical_registry()


def _infer_tls_quantum_status(suite_name: str) -> str:
    up = suite_name.upper()
    if any(k in up for k in ("RSA", "ECDSA", "ECDHE", "DHE", "DH")):
        return "broken-by-shor"
    if any(k in up for k in ("RC4", "3DES", "DES", "MD5")):
        return "broken-classically"
    return "weakened-by-grover"


def lookup_canonical_algorithm(name: str | None) -> dict[str, Any] | None:
    """Look up an algorithm by exact name, normalized uppercase name, or TLS pattern.

    Returns the rule dict with keys:
      canonical, primitive, parameter_set, mode, quantum_status, oid
    or None if the string does not represent a recognized algorithm.
    """
    if not name:
        return None
    cleaned = name.strip("\"' \t\r\n")
    if not cleaned:
        return None

    if _REGISTRY is None or _UPPER_REGISTRY is None:
        load_canonical_registry()
    assert _REGISTRY is not None
    assert _UPPER_REGISTRY is not None

    # 1. Exact match
    if cleaned in _REGISTRY:
        return _REGISTRY[cleaned]

    # 2. Case-insensitive / uppercase match
    up = cleaned.upper()
    if up in _UPPER_REGISTRY:
        return _UPPER_REGISTRY[up]

    # 3. Dynamic TLS / SSL cipher suite pattern
    if _TLS_PATTERN.match(up):
        return {
            "canonical": cleaned,
            "primitive": "protocol",
            "parameter_set": None,
            "mode": None,
            "quantum_status": _infer_tls_quantum_status(up),
            "oid": None,
        }

    return None
