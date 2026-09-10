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


_KNOWN_CRYPTO_MODES = frozenset({
    "CBC", "CFB", "CTR", "CTS", "ECB", "GCM", "OFB", "CCM", "XTS", "OCB",
    "KW", "KWP", "WRAP", "EDE", "EDE3", "BC", "PCBC",
})

_KNOWN_CRYPTO_QUALIFIERS = frozenset({
    "OAEP", "PSS", "PKCS1", "PKCS1V15", "NOPADDING", "RAW", "POLY1305",
    "HMAC", "CMAC", "GMAC", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
    "MD5", "RIPEMD160", "P256", "P384", "P521", "SECP256R1", "SECP256K1",
    "BRAINPOOL", "CURVE25519", "ED25519",
})

_CRYPTO_PARAM_PATTERN = re.compile(r"^\d+(?:BIT|BITS|K|B)?$", re.IGNORECASE)


def _is_crypto_param(token: str) -> bool:
    return bool(_CRYPTO_PARAM_PATTERN.match(token))


def _is_valid_suffix_token(tok: str, upper_registry: dict[str, Any]) -> bool:
    return (
        _is_crypto_param(tok)
        or tok in _KNOWN_CRYPTO_MODES
        or tok in _KNOWN_CRYPTO_QUALIFIERS
        or tok in upper_registry
    )


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

    # 4. Compound-form tokenization fallback (e.g. "AES-256-GCM", "RSA-2048", "RSA-4096")
    if "-" in up or "_" in up:
        parts = [p for p in re.split(r"[-_]", up) if p]
        if len(parts) >= 2:
            prefix_key: str | None = None
            suffix_parts: list[str] = []

            # Check if first token matches a canonical base algorithm
            if parts[0] in _UPPER_REGISTRY:
                prefix_key = parts[0]
                suffix_parts = parts[1:]
            else:
                # Check multi-token prefix (e.g. "SHA-256" in "SHA-256-RAW")
                for k in range(2, len(parts)):
                    c_prefix = "-".join(parts[:k])
                    if c_prefix in _UPPER_REGISTRY:
                        prefix_key = c_prefix
                        suffix_parts = parts[k:]
                        break
                    c_prefix_u = "_".join(parts[:k])
                    if c_prefix_u in _UPPER_REGISTRY:
                        prefix_key = c_prefix_u
                        suffix_parts = parts[k:]
                        break

            if prefix_key is not None and all(
                _is_valid_suffix_token(tok, _UPPER_REGISTRY) for tok in suffix_parts
            ):
                base_rule = dict(_UPPER_REGISTRY[prefix_key])
                param_set = base_rule.get("parameter_set")
                mode = base_rule.get("mode")

                for tok in suffix_parts:
                    if param_set is None and re.match(r"^\d+$", tok):
                        param_set = tok
                    elif tok in _KNOWN_CRYPTO_MODES:
                        mode = tok if mode is None else f"{mode}-{tok}"

                return {
                    **base_rule,
                    "canonical": base_rule.get("canonical", prefix_key),
                    "parameter_set": param_set,
                    "mode": mode,
                    "matched_text": cleaned,
                    "matched_name": cleaned,
                }

    return None
