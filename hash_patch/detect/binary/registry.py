"""hash_patch/detect/binary/registry.py

Loads and caches binary cryptography rules (symbols, libraries, false-positive filters)
and maps observed binary evidence to canonical cryptographic assets.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from hash_patch.detect.canonical_registry import lookup_canonical_algorithm

_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "binary_crypto.yaml"

_REGISTRY_CACHE: dict[str, Any] | None = None


def load_binary_crypto_rules(path: Path | None = None) -> dict[str, Any]:
    global _REGISTRY_CACHE
    p = path or _RULES_PATH
    if not p.is_file():
        return {"libraries": [], "symbols": {}, "false_positive_patterns": []}

    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    compiled_libs = []
    for lib in data.get("libraries", []):
        lib_name = lib.get("name", "")
        regexes = [re.compile(pat, re.IGNORECASE) for pat in lib.get("patterns", [])]
        compiled_libs.append({"name": lib_name, "regexes": regexes})

    compiled_fp = [
        re.compile(pat, re.IGNORECASE) for pat in data.get("false_positive_patterns", [])
    ]

    _REGISTRY_CACHE = {
        "libraries": compiled_libs,
        "symbols": data.get("symbols", {}),
        "false_positive_patterns": compiled_fp,
    }
    return _REGISTRY_CACHE


def get_binary_crypto_rules() -> dict[str, Any]:
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is None:
        load_binary_crypto_rules()
    assert _REGISTRY_CACHE is not None
    return _REGISTRY_CACHE


def match_crypto_library(lib_string: str) -> str | None:
    """Return canonical crypto library name if lib_string matches any known crypto library pattern."""
    clean = Path(lib_string).name
    rules = get_binary_crypto_rules()
    for lib_entry in rules["libraries"]:
        for rx in lib_entry["regexes"]:
            if rx.search(clean):
                return lib_entry["name"]
    return None


def lookup_crypto_symbol(symbol_name: str) -> dict[str, Any] | None:
    """Look up a symbol in the binary crypto registry. Returns metadata dict or None."""
    rules = get_binary_crypto_rules()
    symbols = rules.get("symbols", {})

    # Exact match
    if symbol_name in symbols:
        return dict(symbols[symbol_name])

    # Try stripped underscore match (common in macOS / PE C-names)
    stripped = symbol_name.lstrip("_")
    if stripped in symbols:
        return dict(symbols[stripped])

    return None


def is_false_positive_string(candidate: str) -> bool:
    """Check if a string matches known false positive patterns (keyboard, userKey, etc.)."""
    rules = get_binary_crypto_rules()
    for rx in rules.get("false_positive_patterns", []):
        if rx.search(candidate):
            return True
    return False


def match_algorithm_string(candidate: str) -> dict[str, Any] | None:
    """Determine if a printable string represents an intentional algorithm name."""
    cleaned = candidate.strip("\"' \t\r\n")
    if len(cleaned) < 3 or len(cleaned) > 40:
        return None

    if is_false_positive_string(cleaned):
        return None

    # 1. Verify against canonical algorithm registry
    rule = lookup_canonical_algorithm(cleaned)
    if rule:
        lowered = cleaned.lower()
        if lowered in ("key", "hash", "mac", "sign", "verify", "digest"):
            return None
        res = dict(rule)
        if res.get("mode"):
            res["mode"] = res["mode"].lower()
        return res

    up = cleaned.upper()

    # 2. AES parameterized patterns (e.g. AES-256-GCM, AES-128-CBC, AES/GCM/NoPadding)
    m_aes = re.match(r"^AES-(128|192|256)-(GCM|CBC|CTR|CFB|OFB|ECB)$", up)
    if m_aes:
        return {
            "canonical": "AES",
            "primitive": "block-cipher",
            "parameter_set": m_aes.group(1),
            "mode": m_aes.group(2).lower(),
            "quantum_status": "weakened-by-grover",
            "oid": "2.16.840.1.101.3.4.1",
        }

    m_aes_slash = re.match(r"^AES/(GCM|CBC|CTR|CFB|OFB|ECB)/[A-Z0-9]+$", up)
    if m_aes_slash:
        return {
            "canonical": "AES",
            "primitive": "block-cipher",
            "parameter_set": None,
            "mode": m_aes_slash.group(1).lower(),
            "quantum_status": "weakened-by-grover",
            "oid": "2.16.840.1.101.3.4.1",
        }

    # 3. RSA parameterized patterns (e.g. RSA-2048, RSA-3072, RSA-4096)
    m_rsa = re.match(r"^RSA-(512|768|1024|1536|2048|3072|4096)$", up)
    if m_rsa:
        return {
            "canonical": "RSA",
            "primitive": "pke",
            "parameter_set": m_rsa.group(1),
            "mode": None,
            "quantum_status": "broken-by-shor",
            "oid": "1.2.840.113549.1.1.1",
        }

    # 4. Post-Quantum names (ML-KEM, Kyber, ML-DSA, Dilithium)
    if up.startswith("ML-KEM"):
        return {
            "canonical": "ML-KEM",
            "primitive": "kem",
            "parameter_set": cleaned.split("-")[-1] if "-" in cleaned else None,
            "mode": None,
            "quantum_status": "quantum-safe",
            "oid": None,
        }
    if up.startswith("KYBER"):
        return {
            "canonical": "Kyber",
            "primitive": "kem",
            "parameter_set": None,
            "mode": None,
            "quantum_status": "quantum-safe",
            "oid": None,
        }
    if up.startswith("ML-DSA"):
        return {
            "canonical": "ML-DSA",
            "primitive": "signature",
            "parameter_set": cleaned.split("-")[-1] if "-" in cleaned else None,
            "mode": None,
            "quantum_status": "quantum-safe",
            "oid": None,
        }
    if up.startswith("DILITHIUM"):
        return {
            "canonical": "Dilithium",
            "primitive": "signature",
            "parameter_set": None,
            "mode": None,
            "quantum_status": "quantum-safe",
            "oid": None,
        }

    return None
