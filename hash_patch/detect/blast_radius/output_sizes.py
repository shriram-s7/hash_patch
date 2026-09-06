"""hash_patch/detect/blast_radius/output_sizes.py — Algorithm output & artifact size mappings.

Maps algorithm names and declared buffer sizes to PQC-relevant fields (signature, pubkey, ciphertext)
for structural and data-flow blast-radius correlation without relying solely on variable-name heuristics.
"""

from __future__ import annotations

# Sizing map: algorithm name (normalized uppercase) -> {byte_size: field}
ALGORITHM_OUTPUT_SIZES: dict[str, dict[int, str]] = {
    "ED25519": {
        64: "signature",
        32: "pubkey",
    },
    "RSA": {
        256: "signature",  # RSA-2048
        384: "signature",  # RSA-3072
        512: "signature",  # RSA-4096
        270: "pubkey",     # RSA-2048 DER approx
        398: "pubkey",     # RSA-3072 DER approx
        526: "pubkey",     # RSA-4096 DER approx
    },
    "ECDSA": {
        64: "signature",  # raw r||s for P-256
        70: "signature",  # DER min
        71: "signature",  # DER typical
        72: "signature",  # DER max
        65: "pubkey",     # SEC1 uncompressed point
        33: "pubkey",     # SEC1 compressed point
    },
    "ECDH": {
        65: "pubkey",     # SEC1 uncompressed point
        33: "pubkey",     # SEC1 compressed point
        32: "ciphertext", # shared secret / raw X
    },
}

# Standalone output sizes that strongly indicate specific material when near crypto operations
KNOWN_SIZE_FIELDS: dict[int, str] = {
    64: "signature",
    256: "signature",
    384: "signature",
    512: "signature",
    65: "pubkey",
    33: "pubkey",
}


def match_algorithm_output_size(algo_name: str, size: int) -> str | None:
    """Return 'signature', 'pubkey', or 'ciphertext' if `size` matches a known
    output/artifact size for `algo_name`.
    """
    key = algo_name.upper().replace("-", "").replace("_", "")
    for canonical_name, sizes in ALGORITHM_OUTPUT_SIZES.items():
        c_key = canonical_name.replace("-", "").replace("_", "")
        if c_key in key or key in c_key:
            if size in sizes:
                return sizes[size]
    return None


def infer_field_from_size(size: int) -> str | None:
    """Fallback: return candidate field if `size` is a distinctive cryptographic size."""
    return KNOWN_SIZE_FIELDS.get(size)
