"""Pillar 6: ML-DSA-65 post-quantum signing, verification, and tamper detection."""

from hash_patch.sign.keys import (
    ALGORITHM_NAME,
    STANDARD_NAME,
    compute_public_key_fingerprint,
    generate_keypair,
    load_private_key,
    load_public_key,
)
from hash_patch.sign.sign_cbom import create_detached_signature_data, sign_cbom_file
from hash_patch.sign.verify_cbom import (
    VerificationResult,
    VerificationStatus,
    verify_cbom_file,
)

__all__ = [
    "ALGORITHM_NAME",
    "STANDARD_NAME",
    "VerificationResult",
    "VerificationStatus",
    "compute_public_key_fingerprint",
    "create_detached_signature_data",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "sign_cbom_file",
    "verify_cbom_file",
]
