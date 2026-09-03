"""Verify an ML-DSA-65 detached signature over a CBOM file.

Distinguishes among:
- VALID: Signature is cryptographically valid and file is untampered.
- INVALID: Document was tampered with, or signature does not match the public key.
- ERROR: File missing, malformed signature JSON, or invalid key format.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from hash_patch.sign.keys import (
    ALGORITHM_NAME,
    compute_public_key_fingerprint,
    load_public_key,
)


class VerificationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    ERROR = "ERROR"


@dataclass
class VerificationResult:
    status: VerificationStatus
    message: str
    algorithm: str | None = None
    file_sha256_match: bool | None = None
    signature_match: bool | None = None

    @property
    def is_valid(self) -> bool:
        return self.status == VerificationStatus.VALID


def verify_cbom_file(
    cbom_path: Path,
    sig_path: Path,
    public_key_path: Path,
) -> VerificationResult:
    """Verify a detached signature against a CBOM file and public key.

    Returns a structured VerificationResult with status VALID, INVALID, or ERROR.
    """
    # 1. Check existence of files (ERROR if missing)
    if not cbom_path.is_file():
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"CBOM file not found: {cbom_path}",
        )
    if not sig_path.is_file():
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"Signature file not found: {sig_path}",
        )
    if not public_key_path.is_file():
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"Public key file not found: {public_key_path}",
        )

    # 2. Parse public key (ERROR if malformed or wrong algorithm)
    try:
        pub = load_public_key(public_key_path)
    except (FileNotFoundError, ValueError, TypeError, OSError) as exc:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"Invalid public key file: {exc}",
        )

    # 3. Parse signature file (ERROR if malformed JSON or missing required fields)
    try:
        sig_raw = sig_path.read_text(encoding="utf-8")
        sig_data = json.loads(sig_raw)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"Malformed signature file (JSON parse error): {exc}",
        )

    if not isinstance(sig_data, dict):
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message="Malformed signature file: root must be a JSON object",
        )

    algorithm = sig_data.get("algorithm")
    expected_sha256 = sig_data.get("file_sha256")
    sig_b64 = sig_data.get("signature")

    if not algorithm or not expected_sha256 or not sig_b64:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message="Malformed signature file: missing required fields ('algorithm', 'file_sha256', 'signature')",
        )

    if algorithm != ALGORITHM_NAME:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"Unsupported signature algorithm: '{algorithm}' (expected '{ALGORITHM_NAME}')",
            algorithm=algorithm,
        )

    try:
        sig_bytes = base64.b64decode(sig_b64)
    except (binascii.Error, ValueError) as exc:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"Malformed signature file: invalid base64 in signature field: {exc}",
            algorithm=algorithm,
        )

    # 4. Check document integrity (INVALID if SHA-256 differs -- DOCUMENT tampered with)
    try:
        cbom_bytes = cbom_path.read_bytes()
    except OSError as exc:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"Cannot read CBOM file {cbom_path}: {exc}",
            algorithm=algorithm,
        )

    actual_sha256 = hashlib.sha256(cbom_bytes).hexdigest()

    if actual_sha256.lower() != expected_sha256.lower():
        return VerificationResult(
            status=VerificationStatus.INVALID,
            message=(
                "Document content does not match signature: file SHA-256 hash mismatch. "
                "The CBOM file has been modified or tampered with after signing."
            ),
            algorithm=algorithm,
            file_sha256_match=False,
            signature_match=None,
        )

    # 5. Cryptographic signature verification with ML-DSA-65 public key
    try:
        pub.verify(sig_bytes, cbom_bytes)
    except InvalidSignature:
        return VerificationResult(
            status=VerificationStatus.INVALID,
            message=(
                "Cryptographic signature mismatch: the signature does not match the provided public key "
                "or signature data was modified."
            ),
            algorithm=algorithm,
            file_sha256_match=True,
            signature_match=False,
        )
    except (ValueError, TypeError) as exc:
        return VerificationResult(
            status=VerificationStatus.ERROR,
            message=f"Cryptographic verification error: {exc}",
            algorithm=algorithm,
            file_sha256_match=True,
        )

    # Check key fingerprint consistency if present in signature file
    recorded_fp = sig_data.get("public_key_fingerprint")
    actual_fp = compute_public_key_fingerprint(pub)
    if recorded_fp and recorded_fp.lower() != actual_fp.lower():
        return VerificationResult(
            status=VerificationStatus.INVALID,
            message=(
                "Key fingerprint mismatch: public key does not match the key recorded in the signature file."
            ),
            algorithm=algorithm,
            file_sha256_match=True,
            signature_match=False,
        )

    return VerificationResult(
        status=VerificationStatus.VALID,
        message="Signature verified successfully. Document integrity and authenticity confirmed with ML-DSA-65 (FIPS 204).",
        algorithm=algorithm,
        file_sha256_match=True,
        signature_match=True,
    )
