"""Sign an already-emitted CBOM file using ML-DSA-65 (FIPS 204).

Produces a detached signature file (.cbom.json.sig) over the literal bytes
of the CBOM file as stored on disk.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from pratyaksha.sign.keys import (
    ALGORITHM_NAME,
    STANDARD_NAME,
    compute_public_key_fingerprint,
    load_private_key,
)


def create_detached_signature_data(
    file_bytes: bytes,
    file_name: str,
    private_key_path: Path,
) -> dict[str, Any]:
    """Compute an ML-DSA-65 detached signature over the raw bytes of a file."""
    priv = load_private_key(private_key_path)
    pub = priv.public_key()

    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    pub_fingerprint = compute_public_key_fingerprint(pub)
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()

    sig_bytes = priv.sign(file_bytes)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    return {
        "$schema": "https://pratyaksha.dev/schemas/signature-v1.json",
        "spec_version": "1.0",
        "algorithm": ALGORITHM_NAME,
        "standard": STANDARD_NAME,
        "file_name": file_name,
        "file_sha256": file_sha256,
        "public_key_fingerprint": pub_fingerprint,
        "public_key_pem": pub_pem,
        "signature": sig_b64,
        "signed_at": datetime.now(UTC).isoformat(),
    }


def sign_cbom_file(
    cbom_path: Path,
    private_key_path: Path,
    output_sig_path: Path | None = None,
) -> Path:
    """Sign an already-emitted CBOM file on disk and write a detached signature file.

    Signs the literal bytes of the file directly without re-serialization,
    ensuring that any alteration to whitespace, formatting, or contents
    will invalidate the signature.
    """
    if not cbom_path.is_file():
        raise FileNotFoundError(f"CBOM file not found: {cbom_path}")

    raw_bytes = cbom_path.read_bytes()
    sig_data = create_detached_signature_data(raw_bytes, cbom_path.name, private_key_path)

    if output_sig_path is None:
        target_path = cbom_path.with_name(f"{cbom_path.name}.sig")
    else:
        target_path = output_sig_path

    target_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(sig_data, indent=2, sort_keys=True) + "\n"
    target_path.write_text(serialized, encoding="utf-8")

    return target_path
