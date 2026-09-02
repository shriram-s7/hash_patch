"""Key management for ML-DSA-65 post-quantum signing (FIPS 204).

HONESTY NOTE:
This key management implementation is for demonstration and local offline use:
it generates unencrypted PEM-encoded key files on disk with no Hardware
Security Module (HSM), key rotation, or enterprise access control.
A production deployment requires secure key custody (e.g., PKCS#11 HSM,
cloud KMS with PQC support, or strict operational access control).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

ALGORITHM_NAME = "ML-DSA-65"
STANDARD_NAME = "FIPS 204"
DEFAULT_PRIVATE_KEY_NAME = "pratyaksha_signing.key"
DEFAULT_PUBLIC_KEY_NAME = "pratyaksha_signing.pub"


def generate_keypair(
    output_dir: Path,
    private_key_name: str = DEFAULT_PRIVATE_KEY_NAME,
    public_key_name: str = DEFAULT_PUBLIC_KEY_NAME,
) -> tuple[Path, Path]:
    """Generate a new ML-DSA-65 keypair and save private and public keys as PEM files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    priv = mldsa.MLDSA65PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = output_dir / private_key_name
    pub_path = output_dir / public_key_name

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    return priv_path, pub_path


def load_private_key(key_path: Path) -> mldsa.MLDSA65PrivateKey:
    """Load an ML-DSA-65 private key from a PEM-encoded file."""
    if not key_path.is_file():
        raise FileNotFoundError(f"Private key file not found: {key_path}")

    data = key_path.read_bytes()
    try:
        loaded = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError, OSError) as exc:
        raise ValueError(f"Failed to parse private key from {key_path}: {exc}") from exc

    if not isinstance(loaded, mldsa.MLDSA65PrivateKey):
        raise TypeError(
            f"Expected ML-DSA-65 private key, but {key_path} contains {type(loaded).__name__}"
        )
    return loaded


def load_public_key(pub_path: Path) -> mldsa.MLDSA65PublicKey:
    """Load an ML-DSA-65 public key from a PEM-encoded file."""
    if not pub_path.is_file():
        raise FileNotFoundError(f"Public key file not found: {pub_path}")

    data = pub_path.read_bytes()
    try:
        loaded = serialization.load_pem_public_key(data)
    except (ValueError, TypeError, OSError) as exc:
        raise ValueError(f"Failed to parse public key from {pub_path}: {exc}") from exc

    if not isinstance(loaded, mldsa.MLDSA65PublicKey):
        raise TypeError(
            f"Expected ML-DSA-65 public key, but {pub_path} contains {type(loaded).__name__}"
        )
    return loaded


def compute_public_key_fingerprint(pub: mldsa.MLDSA65PublicKey) -> str:
    """Compute SHA-256 fingerprint of the SubjectPublicKeyInfo DER encoding."""
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()
