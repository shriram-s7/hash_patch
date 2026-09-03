"""
crypto_pyca.py — Positive fixture for Hash Patch Python detector.

Demonstrates PyCA (cryptography library) and pycryptodome usage patterns.
Every algorithm reference below is an actual API call that must produce a
CryptoAsset in the CBOM scan output.

Import aliases are intentionally avoided for pycryptodome so the detector
sees the canonical module attribute names (AES.new, RSA.generate, etc.).
"""

# ── PyCA (cryptography library) ─────────────────────────────────────────────

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# (1) RSA key generation — broken-by-shor
def pyca_rsa_example():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    return private_key


# (2) AES-256-GCM encryption — weakened-by-grover
def pyca_aes_gcm_example(key: bytes, iv: bytes):
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend(),
    )
    return cipher


# (3) SHA-256 hashing — weakened-by-grover
def pyca_sha256_example(data: bytes):
    digest = hashes.SHA256()
    return digest


# (4) MD5 hashing — broken-classically
def pyca_md5_example(data: bytes):
    digest = hashes.MD5()
    return digest


# (5) SHA-1 hashing — broken-classically
def pyca_sha1_example(data: bytes):
    digest = hashes.SHA1()
    return digest


# (6) ECDSA key generation via curve constructor — broken-by-shor
def pyca_ecdsa_example():
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend(),
    )
    return private_key


# ── pycryptodome ─────────────────────────────────────────────────────────────
# Use unaliased imports so the detector sees AES.new, RSA.generate, MD5.new
# matching the pycryptodome_classes in rules/python_crypto.yaml.

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5


# (7) pycryptodome AES-GCM — weakened-by-grover
def pycryptodome_aes_example(key: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher


# (8) pycryptodome RSA keygen — broken-by-shor
def pycryptodome_rsa_example():
    key = RSA.generate(2048)
    return key


# (9) pycryptodome MD5 — broken-classically
def pycryptodome_md5_example(data: bytes):
    h = MD5.new()
    h.update(data)
    return h.hexdigest()
