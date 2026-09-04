"""
pynacl_and_jwt_examples.py — Positive/negative fixture for two coverage
gaps found in the post-hashlib-fix audit (see docs/COVERAGE.md):

PyNaCl (rules/python_crypto.yaml's `bare_constructors` + the
`PrivateKey.generate`/`SigningKey.generate` pycryptodome_classes entries):
  (1) PrivateKey.generate() / Box(...) — X25519, broken-by-shor.
  (2) SigningKey.generate() — Ed25519, broken-by-shor.
  (3) SecretBox(...) — XSalsa20-Poly1305 (AEAD), weakened-by-grover.

PyJWT (rules/python_crypto.yaml's `jwt_algorithms` table):
  (4) jwt.encode(..., algorithm="HS256") — HMAC, weakened-by-grover.
  (5) jwt.encode(..., algorithm="RS256") — RSA, broken-by-shor.
  (6) jwt.encode(..., algorithm="ES384") — ECDSA, broken-by-shor.
  (7) NEGATIVE: jwt.encode(..., algorithm=alg) where `alg` is a variable,
      not a string literal — must produce nothing, never a guess.
"""

from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey
from nacl.secret import SecretBox
import jwt


# (1) X25519 key generation and box construction.
def make_box():
    sk = PrivateKey.generate()
    box = Box(sk, sk.public_key)
    return box


# (2) Ed25519 signing key generation.
def make_signing_key():
    return SigningKey.generate()


# (3) XSalsa20-Poly1305 authenticated symmetric encryption.
def make_secret_box(key: bytes):
    return SecretBox(key)


# (4)/(5)/(6) PyJWT with three different algorithm families.
def sign_hs256(payload: dict, secret: str) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")


def sign_rs256(payload: dict, private_key) -> str:
    return jwt.encode(payload, private_key, algorithm="RS256")


def sign_es384(payload: dict, private_key) -> str:
    return jwt.encode(payload, private_key, algorithm="ES384")


# (7) NEGATIVE: algorithm chosen at runtime — unresolvable, must not guess.
def sign_dynamic(payload: dict, key, alg: str) -> str:
    return jwt.encode(payload, key, algorithm=alg)
