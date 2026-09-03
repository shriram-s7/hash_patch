"""
negative_rsa_mention.py — Negative fixture for Hash Patch Python detector.

"RSA", "AES", and "MD5" appear only in:
  - Module docstrings
  - Comments
  - String literals not passed to a crypto API
  - An unrelated class that happens to be named "RSA"

Hash Patch must produce ZERO CryptoAssets from this file.
"""

# RSA is a public-key algorithm — this is just a comment.

ALGORITHM_DESCRIPTION = "RSA relies on integer factorisation."
LOG_TAG = "Using AES-256 (configured externally via env)"

# A class whose name contains RSA but which is not a crypto API call.
class RSADocumentation:
    """Documentation helper for RSA concepts. Not a real crypto call."""

    algorithm = "RSA"  # plain string attribute, not an API argument

    def describe(self) -> str:
        return "RSA: Rivest–Shamir–Adleman public-key algorithm"

    def hash_name(self) -> str:
        # Returning a string mentioning MD5 — no API call here.
        return "MD5"


# An attribute access on an unrelated object whose name happens to be
# a crypto algorithm name — but the method ("describe") is not in our
# pycryptodome_classes or pyca_modules target lists.
doc = RSADocumentation()
_ = doc.describe()    # RSADocumentation.describe — NOT in rules, no asset

# A function that takes an algorithm name as a plain string argument to
# a non-crypto function — must not produce an asset.
def configure_algo(name: str) -> dict:
    return {"algo": name, "enabled": True}

configure_algo("RSA")
configure_algo("AES")
configure_algo("MD5")

# Attribute access on an object that is in the namespace list but the
# attribute itself is not an algorithm (e.g. hashes.HashAlgorithm is a
# base class, not a concrete hash — and in any case this just assigns it).
import hashlib  # standard library — not in our rules

md5_obj = hashlib.md5(b"hello")   # hashlib.md5 — "hashlib" is not a PyCA namespace
sha1_obj = hashlib.sha1(b"hello") # same — not detected
