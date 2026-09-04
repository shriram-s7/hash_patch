"""
hashlib_sha256_alone.py — the EXACT minimal reproduction from the
hashlib-coverage-gap bug report, scanned in isolation.

Byte-for-byte the same as
D:/cbom_adversarial_corpus/python/data_pipeline/crypto/token_normalizer.py.
Before rules/python_crypto.yaml gained a `hashlib` namespace, scanning this
file alone produced ZERO findings — hashlib.sha256() (Python's standard
library, arguably the single most common way Python code hashes anything)
was completely unmatched by both the PyCA `cryptography` and pycryptodome
patterns this detector recognised.

Must now produce exactly one SHA-256 finding, quantum_status
weakened-by-grover. See tests/unit/test_python_detector.py::
test_hashlib_sha256_alone_produces_exactly_one_finding and
tests/golden/test_python_hashlib_golden.py.
"""

import hashlib


def normalize_token(value: str) -> str:
    # SHA-256 is intentionally used here for a non-public-key digest.
    return hashlib.sha256(value.encode()).hexdigest()
