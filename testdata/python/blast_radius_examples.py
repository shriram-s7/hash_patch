"""
blast_radius_examples.py — Pillar 3 (Blast Radius) corpus fixture for
Python's bytearray(N)/bytes(N) detector
(hash_patch/detect/blast_radius/python_buffers.py).

Each function pairs a fixed-size bytearray()/bytes() allocation with a
nearby RSA signing call in the SAME file — blast-radius correlation is
same-file only, see docs/BLAST_RADIUS.md. Uses `jwt.encode(payload, key,
algorithm="RS256")` (a 2-level `module.function` call
hash_patch/detect/python.py's resolver already handles), which resolves to
canonical name "RSA" with `Primitive.SIGNATURE` — the specific
(name, primitive) combination blast-radius correlation actually requires
for a "signature"-field buffer (bare `rsa.generate_private_key(...)`
resolves to `Primitive.PKE` instead, which has no "signature" field
mapping — see hash_patch/analyze/blast_radius.py's `_PQC_FIELDS`).
`Ed25519` was deliberately NOT used here: real-world Ed25519 usage
(`ed25519.Ed25519PrivateKey.generate()`, a 3-level attribute chain) is a
known, separate, pre-existing gap in the Python OPERATION detector,
unrelated to this blast-radius work — see
test2/python/freight_api/signing.py's own real-world case, which still
correlates successfully via that file's Ed25519 CRYPTO_REFERENCE finding
rather than an OPERATION one. Expected outcomes are recorded in
tests/golden/blast_radius_manifest.json's "python" section.
"""

import jwt


def sign_with_named_buffer(key, payload: dict) -> bytes:
    """(1) MUST FIRE via NAME-PATTERN correlation: `signature_buf` matches
    the "signature" name pattern directly. An RSA-2048 signature (256 bytes
    classically) fits, but ML-DSA-65's 3309-byte signature does not.
    """
    signature = jwt.encode(payload, key, algorithm="RS256").encode()
    signature_buf = bytearray(256)
    signature_buf[: len(signature)] = signature
    return bytes(signature_buf)


def sign_with_generic_name_buffer(key, payload: dict) -> bytes:
    """(2) MUST FIRE via DATA-FLOW correlation, NOT name pattern: `outbox`
    matches no crypto-material name pattern, but is later slice-assigned
    from `signature` inside this same function -- the Python idiom for
    "copy a crypto result into this fixed buffer". Sized at 512 bytes:
    still too small for ML-DSA-65 (3309B), so it MUST fire even though it
    is larger than RSA-2048's own 256-byte signature.
    """
    signature = jwt.encode(payload, key, algorithm="RS256").encode()
    outbox = bytearray(512)
    outbox[: len(signature)] = signature
    return bytes(outbox)


def sign_with_generous_buffer_no_overflow(key, payload: dict) -> bytes:
    """(3) MUST NOT FIRE: `reply` is data-flow correlated to the signature
    (same idiom as (2)) but generously sized at 8192 bytes -- even
    ML-DSA-65's 3309-byte signature fits inside it.
    """
    signature = jwt.encode(payload, key, algorithm="RS256").encode()
    reply = bytearray(8192)
    reply[: len(signature)] = signature
    return bytes(reply)


def unrelated_scratch_buffer() -> bytes:
    """(4) MUST produce NO SizeConstraint at all: `scratch` matches no name
    pattern, has no crypto API call anywhere in this function, and is never
    slice-assigned from a name (only from the literal `1`) -- a plain,
    unrelated bytearray(). Silently dropped, never a guessed correlation.
    """
    scratch = bytearray(16)
    scratch[0] = 1
    return bytes(scratch)
