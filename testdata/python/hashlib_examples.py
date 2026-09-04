"""
hashlib_examples.py — Positive/negative fixture for the hashlib coverage
gap fix (rules/python_crypto.yaml's `hashlib` namespace).

(1) is the second real missed finding from the reproduction corpus:
D:/cbom_adversarial_corpus/python/orchestration/app/crypto/wrappers.py's
`hmac.new(secret, payload, hashlib.sha256)` — the bare `hashlib.sha256`
reference (not itself a call) passed as hmac.new()'s third argument must
be recognised as a hash-algorithm usage.

(2) covers the `hashlib.new("<literal>")` string-based constructor form.

(3) is the negative case: `hashlib.new(algo_name, data)` where the
algorithm name is a variable, not a literal — must produce NOTHING. This
detector only ever matches a resolvable literal; it never guesses.
"""

import hashlib
import hmac


# (1) hmac.new()'s digestmod argument names the hash algorithm via a bare
# hashlib.* reference (no call) — must produce a SHA-256 finding,
# weakened-by-grover.
def mac(payload: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, payload, hashlib.sha256).digest()


# (2) hashlib.new() with a resolvable string-literal algorithm name — must
# produce an MD5 finding, broken-classically.
def legacy_checksum(data: bytes) -> str:
    return hashlib.new("md5", data).hexdigest()


# (3) hashlib.new() with an UNRESOLVABLE (non-literal) algorithm name —
# must produce nothing at all for this call, never a guess.
def dynamic_checksum(data: bytes, algo_name: str) -> str:
    return hashlib.new(algo_name, data).hexdigest()
