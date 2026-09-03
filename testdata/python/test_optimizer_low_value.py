"""
test_optimizer_low_value.py — Pillar 5 (Migration Optimiser) corpus
fixture: the deliberate "cheap + low risk" case.

Named `test_*.py` and containing a function with NO callers at all, this
file is classified INERT by construction (docs/REACHABILITY.md's INERT
rule: "it has no callers at all and sits directly in a test file"). The
X25519 call below uses a generic, non-crypto-suggestive parameter name, so
Pillar 2 (Shelf-Life) also finds no signal for it -- both axes default,
giving this finding the lowest possible risk score in this corpus (see
hash_patch/analyze/risk_score.py's near-zero INERT reachability multiplier
and its default shelf-life constant). See docs/OPTIMISER.md.
"""

from cryptography.hazmat.primitives.asymmetric import x25519


def _generate_unused_keypair(temp_placeholder):
    return x25519.generate_key()
