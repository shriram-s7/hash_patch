"""
reachability_inert.py — Reachability corpus fixture (INERT).

`_reach_inert_helper` performs an ElGamal keygen via pycryptodome but has no
production caller anywhere in this codebase — its only caller is a test
function in tests/test_reachability_inert.py (see docs/REACHABILITY.md for
the test-file convention). It is not reachable from any entry point, and its
only reachability path is through test-only code, so it is eligible for
INERT.
"""

from Crypto.PublicKey import ElGamal


def _reach_inert_helper():
    key = ElGamal.generate(2048, None)
    return key
