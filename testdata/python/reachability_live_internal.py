"""
reachability_live_internal.py — Reachability corpus fixture (LIVE_INTERNAL).

`_reach_live_internal_helper` performs a SHA3-256 hash and is called by
`_reach_live_internal_caller`, an ordinary function that is never invoked
from a tagged entry point (no route decorator, not named `main`, not the
`if __name__ == "__main__":` block). The crypto call is reachable from
*some* function in the codebase but not from any tagged entry point, so it
must be classified LIVE_INTERNAL.
"""

from cryptography.hazmat.primitives import hashes


def _reach_live_internal_helper():
    digest = hashes.SHA3_256()
    return digest


def _reach_live_internal_caller():
    return _reach_live_internal_helper()
