"""
call_chain_example.py — deep call-chain fixture for the "Asset Relationships"
graph (hash_patch/analyze/call_relations.py).

Purpose: demonstrate a real, name-resolvable, multi-level call chain rooted
at the `if __name__ == "__main__":` entry point, six function levels deep
(main -> root_entry -> dispatch -> level_2 -> level_4 -> level_6_leaf), with
three crypto calls sitting at three DIFFERENT depths along that chain
(level_2, level_4, level_6_leaf) rather than one flat helper.

Crucially, the three crypto-bearing functions call each other DIRECTLY
(level_2 -> level_4 -> level_6_leaf, no non-crypto function in between), so
hash_patch/analyze/call_relations.py — which only draws an edge between two
findings when their *enclosing functions* have a direct (one-hop) caller/
callee relationship in the call graph, not a transitive one — has a real
two-edge chain to expose: SHA-512 (level_2) --calls--> RSA (level_4)
--calls--> MD5 (level_6_leaf). `root_entry`/`dispatch` are pure glue with no
crypto call of their own, purely to give the chain its depth from `main`.

Every hop is a plain, statically-resolvable function call, so
hash_patch/analyze/callgraph.py resolves the whole chain (no dynamic
dispatch, no unresolved calls), and all three findings are reachable from the
`__main__` entry point -> expected reachability LIVE_EXTERNAL for all three
(see docs/REACHABILITY.md and tests/golden/reachability_manifest.json).
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def level_6_leaf():
    # Deepest crypto call: a classically-broken hash, six levels below main.
    digest = hashes.MD5()
    return digest


def level_4():
    # Mid-depth crypto call: RSA keypair generation. Calls level_6_leaf()
    # directly, so RSA and MD5's enclosing functions have a direct edge.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = level_6_leaf()
    return key, leaf


def level_2():
    # Shallow crypto call. Calls level_4() directly, so SHA-512 and RSA's
    # enclosing functions have a direct edge too.
    digest = hashes.SHA512()
    return digest, level_4()


def dispatch(payload: bytes):
    return level_2()


def root_entry(payload: bytes):
    return dispatch(payload)


if __name__ == "__main__":
    root_entry(b"call-chain-example-payload")
