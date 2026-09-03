"""
reachability_unknown_dynamic.py — Reachability corpus fixture (UNKNOWN).

`_reach_unknown_helper` performs a ChaCha20 pycryptodome call but is never
invoked by a statically-resolvable call anywhere in this codebase — its
only reference is as a VALUE inside `_DISPATCH`, invoked through a dynamic
subscript lookup (`_DISPATCH[action]()`). This analyzer's simple, name-based
call resolver (hash_patch/analyze/callgraph.py) deliberately does not trace
values through a dict — doing so would require real data-flow analysis,
which is out of scope, matching the level of sophistication the existing
detectors already use.

Because we cannot prove `_reach_unknown_helper` is unreachable — it might
well be invoked by `dynamic_entry` below at runtime — and it sits in
production code (not a test file), the fail-safe default applies per the
HARD SAFETY RULE: UNKNOWN, never INERT.
"""

from Crypto.Cipher import ChaCha20


def _reach_unknown_helper():
    cipher = ChaCha20.new(key=b"0" * 32)
    return cipher


_DISPATCH = {"go": _reach_unknown_helper}


def dynamic_entry(action: str):
    handler = _DISPATCH[action]
    return handler()
