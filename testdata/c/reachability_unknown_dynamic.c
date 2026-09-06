/*
 * reachability_unknown_dynamic.c — Reachability corpus fixture (UNKNOWN).
 *
 * `reach_unknown_helper` performs a SHA3-512 hash but is never invoked by a
 * statically-resolvable call anywhere in this codebase — its only
 * reference is as a VALUE inside `dispatch_table`, invoked through a
 * dynamic array-subscript call (`dispatch_table[idx]()`). This analyzer's
 * simple, name-based call resolver (hash_patch/analyze/callgraph.py)
 * deliberately does not trace values through an array/function-pointer
 * table — doing so would require real data-flow analysis, which is out of
 * scope, matching the level of sophistication the existing detectors
 * already use.
 *
 * Because we cannot prove `reach_unknown_helper` is unreachable — it might
 * well be invoked by `dynamic_entry` below at runtime — and it sits in
 * production code (not a test file), the fail-safe default applies per the
 * HARD SAFETY RULE: UNKNOWN, never INERT.
 */

#include <openssl/evp.h>

typedef void (*handler_fn)(void);

void reach_unknown_helper(void) {
    EVP_sha3_512();
}

static handler_fn dispatch_table[] = { reach_unknown_helper };

void dynamic_entry(int idx) {
    dispatch_table[idx]();
}
