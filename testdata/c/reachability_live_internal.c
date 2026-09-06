/*
 * reachability_live_internal.c — Reachability corpus fixture (LIVE_INTERNAL).
 *
 * `reach_live_internal_helper` performs a SHA3-256 hash and is called by
 * `reach_live_internal_caller`, an ordinary function that is never invoked
 * from a tagged entry point (not named `main`). The crypto call is
 * reachable from *some* function in the codebase but not from any tagged
 * entry point, so it must be classified LIVE_INTERNAL.
 */

#include <openssl/evp.h>

void reach_live_internal_helper(void) {
    EVP_sha3_256();
}

void reach_live_internal_caller(void) {
    reach_live_internal_helper();
}
