/*
 * reachability_live_external.c — Reachability corpus fixture (LIVE_EXTERNAL).
 *
 * `reach_live_external_helper` performs a SHA-512 hash and is called by
 * `main`, C's tagged entry point (see docs/REACHABILITY.md). The crypto
 * call is reachable from a tagged entry point, so it must be classified
 * LIVE_EXTERNAL.
 */

#include <openssl/sha.h>

void reach_live_external_helper(void) {
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
}

int main(void) {
    reach_live_external_helper();
    return 0;
}
