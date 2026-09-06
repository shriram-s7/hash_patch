/*
 * reachability_inert.c — Reachability corpus fixture (INERT).
 *
 * `reach_inert_helper` performs a SHA-384 hash but has no production caller
 * anywhere in this codebase — its only caller is
 * testdata/c/tests/test_reachability_inert.c (see docs/REACHABILITY.md for
 * the C test-file convention). It is not reachable from any entry point,
 * and its only reachability path is through test-only code, so it is
 * eligible for INERT.
 *
 * Deliberately a DIFFERENT algorithm from every other fixture in this
 * corpus (SHA-384, not SHA-512/SHA3-256/SHA3-512): CryptoAsset identity is
 * derived from (type, name, parameter_set, mode) only, not file — see
 * hash_patch/model/assets.py::derive_asset_id — so two fixtures calling the
 * exact same algorithm would merge into one asset carrying evidence from
 * both files, and that asset's reachability would be the MOST-LIVE
 * classification across all of it (see classify_asset), silently hiding
 * whichever scenario is less reachable. Each corpus scenario must use its
 * own distinct algorithm to stay independently verifiable, exactly like
 * the existing Python/Java corpora already do.
 */

#include <openssl/sha.h>

void reach_inert_helper(void) {
    SHA384_CTX ctx;
    SHA384_Init(&ctx);
}
