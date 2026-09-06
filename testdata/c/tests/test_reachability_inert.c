/*
 * test_reachability_inert.c — the ONLY caller of `reach_inert_helper`
 * (testdata/c/reachability_inert.c) anywhere in this codebase. There is no
 * production entry point or production caller, only this test. Lives under
 * testdata/c/tests/, so it matches the "path contains a test/tests
 * directory segment" convention (and its filename also starts with
 * test_) — see docs/REACHABILITY.md.
 */

void reach_inert_helper(void);

int run_reach_inert_test(void) {
    reach_inert_helper();
    return 0;
}
