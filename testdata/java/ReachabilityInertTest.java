package com.example.reachability;

import org.junit.jupiter.api.Test;

/**
 * Test-only caller for ReachabilityInert.signInertHelper() — see the
 * reachability_inert corpus scenario in docs/REACHABILITY.md. This file's
 * name matches the "*Test.java" test-file convention, so it is treated as
 * test-only for reachability purposes.
 */
public class ReachabilityInertTest {

    @Test
    public void testSignInertHelperRuns() throws Exception {
        ReachabilityInert target = new ReachabilityInert();
        target.signInertHelper();
    }
}
