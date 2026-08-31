package com.example.reachability;

import java.security.Signature;

/**
 * Reachability corpus fixture (INERT).
 *
 * signInertHelper() performs a DSA signature but has no production caller
 * anywhere in this codebase — its only caller is ReachabilityInertTest,
 * whose filename matches the "*Test.java" test-file convention (see
 * docs/REACHABILITY.md). Not reachable from any entry point, and reachable
 * only through test-only code, so it is eligible for INERT.
 */
public class ReachabilityInert {

    public Signature signInertHelper() throws Exception {
        Signature sig = Signature.getInstance("SHA256withDSA");
        return sig;
    }
}
