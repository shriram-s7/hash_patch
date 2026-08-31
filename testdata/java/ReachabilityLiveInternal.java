package com.example.reachability;

import java.security.MessageDigest;

/**
 * Reachability corpus fixture (LIVE_INTERNAL).
 *
 * hashLiveInternalHelper() performs a SHA3-256 digest and is called by
 * liveInternalCaller(), an ordinary method on a plain class (no
 * @RestController/@Controller, no main). Reachable from some function in
 * the codebase but not from any tagged entry point, so it must be
 * classified LIVE_INTERNAL.
 */
public class ReachabilityLiveInternal {

    public void liveInternalCaller() throws Exception {
        hashLiveInternalHelper();
    }

    private String hashLiveInternalHelper() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        return digest.getAlgorithm();
    }
}
