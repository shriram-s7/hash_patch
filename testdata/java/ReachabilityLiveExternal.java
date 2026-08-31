package com.example.reachability;

import java.security.MessageDigest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reachability corpus fixture (LIVE_EXTERNAL).
 *
 * hashLiveExternalHelper() performs a SHA-512 digest and is called from
 * liveExternalEndpoint(), a public method of a @RestController class — a
 * tagged entry point (see docs/REACHABILITY.md). Reachable from a tagged
 * entry point, so it must be classified LIVE_EXTERNAL.
 */
@RestController
public class ReachabilityLiveExternal {

    @GetMapping("/live-external")
    public String liveExternalEndpoint() throws Exception {
        return hashLiveExternalHelper();
    }

    private String hashLiveExternalHelper() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        return digest.getAlgorithm();
    }
}
