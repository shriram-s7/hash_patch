package com.example.reachability;

import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;

/**
 * Reachability corpus fixture (UNKNOWN).
 *
 * cipherUnknownHelper() gets a DES Cipher instance but is never invoked by
 * a statically-resolvable call anywhere in this codebase — it is only
 * referenced as a method reference stored in a Map<String, Runnable> and
 * invoked through a runtime key lookup. This analyzer's simple, name-based
 * call resolver (hash_patch/analyze/callgraph.py) does not trace values
 * through a Map (real data-flow analysis, out of scope).
 *
 * Because we cannot prove cipherUnknownHelper is unreachable, and it sits
 * in production code, not a test file, the fail-safe default applies per
 * the HARD SAFETY RULE: UNKNOWN, never INERT.
 */
public class ReachabilityUnknownDynamic {

    private final Map<String, Runnable> dispatch = new HashMap<>();

    public ReachabilityUnknownDynamic() {
        dispatch.put("go", this::cipherUnknownHelper);
    }

    public void dynamicEntry(String action) {
        Runnable handler = dispatch.get(action);
        handler.run();
    }

    private void cipherUnknownHelper() {
        try {
            Cipher cipher = Cipher.getInstance("DES");
        } catch (Exception e) {
            // ignore for fixture purposes
        }
    }
}
