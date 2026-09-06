package com.example.crypto;

import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

public class MapPolicy {
    private final Map<String, String> registry = new HashMap<>();

    public MapPolicy() {
        registry.put("legacy", AlgorithmId.LEGACY_SIGN);
    }

    public String lookup(String key) {
        return registry.get(key);
    }

    public void test() throws Exception {
        Signature.getInstance(lookup("legacy"));
    }
}
