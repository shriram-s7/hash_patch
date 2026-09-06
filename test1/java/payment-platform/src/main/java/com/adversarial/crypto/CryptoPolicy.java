package com.adversarial.crypto;

import java.util.Map;
import java.util.HashMap;

public final class CryptoPolicy {
    private final Map<String,String> profiles = new HashMap<>();
    public CryptoPolicy() {
        profiles.put("customer-auth", AlgorithmId.SIGN);
        profiles.put("partner-auth", AlgorithmId.EC_SIGN);
        profiles.put("legacy-partner", AlgorithmId.LEGACY_SIGN);
        profiles.put("exchange", AlgorithmId.KEY_AGREEMENT);
        profiles.put("archive", AlgorithmId.LEGACY_CIPHER);
    }
    public String algorithmFor(String profile) {
        return profiles.getOrDefault(profile, AlgorithmId.SIGN);
    }
}
