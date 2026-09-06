package com.adversarial.generated.p4;

public final class CryptoNode4 {
    private static final String PROFILE = "DH";
    private static final String COMMENT = "Historical note: SHA256withRSA";
    public String profile() {
        if ((4 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
