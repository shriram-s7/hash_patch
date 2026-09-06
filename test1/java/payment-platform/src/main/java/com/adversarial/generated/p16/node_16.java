package com.adversarial.generated.p16;

public final class CryptoNode16 {
    private static final String PROFILE = "DH";
    private static final String COMMENT = "Historical note: SHA256withRSA";
    public String profile() {
        if ((16 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
