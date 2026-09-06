package com.adversarial.generated.p8;

public final class CryptoNode8 {
    private static final String PROFILE = "SHA256withECDSA";
    private static final String COMMENT = "Historical note: DH";
    public String profile() {
        if ((8 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
