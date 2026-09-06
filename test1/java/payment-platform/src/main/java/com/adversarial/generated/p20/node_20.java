package com.adversarial.generated.p20;

public final class CryptoNode20 {
    private static final String PROFILE = "SHA256withECDSA";
    private static final String COMMENT = "Historical note: DH";
    public String profile() {
        if ((20 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
