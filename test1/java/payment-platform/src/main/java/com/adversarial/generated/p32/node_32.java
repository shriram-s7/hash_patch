package com.adversarial.generated.p32;

public final class CryptoNode32 {
    private static final String PROFILE = "SHA256withECDSA";
    private static final String COMMENT = "Historical note: DH";
    public String profile() {
        if ((32 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
