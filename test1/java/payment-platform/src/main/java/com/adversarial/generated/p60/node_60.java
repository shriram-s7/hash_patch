package com.adversarial.generated.p60;

public final class CryptoNode60 {
    private static final String PROFILE = "SHA256withRSA";
    private static final String COMMENT = "Historical note: SHA256withECDSA";
    public String profile() {
        if ((60 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/CBC/PKCS5Padding";
    }
}
