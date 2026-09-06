package com.adversarial.crypto;
public final class AlgorithmId {
    public static final String SIGN = "SHA256withRSA";
    public static final String LEGACY_SIGN = "SHA1withRSA";
    public static final String EC_SIGN = "SHA256withECDSA";
    public static final String KEY_AGREEMENT = "ECDH";
    public static final String LEGACY_KEY_AGREEMENT = "DH";
    public static final String STORE_CIPHER = "AES/GCM/NoPadding";
    public static final String LEGACY_CIPHER = "AES/CBC/PKCS5Padding";
    private AlgorithmId() {}
}
