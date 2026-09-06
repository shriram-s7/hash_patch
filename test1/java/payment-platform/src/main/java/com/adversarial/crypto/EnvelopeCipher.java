package com.adversarial.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public final class EnvelopeCipher {
    public byte[] seal(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AlgorithmId.STORE_CIPHER);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        return cipher.doFinal(plaintext);
    }

    public byte[] legacySeal(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AlgorithmId.LEGACY_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }
}
