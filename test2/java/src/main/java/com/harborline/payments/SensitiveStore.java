package com.harborline.payments;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.Signature;

final class SensitiveStore {
    static byte[] encryptClinicalSummary(String summary) {
        try {
            byte[] key = "01234567890123456789012345678901".getBytes();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, new byte[12]));
            return cipher.doFinal(summary.getBytes());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] compactSignature() throws Exception {
        byte[] out = new byte[64];
        Signature s = Signature.getInstance("Ed25519");
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
        s.initSign(g.generateKeyPair().getPrivate());
        byte[] sig = s.sign();
        System.arraycopy(sig, 0, out, 0, sig.length);
        return out;
    }
}
