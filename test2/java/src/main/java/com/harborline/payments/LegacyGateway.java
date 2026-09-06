package com.harborline.payments;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

final class LegacyGateway {
    static String partnerFingerprint(String accountNumber) throws Exception {
        return MessageDigest.getInstance("MD5")
                .digest(accountNumber.getBytes(StandardCharsets.UTF_8)).toString();
    }

    static byte[] oldPayload(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        return c.doFinal(data);
    }
}
