package com.harborline.payments;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

final class PolicyDigest {
    static byte[] fingerprint(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    static byte[] hmac(byte[] data, byte[] secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        return mac.doFinal(data);
    }
}
