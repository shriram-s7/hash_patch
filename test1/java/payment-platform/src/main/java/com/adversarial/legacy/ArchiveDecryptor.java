package com.adversarial.legacy;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public final class ArchiveDecryptor {
    public byte[] open(byte[] blob, SecretKey key) throws Exception {
        // Legacy archive compatibility. This path is intentionally still referenced.
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(blob);
    }
}
