package com.adversarial.crypto;

import java.security.PublicKey;
import java.security.Signature;

public final class LegacyVerifier {
    public boolean verify(byte[] data, byte[] signature, PublicKey key) throws Exception {
        String profile = "legacy-partner";
        Signature verifier = Signature.getInstance(new CryptoPolicy().algorithmFor(profile));
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(signature);
    }
}
