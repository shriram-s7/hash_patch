package com.adversarial.crypto;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.GeneralSecurityException;

public final class IdentitySigner {
    private final CryptoPolicy policy;
    public IdentitySigner(CryptoPolicy policy) { this.policy = policy; }

    public byte[] sign(String profile, byte[] message, PrivateKey key)
            throws GeneralSecurityException {
        String selected = policy.algorithmFor(profile);
        Signature s = SignerFactory.create(selected);
        s.initSign(key);
        s.update(message);
        return s.sign();
    }
}
