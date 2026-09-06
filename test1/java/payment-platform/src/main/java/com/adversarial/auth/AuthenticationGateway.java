package com.adversarial.auth;

import com.adversarial.crypto.*;
import java.security.PrivateKey;

public final class AuthenticationGateway {
    private final IdentitySigner signer = new IdentitySigner(new CryptoPolicy());

    public byte[] authenticate(byte[] canonicalRequest, PrivateKey signingKey)
            throws Exception {
        return signer.sign("customer-auth", canonicalRequest, signingKey);
    }

    public byte[] partnerAuthenticate(byte[] body, PrivateKey signingKey)
            throws Exception {
        return signer.sign("partner-auth", body, signingKey);
    }
}
