package com.harborline.payments;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;

final class PaymentSigner {
    static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    static byte[] sign(String accountNumber, long amount) {
        return signBody(canonical(accountNumber, amount), SIGNATURE_ALGORITHM);
    }

    static byte[] signLegacy(String accountNumber, long amount) {
        return signBody(canonical(accountNumber, amount), "Ed25519");
    }

    private static String canonical(String accountNumber, long amount) {
        return accountNumber + ":" + amount;
    }

    private static byte[] signBody(String body, String algorithm) {
        try {
            Signature s = Signature.getInstance(algorithm);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    algorithm.equals("Ed25519") ? "Ed25519" : "EC");
            if (algorithm.equals("Ed25519")) {
                s.initSign(kpg.generateKeyPair().getPrivate());
            } else {
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
                s.initSign(kpg.generateKeyPair().getPrivate());
            }
            s.update(body.getBytes(StandardCharsets.UTF_8));
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String signatureName() {
        return "SHA256withECDSA";
    }
}
