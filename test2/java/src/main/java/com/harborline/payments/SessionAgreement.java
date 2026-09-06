package com.harborline.payments;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;

final class SessionAgreement {
    static byte[] establishDh() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DH");
        g.initialize(new DHParameterSpec(new java.math.BigInteger("23"), 5));
        KeyPair pair = g.generateKeyPair();
        KeyAgreement a = KeyAgreement.getInstance("DH");
        a.init(pair.getPrivate());
        return a.generateSecret();
    }

    static byte[] deriveEcdh() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        KeyPair p = g.generateKeyPair();
        KeyAgreement a = KeyAgreement.getInstance("ECDH");
        a.init(p.getPrivate());
        return a.generateSecret();
    }
}
