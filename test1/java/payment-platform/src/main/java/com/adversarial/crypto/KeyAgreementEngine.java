package com.adversarial.crypto;

import javax.crypto.KeyAgreement;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class KeyAgreementEngine {
    public byte[] derive(PublicKey peer, PrivateKey local, boolean compatibility)
            throws Exception {
        String algorithm = compatibility
                ? AlgorithmId.LEGACY_KEY_AGREEMENT
                : AlgorithmId.KEY_AGREEMENT;
        KeyAgreement ka = KeyAgreement.getInstance(algorithm);
        ka.init(local);
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }
}
