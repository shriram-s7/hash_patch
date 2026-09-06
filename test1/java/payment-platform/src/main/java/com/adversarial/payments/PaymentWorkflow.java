package com.adversarial.payments;

import com.adversarial.auth.AuthenticationGateway;
import com.adversarial.crypto.EnvelopeCipher;
import javax.crypto.SecretKey;
import java.security.PrivateKey;

public final class PaymentWorkflow {
    private final AuthenticationGateway auth = new AuthenticationGateway();
    private final EnvelopeCipher cipher = new EnvelopeCipher();

    public byte[] process(byte[] payload, PrivateKey key, SecretKey storageKey)
            throws Exception {
        byte[] attestation = auth.authenticate(payload, key);
        byte[] sealed = cipher.seal(payload, storageKey);
        byte[] result = new byte[attestation.length + sealed.length];
        System.arraycopy(attestation, 0, result, 0, attestation.length);
        System.arraycopy(sealed, 0, result, attestation.length, sealed.length);
        return result;
    }
}
