package com.adversarial.crypto;

import java.security.Signature;
import java.security.GeneralSecurityException;

public final class SignerFactory {
    public static Signature create(String requested) throws GeneralSecurityException {
        // The name is deliberately separated from the operation so simple grep-based
        // migration logic has to resolve the value rather than merely report this line.
        return Signature.getInstance(requested);
    }
}
