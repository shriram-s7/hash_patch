package com.adversarial.legacy;
import java.security.Signature;

public final class DeadCrypto {
    public static byte[] neverCalled(byte[] x) throws Exception {
        Signature s = Signature.getInstance("SHA1withRSA");
        return s.toString().getBytes();
    }
}
