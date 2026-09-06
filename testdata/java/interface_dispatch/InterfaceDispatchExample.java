package com.example.dispatch;

import javax.crypto.Cipher;

/**
 * InterfaceDispatchExample.java — Track A hardening corpus fixture:
 * `provider`'s STATIC type is the AlgorithmProvider interface, not a
 * concrete class. hash_patch/detect/java_resolver.py's Strategy 6
 * (interface-based dispatch) must resolve `provider.algorithmFor(kind)` by
 * finding EVERY class in the project implementing AlgorithmProvider
 * (ProdAlgorithmProvider AND LegacyAlgorithmProvider) and resolving the
 * algorithm from each independently — this must produce BOTH "AES/GCM/
 * NoPadding" and "DES/ECB/PKCS5Padding", never silently picking just one.
 */
public class InterfaceDispatchExample {
    public static byte[] encrypt(AlgorithmProvider provider, String kind, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance(provider.algorithmFor(kind));
        return c.doFinal(data);
    }
}
