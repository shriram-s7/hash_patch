package com.example.passthrough;

import javax.crypto.Cipher;

/**
 * PassthroughDepth3.java — Track A hardening corpus fixture: Strategy 4
 * (parameter passthrough, hash_patch/detect/java_resolver.py) tracing back
 * through a 3-hop call chain to find the real literal algorithm value.
 *
 * hop3()'s `algo` parameter is resolved by hash_patch/detect/java.py's call
 * to `resolve_java_argument`, which recurses through
 * `resolve_parameter_passthrough` (capped at 3 hops, see that method's own
 * `depth > 3` check):
 *
 *   Cipher.getInstance(algo) in hop3()
 *     -> hop3's caller hop2(algo, data): resolve hop2's own `algo` param
 *     -> hop2's caller hop1(algo, data): resolve hop1's own `algo` param
 *     -> hop1's caller topLevelEntry(): the literal "AES/GCM/NoPadding"
 *
 * Three hops of passthrough tracing (hop3->hop2, hop2->hop1, hop1->literal)
 * must all resolve — this is the specific depth this fixture locks in with
 * a regression test rather than leaving it merely incidental.
 */
public class PassthroughDepth3 {

    public static byte[] topLevelEntry(byte[] data) throws Exception {
        return hop1("AES/GCM/NoPadding", data);
    }

    static byte[] hop1(String algo, byte[] data) throws Exception {
        return hop2(algo, data);
    }

    static byte[] hop2(String algo, byte[] data) throws Exception {
        return hop3(algo, data);
    }

    static byte[] hop3(String algo, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance(algo);
        return c.doFinal(data);
    }
}
