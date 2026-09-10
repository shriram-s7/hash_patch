package com.example.datachain;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;

/**
 * Fixture for hash_patch/analyze/data_chain.py: a single method that
 * cascades RSA encrypt -> AES-GCM encrypt (on the RSA output) -> ChaCha20-
 * Poly1305 encrypt (on the AES output), all within one main() method.
 *
 * All six getInstance() calls below are separate findings with no direct
 * caller/callee edge between them (hash_patch/analyze/call_relations.py
 * only tracks cross-function call-graph adjacency) -- but three of them
 * are genuinely data-chained: RSA-cipher -> AES-GCM-cipher (nested-call
 * form) -> ChaCha20-Poly1305-cipher (bare-variable form). The three keygen
 * calls are never used as an argument to anything, so they stay isolated —
 * neither chained to each other nor to a cipher.
 */
public class Main {

    public static void main(String[] args) throws Exception {
        byte[] plaintext = "top secret payload".getBytes();

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        KeyGenerator aesKg = KeyGenerator.getInstance("AES");
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Case (a): nested-call form — AES's argument is RSA cipher's own call.
        byte[] aesEncrypted = aesCipher.doFinal(rsaCipher.doFinal(plaintext));

        KeyGenerator chachaKg = KeyGenerator.getInstance("ChaCha20");
        Cipher chaChaCipher = Cipher.getInstance("ChaCha20-Poly1305");
        // Case (b): bare-variable form — ChaCha's argument is the AES output variable.
        byte[] finalCiphertext = chaChaCipher.doFinal(aesEncrypted);

        System.out.println(finalCiphertext.length);
    }
}
