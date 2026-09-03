package com.example.negative;

/**
 * Negative fixture: "RSA" appears only in comments and unrelated string
 * literals — NOT as an argument to a JCA/JCE getInstance() call.
 *
 * Hash Patch must produce ZERO CryptoAssets from this file.
 */
public class NegativeRsaMention {

    // RSA is a public-key algorithm — but this is just a comment.

    /** Describes how RSA-2048 works. */
    private static final String ALGORITHM_DESCRIPTION =
        "RSA is based on the difficulty of factoring large integers.";

    /** Log message mentioning RSA. */
    private static final String LOG_MESSAGE =
        "Using RSA for key exchange (configured externally)";

    /**
     * This method does NOT call getInstance() — it only manipulates the
     * string that mentions "RSA" as a label, not as a cryptographic API arg.
     */
    public String getAlgorithmName() {
        // We build a name that contains "RSA" but never pass it to getInstance.
        String name = "RSA";
        return name.toLowerCase();
    }

    /**
     * A call to an unrelated static method that happens to have the same
     * shape (Foo.getInstance(...)) but is not a JCA target class.
     */
    public Object nonJcaGetInstance() {
        // "ConnectionFactory" is not in the JCA target list.
        return ConnectionFactory.getInstance("RSA-like-config");
    }

    // A dummy inner class to make the file compile-like.
    static class ConnectionFactory {
        static Object getInstance(String ignored) { return null; }
    }
}
