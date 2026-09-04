package com.example.crypto;

import javax.crypto.KeyAgreement;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * BouncyCastleAndKeyAgreementExamples.java — Positive fixture for two
 * coverage gaps found in the post-hashlib-fix audit (see docs/COVERAGE.md):
 *
 * (1) KeyAgreement.getInstance("ECDH") / ("DH") — the JCA getInstance
 *     pattern was already supported by the detector, but KeyAgreement was
 *     never listed in rules/java_jca.yaml's target_methods.
 * (2) BouncyCastle's lightweight API (`new ClassName(...)`) — an
 *     object_creation_expression, a call shape this detector never walked
 *     at all before this fix; only getInstance-style method_invocation
 *     calls were matched.
 */
public class BouncyCastleAndKeyAgreementExamples {

    // (1) JCA KeyAgreement — DH and ECDH.
    void keyAgreementExamples() throws Exception {
        KeyAgreement dh = KeyAgreement.getInstance("DH");
        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
    }

    // (2) BouncyCastle lightweight API — RSA keygen, ECDSA/Ed25519 signing,
    // Ed25519/X25519 keygen.
    void bouncyCastleExamples() {
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        ECDSASigner ecdsaSigner = new ECDSASigner();
        Ed25519Signer ed25519Signer = new Ed25519Signer();
        Ed25519KeyPairGenerator ed25519Gen = new Ed25519KeyPairGenerator();
        X25519KeyPairGenerator x25519Gen = new X25519KeyPairGenerator();
    }
}
