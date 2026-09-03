package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Demonstrates JCA/JCE usage patterns detected by Hash Patch.
 * Each getInstance() call below should produce a CryptoAsset in the CBOM.
 */
public class CryptoExamples {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // -----------------------------------------------------------------------
    // (1) RSA key pair generation — broken-by-shor
    // -----------------------------------------------------------------------
    public void rsaExample() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    // -----------------------------------------------------------------------
    // (2) AES-256-GCM encryption — weakened-by-grover
    // -----------------------------------------------------------------------
    public void aesGcmExample() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }

    // -----------------------------------------------------------------------
    // (3) MD5 hashing — broken-classically
    // -----------------------------------------------------------------------
    public void md5Example() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest("hello".getBytes());
    }

    // -----------------------------------------------------------------------
    // (4) SHA-1 hashing — broken-classically
    // -----------------------------------------------------------------------
    public void sha1Example() throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    }

    // -----------------------------------------------------------------------
    // (5) ECDSA signature — broken-by-shor
    // -----------------------------------------------------------------------
    public void ecdsaExample() throws Exception {
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        Signature sig = Signature.getInstance("SHA256withECDSA");
    }

    // -----------------------------------------------------------------------
    // (6) BouncyCastle provider call — RSA via "BC" provider string
    // -----------------------------------------------------------------------
    public void bouncyCastleRsaExample() throws Exception {
        KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("RSA", "BC");
        bcKpg.initialize(4096);
    }

    // -----------------------------------------------------------------------
    // (7) SHA-256 hashing — weakened-by-grover (acceptable post-quantum)
    // -----------------------------------------------------------------------
    public void sha256Example() throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    }
}
