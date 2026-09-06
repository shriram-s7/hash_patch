package com.example.crypto;

import javax.crypto.KeyAgreement;

public class TernaryIndirection {
    public void test(boolean compat) throws Exception {
        KeyAgreement.getInstance(compat ? AlgorithmId.DH_AGREE : AlgorithmId.ECDH_AGREE);
    }
}
