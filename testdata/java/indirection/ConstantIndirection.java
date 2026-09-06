package com.example.crypto;

import javax.crypto.Cipher;

public class ConstantIndirection {
    public void run() throws Exception {
        Cipher.getInstance(AlgorithmId.STORE_CIPHER);
    }
}
