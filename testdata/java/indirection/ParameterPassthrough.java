package com.example.crypto;

import java.security.Signature;

public class ParameterPassthrough {
    public static void create(String algo) throws Exception {
        Signature.getInstance(algo);
    }

    public static void caller() throws Exception {
        create(AlgorithmId.EC_SIGN);
    }
}
