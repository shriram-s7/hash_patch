package com.example.dispatch;

public class LegacyAlgorithmProvider implements AlgorithmProvider {
    public String algorithmFor(String kind) {
        return "DES/ECB/PKCS5Padding";
    }
}
