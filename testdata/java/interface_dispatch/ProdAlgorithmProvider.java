package com.example.dispatch;

public class ProdAlgorithmProvider implements AlgorithmProvider {
    public String algorithmFor(String kind) {
        return "AES/GCM/NoPadding";
    }
}
