package com.harborline.payments;

final class RuntimeProvider {
    static byte[] sign(String payload) throws Exception {
        String impl = System.getenv("PAYMENT_SIGNATURE_PROVIDER");
        Class<?> type = Class.forName(impl);
        Object instance = type.getDeclaredConstructor().newInstance();
        return ((SigningProvider) instance).sign(payload);
    }

    interface SigningProvider {
        byte[] sign(String payload) throws Exception;
    }
}
