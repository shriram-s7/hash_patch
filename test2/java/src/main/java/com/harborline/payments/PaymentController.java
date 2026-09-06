package com.harborline.payments;

public final class PaymentController {
    public byte[] submit(PaymentRequest request) {
        return submitSigned(request, false);
    }

    public byte[] submitSigned(PaymentRequest request, boolean compact) {
        return compact
                ? PaymentSigner.signLegacy(request.accountNumber(), request.amount())
                : PaymentSigner.sign(request.accountNumber(), request.amount());
    }

    public byte[] exportHealthCase(HealthCase c) {
        return SensitiveStore.encryptClinicalSummary(c.summary());
    }

    public byte[] runtimeSignature(String payload) throws Exception {
        return RuntimeProvider.sign(payload);
    }
}
