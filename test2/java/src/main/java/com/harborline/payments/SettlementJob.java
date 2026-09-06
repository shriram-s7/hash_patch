package com.harborline.payments;

final class SettlementJob {
    byte[] settle(String account, long amount) {
        return PaymentSigner.sign(account, amount);
    }

    byte[] audit(String text, byte[] secret) throws Exception {
        return PolicyDigest.hmac(text.getBytes(), secret);
    }
}
