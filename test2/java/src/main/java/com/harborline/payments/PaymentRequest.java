package com.harborline.payments;

public record PaymentRequest(String accountNumber, long amount) {}
