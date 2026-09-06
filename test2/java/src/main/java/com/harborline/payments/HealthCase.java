package com.harborline.payments;

public record HealthCase(String patientId, String summary) {
    // Database contract: HEALTH_TOKEN is CHAR(64), sized for the current
    // compact Ed25519 signature representation.
    public static final int HEALTH_TOKEN_WIDTH = 64;
}
