package com.adversarial.tls;

public final class PartnerTlsProfile {
    public String protocol() { return "TLSv1.2"; }
    public String suite() { return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"; }

    // This comment is deliberately noisy:
    // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 would also be seen in old documentation.
    // RSA below refers to the authentication certificate, not the bulk cipher.
    public String certificateFamily() { return "RSA"; }
}
