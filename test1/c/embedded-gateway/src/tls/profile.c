#include <stddef.h>

const char *tls_profile(void) {
    return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
}

const char *certificate_key_family(void) {
    return "RSA";
}

/* The RSA certificate family is not the same thing as the AES transport cipher. */
