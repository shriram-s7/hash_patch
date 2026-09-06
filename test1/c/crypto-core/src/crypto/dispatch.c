#include "bridge.h"
#include <stddef.h>

static const char *modern = "ECDH";
static const char *legacy = "DH";
static const char *signature = "SHA256withRSA";

const char *dispatch_exchange(int compatibility) {
    return compatibility ? legacy : modern;
}

const char *dispatch_signature(void) {
    return signature;
}

void unused_crypto_catalog(void) {
    const char *rsa = "RSA";
    const char *dsa = "DSA";
    const char *ecdsa = "ECDSA";
    const char *sha1 = "SHA-1";
    (void)rsa; (void)dsa; (void)ecdsa; (void)sha1;
}
