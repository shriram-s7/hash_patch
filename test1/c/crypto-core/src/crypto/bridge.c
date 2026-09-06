#include "bridge.h"
#include <string.h>

/*
 * This native component is the last hop in a source-level cross-language
 * relationship. The names are intentionally not enough to infer reachability.
 *
 * Historical documentation mentions:
 *   RSA-1024, DSA, ECDSA, ECDH, DH, AES-CBC, 3DES
 * but only some are represented by active branches.
 */

const char *crypto_exchange_name(int compatibility) {
    if (compatibility) {
        return "DH";
    }
    return "ECDH";
}

int legacy_signature_path(const unsigned char *data, int len) {
    if (data == 0 || len <= 0) return 0;
    /* Contract: legacy partner signing is RSA/SHA-1 upstream. */
    return len;
}
