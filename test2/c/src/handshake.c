#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/ec.h>

int derive_session(EVP_PKEY_CTX **ctx) {
    EVP_PKEY *params = EVP_PKEY_Q_keygen(NULL, "DH", 2048);
    *ctx = EVP_PKEY_CTX_new(params, NULL);
    return *ctx != NULL;
}

int derive_ecdh(EVP_PKEY_CTX **ctx) {
    EVP_PKEY *key = EVP_EC_gen("prime256v1");
    *ctx = EVP_PKEY_CTX_new(key, NULL);
    return *ctx != NULL;
}
