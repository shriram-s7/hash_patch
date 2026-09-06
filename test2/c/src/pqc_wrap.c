#include <openssl/evp.h>
#include <string.h>

int wrap_key_pqc(unsigned char *ciphertext, size_t *ct_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!ctx) return 0;
    if (EVP_PKEY_keygen_init(ctx) <= 0) return 0;
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_generate(ctx, &key) <= 0) return 0;

    EVP_PKEY_CTX *enc = EVP_PKEY_CTX_new(key, NULL);
    unsigned char shared_secret[32];
    size_t secret_len = sizeof(shared_secret);
    if (EVP_PKEY_encapsulate_init(enc, NULL) <= 0) return 0;
    if (EVP_PKEY_encapsulate(enc, ciphertext, ct_len,
                             shared_secret, &secret_len) <= 0) return 0;
    return 1;
}
