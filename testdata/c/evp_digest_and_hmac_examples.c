/*
 * evp_digest_and_hmac_examples.c — Positive fixture for two items checked
 * in the post-hashlib-fix audit (see docs/COVERAGE.md):
 *
 * (1) EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) — the modern OpenSSL 3.0
 *     generic digest API. This ALREADY worked before this fixture was
 *     added (EVP_sha256() is matched independently, regardless of its
 *     enclosing call) — this fixture locks that behavior in with a
 *     regression test rather than leaving it merely incidental.
 * (2) HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL) — a genuine gap:
 *     rules/c_openssl.yaml had zero HMAC coverage. Must now ALSO produce
 *     an HMAC finding, additive to the SHA-256 finding EVP_sha256() itself
 *     produces.
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>

/* (1) EVP_DigestInit_ex with the modern EVP_MD selector API. */
void digest_example(const unsigned char *data, size_t len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    unsigned char out[32];
    unsigned int outlen;
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

/* (2) HMAC_Init_ex — MAC construction, additive to the EVP_sha256() hash
 * finding its own selector argument produces. */
void hmac_example(const unsigned char *key, int keylen, const unsigned char *data, size_t len) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL);
    HMAC_Update(ctx, data, len);
    unsigned char out[32];
    unsigned int outlen;
    HMAC_Final(ctx, out, &outlen);
    HMAC_CTX_free(ctx);
}
