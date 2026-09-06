#include <openssl/evp.h>

int reconcile_old_terminal(const unsigned char *data, int len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[32];
    unsigned int n = 0;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &n);
    EVP_MD_CTX_free(ctx);
    return (int)n;
}
