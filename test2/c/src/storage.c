#include <openssl/evp.h>
#include <string.h>

/* Database contract: PAN_WRAPPED is CHAR(64), sized for the current AES-GCM
   envelope representation. A larger post-quantum encapsulation must not be
   silently truncated into this column. */

int store_pan(const unsigned char *pan, unsigned long len,
              char db_value[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[32];
    unsigned int n = 0;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, pan, len);
    EVP_DigestFinal_ex(ctx, digest, &n);
    memcpy(db_value, digest, 32);
    EVP_MD_CTX_free(ctx);
    return 1;
}
