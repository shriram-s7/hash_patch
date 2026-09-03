#include <stdio.h>
#include <string.h>

// Negative fixture: RSA, AES, MD5, SHA-1, DES appear only in comments,
// string literals, function parameters, and non-crypto struct types.
// Hash Patch must produce ZERO CryptoAssets from this file.

// RSA is a public-key cryptosystem.
// AES is an advanced encryption standard.
// MD5 is a 128-bit hash.

static const char *kRsaInfo = "RSA key size configured to 2048";
static const char *kAesInfo = "AES-256-GCM selected in config";
static const char *kMd5Info = "MD5 hash verification";

struct RSAConfig {
    char name[32];
    int key_size;
};

void print_crypto_info(const char *algo) {
    printf("Algorithm: %s\n", algo);
}

int configure_rsa(struct RSAConfig *cfg) {
    if (!cfg) return -1;
    strncpy(cfg->name, "RSA", sizeof(cfg->name));
    cfg->key_size = 2048;
    return 0;
}

int main(void) {
    struct RSAConfig config;
    configure_rsa(&config);
    print_crypto_info(kRsaInfo);
    print_crypto_info(kAesInfo);
    print_crypto_info(kMd5Info);
    return 0;
}
