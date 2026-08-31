#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>

// 1. RSA Example (EVP + Legacy) — broken-by-shor
void rsa_example(void) {
    // EVP API
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx) {
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_free(pctx);
    }

    // Legacy API
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    if (rsa && bne) {
        BN_set_word(bne, RSA_F4);
        RSA_generate_key_ex(rsa, 2048, bne, NULL);
        RSA_free(rsa);
        BN_free(bne);
    }
}

// 2. AES-256-GCM Example (EVP) — weakened-by-grover
void aes_gcm_example(const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_CIPHER_CTX_free(ctx);
    }
}

// 3. MD5 Example — broken-classically
void md5_example(const unsigned char *data, size_t len) {
    MD5_CTX ctx;
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, len);
    MD5_Final(digest, &ctx);
}

// 4. SHA-1 Example — broken-classically
void sha1_example(const unsigned char *data, size_t len) {
    SHA_CTX ctx;
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(digest, &ctx);
}

// 5. ECDSA via EC_KEY Example — broken-by-shor
void ecdsa_example(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key) {
        EC_KEY_generate_key(key);
        EC_KEY_free(key);
    }
}

// 6. 3DES Example — broken-classically
void triple_des_example(const unsigned char *in, unsigned char *out, long len) {
    DES_cblock key1, key2, key3;
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock ivec;

    DES_set_key(&key1, &ks1);
    DES_set_key(&key2, &ks2);
    DES_set_key(&key3, &ks3);
    DES_ede3_cbc_encrypt(in, out, len, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);
}

// 7. SHA-256 Example (EVP) — weakened-by-grover
void sha256_example(const unsigned char *data, size_t len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx) {
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_MD_CTX_free(mdctx);
    }
}

int main(void) {
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    unsigned char buf[64] = {0};

    rsa_example();
    aes_gcm_example(key, iv);
    md5_example(buf, sizeof(buf));
    sha1_example(buf, sizeof(buf));
    ecdsa_example();
    triple_des_example(buf, buf, sizeof(buf));
    sha256_example(buf, sizeof(buf));

    return 0;
}
