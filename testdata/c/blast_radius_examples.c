/*
 * blast_radius_examples.c — Pillar 3 (Blast Radius) corpus fixture.
 *
 * Each function below pairs a fixed-size buffer with a nearby OpenSSL call
 * in the SAME file — blast-radius correlation is same-file only, see
 * docs/BLAST_RADIUS.md. Expected outcomes are recorded in
 * tests/golden/blast_radius_manifest.json.
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdlib.h>

#define RSA_SIG_BUF_LEN 256

/* (1) MUST FIRE: an RSA-2048 signature fits classically in 256 bytes, but
 * ML-DSA-65's 3309-byte signature does not. Also exercises one level of
 * #define resolution (RSA_SIG_BUF_LEN). */
void sign_with_rsa(RSA *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char signature[RSA_SIG_BUF_LEN];
    unsigned int sig_len = 0;
    RSA_sign(0, msg, msg_len, signature, &sig_len, key);
}

/* (2) MUST FIRE: Ed25519's 32-byte public key fits classically, but
 * ML-DSA-65's 1952-byte public key does not. (Ed25519's primitive is
 * "signature" in rules/c_openssl.yaml, so blast_radius.py compares it
 * against the ML-DSA family, not ML-KEM — see docs/BLAST_RADIUS.md for why.) */
void generate_ed25519_keypair(void) {
    unsigned char pubkey[32];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
}

/* (3) MUST NOT FIRE: already generously sized — even ML-DSA-65's largest
 * relevant field here (the 3309-byte signature) fits inside 8192 bytes. */
void sign_with_rsa_generous_buffer(RSA *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char rsa_signature_buf[8192];
    unsigned int sig_len = 0;
    RSA_sign(0, msg, msg_len, rsa_signature_buf, &sig_len, key);
}

/* (4) MUST be silently skipped, not guessed: UNRESOLVED_SIG_LEN is not
 * #define'd anywhere in this file (imagine it coming from an external
 * header hash_patch never sees), so its size cannot be resolved — no
 * SizeConstraint is emitted for it at all. */
void sign_with_unresolved_buffer(RSA *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char sig_buffer[UNRESOLVED_SIG_LEN];
    unsigned int sig_len = 0;
    RSA_sign(0, msg, msg_len, sig_buffer, &sig_len, key);
}
