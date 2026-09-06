/*
 * blast_radius_reachable_chain.c — combined Pillar 3 (Blast Radius) / C
 * call-graph reachability fixture.
 *
 * Exercises the case that used to be structurally impossible before C had
 * call-graph coverage: a blast-radius finding (a fixed-size buffer sized
 * for a classical RSA signature, same-file-correlated to the RSA_sign
 * call per docs/BLAST_RADIUS.md) whose enclosing function also sits inside
 * a real, resolvable, multi-hop C call chain reachable from `main` — see
 * docs/REACHABILITY.md and hash_patch/analyze/callgraph.py.
 *
 * Call chain (3 hops): main -> sign_entry -> sign_middle -> sign_leaf.
 * `sign_leaf` is where the RSA_sign() call and its 256-byte signature
 * buffer live: an RSA-2048 signature fits classically in 256 bytes, but
 * ML-DSA-65's 3309-byte signature does not, so this MUST still fire a
 * blast-radius finding exactly like testdata/c/blast_radius_examples.c's
 * `sign_with_rsa` does — the only difference here is that `sign_leaf` is
 * now provably LIVE_EXTERNAL rather than UNKNOWN, so the UI's blast-radius
 * shockwave view has real multi-node call-graph data to intersect with,
 * not just a single isolated finding.
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>

#define RSA_SIG_BUF_LEN 256

static void sign_leaf(RSA *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char signature[RSA_SIG_BUF_LEN];
    unsigned int sig_len = 0;
    RSA_sign(0, msg, msg_len, signature, &sig_len, key);
}

static void sign_middle(RSA *key, const unsigned char *msg, unsigned int msg_len) {
    sign_leaf(key, msg, msg_len);
}

void sign_entry(RSA *key, const unsigned char *msg, unsigned int msg_len) {
    sign_middle(key, msg, msg_len);
}

int main(void) {
    sign_entry(0, 0, 0);
    return 0;
}
