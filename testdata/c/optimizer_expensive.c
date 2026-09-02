/*
 * optimizer_expensive.c — Pillar 5 (Migration Optimiser) corpus fixture.
 *
 * Five undersized signature buffers, each near its own ECDSA_sign() call
 * site in this file, all correlating (same-file, nearest-by-line, per
 * docs/BLAST_RADIUS.md) to the SAME merged "ECDSA" CryptoAsset (ECDSA_sign
 * carries no parameter_set — rules/c_openssl.yaml — so all five call
 * sites merge into one asset id, per pratyaksha/model/assets.py's
 * derive_asset_id). Each buffer produces its own BlastRadiusFinding
 * (0.5 engineer-days each, pratyaksha/analyze/blast_radius.py's flat base
 * estimate), so this asset's TOTAL blast-radius cost is 2.5 engineer-days —
 * 5x the flat no-blast-radius-data default (see
 * pratyaksha/analyze/risk_score.py::DEFAULT_COST_DAYS_NO_BLAST_RADIUS) —
 * deliberately EXPENSIVE. Go and C get no P1/P2 data (see
 * docs/REACHABILITY.md / docs/SHELF_LIFE.md), so this asset's reachability
 * stays UNKNOWN and its shelf-life stays the documented default — real,
 * but modest, risk, at a genuinely elevated cost.
 *
 * Five buffers (not three) specifically so this finding's risk-density
 * (1.5 risk / 2.5 cost = 0.6) drops BELOW even the discounted density of
 * testdata/python/optimizer_examples.py's three `credentials` findings
 * (0.35 discounted risk / 0.5 cost = 0.7) under EVERY quantum-arrival
 * scenario (ontology/quantum_arrival.yaml) — without that, a naive
 * risk-only ranking would never actually prefer this finding over those
 * three (its raw risk, 1.5, is still higher than any one of theirs, 1.0
 * each, so a naive ranking DOES try this one first) while a risk-density
 * ranking prefers the three smaller ones instead. That mismatch is what
 * makes the naive baseline provably waste budget here, in BOTH the plain
 * (scenario-independent) and the scenario-adjusted comparison. See
 * docs/OPTIMISER.md's worked "naive wastes budget on the expensive
 * finding" example.
 */

#include <openssl/ec.h>
#include <openssl/ecdsa.h>

void sign_record_a(EC_KEY *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char ecdsa_signature_buf_a[72];
    unsigned int sig_len = 0;
    ECDSA_sign(0, msg, msg_len, ecdsa_signature_buf_a, &sig_len, key);
}

void sign_record_b(EC_KEY *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char ecdsa_signature_buf_b[72];
    unsigned int sig_len = 0;
    ECDSA_sign(0, msg, msg_len, ecdsa_signature_buf_b, &sig_len, key);
}

void sign_record_c(EC_KEY *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char ecdsa_signature_buf_c[72];
    unsigned int sig_len = 0;
    ECDSA_sign(0, msg, msg_len, ecdsa_signature_buf_c, &sig_len, key);
}

void sign_record_d(EC_KEY *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char ecdsa_signature_buf_d[72];
    unsigned int sig_len = 0;
    ECDSA_sign(0, msg, msg_len, ecdsa_signature_buf_d, &sig_len, key);
}

void sign_record_e(EC_KEY *key, const unsigned char *msg, unsigned int msg_len) {
    unsigned char ecdsa_signature_buf_e[72];
    unsigned int sig_len = 0;
    ECDSA_sign(0, msg, msg_len, ecdsa_signature_buf_e, &sig_len, key);
}
