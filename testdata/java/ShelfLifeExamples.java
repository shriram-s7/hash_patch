package com.example.shelflife;

import java.security.MessageDigest;

/**
 * ShelfLifeExamples.java — Pillar 2 (Shelf-Life Inference) corpus fixture.
 *
 * See docs/SHELF_LIFE.md and tests/golden/shelf_life_manifest.json.
 *
 * Three scenarios, each using a DIFFERENT digest algorithm so each crypto
 * call produces its own distinct CryptoAsset (same canonical name + same
 * file would otherwise merge multiple call sites' evidence onto one asset).
 * Unlike the Python corpus, none of these use the `call_argument` candidate
 * kind: MessageDigest.getInstance(...) (like every JCA target method in
 * rules/java_jca.yaml) takes only an algorithm-name string literal, never
 * the data itself, so for Java the signal comes from enclosing method/class
 * names and same-class field names instead — see
 * hash_patch/detect/shelf_life/data_context.py.
 *
 *   1. hashAadhaarNumber() — MessageDigest.getInstance("SHA-256") inside a
 *      method whose own name names the aadhaar category (`enclosing_function`
 *      candidate kind) -> must produce a ShelfLifeFinding, category="aadhaar".
 *
 *   2. cacheTempValue() — MessageDigest.getInstance("SHA-512"): a plain,
 *      non-sensitive-looking name, no enclosing class, no matching method
 *      name -> must produce NO ShelfLifeFinding at all.
 *
 *   3. CustomerRecord.hashRecord() — MessageDigest.getInstance("SHA3-256"):
 *      neither the method name nor the class name is crypto-suggestive, so
 *      the only signal comes from CustomerRecord's own two fields
 *      (`model_field` candidate kind, class-scoped): aadhaarNumber (aadhaar
 *      category) and accountNumber (financial_account category). Per
 *      hash_patch/analyze/shelf_life.py's longest-shelf-life-wins fail-safe
 *      rule, this must resolve to whichever of {aadhaar, financial_account}
 *      has the LONGER shelf_life_years in ontology/data_sensitivity.yaml —
 *      the test reads those actual numbers rather than assuming which one
 *      wins.
 *
 *   4. partnerFingerprint() — MessageDigest.getInstance("MD5"): a
 *      REGRESSION fixture for a confirmed false positive (found on
 *      test2/java/.../LegacyGateway.java's real partnerFingerprint()
 *      method). "Fingerprint" here is the common security-engineering
 *      sense — a short hash used to identify/verify something — with zero
 *      biometric data involved. ontology/data_sensitivity.yaml's
 *      `biometric` category previously listed a bare "fingerprint"
 *      pattern that matched this method NAME alone; it now only matches a
 *      biometric fingerprint ARTIFACT (scan/image/template/sensor), so
 *      this must produce NO ShelfLifeFinding at all.
 *
 *   5. encryptClinicalSummary() — MessageDigest.getInstance("SHA-384"): a
 *      REGRESSION fixture for a confirmed false NEGATIVE (found on
 *      test2/java/.../SensitiveStore.java's real encryptClinicalSummary()
 *      method). The only signal is the enclosing method NAME itself
 *      ("encryptClinicalSummary", an `enclosing_function` candidate)
 *      matching the health_record category's now-widened "clinical"
 *      pattern -> category "health_record".
 */
public class ShelfLifeExamples {

    public String hashAadhaarNumber(String aadhaarNumber) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(aadhaarNumber.getBytes());
        return bytesToHex(digest.digest());
    }

    public String cacheTempValue(String tempCacheValue) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(tempCacheValue.getBytes());
        return bytesToHex(digest.digest());
    }

    public String partnerFingerprint(String accountId) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        digest.update(accountId.getBytes());
        return bytesToHex(digest.digest());
    }

    public String encryptClinicalSummary(String summary) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-384");
        digest.update(summary.getBytes());
        return bytesToHex(digest.digest());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static class CustomerRecord {
        private String aadhaarNumber;
        private String accountNumber;

        public String hashRecord(String recordBytes) throws Exception {
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            digest.update(recordBytes.getBytes());
            return bytesToHexStatic(digest.digest());
        }

        private static String bytesToHexStatic(byte[] bytes) {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }
    }
}
