package com.example.datachain;

import java.security.MessageDigest;

/**
 * Negative fixture for hash_patch/analyze/data_chain.py: two independent
 * hash operations in the same method, each over its own unrelated input —
 * no data flows from one into the other, so no same_function_data_chain
 * edge must be created between them. Deliberately uses two differently
 * named source byte arrays (userRecord / auditLogEntry) so there is no
 * coincidental variable-name reuse that could produce a false edge.
 */
public class NegativeUnrelatedHashes {

    public static void run() throws Exception {
        byte[] userRecord = "alice@example.com".getBytes();
        byte[] auditLogEntry = "2026-09-07T00:00:00Z login".getBytes();

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] userRecordHash = sha256.digest(userRecord);

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
        byte[] auditLogHash = sha3.digest(auditLogEntry);

        System.out.println(userRecordHash.length + auditLogHash.length);
    }
}
