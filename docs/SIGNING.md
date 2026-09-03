# Post-Quantum Report Signing (Pillar 6)

Hash Patch's sixth pillar provides **tamper-evident post-quantum signing**
for emitted Cryptography Bill of Materials (CBOM) reports using **ML-DSA-65
(FIPS 204)**.

The report about quantum readiness is itself signed with the very post-quantum
cryptography it recommends. If an attacker or unauthorized party attempts
to modify findings, downgrade quantum risk classifications, or alter asset
inventories in an emitted CBOM, the post-quantum signature verification will
immediately fail.

---

## 1. Cryptographic Backend

### Live Backend in this Codebase: Native ML-DSA-65 (FIPS 204)
- **Library**: `pyca/cryptography` (module `cryptography.hazmat.primitives.asymmetric.mldsa`)
- **Algorithm**: `ML-DSA-65` (Module-Lattice-Based Digital Signature Standard, parameter set 65)
- **Standard**: NIST FIPS 204 (August 2024)
- **Key sizes & characteristics**:
  - Public key size: 1,952 bytes (SubjectPublicKeyInfo PEM or raw bytes)
  - Private key size: 4,032 bytes expanded / 32 bytes seed (PKCS#8 PEM)
  - Signature size: 3,309 bytes (base64-encoded in detached signature file)
  - NIST Security Category: Level 3 (equivalent to AES-192 security against classical/quantum attacks)

### Why this backend was chosen over `liboqs-python`
During investigation (Step 1), `liboqs-python` was evaluated. Although a pure-Python
wheel downloads from PyPI, `import oqs` triggers an automatic runtime build script
that attempts to clone the upstream `liboqs` C repository from GitHub and build
it using CMake and a C compiler toolchain in `C:\Users\<user>\_oqs`.

This violated Hash Patch's non-negotiable constraints:
1. **Offline execution**: No network calls at scan or execution time.
2. **Deterministic, dependency-free environment**: Dev and CI environments on Windows
   should not require external C build toolchains for Python CLI usage.

In contrast, `pyca/cryptography>=50.0.0` provides pre-compiled, statically-linked
binary wheels for Windows (x86_64, ARM64) and Linux/macOS with first-class, official
FIPS 204 `mldsa` classes (`MLDSA65PrivateKey` and `MLDSA65PublicKey`). It executes
completely offline, requires no compilation, and conforms strictly to the NIST standard.

---

## 2. Key Management & Custody Caveat

### Honesty Disclaimer: Demonstration Key Scheme
`hash-patch keygen` generates local, unencrypted PEM files (`hash-patch_signing.key`
and `hash-patch_signing.pub`) on the local filesystem.

> [!WARNING]
> **This is a DEMONSTRATION key management scheme.**
> It lacks:
> - Hardware Security Module (HSM) or secure enclave backing
> - Access control and audit logging
> - Key rotation and expiration policies
> - Certificate authority (PKI) chaining or revocation mechanisms
>
> In a production NTRO / enterprise deployment, private keys must be held in an
> accredited HSM (e.g. FIPS 140-3 Level 3+ with PQC algorithm support) or a
> cloud KMS with post-quantum signing capabilities. Local unencrypted private
> key files are suitable only for demonstration, local development, and offline testing.

---

## 3. CLI Usage

Three subcommands operate on files, matching the pattern established by `scan`
and `optimize`:

### 1. Key Generation: `keygen`
Generate a new ML-DSA-65 keypair:

```bash
hash-patch keygen --output-dir ./keys
```

Outputs:
- `./keys/hash-patch_signing.key` (PKCS#8 PEM private key)
- `./keys/hash-patch_signing.pub` (SubjectPublicKeyInfo PEM public key)

### 2. Sign CBOM: `sign`
Sign an already-emitted CBOM file to produce a detached signature file:

```bash
hash-patch sign my_report.cbom.json --key ./keys/hash-patch_signing.key --output my_report.cbom.json.sig
```

- Operates directly on the **literal file bytes on disk** (not an in-memory re-serialized dict).
- Default output path if omitted: `<input>.sig` (e.g. `my_report.cbom.json.sig`).

### 3. Verify CBOM: `verify`
Verify an already-emitted CBOM file against a detached signature file and public key:

```bash
hash-patch verify my_report.cbom.json --sig my_report.cbom.json.sig --key ./keys/hash-patch_signing.pub
```

Exit codes:
- `0`: Signature is **VALID**.
- `1`: Signature is **INVALID** (document was tampered with, or wrong public key was provided).
- `2`: **ERROR** (missing files, malformed signature JSON, or unreadable key).

---

## 4. Detached Signature File Format

The detached signature is a small, human-readable, schema-versioned JSON file:

```json
{
  "$schema": "https://hash_patch.dev/schemas/signature-v1.json",
  "spec_version": "1.0",
  "algorithm": "ML-DSA-65",
  "standard": "FIPS 204",
  "file_name": "my_report.cbom.json",
  "file_sha256": "4a5e3b9f...",
  "public_key_fingerprint": "8d7f2a1c...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "signature": "base64-encoded-3309-bytes-mldsa65-signature...",
  "signed_at": "2026-09-02T04:45:00.000000+00:00"
}
```

### Field Definitions:
- `algorithm`: Identifier of the signature algorithm (`ML-DSA-65`).
- `standard`: Underlying standard specification (`FIPS 204`).
- `file_name`: Original name of the signed CBOM file.
- `file_sha256`: Hexadecimal SHA-256 digest of the exact file bytes at time of signing. Used as an immediate pre-check for document tampering.
- `public_key_fingerprint`: SHA-256 digest of the SubjectPublicKeyInfo DER bytes.
- `public_key_pem`: Full PEM representation of the signer's public key.
- `signature`: Base64-encoded raw signature bytes (3,309 bytes for ML-DSA-65).
- `signed_at`: ISO-8601 UTC timestamp of signature creation.

---

## 5. Tamper-Detection Guarantee

### What a `VALID` Verification Proves
1. **Document Integrity**: The CBOM file bytes on disk are bit-for-bit identical
   to the bytes when the signature was created. Any alteration—including changing
   a single character, deleting a finding, altering whitespace, or re-ordering keys—will
   cause verification to fail.
2. **Authenticity**: The signature was generated by someone possessing the private key
   corresponding to the supplied ML-DSA-65 public key.
3. **Post-Quantum Assurance**: The signature scheme itself (ML-DSA-65) cannot be forged
   by Shor's algorithm running on a Cryptanalytically Relevant Quantum Computer (CRQC).

### What a `VALID` Verification Does NOT Prove
1. **Accuracy of Findings**: Signing does not prove that the scanner detected every
   cryptographic asset in the codebase, nor that its reachability, shelf-life, or
   blast-radius estimates are objectively correct.
2. **Codebase Security**: An untampered CBOM report stating that all findings are
   `BROKEN_BY_SHOR` does not mean the system is secure; it only means the report
   faithfully documents what Hash Patch discovered.
3. **Key Ownership / Identity**: Without an external PKI or trust root, the signature
   proves custody of the keypair, but does not prove who generated the keypair.

---

## 6. Determinism & Randomized Hedging in FIPS 204

FIPS 204 defines two signing variants:
- **Deterministic ML-DSA**: Re-generates pseudorandom values deterministically from the private key and message.
- **Randomized (Hedged) ML-DSA (Algorithm 7)**: Incorporates an additional 32-byte fresh random seed into the signing process.

`pyca/cryptography` implements **randomized (hedged) signing** by default. This is
the NIST-recommended mode because it protects against side-channel analysis and
fault-injection attacks (e.g. differential power analysis).

**Implication for Hash Patch**:
Signing the exact same CBOM file twice with the same ML-DSA-65 key produces two distinct,
valid signatures. Both signatures independently verify as `VALID` against the public key,
and both share identical `file_sha256`, `algorithm`, and `public_key_fingerprint` fields.
Hash Patch's test suite explicitly verifies this structural validity and independent
verification rather than asserting byte-identical signature blobs.
