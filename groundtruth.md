# Ground Truth — Harborline Logistics crypto-discovery corpus

**Placement:** `groundtruth.md` belongs in the **parent directory**, next to `crypto_discovery_corpus/`, not inside the corpus. Do not scan this file with the corpus.

## Corpus profile
- Fictional company: Harborline Logistics, a mid-size freight/dispatch platform.
- Source files: 41 across exactly four programming languages: Python, Java, Go, C.
- Fixture: `c/tests/fixtures/algorithm_names.txt` is data, not a fifth programming language.

## Verification method
1. Count executable cryptographic construction, initialization, derivation, hashing, signing, encryption/decryption, encapsulation, and certificate parsing as operations.
2. Count constants, maps, returned labels, comments, and fixture strings as references unless executable crypto code consumes them.
3. Resolve direct calls, multi-hop call chains, constants/maps, runtime branches, and assigned callable references from the final source.
4. Mark environment/configuration/reflection/dynamic-loader choices genuinely unresolvable when the exact implementation cannot be known statically.
5. Re-checked every operation line against the final generated files after the final patches.

## Quantum classification
- **Shor-broken:** RSA, ECDSA, ECDH, DH, DSA, Ed25519.
- **Classically-broken:** MD5, SHA-1, DES, 3DES.
- **Grover-weakened:** AES and SHA-256/HMAC-SHA256/PBKDF2-HMAC-SHA256.
- **Safe:** ML-KEM-768 and X.509 certificate parsing itself; this is only the requested quantum-vulnerability category.

## Genuine crypto operations
| # | Language | File:line | Operation / algorithm | Quantum category | Reachability | Call chain / resolution |
|---:|---|---|---|---|---|---|
| 1 | Python | `python/freight_api/signing.py:7` | Ed25519 private-key loading | **Shor-broken** | **live-reachable** | /deliveries/token → delivery_token → issue_delivery_token → _load_signer |
| 2 | Python | `python/freight_api/signing.py:13` | Ed25519 signing | **Shor-broken** | **live-reachable** | /deliveries/token → delivery_token → issue_delivery_token → _sign_payload → signer.sign |
| 3 | Python | `python/freight_api/customer_crypto.py:8` | PBKDF2-HMAC-SHA256 | **Grover-weakened** | **live-reachable** | /customers/pan → customer_pan → protect_pan |
| 4 | Python | `python/freight_api/customer_crypto.py:9` | PBKDF2-HMAC-SHA256 key derivation | **Grover-weakened** | **live-reachable** | /customers/pan → customer_pan → protect_pan → kdf.derive |
| 5 | Python | `python/freight_api/customer_crypto.py:10` | AES-GCM construction | **Grover-weakened** | **live-reachable** | /customers/pan → customer_pan → protect_pan |
| 6 | Python | `python/freight_api/customer_crypto.py:11` | AES-GCM encryption | **Grover-weakened** | **live-reachable** | /customers/pan → customer_pan → protect_pan → encryptor.update |
| 7 | Python | `python/freight_api/customer_crypto.py:14` | PBKDF2-HMAC-SHA256 | **Grover-weakened** | **live-reachable** | /health/note → health_note → protect_health_note → derive_operator_key |
| 8 | Python | `python/freight_api/customer_crypto.py:16` | PBKDF2-HMAC-SHA256 key derivation | **Grover-weakened** | **live-reachable** | /health/note → health_note → protect_health_note → derive_operator_key → kdf.derive |
| 9 | Python | `python/freight_api/customer_crypto.py:20` | AES-CBC construction | **Grover-weakened** | **live-reachable** | protect_health_note |
| 10 | Python | `python/freight_api/customer_crypto.py:21` | AES-CBC encryption | **Grover-weakened** | **live-reachable** | /health/note → health_note → protect_health_note → encryptor.update |
| 11 | Python | `python/freight_api/crypto_policy.py:15` | RSA-1024 key generation | **Shor-broken** | **dead-unreachable** | make_key('parcel') has no caller in the corpus |
| 12 | Python | `python/freight_api/crypto_policy.py:17` | ECDH P-256 private-key generation | **Shor-broken** | **live-reachable-by-function-call** | prepare_driver_channel → make_key('session') → ECDH branch |
| 13 | Python | `python/freight_api/crypto_policy.py:19` | DSA-2048 private-key generation | **Shor-broken** | **live-reachable-by-function-call** | prepare_vendor_channel → make_key('vendor') → DSA branch |
| 14 | Python | `python/freight_api/crypto_policy.py:20` | DH parameter generation | **Shor-broken** | **dead-unreachable** | make_key with an unlisted kind has no caller in the corpus |
| 15 | Python | `python/freight_api/crypto_policy.py:24` | SHA-1 or SHA-256 algorithm instantiation | **Classically-broken or Grover-weakened** | **live-reachable** | /manifest/digest → manifest → prepare_manifest → manifest_digest; request parameter selects branch |
| 16 | Python | `python/freight_api/crypto_policy.py:26` | SHA-1 or SHA-256 hash construction | **Classically-broken or Grover-weakened** | **live-reachable** | same branch-dependent chain |
| 17 | Python | `python/freight_api/crypto_policy.py:27` | SHA-1 or SHA-256 hashing | **Classically-broken or Grover-weakened** | **live-reachable** | same chain → Hash.update |
| 18 | Python | `python/freight_api/crypto_policy.py:28` | SHA-1 or SHA-256 hashing | **Classically-broken or Grover-weakened** | **live-reachable** | same chain → Hash.finalize |
| 19 | Python | `python/freight_api/legacy_import.py:5` | MD5 | **Classically-broken** | **live-reachable-by-function-call** | import_partner_digest |
| 20 | Python | `python/freight_api/legacy_import.py:8` | SHA-1 | **Classically-broken** | **live-reachable-by-function-call** | verify_old_manifest |
| 21 | Python | `python/freight_api/legacy_import.py:11` | 3DES-CBC | **Classically-broken** | **live-reachable-by-function-call** | decrypt_archive |
| 22 | Python | `python/freight_api/pq_client.py:5` | ML-KEM-768 KEM object | **Safe** | **live-reachable** | audit_case → archive_health_record → wrap_health_record → _build_kem |
| 23 | Python | `python/freight_api/pq_client.py:8` | ML-KEM-768 encapsulation | **Safe** | **live-reachable** | audit_case → archive_health_record → wrap_health_record → _encapsulate → kem.encap_secret |
| 24 | Python | `python/freight_api/records.py:8` | SHA-256 | **Grover-weakened** | **dead-unreachable** | local_audit_digest has no caller |
| 25 | Python | `python/freight_api/runtime_crypto.py:8` | AES-GCM | **Grover-weakened** | **genuinely-unresolvable** | /runtime/encrypt → runtime_encrypt → encrypt_runtime; mode/key material comes from runtime environment JSON |
| 26 | Python | `python/freight_api/runtime_crypto.py:9` | AES-CBC | **Grover-weakened** | **genuinely-unresolvable** | same runtime path; exact branch depends on external configuration |
| 27 | Java | `java/src/main/java/com/harborline/payments/PaymentSigner.java:24` | SHA256withECDSA / Ed25519 Signature object | **Shor-broken** | **live-reachable** | PaymentController.submit → submitSigned → sign/signLegacy → signBody |
| 28 | Java | `java/src/main/java/com/harborline/payments/PaymentSigner.java:25` | EC or Ed25519 key-generator selection | **Shor-broken** | **live-reachable** | same chain; ternary selects generator family |
| 29 | Java | `java/src/main/java/com/harborline/payments/PaymentSigner.java:28` | Ed25519 signing initialization | **Shor-broken** | **live-reachable** | submitSigned(..., true) → signLegacy → signBody |
| 30 | Java | `java/src/main/java/com/harborline/payments/PaymentSigner.java:31` | ECDSA signing initialization | **Shor-broken** | **live-reachable** | submitSigned(..., false) → sign → signBody |
| 31 | Java | `java/src/main/java/com/harborline/payments/PaymentSigner.java:34` | ECDSA or Ed25519 signature generation | **Shor-broken** | **live-reachable** | same per-call-site branch → s.sign |
| 32 | Java | `java/src/main/java/com/harborline/payments/LegacyGateway.java:9` | MD5 | **Classically-broken** | **live-reachable-by-function-call** | partnerFingerprint |
| 33 | Java | `java/src/main/java/com/harborline/payments/LegacyGateway.java:14` | 3DES-CBC | **Classically-broken** | **live-reachable-by-function-call** | oldPayload |
| 34 | Java | `java/src/main/java/com/harborline/payments/PolicyDigest.java:9` | SHA-1 | **Classically-broken** | **live-reachable-by-function-call** | fingerprint |
| 35 | Java | `java/src/main/java/com/harborline/payments/PolicyDigest.java:13` | HMAC-SHA256 construction | **Grover-weakened** | **live-reachable-by-function-call** | SettlementJob.audit → PolicyDigest.hmac |
| 36 | Java | `java/src/main/java/com/harborline/payments/PolicyDigest.java:15` | HMAC-SHA256 | **Grover-weakened** | **live-reachable-by-function-call** | SettlementJob.audit → PolicyDigest.hmac → mac.doFinal |
| 37 | Java | `java/src/main/java/com/harborline/payments/SensitiveStore.java:11` | AES-GCM construction | **Grover-weakened** | **live-reachable** | PaymentController.exportHealthCase → encryptClinicalSummary |
| 38 | Java | `java/src/main/java/com/harborline/payments/SensitiveStore.java:14` | AES-GCM encryption | **Grover-weakened** | **live-reachable** | same chain → cipher.doFinal |
| 39 | Java | `java/src/main/java/com/harborline/payments/SensitiveStore.java:22` | Ed25519 Signature object | **Shor-broken** | **dead-unreachable** | compactSignature has no caller |
| 40 | Java | `java/src/main/java/com/harborline/payments/SensitiveStore.java:23` | Ed25519 key generation | **Shor-broken** | **dead-unreachable** | compactSignature has no caller |
| 41 | Java | `java/src/main/java/com/harborline/payments/SensitiveStore.java:26` | Ed25519 signing | **Shor-broken** | **dead-unreachable** | compactSignature has no caller |
| 42 | Java | `java/src/main/java/com/harborline/payments/SessionAgreement.java:9` | DH key-generator construction | **Shor-broken** | **live-reachable-by-function-call** | establishDh |
| 43 | Java | `java/src/main/java/com/harborline/payments/SessionAgreement.java:12` | DH key agreement | **Shor-broken** | **live-reachable-by-function-call** | establishDh → generateSecret |
| 44 | Java | `java/src/main/java/com/harborline/payments/SessionAgreement.java:18` | EC key-generator construction | **Shor-broken** | **live-reachable-by-function-call** | deriveEcdh |
| 45 | Java | `java/src/main/java/com/harborline/payments/SessionAgreement.java:21` | ECDH key agreement | **Shor-broken** | **live-reachable-by-function-call** | deriveEcdh → generateSecret |
| 46 | Java | `java/src/main/java/com/harborline/payments/SessionAgreement.java:23` | ECDH shared-secret derivation | **Shor-broken** | **live-reachable-by-function-call** | deriveEcdh → a.generateSecret |
| 47 | Java | `java/src/main/java/com/harborline/payments/RuntimeProvider.java:8` | Runtime-selected signing implementation | **Unresolved** | **genuinely-unresolvable** | PaymentController.runtimeSignature → RuntimeProvider.sign → environment value → Class.forName → implementation |
| 48 | Go | `go/internal/tokens/issue.go:8` | Ed25519 key construction | **Shor-broken** | **live-reachable** | main → /token → Issue |
| 49 | Go | `go/internal/tokens/issue.go:16` | Ed25519 signing | **Shor-broken** | **live-reachable** | main → /token → Issue → buildDeliverySignature → ed25519.Sign |
| 50 | Go | `go/internal/customer/account.go:10` | SHA-256 | **Grover-weakened** | **live-reachable** | main → /account → StoreAccount |
| 51 | Go | `go/internal/customer/account.go:11` | AES key/cipher construction | **Grover-weakened** | **live-reachable** | main → /account → StoreAccount |
| 52 | Go | `go/internal/customer/account.go:13` | AES-GCM encryption | **Grover-weakened** | **live-reachable** | main → /account → StoreAccount → gcm.Seal |
| 53 | Go | `go/internal/customer/account.go:17` | SHA-256 | **Grover-weakened** | **live-reachable-by-function-call** | StoreHealthSummary |
| 54 | Go | `go/internal/customer/account.go:18` | AES key/cipher construction | **Grover-weakened** | **live-reachable-by-function-call** | StoreHealthSummary |
| 55 | Go | `go/internal/customer/account.go:20` | AES-GCM encryption | **Grover-weakened** | **live-reachable-by-function-call** | StoreHealthSummary → gcm.Seal |
| 56 | Go | `go/internal/customer/account.go:24` | SHA-256 | **Grover-weakened** | **live-reachable-by-function-call** | clinicalDigest |
| 57 | Go | `go/internal/keys/agreement.go:6` | ECDH P-256 key generation | **Shor-broken** | **live-reachable-by-function-call** | negotiate |
| 58 | Go | `go/internal/keys/agreement.go:7` | ECDH P-256 key generation | **Shor-broken** | **live-reachable-by-function-call** | negotiate |
| 59 | Go | `go/internal/keys/agreement.go:8` | ECDH shared-secret derivation | **Shor-broken** | **live-reachable-by-function-call** | negotiate → private.ECDH |
| 60 | Go | `go/internal/keys/classical.go:11` | RSA-1024 key generation | **Shor-broken** | **live-reachable-by-function-call** | issueLegacyRSA |
| 61 | Go | `go/internal/keys/classical.go:20` | RSA-2048 key generation | **Shor-broken** | **dead-unreachable** | deadProvisioner has no caller |
| 62 | Go | `go/internal/transport/transport.go:22` | AES key construction via runtime-selected map entry | **Grover-weakened** | **live-reachable** | /parcel or /note → Protect* → protect → encrypt; mode selects map entry |
| 63 | Go | `go/internal/transport/transport.go:25` | AES-GCM encryption | **Grover-weakened** | **live-reachable** | /parcel → ProtectParcel → protect → encrypt |
| 64 | Go | `go/internal/transport/transport.go:27` | AES-CBC operation | **Grover-weakened** | **live-reachable** | /note → ProtectArchivedNote → protect → encrypt → blockModeCBC |
| 65 | Go | `go/internal/transport/transport.go:31` | SHA-1 | **Classically-broken** | **live-reachable-by-function-call** | legacyDigest |
| 66 | Go | `go/internal/crypto/runtime.go:12` | AES cipher construction | **Grover-weakened** | **genuinely-unresolvable** | EncryptFromEnvironment obtains mode/key from environment; exact cryptographic mode is runtime-dependent |
| 67 | Go | `go/internal/crypto/runtime.go:15` | AES-GCM encryption | **Grover-weakened** | **genuinely-unresolvable** | same environment-dependent path |
| 68 | Go | `go/internal/crypto/runtime.go:17` | AES-CBC cipher construction | **Grover-weakened** | **genuinely-unresolvable** | same environment-dependent path |
| 69 | C | `c/src/custody.c:8` | AES-256-GCM initialization | **Grover-weakened** | **live-reachable** | main → seal_biometric → initialize_aes |
| 70 | C | `c/src/custody.c:14` | AES-256-GCM encryption | **Grover-weakened** | **live-reachable** | main → seal_biometric → encrypt_payload |
| 71 | C | `c/src/custody.c:26` | Ed25519 signing initialization | **Shor-broken** | **live-reachable** | main → seal_biometric → sign_terminal_receipt |
| 72 | C | `c/src/custody.c:27` | Ed25519 signing | **Shor-broken** | **live-reachable** | main → seal_biometric → sign_terminal_receipt → EVP_DigestSign |
| 73 | C | `c/src/custody.c:41` | AES-256-GCM finalization | **Grover-weakened** | **live-reachable** | main → seal_biometric → EVP_EncryptFinal_ex |
| 74 | C | `c/src/custody.c:54` | HMAC-SHA256 | **Grover-weakened** | **live-reachable-by-function-call** | protect_account_hmac |
| 75 | C | `c/src/certificates.c:6` | X.509 certificate parsing | **Safe** | **live-reachable-by-function-call** | inspect_partner_certificate |
| 76 | C | `c/src/legacy.c:7` | MD5 | **Classically-broken** | **live-reachable-by-function-call** | legacy_fingerprint |
| 77 | C | `c/src/legacy.c:13` | DES key setup | **Classically-broken** | **live-reachable-by-function-call** | legacy_encrypt |
| 78 | C | `c/src/legacy.c:16` | DES encryption | **Classically-broken** | **live-reachable-by-function-call** | legacy_encrypt → DES_ecb_encrypt |
| 79 | C | `c/src/handshake.c:6` | DH-2048 key generation | **Shor-broken** | **live-reachable-by-function-call** | derive_session |
| 80 | C | `c/src/handshake.c:12` | ECDH P-256 key generation | **Shor-broken** | **live-reachable-by-function-call** | derive_ecdh |
| 81 | C | `c/src/pqc_wrap.c:5` | ML-KEM-768 context construction | **Safe** | **live-reachable-by-function-call** | wrap_key_pqc |
| 82 | C | `c/src/pqc_wrap.c:7` | ML-KEM-768 key-generation initialization | **Safe** | **live-reachable-by-function-call** | wrap_key_pqc |
| 83 | C | `c/src/pqc_wrap.c:9` | ML-KEM-768 key generation | **Safe** | **live-reachable-by-function-call** | wrap_key_pqc |
| 84 | C | `c/src/pqc_wrap.c:12` | ML-KEM-768 encapsulation initialization | **Safe** | **live-reachable-by-function-call** | wrap_key_pqc |
| 85 | C | `c/src/pqc_wrap.c:13` | ML-KEM-768 encapsulation | **Safe** | **live-reachable-by-function-call** | wrap_key_pqc |
| 86 | C | `c/src/storage.c:13` | SHA-256 initialization | **Grover-weakened** | **live-reachable-by-function-call** | store_pan |
| 87 | C | `c/src/storage.c:14` | SHA-256 hashing | **Grover-weakened** | **live-reachable-by-function-call** | store_pan |
| 88 | C | `c/src/storage.c:15` | SHA-256 finalization | **Grover-weakened** | **live-reachable-by-function-call** | store_pan |
| 89 | C | `c/src/dead_code.c:7` | SHA-1 initialization | **Classically-broken** | **dead-unreachable** | reconcile_old_terminal has no caller |
| 90 | C | `c/src/dead_code.c:8` | SHA-1 hashing | **Classically-broken** | **dead-unreachable** | reconcile_old_terminal has no caller |
| 91 | C | `c/src/dead_code.c:9` | SHA-1 finalization | **Classically-broken** | **dead-unreachable** | reconcile_old_terminal has no caller |

**Operation-site count: 91.**

## Fixed-buffer / blast-radius ground truth
| Language/context | Location | Finding |
|---|---|---|
| Python | `python/freight_api/signing.py:19` | `bytearray(64)` holds an Ed25519 signature; a larger PQ signature would not fit. |
| Java | `java/src/main/java/com/harborline/payments/SensitiveStore.java:20-28` | `new byte[64]` holds an Ed25519 signature; a larger PQ signature would not fit. |
| Go | `go/internal/tokens/issue.go:19-21` | `var wire [64]byte` stores the Ed25519 signature; the adjacent DB contract is CHAR(64). |
| C | `c/src/custody.c:18-27 and :44-45` | `out[64]` / `receipt[64]` are fixed-size Ed25519 signature buffers on a reachable path. |
| Java DB | `java/src/main/java/com/harborline/payments/HealthCase.java:4-6` | HEALTH_TOKEN is documented as CHAR(64). |
| Go DB | `go/internal/tokens/issue.go:17-20` | TOKEN_SIG is documented as CHAR(64). |
| C DB | `c/src/storage.c:4-6` | PAN_WRAPPED is documented as CHAR(64). |

## Genuine non-operation references
| # | Language | File:line | Why it is not an operation |
|---:|---|---|---|
| 1 | Python | `python/freight_api/signing.py:3` | Constant metadata value "Ed25519"; not an execution site. |
| 2 | Python | `python/freight_api/signing.py:25` | Accessor returns "Ed25519" and performs no crypto operation. |
| 3 | Python | `python/freight_api/crypto_policy.py:5` | Map entry; algorithm is resolved only by lookup. |
| 4 | Python | `python/freight_api/crypto_policy.py:6` | Map entry; algorithm is resolved only by lookup. |
| 5 | Python | `python/freight_api/crypto_policy.py:7` | Map entry; algorithm is resolved only by lookup. |
| 6 | Python | `python/freight_api/crypto_policy.py:8` | Map entry; algorithm is resolved only by lookup. |
| 7 | Python | `python/freight_api/crypto_policy.py:9` | Unused RC4 map entry; never read. |
| 8 | Python | `python/freight_api/runtime_crypto.py:17` | Accessor returns a TLS cipher-suite string; no TLS API call in the body. |
| 9 | Python | `python/freight_api/pq_client.py:12` | Comment describes a PQC use; comment itself is not executable crypto. |
| 10 | Java | `java/src/main/java/com/harborline/payments/PaymentSigner.java:8` | Constants-class style algorithm identifier; consumed by sign(). |
| 11 | Java | `java/src/main/java/com/harborline/payments/PaymentSigner.java:41` | Accessor returns "SHA256withECDSA"; no crypto call in the accessor. |
| 12 | Java | `java/src/main/java/com/harborline/payments/CryptoNotes.java:5` | Documentation comment only. |
| 13 | Java | `java/src/main/java/com/harborline/payments/CryptoNotes.java:6` | Documentation comment only. |
| 14 | Java | `java/src/main/java/com/harborline/payments/HealthCase.java:5` | Database-width comment naming Ed25519; not an operation. |
| 15 | Go | `go/internal/tokens/issue.go:25` | Accessor returns "Ed25519"; no crypto operation in the body. |
| 16 | Go | `go/internal/transport/transport.go:11` | TLS cipher-suite string in configuration; no TLS API execution. |
| 17 | Go | `go/internal/transport/transport.go:12` | Legacy TLS cipher-suite string in configuration; no TLS API execution. |
| 18 | Go | `go/internal/transport/transport.go:13` | Unused RC4-SHA map entry; never read. |
| 19 | Go | `go/internal/transport/transport.go:48` | Accessor returns a TLS cipher-suite string; no TLS API execution. |
| 20 | Go | `go/internal/crypto/pqc.go:3` | Explicit cross-service contract comment; not a source-level call edge. |
| 21 | Go | `go/internal/crypto/pqc.go:4` | Cross-service contract documentation; not an operation. |
| 22 | Go | `go/internal/crypto/pqc.go:5` | Cross-service contract documentation; not an operation. |
| 23 | Go | `go/internal/crypto/pqc.go:6` | Cross-service contract documentation; not an operation. |
| 24 | Go | `go/internal/crypto/pqc.go:9` | Accessor returns ML-KEM-768 as a contract label; not an operation. |
| 25 | Go | `go/internal/transport/cross_service.go:3` | Explicit cross-service contract comment; not a source-level call edge. |
| 26 | Go | `go/internal/transport/cross_service.go:4` | Contract documentation; not an operation. |
| 27 | Go | `go/internal/transport/cross_service.go:5` | Contract documentation; not an operation. |
| 28 | Go | `go/internal/transport/cross_service.go:6` | Contract documentation; not an operation. |
| 29 | C | `c/src/storage.c:4` | Database contract comment naming AES-GCM and fixed-width storage; not an operation. |
| 30 | Fixture data | `c/tests/fixtures/algorithm_names.txt:4` | Fixture data only; algorithm name is not executable. |
| 31 | Fixture data | `c/tests/fixtures/algorithm_names.txt:5` | Fixture data only; algorithm name is not executable. |
| 32 | Fixture data | `c/tests/fixtures/algorithm_names.txt:6` | Fixture data only; algorithm name is not executable. |
| 33 | Fixture data | `c/tests/fixtures/algorithm_names.txt:7` | Fixture data only; algorithm name is not executable. |
| 34 | Fixture data | `c/tests/fixtures/algorithm_names.txt:8` | Fixture data only; algorithm name is not executable. |
| 35 | Fixture data | `c/tests/fixtures/algorithm_names.txt:9` | Fixture data only; algorithm name is not executable. |
| 36 | Fixture data | `c/tests/fixtures/algorithm_names.txt:10` | Fixture data only; algorithm name is not executable. |
| 37 | Fixture data | `c/tests/fixtures/algorithm_names.txt:11` | Fixture data only; algorithm name is not executable. |
| 38 | Fixture data | `c/tests/fixtures/algorithm_names.txt:12` | Fixture data only; algorithm name is not executable. |
| 39 | Fixture data | `c/tests/fixtures/algorithm_names.txt:13` | Fixture data only; algorithm name is not executable. |
| 40 | Fixture data | `c/tests/fixtures/algorithm_names.txt:14` | Fixture data only; algorithm name is not executable. |
| 41 | Fixture data | `c/tests/fixtures/algorithm_names.txt:15` | Fixture data only; algorithm name is not executable. |
| 42 | Fixture data | `c/tests/fixtures/algorithm_names.txt:16` | Fixture data only; algorithm name is not executable. |
| 43 | Fixture data | `c/tests/fixtures/algorithm_names.txt:17` | Fixture data only; algorithm name is not executable. |
| 44 | Fixture data | `c/tests/fixtures/algorithm_names.txt:18` | Fixture data only; algorithm name is not executable. |
| 45 | Fixture data | `c/tests/fixtures/algorithm_names.txt:19` | Fixture data only; algorithm name is not executable. |

**Reference-site count: 45.**

## Required adversarial cases cross-check
- **Runtime-unresolvable selection:** Python `runtime_crypto.py:5-13`, Java `RuntimeProvider.java:7-10`, Go `crypto/runtime.go:10-20`, C `runtime.c:9-11`.
- **Constant/const indirection:** Java `PaymentSigner.java:8,11`; Go `transport.go:12-25`.
- **Runtime map/dictionary indirection:** Python `crypto_policy.py:13-20`; Go `transport.go:21-27`.
- **Two-algorithm branch:** Python `crypto_policy.py:23-28`; Java `PaymentSigner.java:26-31`; Go `pipeline.go:11-16`.
- **Parameter indirection:** Python `make_key(kind)`; Java `signBody(..., algorithm)`; Go `encrypt(mode,...)`; C helper functions.
- **Assigned callable then invoked:** Python `runtime_crypto.py:11-12`; Go `transport.go:21-22`; C `runtime.c:11`.
- **Dead crypto:** Python `records.py`; Java `SensitiveStore.compactSignature`; Go `deadProvisioner`; C `dead_code.c`.
- **3–5 hop reachable chains:** Python delivery token, Java payment signing, Go parcel protection, and C biometric sealing.
- **Same consumer, two call-site algorithms:** Go `ProtectParcel` passes `gcm` and `ProtectArchivedNote` passes `cbc` to the same consumer; Java `submitSigned` selects Ed25519 vs ECDSA.
- **Fixed classical-size buffers:** Python `bytearray(64)`; Java `new byte[64]`; Go `[64]byte`; C `out[64]`/`receipt[64]`.
- **Database-adjacent crypto width:** Go `TOKEN_SIG CHAR(64)`, Java `HEALTH_TOKEN CHAR(64)`, C `PAN_WRAPPED CHAR(64)`.
- **Reachable blast-radius correlation:** Python delivery-token signature, Go token issuance, and C terminal receipt are reachable from service/entry paths.
- **Cross-language contract only:** Go `crypto/pqc.go` and `transport/cross_service.go` explicitly state that network communication is not a source-level call edge.
- **Sensitive-data scenarios:** Python PAN + clinical note; Java account number + clinical summary; Go account number + health summary; C biometric template + account number.
- **Reference-vs-operation traps:** Python/Java/Go accessors; Java comment block; C fixture; unused RC4 entries.
- **TLS and X.509:** Python/Go TLS suite strings; C X.509 parse call.
- **PQC:** Python ML-KEM-768 encapsulation and C ML-KEM-768 key generation/encapsulation.

## Important interpretation notes
- Runtime-selected crypto is not silently guessed. Python's environment JSON chooses GCM vs CBC; Java chooses an implementation class from an environment variable; Go chooses GCM vs CBC from an environment variable; C loads a shared object by runtime name.
- TLS cipher-suite strings are references, not TLS execution sites.
- The 64-byte signature buffers deliberately match Ed25519's signature size; a larger PQ signature requires a buffer/schema migration.
- The C PQC path uses OpenSSL's named ML-KEM provider interface and performs key generation plus encapsulation.