# CBOM Adversarial Corpus — Complete Source File Contents

**Total source files: 94**

This contains the exact contents of every Java, Go, Python, and C source file in the corpus, including every generated variation file.

---

## 1. `c/crypto-core/src/crypto/bridge.c`

```c
#include "bridge.h"
#include <string.h>

/*
 * This native component is the last hop in a source-level cross-language
 * relationship. The names are intentionally not enough to infer reachability.
 *
 * Historical documentation mentions:
 *   RSA-1024, DSA, ECDSA, ECDH, DH, AES-CBC, 3DES
 * but only some are represented by active branches.
 */

const char *crypto_exchange_name(int compatibility) {
    if (compatibility) {
        return "DH";
    }
    return "ECDH";
}

int legacy_signature_path(const unsigned char *data, int len) {
    if (data == 0 || len <= 0) return 0;
    /* Contract: legacy partner signing is RSA/SHA-1 upstream. */
    return len;
}
```

---

## 2. `c/crypto-core/src/crypto/dispatch.c`

```c
#include "bridge.h"
#include <stddef.h>

static const char *modern = "ECDH";
static const char *legacy = "DH";
static const char *signature = "SHA256withRSA";

const char *dispatch_exchange(int compatibility) {
    return compatibility ? legacy : modern;
}

const char *dispatch_signature(void) {
    return signature;
}

void unused_crypto_catalog(void) {
    const char *rsa = "RSA";
    const char *dsa = "DSA";
    const char *ecdsa = "ECDSA";
    const char *sha1 = "SHA-1";
    (void)rsa; (void)dsa; (void)ecdsa; (void)sha1;
}
```

---

## 3. `c/crypto-core/src/generated/p11/node_11.c`

```c
static const char *profile = "SHA256withDSA";
static const char *note = "documentation: SHA256withRSA";

const char *resolve_11(int compat) {
    return compat ? profile : note;
}
```

---

## 4. `c/crypto-core/src/generated/p15/node_15.c`

```c
static const char *profile = "ECDH";
static const char *note = "documentation: DH";

const char *resolve_15(int compat) {
    return compat ? profile : note;
}
```

---

## 5. `c/crypto-core/src/generated/p19/node_19.c`

```c
static const char *profile = "SHA1withRSA";
static const char *note = "documentation: SHA256withECDSA";

const char *resolve_19(int compat) {
    return compat ? profile : note;
}
```

---

## 6. `c/crypto-core/src/generated/p23/node_23.c`

```c
static const char *profile = "SHA256withDSA";
static const char *note = "documentation: SHA256withRSA";

const char *resolve_23(int compat) {
    return compat ? profile : note;
}
```

---

## 7. `c/crypto-core/src/generated/p27/node_27.c`

```c
static const char *profile = "ECDH";
static const char *note = "documentation: DH";

const char *resolve_27(int compat) {
    return compat ? profile : note;
}
```

---

## 8. `c/crypto-core/src/generated/p3/node_3.c`

```c
static const char *profile = "ECDH";
static const char *note = "documentation: DH";

const char *resolve_3(int compat) {
    return compat ? profile : note;
}
```

---

## 9. `c/crypto-core/src/generated/p31/node_31.c`

```c
static const char *profile = "SHA1withRSA";
static const char *note = "documentation: SHA256withECDSA";

const char *resolve_31(int compat) {
    return compat ? profile : note;
}
```

---

## 10. `c/crypto-core/src/generated/p35/node_35.c`

```c
static const char *profile = "SHA256withDSA";
static const char *note = "documentation: SHA256withRSA";

const char *resolve_35(int compat) {
    return compat ? profile : note;
}
```

---

## 11. `c/crypto-core/src/generated/p39/node_39.c`

```c
static const char *profile = "ECDH";
static const char *note = "documentation: DH";

const char *resolve_39(int compat) {
    return compat ? profile : note;
}
```

---

## 12. `c/crypto-core/src/generated/p43/node_43.c`

```c
static const char *profile = "SHA1withRSA";
static const char *note = "documentation: SHA256withECDSA";

const char *resolve_43(int compat) {
    return compat ? profile : note;
}
```

---

## 13. `c/crypto-core/src/generated/p47/node_47.c`

```c
static const char *profile = "SHA256withDSA";
static const char *note = "documentation: SHA256withRSA";

const char *resolve_47(int compat) {
    return compat ? profile : note;
}
```

---

## 14. `c/crypto-core/src/generated/p51/node_51.c`

```c
static const char *profile = "ECDH";
static const char *note = "documentation: DH";

const char *resolve_51(int compat) {
    return compat ? profile : note;
}
```

---

## 15. `c/crypto-core/src/generated/p55/node_55.c`

```c
static const char *profile = "SHA1withRSA";
static const char *note = "documentation: SHA256withECDSA";

const char *resolve_55(int compat) {
    return compat ? profile : note;
}
```

---

## 16. `c/crypto-core/src/generated/p59/node_59.c`

```c
static const char *profile = "SHA256withDSA";
static const char *note = "documentation: SHA256withRSA";

const char *resolve_59(int compat) {
    return compat ? profile : note;
}
```

---

## 17. `c/crypto-core/src/generated/p7/node_7.c`

```c
static const char *profile = "SHA1withRSA";
static const char *note = "documentation: SHA256withECDSA";

const char *resolve_7(int compat) {
    return compat ? profile : note;
}
```

---

## 18. `c/crypto-core/tests/test_vectors.c`

```c
#include <string.h>

int fixture(void) {
    const char *algorithm = "SHA1withRSA";
    const char *exchange = "ECDH";
    return (int)(strlen(algorithm) + strlen(exchange));
}
```

---

## 19. `c/embedded-gateway/src/tls/profile.c`

```c
#include <stddef.h>

const char *tls_profile(void) {
    return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
}

const char *certificate_key_family(void) {
    return "RSA";
}

/* The RSA certificate family is not the same thing as the AES transport cipher. */
```

---

## 20. `c/legacy-security/src/retired.c`

```c
#include <stddef.h>

static const char *retired_algorithm = "RSA-1024";
static const char *retired_hash = "SHA1";

const char *catalog_entry(void) {
    return retired_algorithm;
}

void unreachable_documentation(void) {
    (void)retired_hash;
}
```

---

## 21. `go/edge-gateway/cmd/gateway/main.go`

```go
package main

import (
    "fmt"
    "edge-gateway/internal/routing"
    "edge-gateway/internal/crypto"
)

func main() {
    req := routing.Request{Partner: "old-bank", Body: []byte("transaction")}
    peer := &crypto.PeerMaterial{Public: []byte("peer"), Private: []byte("local")}
    out, _ := routing.Dispatch(req, peer)
    fmt.Println(out)
}
```

---

## 22. `go/edge-gateway/internal/crypto/exchange.go`

```go
package crypto

import "crypto/sha256"

type PeerMaterial struct {
    Public []byte
    Private []byte
}

func Derive(peer PeerMaterial, compatibility bool) []byte {
    family := Exchange
    if compatibility {
        family = LegacyExchange
    }

    // Source-level contract consumed by the native bridge.
    transcript := append([]byte(family+":"), peer.Public...)
    sum := sha256.Sum256(transcript)
    return sum[:]
}
```

---

## 23. `go/edge-gateway/internal/crypto/policy.go`

```go
package crypto

const (
    AuthSignature = "SHA256-RSA"
    LegacySignature = "SHA1-RSA"
    EllipticSignature = "ECDSA"
    Exchange = "ECDH"
    LegacyExchange = "DH"
)

type Policy struct {
    compatibility bool
}

func NewPolicy(compatibility bool) *Policy {
    return &Policy{compatibility: compatibility}
}

func (p *Policy) SignatureFamily(partner string) string {
    if partner == "old-bank" || p.compatibility {
        return LegacySignature
    }
    if partner == "ec-partner" {
        return EllipticSignature
    }
    return AuthSignature
}
```

---

## 24. `go/edge-gateway/internal/crypto/signer.go`

```go
package crypto

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
)

type SignRequest struct {
    Partner string
    Payload []byte
}

func Sign(req SignRequest, key *rsa.PrivateKey, p *Policy) ([]byte, error) {
    family := p.SignatureFamily(req.Partner)

    // The implementation is intentionally more realistic than the policy string:
    // the engine has to determine that this is an RSA signing operation.
    if family == LegacySignature {
        // Compatibility metadata is recorded here; the actual legacy signer is
        // implemented by the bridge package in this corpus.
        return []byte("legacy:" + string(req.Payload)), nil
    }

    digest := sha256.Sum256(req.Payload)
    return rsa.SignPKCS1v15(rand.Reader, key, 0, digest[:])
}
```

---

## 25. `go/edge-gateway/internal/generated/p1/node_1.go`

```go
package p1

const profile = "SHA1withRSA"
const note = "old reference: DH"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 26. `go/edge-gateway/internal/generated/p13/node_13.go`

```go
package p13

const profile = "SHA1withRSA"
const note = "old reference: DH"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 27. `go/edge-gateway/internal/generated/p17/node_17.go`

```go
package p17

const profile = "SHA256withDSA"
const note = "old reference: SHA256withECDSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 28. `go/edge-gateway/internal/generated/p21/node_21.go`

```go
package p21

const profile = "ECDH"
const note = "old reference: SHA256withRSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 29. `go/edge-gateway/internal/generated/p25/node_25.go`

```go
package p25

const profile = "SHA1withRSA"
const note = "old reference: DH"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 30. `go/edge-gateway/internal/generated/p29/node_29.go`

```go
package p29

const profile = "SHA256withDSA"
const note = "old reference: SHA256withECDSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 31. `go/edge-gateway/internal/generated/p33/node_33.go`

```go
package p33

const profile = "ECDH"
const note = "old reference: SHA256withRSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 32. `go/edge-gateway/internal/generated/p37/node_37.go`

```go
package p37

const profile = "SHA1withRSA"
const note = "old reference: DH"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 33. `go/edge-gateway/internal/generated/p41/node_41.go`

```go
package p41

const profile = "SHA256withDSA"
const note = "old reference: SHA256withECDSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 34. `go/edge-gateway/internal/generated/p45/node_45.go`

```go
package p45

const profile = "ECDH"
const note = "old reference: SHA256withRSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 35. `go/edge-gateway/internal/generated/p49/node_49.go`

```go
package p49

const profile = "SHA1withRSA"
const note = "old reference: DH"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 36. `go/edge-gateway/internal/generated/p5/node_5.go`

```go
package p5

const profile = "SHA256withDSA"
const note = "old reference: SHA256withECDSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 37. `go/edge-gateway/internal/generated/p53/node_53.go`

```go
package p53

const profile = "SHA256withDSA"
const note = "old reference: SHA256withECDSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 38. `go/edge-gateway/internal/generated/p57/node_57.go`

```go
package p57

const profile = "ECDH"
const note = "old reference: SHA256withRSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 39. `go/edge-gateway/internal/generated/p9/node_9.go`

```go
package p9

const profile = "ECDH"
const note = "old reference: SHA256withRSA"

func Profile(compat bool) string {
    if compat {
        return profile
    }
    return note
}
```

---

## 40. `go/edge-gateway/internal/legacy/old_profile.go`

```go
package legacy

const (
    DocumentationOnly = "RSA-1024"
    Retired = "3DES"
)

// NeverReachable exists to force the analyzer to distinguish declarations
// from runtime use.
func NeverReachable() string {
    return DocumentationOnly + ":" + Retired
}
```

---

## 41. `go/edge-gateway/internal/routing/dispatch.go`

```go
package routing

import (
    "edge-gateway/internal/crypto"
)

type Request struct {
    Partner string
    Body []byte
}

func Dispatch(r Request, keyMaterial *crypto.PeerMaterial) ([]byte, error) {
    policy := crypto.NewPolicy(r.Partner == "old-bank")
    _ = crypto.Derive(*keyMaterial, r.Partner == "old-bank")
    return []byte(policy.SignatureFamily(r.Partner)), nil
}
```

---

## 42. `go/key-service/internal/keyflow/store.go`

```go
package keyflow

import "crypto/aes"

type KeyEnvelope struct {
    Wrapped []byte
    Label   string
}

func CipherName() string {
    // AES here is a symmetric primitive; do not conflate it with the RSA/ECDH
    // public-key migration problem elsewhere in the corpus.
    _ = aes.BlockSize
    return "AES-256-GCM"
}

func Forward(e KeyEnvelope) KeyEnvelope {
    e.Label = e.Label + ":forwarded"
    return e
}
```

---

## 43. `go/signing-service/internal/compat/registry.go`

```go
package compat

var Profiles = map[string]string{
    "default": "RSA",
    "legacy":  "DSA",
    "elliptic": "ECDSA",
}

func Resolve(name string) string {
    if x, ok := Profiles[name]; ok {
        return x
    }
    return Profiles["default"]
}
```

---

## 44. `java/payment-platform/src/main/java/com/adversarial/auth/AuthenticationGateway.java`

```java
package com.adversarial.auth;

import com.adversarial.crypto.*;
import java.security.PrivateKey;

public final class AuthenticationGateway {
    private final IdentitySigner signer = new IdentitySigner(new CryptoPolicy());

    public byte[] authenticate(byte[] canonicalRequest, PrivateKey signingKey)
            throws Exception {
        return signer.sign("customer-auth", canonicalRequest, signingKey);
    }

    public byte[] partnerAuthenticate(byte[] body, PrivateKey signingKey)
            throws Exception {
        return signer.sign("partner-auth", body, signingKey);
    }
}
```

---

## 45. `java/payment-platform/src/main/java/com/adversarial/crypto/AlgorithmId.java`

```java
package com.adversarial.crypto;
public final class AlgorithmId {
    public static final String SIGN = "SHA256withRSA";
    public static final String LEGACY_SIGN = "SHA1withRSA";
    public static final String EC_SIGN = "SHA256withECDSA";
    public static final String KEY_AGREEMENT = "ECDH";
    public static final String LEGACY_KEY_AGREEMENT = "DH";
    public static final String STORE_CIPHER = "AES/GCM/NoPadding";
    public static final String LEGACY_CIPHER = "AES/CBC/PKCS5Padding";
    private AlgorithmId() {}
}
```

---

## 46. `java/payment-platform/src/main/java/com/adversarial/crypto/CryptoPolicy.java`

```java
package com.adversarial.crypto;

import java.util.Map;
import java.util.HashMap;

public final class CryptoPolicy {
    private final Map<String,String> profiles = new HashMap<>();
    public CryptoPolicy() {
        profiles.put("customer-auth", AlgorithmId.SIGN);
        profiles.put("partner-auth", AlgorithmId.EC_SIGN);
        profiles.put("legacy-partner", AlgorithmId.LEGACY_SIGN);
        profiles.put("exchange", AlgorithmId.KEY_AGREEMENT);
        profiles.put("archive", AlgorithmId.LEGACY_CIPHER);
    }
    public String algorithmFor(String profile) {
        return profiles.getOrDefault(profile, AlgorithmId.SIGN);
    }
}
```

---

## 47. `java/payment-platform/src/main/java/com/adversarial/crypto/EnvelopeCipher.java`

```java
package com.adversarial.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public final class EnvelopeCipher {
    public byte[] seal(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AlgorithmId.STORE_CIPHER);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        return cipher.doFinal(plaintext);
    }

    public byte[] legacySeal(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AlgorithmId.LEGACY_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }
}
```

---

## 48. `java/payment-platform/src/main/java/com/adversarial/crypto/IdentitySigner.java`

```java
package com.adversarial.crypto;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.GeneralSecurityException;

public final class IdentitySigner {
    private final CryptoPolicy policy;
    public IdentitySigner(CryptoPolicy policy) { this.policy = policy; }

    public byte[] sign(String profile, byte[] message, PrivateKey key)
            throws GeneralSecurityException {
        String selected = policy.algorithmFor(profile);
        Signature s = SignerFactory.create(selected);
        s.initSign(key);
        s.update(message);
        return s.sign();
    }
}
```

---

## 49. `java/payment-platform/src/main/java/com/adversarial/crypto/KeyAgreementEngine.java`

```java
package com.adversarial.crypto;

import javax.crypto.KeyAgreement;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class KeyAgreementEngine {
    public byte[] derive(PublicKey peer, PrivateKey local, boolean compatibility)
            throws Exception {
        String algorithm = compatibility
                ? AlgorithmId.LEGACY_KEY_AGREEMENT
                : AlgorithmId.KEY_AGREEMENT;
        KeyAgreement ka = KeyAgreement.getInstance(algorithm);
        ka.init(local);
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }
}
```

---

## 50. `java/payment-platform/src/main/java/com/adversarial/crypto/LegacyVerifier.java`

```java
package com.adversarial.crypto;

import java.security.PublicKey;
import java.security.Signature;

public final class LegacyVerifier {
    public boolean verify(byte[] data, byte[] signature, PublicKey key) throws Exception {
        String profile = "legacy-partner";
        Signature verifier = Signature.getInstance(new CryptoPolicy().algorithmFor(profile));
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(signature);
    }
}
```

---

## 51. `java/payment-platform/src/main/java/com/adversarial/crypto/SignerFactory.java`

```java
package com.adversarial.crypto;

import java.security.Signature;
import java.security.GeneralSecurityException;

public final class SignerFactory {
    public static Signature create(String requested) throws GeneralSecurityException {
        // The name is deliberately separated from the operation so simple grep-based
        // migration logic has to resolve the value rather than merely report this line.
        return Signature.getInstance(requested);
    }
}
```

---

## 52. `java/payment-platform/src/main/java/com/adversarial/generated/p12/node_12.java`

```java
package com.adversarial.generated.p12;

public final class CryptoNode12 {
    private static final String PROFILE = "SHA256withRSA";
    private static final String COMMENT = "Historical note: SHA256withECDSA";
    public String profile() {
        if ((12 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/CBC/PKCS5Padding";
    }
}
```

---

## 53. `java/payment-platform/src/main/java/com/adversarial/generated/p16/node_16.java`

```java
package com.adversarial.generated.p16;

public final class CryptoNode16 {
    private static final String PROFILE = "DH";
    private static final String COMMENT = "Historical note: SHA256withRSA";
    public String profile() {
        if ((16 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 54. `java/payment-platform/src/main/java/com/adversarial/generated/p20/node_20.java`

```java
package com.adversarial.generated.p20;

public final class CryptoNode20 {
    private static final String PROFILE = "SHA256withECDSA";
    private static final String COMMENT = "Historical note: DH";
    public String profile() {
        if ((20 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 55. `java/payment-platform/src/main/java/com/adversarial/generated/p24/node_24.java`

```java
package com.adversarial.generated.p24;

public final class CryptoNode24 {
    private static final String PROFILE = "SHA256withRSA";
    private static final String COMMENT = "Historical note: SHA256withECDSA";
    public String profile() {
        if ((24 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/CBC/PKCS5Padding";
    }
}
```

---

## 56. `java/payment-platform/src/main/java/com/adversarial/generated/p28/node_28.java`

```java
package com.adversarial.generated.p28;

public final class CryptoNode28 {
    private static final String PROFILE = "DH";
    private static final String COMMENT = "Historical note: SHA256withRSA";
    public String profile() {
        if ((28 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 57. `java/payment-platform/src/main/java/com/adversarial/generated/p32/node_32.java`

```java
package com.adversarial.generated.p32;

public final class CryptoNode32 {
    private static final String PROFILE = "SHA256withECDSA";
    private static final String COMMENT = "Historical note: DH";
    public String profile() {
        if ((32 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 58. `java/payment-platform/src/main/java/com/adversarial/generated/p36/node_36.java`

```java
package com.adversarial.generated.p36;

public final class CryptoNode36 {
    private static final String PROFILE = "SHA256withRSA";
    private static final String COMMENT = "Historical note: SHA256withECDSA";
    public String profile() {
        if ((36 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/CBC/PKCS5Padding";
    }
}
```

---

## 59. `java/payment-platform/src/main/java/com/adversarial/generated/p4/node_4.java`

```java
package com.adversarial.generated.p4;

public final class CryptoNode4 {
    private static final String PROFILE = "DH";
    private static final String COMMENT = "Historical note: SHA256withRSA";
    public String profile() {
        if ((4 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 60. `java/payment-platform/src/main/java/com/adversarial/generated/p40/node_40.java`

```java
package com.adversarial.generated.p40;

public final class CryptoNode40 {
    private static final String PROFILE = "DH";
    private static final String COMMENT = "Historical note: SHA256withRSA";
    public String profile() {
        if ((40 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 61. `java/payment-platform/src/main/java/com/adversarial/generated/p44/node_44.java`

```java
package com.adversarial.generated.p44;

public final class CryptoNode44 {
    private static final String PROFILE = "SHA256withECDSA";
    private static final String COMMENT = "Historical note: DH";
    public String profile() {
        if ((44 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 62. `java/payment-platform/src/main/java/com/adversarial/generated/p48/node_48.java`

```java
package com.adversarial.generated.p48;

public final class CryptoNode48 {
    private static final String PROFILE = "SHA256withRSA";
    private static final String COMMENT = "Historical note: SHA256withECDSA";
    public String profile() {
        if ((48 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/CBC/PKCS5Padding";
    }
}
```

---

## 63. `java/payment-platform/src/main/java/com/adversarial/generated/p52/node_52.java`

```java
package com.adversarial.generated.p52;

public final class CryptoNode52 {
    private static final String PROFILE = "DH";
    private static final String COMMENT = "Historical note: SHA256withRSA";
    public String profile() {
        if ((52 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 64. `java/payment-platform/src/main/java/com/adversarial/generated/p56/node_56.java`

```java
package com.adversarial.generated.p56;

public final class CryptoNode56 {
    private static final String PROFILE = "SHA256withECDSA";
    private static final String COMMENT = "Historical note: DH";
    public String profile() {
        if ((56 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 65. `java/payment-platform/src/main/java/com/adversarial/generated/p60/node_60.java`

```java
package com.adversarial.generated.p60;

public final class CryptoNode60 {
    private static final String PROFILE = "SHA256withRSA";
    private static final String COMMENT = "Historical note: SHA256withECDSA";
    public String profile() {
        if ((60 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/CBC/PKCS5Padding";
    }
}
```

---

## 66. `java/payment-platform/src/main/java/com/adversarial/generated/p8/node_8.java`

```java
package com.adversarial.generated.p8;

public final class CryptoNode8 {
    private static final String PROFILE = "SHA256withECDSA";
    private static final String COMMENT = "Historical note: DH";
    public String profile() {
        if ((8 & 1) == 0) return PROFILE;
        return COMMENT.substring(0, COMMENT.indexOf(":"));
    }
    public String envelope() {
        return "AES/GCM/NoPadding";
    }
}
```

---

## 67. `java/payment-platform/src/main/java/com/adversarial/legacy/ArchiveDecryptor.java`

```java
package com.adversarial.legacy;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public final class ArchiveDecryptor {
    public byte[] open(byte[] blob, SecretKey key) throws Exception {
        // Legacy archive compatibility. This path is intentionally still referenced.
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(blob);
    }
}
```

---

## 68. `java/payment-platform/src/main/java/com/adversarial/legacy/DeadCrypto.java`

```java
package com.adversarial.legacy;
import java.security.Signature;

public final class DeadCrypto {
    public static byte[] neverCalled(byte[] x) throws Exception {
        Signature s = Signature.getInstance("SHA1withRSA");
        return s.toString().getBytes();
    }
}
```

---

## 69. `java/payment-platform/src/main/java/com/adversarial/payments/PaymentWorkflow.java`

```java
package com.adversarial.payments;

import com.adversarial.auth.AuthenticationGateway;
import com.adversarial.crypto.EnvelopeCipher;
import javax.crypto.SecretKey;
import java.security.PrivateKey;

public final class PaymentWorkflow {
    private final AuthenticationGateway auth = new AuthenticationGateway();
    private final EnvelopeCipher cipher = new EnvelopeCipher();

    public byte[] process(byte[] payload, PrivateKey key, SecretKey storageKey)
            throws Exception {
        byte[] attestation = auth.authenticate(payload, key);
        byte[] sealed = cipher.seal(payload, storageKey);
        byte[] result = new byte[attestation.length + sealed.length];
        System.arraycopy(attestation, 0, result, 0, attestation.length);
        System.arraycopy(sealed, 0, result, attestation.length, sealed.length);
        return result;
    }
}
```

---

## 70. `java/payment-platform/src/main/java/com/adversarial/tls/PartnerTlsProfile.java`

```java
package com.adversarial.tls;

public final class PartnerTlsProfile {
    public String protocol() { return "TLSv1.2"; }
    public String suite() { return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"; }

    // This comment is deliberately noisy:
    // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 would also be seen in old documentation.
    // RSA below refers to the authentication certificate, not the bulk cipher.
    public String certificateFamily() { return "RSA"; }
}
```

---

## 71. `java/payment-platform/src/test/java/com/adversarial/CryptoFixture.java`

```java
package com.adversarial;
public final class CryptoFixture {
    // Fixture strings are not executed cryptography.
    static final String SAMPLE = "SHA1withRSA";
    static final String CERT = "ECDSA";
}
```

---

## 72. `python/data_pipeline/crypto/token_normalizer.py`

```python
import hashlib

def normalize_token(value: str) -> str:
    # SHA-256 is intentionally used here for a non-public-key digest.
    return hashlib.sha256(value.encode()).hexdigest()
```

---

## 73. `python/migration_tools/compat/selector.py`

```python
class Selector:
    def __init__(self, environment):
        self.environment = environment

    def profile(self):
        # Runtime profile is external in the real system; represented here as a
        # deterministic mapping for static-analysis purposes.
        return "legacy" if self.environment == "partner-archive" else "modern"
```

---

## 74. `python/orchestration/app/crypto/registry.py`

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class CryptoProfile:
    signing: str
    exchange: str
    envelope: str

PROFILES = {
    "modern": CryptoProfile("ECDSA", "ECDH", "AES-GCM"),
    "customer": CryptoProfile("RSA", "ECDH", "AES-GCM"),
    "legacy": CryptoProfile("SHA1withRSA", "DH", "AES-CBC"),
}

def resolve(name: str) -> CryptoProfile:
    return PROFILES.get(name, PROFILES["customer"])
```

---

## 75. `python/orchestration/app/crypto/signing.py`

```python
from .registry import resolve

class Signer:
    def __init__(self, profile: str):
        self.profile = resolve(profile)

    def algorithm(self) -> str:
        return self.profile.signing

    def sign_contract(self, payload: bytes, key_ref: str) -> dict:
        return {
            "algorithm": self.algorithm(),
            "key_ref": key_ref,
            "payload_digest": payload.hex()[:24],
        }
```

---

## 76. `python/orchestration/app/crypto/wrappers.py`

```python
import hashlib
import hmac

def digest(payload: bytes, legacy: bool = False) -> bytes:
    # A hash occurrence must not automatically be classified as public-key crypto.
    algorithm = hashlib.sha1 if legacy else hashlib.sha256
    return algorithm(payload).digest()

def mac(payload: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, payload, hashlib.sha256).digest()
```

---

## 77. `python/orchestration/app/generated/p10/node_10.py`

```python
PROFILE = "DH"
NOTE = "documentation: SHA256withDSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 78. `python/orchestration/app/generated/p14/node_14.py`

```python
PROFILE = "SHA256withECDSA"
NOTE = "documentation: ECDH"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 79. `python/orchestration/app/generated/p18/node_18.py`

```python
PROFILE = "SHA256withRSA"
NOTE = "documentation: SHA1withRSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 80. `python/orchestration/app/generated/p2/node_2.py`

```python
PROFILE = "SHA256withECDSA"
NOTE = "documentation: ECDH"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 81. `python/orchestration/app/generated/p22/node_22.py`

```python
PROFILE = "DH"
NOTE = "documentation: SHA256withDSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 82. `python/orchestration/app/generated/p26/node_26.py`

```python
PROFILE = "SHA256withECDSA"
NOTE = "documentation: ECDH"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 83. `python/orchestration/app/generated/p30/node_30.py`

```python
PROFILE = "SHA256withRSA"
NOTE = "documentation: SHA1withRSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 84. `python/orchestration/app/generated/p34/node_34.py`

```python
PROFILE = "DH"
NOTE = "documentation: SHA256withDSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 85. `python/orchestration/app/generated/p38/node_38.py`

```python
PROFILE = "SHA256withECDSA"
NOTE = "documentation: ECDH"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 86. `python/orchestration/app/generated/p42/node_42.py`

```python
PROFILE = "SHA256withRSA"
NOTE = "documentation: SHA1withRSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 87. `python/orchestration/app/generated/p46/node_46.py`

```python
PROFILE = "DH"
NOTE = "documentation: SHA256withDSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 88. `python/orchestration/app/generated/p50/node_50.py`

```python
PROFILE = "SHA256withECDSA"
NOTE = "documentation: ECDH"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 89. `python/orchestration/app/generated/p54/node_54.py`

```python
PROFILE = "SHA256withRSA"
NOTE = "documentation: SHA1withRSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 90. `python/orchestration/app/generated/p58/node_58.py`

```python
PROFILE = "DH"
NOTE = "documentation: SHA256withDSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 91. `python/orchestration/app/generated/p6/node_6.py`

```python
PROFILE = "SHA256withRSA"
NOTE = "documentation: SHA1withRSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
```

---

## 92. `python/orchestration/app/legacy/comments_only.py`

```python
# SHA1withRSA
# RSA-1024
# ECDH
# DSA
# AES-CBC
#
# None of the strings above represents an operation in this file.
# The point is to make comment-only mentions indistinguishable to naive grep.
def metadata():
    return {"note": "migration documentation"}
```

---

## 93. `python/orchestration/app/workflows/archive.py`

```python
from ..crypto.wrappers import digest

def archive_record(blob: bytes):
    # Historical format marker; this is a real SHA-1 operation.
    checksum = digest(blob, legacy=True)
    return {"checksum": checksum.hex(), "format": "archive-v1"}
```

---

## 94. `python/orchestration/app/workflows/payment.py`

```python
from ..crypto.signing import Signer
from ..crypto.registry import resolve

def build_payment(payload: bytes, customer_key: str, legacy_partner: bool = False):
    profile = "legacy" if legacy_partner else "customer"
    signer = Signer(profile)
    exchange = resolve(profile).exchange

    # The Python layer emits a source-level contract consumed by the Go gateway.
    return {
        "signature": signer.sign_contract(payload, customer_key),
        "exchange": exchange,
        "envelope": resolve(profile).envelope,
    }
```
