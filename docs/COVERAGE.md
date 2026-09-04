# Detection coverage — what's in, what isn't

Hash Patch's detectors are **rule-based, not heuristic**: every algorithm,
library, and API surface they can find is explicitly listed in
`rules/*.yaml`. This is deliberate (see CLAUDE.md's "Detection rules live in
YAML, not Python") — it makes the tool's exact reach auditable in a way a
fuzzy/ML detector isn't. The direct consequence is also unavoidable: **a
library or API shape that is not listed in the relevant `rules/*.yaml` file
produces no finding at all.** That is a known, documented gap, not a silent
failure or a bug — this page exists so the answer to "what about `<library>`
you don't mention?" is already written down rather than improvised.

This file was written after an audit prompted by a real gap: Python's
standard-library `hashlib` module had zero rule coverage until it was found
via an adversarial test corpus (not caught by the existing golden-corpus
tests, since none of them happened to use `hashlib`). That audit — and the
fixes that came out of it — is what this page reflects.

## Python (`rules/python_crypto.yaml`, `hash_patch/detect/python.py`)

Covered:
- **PyCA `cryptography`** (hazmat): `hashes`, `algorithms` (block/stream
  ciphers), `rsa`, `dsa`, `ec` (+ curve constructors), `dh`, `x25519`,
  `x448`, `ed25519`, `ed448`, `padding`, `hmac`, `poly1305`, `cmac`.
- **pycryptodome / PyCrypto**: `AES`/`DES`/`DES3`/`ARC2`/`ARC4`/`Blowfish`/
  `CAST`/`ChaCha20`/`Salsa20`.new, `RSA`/`DSA`/`ElGamal`/`ECC`.generate/
  import_key/construct, `MD5`/`SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`/
  `SHA3_*`/`BLAKE2b`/`BLAKE2s`.new, `CMAC`/`HMAC`/`Poly1305`.new.
- **Standard library `hashlib`**: direct calls (`hashlib.sha256(...)`, etc.
  for md5/sha1/sha256/sha384/sha512/sha3_256/sha3_384/sha3_512/blake2s/
  blake2b), `hashlib.new("<literal>")` (string-literal algorithm names
  only — a variable is never guessed at), and `hmac.new(key, msg, digestmod)`
  where `digestmod` is a bare `hashlib.X` reference or a string literal.
- **PyNaCl**: `nacl.public.PrivateKey`/`Box` (X25519, both the
  `.generate()` classmethod and the bare constructor form), `nacl.signing.
  SigningKey` (Ed25519, same two forms), `nacl.secret.SecretBox`
  (XSalsa20-Poly1305).
- **PyJWT**: `jwt.encode(payload, key, algorithm="...")` — HS256/384/512
  (HMAC), RS256/384/512 (RSA signature), PS256/384/512 (RSASSA-PSS),
  ES256/384/512 (ECDSA) — only when `algorithm` is a resolvable string
  literal; a variable, or the argument omitted entirely, produces nothing
  (PyJWT's own HS256 default is never assumed).

**Known gaps, not fixed:** `hashlib.pbkdf2_hmac()`/`hashlib.scrypt()`
(functional KDF calls), `hmac.digest()` (the newer one-shot HMAC function),
`jwt.decode()`'s `algorithms=[...]` list argument, any crypto library not
named above (e.g. `pynacl`'s `nacl.pwhash`, `argon2-cffi`, `cryptg`), and any
call where the algorithm is chosen through a variable/dict/dispatch table
rather than written literally at the call site (by design — see
`docs/REACHABILITY.md`'s and `docs/SHELF_LIFE.md`'s equivalent no-dataflow
caveats).

## Java (`rules/java_jca.yaml`, `hash_patch/detect/java.py`)

Covered:
- **JCA/JCE `getInstance`-family**: `Cipher`, `KeyPairGenerator`,
  `MessageDigest`, `Signature`, `KeyGenerator`, `Mac`, `KeyAgreement`,
  `SecretKeyFactory`, `AlgorithmParameters`, `KeyFactory` — covers AES/DES/
  3DES/Blowfish/RC2/RC4/ChaCha20(-Poly1305), RSA/RSASSA-PSS/DSA/EC/ECDSA/
  ECDH/DH/Ed25519/Ed448/X25519/X448, MD2/MD4/MD5/SHA-1/SHA-256/384/512/
  SHA3-*/SHAKE128/256/BLAKE2b/s, HmacSHA1/256/384/512, HmacMD5,
  PBKDF2WithHmacSHA1/256.
- **BouncyCastle, via JCA**: `Security.addProvider(new
  BouncyCastleProvider())` + `getInstance(..., "BC")` (covered by the same
  getInstance matching above), plus `JcaX509CertificateConverter
  .getCertificate` / `JcaContentSignerBuilder.build`.
- **BouncyCastle lightweight API** (`new ClassName(...)`, a call shape
  distinct from `getInstance`): `RSAKeyPairGenerator`, `ECDSASigner`,
  `Ed25519Signer`, `Ed25519KeyPairGenerator`, `X25519KeyPairGenerator` —
  the highest-prevalence entry points, not the full BC surface.

**Known gaps, not fixed:** the rest of BC's lightweight API (DSA/DH/ElGamal
signers and generators, GCM/CCM block-cipher engines used directly rather
than through JCA, BC's own `Digest`/`Mac` engine classes), Web Crypto API
(not applicable — this is server-side Java), any `getInstance` call whose
algorithm argument is a variable rather than a string literal (by design —
no data-flow tracing anywhere in this codebase).

## Go (`rules/go_crypto.yaml`, `hash_patch/detect/go.py`)

Covered:
- **Standard library**: `crypto/rsa`, `crypto/ecdsa` + `crypto/elliptic`,
  `crypto/ecdh`, `crypto/ed25519`, `crypto/dsa`, `crypto/aes` +
  `crypto/cipher` (GCM/CBC/CTR), `crypto/des`, `crypto/rc4`, `crypto/md5`,
  `crypto/sha1`, `crypto/sha256`, `crypto/sha512`, `crypto/hmac`.
- **`golang.org/x/crypto`**: `chacha20`, `chacha20poly1305`, and (added in
  this audit) `bcrypt` (`GenerateFromPassword`/`CompareHashAndPassword`).

**Known gaps, not fixed:** `golang.org/x/crypto/curve25519` (the standalone
package — `crypto/ecdh`'s `ecdh.X25519` above covers the modern stdlib
equivalent, but not this older package's own function names),
`golang.org/x/crypto/ssh` (host/client key material, distinct call shapes
from the raw primitive packages above), `golang.org/x/crypto/argon2`,
`golang.org/x/crypto/pbkdf2`, `golang.org/x/crypto/hkdf`, any third-party
crypto library (e.g. `filippo.io/edwards25519`).

## C / C++ (`rules/c_openssl.yaml`, `hash_patch/detect/c.py`)

Covered:
- **OpenSSL legacy API**: `RSA_*`, `EC_KEY_*`, `ECDSA_*`, `DSA_*`,
  `DH_generate_key`, `DES_*`, `RC4*`, `MD5_*`, `SHA1_*`, `SHA224_Init`
  through `SHA512_Init`.
- **OpenSSL modern EVP API**: `EVP_aes_*` (GCM/CBC/CTR/ECB/CCM,
  128/192/256), `EVP_chacha20`/`EVP_chacha20_poly1305`, `EVP_des_*`,
  `EVP_rc4`, `EVP_sha*`/`EVP_md5` (the `EVP_MD` selector functions — these
  are matched as ordinary calls wherever they appear, so
  `EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)` already works: the walk
  visits every call node, nested or not), `EVP_PKEY_CTX_new_id` +
  curve-name macro arguments, `EVP_CIPHER_fetch`/`EVP_MD_fetch`/
  `EVP_get_cipherbyname`/`EVP_get_digestbyname` string arguments.
- **HMAC** (added in this audit): `HMAC_Init_ex`, `HMAC_Init`, the one-shot
  `HMAC()` function — a genuinely separate MAC finding, additive to
  whichever `EVP_MD` selector call already fires for the underlying hash.

**Known gaps, not fixed:** `EVP_PKEY_derive` (raw key-agreement output,
distinct from the keygen/curve-name macro path already covered),
libsodium's own C API (`crypto_box_*`, `crypto_sign_*`,
`crypto_secretbox_*`), mbedTLS/wolfSSL/GnuTLS (entirely different APIs from
OpenSSL — this file is OpenSSL-only by name and scope), any call where the
algorithm/cipher is chosen through a variable rather than the literal
function/macro/string this pillar matches on.

## Why this list, not "we cover everything"

Per CLAUDE.md's "Detection rules live in YAML, not Python": every entry
above exists because someone wrote it into a `rules/*.yaml` file. There is
no fallback heuristic, no LLM-based guess, no partial credit for "looks like
crypto" — a call this tool doesn't recognize produces **no finding**, the
same as a call that genuinely isn't crypto. That is the correct, honest
behavior for a rule-based scanner (the alternative — guessing — is
explicitly forbidden throughout this codebase, see e.g. the "skip silently
if unresolvable" discipline in `hash_patch/detect/python.py`), but it means
this list is the actual boundary of what a scan can find, not an aspiration.
Extend the relevant `rules/*.yaml` file (never hardcode names in Python) to
close a gap found in a real codebase — the same way every entry in this
document was added.
