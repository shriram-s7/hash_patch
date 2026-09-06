# Certificate test fixtures — how they were generated

`testdata/certificates/*` were generated with the OpenSSL CLI (never
hand-crafted binary data), so they are reproducible. Private keys used to
generate them are NOT committed — only the resulting certificate/PKCS12
files, which is all `hash_patch/detect/certificates.py` ever reads.

Run from `testdata/certificates/` (Git Bash on Windows needs
`MSYS_NO_PATHCONV=1` set first, or the `/CN=...` subject argument gets
mangled into a path):

```sh
export MSYS_NO_PATHCONV=1
mkdir -p keys_scratch

# 1. valid_rsa2048.crt — self-signed RSA-2048, valid ~825 days from generation
openssl req -x509 -newkey rsa:2048 -keyout keys_scratch/rsa_key.pem \
  -out valid_rsa2048.crt -days 825 -nodes \
  -subj "/CN=valid-rsa.example.com/O=HashPatch Test"

# 2. expired_rsa2048.crt — self-signed RSA-2048, EXPLICIT fixed validity
#    window (already expired) so its dates are reproducible byte-for-byte,
#    unlike the -days-relative certs above.
openssl req -x509 -newkey rsa:2048 -keyout keys_scratch/expired_key.pem \
  -out expired_rsa2048.crt -nodes \
  -subj "/CN=expired.example.com/O=HashPatch Test" \
  -not_before 20200101000000Z -not_after 20210101000000Z

# 3. ecdsa_p256.crt — self-signed ECDSA P-256
openssl ecparam -name prime256v1 -genkey -noout -out keys_scratch/ec_key.pem
openssl req -x509 -key keys_scratch/ec_key.pem -out ecdsa_p256.crt \
  -days 825 -nodes -subj "/CN=ecdsa.example.com/O=HashPatch Test"

# 4. ca_signed_chain.pem — a 2-certificate chain: a CA-signed leaf (NOT
#    self-signed) followed by its root CA (self-signed), concatenated in
#    one PEM file to exercise chain-depth parsing.
openssl req -x509 -newkey rsa:2048 -keyout keys_scratch/ca_key.pem \
  -out keys_scratch/ca_cert.pem -days 3650 -nodes \
  -subj "/CN=HashPatch Test Root CA/O=HashPatch Test"
openssl req -newkey rsa:2048 -keyout keys_scratch/leaf_key.pem \
  -out keys_scratch/leaf.csr -nodes \
  -subj "/CN=ca-signed-leaf.example.com/O=HashPatch Test"
openssl x509 -req -in keys_scratch/leaf.csr -CA keys_scratch/ca_cert.pem \
  -CAkey keys_scratch/ca_key.pem -CAcreateserial \
  -out keys_scratch/leaf_signed.crt -days 825
cat keys_scratch/leaf_signed.crt keys_scratch/ca_cert.pem > ca_signed_chain.pem

# 5. protected.p12 — the valid_rsa2048.crt cert + its key, password-protected
openssl pkcs12 -export -in valid_rsa2048.crt -inkey keys_scratch/rsa_key.pem \
  -out protected.p12 -passout pass:testpass123

rm -rf keys_scratch
```

Password for `protected.p12` in tests: `testpass123` (plain test fixture
credential, not a real secret — see `tests/golden/certificate_manifest.json`).

**Why no exact validity dates in the manifest for certs 1/3/4**: they use
`-days N` relative to generation time, so `notBefore`/`notAfter` are
different every time these fixtures are regenerated — only
`expired_rsa2048.crt` (explicit `-not_before`/`-not_after`) has fixed,
assertable dates. The golden test asserts structural fields (algorithm, key
size, self-signed, chain position/depth, quantum status, expired flag) for
all five, and exact dates additionally for the expired one.
