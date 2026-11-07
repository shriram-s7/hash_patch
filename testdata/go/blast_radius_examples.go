package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

// (1) MUST FIRE: 64-byte signature buffer sized for classical Ed25519 signature (64 bytes).
// When migrating to post-quantum ML-DSA-65 (FIPS 204, 3309 bytes), this buffer overflows
// by 3245 bytes and surfaces as a High Severity blast radius finding.
func signWithEd25519(priv ed25519.PrivateKey, msg []byte) []byte {
	sig := ed25519.Sign(priv, msg)
	var signature [64]byte
	copy(signature[:], sig)
	return signature[:]
}

// (2) MUST NOT FIRE: Generously sized buffer (8192 bytes) easily fits ML-DSA-65's 3309-byte signature.
func signWithGenerousBuffer(priv ed25519.PrivateKey, msg []byte) []byte {
	sig := ed25519.Sign(priv, msg)
	var large_signature_buf [8192]byte
	copy(large_signature_buf[:], sig)
	return large_signature_buf[:]
}

func main() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	_ = signWithEd25519(priv, []byte("data"))
	_ = signWithGenerousBuffer(priv, []byte("data"))
}
