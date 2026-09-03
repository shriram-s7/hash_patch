package main

import "fmt"

// Negative fixture: RSA, AES, MD5, SHA1 appear only in comments,
// string literals, variable names, and non-crypto struct methods.
// Hash Patch must produce ZERO CryptoAssets from this file.

// RSA is a public-key cryptosystem.
// AES is an encryption standard.
// MD5 is a cryptographic hash function.

const (
	RsaDescription = "RSA 2048-bit key configuration"
	AesLogMessage  = "AES cipher selected in config file"
	Md5ChecksumTag = "MD5: d41d8cd98f00b204e9800998ecf8427e"
)

type RSAHandler struct {
	Algorithm string
}

func (h *RSAHandler) GenerateKey() string {
	return "not-a-crypto-key"
}

func logCryptoName(algo string) {
	fmt.Printf("Configured crypto algorithm: %s\n", algo)
}

func main() {
	logCryptoName("RSA")
	logCryptoName("AES")
	logCryptoName("MD5")
	logCryptoName("SHA-1")

	handler := &RSAHandler{Algorithm: "RSA"}
	_ = handler.GenerateKey()
}
