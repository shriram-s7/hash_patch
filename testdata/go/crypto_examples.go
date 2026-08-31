package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
)

// RSA example — broken-by-shor
func rsaExample() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// AES-256-GCM example — weakened-by-grover
func aesGcmExample(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// MD5 example — broken-classically
func md5Example(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// SHA-1 example — broken-classically
func sha1Example(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// ECDSA example — broken-by-shor
func ecdsaExample() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// 3DES example — broken-classically
func tripleDesExample(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key[:24])
}

// SHA-256 example — weakened-by-grover
func sha256Example(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func main() {
	key := make([]byte, 32)
	_, _ = rsaExample()
	_, _ = aesGcmExample(key)
	_ = md5Example([]byte("test"))
	_ = sha1Example([]byte("test"))
	_, _ = ecdsaExample()
	_, _ = tripleDesExample(key)
	_ = sha256Example([]byte("test"))
}
