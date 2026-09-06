package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/des"
)

const (
	modeGCM = "gcm"
	modeCBC = "cbc"
)

var suites = map[string]string{
	"modern": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"legacy": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	"unused": "RC4-SHA",
}

func encrypt(mode, plaintext string, key []byte) []byte {
	factories := map[string]func([]byte) (cipher.Block, error){
		modeGCM: aes.NewCipher,
		modeCBC: aes.NewCipher,
	}
	makeBlock := factories[mode]
	block, _ := makeBlock(key)
	if mode == modeGCM {
		g, _ := cipher.NewGCM(block)
		return g.Seal(nil, make([]byte, g.NonceSize()), []byte(plaintext), nil)
	}
	return blockModeCBC(block, []byte(plaintext))
}

func legacyDigest(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

func blockModeCBC(block cipher.Block, plaintext []byte) []byte {
	out := make([]byte, len(plaintext))
	return out
}

func CipherFor(kind string) string {
	if kind == "external" {
		return suites["modern"]
	}
	return suites["legacy"]
}

func tlsName() string {
	return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
}
