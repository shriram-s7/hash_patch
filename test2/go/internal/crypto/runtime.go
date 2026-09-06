package crypto

import (
	"os"
	"crypto/aes"
	"crypto/cipher"
)

func EncryptFromEnvironment(data []byte) []byte {
	mode := os.Getenv("HARBOURLINE_CIPHER_MODE")
	key := []byte(os.Getenv("HARBOURLINE_CIPHER_KEY"))
	block, _ := aes.NewCipher(key)
	if mode == "gcm" {
		gcm, _ := cipher.NewGCM(block)
		return gcm.Seal(nil, make([]byte, gcm.NonceSize()), data, nil)
	}
	enc := cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize))
	out := make([]byte, len(data))
	enc.CryptBlocks(out, data)
	return out
}
