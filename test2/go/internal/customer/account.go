package customer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

func StoreAccount(w interface{}, accountNumber string) []byte {
	key := sha256.Sum256([]byte("account-wrap-secret"))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nil, make([]byte, gcm.NonceSize()), []byte(accountNumber), nil)
}

func StoreHealthSummary(summary string, patientID string) []byte {
	key := sha256.Sum256([]byte("clinical-wrap-secret"))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nil, make([]byte, gcm.NonceSize()), []byte(patientID+":"+summary), nil)
}

func clinicalDigest(summary string) [32]byte {
	return sha256.Sum256([]byte(summary))
}
