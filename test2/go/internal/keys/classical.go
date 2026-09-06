package keys

import (
	"crypto/rsa"
	"crypto/dsa"
	"crypto/rand"
	"math/big"
)

func issueLegacyRSA() *rsa.PrivateKey {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	return k
}

func loadDsaParameters() *dsa.Parameters {
	return &dsa.Parameters{P: big.NewInt(23), Q: big.NewInt(11), G: big.NewInt(2)}
}

func deadProvisioner() *rsa.PrivateKey {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	return k
}
