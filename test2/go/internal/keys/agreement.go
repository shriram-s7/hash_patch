package keys

import "crypto/ecdh"

func negotiate() []byte {
	private, _ := ecdh.P256().GenerateKey(nil)
	peer, _ := ecdh.P256().GenerateKey(nil)
	secret, _ := private.ECDH(peer.PublicKey())
	return secret
}
