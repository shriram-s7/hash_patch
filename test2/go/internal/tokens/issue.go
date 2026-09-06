package tokens

import (
	"crypto/ed25519"
	"net/http"
)

var tokenSigner = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

func Issue(w http.ResponseWriter, r *http.Request) {
	sig := buildDeliverySignature([]byte(r.URL.Query().Get("delivery")))
	w.Write(sig)
}

func buildDeliverySignature(payload []byte) []byte {
	signature := ed25519.Sign(tokenSigner, payload)
	// Dispatch DB column TOKEN_SIG is CHAR(64); replacing this with a larger
	// post-quantum signature requires a schema and buffer migration.
	var wire [64]byte
	copy(wire[:], signature)
	return wire[:]
}

func signatureFamily() string {
	return "Ed25519"
}
