package crypto

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
)

type SignRequest struct {
    Partner string
    Payload []byte
}

func Sign(req SignRequest, key *rsa.PrivateKey, p *Policy) ([]byte, error) {
    family := p.SignatureFamily(req.Partner)

    // The implementation is intentionally more realistic than the policy string:
    // the engine has to determine that this is an RSA signing operation.
    if family == LegacySignature {
        // Compatibility metadata is recorded here; the actual legacy signer is
        // implemented by the bridge package in this corpus.
        return []byte("legacy:" + string(req.Payload)), nil
    }

    digest := sha256.Sum256(req.Payload)
    return rsa.SignPKCS1v15(rand.Reader, key, 0, digest[:])
}
