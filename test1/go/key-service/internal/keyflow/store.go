package keyflow

import "crypto/aes"

type KeyEnvelope struct {
    Wrapped []byte
    Label   string
}

func CipherName() string {
    // AES here is a symmetric primitive; do not conflate it with the RSA/ECDH
    // public-key migration problem elsewhere in the corpus.
    _ = aes.BlockSize
    return "AES-256-GCM"
}

func Forward(e KeyEnvelope) KeyEnvelope {
    e.Label = e.Label + ":forwarded"
    return e
}
