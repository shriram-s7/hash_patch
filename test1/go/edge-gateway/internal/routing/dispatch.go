package routing

import (
    "edge-gateway/internal/crypto"
)

type Request struct {
    Partner string
    Body []byte
}

func Dispatch(r Request, keyMaterial *crypto.PeerMaterial) ([]byte, error) {
    policy := crypto.NewPolicy(r.Partner == "old-bank")
    _ = crypto.Derive(*keyMaterial, r.Partner == "old-bank")
    return []byte(policy.SignatureFamily(r.Partner)), nil
}
