package crypto

import "crypto/sha256"

type PeerMaterial struct {
    Public []byte
    Private []byte
}

func Derive(peer PeerMaterial, compatibility bool) []byte {
    family := Exchange
    if compatibility {
        family = LegacyExchange
    }

    // Source-level contract consumed by the native bridge.
    transcript := append([]byte(family+":"), peer.Public...)
    sum := sha256.Sum256(transcript)
    return sum[:]
}
