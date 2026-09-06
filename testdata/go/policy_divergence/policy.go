package crypto

const (
    AuthSignature   = "SHA256-RSA"
    LegacySignature = "SHA1-RSA"
    EllipticSignature = "ECDSA"
    Exchange        = "ECDH"
    LegacyExchange  = "DH"
)

type Policy struct {
    compatibility bool
}

func NewPolicy(compatibility bool) *Policy {
    return &Policy{compatibility: compatibility}
}

func (p *Policy) SignatureFamily(partner string) string {
    if partner == "old-bank" || p.compatibility {
        return LegacySignature
    }
    if partner == "ec-partner" {
        return EllipticSignature
    }
    return AuthSignature
}
