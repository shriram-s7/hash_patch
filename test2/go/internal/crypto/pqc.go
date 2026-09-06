package crypto

// Cross-service contract (not a source-level call edge):
// Python records-service publishes ML-KEM-768 wrapped health-record keys over HTTPS.
// This Go package consumes the resulting envelope; the two implementations are
// deployed independently and are not directly callable from one another.

func expectedEnvelope() string {
	return "ML-KEM-768"
}
