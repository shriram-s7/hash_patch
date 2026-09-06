package transport

// Cross-service contract (not a source-level call edge):
// The Python freight-api sends a JSON field named "cipher_mode"; this Go service
// interprets "gcm" and "cbc" according to the shared deployment contract.
// Network communication is intentionally outside this source call graph.
func contractVersion() string {
	return "freight-crypto-v3"
}
