// bcrypt_examples.go — Positive fixture for the golang.org/x/crypto/bcrypt
// coverage gap found in the post-hashlib-fix audit (see docs/COVERAGE.md).
// rules/go_crypto.yaml had zero bcrypt coverage despite it being the
// highest-prevalence x/crypto password-hashing package.
package examples

import "golang.org/x/crypto/bcrypt"

// (1) bcrypt.GenerateFromPassword — weakened-by-grover.
func hashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
}

// (2) bcrypt.CompareHashAndPassword — weakened-by-grover.
func checkPassword(hash, password []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}
