// hasher.go — the other half of the mixed-language regression fixture for
// tests/integration/test_cli_scan.py::test_mixed_language_directory_keeps_both_findings.
//
// Computes a SHA-256 digest via Go's standard library, independently of
// ../pyservice/hasher.py's Python SHA-256 call, at a different file/line.
package goservice

import "crypto/sha256"

func Normalize(value []byte) [32]byte {
	return sha256.Sum256(value)
}
