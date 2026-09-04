"""
hasher.py — half of the mixed-language regression fixture for
tests/integration/test_cli_scan.py::test_mixed_language_directory_keeps_both_findings.

Computes a SHA-256 digest via Python's stdlib hashlib, in a directory
scanned ALONGSIDE a Go file (../goservice/hasher.go) that also computes a
SHA-256 digest, independently, at a different file/line. Both must survive
a scan of the shared parent directory as distinct Evidence occurrences on
the (correctly, deliberately) single merged SHA-256 CryptoAsset — see
docs/COVERAGE.md and hash_patch/model/assets.py::derive_asset_id's own
docstring for why one CryptoAsset per logical algorithm, not one per
call site, is the correct CBOM model here.
"""

import hashlib


def normalize(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
