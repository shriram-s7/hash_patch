# Hash Patch

Offline cryptographic discovery and post-quantum risk analysis tool. Built for
Smart India Hackathon 2026, Problem Statement 26164 (NTRO).

- Scans source code, binaries, container images, config/IaC, and live network
  endpoints to inventory every cryptographic asset — algorithms, keys,
  certificates, protocols, libraries, and HSM/KMS usage.
- Emits a CycloneDX 1.6 (ECMA-424) Cryptography Bill of Materials (CBOM), with
  every finding backed by hard evidence: file, line, column, and snippet.
- Runs fully offline and deterministically — identical input always produces
  a byte-identical CBOM (apart from the scan timestamp).

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
hash-patch version
hash-patch scan PATH
```

## Status: M1 scaffold
