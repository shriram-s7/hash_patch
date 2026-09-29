# Hash Patch

[![Release](https://img.shields.io/github/v/release/shriram-s7/hash_patch?style=flat-square&color=blue)](https://github.com/shriram-s7/hash_patch/releases/latest)
[![Tests](https://img.shields.io/badge/tests-821%20passed-brightgreen?style=flat-square)](https://github.com/shriram-s7/hash_patch)
[![Linter](https://img.shields.io/badge/linter-ruff%20passed-brightgreen?style=flat-square)](https://github.com/shriram-s7/hash_patch)
[![CBOM](https://img.shields.io/badge/CBOM-CycloneDX%201.6-purple?style=flat-square)](https://cyclonedx.org)
[![Offline](https://img.shields.io/badge/network-100%25%20air--gapped%20ready-success?style=flat-square)](https://github.com/shriram-s7/hash_patch)

**Hash Patch** is a post-quantum cryptographic (PQC) discovery, risk assessment, and migration platform

It scans polyglot codebases, configuration files, and container manifests completely offline to produce deterministic **CycloneDX 1.6 Cryptography Bill of Materials (CBOM)**, calculate call-graph reachability, trace cryptographic data chains, evaluate data shelf-life (Mosca Law / DPDP Act), and synthesize migration roadmaps.

---

## 📥 Desktop Downloads (Windows x64)

The desktop application packages the full offline backend engine, the modern forensic terminal UI, and optional local AI capabilities into an air-gapped bundle:

| Version | Package | Format | Direct Download Link |
| :--- | :--- | :--- | :--- |
| **v0.1.0** | **Windows Installer (Recommended)** | NSIS `.exe` | [**Download HashPatch-Setup.exe**](https://github.com/shriram-s7/hash_patch/releases/download/v0.1.0/HashPatch-Setup.exe) |
| **v0.1.0** | **Windows Standalone Portable** | Single `.exe` | [**Download HashPatch-Portable.exe**](https://github.com/shriram-s7/hash_patch/releases/download/v0.1.0/HashPatch-Portable.exe) |

> 🔗 Full Release Notes & Checksums: [**GitHub Releases**](https://github.com/shriram-s7/hash_patch/releases/latest)

---

## 💻 System Requirements & Compatibility

- **Core Discovery & Engine (Pillars 1 to 5)**:
  - **Memory:** 2 GB – 4 GB RAM minimum
  - **CPU:** Any modern x86_64 / ARM64 processor
  - **Network:** **Zero network connection required.** 100% air-gap compatible.
  - All AST multi-language scanning (C, Go, Java, Python), CycloneDX 1.6 CBOM generation, static call-graph reachability, and risk estimation run deterministically with minimal resource footprints.
- **Offline AI Assistant ("Ask" / Natural Language Q&A)**:
  - Powered locally by Ollama running `llama3.2:3b`.
  - **Memory:** 6 GB to 8 GB+ RAM recommended to comfortably host the local model.
  - *Note:* On low-RAM or headless systems, the core engine still provides comprehensive rule-based grounded answers without needing the local LLM.

---

## 🚀 Key Features

1. **Multi-Language AST Analysis**:
   - Deep structural parsing using Tree-sitter for **Java** (JCA, JCE, BouncyCastle), **Python** (hashlib, hmac, cryptography, PyNaCl, PyJWT), **Go** (crypto/*, golang.org/x/crypto), and **C** (OpenSSL, WolfSSL, libsodium).
   - Extracts algorithms, key lengths, elliptic curves, cipher modes, and padding schemes with precise line/column evidence snippets.

2. **Inter-Procedural Reachability & Data Chains**:
   - Call graph construction differentiates between dead/unreachable crypto in test files and actively executed production crypto.
   - Taint-tracking analyzes cryptographic data flow (e.g. key derivation feeding cipher initializations).

3. **CycloneDX 1.6 CBOM (ECMA-424 Compliant)**:
   - Exports standard-compliant JSON bills of materials with cryptographic properties (`algorithm`, `keyLength`, `classicalSecurityLevel`, `nistQuantumSecurityLevel`).

4. **Mosca Theorem & Regulatory Shelf-Life**:
   - Computes migration urgency by comparing quantum vulnerability horizon ($T_{collapse}$) against data retention requirements ($X$) and migration time ($Y$), with compliance mapping for regulations like the **DPDP Act 2023**.

5. **Optimal Migration Prioritization**:
   - Algorithmic scheduler prioritizing PQC replacements (e.g., transitioning from RSA-2048 / ECDSA to ML-KEM, ML-DSA, or SLH-DSA) with actionable code snippets.

6. **Executive & Technical PDF Reporting**:
   - Discrete, multi-page vector PDF reports tailored for executive leadership, security auditors, and compliance teams.

---

## 🛠️ CLI Installation & Usage

### Prerequisites
- Python 3.10+
- `git`

### Quick Start
```bash
# Clone repository
git clone https://github.com/shriram-s7/hash_patch.git
cd hash_patch

# Install package in editable mode with development dependencies
pip install -e ".[dev]"

# Verify installation
hash-patch version

# Scan a target directory and generate CBOM
hash-patch scan /path/to/target/project --format cyclonedx --output cbom.json

# Analyze reachability and risk
hash-patch analyze cbom.json
```

---

## 🧪 Testing & Verification

The test suite contains over 820+ automated unit, regression, and golden test cases:

```bash
# Run pytest test suite
pytest

# Run code style & static analysis
ruff check .
```

---

## 📄 License
This project is licensed under the Apache 2.0 / MIT License.
