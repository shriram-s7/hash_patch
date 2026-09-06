# CBOM Adversarial Corpus — Quantum Crypto Migration Testbed

Purpose
-------
A deliberately difficult source-code corpus for testing CBOM discovery, normalization,
crypto reachability, key-flow analysis, substitution planning, and migration-impact
analysis.

Language constraint
-------------------
Project source files are ONLY Java, Go, Python, and C. No JavaScript, TypeScript,
Rust, C++, or other source languages are used.

Important
---------
This is a STATIC ANALYSIS TEST CORPUS. The cryptographic material is synthetic and
must not be used as production security code.

The corpus intentionally contains:
- direct and wrapped cryptographic APIs
- algorithm aliases and constants
- factories and provider registries
- nested call chains
- configuration-driven algorithm selection
- reachable and unreachable crypto
- compatibility/legacy branches
- misleading comments
- duplicated implementations
- certificate/TLS configuration
- key material flowing through several abstractions
- cross-language service relationships represented through source-level contracts
- quantum-vulnerable public-key primitives mixed with symmetric primitives
- intentionally difficult naming and indirection

Expected challenge
------------------
A competent CBOM engine should distinguish:
1. an occurrence of a cryptographic name,
2. an actual cryptographic operation,
3. the algorithm/provider used by that operation,
4. whether the operation is reachable,
5. what asset/data/key it protects,
6. what depends on it,
7. whether replacement is technically plausible,
8. and which findings are merely comments or dead code.

Do not judge correctness by line count alone. The corpus contains a manifest under
docs/expected_inventory.md describing the intended classes of findings. It is
provided so the corpus can later be used for differential verification.
