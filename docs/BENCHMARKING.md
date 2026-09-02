# Post-Quantum Cryptography Benchmarking & Recommendations

PRATYAKSHA includes a dedicated performance and byte-size measurement harness
(`pratyaksha/benchmark/pqc_bench.py`) and a grounded recommendation engine
(`pratyaksha/recommend/engine.py`).

Rather than relying purely on static lookups, PRATYAKSHA can measure real latencies
and exact byte sizes on the host system to produce migration recommendations cited
with actual measured numbers.

---

## 1. Benchmarking Methodology & Discipline

The benchmark harness tests post-quantum algorithms and classical comparators natively
using `pyca/cryptography` (FIPS 203 ML-KEM and FIPS 204 ML-DSA):

### Algorithms Tested
- **PQC Signatures (FIPS 204)**:
  - `ML-DSA-44` (NIST Category 2)
  - `ML-DSA-65` (NIST Category 3 / standard baseline)
  - `ML-DSA-87` (NIST Category 5 / high security)
- **PQC Key Encapsulation (FIPS 203)**:
  - `ML-KEM-768` (NIST Category 3 / standard baseline)
  - `ML-KEM-1024` (NIST Category 5 / high security)
- **Classical Baselines**:
  - `RSA-2048` (PKCS#1 v2.2, SHA-256)
  - `ECDSA-P256` (ANSI X9.62, SECP256R1, SHA-256)

### Measurement Discipline
- **Representative Payload**: A fixed 32-byte byte payload (`PRATYAKSHA_BENCHMARK_DIGEST_32B`),
  mirroring the realistic SHA-256 digest passed to signature and KEM primitives in real protocols.
- **Warmup Phase**: Discards a documented number of initial iterations (default: 5 warmup runs)
  to ensure memory caches, OS page tables, and Python imports are fully primed before timing begins.
- **Measured Phase**: Executes $N$ iterations (default: 50 runs), measuring keygen, sign/encapsulate,
  and verify/decapsulate using high-resolution monotonic timers (`time.perf_counter()`).
- **Percentiles**: Records `min`, median (`p50`), 95th-percentile (`p95`), and `max` latency
  in milliseconds.
- **Dynamic Byte Sizing**: Key and payload lengths are extracted directly from the actual in-memory
  objects generated during the run (`public_bytes_raw()`, `len(sig)`, `len(ciphertext)`), ensuring
  the report reflects verified wire sizes rather than hardcoded assumptions.

---

## 2. Single-Machine Honesty Caveat

> [!WARNING]
> **Development Environment Measurement — Not a Multi-Platform SLA**
>
> All measurements captured by `pratyaksha benchmark` represent single-machine, single-run-context
> samples gathered on local development hardware.
>
> These figures characterize **relative performance scaling and comparative overheads** (e.g.,
> ML-DSA keygen being substantially faster than RSA-2048 keygen, but signatures being ~13x larger),
> not an absolute performance SLA.
>
> Production migration planning should execute `pratyaksha benchmark` directly on target deployment
> hardware (e.g. cloud instances, edge gateways, or container runtimes) to observe host-specific
> throughput and memory characteristics.

---

## 3. Documented Library Gaps

PRATYAKSHA explicitly documents two gaps in the underlying cryptographic backend:

1. **`SLH-DSA` (FIPS 205, Stateless Hash-Based Signatures)**:
   - **Status**: Not available in `pyca/cryptography 50.0.1`.
   - **Handling**: For long-lived firmware, boot ROM, and code-signing use cases, SLH-DSA is the
     textbook-correct choice due to its minimal mathematical assumptions (no lattice hardness
     assumptions). When such an asset is detected, the recommendation engine explicitly flags that
     SLH-DSA is the theoretical choice, documents that it is unavailable in this environment, and
     recommends `ML-DSA-87` as an available high-assurance fallback.
2. **`ML-KEM-512` (FIPS 203, NIST Category 1)**:
   - **Status**: Not exposed in `pyca/cryptography 50.0.1`.
   - **Handling**: Modern PQC deployment guidance treats `ML-KEM-768` (Category 3) as the realistic
     production floor; the omission of ML-KEM-512 does not impair production migration readiness.

---

## 4. Recommendation Engine & Confidence Distinction

The recommendation engine (`pratyaksha/recommend/`) translates inventory findings into actionable
PQC migration advice.

The engine provides **two visibly distinguishable confidence levels**:

| Confidence | Provenance | Source Note Example | Latency Figures |
| :--- | :--- | :--- | :--- |
| **`measured`** | Generated from a `BenchmarkReport` run on the host. | `Measured on Windows 11 (AMD64) on 2026-09-02 (50 iterations)` | Real measured `p50` latencies and vs-classical speed multipliers. |
| **`estimated`** | Fallback to static FIPS specifications (`rules/pqc_sizes.yaml`). | `Estimated from published FIPS specifications, not measured on this hardware` | `None` (latency is not guessed). |

---

## 5. CLI Usage

### Running the Benchmark
```bash
# Run benchmark and write report JSON
pratyaksha benchmark --iterations 50 --warmup 5 --output bench.json
```

### Attaching Recommendations to a CBOM Scan
```bash
# Scan repository and attach measured PQC recommendations
pratyaksha scan /path/to/project --benchmark-report bench.json --output cbom.json
```

In the emitted CycloneDX 1.6 CBOM, recommendations are attached to each vulnerable component's
`properties` bag under `pratyaksha:property.recommendation.<target_algo>`.
