"""pratyaksha/benchmark/pqc_bench.py — PQC performance and byte-size measurement harness.

Measures real keygen, sign/encapsulate, and verify/decapsulate latencies and
exact byte sizes for post-quantum algorithms (ML-DSA-44/65/87, ML-KEM-768/1024)
and classical baseline comparators (RSA-2048, ECDSA-P256) on the local host.
"""

from __future__ import annotations

import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from typing import Any

import cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem, padding, rsa

from pratyaksha.model.benchmark import (
    AlgorithmBenchmark,
    BenchmarkReport,
    BenchmarkRunMetadata,
    ByteSizes,
    OperationTiming,
)

# Realistic 32-byte payload representing a standard SHA-256 digest being signed
REPRESENTATIVE_PAYLOAD: bytes = b"PRATYAKSHA_BENCHMARK_DIGEST_32B"


def _calc_timing(durations_ms: list[float]) -> OperationTiming:
    """Compute min, median (p50), 95th-percentile (p95), and max latency."""
    if not durations_ms:
        return OperationTiming(min_ms=0.0, p50_ms=0.0, p95_ms=0.0, max_ms=0.0)

    sorted_d = sorted(durations_ms)
    p50 = statistics.median(sorted_d)
    # Nearest-rank 95th percentile
    p95_idx = round((len(sorted_d) - 1) * 0.95)
    p95 = sorted_d[p95_idx]

    return OperationTiming(
        min_ms=round(sorted_d[0], 4),
        p50_ms=round(p50, 4),
        p95_ms=round(p95, 4),
        max_ms=round(sorted_d[-1], 4),
    )


def _bench_mldsa(
    name: str,
    cls: Any,
    level: int,
    iterations: int,
    warmup: int,
) -> AlgorithmBenchmark:
    """Benchmark an ML-DSA parameter set (keygen, sign, verify)."""
    # Warmup
    for _ in range(warmup):
        priv = cls.generate()
        pub = priv.public_key()
        sig = priv.sign(REPRESENTATIVE_PAYLOAD)
        pub.verify(sig, REPRESENTATIVE_PAYLOAD)

    kg_times: list[float] = []
    sign_times: list[float] = []
    verify_times: list[float] = []

    last_priv = None
    last_pub = None
    last_sig = None

    for _ in range(iterations):
        t0 = time.perf_counter()
        priv = cls.generate()
        kg_times.append((time.perf_counter() - t0) * 1000.0)

        pub = priv.public_key()

        t0 = time.perf_counter()
        sig = priv.sign(REPRESENTATIVE_PAYLOAD)
        sign_times.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        pub.verify(sig, REPRESENTATIVE_PAYLOAD)
        verify_times.append((time.perf_counter() - t0) * 1000.0)

        last_priv = priv
        last_pub = pub
        last_sig = sig

    assert last_priv is not None and last_pub is not None and last_sig is not None

    sizes = ByteSizes(
        public_key_bytes=len(last_pub.public_bytes_raw()),
        private_key_bytes=len(last_priv.private_bytes_raw()),
        signature_bytes=len(last_sig),
    )

    timings = {
        "keygen": _calc_timing(kg_times),
        "sign": _calc_timing(sign_times),
        "verify": _calc_timing(verify_times),
    }

    return AlgorithmBenchmark(
        algorithm=name,
        standard="FIPS 204",
        primitive_family="signature",
        nist_security_level=level,
        is_pqc=True,
        timings=timings,
        byte_sizes=sizes,
    )


def _bench_mlkem(
    name: str,
    cls: Any,
    level: int,
    iterations: int,
    warmup: int,
) -> AlgorithmBenchmark:
    """Benchmark an ML-KEM parameter set (keygen, encapsulate, decapsulate)."""
    # Warmup
    for _ in range(warmup):
        priv = cls.generate()
        pub = priv.public_key()
        ss, ct = pub.encapsulate()
        ss_dec = priv.decapsulate(ct)
        assert ss == ss_dec

    kg_times: list[float] = []
    enc_times: list[float] = []
    dec_times: list[float] = []

    last_priv = None
    last_pub = None
    last_ct = None
    last_ss = None

    for _ in range(iterations):
        t0 = time.perf_counter()
        priv = cls.generate()
        kg_times.append((time.perf_counter() - t0) * 1000.0)

        pub = priv.public_key()

        t0 = time.perf_counter()
        ss, ct = pub.encapsulate()
        enc_times.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        ss_dec = priv.decapsulate(ct)
        dec_times.append((time.perf_counter() - t0) * 1000.0)

        last_priv = priv
        last_pub = pub
        last_ct = ct
        last_ss = ss

    assert (
        last_priv is not None
        and last_pub is not None
        and last_ct is not None
        and last_ss is not None
    )

    sizes = ByteSizes(
        public_key_bytes=len(last_pub.public_bytes_raw()),
        private_key_bytes=len(last_priv.private_bytes_raw()),
        ciphertext_bytes=len(last_ct),
        shared_secret_bytes=len(last_ss),
    )

    timings = {
        "keygen": _calc_timing(kg_times),
        "encapsulate": _calc_timing(enc_times),
        "decapsulate": _calc_timing(dec_times),
    }

    return AlgorithmBenchmark(
        algorithm=name,
        standard="FIPS 203",
        primitive_family="key_agreement_or_pke",
        nist_security_level=level,
        is_pqc=True,
        timings=timings,
        byte_sizes=sizes,
    )


def _bench_rsa_2048(iterations: int, warmup: int) -> AlgorithmBenchmark:
    """Benchmark RSA-2048 (keygen, PKCS#1v1.5 sign, verify)."""
    for _ in range(warmup):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        sig = priv.sign(REPRESENTATIVE_PAYLOAD, padding.PKCS1v15(), hashes.SHA256())
        pub.verify(sig, REPRESENTATIVE_PAYLOAD, padding.PKCS1v15(), hashes.SHA256())

    kg_times: list[float] = []
    sign_times: list[float] = []
    verify_times: list[float] = []

    last_priv = None
    last_pub = None
    last_sig = None

    for _ in range(iterations):
        t0 = time.perf_counter()
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kg_times.append((time.perf_counter() - t0) * 1000.0)

        pub = priv.public_key()

        t0 = time.perf_counter()
        sig = priv.sign(REPRESENTATIVE_PAYLOAD, padding.PKCS1v15(), hashes.SHA256())
        sign_times.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        pub.verify(sig, REPRESENTATIVE_PAYLOAD, padding.PKCS1v15(), hashes.SHA256())
        verify_times.append((time.perf_counter() - t0) * 1000.0)

        last_priv = priv
        last_pub = pub
        last_sig = sig

    assert last_priv is not None and last_pub is not None and last_sig is not None

    pub_der = last_pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_der = last_priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    sizes = ByteSizes(
        public_key_bytes=len(pub_der),
        private_key_bytes=len(priv_der),
        signature_bytes=len(last_sig),
    )

    timings = {
        "keygen": _calc_timing(kg_times),
        "sign": _calc_timing(sign_times),
        "verify": _calc_timing(verify_times),
    }

    return AlgorithmBenchmark(
        algorithm="RSA-2048",
        standard="PKCS#1 v2.2",
        primitive_family="signature",
        nist_security_level=1,
        is_pqc=False,
        timings=timings,
        byte_sizes=sizes,
    )


def _bench_ecdsa_p256(iterations: int, warmup: int) -> AlgorithmBenchmark:
    """Benchmark ECDSA-P256 (keygen, ECDSA sign, verify)."""
    for _ in range(warmup):
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        sig = priv.sign(REPRESENTATIVE_PAYLOAD, ec.ECDSA(hashes.SHA256()))
        pub.verify(sig, REPRESENTATIVE_PAYLOAD, ec.ECDSA(hashes.SHA256()))

    kg_times: list[float] = []
    sign_times: list[float] = []
    verify_times: list[float] = []

    last_priv = None
    last_pub = None
    last_sig = None

    for _ in range(iterations):
        t0 = time.perf_counter()
        priv = ec.generate_private_key(ec.SECP256R1())
        kg_times.append((time.perf_counter() - t0) * 1000.0)

        pub = priv.public_key()

        t0 = time.perf_counter()
        sig = priv.sign(REPRESENTATIVE_PAYLOAD, ec.ECDSA(hashes.SHA256()))
        sign_times.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        pub.verify(sig, REPRESENTATIVE_PAYLOAD, ec.ECDSA(hashes.SHA256()))
        verify_times.append((time.perf_counter() - t0) * 1000.0)

        last_priv = priv
        last_pub = pub
        last_sig = sig

    assert last_priv is not None and last_pub is not None and last_sig is not None

    pub_der = last_pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_der = last_priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    sizes = ByteSizes(
        public_key_bytes=len(pub_der),
        private_key_bytes=len(priv_der),
        signature_bytes=len(last_sig),
    )

    timings = {
        "keygen": _calc_timing(kg_times),
        "sign": _calc_timing(sign_times),
        "verify": _calc_timing(verify_times),
    }

    return AlgorithmBenchmark(
        algorithm="ECDSA-P256",
        standard="ANSI X9.62",
        primitive_family="signature",
        nist_security_level=1,
        is_pqc=False,
        timings=timings,
        byte_sizes=sizes,
    )


def run_benchmark(iterations: int = 50, warmup: int = 5) -> BenchmarkReport:
    """Run full benchmark harness across available PQC and classical algorithms."""
    results: list[AlgorithmBenchmark] = []

    # 1. PQC Signatures: ML-DSA-44, ML-DSA-65, ML-DSA-87
    results.append(_bench_mldsa("ML-DSA-44", mldsa.MLDSA44PrivateKey, 2, iterations, warmup))
    results.append(_bench_mldsa("ML-DSA-65", mldsa.MLDSA65PrivateKey, 3, iterations, warmup))
    results.append(_bench_mldsa("ML-DSA-87", mldsa.MLDSA87PrivateKey, 5, iterations, warmup))

    # 2. PQC Key Encapsulation: ML-KEM-768, ML-KEM-1024
    results.append(_bench_mlkem("ML-KEM-768", mlkem.MLKEM768PrivateKey, 3, iterations, warmup))
    results.append(_bench_mlkem("ML-KEM-1024", mlkem.MLKEM1024PrivateKey, 5, iterations, warmup))

    # 3. Classical baselines
    results.append(_bench_rsa_2048(iterations, warmup))
    results.append(_bench_ecdsa_p256(iterations, warmup))

    metadata = BenchmarkRunMetadata(
        python_version=sys.version.split()[0],
        cryptography_version=cryptography.__version__,
        platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
        processor=platform.processor() or "unknown",
        timestamp=datetime.now(UTC),
        iterations=iterations,
        warmup_iterations=warmup,
    )

    return BenchmarkReport(metadata=metadata, results=results)
