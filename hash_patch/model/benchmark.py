"""hash_patch/model/benchmark.py — PQC benchmark results and recommendation models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class OperationTiming(BaseModel):
    """Latency percentiles for a single cryptographic operation in milliseconds."""

    model_config = ConfigDict(frozen=True)

    min_ms: float
    p50_ms: float
    p95_ms: float
    max_ms: float


class ByteSizes(BaseModel):
    """Raw encoded byte sizes of cryptographic artefacts."""

    model_config = ConfigDict(frozen=True)

    public_key_bytes: int
    private_key_bytes: int
    signature_bytes: int | None = None
    ciphertext_bytes: int | None = None
    shared_secret_bytes: int | None = None


class AlgorithmBenchmark(BaseModel):
    """Benchmark results for a specific algorithm / parameter set."""

    model_config = ConfigDict(frozen=True)

    algorithm: str
    standard: str
    primitive_family: Literal["signature", "key_agreement_or_pke"]
    nist_security_level: int | None = None
    is_pqc: bool = True
    timings: dict[str, OperationTiming]
    byte_sizes: ByteSizes


class BenchmarkRunMetadata(BaseModel):
    """Hardware and environment provenance for a benchmark run."""

    model_config = ConfigDict(frozen=True)

    python_version: str
    cryptography_version: str
    platform: str
    processor: str
    timestamp: datetime
    iterations: int
    warmup_iterations: int


class BenchmarkReport(BaseModel):
    """Complete collection of benchmark measurements and metadata."""

    model_config = ConfigDict(frozen=True)

    metadata: BenchmarkRunMetadata
    results: list[AlgorithmBenchmark]
    disclaimer: str = (
        "Single-machine development measurement on local hardware. These figures "
        "characterise relative performance and byte-size scaling, not an absolute SLA "
        "guarantee. Production deployments should re-run this benchmark on target hardware."
    )

    def get_result(self, algorithm: str) -> AlgorithmBenchmark | None:
        """Find an algorithm benchmark by case-insensitive name."""
        target = algorithm.lower().replace("-", "").replace("_", "")
        for r in self.results:
            cand = r.algorithm.lower().replace("-", "").replace("_", "")
            if cand == target:
                return r
        return None


class RecommendationFinding(BaseModel):
    """PQC migration recommendation for a cryptographic asset."""

    model_config = ConfigDict(frozen=True)

    asset_id: str
    source_primitive: str
    target_algorithm: str
    target_standard: str
    confidence: Literal["measured", "estimated"]
    source_note: str
    rationale: str
    latency_summary: str | None = None
    size_delta_summary: str
