"""tests/unit/test_benchmark.py — Unit tests for PQC benchmarking harness and recommender."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pratyaksha.benchmark.pqc_bench import run_benchmark
from pratyaksha.cli import app
from pratyaksha.model.assets import AssetType, CryptoAsset, Primitive, QuantumStatus
from pratyaksha.model.evidence import Evidence
from pratyaksha.recommend import recommend_for_asset

runner = CliRunner()


def _make_evidence(locator: str = "test.py", line: int = 1) -> Evidence:
    return Evidence(
        locator=locator,
        line=line,
        column=1,
        byte_offset=0,
        snippet="mock code",
        source_type="source",
        detector_id="test",
        detector_version="0.1.0",
    )


def test_benchmark_harness_smoke_run() -> None:
    """Smoke test: harness runs and produces non-zero, plausible timing numbers.

    Note: In this test we use iterations=2, warmup=1 for speed in the automated
    test suite, rather than the CLI default of iterations=50, warmup=5.
    """
    report = run_benchmark(iterations=2, warmup=1)
    assert len(report.results) == 7

    # Check ML-DSA-65
    dsa65 = report.get_result("ML-DSA-65")
    assert dsa65 is not None
    assert dsa65.timings["keygen"].p50_ms > 0.0
    assert dsa65.timings["sign"].p50_ms > 0.0
    assert dsa65.timings["verify"].p50_ms > 0.0

    # Check ML-KEM-768
    kem768 = report.get_result("ML-KEM-768")
    assert kem768 is not None
    assert kem768.timings["keygen"].p50_ms > 0.0
    assert kem768.timings["encapsulate"].p50_ms > 0.0
    assert kem768.timings["decapsulate"].p50_ms > 0.0


def test_measured_byte_sizes_match_nist_standards() -> None:
    """Byte sizes measured by the harness must exactly match published FIPS specs.

    This guards against upstream library version drifts or serialization alterations.
    """
    report = run_benchmark(iterations=1, warmup=0)

    # ML-DSA-44, 65, 87
    dsa44 = report.get_result("ML-DSA-44")
    assert dsa44 is not None
    assert dsa44.byte_sizes.public_key_bytes == 1312
    assert dsa44.byte_sizes.signature_bytes == 2420

    dsa65 = report.get_result("ML-DSA-65")
    assert dsa65 is not None
    assert dsa65.byte_sizes.public_key_bytes == 1952
    assert dsa65.byte_sizes.signature_bytes == 3309

    dsa87 = report.get_result("ML-DSA-87")
    assert dsa87 is not None
    assert dsa87.byte_sizes.public_key_bytes == 2592
    assert dsa87.byte_sizes.signature_bytes == 4627

    # ML-KEM-768, 1024
    kem768 = report.get_result("ML-KEM-768")
    assert kem768 is not None
    assert kem768.byte_sizes.public_key_bytes == 1184
    assert kem768.byte_sizes.ciphertext_bytes == 1088
    assert kem768.byte_sizes.shared_secret_bytes == 32

    kem1024 = report.get_result("ML-KEM-1024")
    assert kem1024 is not None
    assert kem1024.byte_sizes.public_key_bytes == 1568
    assert kem1024.byte_sizes.ciphertext_bytes == 1568
    assert kem1024.byte_sizes.shared_secret_bytes == 32


def test_recommender_selection_logic() -> None:
    """Recommender picks ML-KEM for key-agreement / PKE and ML-DSA for signatures."""
    ev = _make_evidence()

    # Signature asset -> ML-DSA-65
    sig_asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA-2048",
        primitive=Primitive.SIGNATURE,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[ev],
    )
    rec_sig = recommend_for_asset(sig_asset)
    assert rec_sig is not None
    assert rec_sig.target_algorithm == "ML-DSA-65"
    assert rec_sig.target_standard == "FIPS 204"

    # Key exchange asset -> ML-KEM-768
    ka_asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="ECDH",
        primitive=Primitive.KEY_AGREE,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[ev],
    )
    rec_ka = recommend_for_asset(ka_asset)
    assert rec_ka is not None
    assert rec_ka.target_algorithm == "ML-KEM-768"
    assert rec_ka.target_standard == "FIPS 203"

    # High security parameter set -> Level 5
    high_sig = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA-4096",
        primitive=Primitive.SIGNATURE,
        parameter_set="4096",
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[ev],
    )
    rec_high = recommend_for_asset(high_sig)
    assert rec_high is not None
    assert rec_high.target_algorithm == "ML-DSA-87"


def test_recommender_firmware_slh_dsa_caveat() -> None:
    """When firmware / boot signing is detected, recommender caveats the SLH-DSA gap."""
    ev = _make_evidence(locator="firmware_signer.py")
    fw_asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA-2048",
        primitive=Primitive.SIGNATURE,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[ev],
    )
    rec = recommend_for_asset(fw_asset)
    assert rec is not None
    assert "SLH-DSA" in rec.rationale
    assert "FIPS 205" in rec.rationale
    assert "fallback" in rec.rationale


def test_recommender_confidence_distinction() -> None:
    """Recommender cleanly distinguishes 'measured' vs 'estimated' confidence."""
    ev = _make_evidence()
    asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA-2048",
        primitive=Primitive.SIGNATURE,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[ev],
    )

    # 1. Without benchmark report -> estimated
    est_rec = recommend_for_asset(asset, benchmark_report=None)
    assert est_rec is not None
    assert est_rec.confidence == "estimated"
    assert "Estimated from published FIPS" in est_rec.source_note
    assert est_rec.latency_summary is None

    # 2. With benchmark report -> measured
    rep = run_benchmark(iterations=1, warmup=0)
    meas_rec = recommend_for_asset(asset, benchmark_report=rep)
    assert meas_rec is not None
    assert meas_rec.confidence == "measured"
    assert "Measured on" in meas_rec.source_note
    assert meas_rec.latency_summary is not None
    assert "p50" in meas_rec.latency_summary


def test_recommender_ignores_non_shor_assets() -> None:
    """Assets that are quantum-safe, Grover-weakened, or classically broken get no PQC recs."""
    ev = _make_evidence()
    aes = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="AES-256",
        primitive=Primitive.BLOCK_CIPHER,
        quantum_status=QuantumStatus.WEAKENED_BY_GROVER,
        evidence=[ev],
    )
    md5 = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="MD5",
        primitive=Primitive.HASH,
        quantum_status=QuantumStatus.BROKEN_CLASSICALLY,
        evidence=[ev],
    )
    assert recommend_for_asset(aes) is None
    assert recommend_for_asset(md5) is None


def test_recommendation_logic_determinism() -> None:
    """While timing numbers naturally vary across runs, the recommendation logic
    and exact byte sizes are 100% deterministic.
    """
    ev = _make_evidence()
    asset = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="ECDSA-P256",
        primitive=Primitive.SIGNATURE,
        quantum_status=QuantumStatus.BROKEN_BY_SHOR,
        evidence=[ev],
    )

    rec1 = recommend_for_asset(asset, benchmark_report=None)
    rec2 = recommend_for_asset(asset, benchmark_report=None)
    assert rec1 is not None and rec2 is not None
    assert rec1.target_algorithm == rec2.target_algorithm
    assert rec1.target_standard == rec2.target_standard
    assert rec1.size_delta_summary == rec2.size_delta_summary


def test_cli_benchmark_command(tmp_path: Path) -> None:
    """CLI subcommand `pratyaksha benchmark` runs and outputs formatted JSON."""
    out_file = tmp_path / "bench_report.json"
    res = runner.invoke(app, ["benchmark", "--iterations", "2", "--warmup", "1", "--output", str(out_file)])
    assert res.exit_code == 0
    assert "PRATYAKSHA Post-Quantum Cryptography Benchmark" in res.stdout
    assert out_file.is_file()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "metadata" in data
    assert "results" in data
    assert len(data["results"]) == 7


def test_cli_scan_with_benchmark_report(tmp_path: Path) -> None:
    """CLI scan with --benchmark-report attaches pratyaksha:property.recommendation.*"""
    bench_file = tmp_path / "bench.json"
    bench_res = runner.invoke(app, ["benchmark", "--iterations", "2", "--warmup", "1", "--output", str(bench_file)])
    assert bench_res.exit_code == 0

    target_dir = Path(__file__).resolve().parents[2] / "testdata" / "python"
    cbom_file = tmp_path / "output.cbom.json"

    scan_res = runner.invoke(app, ["scan", str(target_dir), "--benchmark-report", str(bench_file), "--output", str(cbom_file)])
    assert scan_res.exit_code == 0
    assert "PQC recommendations generated" in scan_res.stdout
    assert cbom_file.is_file()

    doc = json.loads(cbom_file.read_text(encoding="utf-8"))
    components = doc.get("components", [])
    rec_props = [
        prop
        for c in components
        for prop in c.get("properties", [])
        if prop["name"].startswith("pratyaksha:property.recommendation.")
    ]
    assert len(rec_props) > 0
    val = json.loads(rec_props[0]["value"])
    assert val["confidence"] == "measured"
    assert "Measured on" in val["sourceNote"]
