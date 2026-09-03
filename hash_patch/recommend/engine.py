"""hash_patch/recommend/engine.py — PQC migration recommendation engine.

Recommends post-quantum replacements (FIPS 203 ML-KEM and FIPS 204 ML-DSA) for
cryptographic assets vulnerable to quantum attacks (BROKEN_BY_SHOR).

When a BenchmarkReport is provided, citations cite real measured latencies and
exact byte sizes on the host hardware (confidence="measured"). When absent, the
engine falls back to published FIPS specifications from rules/pqc_sizes.yaml
(confidence="estimated").
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, QuantumStatus
from hash_patch.model.benchmark import BenchmarkReport, RecommendationFinding

_PQC_SIZES_PATH = Path(__file__).resolve().parents[2] / "rules" / "pqc_sizes.yaml"


def _load_static_pqc_sizes() -> dict[str, Any]:
    if not _PQC_SIZES_PATH.is_file():
        return {}
    with _PQC_SIZES_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _is_signature_asset(asset: CryptoAsset) -> bool:
    """Determine if a CryptoAsset represents a digital signature primitive."""
    if asset.primitive == Primitive.SIGNATURE:
        return True
    if asset.asset_type == AssetType.CERTIFICATE:
        return True
    name = asset.name.lower()
    return any(s in name for s in ("ecdsa", "ed25519", "dsa", "sign")) or (
        "rsa" in name and asset.primitive != Primitive.PKE
    )


def _is_long_lived_or_firmware(asset: CryptoAsset) -> bool:
    """Check if an asset indicates long-lived firmware, boot, or secure-hardware signing."""
    ev_snippets = " ".join(e.snippet or "" for e in asset.evidence)
    locators = " ".join(e.locator for e in asset.evidence)
    text_corpus = f"{asset.name} {ev_snippets} {locators}".lower()
    keywords = ("firmware", "boot", "ota", "rom", "uefi", "secure_boot", "hardware", "device")
    return any(kw in text_corpus for kw in keywords)


def _format_size_delta(
    pqc_pub: int,
    pqc_payload: int,
    payload_name: str,
    classical_pub: int | None,
    classical_payload: int | None,
    classical_name: str,
) -> str:
    """Format comparative byte sizes and percentage increases."""
    if classical_pub is not None and classical_payload is not None:
        pub_pct = ((pqc_pub - classical_pub) / classical_pub) * 100.0
        payload_pct = ((pqc_payload - classical_payload) / classical_payload) * 100.0
        return (
            f"Public key: {pqc_pub:,}B ({pub_pct:+.0f}% vs {classical_name} {classical_pub:,}B); "
            f"{payload_name}: {pqc_payload:,}B ({payload_pct:+.0f}% vs {classical_name} {classical_payload:,}B)"
        )
    return f"Public key: {pqc_pub:,}B; {payload_name}: {pqc_payload:,}B"


def recommend_for_asset(
    asset: CryptoAsset,
    benchmark_report: BenchmarkReport | None = None,
) -> RecommendationFinding | None:
    """Generate a migration recommendation for a single CryptoAsset.

    Only assets with QuantumStatus.BROKEN_BY_SHOR are eligible for PQC migration.
    Returns None for Grover-weakened (e.g. AES) or classically broken (e.g. MD5) assets.
    """
    if asset.quantum_status != QuantumStatus.BROKEN_BY_SHOR:
        return None

    name = asset.name
    name_lower = name.lower()
    is_sig = _is_signature_asset(asset)
    is_firmware = _is_long_lived_or_firmware(asset)

    # Determine parameter-set security level (Level 3 default, Level 5 for high security)
    is_level_5 = False
    if asset.parameter_set:
        param_lower = asset.parameter_set.lower()
        if any(h in param_lower for h in ("4096", "521", "384")):
            is_level_5 = True

    if is_sig:
        target_algo = "ML-DSA-87" if is_level_5 else "ML-DSA-65"
        target_std = "FIPS 204"
        classical_name = "RSA-2048" if "rsa" in name_lower else "ECDSA-P256"
        payload_name = "Signature"

        if is_firmware:
            rationale = (
                f"Replace {name} with {target_algo} ({target_std}). "
                "NOTE: SLH-DSA (FIPS 205, stateless hash-based signatures) is the textbook-correct "
                "choice for long-lived firmware/code signing due to minimal mathematical assumptions, "
                "but is not available in the installed cryptography library. Recommending "
                f"{target_algo} as the available high-assurance fallback."
            )
        else:
            rationale = (
                f"Replace {name} with {target_algo} ({target_std}), "
                f"providing NIST Category {5 if is_level_5 else 3} post-quantum signature security."
            )
    else:
        # Key agreement or PKE
        target_algo = "ML-KEM-1024" if is_level_5 else "ML-KEM-768"
        target_std = "FIPS 203"
        classical_name = "ECDSA-P256"  # P-256 / X25519 equivalent
        payload_name = "Ciphertext"
        rationale = (
            f"Replace {name} with {target_algo} ({target_std}), "
            f"providing NIST Category {5 if is_level_5 else 3} post-quantum key encapsulation. "
            "(ML-KEM-512 is not recommended for production deployments)."
        )

    # Build measured or estimated metrics
    if benchmark_report is not None:
        pqc_bench = benchmark_report.get_result(target_algo)
        class_bench = benchmark_report.get_result(classical_name)

        if pqc_bench is not None:
            confidence = "measured"
            date_str = benchmark_report.metadata.timestamp.strftime("%Y-%m-%d")
            source_note = (
                f"Measured on {benchmark_report.metadata.platform} on {date_str} "
                f"({benchmark_report.metadata.iterations} iterations)"
            )

            pqc_pub = pqc_bench.byte_sizes.public_key_bytes
            pqc_payload = (
                pqc_bench.byte_sizes.signature_bytes
                if is_sig
                else pqc_bench.byte_sizes.ciphertext_bytes or 0
            )

            class_pub = class_bench.byte_sizes.public_key_bytes if class_bench else None
            class_payload = (
                class_bench.byte_sizes.signature_bytes if class_bench and is_sig else None
            )

            size_summary = _format_size_delta(
                pqc_pub, pqc_payload, payload_name, class_pub, class_payload, classical_name
            )

            # Format latency summary
            lat_parts = []
            for op, timing in sorted(pqc_bench.timings.items()):
                lat_parts.append(f"{op}: {timing.p50_ms:.2f}ms (p50)")

            if class_bench is not None:
                # Add comparative ratio for main operation
                main_pqc_op = "sign" if is_sig else "encapsulate"
                main_class_op = "sign" if is_sig else "keygen"
                if main_pqc_op in pqc_bench.timings and main_class_op in class_bench.timings:
                    pqc_p50 = pqc_bench.timings[main_pqc_op].p50_ms
                    class_p50 = class_bench.timings[main_class_op].p50_ms
                    if class_p50 > 0:
                        ratio = pqc_p50 / class_p50
                        rel_str = f"{ratio:.1f}x slower" if ratio >= 1.0 else f"{1.0/ratio:.1f}x faster"
                        lat_parts.append(f"({main_pqc_op} is {rel_str} vs {classical_name} {main_class_op})")

            latency_summary = ", ".join(lat_parts)

            return RecommendationFinding(
                asset_id=asset.id,
                source_primitive=name,
                target_algorithm=target_algo,
                target_standard=target_std,
                confidence=confidence,
                source_note=source_note,
                rationale=rationale,
                latency_summary=latency_summary,
                size_delta_summary=size_summary,
            )

    # Fallback to static table (estimated)
    static_data = _load_static_pqc_sizes()
    pqc_key = target_algo.lower().replace("-", "_")
    pqc_entry = static_data.get("pqc", {}).get(pqc_key, {})

    pqc_pub = pqc_entry.get("pubkey_bytes", 0)
    pqc_payload = (
        pqc_entry.get("signature_bytes", 0) if is_sig else pqc_entry.get("ciphertext_bytes", 0)
    )

    class_key = classical_name.lower().replace("-", "_")
    class_entry = static_data.get("classical", {}).get(class_key, {})
    class_pub = class_entry.get("pubkey_bytes")
    class_payload = (
        class_entry.get("signature_bytes") if is_sig else class_entry.get("signature_bytes_max")
    )

    size_summary = _format_size_delta(
        pqc_pub, pqc_payload, payload_name, class_pub, class_payload, classical_name
    )

    return RecommendationFinding(
        asset_id=asset.id,
        source_primitive=name,
        target_algorithm=target_algo,
        target_standard=target_std,
        confidence="estimated",
        source_note="Estimated from published FIPS specifications, not measured on this hardware",
        rationale=rationale,
        latency_summary=None,
        size_delta_summary=size_summary,
    )


def generate_recommendations(
    assets: list[CryptoAsset],
    benchmark_report: BenchmarkReport | None = None,
) -> list[RecommendationFinding]:
    """Generate PQC recommendations for all BROKEN_BY_SHOR assets in the list."""
    findings: list[RecommendationFinding] = []
    for asset in assets:
        rec = recommend_for_asset(asset, benchmark_report)
        if rec is not None:
            findings.append(rec)
    return findings
