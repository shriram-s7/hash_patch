from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from hash_patch import __version__
from hash_patch.analyze.blast_radius import (
    is_inferred_finding,
    primitive_for_replacement,
    run_blast_radius,
)
from hash_patch.analyze.cbom_reader import read_candidates, read_reference_year
from hash_patch.analyze.optimizer import run_optimizer
from hash_patch.analyze.reachability import apply_reachability
from hash_patch.analyze.shelf_life import run_shelf_life
from hash_patch.detect import registry  # triggers side-effect detector registration
from hash_patch.detect.base import Detector
from hash_patch.emit import render_cbom_json, to_cyclonedx, validate_cbom
from hash_patch.model.assets import AssetType, CryptoAsset, QuantumStatus
from hash_patch.model.benchmark import RecommendationFinding
from hash_patch.model.blast_radius import BlastRadiusFinding
from hash_patch.model.config_finding import ContradictionFinding, TlsConfigFinding
from hash_patch.model.findings import ScanResult
from hash_patch.model.optimizer import OptimizationReport
from hash_patch.model.shelf_life import ShelfLifeFinding

app = typer.Typer(name="hash-patch")


@app.command()
def version() -> None:
    """Print the tool version."""
    typer.echo(f"hash-patch {__version__}")


def _quantum_status_summary(result: ScanResult) -> str:
    if not result.assets:
        return "0 assets"
    counts = Counter(asset.quantum_status.value for asset in result.assets)
    breakdown = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
    return f"{len(result.assets)} assets ({breakdown})"


def _blast_radius_summary(findings: list[BlastRadiusFinding]) -> str:
    total_days = sum(f.estimated_effort_days for f in findings)
    return f"{len(findings)} blast-radius findings, estimated {total_days:g} engineer-days"


def _shelf_life_summary(findings: list[ShelfLifeFinding]) -> str:
    if not findings:
        return "0 shelf-life findings"
    longest = max(findings, key=lambda f: (f.shelf_life_years, f.category))
    return f"{len(findings)} shelf-life findings (longest: {longest.shelf_life_years} years, {longest.category})"


def _contradictions_summary(findings: list[ContradictionFinding]) -> str:
    high_count = sum(1 for f in findings if f.severity == "high")
    return f"{len(findings)} cross-layer contradictions found ({high_count} high severity)"


def _recommendation_property(finding: RecommendationFinding) -> tuple[str, str]:
    key = f"recommendation.{finding.target_algorithm}"
    val = json.dumps(
        {
            "targetAlgorithm": finding.target_algorithm,
            "targetStandard": finding.target_standard,
            "confidence": finding.confidence,
            "sourceNote": finding.source_note,
            "rationale": finding.rationale,
            "latencySummary": finding.latency_summary,
            "sizeDeltaSummary": finding.size_delta_summary,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return key, val


def _attach_recommendation_properties(
    result: ScanResult, recs: list[RecommendationFinding]
) -> None:
    by_id = {asset.id: asset for asset in result.assets}
    for rec in recs:
        asset = by_id.get(rec.asset_id)
        if asset is None:
            continue
        key, val = _recommendation_property(rec)
        asset.properties[key] = val


def _shelf_life_property(finding: ShelfLifeFinding) -> tuple[str, str]:
    ev = finding.evidence[0]
    key = f"shelfLife.{finding.category}"
    value = json.dumps(
        {
            "shelfLifeYears": finding.shelf_life_years,
            "statutoryBasis": finding.statutory_basis,
            "confidence": finding.confidence,
            "moscaNote": finding.mosca_note,
            "locator": ev.locator,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return key, value


def _attach_shelf_life_properties(result: ScanResult) -> None:
    """Mirror each shelf-life finding onto its correlated CBOM component's
    `properties` bag — the same `pratyaksha:property.<key>` namespacing
    CLAUDE.md documents (see hash_patch/emit/cyclonedx.py's field mapping)
    and `_attach_blast_radius_properties` already uses.

    Unlike blast radius, every ShelfLifeFinding always has a real,
    already-present CryptoAsset (hash_patch/analyze/shelf_life.py only ever
    emits a finding for an asset it was given) — there is no synthetic-
    component fallback path here.
    """
    by_id = {asset.id: asset for asset in result.assets}
    for finding in result.shelf_life_findings:
        asset = by_id.get(finding.asset_id)
        if asset is None:
            continue  # should never happen -- compute_shelf_life only emits findings for real, given assets
        key, value = _shelf_life_property(finding)
        asset.properties[key] = value


def _blast_radius_property(finding: BlastRadiusFinding) -> tuple[str, str]:
    ev = finding.size_constraint.evidence[0]
    key = f"blastRadius.{finding.size_constraint.kind}.{finding.size_constraint.name}.{ev.line}"
    value = json.dumps(
        {
            "declaredBytes": finding.size_constraint.declared_bytes,
            "classicalBytes": finding.classical_bytes,
            "pqcBytes": finding.pqc_bytes,
            "overflowBytes": finding.overflow_bytes,
            "pqcReplacement": finding.pqc_replacement_name,
            "severity": finding.severity,
            "estimatedEffortDays": finding.estimated_effort_days,
            "locator": ev.locator,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return key, value


def _synthetic_asset_for_inferred_finding(finding: BlastRadiusFinding) -> CryptoAsset:
    """Build a SYNTHETIC CryptoAsset for a db_column name-pattern-only
    fallback finding (see hash_patch/analyze/blast_radius.py's module
    docstring) so it's actually visible in the emitted CBOM instead of only
    existing in the CLI summary line / ScanResult.blast_radius_findings.

    Marked `confidence="inferred"` (never "confirmed" -- CLAUDE.md's "Name"
    section) since this isn't a direct observation of which algorithm
    produced the underlying data, only a name-pattern guess at what it would
    need to become. It still carries real Evidence -- the SizeConstraint's
    own file/line -- satisfying CLAUDE.md hard constraint #3.
    """
    return CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name=f"{finding.pqc_replacement_name} (inferred)",
        primitive=primitive_for_replacement(finding.pqc_replacement_name),
        quantum_status=QuantumStatus.UNKNOWN,
        confidence="inferred",
        evidence=list(finding.size_constraint.evidence),
    )


def _attach_blast_radius_properties(result: ScanResult) -> None:
    """Mirror each blast-radius finding onto a CBOM component's `properties`
    bag — the same `pratyaksha:property.<key>` CBOM namespacing pattern
    CLAUDE.md already documents for arbitrary asset-level data (see
    hash_patch/emit/cyclonedx.py's field mapping).

    A finding with a real correlated CryptoAsset (asset_id matches one in
    result.assets) is attached directly to it. A finding from
    analyze/blast_radius.py's db_column name-pattern-only fallback
    (`is_inferred_finding`) has no real CryptoAsset to attach to, so a
    SYNTHETIC component is built and added to result.assets instead
    (`confidence="inferred"`) -- otherwise it would be reported by the CLI
    summary line but invisible in the actual CBOM, defeating the point of a
    written report. See that module's docstring.
    """
    by_id = {asset.id: asset for asset in result.assets}
    for finding in result.blast_radius_findings:
        asset = by_id.get(finding.asset_id)
        if asset is None:
            if not is_inferred_finding(finding):
                continue
            synthetic = _synthetic_asset_for_inferred_finding(finding)
            result.add_asset(synthetic)
            asset = next(a for a in result.assets if a.id == synthetic.id)
            by_id[asset.id] = asset

        key, value = _blast_radius_property(finding)
        asset.properties[key] = value


def _iter_targets(path: Path) -> Iterator[Path]:
    """Yield every file reachable from path.

    - If path is a regular file, yield it directly.
    - If path is a directory, walk it recursively (sorted for determinism)
      and yield every regular file found.

    Detectors individually decide whether a given file is in-scope via their
    supports() method; this layer only enumerates; it does not filter.
    """
    if path.is_file():
        yield path
    elif path.is_dir():
        # rglob("*") returns all descendants; filter to regular files only.
        # Sorted for determinism: same directory always produces the same
        # file order, which matters for reproducible CBOM serial numbers.
        for child in sorted(path.rglob("*")):
            if child.is_file():
                yield child
    # Silently ignore anything that is neither a file nor a directory
    # (e.g. a broken symlink). Real errors (permission denied, etc.) will
    # propagate naturally from the detector's read_bytes() call.


def run_scan(path: Path, tool_version: str = __version__) -> ScanResult:
    """Core scan logic, separated from the CLI surface for testability.

    Returns a populated ScanResult without touching stdout or the filesystem
    (beyond reading input files). Callers own the output / printing.
    """
    result = ScanResult(
        target=str(path),
        assets=[],
        scan_started_at=datetime.now(UTC),
        tool_version=tool_version,
    )

    detectors: list[Detector] = registry.detectors()
    scanned_files: list[Path] = []

    for file_path in _iter_targets(path):
        scanned_files.append(file_path)
        for detector in detectors:
            if detector.supports(file_path):
                for asset in detector.detect(file_path):
                    result.add_asset(asset)

    # Reachability classification for Python/Java assets (Go/C keep the
    # model's default Reachability.UNKNOWN — see hash_patch/detect/go.py and
    # hash_patch/detect/c.py). Runs over the whole scanned file set so calls
    # across files in the same target are resolved, per
    # hash_patch/analyze/reachability.py.
    apply_reachability(result.assets, scanned_files)

    # Pillar 3 (Blast Radius): only does anything when the scanned file set
    # contains C and/or .sql files — see hash_patch/analyze/blast_radius.py.
    result.blast_radius_findings = run_blast_radius(result.assets, scanned_files)
    _attach_blast_radius_properties(result)

    # Pillar 2 (Shelf-Life Inference), Python/Java only — see
    # hash_patch/analyze/shelf_life.py. scan_started_at.date() is the one
    # wall-clock read CLAUDE.md permits (ScanResult.scan_started_at itself);
    # run_shelf_life/compute_shelf_life never read the clock themselves.
    result.shelf_life_findings = run_shelf_life(result.assets, result.scan_started_at.date())
    _attach_shelf_life_properties(result)

    # Pillar 4 (Cross-Layer Contradictions): scans deployed TLS configuration
    # files (nginx, apache, java properties) and source-code TLS intent (Python, Java),
    # then detects policy contradictions between them within the same target scope.
    from hash_patch.analyze.contradictions import run_contradiction_analysis
    from hash_patch.detect.config.source_tls_intent import detect_source_tls_intent
    from hash_patch.detect.config.tls_config import detect_tls_config_file

    tls_findings: list[TlsConfigFinding] = []
    for file_path in scanned_files:
        cfg_findings = detect_tls_config_file(file_path)
        if cfg_findings:
            tls_findings.extend(cfg_findings)
        src_intent = detect_source_tls_intent(file_path)
        if src_intent:
            tls_findings.extend(src_intent)

    result.tls_config_findings = tls_findings
    target_root = path if path.is_dir() else path.parent
    result.contradiction_findings = run_contradiction_analysis(tls_findings, target_root=target_root)

    return result


@app.command()
def scan(
    path: Path,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the CBOM as JSON to this path."),
    ] = None,
    validate: Annotated[
        bool,
        typer.Option(
            "--validate/--no-validate",
            help="Validate the emitted CBOM against the vendored CycloneDX 1.6 schema.",
        ),
    ] = True,
    benchmark_report: Annotated[
        Path | None,
        typer.Option(
            "--benchmark-report",
            help="Path to a benchmark report JSON to cite real measured latencies and sizes.",
        ),
    ] = None,
) -> None:
    """Scan PATH for cryptographic assets and emit a CycloneDX 1.6 CBOM.

    PATH may be a single file or a directory. Directories are scanned
    recursively; each file is routed to whichever registered detector
    supports it (matched by file extension).
    """
    result = run_scan(path)

    recs: list[RecommendationFinding] = []
    if benchmark_report is not None:
        from hash_patch.model.benchmark import BenchmarkReport
        from hash_patch.recommend import generate_recommendations

        report_data = BenchmarkReport.model_validate_json(
            benchmark_report.read_text(encoding="utf-8")
        )
        recs = generate_recommendations(result.assets, benchmark_report=report_data)
        _attach_recommendation_properties(result, recs)

    doc = to_cyclonedx(result)

    if validate:
        errors = validate_cbom(doc)
        if errors:
            for error in errors:
                typer.echo(f"schema validation error: {error}", err=True)
            raise typer.Exit(code=1)

    summary = _quantum_status_summary(result)
    blast_radius_summary = _blast_radius_summary(result.blast_radius_findings)
    shelf_life_summary = _shelf_life_summary(result.shelf_life_findings)
    contradictions_summary = _contradictions_summary(result.contradiction_findings)
    if output is not None:
        output.write_text(render_cbom_json(doc), encoding="utf-8")
        typer.echo(f"wrote CBOM to {output}; {summary}")
    else:
        typer.echo(summary)
    typer.echo(blast_radius_summary)
    typer.echo(shelf_life_summary)
    typer.echo(contradictions_summary)
    if benchmark_report is not None:
        meas_count = sum(1 for r in recs if r.confidence == "measured")
        typer.echo(f"{len(recs)} PQC recommendations generated ({meas_count} measured)")


def _optimize_summary(report: OptimizationReport) -> str:
    return (
        f"{report.candidate_count} migration candidates "
        f"({report.excluded_count} excluded -- not broken-by-shor)"
    )


def run_optimize(input_path: Path, budget_days: float, parallelism: int) -> OptimizationReport:
    """Core `pratyaksha optimize` logic, separated from the CLI surface for
    testability -- mirrors run_scan()'s split for the `scan` command.

    Reads an ALREADY-EMITTED CBOM (hash_patch/analyze/cbom_reader.py) --
    this command never re-scans source code itself, per Pillar 5's scope
    (docs/OPTIMISER.md): it operates purely on P1/P2/P3 data already
    attached to CryptoAsset findings by a prior `pratyaksha scan`.
    """
    doc = json.loads(input_path.read_text(encoding="utf-8"))
    candidates, excluded_count = read_candidates(doc)
    reference_year = read_reference_year(doc)
    return run_optimizer(
        candidates,
        budget_days=budget_days,
        parallelism=parallelism,
        reference_year=reference_year,
        excluded_count=excluded_count,
    )


@app.command()
def optimize(
    input: Annotated[
        Path, typer.Argument(help="Path to an already-emitted CBOM JSON file (from `pratyaksha scan`).")
    ],
    budget_days: Annotated[
        float, typer.Option("--budget-days", help="Migration budget, in engineer-days.")
    ],
    parallelism: Annotated[
        int, typer.Option("--parallelism", help="Number of findings that can be worked on in parallel.")
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the optimisation report as JSON to this path."),
    ] = None,
) -> None:
    """Read an already-emitted CBOM and produce a Pillar 5 migration plan.

    NOT part of `pratyaksha scan` -- this is a separate pipeline stage that
    operates on a CBOM already carrying P1 (reachability), P2 (shelf-life),
    and P3 (blast-radius) data. See docs/OPTIMISER.md for the risk-score
    formula, the greedy-vs-naive comparison, and the quantum-arrival
    scenario honesty disclaimer.
    """
    if budget_days <= 0:
        raise typer.BadParameter("--budget-days must be > 0")
    if parallelism < 1:
        raise typer.BadParameter("--parallelism must be >= 1")

    report = run_optimize(input, budget_days, parallelism)

    doc = json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    summary = _optimize_summary(report)
    if output is not None:
        output.write_text(doc, encoding="utf-8")
        typer.echo(f"wrote optimisation report to {output}; {summary}")
    else:
        typer.echo(summary)
    for scenario_result in report.scenarios:
        typer.echo(scenario_result.headline_message)


@app.command()
def keygen(
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", "-d", help="Directory to save generated keypair files."),
    ] = Path("."),
) -> None:
    """Generate a new ML-DSA-65 (FIPS 204) post-quantum keypair for signing CBOM files."""
    from hash_patch.sign import ALGORITHM_NAME, generate_keypair

    priv_path, pub_path = generate_keypair(output_dir)
    typer.echo(f"generated {ALGORITHM_NAME} keypair:")
    typer.echo(f"  private key: {priv_path}")
    typer.echo(f"  public key:  {pub_path}")


@app.command()
def sign(
    input: Annotated[
        Path,
        typer.Argument(help="Path to the CBOM JSON file to sign."),
    ],
    key: Annotated[
        Path,
        typer.Option("--key", "-k", help="Path to ML-DSA-65 private key file (.key)."),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write the detached signature (.sig) file."),
    ] = None,
) -> None:
    """Sign an already-emitted CBOM file using an ML-DSA-65 post-quantum private key."""
    from hash_patch.sign import ALGORITHM_NAME, sign_cbom_file

    try:
        sig_path = sign_cbom_file(input, key, output)
    except (ValueError, TypeError, OSError) as exc:
        typer.echo(f"signing error: {exc}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"signed CBOM {input} with {ALGORITHM_NAME}; wrote detached signature to {sig_path}")


@app.command()
def verify(
    input: Annotated[
        Path,
        typer.Argument(help="Path to the CBOM JSON file to verify."),
    ],
    sig: Annotated[
        Path,
        typer.Option("--sig", "-s", help="Path to detached signature file (.sig)."),
    ],
    key: Annotated[
        Path,
        typer.Option("--key", "-k", help="Path to ML-DSA-65 public key file (.pub)."),
    ],
) -> None:
    """Verify an already-emitted CBOM file against a detached ML-DSA-65 signature."""
    from hash_patch.sign import VerificationStatus, verify_cbom_file

    result = verify_cbom_file(input, sig, key)
    if result.status == VerificationStatus.VALID:
        typer.echo(f"VALID: {result.message}")
    elif result.status == VerificationStatus.INVALID:
        typer.echo(f"INVALID: {result.message}", err=True)
        raise typer.Exit(code=1)
    else:
        typer.echo(f"ERROR: {result.message}", err=True)
        raise typer.Exit(code=2)


@app.command()
def benchmark(
    iterations: Annotated[
        int,
        typer.Option("--iterations", "-n", help="Number of benchmark iterations per algorithm."),
    ] = 50,
    warmup: Annotated[
        int,
        typer.Option("--warmup", "-w", help="Number of warmup iterations to discard."),
    ] = 5,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write the full benchmark report JSON."),
    ] = None,
) -> None:
    """Benchmark real PQC and classical algorithm latencies and byte sizes on this host."""
    from rich.console import Console
    from rich.table import Table

    from hash_patch.benchmark.pqc_bench import run_benchmark

    console = Console()
    with console.status(
        f"[bold green]Running PQC benchmarks ({iterations} iterations, {warmup} warmup)..."
    ):
        report = run_benchmark(iterations=iterations, warmup=warmup)

    rsa_res = report.get_result("RSA-2048")
    ecdsa_res = report.get_result("ECDSA-P256")

    title_text = (
        "Hash Patch Post-Quantum Cryptography Benchmark\n"
        f"[dim]{report.metadata.platform} | Python {report.metadata.python_version} | "
        f"cryptography {report.metadata.cryptography_version} ({iterations} iterations)[/dim]"
    )
    table = Table(title=title_text, caption=report.disclaimer)
    table.add_column("Algorithm", style="cyan", no_wrap=True)
    table.add_column("Standard", style="magenta")
    table.add_column("Level", justify="center")
    table.add_column("Keygen (p50)", justify="right")
    table.add_column("Sign/Enc (p50)", justify="right")
    table.add_column("Verify/Dec (p50)", justify="right")
    table.add_column("Pubkey Size", justify="right")
    table.add_column("Sig / CT Size", justify="right")
    table.add_column("vs Classical Reference", style="green")

    for r in report.results:
        sec = f"Level {r.nist_security_level}" if r.nist_security_level else "-"
        kg_timing = r.timings.get("keygen")
        kg_str = f"{kg_timing.p50_ms:.2f} ms" if kg_timing else "-"

        if "sign" in r.timings:
            op2_str = f"{r.timings['sign'].p50_ms:.2f} ms (sign)"
        elif "encapsulate" in r.timings:
            op2_str = f"{r.timings['encapsulate'].p50_ms:.2f} ms (enc)"
        else:
            op2_str = "-"

        if "verify" in r.timings:
            op3_str = f"{r.timings['verify'].p50_ms:.2f} ms (ver)"
        elif "decapsulate" in r.timings:
            op3_str = f"{r.timings['decapsulate'].p50_ms:.2f} ms (dec)"
        else:
            op3_str = "-"

        pub_str = f"{r.byte_sizes.public_key_bytes:,} B"
        payload_bytes = r.byte_sizes.signature_bytes or r.byte_sizes.ciphertext_bytes or 0
        payload_str = f"{payload_bytes:,} B"

        comp_str = ""
        if r.is_pqc:
            if r.primitive_family == "signature" and rsa_res is not None:
                class_pub = rsa_res.byte_sizes.public_key_bytes
                class_sig = rsa_res.byte_sizes.signature_bytes or 1
                pub_mult = r.byte_sizes.public_key_bytes / class_pub
                sig_mult = payload_bytes / class_sig
                sign_pqc = r.timings.get("sign")
                sign_class = rsa_res.timings.get("sign")
                lat_mult = (
                    (sign_pqc.p50_ms / sign_class.p50_ms)
                    if (sign_pqc and sign_class and sign_class.p50_ms > 0)
                    else 1.0
                )
                comp_str = f"Pub {pub_mult:.1f}x, Sig {sig_mult:.1f}x, Sign {lat_mult:.1f}x vs RSA-2048"
            elif r.primitive_family == "key_agreement_or_pke" and ecdsa_res is not None:
                class_pub = ecdsa_res.byte_sizes.public_key_bytes
                class_ct = ecdsa_res.byte_sizes.signature_bytes or 1
                pub_mult = r.byte_sizes.public_key_bytes / class_pub
                ct_mult = payload_bytes / class_ct
                comp_str = f"Pub {pub_mult:.1f}x, CT {ct_mult:.1f}x vs P-256"
        else:
            comp_str = "[dim]Classical baseline[/dim]"

        table.add_row(
            r.algorithm,
            r.standard,
            sec,
            kg_str,
            op2_str,
            op3_str,
            pub_str,
            payload_str,
            comp_str,
        )

    console.print(table)

    if output is not None:
        output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"wrote benchmark report to {output}")


@app.command()
def serve(
    host: Annotated[
        str,
        typer.Option("--host", "-h", help="Host address to bind to."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Port to bind to."),
    ] = 8420,
) -> None:
    """Start local HTTP service for Hash Patch UI."""
    try:
        import uvicorn

        from hash_patch.service import app as service_app
    except ImportError as e:
        typer.echo(
            "Service dependencies not installed. Install with: pip install 'hash-patch[service]'",
            err=True,
        )
        raise typer.Exit(code=1) from e

    url = f"http://{host}:{port}"
    typer.echo(f"Starting Hash Patch service at {url}")
    uvicorn.run(service_app, host=host, port=port)


if __name__ == "__main__":
    app()

