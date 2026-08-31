from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Iterator

import typer

from pratyaksha import __version__
from pratyaksha.analyze.reachability import apply_reachability
from pratyaksha.detect import registry  # triggers side-effect detector registration
from pratyaksha.detect.base import Detector
from pratyaksha.emit import render_cbom_json, to_cyclonedx, validate_cbom
from pratyaksha.model.findings import ScanResult

app = typer.Typer(name="pratyaksha")


@app.command()
def version() -> None:
    """Print the tool version."""
    typer.echo(f"pratyaksha {__version__}")


def _quantum_status_summary(result: ScanResult) -> str:
    if not result.assets:
        return "0 assets"
    counts = Counter(asset.quantum_status.value for asset in result.assets)
    breakdown = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
    return f"{len(result.assets)} assets ({breakdown})"


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
    # model's default Reachability.UNKNOWN — see pratyaksha/detect/go.py and
    # pratyaksha/detect/c.py). Runs over the whole scanned file set so calls
    # across files in the same target are resolved, per
    # pratyaksha/analyze/reachability.py.
    apply_reachability(result.assets, scanned_files)

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
) -> None:
    """Scan PATH for cryptographic assets and emit a CycloneDX 1.6 CBOM.

    PATH may be a single file or a directory. Directories are scanned
    recursively; each file is routed to whichever registered detector
    supports it (matched by file extension).
    """
    result = run_scan(path)
    doc = to_cyclonedx(result)

    if validate:
        errors = validate_cbom(doc)
        if errors:
            for error in errors:
                typer.echo(f"schema validation error: {error}", err=True)
            raise typer.Exit(code=1)

    summary = _quantum_status_summary(result)
    if output is not None:
        output.write_text(render_cbom_json(doc), encoding="utf-8")
        typer.echo(f"wrote CBOM to {output}; {summary}")
    else:
        typer.echo(summary)


if __name__ == "__main__":
    app()
