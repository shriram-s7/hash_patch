from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from hash_patch.analyze.cbom_reader import read_candidates, read_reference_year
from hash_patch.analyze.optimizer import run_optimizer
from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
]

app = FastAPI(
    title="Hash Patch Service",
    description="Local dev HTTP service for Hash Patch CBOM scanner",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    path: str


class OptimizeRequest(BaseModel):
    cbom: dict[str, Any] | None = None
    budget_days: float = 5.0
    parallelism: int = 1


@app.get("/api/health")
def health() -> dict[str, str]:
    """Trivial health check endpoint."""
    return {"status": "ok"}


@app.post("/api/scan")
def scan_directory(req: ScanRequest) -> dict[str, Any]:
    """Scan a local directory and return the resulting CycloneDX 1.6 CBOM directly."""
    raw_path = req.path.strip() if req.path else ""
    if not raw_path:
        raise HTTPException(status_code=400, detail="Path cannot be empty.")

    target_path = Path(raw_path)
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {raw_path}")
    if not target_path.is_dir():
        raise HTTPException(status_code=400, detail=f"Path is not a directory: {raw_path}")

    try:
        result = run_scan(target_path)
        doc = to_cyclonedx(result)
        return doc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc


@app.post("/api/optimize")
def optimize_cbom(req: OptimizeRequest) -> dict[str, Any]:
    """Run the real Pillar-5 migration optimiser (hash_patch/analyze/optimizer.py)
    against a CBOM document supplied directly in the request body -- the CBOM
    currently loaded in the UI, whether it came from a live folder scan or an
    uploaded file, with no separate file on disk required. Reuses
    `read_candidates` / `read_reference_year` / `run_optimizer` exactly as
    `hash-patch optimize` (hash_patch/cli.py::run_optimize) does; the only
    difference is the CBOM comes from the request body instead of a file path.
    """
    if req.cbom is None:
        raise HTTPException(status_code=400, detail="Request body must include a 'cbom' document.")
    if req.budget_days <= 0:
        raise HTTPException(status_code=400, detail="budget_days must be > 0")
    if req.parallelism < 1:
        raise HTTPException(status_code=400, detail="parallelism must be >= 1")

    try:
        candidates, excluded_count = read_candidates(req.cbom)
        reference_year = read_reference_year(req.cbom)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid CBOM document: {exc}") from exc

    try:
        report = run_optimizer(
            candidates,
            budget_days=req.budget_days,
            parallelism=req.parallelism,
            reference_year=reference_year,
            excluded_count=excluded_count,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Optimization failed: {exc}") from exc

    return report.model_dump(mode="json")
