from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from hash_patch.analyze.cbom_reader import read_candidates, read_reference_year
from hash_patch.analyze.optimizer import run_optimizer
from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.grounding import ground_question
from hash_patch.qa.ollama_client import REFUSAL_MESSAGE, ask_ollama
from hash_patch.qa.registry import GLOBAL_SCAN_REGISTRY, ScanRecord

# Files above this size are refused by /api/file-content rather than read in
# full into memory and shipped to the browser — this endpoint is for showing
# source code, not for serving arbitrary large files.
_MAX_FILE_CONTENT_BYTES = 5 * 1024 * 1024

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


class AskRequest(BaseModel):
    scan_id: str | None = None
    cbom: dict[str, Any] | None = None
    question: str
    plan: dict[str, Any] | None = None
    conversation_id: str | None = None
    session_id: str | None = None
    conversation_history: list[dict[str, str]] | None = None


class AnswerHighlight(BaseModel):
    type: str  # "CRITICAL", "HIGH", "WARNING", "SAFE", "INFO", "UNKNOWN"
    label: str
    source_id: str | None = None
    description: str | None = None


class AskResponse(BaseModel):
    answer: str
    grounded: bool
    category: str
    matched_findings: list[str] = []
    sources: list[str] = []
    scan_id: str | None = None
    highlights: list[AnswerHighlight] = []


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
    from hash_patch.detect.container.formats import probe_container_target
    if target_path.is_file():
        if not probe_container_target(target_path):
            raise HTTPException(status_code=400, detail=f"Path is not a directory: {raw_path}")
    elif not target_path.is_dir():
        raise HTTPException(status_code=400, detail=f"Path is not a directory: {raw_path}")

    try:
        result = run_scan(target_path)
        doc = to_cyclonedx(result)
        GLOBAL_SCAN_REGISTRY.register_scan(doc)
        return doc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc


@app.get("/api/file-content")
def file_content(
    path: str = Query(..., description="Absolute path of the file to read"),
    root: str = Query(..., description="Absolute path of the scan target directory this file must be under"),
) -> dict[str, str]:
    """Return the real content of a file from the local filesystem, for the
    Repository tab's code viewer.

    Strictly scoped: `path` must resolve to a location at or under `root`
    (the directory the current scan actually targeted). This is a local,
    single-user dev tool with no auth, so `root` is client-supplied like
    `/api/scan`'s target path already is -- but the containment check below
    means this can only ever read files inside whatever directory the user
    themselves already asked to scan; it is never a general-purpose
    arbitrary-file-read endpoint. Path traversal (`..`) is defeated by
    resolving both paths before comparing, not by string matching.
    """
    raw_root = root.strip() if root else ""
    raw_path = path.strip() if path else ""
    if not raw_root or not raw_path:
        raise HTTPException(status_code=400, detail="Both 'path' and 'root' are required.")

    try:
        root_resolved = Path(raw_root).resolve(strict=True)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"root does not exist: {raw_root}") from exc
    if not root_resolved.is_dir():
        raise HTTPException(status_code=400, detail=f"root is not a directory: {raw_root}")

    try:
        path_resolved = Path(raw_path).resolve(strict=True)
    except OSError as exc:
        raise HTTPException(status_code=404, detail=f"File not found: {raw_path}") from exc

    if path_resolved != root_resolved and root_resolved not in path_resolved.parents:
        raise HTTPException(status_code=403, detail="Requested path is outside the scanned target directory.")

    if not path_resolved.is_file():
        raise HTTPException(status_code=400, detail=f"Not a file: {raw_path}")

    try:
        size = path_resolved.stat().st_size
    except OSError as exc:
        raise HTTPException(status_code=404, detail=f"File not found: {raw_path}") from exc
    if size > _MAX_FILE_CONTENT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large to preview ({size} bytes > {_MAX_FILE_CONTENT_BYTES} byte limit).",
        )

    try:
        content = path_resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {exc}") from exc

    return {"path": str(path_resolved), "content": content}


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


_SESSIONS: dict[str, Any] = {}


@app.post("/api/ask")
def ask_about_scan(req: AskRequest) -> AskResponse:
    """Grounded Q&A over the CURRENT scan's own CBOM (and, optionally, its
    Pillar 5 migration plan) via a local Ollama model.
    """
    question = req.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="question cannot be empty.")

    from hash_patch.qa.query import ConversationContext, QueryAnalyzer

    # 1. Resolve Scan Record
    record: ScanRecord | None = None
    if req.scan_id:
        record = GLOBAL_SCAN_REGISTRY.get_scan(req.scan_id)
        if record is None:
            # If client provided cbom as fallback alongside scan_id, register it
            if req.cbom is not None:
                record = GLOBAL_SCAN_REGISTRY.register_scan(req.cbom, plan=req.plan, scan_id=req.scan_id)
            else:
                raise HTTPException(
                    status_code=404,
                    detail=f"Scan ID '{req.scan_id}' not found in registry. Please rescan or provide 'cbom' in the request payload.",
                )
    elif req.cbom is not None:
        # Legacy path: register/resolve the provided CBOM
        record = GLOBAL_SCAN_REGISTRY.register_scan(req.cbom, plan=req.plan)
    else:
        raise HTTPException(
            status_code=400,
            detail="Either 'scan_id' or 'cbom' must be provided.",
        )

    # 2. Update plan on the record if client provided a newer plan
    if req.plan is not None and record.plan != req.plan:
        record.plan = req.plan
        record.index = None

    # 3. Resolve scan-scoped conversation
    conv_id = req.conversation_id or req.session_id
    session: ConversationContext | None = None
    if conv_id:
        session = GLOBAL_SCAN_REGISTRY.get_conversation(record.scan_id, conv_id)

    # 4. Ground question using the resolved scan record
    result = ground_question(question, record.cbom, record.plan, conversation=session)
    if not result.grounded:
        return AskResponse(
            answer=REFUSAL_MESSAGE,
            grounded=False,
            category=result.category,
            matched_findings=result.matched_findings,
            sources=result.sources,
            scan_id=record.scan_id,
        )

    if result.category in ("known_ungroundable", "conversational"):
        ans = result.context or REFUSAL_MESSAGE
        if session:
            pq = QueryAnalyzer.parse(question, set(result.matched_findings), session)
            session.update(question, ans, pq)
        return AskResponse(
            answer=ans,
            grounded=True,
            category=result.category,
            matched_findings=result.matched_findings,
            sources=result.sources,
            scan_id=record.scan_id,
        )

    try:
        answer = ask_ollama(
            question,
            result.context or "",
            conversation_history=req.conversation_history,
            evidence_package=result.evidence_package,
            query=result.query,
        )
    except httpx.HTTPError:
        answer = f"[Local Ollama model unavailable — showing verified scan evidence]\n\n{result.context or ''}"

    if session:
        pq = result.query or QueryAnalyzer.parse(question, set(result.matched_findings), session)
        session.update(question, answer, pq)

    # Compute grounded semantic highlights from EvidencePackage
    highlights: list[AnswerHighlight] = []
    pkg = result.evidence_package
    if pkg is not None:
        # Check operations for live-external & quantum vulnerability
        for f in getattr(pkg, "findings", []):
            if getattr(f, "is_operation", True):
                if getattr(f, "quantum_status", None) == "broken-by-shor":
                    highlights.append(
                        AnswerHighlight(
                            type="CRITICAL",
                            label=f"CRQC Vulnerable: {f.name}",
                            source_id=f"finding:{f.id}",
                            description=f"{f.name} is broken by Shor's algorithm",
                        )
                    )
                elif getattr(f, "quantum_status", None) == "broken-classically":
                    highlights.append(
                        AnswerHighlight(
                            type="HIGH",
                            label=f"Classically Broken: {f.name}",
                            source_id=f"finding:{f.id}",
                            description=f"{f.name} is insecure against classical cryptanalysis",
                        )
                    )
                elif getattr(f, "quantum_status", None) == "quantum-safe":
                    highlights.append(
                        AnswerHighlight(
                            type="SAFE",
                            label=f"Quantum-Safe: {f.name}",
                            source_id=f"finding:{f.id}",
                            description=f"{f.name} is believed quantum-safe",
                        )
                    )

                if getattr(f, "reachability", None) == "live-external":
                    highlights.append(
                        AnswerHighlight(
                            type="WARNING",
                            label=f"Externally Reachable: {f.name}",
                            source_id=f"finding:{f.id}",
                            description=f"{f.name} is reachable via external network call",
                        )
                    )
                elif getattr(f, "reachability", None) == "unknown":
                    highlights.append(
                        AnswerHighlight(
                            type="UNKNOWN",
                            label=f"Unknown Reachability: {f.name}",
                            source_id=f"finding:{f.id}",
                            description=f"Reachability for {f.name} could not be proven statically",
                        )
                    )

        # Blast radius overflow highlights
        for b in getattr(pkg, "blast_radius", []):
            if getattr(b, "overflow_bytes", 0) > 0:
                highlights.append(
                    AnswerHighlight(
                        type="CRITICAL" if b.severity == "critical" else "HIGH",
                        label=f"Buffer Overflow: {b.buffer_name} (+{b.overflow_bytes}B)",
                        source_id=f"blast_radius:{b.buffer_name}:{b.asset_name}",
                        description=f"PQC replacement overflows declared buffer '{b.buffer_name}' by {b.overflow_bytes} bytes",
                    )
                )

        # Top migration priority candidate
        top_cand = getattr(pkg, "migration", {}).get("top_candidate")
        if top_cand:
            highlights.append(
                AnswerHighlight(
                    type="HIGH",
                    label=f"Top Migration Priority: {top_cand}",
                    source_id=f"migration:{top_cand}",
                    description=f"{top_cand} is ranked #1 in authoritative migration sequence",
                )
            )

    # De-duplicate highlights preserving order (limit to top 6)
    seen_hl = set()
    deduped_highlights: list[AnswerHighlight] = []
    for h in highlights:
        key = (h.type, h.label)
        if key not in seen_hl:
            seen_hl.add(key)
            deduped_highlights.append(h)
        if len(deduped_highlights) >= 6:
            break

    return AskResponse(
        answer=answer,
        grounded=True,
        category=result.category,
        matched_findings=result.matched_findings,
        sources=result.sources,
        scan_id=record.scan_id,
        highlights=deduped_highlights,
    )
