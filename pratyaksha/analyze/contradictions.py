"""pratyaksha/analyze/contradictions.py — Pillar 4: Cross-layer contradiction detection.

Analyzes pairs of source-side TLS intent findings and deployed configuration
findings within the same scan target. Detects contradictions where source code
declares a strict TLS policy (e.g. TLS 1.3 or TLS 1.2 minimum) but deployed
configuration (e.g. nginx.conf) allows deprecated / weak protocols or ciphers.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from pratyaksha.model.config_finding import ContradictionFinding, TlsConfigFinding


def _derive_contradiction_id(source_finding: TlsConfigFinding, config_finding: TlsConfigFinding) -> str:
    """Deterministically derive a stable ID for a contradiction finding."""
    src_ev = source_finding.evidence[0] if source_finding.evidence else None
    cfg_ev = config_finding.evidence[0] if config_finding.evidence else None
    src_part = f"{src_ev.locator}:{src_ev.line}" if src_ev else "src"
    cfg_part = f"{cfg_ev.locator}:{cfg_ev.line}" if cfg_ev else "cfg"
    seed = f"{src_part}|{cfg_part}|{source_finding.value}|{config_finding.value}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"contradiction-{digest}"


def _in_same_scope(path_a: Path, path_b: Path, target_root: Path | None) -> bool:
    """Determine whether two files share the same deployment/project scope.

    Rules:
    1. If they reside in the exact same directory, they are always in the same scope.
    2. If a target_root is provided:
       - If both files are directly in target_root, they share scope.
       - If target_root contains distinct subproject directories (e.g. test scenarios or services),
         files must belong to the same top-level subproject relative to target_root.
       - A config file in an isolated subdirectory with no source files does NOT correlate
         with source files in a sibling subdirectory.
    """
    if path_a.parent == path_b.parent:
        return True

    if target_root is not None:
        try:
            rel_a = path_a.resolve().relative_to(target_root.resolve())
            rel_b = path_b.resolve().relative_to(target_root.resolve())
            # If both are under subdirectories of target_root, check if first directory matches
            if len(rel_a.parts) > 1 and len(rel_b.parts) > 1:
                return rel_a.parts[0] == rel_b.parts[0]
            # If one is at root of target and other is deeper, only match if no other subprojects
            if len(rel_a.parts) == 1 or len(rel_b.parts) == 1:
                return True
        except ValueError:
            # Not relative to target_root
            pass

    return False


def run_contradiction_analysis(
    findings: list[TlsConfigFinding],
    target_root: Path | None = None,
) -> list[ContradictionFinding]:
    """Identify cross-layer policy contradictions between source-intent and deployed-config findings."""
    source_intents = [f for f in findings if f.config_format == "source-code-intent"]
    deployed_configs = [f for f in findings if f.config_format != "source-code-intent"]

    contradictions: list[ContradictionFinding] = []

    # Sort both lists for deterministic iteration
    sorted_sources = sorted(
        source_intents,
        key=lambda f: (f.source_file, f.evidence[0].line if f.evidence else 0),
    )
    sorted_configs = sorted(
        deployed_configs,
        key=lambda f: (f.source_file, f.evidence[0].line if f.evidence else 0),
    )

    for src in sorted_sources:
        # We only look for contradictions when source expresses a strict policy (does not allow legacy)
        if src.allows_legacy:
            continue

        src_path = Path(src.source_file)
        src_ev = src.evidence[0] if src.evidence else None
        src_loc = f"{src_ev.locator}:{src_ev.line}" if src_ev else src.source_file

        for cfg in sorted_configs:
            # A contradiction occurs when deployed config allows legacy
            if not cfg.allows_legacy:
                continue

            # Must match kind (protocol_version vs protocol_version, or cipher vs cipher)
            if src.kind != cfg.kind:
                continue

            cfg_path = Path(cfg.source_file)
            if not _in_same_scope(src_path, cfg_path, target_root):
                continue

            cfg_ev = cfg.evidence[0] if cfg.evidence else None
            cfg_loc = f"{cfg_ev.locator}:{cfg_ev.line}" if cfg_ev else cfg.source_file

            reasons_str = ", ".join(cfg.legacy_reasons) if cfg.legacy_reasons else cfg.value
            desc = (
                f"Source code at {src_loc} configures {src.value} minimum, but deployed "
                f"configuration at {cfg_loc} ({cfg.config_format}) permits {reasons_str} — "
                "the deployed configuration does not enforce the code's stated policy."
            )

            severity = "high" if cfg.severity == "high" else "medium"
            cid = _derive_contradiction_id(src, cfg)

            contradictions.append(
                ContradictionFinding(
                    id=cid,
                    source_intent=src,
                    deployed_config=cfg,
                    description=desc,
                    severity=severity,
                )
            )

    return sorted(contradictions, key=lambda c: c.id)
