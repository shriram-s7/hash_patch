"""hash_patch/model/config_finding.py — Models for TLS configuration findings and
cross-layer contradictions (Pillar 4).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from hash_patch.model.evidence import Evidence


class TlsConfigFinding(BaseModel):
    """A TLS/SSL configuration policy observation from either a deployed config
    file (nginx, Apache, Java properties) or from source code intent (Python/Java).
    """

    model_config = ConfigDict(frozen=True)

    kind: Literal["protocol_version", "cipher_suite"]
    value: str
    allows_legacy: bool
    legacy_reasons: list[str] = Field(default_factory=list)
    severity: Literal["high", "medium", "none"] = "none"
    evidence: list[Evidence]
    source_file: str
    config_format: str  # "nginx" | "apache" | "java-properties" | "source-code-intent"


class ContradictionFinding(BaseModel):
    """A cross-layer policy contradiction: source code enforces a strict TLS
    policy, but deployed configuration within the same scan target permits
    legacy/weak protocols or cipher suites.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    source_intent: TlsConfigFinding
    deployed_config: TlsConfigFinding
    description: str
    severity: Literal["high", "medium"]


class AlgorithmDivergenceFinding(BaseModel):
    """A different kind of Pillar 4 contradiction: a policy/dispatch function
    within a package DECLARES (via a returned string/constant that resolves
    to a known algorithm name) that a call path uses algorithm family
    `declared_algorithm`, but the crypto API call actually reached along that
    same, unguarded control-flow path invokes `implemented_algorithm` — a
    different family. See hash_patch/analyze/algorithm_contradictions.py for
    the full method and its honesty caveats (same-package correlation only,
    call-reachability via direct textual call-site matching, not full
    interprocedural dataflow).
    """

    model_config = ConfigDict(frozen=True)

    id: str
    declared_algorithm: str
    implemented_algorithm: str
    declaring_function: str
    declaring_branch_condition: str | None
    declaring_evidence: Evidence
    call_site_function: str
    call_site_evidence: Evidence
    description: str
    severity: Literal["high", "medium"] = "high"
