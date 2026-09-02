"""pratyaksha/model/config_finding.py — Models for TLS configuration findings and
cross-layer contradictions (Pillar 4).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from pratyaksha.model.evidence import Evidence


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
