from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from hash_patch.model.evidence import Evidence

SizeConstraintKind = Literal["stack_buffer", "heap_alloc", "db_column"]
BlastRadiusLanguage = Literal["c", "sql", "go", "java", "python"]
Severity = Literal["low", "medium", "high", "critical"]


class SizeConstraint(BaseModel):
    """A statically declared size limit on something that might hold
    cryptographic material — a fixed buffer, a heap allocation with a
    literal size, or a fixed-width database column.

    This is deliberately NOT a CryptoAsset: it isn't a cryptographic asset,
    it's a size constraint that MIGHT apply to one. Correlating it with an
    actual CryptoAsset (same file, plausible primitive match) is
    hash_patch/analyze/blast_radius.py's job, not the detectors'.

    Only ever constructed when declared_bytes is a resolvable literal — see
    hash_patch/detect/blast_radius/c_buffers.py and .../sql_ddl.py: an
    unresolved size (a variable, an un-#define'd macro, an untyped TEXT/BLOB
    column) means no SizeConstraint is emitted at all, never a guessed one.
    """

    model_config = ConfigDict(frozen=False)

    kind: SizeConstraintKind
    name: str
    declared_bytes: int
    evidence: list[Evidence] = Field(default_factory=list)
    language: BlastRadiusLanguage
    inferred_field: Literal["signature", "pubkey", "ciphertext"] | None = None


class BlastRadiusFinding(BaseModel):
    """A prediction that migrating `asset_name`/`asset_id` (a CryptoAsset
    whose quantum_status is BROKEN_BY_SHOR) to its PQC replacement will
    overflow `size_constraint`.

    `estimated_effort_days` is a coarse heuristic placeholder, NOT derived
    from real migration data — see
    hash_patch/analyze/blast_radius.py::_estimate_effort_days and
    docs/BLAST_RADIUS.md.
    """

    model_config = ConfigDict(frozen=False)

    asset_id: str
    asset_name: str
    size_constraint: SizeConstraint
    pqc_replacement_name: str  # e.g. "ML-DSA-65", the rules/pqc_sizes.yaml key
    classical_bytes: int
    pqc_bytes: int
    overflow_bytes: int
    severity: Severity
    estimated_effort_days: float
