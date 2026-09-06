from __future__ import annotations

import hashlib
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from hash_patch.model.evidence import Evidence

# "confirmed" = directly observed by a detector (the default for every real
# CryptoAsset). "inferred" = a name-pattern-only guess with no corroborating
# direct evidence of *which* algorithm produced the artefact (e.g. the
# blast-radius db_column fallback, see hash_patch/analyze/blast_radius.py) —
# per CLAUDE.md's "Name" section, this is never merged into the confirmed
# inventory as if it were equivalent; it must stay visibly distinguishable in
# the emitted CBOM (hash_patch:confidence property, see emit/cyclonedx.py).
Confidence = Literal["confirmed", "inferred", "HIGH", "LOW", "high", "low"]


class AssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class Primitive(str, Enum):
    DRBG = "drbg"
    MAC = "mac"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    SIGNATURE = "signature"
    HASH = "hash"
    PKE = "pke"
    XOF = "xof"
    KDF = "kdf"
    KEY_AGREE = "key-agree"
    KEM = "kem"
    AE = "ae"
    COMBINER = "combiner"
    OTHER = "other"
    UNKNOWN = "unknown"


class QuantumStatus(str, Enum):
    BROKEN_BY_SHOR = "broken-by-shor"
    WEAKENED_BY_GROVER = "weakened-by-grover"
    QUANTUM_SAFE = "quantum-safe"
    BROKEN_CLASSICALLY = "broken-classically"
    UNKNOWN = "unknown"
    # A cloud KMS/HSM client-side operation call (hash_patch/detect/
    # cloud_kms/) reveals NOTHING about which algorithm the cloud provider
    # actually uses server-side -- that is provider-side configuration,
    # invisible to static analysis of the calling code. Deliberately
    # distinct from every other status above (never guessed as
    # broken-by-shor/weakened-by-grover/quantum-safe/broken-classically,
    # and distinct from UNKNOWN too -- UNKNOWN means "we don't know yet but
    # could in principle", this means "this is architecturally not
    # observable from here at all"). Never a migration candidate (Pillar 5)
    # and never a blast-radius candidate (Pillar 3) -- both pillars only
    # ever consider BROKEN_BY_SHOR assets, so this status excludes cloud-key
    # findings from both automatically, with no separate exclusion logic
    # needed. See CLAUDE.md's "Cloud KMS" section.
    ALGORITHM_OPAQUE = "algorithm-opaque-provider-managed"


class Reachability(str, Enum):
    LIVE_EXTERNAL = "live-external"
    LIVE_INTERNAL = "live-internal"
    INERT = "inert"
    UNKNOWN = "unknown"


def derive_asset_id(
    asset_type: AssetType,
    name: str,
    parameter_set: str | None,
    mode: str | None,
    extra: str | None = None,
) -> str:
    """Deterministically derive a CryptoAsset id from its identity fields.

    Never use uuid4() or any time-based source here: the same logical asset
    must always yield the same id, across processes and across runs, so that
    scan output is byte-identical for identical input.
    """
    parts = [
        asset_type.value,
        name,
        parameter_set or "",
        mode or "",
    ]
    if extra:
        parts.append(extra)
    basis = "|".join(parts)
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]
    return f"crypto-asset:{digest}"


class CryptoAsset(BaseModel):
    model_config = ConfigDict(frozen=False)

    id: str
    asset_type: AssetType
    name: str
    primitive: Primitive
    parameter_set: str | None = None
    mode: str | None = None
    crypto_functions: list[str] = Field(default_factory=list)
    oid: str | None = None
    quantum_status: QuantumStatus = QuantumStatus.UNKNOWN
    nist_quantum_security_level: int | None = None
    reachability: Reachability = Reachability.UNKNOWN
    evidence: list[Evidence] = Field(default_factory=list)
    properties: dict[str, str] = Field(default_factory=dict)
    confidence: Confidence = "confirmed"
    finding_type: str = "OPERATION"

    @classmethod
    def create(
        cls,
        asset_type: AssetType,
        name: str,
        primitive: Primitive,
        parameter_set: str | None = None,
        mode: str | None = None,
        extra_id_seed: str | None = None,
        finding_type: str = "OPERATION",
        **kwargs: object,
    ) -> CryptoAsset:
        """Construct a CryptoAsset with its id derived deterministically."""
        seed = extra_id_seed
        if finding_type != "OPERATION":
            seed = f"{extra_id_seed}:{finding_type}" if extra_id_seed else finding_type
        asset_id = derive_asset_id(asset_type, name, parameter_set, mode, extra=seed)
        return cls(
            id=asset_id,
            asset_type=asset_type,
            name=name,
            primitive=primitive,
            parameter_set=parameter_set,
            mode=mode,
            finding_type=finding_type,
            **kwargs,
        )
