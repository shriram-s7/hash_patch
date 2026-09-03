"""hash_patch/analyze/blast_radius.py — Pillar 3 (Blast Radius) computation.

Correlates SizeConstraint findings (hash_patch/detect/blast_radius/{c_buffers,
sql_ddl}.py) with CryptoAsset findings whose quantum_status is
BROKEN_BY_SHOR, and predicts whether migrating that asset to its PQC
replacement will overflow the declared size — see docs/BLAST_RADIUS.md for
the full method, the correlation heuristic's limits, and the effort-estimate
caveat.

**Correlation is same-file AND nearest-by-line.** A SizeConstraint is only
ever correlated with a CryptoAsset that (a) shares a locator (file path)
among its evidence — cross-file name-based correlation is a false-positive
machine, see CLAUDE.md's "Blast Radius" section — and, among same-file
candidates, (b) is the CLOSEST by line distance. A single file legitimately
containing two unrelated crypto operations (e.g. an RSA signing routine and
an Ed25519 keygen routine) must not let a buffer near one get credited to
the other just because both are technically "in the same file" — see
`_pick_correlated_asset` and docs/BLAST_RADIUS.md.

**Name-pattern-to-primitive matching.** A constraint's name-pattern `field`
(signature/pubkey/ciphertext, from rules/blast_radius_names.yaml) also
restricts which same-file assets are even candidates: only an asset whose
OWN primitive maps (via `_pqc_family_for_primitive`) to a PQC family for
which that field is a meaningful comparison (`_PQC_FIELDS`) is considered at
all. The PQC family used for a real correlated asset always comes from that
asset's real primitive — never a hardcoded default; `_FALLBACK_FAMILY_FOR_FIELD`
below is used ONLY by the db_column no-real-asset fallback (pass 2), never
for an asset that was actually correlated in pass 1. `field == "pubkey"` is
the one field meaningful for both families (a signature scheme and a
PKE/KEM both have public keys); ties at equal line distance prefer the
pke/key-agreement family, per `_FIELD_FAMILY_PRIORITY` — proximity still
decides in every case where the candidates aren't equidistant.

**`db_column` name-pattern-only fallback.** No detector in this codebase
produces a CryptoAsset from a `.sql` file (there is no SQL algorithm
detector), so a `db_column` SizeConstraint can never have a same-file
CryptoAsset to correlate against under the rule above. Rather than either
(a) silently never firing for SQL DDL at all, or (b) loosening same-file
correlation for db_column and reopening the exact cross-file false-positive
risk the rule exists to prevent, `compute_blast_radius` runs a SECOND pass:
any `db_column` constraint that found no same-file CryptoAsset gets a
finding synthesized directly from its own crypto-suggestive name pattern
(signature -> ML-DSA-65, ciphertext -> ML-KEM-768, pubkey -> the larger,
more conservative of the two), with a synthetic `asset_id`
(`"blast-radius-inferred:<field>"`) instead of a real CryptoAsset id. This
is weaker evidence than a real correlation and is documented as such — see
docs/BLAST_RADIUS.md. `hash_patch/cli.py` turns such a finding into a
SYNTHETIC CBOM component (`hash_patch:confidence = "inferred"`, never
`"confirmed"`) carrying the SizeConstraint's own evidence, rather than
mirroring it onto a real (nonexistent) CryptoAsset's properties — see
`hash_patch.cli._synthetic_asset_for_inferred_finding` and
`is_inferred_finding` below.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from hash_patch.detect.blast_radius.c_buffers import CBufferBlastRadiusDetector
from hash_patch.detect.blast_radius.names import NamePattern, load_name_patterns, match_name_pattern
from hash_patch.detect.blast_radius.sql_ddl import SqlDdlBlastRadiusDetector
from hash_patch.model.assets import CryptoAsset, Primitive, QuantumStatus
from hash_patch.model.blast_radius import BlastRadiusFinding, SizeConstraint

_PQC_SIZES_PATH = Path(__file__).resolve().parents[2] / "rules" / "pqc_sizes.yaml"

# Which pqc_sizes.yaml `pqc.<key>` fields correspond to which name-pattern
# `field` value, per PQC family. A field absent from this map for a given
# family (e.g. "ciphertext" for the signature family) is never correlated —
# it isn't a meaningful comparison, not a missing lookup to guess at.
_PQC_FIELDS: dict[str, dict[str, str]] = {
    "signature": {"signature": "signature_bytes", "pubkey": "pubkey_bytes"},
    "key_agreement_or_pke": {"pubkey": "pubkey_bytes", "ciphertext": "ciphertext_bytes"},
}

_DISPLAY_NAMES: dict[str, str] = {"ml_kem_768": "ML-KEM-768", "ml_dsa_65": "ML-DSA-65"}

# Reverse of _DISPLAY_NAMES, keyed the other way: which Primitive a SYNTHETIC
# (db_column-fallback, no real CryptoAsset) component should carry, based on
# the PQC replacement family name it was inferred against. Used only by
# hash_patch/cli.py when building that synthetic component — never for a
# real correlated asset, which always keeps its own detected primitive.
_PRIMITIVE_FOR_REPLACEMENT: dict[str, Primitive] = {
    "ML-DSA-65": Primitive.SIGNATURE,
    "ML-KEM-768": Primitive.KEM,
}

# field -> family -> tie-break priority (lower wins) when two same-file
# candidate assets of DIFFERENT families are equidistant from a constraint.
# Only "pubkey" is ever ambiguous between families (see _PQC_FIELDS); ties on
# "signature" or "ciphertext" can't happen since only one family maps them.
_FIELD_FAMILY_PRIORITY: dict[str, dict[str, int]] = {
    "pubkey": {"key_agreement_or_pke": 0, "signature": 1},
}

# Canonical CryptoAsset.name -> rules/pqc_sizes.yaml `classical.<key>`.
# Scope matches exactly the classical algorithms rules/pqc_sizes.yaml
# documents (RSA / ECDSA-P256 / Ed25519 / ECDH-P256, per this prompt's
# Step 1) — DSA, DH, X25519/X448, Ed448 and RSA padding-scheme variants
# (RSASSA-PSS, RSA-OAEP, RSA-PKCS1v15) have no classical reference size
# here and are simply never correlated (see docs/BLAST_RADIUS.md).
_CLASSICAL_RSA_BY_PARAM: dict[str, str] = {
    "2048": "rsa_2048",
    "3072": "rsa_3072",
    "4096": "rsa_4096",
}
_CLASSICAL_KEY_BY_NAME: dict[str, str] = {
    "ECDSA": "ecdsa_p256",
    "Ed25519": "ed25519",
    "ECDH": "ecdh_p256",
}

# Name-pattern `field` -> PQC family, used ONLY by the db_column
# name-pattern-only fallback pass (no real CryptoAsset primitive is known).
# "pubkey" is ambiguous between the two families; it defaults to
# "signature" because ML-DSA-65's pubkey (1952 bytes) is larger than
# ML-KEM-768's (1184 bytes) — the more conservative (larger overflow,
# never an understatement) of the two candidates.
_FALLBACK_FAMILY_FOR_FIELD: dict[str, str] = {
    "signature": "signature",
    "ciphertext": "key_agreement_or_pke",
    "pubkey": "signature",
}

_INFERRED_ASSET_ID_PREFIX = "blast-radius-inferred:"


def _load_pqc_sizes(path: Path = _PQC_SIZES_PATH) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh)
    return data


def _normalize_locator(locator: str) -> str:
    return locator.replace("\\", "/")


def _pqc_family_for_primitive(primitive: Primitive) -> str | None:
    if primitive == Primitive.SIGNATURE:
        return "signature"
    if primitive in (Primitive.PKE, Primitive.KEY_AGREE, Primitive.KEM):
        return "key_agreement_or_pke"
    return None


def _classical_key_for_asset(asset: CryptoAsset) -> str | None:
    if asset.name == "RSA":
        # RSA key size isn't always known from the asset (parameter_set is
        # frequently null for the C/OpenSSL detector's RSA_sign etc.) — see
        # the module docstring on this default. This only affects the
        # informational `classical_bytes` field, never whether a finding
        # fires (that's governed solely by pqc_bytes vs declared_bytes).
        return _CLASSICAL_RSA_BY_PARAM.get(asset.parameter_set or "", "rsa_2048")
    return _CLASSICAL_KEY_BY_NAME.get(asset.name)


def _classical_field_bytes(classical_entry: dict[str, Any], field: str) -> int:
    if field == "signature":
        return int(classical_entry.get("signature_bytes") or classical_entry.get("signature_bytes_max") or 0)
    if field == "pubkey":
        return int(classical_entry.get("pubkey_bytes") or 0)
    if field == "ciphertext":
        return int(classical_entry.get("ciphertext_bytes") or 0)
    return 0


def _severity_for_overflow(overflow_bytes: int) -> str:
    """Coarse, explicitly documented thresholds — NOT calibrated against
    real incident data. See docs/BLAST_RADIUS.md.

    < 256 bytes overflow   -> low
    256-1023 bytes         -> medium
    1024-4095 bytes        -> high
    >= 4096 bytes          -> critical
    """
    if overflow_bytes < 256:
        return "low"
    if overflow_bytes < 1024:
        return "medium"
    if overflow_bytes < 4096:
        return "high"
    return "critical"


def _estimate_effort_days(constraint: SizeConstraint) -> float:
    """Heuristic placeholder, NOT derived from real migration data.

    Base 0.5 engineer-days per finding; +0.5 if the constraint is a
    db_column (schema migrations — ALTER TABLE, backfills, downstream
    consumers — cost more than resizing a buffer). See docs/BLAST_RADIUS.md.
    """
    days = 0.5
    if constraint.kind == "db_column":
        days += 0.5
    return days


def primitive_for_replacement(pqc_replacement_name: str) -> Primitive:
    """Which Primitive a SYNTHETIC (db_column-fallback) component should
    carry, given the PQC family name it was inferred against. Used only by
    hash_patch/cli.py's synthetic-component construction — see the module
    docstring's "db_column name-pattern-only fallback" note. Never used for
    a real correlated asset, which keeps its own detected primitive.
    """
    return _PRIMITIVE_FOR_REPLACEMENT.get(pqc_replacement_name, Primitive.UNKNOWN)


def is_inferred_finding(finding: BlastRadiusFinding) -> bool:
    """True for a pass-2 (db_column, no real CryptoAsset) synthesized
    finding — see the module docstring's "db_column name-pattern-only
    fallback" note. `hash_patch/cli.py` uses this to decide whether to build
    a synthetic CBOM component for a finding it can't find a real asset for.
    """
    return finding.asset_id.startswith(_INFERRED_ASSET_ID_PREFIX)


def _line_distance(asset: CryptoAsset, constraint: SizeConstraint) -> int | None:
    """Smallest line distance between `constraint`'s own evidence and any of
    `asset`'s evidence IN THE SAME FILE, or None if `asset` has no evidence
    in that file at all (never correlate across files) or line numbers are
    unavailable.
    """
    constraint_ev = constraint.evidence[0]
    constraint_locator = _normalize_locator(constraint_ev.locator)
    if constraint_ev.line is None:
        return None

    best: int | None = None
    for ev in asset.evidence:
        if _normalize_locator(ev.locator) != constraint_locator or ev.line is None:
            continue
        distance = abs(ev.line - constraint_ev.line)
        if best is None or distance < best:
            best = distance
    return best


def _pick_correlated_asset(
    constraint: SizeConstraint,
    field: str,
    shor_assets: Sequence[CryptoAsset],
) -> tuple[CryptoAsset, str, str] | None:
    """Pick the single best same-file CryptoAsset to correlate `constraint`
    with, given its name-pattern `field`. See the module docstring's
    "Correlation is same-file AND nearest-by-line" / "Name-pattern-to-
    primitive matching" sections.

    A candidate must (1) be in the same file as the constraint, (2) have a
    primitive that maps (via `_pqc_family_for_primitive` — the asset's OWN
    real primitive, never a hardcoded default) to a PQC family for which
    `field` is a meaningful comparison, and (3) have a classical reference
    size in scope. Among candidates, the nearest by line distance wins;
    ties between different families are broken by `_FIELD_FAMILY_PRIORITY`;
    remaining ties are broken by asset id, for determinism.

    Returns (asset, family, pqc_field_key), or None if no same-file asset is
    a plausible candidate at all.
    """
    best_key: tuple[int, int, str] | None = None
    best: tuple[CryptoAsset, str, str] | None = None

    for asset in shor_assets:
        family = _pqc_family_for_primitive(asset.primitive)
        if family is None:
            continue
        pqc_field_key = _PQC_FIELDS[family].get(field)
        if pqc_field_key is None:
            continue  # e.g. "ciphertext" field near a signature-only asset
        if _classical_key_for_asset(asset) is None:
            continue  # no classical reference size in scope for this algorithm

        distance = _line_distance(asset, constraint)
        if distance is None:
            continue  # different file (or no line info) -> never a candidate

        priority = _FIELD_FAMILY_PRIORITY.get(field, {}).get(family, 0)
        key = (distance, priority, asset.id)
        if best_key is None or key < best_key:
            best_key = key
            best = (asset, family, pqc_field_key)

    return best


def compute_blast_radius(
    crypto_assets: Sequence[CryptoAsset],
    size_constraints: Sequence[SizeConstraint],
    pqc_sizes: dict[str, Any] | None = None,
) -> list[BlastRadiusFinding]:
    """Correlate BROKEN_BY_SHOR CryptoAssets with same-file SizeConstraints
    and emit a BlastRadiusFinding wherever the smallest currently credible
    PQC replacement's relevant size would exceed the declared size.

    A second pass then handles `db_column` constraints that found no
    same-file CryptoAsset at all (see the "db_column name-pattern-only
    fallback" note in the module docstring).
    """
    if not size_constraints:
        return []

    sizes = pqc_sizes if pqc_sizes is not None else _load_pqc_sizes()
    name_patterns: list[NamePattern] = load_name_patterns()
    findings: list[BlastRadiusFinding] = []
    correlated: set[int] = set()  # id(constraint) for constraints matched in pass 1

    shor_assets = [a for a in crypto_assets if a.quantum_status == QuantumStatus.BROKEN_BY_SHOR]

    # Pass 1: for EACH constraint (not each asset — see module docstring),
    # pick at most one same-file, nearest-by-line, primitive-plausible
    # CryptoAsset to correlate it with. This is what stops a single file
    # with two unrelated crypto operations (e.g. RSA signing + Ed25519
    # keygen) from cross-attributing each other's buffers.
    for constraint in size_constraints:
        match = match_name_pattern(constraint.name, name_patterns)
        if match is None:
            continue
        _, name_field = match
        if name_field is None:
            continue  # e.g. privkey/cert/digest/hash -> no PQC field to compare

        picked = _pick_correlated_asset(constraint, name_field, shor_assets)
        if picked is None:
            continue
        asset, family, pqc_field_key = picked

        replacement_key: str = sizes["default_replacement"][family]
        pqc_entry = sizes["pqc"][replacement_key]

        pqc_bytes = int(pqc_entry[pqc_field_key])
        overflow_bytes = pqc_bytes - constraint.declared_bytes
        if overflow_bytes <= 0:
            continue  # fits even the PQC replacement -> no finding

        classical_key = _classical_key_for_asset(asset)
        assert classical_key is not None  # _pick_correlated_asset already filtered this
        classical_entry = sizes["classical"][classical_key]

        correlated.add(id(constraint))
        findings.append(
            BlastRadiusFinding(
                asset_id=asset.id,
                asset_name=asset.name,
                size_constraint=constraint,
                pqc_replacement_name=_DISPLAY_NAMES[replacement_key],
                classical_bytes=_classical_field_bytes(classical_entry, name_field),
                pqc_bytes=pqc_bytes,
                overflow_bytes=overflow_bytes,
                severity=_severity_for_overflow(overflow_bytes),  # type: ignore[arg-type]
                estimated_effort_days=_estimate_effort_days(constraint),
            )
        )

    # Pass 2: db_column constraints with no same-file CryptoAsset — see the
    # "db_column name-pattern-only fallback" note in the module docstring.
    for constraint in size_constraints:
        if constraint.kind != "db_column" or id(constraint) in correlated:
            continue

        match = match_name_pattern(constraint.name, name_patterns)
        if match is None:
            continue
        _, name_field = match
        if name_field is None:
            continue

        fallback_family = _FALLBACK_FAMILY_FOR_FIELD.get(name_field)
        if fallback_family is None:
            continue
        fallback_replacement_key = sizes["default_replacement"][fallback_family]
        fallback_pqc_entry = sizes["pqc"][fallback_replacement_key]
        fallback_pqc_field_key = _PQC_FIELDS[fallback_family].get(name_field)
        if fallback_pqc_field_key is None:
            continue

        pqc_bytes = int(fallback_pqc_entry[fallback_pqc_field_key])
        overflow_bytes = pqc_bytes - constraint.declared_bytes
        if overflow_bytes <= 0:
            continue

        findings.append(
            BlastRadiusFinding(
                asset_id=f"{_INFERRED_ASSET_ID_PREFIX}{name_field}",
                asset_name=f"unidentified {name_field}-shaped material (name-pattern only, no source CryptoAsset)",
                size_constraint=constraint,
                pqc_replacement_name=_DISPLAY_NAMES[fallback_replacement_key],
                classical_bytes=0,  # no real asset -> no classical reference available
                pqc_bytes=pqc_bytes,
                overflow_bytes=overflow_bytes,
                severity=_severity_for_overflow(overflow_bytes),  # type: ignore[arg-type]
                estimated_effort_days=_estimate_effort_days(constraint),
            )
        )

    return sorted(findings, key=_finding_sort_key)


def _finding_sort_key(finding: BlastRadiusFinding) -> tuple[str, str, int, str]:
    ev = finding.size_constraint.evidence[0]
    return (finding.asset_id, _normalize_locator(ev.locator), ev.line or 0, finding.size_constraint.name)


def collect_size_constraints(scanned_files: Sequence[Path]) -> list[SizeConstraint]:
    """Run the blast-radius detectors (C buffers, SQL DDL) over every file
    in `scanned_files` that they support. Not routed through
    hash_patch.detect.registry — see hash_patch/detect/blast_radius/__init__.py.
    """
    c_detector = CBufferBlastRadiusDetector()
    sql_detector = SqlDdlBlastRadiusDetector()

    results: list[SizeConstraint] = []
    for file_path in scanned_files:
        if c_detector.supports(file_path):
            results.extend(c_detector.detect(file_path))
        if sql_detector.supports(file_path):
            results.extend(sql_detector.detect(file_path))
    return results


def run_blast_radius(
    crypto_assets: Sequence[CryptoAsset], scanned_files: Sequence[Path]
) -> list[BlastRadiusFinding]:
    """End-to-end entry point used by hash_patch/cli.py::run_scan: detect
    SizeConstraints in the scanned file set, then correlate against the
    already-detected CryptoAsset findings.
    """
    size_constraints = collect_size_constraints(scanned_files)
    if not size_constraints:
        return []
    return compute_blast_radius(crypto_assets, size_constraints)
