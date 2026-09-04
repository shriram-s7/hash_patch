from __future__ import annotations

import json
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoMode,
    CryptoPrimitive,
    CryptoProperties,
)
from cyclonedx.model.tool import ToolRepository
from cyclonedx.output import OutputFormat, make_outputter
from cyclonedx.schema import SchemaVersion

from hash_patch.model.assets import AssetType, CryptoAsset
from hash_patch.model.evidence import Evidence
from hash_patch.model.findings import ScanResult

_CRYPTO_FUNCTION_VALUES = {f.value for f in CryptoFunction}
_CRYPTO_MODE_VALUES = {m.value for m in CryptoMode}

# Every asset still needs at least one Evidence entry regardless of
# confidence (an asset with none is refused below -- CLAUDE.md hard
# constraint #3). `hash_patch:confidence` itself comes straight from
# CryptoAsset.confidence: "confirmed" for a real detector finding, or
# "inferred" for a name-pattern-only guess (e.g. the blast-radius db_column
# fallback synthetic asset built in hash_patch/cli.py) that still carries
# real evidence (it points at the file/line that suggested it) but is not a
# direct observation of which algorithm actually produced the artefact — see
# CLAUDE.md's "Name" section.


def _derive_serial_number(result: ScanResult) -> UUID:
    """Deterministically derive the BOM serial number from the scan target
    and the full set of asset ids it produced.

    Never uuid4(): the same target + the same assets must always yield the
    same serial number, so that repeated scans of identical input are
    byte-identical apart from the timestamp (see CLAUDE.md hard constraint
    #2). Sorting the asset ids first makes this independent of insertion
    order.
    """
    asset_ids = sorted(asset.id for asset in result.assets)
    seed = "hash_patch:cbom:" + result.target + ":" + ",".join(asset_ids)
    return uuid5(NAMESPACE_URL, seed)


def _map_crypto_functions(functions: list[str]) -> tuple[list[CryptoFunction], list[str]]:
    """Split our free-form crypto_functions strings into ones that fit the
    CycloneDX CryptoFunction enum and ones that don't. Unmapped values are
    never dropped -- the caller must surface them via a hash_patch: property.
    """
    mapped: list[CryptoFunction] = []
    unmapped: list[str] = []
    for fn in functions:
        if fn in _CRYPTO_FUNCTION_VALUES:
            mapped.append(CryptoFunction(fn))
        else:
            unmapped.append(fn)
    return mapped, unmapped


def _map_mode(mode: str | None) -> tuple[CryptoMode | None, str | None]:
    if mode is None:
        return None, None
    if mode in _CRYPTO_MODE_VALUES:
        return CryptoMode(mode), None
    return None, mode


def _evidence_to_occurrence(ev: Evidence) -> Occurrence:
    """Map an Evidence entry onto a CycloneDX occurrence.

    location/line/offset have direct CycloneDX homes. `symbol` has no
    equivalent in our model (it names a programming-language symbol/import,
    not a code snippet) so it is left unset rather than repurposed.
    source_type, column and snippet have no structured field in
    occurrenceType, so they are folded into additional_context as a compact
    JSON object -- lossless, and scoped to the correct occurrence, rather
    than flattened into unscoped component-level properties. See CLAUDE.md
    "Output format" section.
    """
    extra = {
        "source_type": ev.source_type,
        "column": ev.column,
        "snippet": ev.snippet,
    }
    extra = {k: v for k, v in extra.items() if v is not None}
    return Occurrence(
        location=ev.locator,
        line=ev.line,
        offset=ev.byte_offset,
        additional_context=json.dumps(extra, sort_keys=True) if extra else None,
    )


def _asset_properties(
    asset: CryptoAsset,
    unmapped_functions: list[str],
    unmapped_mode: str | None,
) -> list[Property]:
    """Our extra fields that have no standard CycloneDX component-level home.

    All live under the hash_patch: namespace prefix, never as invented
    top-level keys (see CLAUDE.md "Output format" section).
    """
    detector_ids = sorted({ev.detector_id for ev in asset.evidence})
    detector_versions = sorted({ev.detector_version for ev in asset.evidence})

    props = [
        Property(name="hash_patch:quantumStatus", value=asset.quantum_status.value),
        Property(name="hash_patch:reachability", value=asset.reachability.value),
        Property(name="hash_patch:detectorId", value=",".join(detector_ids)),
        Property(name="hash_patch:detectorVersion", value=",".join(detector_versions)),
        Property(name="hash_patch:confidence", value=asset.confidence),
    ]
    if unmapped_functions:
        props.append(
            Property(name="hash_patch:cryptoFunctionsUnmapped", value=",".join(unmapped_functions))
        )
    if unmapped_mode:
        props.append(Property(name="hash_patch:modeUnmapped", value=unmapped_mode))
    if asset.finding_type != "OPERATION":
        props.append(Property(name="hash_patch:findingType", value=asset.finding_type))
    for key in sorted(asset.properties):
        props.append(Property(name=f"hash_patch:property.{key}", value=asset.properties[key]))
    return props


def _asset_to_component(asset: CryptoAsset) -> Component:
    if not asset.evidence:
        raise ValueError(
            f"CryptoAsset {asset.id!r} ({asset.name}) has no evidence; "
            "refusing to emit (see CLAUDE.md hard constraint #3)"
        )

    algorithm_properties: AlgorithmProperties | None = None
    unmapped_functions: list[str] = []
    unmapped_mode: str | None = None

    if asset.asset_type is AssetType.ALGORITHM:
        # algorithmProperties only makes sense for the "algorithm" asset
        # type -- our model has no certificate/protocol-specific fields
        # (subject/issuer/validity, cipher suite, ...) to populate
        # certificateProperties/protocolProperties with, so we never
        # fabricate them for other asset types. See CLAUDE.md.
        mapped_functions, unmapped_functions = _map_crypto_functions(asset.crypto_functions)
        mapped_mode, unmapped_mode = _map_mode(asset.mode)
        algorithm_properties = AlgorithmProperties(
            primitive=CryptoPrimitive(asset.primitive.value),
            parameter_set_identifier=asset.parameter_set,
            mode=mapped_mode,
            crypto_functions=mapped_functions,
            nist_quantum_security_level=asset.nist_quantum_security_level,
        )

    crypto_properties = CryptoProperties(
        asset_type=CryptoAssetType(asset.asset_type.value),
        algorithm_properties=algorithm_properties,
        oid=asset.oid,
    )

    occurrences = [_evidence_to_occurrence(ev) for ev in asset.evidence]
    properties = _asset_properties(asset, unmapped_functions, unmapped_mode)

    return Component(
        name=asset.name,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=asset.id,
        crypto_properties=crypto_properties,
        evidence=ComponentEvidence(occurrences=occurrences),
        properties=properties,
    )


def _sort_document_for_determinism(doc: dict[str, Any]) -> dict[str, Any]:
    """Explicitly enforce our own sort order on the emitted dict, rather than
    relying on cyclonedx-python-lib's internal sort keys (which order
    components by type/group/name/... rather than bom-ref, and could change
    across library versions): components by bom-ref, each component's
    properties by name, each component's evidence occurrences by
    (location, line, offset), and each cryptoFunctions list.

    See CLAUDE.md "Output format" -> "Determinism".
    """
    for component in doc.get("components", []):
        properties = component.get("properties")
        if properties:
            component["properties"] = sorted(properties, key=lambda p: p["name"])

        occurrences = component.get("evidence", {}).get("occurrences")
        if occurrences:
            component["evidence"]["occurrences"] = sorted(
                occurrences,
                key=lambda o: (o.get("location", ""), o.get("line", -1), o.get("offset", -1)),
            )

        crypto_functions = component.get("cryptoProperties", {}).get(
            "algorithmProperties", {}
        ).get("cryptoFunctions")
        if crypto_functions:
            component["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"] = sorted(
                crypto_functions
            )

    metadata = doc.get("metadata")
    if metadata and "properties" in metadata:
        metadata["properties"] = sorted(metadata["properties"], key=lambda p: p["name"])

    doc["components"] = sorted(doc.get("components", []), key=lambda c: c["bom-ref"])
    return doc


def to_cyclonedx(result: ScanResult) -> dict[str, Any]:
    """Map a ScanResult onto a CycloneDX 1.6 BOM document (as a plain dict).

    metadata.timestamp is the only field allowed to vary between runs over
    identical input (see CLAUDE.md hard constraint #2); everything else,
    including the BOM serial number and all list ordering, is derived
    deterministically.
    """
    components = [_asset_to_component(asset) for asset in result.sorted_assets()]

    meta_props: list[Property] = []
    for contra in sorted(result.contradiction_findings, key=lambda c: c.id):
        src_ev = contra.source_intent.evidence[0] if contra.source_intent.evidence else None
        cfg_ev = contra.deployed_config.evidence[0] if contra.deployed_config.evidence else None
        val_data = {
            "id": contra.id,
            "severity": contra.severity,
            "description": contra.description,
            "sourceIntent": {
                "format": contra.source_intent.config_format,
                "value": contra.source_intent.value,
                "locator": src_ev.locator if src_ev else contra.source_intent.source_file,
                "line": src_ev.line if src_ev else None,
            },
            "deployedConfig": {
                "format": contra.deployed_config.config_format,
                "value": contra.deployed_config.value,
                "legacyReasons": contra.deployed_config.legacy_reasons,
                "locator": cfg_ev.locator if cfg_ev else contra.deployed_config.source_file,
                "line": cfg_ev.line if cfg_ev else None,
            },
        }
        meta_props.append(
            Property(
                name=f"hash_patch:contradiction.{contra.id}",
                value=json.dumps(val_data, sort_keys=True, separators=(",", ":")),
            )
        )

    if result.scanned_files:
        meta_props.append(
            Property(
                name="hash_patch:scanned_files",
                value=json.dumps(result.scanned_files, sort_keys=True, separators=(",", ":")),
            )
        )

    metadata = BomMetaData(
        timestamp=result.scan_started_at,
        tools=ToolRepository(
            components=[
                Component(
                    type=ComponentType.APPLICATION,
                    name="Hash Patch",
                    version=result.tool_version,
                )
            ]
        ),
        properties=meta_props if meta_props else None,
    )

    bom = Bom(
        serial_number=_derive_serial_number(result),
        version=1,
        metadata=metadata,
        components=components,
    )

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    doc: dict[str, Any] = json.loads(outputter.output_as_string())
    return _sort_document_for_determinism(doc)


def render_cbom_json(doc: dict[str, Any]) -> str:
    """Canonical serialization for a to_cyclonedx() document.

    Fixed key order (sort_keys), fixed indentation, no ASCII-escaping, and a
    trailing newline -- the single serialization path every writer (CLI,
    write_cbom, tests) must go through so output is byte-identical for
    byte-identical documents. See CLAUDE.md "Output format" -> "Determinism".
    """
    return json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
