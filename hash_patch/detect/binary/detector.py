"""hash_patch/detect/binary/detector.py

Binary / Compiled-Artifact Cryptography Detector.
Scans ELF, PE, and Mach-O binaries for:
- Linked cryptographic libraries (e.g. libcrypto, libssl, libsodium, libgcrypt)
- Observable cryptographic symbols (e.g. RSA_public_encrypt, ECDSA_sign, BCryptEncrypt)
- Observable algorithm strings (e.g. AES-256-GCM, Kyber, ML-KEM)
- Embedded certificates and key material

Guarantees:
1. Pure static inspection — never executes, loads, or dynamically links scanned binaries.
2. Honest framing — never claims runtime execution or runtime reachability.
3. Does not infer quantum risk merely from library linkage.
4. Bounded, memory-safe parsing of corrupt, truncated, or hostile binaries.
"""

from __future__ import annotations

import logging
from pathlib import Path

from hash_patch.detect.base import Detector
from hash_patch.detect.binary.formats.elf import parse_elf
from hash_patch.detect.binary.formats.macho import parse_macho
from hash_patch.detect.binary.formats.pe import parse_pe
from hash_patch.detect.binary.formats.safety import (
    MAX_BINARY_SCAN_BYTES,
    probe_binary_format,
)
from hash_patch.detect.binary.registry import (
    lookup_crypto_symbol,
    match_algorithm_string,
    match_crypto_library,
)
from hash_patch.detect.binary.strings import (
    extract_embedded_certificates,
    extract_printable_strings,
)
from hash_patch.model.assets import (
    AssetType,
    CryptoAsset,
    Primitive,
    QuantumStatus,
    Reachability,
)
from hash_patch.model.evidence import Evidence

logger = logging.getLogger(__name__)

# Non-binary extensions to immediately reject without probing
IGNORED_EXTENSIONS = frozenset(
    {
        ".py", ".pyc", ".pyw", ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hxx",
        ".go", ".java", ".class", ".txt", ".md", ".json", ".yaml", ".yml", ".sql",
        ".html", ".css", ".ts", ".tsx", ".js", ".jsx", ".rst", ".toml", ".ini",
        ".cfg", ".xml", ".csv", ".tsv", ".svg", ".png", ".jpg", ".jpeg", ".gif",
    }
)


class BinaryDetector(Detector):
    detector_id = "binary-crypto"
    detector_version = "0.1.0"

    def supports(self, target: Path) -> bool:
        """Fast check to see if target is a supported compiled binary artifact."""
        try:
            if not target.is_file():
                return False
            # Exclude known non-binary source extensions immediately
            if target.suffix.lower() in IGNORED_EXTENSIONS:
                return False
            # Sniff magic header
            fmt = probe_binary_format(target)
            return fmt is not None
        except Exception:
            return False

    def detect(self, target: Path) -> list[CryptoAsset]:
        """Statically inspect the binary artifact and emit deterministic crypto findings."""
        try:
            size = target.stat().st_size
            if size < 4:
                return []
            if size > MAX_BINARY_SCAN_BYTES:
                logger.warning(
                    "Binary %s exceeds maximum scan size limit (%d bytes); parsing headers only",
                    target,
                    MAX_BINARY_SCAN_BYTES,
                )
                with target.open("rb") as f:
                    data = f.read(10 * 1024 * 1024)
            else:
                with target.open("rb") as f:
                    data = f.read()
        except Exception as e:
            logger.warning("Failed to read binary file %s: %s", target, e)
            return []

        fmt = probe_binary_format(target)
        if not fmt:
            return []

        parsed_arch: str | None = None
        linked_libraries: list[str] = []
        symbols: list[str] = []

        # 1. Format-specific structured parsing
        if fmt == "ELF":
            elf_res = parse_elf(data)
            if elf_res:
                parsed_arch = elf_res.architecture
                linked_libraries = elf_res.linked_libraries
                symbols = elf_res.symbols
        elif fmt == "PE":
            pe_res = parse_pe(data)
            if pe_res:
                parsed_arch = pe_res.architecture
                linked_libraries = pe_res.linked_libraries
                symbols = pe_res.symbols
        elif fmt == "Mach-O":
            macho_res = parse_macho(data)
            if macho_res:
                parsed_arch = macho_res.architecture
                linked_libraries = macho_res.linked_libraries
                symbols = macho_res.symbols

        # Deduplication map: dedup_key -> CryptoAsset
        findings_map: dict[str, CryptoAsset] = {}

        # 2. Linked Cryptographic Libraries
        for lib in linked_libraries:
            matched_lib = match_crypto_library(lib)
            if matched_lib:
                dedup_key = f"{target}|linked_library|{lib}|unknown|linkage"
                if dedup_key not in findings_map:
                    ev = Evidence(
                        source_type="binary",
                        locator=str(target).replace("\\", "/"),
                        byte_offset=None,
                        snippet=f"Linked cryptographic library dependency: {lib}",
                        detector_id=self.detector_id,
                        detector_version=self.detector_version,
                    )
                    asset = CryptoAsset.create(
                        asset_type=AssetType.ALGORITHM,
                        name=matched_lib,
                        primitive=Primitive.OTHER,
                        parameter_set=None,
                        mode=None,
                        quantum_status=QuantumStatus.UNKNOWN,
                        reachability=Reachability.UNKNOWN,
                        confidence="confirmed",
                        finding_type="COMPILED_CRYPTO_ARTEFACT",
                        evidence=[ev],
                        properties={
                            "binaryFormat": fmt,
                            "architecture": parsed_arch or "unknown",
                            "evidenceType": "linked_library",
                            "observedValue": lib,
                            "library": matched_lib,
                            "algorithm": "unknown",
                            "operation": "library_linkage",
                            "verificationScope": "linked_library_observation",
                            "honestFraming": "Crypto library linkage observed; specific algorithm usage is not established.",
                        },
                    )
                    findings_map[dedup_key] = asset

        # 3. Cryptographic Symbols
        for sym in symbols:
            sym_meta = lookup_crypto_symbol(sym)
            if sym_meta:
                algo_name = sym_meta.get("algorithm", "unknown")
                op_name = sym_meta.get("operation", "crypto_operation")
                lib_name = sym_meta.get("library", "unknown")
                prim_val = sym_meta.get("primitive", "other")
                q_status_val = sym_meta.get("quantum_status", "unknown")
                oid_val = sym_meta.get("oid")

                dedup_key = f"{target}|symbol|{sym}|{algo_name}|{op_name}"
                if dedup_key not in findings_map:
                    ev = Evidence(
                        source_type="binary",
                        locator=str(target).replace("\\", "/"),
                        byte_offset=None,
                        snippet=f"Observed cryptographic symbol: {sym} ({algo_name})",
                        detector_id=self.detector_id,
                        detector_version=self.detector_version,
                    )
                    try:
                        prim = Primitive(prim_val)
                    except ValueError:
                        prim = Primitive.OTHER

                    try:
                        q_status = QuantumStatus(q_status_val)
                    except ValueError:
                        q_status = QuantumStatus.UNKNOWN

                    asset = CryptoAsset.create(
                        asset_type=AssetType.ALGORITHM,
                        name=algo_name,
                        primitive=prim,
                        parameter_set=sym_meta.get("parameter_set"),
                        mode=sym_meta.get("mode"),
                        oid=oid_val,
                        quantum_status=q_status,
                        reachability=Reachability.UNKNOWN,
                        confidence="confirmed",
                        finding_type="COMPILED_CRYPTO_ARTEFACT",
                        evidence=[ev],
                        properties={
                            "binaryFormat": fmt,
                            "architecture": parsed_arch or "unknown",
                            "evidenceType": "symbol",
                            "observedValue": sym,
                            "library": lib_name,
                            "algorithm": algo_name,
                            "operation": op_name,
                            "verificationScope": "static_binary_observation",
                            "honestFraming": "Cryptographic symbol observed in compiled artifact; runtime execution is not independently verified.",
                        },
                    )
                    findings_map[dedup_key] = asset

        # 4. Embedded Strings (Algorithm names)
        extracted_strings = extract_printable_strings(data, min_length=3, max_length=64)
        for ext_str in extracted_strings:
            algo_meta = match_algorithm_string(ext_str.value)
            if algo_meta:
                algo_name = algo_meta.get("canonical", ext_str.value)
                prim_val = algo_meta.get("primitive", "other")
                q_status_val = algo_meta.get("quantum_status", "unknown")
                mode_val = algo_meta.get("mode")
                param_set = algo_meta.get("parameter_set")
                oid_val = algo_meta.get("oid")

                dedup_key = f"{target}|algorithm_string|{ext_str.value}|{algo_name}|string_constant"
                if dedup_key not in findings_map:
                    ev = Evidence(
                        source_type="binary",
                        locator=str(target).replace("\\", "/"),
                        byte_offset=ext_str.offset,
                        snippet=f"Embedded algorithm string: {ext_str.value} (offset {ext_str.offset:#x})",
                        detector_id=self.detector_id,
                        detector_version=self.detector_version,
                    )
                    try:
                        prim = Primitive(prim_val)
                    except ValueError:
                        prim = Primitive.OTHER

                    try:
                        q_status = QuantumStatus(q_status_val)
                    except ValueError:
                        q_status = QuantumStatus.UNKNOWN

                    asset = CryptoAsset.create(
                        asset_type=AssetType.ALGORITHM,
                        name=algo_name,
                        primitive=prim,
                        parameter_set=param_set,
                        mode=mode_val,
                        oid=oid_val,
                        quantum_status=q_status,
                        reachability=Reachability.UNKNOWN,
                        confidence="low",
                        finding_type="COMPILED_CRYPTO_ARTEFACT",
                        evidence=[ev],
                        properties={
                            "binaryFormat": fmt,
                            "architecture": parsed_arch or "unknown",
                            "evidenceType": "algorithm_string",
                            "observedValue": ext_str.value,
                            "library": "unknown",
                            "algorithm": algo_name,
                            "operation": "string_constant",
                            "verificationScope": "embedded_string_observation",
                            "honestFraming": "Algorithm name observed in binary data; runtime execution is not established.",
                        },
                    )
                    findings_map[dedup_key] = asset
                else:
                    # Union additional evidence offset
                    existing_asset = findings_map[dedup_key]
                    ev = Evidence(
                        source_type="binary",
                        locator=str(target).replace("\\", "/"),
                        byte_offset=ext_str.offset,
                        snippet=f"Embedded algorithm string: {ext_str.value} (offset {ext_str.offset:#x})",
                        detector_id=self.detector_id,
                        detector_version=self.detector_version,
                    )
                    if not any(e.byte_offset == ext_str.offset for e in existing_asset.evidence):
                        existing_asset.evidence.append(ev)

        # 5. Embedded Certificates
        embedded_certs = extract_embedded_certificates(data)
        for c in embedded_certs:
            dedup_key = f"{target}|certificate|PEM_CERTIFICATE|RSA|embedded_certificate"
            if dedup_key not in findings_map:
                ev = Evidence(
                    source_type="binary",
                    locator=str(target).replace("\\", "/"),
                    byte_offset=c.offset,
                    snippet=f"Embedded PEM certificate structure at offset {c.offset:#x}",
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                )
                asset = CryptoAsset.create(
                    asset_type=AssetType.CERTIFICATE,
                    name="Embedded-Certificate",
                    primitive=Primitive.OTHER,
                    quantum_status=QuantumStatus.UNKNOWN,
                    reachability=Reachability.UNKNOWN,
                    confidence="confirmed",
                    finding_type="COMPILED_CRYPTO_ARTEFACT",
                    evidence=[ev],
                    properties={
                        "binaryFormat": fmt,
                        "architecture": parsed_arch or "unknown",
                        "evidenceType": "certificate",
                        "observedValue": "PEM Certificate",
                        "library": "unknown",
                        "algorithm": "X.509",
                        "operation": "certificate_storage",
                        "verificationScope": "embedded_certificate_observation",
                        "honestFraming": "Certificate material observed in compiled artifact; runtime execution is not established.",
                    },
                )
                findings_map[dedup_key] = asset

        return sorted(findings_map.values(), key=lambda a: a.id)
