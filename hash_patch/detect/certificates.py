"""hash_patch/detect/certificates.py — certificate file parsing.

A NEW, INDEPENDENT pipeline stage, not a language source detector: a
certificate file (.pem/.crt/.cer/.der/.p12/.pfx) is not executable code, so
none of the OPERATION/CRYPTO_REFERENCE machinery in hash_patch/detect/{c,go,
java,python}.py applies here — there is no call site, no reference literal,
just a structured binary/text artifact to parse. Mirrors the precedent set
by hash_patch/detect/blast_radius/: a plain function invoked directly from
hash_patch/cli.py::run_scan, NOT registered into hash_patch.detect.registry
(that registry, and the base `Detector` ABC, assume "walk source, look for
call/reference sites" — this stage doesn't fit that shape).

Every finding here is `AssetType.CERTIFICATE` (hash_patch/model/assets.py),
never `AssetType.ALGORITHM` — a certificate is a distinct kind of artifact
from a source-detected crypto operation, and must render as one in the UI
(distinct badge, no reachability badge — see docs and MigrationView.tsx's
sibling CRYPTO_REFERENCE precedent).

Quantum-vulnerability classification is NEVER duplicated here: the
certificate's public-key algorithm name (RSA/ECDSA/Ed25519/DSA) is looked
up through the exact same shared registry every language detector already
uses (hash_patch.detect.canonical_registry.lookup_canonical_algorithm,
rules/canonical_algorithms.yaml) — an RSA-2048 certificate is classified
broken-by-shor by the identical rule that classifies a source-detected
RSA-2048 keygen call, not a second hand-copied mapping.

Reachability does NOT apply to a certificate file (nothing "calls" it) —
Evidence.source_type is "certificate", not "source", so
hash_patch/analyze/reachability.py's classifier casts no vote on it and it
keeps the model's default Reachability.UNKNOWN, exactly like binary/
container/config/network evidence already does. Blast-radius does not apply
either (no fixed-size buffer to overflow) and is never invoked here.

Shelf-life: a certificate's own `notValidAfter` date is real, directly-known
data — arguably more concrete than the DPDP name-pattern inference
hash_patch/analyze/shelf_life.py performs for Python/Java source. Rather
than routing it through that pipeline (which requires a same-file,
same-call-site DataContextMatch that no certificate file has), this module
attaches a `hash_patch:property.shelfLife.certificate_expiry` property
directly, in the exact JSON shape hash_patch/analyze/cbom_reader.py already
knows how to read back — no changes needed there. Its `evidenceSource`
field is always the literal string "certificate_expiry", so it is never
confused with a DPDP-inferred figure. `shelf_life_years` is computed from
`(not_after - reference_date).days`, clamped to 0 for an already-expired
certificate — a lapsed certificate provides no forward secrecy window at
all, not a negative one.

`reference_date` is always the caller-supplied scan date
(ScanResult.scan_started_at.date() in hash_patch/cli.py::run_scan) — never
read from the system clock in this module, per CLAUDE.md hard constraint
#2. Two scans of the same certificate on different days will legitimately
report different `expired`/`expiringSoon`/`shelf_life_years` values because
time genuinely passed; this mirrors the one sanctioned exception
(`metadata.timestamp`) rather than adding a second one.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from hash_patch.detect.canonical_registry import lookup_canonical_algorithm
from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, QuantumStatus
from hash_patch.model.evidence import Evidence

_DETECTOR_ID = "certificate-parser"
_DETECTOR_VERSION = "0.1.0"

_PEM_EXTENSIONS = frozenset({".pem", ".crt", ".cer"})
_DER_EXTENSIONS = frozenset({".der"})
_P12_EXTENSIONS = frozenset({".p12", ".pfx"})
_SUPPORTED_EXTENSIONS = _PEM_EXTENSIONS | _DER_EXTENSIONS | _P12_EXTENSIONS

DEFAULT_EXPIRY_WINDOW_DAYS = 90

_CURVE_DISPLAY_NAMES: dict[str, str] = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "secp256k1": "secp256k1",
}


def supports(target: Path) -> bool:
    return target.is_file() and target.suffix.lower() in _SUPPORTED_EXTENSIONS


def _pubkey_algorithm_and_size(public_key: Any) -> tuple[str, str | None]:
    """Returns (canonical algorithm name, parameter_set) — real, cert-derived
    key-size data, never guessed. The algorithm NAME is what gets looked up
    against the shared canonical registry for quantum classification; the
    size comes straight from the key object, never from a registry entry
    (registry entries like "RSA-1024" are for source-code detectors that
    only ever see a literal size argument, not an object to introspect).
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", str(public_key.key_size)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        display = _CURVE_DISPLAY_NAMES.get(curve_name, curve_name)
        return "ECDSA", display
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", "255"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", "448"
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", str(public_key.key_size)
    return "UNKNOWN", None


def _signature_algorithm_name(cert: x509.Certificate) -> str:
    try:
        name = cert.signature_algorithm_oid._name
        if name:
            return name
    except Exception:  # noqa: BLE001 -- fall through to the hash-algorithm fallback below
        pass
    try:
        hash_algo = cert.signature_hash_algorithm
        if hash_algo is not None:
            return hash_algo.name
    except UnsupportedAlgorithm:
        pass
    return "UNKNOWN"


def _not_before(cert: x509.Certificate) -> date:
    try:
        return cert.not_valid_before_utc.date()
    except AttributeError:  # pragma: no cover -- older cryptography without the _utc accessor
        return cert.not_valid_before.date()


def _not_after(cert: x509.Certificate) -> date:
    try:
        return cert.not_valid_after_utc.date()
    except AttributeError:  # pragma: no cover -- older cryptography without the _utc accessor
        return cert.not_valid_after.date()


def _is_self_signed(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject


def _shelf_life_property(not_after: date, reference_date: date) -> tuple[str, str]:
    """Returns (property_name, json_value) for
    `hash_patch:property.shelfLife.certificate_expiry` — see this module's
    docstring for why this bypasses hash_patch/analyze/shelf_life.py's
    DataContextMatch pipeline entirely and is written directly.
    """
    days_remaining = (not_after - reference_date).days
    shelf_life_years = max(0, days_remaining) // 365
    mosca_note = (
        f"Certificate expires {not_after.isoformat()}; already expired as of the scan date."
        if days_remaining < 0
        else f"Certificate remains valid until {not_after.isoformat()} "
        f"({shelf_life_years}yr shelf-life from scan date)."
    )
    value = {
        "shelfLifeYears": shelf_life_years,
        "moscaNote": mosca_note,
        "evidenceSource": "certificate_expiry",
        "confidence": "high",
    }
    import json

    return "hash_patch:property.shelfLife.certificate_expiry", json.dumps(value, sort_keys=True)


def _build_certificate_asset(
    cert: x509.Certificate,
    locator: str,
    chain_position: int,
    chain_depth: int,
    reference_date: date,
    expiry_window_days: int,
) -> CryptoAsset:
    pubkey_name, parameter_set = _pubkey_algorithm_and_size(cert.public_key())
    lookup = lookup_canonical_algorithm(pubkey_name)
    if lookup is not None:
        primitive = Primitive(lookup.get("primitive") or "unknown")
        quantum_status = QuantumStatus(lookup.get("quantum_status") or "unknown")
        oid = lookup.get("oid")
    else:
        primitive = Primitive.UNKNOWN
        quantum_status = QuantumStatus.UNKNOWN
        oid = None

    not_before = _not_before(cert)
    not_after = _not_after(cert)
    sig_algo = _signature_algorithm_name(cert)
    self_signed = _is_self_signed(cert)
    is_expired = not_after < reference_date
    is_expiring_soon = not is_expired and (not_after - reference_date).days <= expiry_window_days
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    snippet = (
        f"subject={cert.subject.rfc4514_string()}; issuer={cert.issuer.rfc4514_string()}; "
        f"notBefore={not_before.isoformat()}; notAfter={not_after.isoformat()}"
    )

    evidence = Evidence(
        source_type="certificate",
        locator=locator,
        line=None,
        column=None,
        byte_offset=None,
        snippet=snippet,
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
    )

    properties: dict[str, str] = {
        "certificate.subject": cert.subject.rfc4514_string(),
        "certificate.issuer": cert.issuer.rfc4514_string(),
        "certificate.signatureAlgorithm": sig_algo,
        "certificate.notBefore": not_before.isoformat(),
        "certificate.notAfter": not_after.isoformat(),
        "certificate.selfSigned": "true" if self_signed else "false",
        "certificate.expired": "true" if is_expired else "false",
        "certificate.expiringSoon": "true" if is_expiring_soon else "false",
        "certificate.expiryWindowDays": str(expiry_window_days),
        "certificate.chainPosition": str(chain_position),
        "certificate.chainDepth": str(chain_depth),
        "certificate.fingerprintSha256": fingerprint,
    }
    shelf_life_key, shelf_life_value = _shelf_life_property(not_after, reference_date)
    properties[shelf_life_key.removeprefix("hash_patch:property.")] = shelf_life_value

    asset = CryptoAsset.create(
        asset_type=AssetType.CERTIFICATE,
        name=pubkey_name,
        primitive=primitive,
        parameter_set=parameter_set,
        oid=oid,
        quantum_status=quantum_status,
        confidence="confirmed",
        finding_type="CERTIFICATE",
        properties=properties,
        extra_id_seed=fingerprint,
        evidence=[evidence],
    )
    return asset


def _unparseable_asset(locator: str, reason: str) -> CryptoAsset:
    """A certificate/PKCS12 file that was FOUND but could not be parsed —
    e.g. a password-protected .p12 with no password supplied, or corrupt
    data. Reported explicitly (never silently dropped, never crashes the
    whole scan) with `finding_type="CERTIFICATE_UNPARSEABLE"` so the UI can
    render it distinctly from both a real certificate finding and a plain
    scan error — mirrors the "UNRESOLVED" convention the source detectors
    already use for a call site that was seen but couldn't be identified.
    """
    evidence = Evidence(
        source_type="certificate",
        locator=locator,
        snippet=reason,
        detector_id=_DETECTOR_ID,
        detector_version=_DETECTOR_VERSION,
    )
    return CryptoAsset.create(
        asset_type=AssetType.CERTIFICATE,
        name="UNPARSEABLE_CERTIFICATE",
        primitive=Primitive.UNKNOWN,
        quantum_status=QuantumStatus.UNKNOWN,
        confidence="LOW",
        finding_type="CERTIFICATE_UNPARSEABLE",
        properties={"certificate.error": reason},
        extra_id_seed=locator,
        evidence=[evidence],
    )


def detect_certificate_file(
    target: Path,
    reference_date: date,
    expiry_window_days: int = DEFAULT_EXPIRY_WINDOW_DAYS,
    p12_password: bytes | None = None,
) -> list[CryptoAsset]:
    """Parse one certificate/PKCS12 file into zero or more CryptoAsset
    findings (a PEM chain file yields one asset per certificate in it).
    Never raises: a file that exists but cannot be parsed produces a single
    `_unparseable_asset` rather than propagating an exception up into
    hash_patch/cli.py::run_scan and aborting the whole scan.
    """
    if not supports(target):
        return []

    locator = str(target)
    suffix = target.suffix.lower()

    try:
        data = target.read_bytes()
    except OSError as exc:
        return [_unparseable_asset(locator, f"could not read file: {exc}")]

    certs: list[x509.Certificate] = []
    try:
        if suffix in _P12_EXTENSIONS:
            try:
                _, cert, additional = pkcs12.load_key_and_certificates(data, p12_password)
            except Exception:  # noqa: BLE001 -- wrong/missing password or corrupt PKCS12 container
                return [
                    _unparseable_asset(
                        locator,
                        "found, unparseable without password"
                        if p12_password is None
                        else "found, unparseable with the supplied password",
                    )
                ]
            if cert is not None:
                certs.append(cert)
            certs.extend(c for c in (additional or []) if c is not None)
        elif suffix in _DER_EXTENSIONS:
            certs.append(x509.load_der_x509_certificate(data))
        else:
            try:
                certs.extend(x509.load_pem_x509_certificates(data))
            except ValueError:
                # Some tools write DER bytes under a .crt/.cer extension —
                # fall back to a single DER-encoded certificate before
                # giving up, rather than assuming PEM was the only option.
                certs.append(x509.load_der_x509_certificate(data))
    except Exception as exc:  # noqa: BLE001 -- any parse failure is reported, never crashes the scan
        return [_unparseable_asset(locator, f"parse error: {exc}")]

    if not certs:
        return [_unparseable_asset(locator, "no certificate found in file")]

    chain_depth = len(certs)
    assets: list[CryptoAsset] = []
    for position, cert in enumerate(certs):
        try:
            assets.append(
                _build_certificate_asset(cert, locator, position, chain_depth, reference_date, expiry_window_days)
            )
        except Exception as exc:  # noqa: BLE001 -- lazy ASN.1 / key parse errors must not crash scan
            assets.append(_unparseable_asset(locator, f"unparseable certificate attribute: {exc}"))
    return assets


def detect_certificates(
    scanned_files: list[Path],
    reference_date: date,
    expiry_window_days: int = DEFAULT_EXPIRY_WINDOW_DAYS,
) -> list[CryptoAsset]:
    """Run certificate parsing over every certificate-shaped file in
    `scanned_files` — the entry point hash_patch/cli.py::run_scan calls,
    mirroring hash_patch.analyze.blast_radius.collect_size_constraints's
    "filter scanned_files by supports(), run the parser" shape.
    """
    assets: list[CryptoAsset] = []
    for file_path in scanned_files:
        if supports(file_path):
            assets.extend(detect_certificate_file(file_path, reference_date, expiry_window_days))
    return assets
