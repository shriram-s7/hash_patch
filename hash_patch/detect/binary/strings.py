"""hash_patch/detect/binary/strings.py

Safe, bounded extraction of printable strings and certificate material from binary data.
Ensures memory safety and prevents DoS when scanning large or hostile compiled binaries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Printable ASCII characters (0x20 to 0x7E)
PRINTABLE_ASCII_PATTERN = re.compile(b"[ -~]{3,256}")

# PEM certificate pattern
PEM_CERT_PATTERN = re.compile(
    b"-----BEGIN (?:CERTIFICATE|X509 CERTIFICATE|TRUSTED CERTIFICATE)-----[^-]+-----END (?:CERTIFICATE|X509 CERTIFICATE|TRUSTED CERTIFICATE)-----"
)

# PEM public key pattern
PEM_PUBKEY_PATTERN = re.compile(
    b"-----BEGIN (?:PUBLIC KEY|RSA PUBLIC KEY)-----[^-]+-----END (?:PUBLIC KEY|RSA PUBLIC KEY)-----"
)


@dataclass(frozen=True)
class ExtractedString:
    value: str
    offset: int


@dataclass(frozen=True)
class ExtractedCertificate:
    raw_bytes: bytes
    offset: int
    format_type: str  # "PEM" or "DER"


def extract_printable_strings(
    data: bytes,
    min_length: int = 3,
    max_length: int = 256,
    max_strings: int = 50000,
) -> list[ExtractedString]:
    """Safely extract printable ASCII/UTF-8 strings and their byte offsets from raw binary data."""
    results: list[ExtractedString] = []
    count = 0

    for match in PRINTABLE_ASCII_PATTERN.finditer(data):
        raw = match.group()
        if len(raw) < min_length or len(raw) > max_length:
            continue
        try:
            val = raw.decode("utf-8", errors="strict")
            results.append(ExtractedString(value=val, offset=match.start()))
            count += 1
            if count >= max_strings:
                break
        except UnicodeDecodeError:
            continue

    return results


def extract_embedded_certificates(data: bytes) -> list[ExtractedCertificate]:
    """Detect embedded PEM or recognizable certificate structures in binary data."""
    certs: list[ExtractedCertificate] = []

    # 1. Search for PEM certificates
    for match in PEM_CERT_PATTERN.finditer(data):
        certs.append(
            ExtractedCertificate(
                raw_bytes=match.group(),
                offset=match.start(),
                format_type="PEM",
            )
        )

    return certs
