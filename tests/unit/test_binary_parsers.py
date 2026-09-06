"""tests/unit/test_binary_parsers.py

Unit tests for binary format parsers, probe detection, safe string extraction,
and resilience against malformed / corrupted binaries.
"""

from __future__ import annotations

import os
from pathlib import Path

from hash_patch.detect.binary.formats.elf import parse_elf
from hash_patch.detect.binary.formats.macho import parse_macho
from hash_patch.detect.binary.formats.pe import parse_pe
from hash_patch.detect.binary.formats.safety import probe_binary_format
from hash_patch.detect.binary.registry import (
    is_false_positive_string,
    match_algorithm_string,
    match_crypto_library,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "testdata" / "binary_crypto"


def test_probe_binary_format_types():
    elf_file = FIXTURE_DIR / "elf" / "crypto_server.elf"
    pe_file = FIXTURE_DIR / "pe" / "crypto_service.exe"
    macho_file = FIXTURE_DIR / "macho" / "crypto_tool.dylib"
    text_file = REPO_ROOT / "pyproject.toml"

    assert probe_binary_format(elf_file) == "ELF"
    assert probe_binary_format(pe_file) == "PE"
    assert probe_binary_format(macho_file) == "Mach-O"
    assert probe_binary_format(text_file) is None


def test_probe_binary_format_malformed_and_edge_cases(tmp_path: Path):
    # Empty file
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert probe_binary_format(empty) is None

    # 3-byte file
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"MZ\x00")
    assert probe_binary_format(tiny) is None

    # Java class file disambiguation (magic 0xCAFEBABE with major_version 52 / Java 8)
    java_class = tmp_path / "Test.class"
    java_class.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 32)
    assert probe_binary_format(java_class) is None


def test_elf_parser_crypto_server():
    elf_path = FIXTURE_DIR / "elf" / "crypto_server.elf"
    res = parse_elf(elf_path.read_bytes())
    assert res is not None
    assert res.architecture == "x86_64"
    assert "libcrypto.so.3" in res.linked_libraries
    assert "RSA_public_encrypt" in res.symbols
    assert "ECDSA_sign" in res.symbols
    assert "AES_encrypt" in res.symbols


def test_pe_parser_crypto_service():
    pe_path = FIXTURE_DIR / "pe" / "crypto_service.exe"
    res = parse_pe(pe_path.read_bytes())
    assert res is not None
    assert res.architecture == "x86_64"
    assert "bcrypt.dll" in res.linked_libraries
    assert "BCryptEncrypt" in res.symbols
    assert "BCryptDecrypt" in res.symbols


def test_macho_parser_crypto_tool():
    macho_path = FIXTURE_DIR / "macho" / "crypto_tool.dylib"
    res = parse_macho(macho_path.read_bytes())
    assert res is not None
    assert res.architecture == "x86_64"
    assert any("libcrypto" in lib for lib in res.linked_libraries)
    assert "RSA_public_encrypt" in res.symbols
    assert "ECDSA_sign" in res.symbols


def test_false_positive_filters():
    assert is_false_positive_string("keyboard") is True
    assert is_false_positive_string("userKey") is True
    assert is_false_positive_string("releaseKey") is True
    assert is_false_positive_string("encryptButton") is True
    assert is_false_positive_string("crypto_helper") is True
    assert is_false_positive_string("key_manager") is True

    # Real algorithms must not be false positives
    assert is_false_positive_string("RSA") is False
    assert is_false_positive_string("AES-256-GCM") is False
    assert is_false_positive_string("ECDSA") is False


def test_match_algorithm_string():
    assert match_algorithm_string("keyboard") is None
    assert match_algorithm_string("userKey") is None
    assert match_algorithm_string("encryptButton") is None

    # Algorithm matches
    rsa_match = match_algorithm_string("RSA-2048")
    assert rsa_match is not None
    assert rsa_match["canonical"] == "RSA"
    assert rsa_match["quantum_status"] == "broken-by-shor"

    aes_match = match_algorithm_string("AES-256-GCM")
    assert aes_match is not None
    assert aes_match["canonical"] == "AES"
    assert aes_match["mode"] == "gcm"
    assert aes_match["quantum_status"] == "weakened-by-grover"

    kyber_match = match_algorithm_string("Kyber")
    assert kyber_match is not None
    assert kyber_match["quantum_status"] == "quantum-safe"


def test_match_crypto_library():
    assert match_crypto_library("libcrypto.so.3") == "OpenSSL/libcrypto"
    assert match_crypto_library("libcrypto.so.1.1") == "OpenSSL/libcrypto"
    assert match_crypto_library("libssl.so") == "OpenSSL/libssl"
    assert match_crypto_library("libsodium.so.23") == "libsodium"
    assert match_crypto_library("libgcrypt.so.20") == "libgcrypt"
    assert match_crypto_library("libbssl.so") == "BoringSSL"
    assert match_crypto_library("libc.so.6") is None
    assert match_crypto_library("libm.so") is None


def test_malformed_binaries_resilience():
    # Never crash on corrupt or random binary inputs
    assert parse_elf(b"") is None
    assert parse_pe(b"") is None
    assert parse_macho(b"") is None

    noise = os.urandom(2048)
    assert parse_elf(noise) is None
    assert parse_pe(noise) is None
    assert parse_macho(noise) is None

    # Truncated ELF header returns None safely without error
    truncated_elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
    assert parse_elf(truncated_elf) is None
