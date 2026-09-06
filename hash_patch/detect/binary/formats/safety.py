"""hash_patch/detect/binary/formats/safety.py

Safe header magic probing and bounds checking for compiled binary artifacts.
Guarantees:
1. Rejects non-binary files (e.g. source code, text) in microseconds without loading.
2. Identifies ELF, PE, and Mach-O strictly from content/magic, not just file extensions.
3. Defensively bounds maximum file sizes to prevent OOM/DoS.
4. Handles empty, truncated, or unreadable files safely.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Literal

BinaryFormat = Literal["ELF", "PE", "Mach-O"]

MAX_BINARY_SCAN_BYTES = 50 * 1024 * 1024  # 50 MB safety ceiling for full scanning

# Magic constants
ELF_MAGIC = b"\x7fELF"
DOS_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

MACHO_MAGICS = {
    0xFEEDFACE: ("Mach-O 32-bit", False),
    0xCEFAEDFE: ("Mach-O 32-bit", True),   # Byte-swapped
    0xFEEDFACF: ("Mach-O 64-bit", False),
    0xCFFAEDFE: ("Mach-O 64-bit", True),   # Byte-swapped
    0xCAFEBABE: ("Mach-O Universal", False),
    0xBEBAFECA: ("Mach-O Universal", True),
    0xCAFEBABF: ("Mach-O Universal 64-bit", False),
    0xBFBAFECA: ("Mach-O Universal 64-bit", True),
}


def probe_binary_format(path: Path) -> BinaryFormat | None:
    """Read the initial header bytes of a file and determine if it is a supported binary.

    Returns 'ELF', 'PE', 'Mach-O', or None if the file is not a supported compiled binary.
    Never throws an exception: permission errors, missing files, or truncated files return None.
    """
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
        if size < 4:
            return None

        with path.open("rb") as f:
            header = f.read(1024)

        if len(header) < 4:
            return None

        # 1. ELF check
        if header.startswith(ELF_MAGIC):
            return "ELF"

        # 2. PE check: starts with 'MZ', and at e_lfanew has 'PE\0\0'
        if header.startswith(DOS_MAGIC) and len(header) >= 64:
            try:
                e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
                if e_lfanew > 0 and e_lfanew + 4 <= size:
                    # If e_lfanew is within the initial 1024 bytes
                    if e_lfanew + 4 <= len(header):
                        pe_sig = header[e_lfanew : e_lfanew + 4]
                    else:
                        with path.open("rb") as f2:
                            f2.seek(e_lfanew)
                            pe_sig = f2.read(4)
                    if pe_sig == PE_SIGNATURE:
                        return "PE"
            except Exception:
                pass

        # 3. Mach-O check
        if len(header) >= 4:
            magic_be = struct.unpack(">I", header[:4])[0]
            if magic_be in MACHO_MAGICS:
                # Disambiguate Java class file: Java class files also start with 0xCAFEBABE!
                # In Java class files, bytes 4..8 are minor_version (2 bytes) + major_version (2 bytes).
                # Major version for Java 1.1+ is >= 45 (0x2D).
                # In Mach-O Fat Universal, bytes 4..8 are nfat_arch (number of architectures, usually 1-5).
                if magic_be == 0xCAFEBABE and len(header) >= 8:
                    nfat_or_major = struct.unpack(">I", header[4:8])[0]
                    # If the integer after 0xCAFEBABE is >= 45, it's a Java .class file, NOT a Mach-O!
                    if nfat_or_major >= 45:
                        return None
                return "Mach-O"

        return None
    except Exception:
        return None
