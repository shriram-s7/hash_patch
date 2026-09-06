"""hash_patch/detect/binary/formats/macho.py

Pure-Python parser for Mach-O 32-bit, 64-bit, and Universal/Fat binary formats.
Extracts:
1. Target architecture (e.g. x86_64, arm64, arm, x86)
2. Linked dynamic libraries (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB)
3. Imported and exported symbols (LC_SYMTAB)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MACHO_CPUTYPES = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
}

# Load commands
LC_SYMTAB = 0x02
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
LC_REEXPORT_DYLIB = 0x1F | 0x80000000


@dataclass
class ParsedMacho:
    format_name: str = "Mach-O"
    architecture: str | None = None
    is_64bit: bool = True
    linked_libraries: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)


def parse_macho(data: bytes) -> ParsedMacho | None:
    """Parse a macOS Mach-O binary or Universal/Fat binary from bytes safely."""
    if len(data) < 28:
        return None

    try:
        magic_be = struct.unpack(">I", data[:4])[0]

        # 1. Universal / Fat binary check
        if magic_be in (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA):
            endian = ">" if magic_be in (0xCAFEBABE, 0xCAFEBABF) else "<"
            is_fat64 = magic_be in (0xCAFEBABF, 0xBFBAFECA)
            nfat_arch = struct.unpack_from(f"{endian}I", data, 4)[0]
            if nfat_arch == 0 or nfat_arch > 32:
                return None

            # Parse first valid slice
            fat_arch_size = 32 if is_fat64 else 20
            archs_found: list[str] = []
            primary_slice_data: bytes | None = None

            for i in range(min(nfat_arch, 8)):
                off = 8 + (i * fat_arch_size)
                if off + fat_arch_size > len(data):
                    break
                cputype = struct.unpack_from(f"{endian}I", data, off)[0]
                arch_name = MACHO_CPUTYPES.get(cputype, f"cputype_{cputype:#x}")
                archs_found.append(arch_name)
                slice_off = struct.unpack_from(f"{endian}Q" if is_fat64 else f"{endian}I", data, off + 8)[0]
                slice_size = struct.unpack_from(f"{endian}Q" if is_fat64 else f"{endian}I", data, off + (16 if is_fat64 else 12))[0]
                if primary_slice_data is None and slice_off + slice_size <= len(data):
                    primary_slice_data = data[slice_off : slice_off + slice_size]

            if primary_slice_data is not None:
                parsed_slice = _parse_single_macho(primary_slice_data)
                if parsed_slice is not None:
                    if archs_found:
                        parsed_slice.architecture = "/".join(archs_found)
                    return parsed_slice
            return None

        # 2. Single architecture Mach-O
        return _parse_single_macho(data)
    except Exception:
        return None


def _parse_single_macho(data: bytes) -> ParsedMacho | None:
    if len(data) < 28:
        return None

    try:
        magic_be = struct.unpack(">I", data[:4])[0]
        if magic_be in (0xFEEDFACE, 0xFEEDFACF):
            endian = ">"
            is_64bit = magic_be == 0xFEEDFACF
        elif magic_be in (0xCEFAEDFE, 0xCFFAEDFE):
            endian = "<"
            is_64bit = magic_be == 0xCFFAEDFE
        else:
            return None

        cputype, _, _, ncmds, sizeofcmds, _ = struct.unpack_from(f"{endian}IIIIII", data, 4)
        arch = MACHO_CPUTYPES.get(cputype, f"cputype_{cputype:#x}")

        header_size = 32 if is_64bit else 28
        if header_size + sizeofcmds > len(data):
            return None

        parsed = ParsedMacho(
            architecture=arch,
            is_64bit=is_64bit,
        )

        libs_seen: set[str] = set()
        symbols_seen: set[str] = set()

        cmd_offset = header_size
        for _ in range(min(ncmds, 512)):
            if cmd_offset + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(f"{endian}II", data, cmd_offset)
            if cmdsize < 8 or cmd_offset + cmdsize > len(data):
                break

            # Linked dynamic libraries
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                if cmdsize >= 16:
                    str_offset_in_cmd = struct.unpack_from(f"{endian}I", data, cmd_offset + 8)[0]
                    str_abs_off = cmd_offset + str_offset_in_cmd
                    if str_abs_off < cmd_offset + cmdsize:
                        end = data.find(b"\x00", str_abs_off)
                        if end == -1 or end > cmd_offset + cmdsize:
                            end = cmd_offset + cmdsize
                        raw_dylib = data[str_abs_off:end].decode("utf-8", errors="replace")
                        dylib_name = raw_dylib.split("/")[-1] if raw_dylib else ""
                        if dylib_name and dylib_name not in libs_seen:
                            libs_seen.add(dylib_name)
                            parsed.linked_libraries.append(dylib_name)

            # Symbol table
            elif cmd == LC_SYMTAB:
                if cmdsize >= 24:
                    symoff, nsyms, stroff, strsize = struct.unpack_from(
                        f"{endian}IIII", data, cmd_offset + 8
                    )
                    nlist_size = 16 if is_64bit else 12
                    if symoff + (nsyms * nlist_size) <= len(data) and stroff + strsize <= len(data):
                        for sym_i in range(min(nsyms, 20000)):
                            entry_off = symoff + (sym_i * nlist_size)
                            n_strx = struct.unpack_from(f"{endian}I", data, entry_off)[0]
                            if 0 < n_strx < strsize:
                                str_off = stroff + n_strx
                                end = data.find(b"\x00", str_off)
                                if end == -1 or end > stroff + strsize:
                                    end = stroff + strsize
                                sym_name = data[str_off:end].decode("utf-8", errors="replace")
                                # Mach-O C symbols are typically prefixed with an underscore (e.g. _RSA_public_encrypt)
                                clean_name = sym_name.removeprefix("_")
                                if clean_name and clean_name not in symbols_seen:
                                    symbols_seen.add(clean_name)
                                    parsed.symbols.append(clean_name)

            cmd_offset += cmdsize

        return parsed
    except Exception:
        return None
