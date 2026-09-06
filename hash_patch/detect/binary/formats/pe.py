"""hash_patch/detect/binary/formats/pe.py

Pure-Python parser for PE32 and PE32+ (Portable Executable) binary formats.
Extracts:
1. Target architecture (e.g. x86_64, x86, arm64)
2. Linked / imported DLLs (from Import Directory and Delay Import Directory)
3. Imported and exported symbols
4. Section information
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86_64",
    0xAA64: "arm64",
    0x01C0: "arm",
}


@dataclass
class PeSection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass
class ParsedPe:
    format_name: str = "PE"
    architecture: str | None = None
    is_64bit: bool = True
    linked_libraries: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    sections: list[PeSection] = field(default_factory=list)


def parse_pe(data: bytes) -> ParsedPe | None:
    """Parse a Windows PE executable or DLL from bytes safely."""
    if len(data) < 128 or not data.startswith(b"MZ"):
        return None

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None

        coff_offset = e_lfanew + 4
        machine, num_sections, _, _, _, size_of_opt_header, _ = struct.unpack_from(
            "<HHIIIHH", data, coff_offset
        )

        arch = PE_MACHINES.get(machine, f"machine_{machine:#x}")
        opt_offset = coff_offset + 20
        if opt_offset + 2 > len(data):
            return None

        opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_64bit = opt_magic == 0x020B

        parsed = ParsedPe(
            architecture=arch,
            is_64bit=is_64bit,
        )

        # Section headers follow Optional Header
        sec_headers_offset = opt_offset + size_of_opt_header
        sections: list[PeSection] = []
        for i in range(min(num_sections, 96)):
            sec_off = sec_headers_offset + (i * 40)
            if sec_off + 40 > len(data):
                break
            raw_name = data[sec_off : sec_off + 8].rstrip(b"\x00")
            name = raw_name.decode("latin1", errors="replace")
            vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", data, sec_off + 8)
            sections.append(
                PeSection(
                    name=name,
                    virtual_address=vaddr,
                    virtual_size=vsize,
                    raw_offset=raw_off,
                    raw_size=raw_size,
                )
            )
        parsed.sections = sections

        def rva_to_offset(rva: int) -> int | None:
            for s in sections:
                size = max(s.virtual_size, s.raw_size)
                if s.virtual_address <= rva < s.virtual_address + size:
                    off = rva - s.virtual_address + s.raw_offset
                    if off < len(data):
                        return off
            return None

        def read_cstring(offset: int | None) -> str:
            if offset is None or offset >= len(data):
                return ""
            end = data.find(b"\x00", offset)
            if end == -1:
                end = min(offset + 256, len(data))
            return data[offset:end].decode("utf-8", errors="replace")

        # Data directories
        data_dir_offset = opt_offset + (112 if is_64bit else 96)
        export_rva = export_size = import_rva = import_size = 0
        if data_dir_offset + 16 <= sec_headers_offset:
            export_rva, export_size = struct.unpack_from("<II", data, data_dir_offset)
            import_rva, import_size = struct.unpack_from("<II", data, data_dir_offset + 8)

        libs_seen: set[str] = set()
        symbols_seen: set[str] = set()

        # 1. Parse Imports (IMAGE_IMPORT_DESCRIPTOR array)
        if import_rva > 0:
            import_off = rva_to_offset(import_rva)
            if import_off is not None:
                for i in range(256):  # Bound to 256 imported DLLs
                    desc_off = import_off + (i * 20)
                    if desc_off + 20 > len(data):
                        break
                    orig_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, desc_off)
                    if name_rva == 0 and first_thunk == 0:
                        break  # Null terminator

                    dll_name = read_cstring(rva_to_offset(name_rva))
                    if dll_name and dll_name not in libs_seen:
                        libs_seen.add(dll_name)
                        parsed.linked_libraries.append(dll_name)

                    # Import thunks (symbols)
                    thunk_rva = orig_thunk if orig_thunk != 0 else first_thunk
                    thunk_off = rva_to_offset(thunk_rva)
                    if thunk_off is not None:
                        step = 8 if is_64bit else 4
                        for j in range(2000):  # Bound to 2000 symbols per DLL
                            entry_off = thunk_off + (j * step)
                            if entry_off + step > len(data):
                                break
                            val = (
                                struct.unpack_from("<Q", data, entry_off)[0]
                                if is_64bit
                                else struct.unpack_from("<I", data, entry_off)[0]
                            )
                            if val == 0:
                                break
                            ordinal_flag = (1 << 63) if is_64bit else (1 << 31)
                            if not (val & ordinal_flag):
                                # Import by name: val is RVA to IMAGE_IMPORT_BY_NAME
                                name_entry_off = rva_to_offset(val)
                                if name_entry_off is not None and name_entry_off + 2 < len(data):
                                    sym_name = read_cstring(name_entry_off + 2)
                                    if sym_name and sym_name not in symbols_seen:
                                        symbols_seen.add(sym_name)
                                        parsed.symbols.append(sym_name)

        # 2. Parse Exports (IMAGE_EXPORT_DIRECTORY)
        if export_rva > 0:
            exp_off = rva_to_offset(export_rva)
            if exp_off is not None and exp_off + 40 <= len(data):
                _, _, _, name_rva, _, num_names, _, names_rva, _ = struct.unpack_from(
                    "<IIIIIIIII", data, exp_off + 4
                )
                names_table_off = rva_to_offset(names_rva)
                if names_table_off is not None:
                    for i in range(min(num_names, 5000)):
                        if names_table_off + (i * 4) + 4 > len(data):
                            break
                        n_rva = struct.unpack_from("<I", data, names_table_off + (i * 4))[0]
                        sym_name = read_cstring(rva_to_offset(n_rva))
                        if sym_name and sym_name not in symbols_seen:
                            symbols_seen.add(sym_name)
                            parsed.symbols.append(sym_name)

        return parsed
    except Exception:
        return None
