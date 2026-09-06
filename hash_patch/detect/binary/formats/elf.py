"""hash_patch/detect/binary/formats/elf.py

Pure-Python parser for ELF32 and ELF64 binary formats.
Extracts:
1. Target architecture (e.g. x86_64, aarch64, arm, i386)
2. Linked dynamic libraries (DT_NEEDED entries)
3. Exported and imported symbol names (.dynsym, .symtab)
4. Section data offsets for string scanning
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Machine architectures
ELF_MACHINES = {
    3: "x86",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}

# Dynamic tags
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SONAME = 14

# Section header types
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11


@dataclass
class ElfSection:
    name: str
    sh_type: int
    sh_flags: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_entsize: int


@dataclass
class ParsedElf:
    format_name: str = "ELF"
    architecture: str | None = None
    is_64bit: bool = True
    endianness: str = "little"
    linked_libraries: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    sections: list[ElfSection] = field(default_factory=list)


def parse_elf(data: bytes) -> ParsedElf | None:
    """Parse an ELF binary from bytes safely. Returns None on corrupted/unsupported formats."""
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        return None

    try:
        ei_class = data[4]
        is_64bit = ei_class == 2
        ei_data = data[5]
        endian = "<" if ei_data == 1 else ">"

        e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
        arch = ELF_MACHINES.get(e_machine, f"machine_{e_machine}")

        parsed = ParsedElf(
            is_64bit=is_64bit,
            endianness="little" if ei_data == 1 else "big",
            architecture=arch,
        )

        if is_64bit:
            if len(data) < 64:
                return None
            e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = (
                struct.unpack_from(f"{endian}QQIHHHHHH", data, 32)
            )
        else:
            e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = (
                struct.unpack_from(f"{endian}IIIIHHHHHH", data, 28)
            )

        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
            # Relocatable or stripped binary without section headers — fallback
            return parsed

        # Bounds check section header table
        total_sh_bytes = e_shnum * e_shentsize
        if e_shoff + total_sh_bytes > len(data):
            # Truncated section header table
            return parsed

        # Read section headers
        raw_sections: list[tuple[int, int, int, int, int, int, int]] = []
        for i in range(min(e_shnum, 1024)):  # Bound to 1024 sections
            sh_offset = e_shoff + (i * e_shentsize)
            if is_64bit:
                sh_name, sh_type, sh_flags, sh_addr, sec_offset, sec_size, sh_link, sh_info, sh_addralign, sh_entsize = (
                    struct.unpack_from(f"{endian}IIQQQQIIQQ", data, sh_offset)
                )
            else:
                sh_name, sh_type, sh_flags, sh_addr, sec_offset, sec_size, sh_link, sh_info, sh_addralign, sh_entsize = (
                    struct.unpack_from(f"{endian}IIIIIIIIII", data, sh_offset)
                )
            raw_sections.append((sh_name, sh_type, sh_flags, sec_offset, sec_size, sh_link, sh_entsize))

        # Helper to read null-terminated string
        def read_cstring(strtab_offset: int, strtab_size: int, str_idx: int) -> str:
            if str_idx < 0 or str_idx >= strtab_size:
                return ""
            end = data.find(b"\x00", strtab_offset + str_idx)
            if end == -1 or end > strtab_offset + strtab_size:
                end = strtab_offset + strtab_size
            raw = data[strtab_offset + str_idx : end]
            return raw.decode("utf-8", errors="replace")

        # Resolve section names via shstrtab
        shstrtab_offset = 0
        shstrtab_size = 0
        if 0 <= e_shstrndx < len(raw_sections):
            _, _, _, shstrtab_offset, shstrtab_size, _, _ = raw_sections[e_shstrndx]

        sections: list[ElfSection] = []
        for sh_name, sh_type, sh_flags, sec_offset, sec_size, sh_link, sh_entsize in raw_sections:
            sec_name = read_cstring(shstrtab_offset, shstrtab_size, sh_name) if shstrtab_offset else ""
            sections.append(
                ElfSection(
                    name=sec_name,
                    sh_type=sh_type,
                    sh_flags=sh_flags,
                    sh_offset=sec_offset,
                    sh_size=sec_size,
                    sh_link=sh_link,
                    sh_entsize=sh_entsize,
                )
            )
        parsed.sections = sections

        # Extract symbols and dynamic libraries
        symbols_seen: set[str] = set()
        libs_seen: set[str] = set()

        for sec in sections:
            # 1. Symbol tables: SHT_SYMTAB or SHT_DYNSYM
            if sec.sh_type in (SHT_SYMTAB, SHT_DYNSYM) and sec.sh_size > 0:
                link_idx = sec.sh_link
                if 0 <= link_idx < len(sections):
                    strtab_sec = sections[link_idx]
                    strtab_offset = strtab_sec.sh_offset
                    strtab_size = strtab_sec.sh_size

                    entsize = sec.sh_entsize
                    if entsize == 0:
                        entsize = 24 if is_64bit else 16

                    num_syms = min(sec.sh_size // entsize, 20000)  # Bound to 20,000 symbols
                    for sym_i in range(num_syms):
                        sym_entry_off = sec.sh_offset + (sym_i * entsize)
                        if sym_entry_off + 4 > len(data):
                            break
                        st_name = struct.unpack_from(f"{endian}I", data, sym_entry_off)[0]
                        if st_name > 0:
                            sym_name = read_cstring(strtab_offset, strtab_size, st_name)
                            if sym_name and sym_name not in symbols_seen:
                                symbols_seen.add(sym_name)
                                parsed.symbols.append(sym_name)

            # 2. Dynamic section: SHT_DYNAMIC
            elif sec.sh_type == SHT_DYNAMIC and sec.sh_size > 0:
                link_idx = sec.sh_link
                if 0 <= link_idx < len(sections):
                    strtab_sec = sections[link_idx]
                    strtab_offset = strtab_sec.sh_offset
                    strtab_size = strtab_sec.sh_size

                    entsize = sec.sh_entsize or (16 if is_64bit else 8)
                    num_dyns = min(sec.sh_size // entsize, 1000)
                    for dyn_i in range(num_dyns):
                        dyn_off = sec.sh_offset + (dyn_i * entsize)
                        if is_64bit:
                            if dyn_off + 16 > len(data):
                                break
                            d_tag, d_val = struct.unpack_from(f"{endian}QQ", data, dyn_off)
                        else:
                            if dyn_off + 8 > len(data):
                                break
                            d_tag, d_val = struct.unpack_from(f"{endian}II", data, dyn_off)

                        if d_tag == DT_NULL:
                            break
                        if d_tag == DT_NEEDED:
                            lib_name = read_cstring(strtab_offset, strtab_size, d_val)
                            if lib_name and lib_name not in libs_seen:
                                libs_seen.add(lib_name)
                                parsed.linked_libraries.append(lib_name)

        return parsed
    except Exception:
        return None
