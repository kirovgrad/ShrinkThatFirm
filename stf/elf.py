from __future__ import annotations

import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

# e_type
ET_EXEC = 2
ET_DYN = 3

# p_type
PT_LOAD = 1
PT_DYNAMIC = 2

# d_tag (subset we care about)
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SONAME = 14

# ELF header field offsets
_EI_CLASS = 4
_EI_DATA = 5

# Struct layouts (little/big endian). Each is: '<' or '>' + format string.
_EHDR32 = "16sHHI IIIIHHHHHH"
_EHDR64 = "16sHHI QQQIHHHHHH"
_PHDR32 = "IIIIIIII"
_PHDR64 = "IIQQQQQQ"
_DYN32 = "iI"
_DYN64 = "qQ"


def _fmt(endian: str, layout: str) -> str:
    return endian + layout


class ELFParserError(Exception):
    """Raised when a file cannot be parsed as ELF."""


def is_elf(path: str | Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == ELF_MAGIC
    except OSError:
        return False


def parse_needed_libraries(path: str | Path) -> set[str]:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return set()

    try:
        needed, _soname = _parse_dynamic(data)
    except (ELFParserError, struct.error):
        return set()
    return needed


def _parse_dynamic(data: bytes) -> tuple[set[str], str | None]:
    if data[:4] != ELF_MAGIC:
        raise ELFParserError("not an ELF file")

    elf_class = data[_EI_CLASS]
    endian = "<" if data[_EI_DATA] == 1 else ">"

    if elf_class == 1:
        ehdr = struct.unpack_from(_fmt(endian, _EHDR32), data, 0)
        phoff = ehdr[5]
        phentsize, phnum = ehdr[9], ehdr[10]
        phdr_fmt = _fmt(endian, _PHDR32)
    elif elf_class == 2:
        ehdr = struct.unpack_from(_fmt(endian, _EHDR64), data, 0)
        phoff = ehdr[5]
        phentsize, phnum = ehdr[9], ehdr[10]
        phdr_fmt = _fmt(endian, _PHDR64)
    else:
        raise ELFParserError(f"unsupported ELF class {elf_class}")

    if phnum == 0 or phentsize == 0:
        return set(), None

    # Collect PT_LOAD segments first so we can translate virtual addresses
    # (as found in DT_STRTAB) back to file offsets.
    loads: list[tuple[int, int, int]] = []  # (vaddr, offset, filesz)
    dynamic: tuple[int, int] | None = None  # (offset, filesz)

    for i in range(phnum):
        off = phoff + i * phentsize
        if off + phentsize > len(data):
            break
        phdr = struct.unpack_from(phdr_fmt, data, off)
        if elf_class == 1:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = phdr[:6]
        else:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = phdr[:7]

        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)

    if dynamic is None:
        return set(), None

    dyn_off, dyn_size = dynamic
    if dyn_off + dyn_size > len(data):
        raise ELFParserError("dynamic segment out of bounds")

    dyn_fmt = _fmt(endian, _DYN64 if elf_class == 2 else _DYN32)
    dyn_entry_size = struct.calcsize(dyn_fmt)

    strtab_vaddr: int | None = None
    needed_offsets: list[int] = []
    soname_offset: int | None = None

    for j in range(0, dyn_size, dyn_entry_size):
        off = dyn_off + j
        if off + dyn_entry_size > len(data):
            break
        tag, val = struct.unpack_from(dyn_fmt, data, off)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            needed_offsets.append(val)
        elif tag == DT_SONAME:
            soname_offset = val
        elif tag == DT_STRTAB:
            strtab_vaddr = val

    if strtab_vaddr is None:
        return set(), None

    strtab_off = _vaddr_to_offset(strtab_vaddr, loads, len(data))
    if strtab_off is None:
        return set(), None

    def read_cstring(start: int) -> str:
        if start >= len(data):
            return ""
        end = data.find(b"\x00", start)
        if end == -1:
            end = len(data)
        return data[start:end].decode("utf-8", "replace")

    needed = {read_cstring(strtab_off + off) for off in needed_offsets}
    needed.discard("")
    soname = read_cstring(strtab_off + soname_offset) if soname_offset is not None else None
    return needed, soname


def _vaddr_to_offset(vaddr: int, loads: list[tuple[int, int, int]], file_size: int) -> int | None:
    for base, offset, size in loads:
        if base <= vaddr < base + max(size, 1):
            return offset + (vaddr - base)
    return None


def is_shared_object(path: str | Path) -> bool:
    """Return True for ET_DYN ELF files (shared objects / PIE executables)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(64)
        return struct.unpack_from("<H", data, 16)[0] == ET_DYN
    except (OSError, struct.error):
        return False
