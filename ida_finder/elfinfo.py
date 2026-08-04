from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------- constants

ET_REL, ET_EXEC, ET_DYN, ET_CORE = 1, 2, 3, 4

SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_DYNAMIC = 2, 3, 4, 6
SHT_NOBITS, SHT_REL, SHT_DYNSYM = 8, 9, 11
SHT_INIT_ARRAY, SHT_FINI_ARRAY, SHT_PREINIT_ARRAY = 14, 15, 16
SHT_GNU_VERSYM, SHT_GNU_VERNEED, SHT_GNU_VERDEF = 0x6FFFFFFF, 0x6FFFFFFE, 0x6FFFFFFD

PT_LOAD, PT_DYNAMIC = 1, 2

STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_GNU_IFUNC = 0, 1, 2, 10
STV_DEFAULT, STV_INTERNAL, STV_HIDDEN, STV_PROTECTED = 0, 1, 2, 3
SHN_UNDEF, SHN_ABS = 0, 0xFFF1

DT_NEEDED, DT_INIT, DT_FINI, DT_SONAME, DT_RPATH = 1, 12, 13, 14, 15
DT_SYMBOLIC, DT_INIT_ARRAY, DT_FINI_ARRAY = 16, 25, 26
DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH = 27, 28, 29
DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ = 32, 33

EM_NAMES = {
    3: "i386", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm",
    62: "x86_64", 183: "aarch64", 243: "riscv", 106: "sparc",
}


class ELFError(Exception):
    pass


# ---------------------------------------------------------------- records

@dataclass(frozen=True)
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    size: int
    info: int
    other: int
    shndx: int
    version: str | None = None

    @property
    def bind(self) -> int:
        return self.info >> 4

    @property
    def type(self) -> int:
        return self.info & 0xF

    @property
    def visibility(self) -> int:
        return self.other & 0x3

    @property
    def is_undef(self) -> bool:
        return self.shndx == SHN_UNDEF

    @property
    def is_exported(self) -> bool:
        return (
            not self.is_undef
            and self.bind in (STB_GLOBAL, STB_WEAK)
            and self.visibility in (STV_DEFAULT, STV_PROTECTED)
            and bool(self.name)
        )

    @property
    def is_callable(self) -> bool:
        return self.type in (STT_FUNC, STT_GNU_IFUNC, STT_NOTYPE)


@dataclass
class ELF:
    path: Path
    is64: bool
    big_endian: bool
    e_type: int
    machine: int
    entry: int
    sections: list[Section] = field(default_factory=list)
    segments: list[tuple[int, int, int, int, int]] = field(default_factory=list)
    dynamic: list[tuple[int, int]] = field(default_factory=list)
    dynsyms: list[Symbol] = field(default_factory=list)
    symtab: list[Symbol] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)
    soname: str | None = None
    runpath: list[str] = field(default_factory=list)
    init_fini: list[int] = field(default_factory=list)

    # ---- convenience -----------------------------------------------------

    @property
    def arch(self) -> str:
        base = EM_NAMES.get(self.machine, f"em{self.machine}")
        return f"{base}{'64' if self.is64 else '32'}{'be' if self.big_endian else 'le'}"

    @property
    def is_kernel_module(self) -> bool:
        return self.e_type == ET_REL and any(
            s.name.startswith((".gnu.linkonce.this_module", ".modinfo")) for s in self.sections
        )

    def section(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def exports(self) -> set[str]:
        if self.is_kernel_module:
            # Kernel modules export through __ksymtab_<name>, not dynsym.
            out = {
                s.name[len("__ksymtab_"):]
                for s in self.symtab
                if s.name.startswith("__ksymtab_")
            }
            return out
        return {s.name for s in self.dynsyms if s.is_exported and s.is_callable}

    def export_symbols(self) -> list[Symbol]:
        return [s for s in self.dynsyms if s.is_exported and s.is_callable]

    def imports(self) -> set[str]:
        src = self.symtab if self.is_kernel_module else self.dynsyms
        return {s.name for s in src if s.is_undef and s.name and s.is_callable}

    def ifunc_resolvers(self) -> set[int]:
        return {s.value for s in self.dynsyms if s.type == STT_GNU_IFUNC and not s.is_undef}


# ---------------------------------------------------------------- parsing

def _magic_ok(data: bytes) -> bool:
    return len(data) >= 20 and data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2)


def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return _magic_ok(fh.read(20))
    except OSError:
        return False


class _Reader:
    def __init__(self, data: bytes, is64: bool, big: bool):
        self.d = data
        self.is64 = is64
        self.e = ">" if big else "<"

    def u(self, fmt: str, off: int):
        size = struct.calcsize(self.e + fmt)
        if off < 0 or off + size > len(self.d):
            raise ELFError("read past end of file")
        return struct.unpack_from(self.e + fmt, self.d, off)

    def u16(self, off: int) -> int:
        return self.u("H", off)[0]

    def u32(self, off: int) -> int:
        return self.u("I", off)[0]

    def word(self, off: int) -> int:
        return self.u("Q" if self.is64 else "I", off)[0]

    @property
    def wsize(self) -> int:
        return 8 if self.is64 else 4

    def cstr(self, off: int) -> str:
        if off <= 0 or off >= len(self.d):
            return ""
        end = self.d.find(b"\x00", off)
        if end < 0:
            end = len(self.d)
        return self.d[off:end].decode("utf-8", "replace")


def parse(path: Path, data: bytes | None = None) -> ELF:
    if data is None:
        data = Path(path).read_bytes()
    if not _magic_ok(data):
        raise ELFError("not an ELF")

    is64 = data[4] == 2
    big = data[5] == 2
    r = _Reader(data, is64, big)

    if is64:
        e_type, machine = r.u16(16), r.u16(18)
        entry, phoff, shoff = r.word(24), r.word(32), r.word(40)
        phentsize, phnum = r.u16(54), r.u16(56)
        shentsize, shnum, shstrndx = r.u16(58), r.u16(60), r.u16(62)
    else:
        e_type, machine = r.u16(16), r.u16(18)
        entry, phoff, shoff = r.word(24), r.word(28), r.word(32)
        phentsize, phnum = r.u16(42), r.u16(44)
        shentsize, shnum, shstrndx = r.u16(46), r.u16(48), r.u16(50)

    elf = ELF(Path(path), is64, big, e_type, machine, entry)

    # ---- program headers (needed to map vaddr -> file offset) ------------
    for i in range(phnum):
        base = phoff + i * phentsize
        try:
            if is64:
                p_type = r.u32(base)
                p_off, p_vaddr = r.word(base + 8), r.word(base + 16)
                p_filesz, p_memsz = r.word(base + 32), r.word(base + 40)
            else:
                p_type = r.u32(base)
                p_off, p_vaddr = r.word(base + 4), r.word(base + 8)
                p_filesz, p_memsz = r.word(base + 16), r.word(base + 20)
        except ELFError:
            break
        elf.segments.append((p_type, p_off, p_vaddr, p_filesz, p_memsz))

    # ---- section headers -------------------------------------------------
    raw: list[tuple[int, ...]] = []
    for i in range(shnum):
        base = shoff + i * shentsize
        try:
            if is64:
                vals = r.u("IIQQQQIIQQ", base)  # name type flags addr off size link info align ent
            else:
                vals = r.u("IIIIIIIIII", base)
        except ELFError:
            break
        raw.append(vals)

    shstr_off = raw[shstrndx][4] if 0 <= shstrndx < len(raw) else 0
    for vals in raw:
        name = r.cstr(shstr_off + vals[0]) if shstr_off else ""
        elf.sections.append(
            Section(name, vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7], vals[9])
        )

    # ---- dynamic ---------------------------------------------------------
    _parse_dynamic(elf, r)
    _parse_symbols(elf, r)
    _apply_versions(elf, r)
    return elf


def _vaddr_to_off(elf: ELF, vaddr: int) -> int | None:
    for p_type, p_off, p_vaddr, p_filesz, _ in elf.segments:
        if p_type == PT_LOAD and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_off + (vaddr - p_vaddr)
    return None


def _parse_dynamic(elf: ELF, r: _Reader) -> None:
    sec = next((s for s in elf.sections if s.sh_type == SHT_DYNAMIC), None)
    if sec is not None:
        off, size, strtab_sec = sec.offset, sec.size, sec.link
        dynstr_off = elf.sections[strtab_sec].offset if strtab_sec < len(elf.sections) else 0
    else:
        seg = next((s for s in elf.segments if s[0] == PT_DYNAMIC), None)
        if seg is None:
            return
        off, size, dynstr_off = seg[1], seg[3], 0

    entries: list[tuple[int, int]] = []
    step = r.wsize * 2
    for pos in range(off, off + size, step):
        try:
            tag, val = r.word(pos), r.word(pos + r.wsize)
        except ELFError:
            break
        if tag == 0:
            break
        entries.append((tag, val))
    elf.dynamic = entries

    if not dynstr_off:  # PT_DYNAMIC fallback: DT_STRTAB is a vaddr
        strtab_va = next((v for t, v in entries if t == 5), 0)
        dynstr_off = _vaddr_to_off(elf, strtab_va) or 0

    for tag, val in entries:
        if tag == DT_NEEDED:
            elf.needed.append(r.cstr(dynstr_off + val))
        elif tag == DT_SONAME:
            elf.soname = r.cstr(dynstr_off + val)
        elif tag in (DT_RPATH, DT_RUNPATH):
            elf.runpath.extend(p for p in r.cstr(dynstr_off + val).split(":") if p)
        elif tag in (DT_INIT, DT_FINI):
            elf.init_fini.append(val)

    # DT_*_ARRAY contents are the real constructor/destructor roots.
    for tag, szt in ((DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
                     (DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
                     (DT_FINI_ARRAY, DT_FINI_ARRAYSZ)):
        va = next((v for t, v in entries if t == tag), None)
        sz = next((v for t, v in entries if t == szt), 0)
        if va is None or not sz:
            continue
        base = _vaddr_to_off(elf, va)
        if base is None:
            continue
        for pos in range(base, base + sz, r.wsize):
            try:
                ptr = r.word(pos)
            except ELFError:
                break
            if ptr not in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                elf.init_fini.append(ptr)


def _read_symtab(elf: ELF, r: _Reader, sec: Section) -> list[Symbol]:
    if sec.link >= len(elf.sections):
        return []
    stroff = elf.sections[sec.link].offset
    ent = sec.entsize or (24 if elf.is64 else 16)
    out: list[Symbol] = []
    for pos in range(sec.offset, sec.offset + sec.size, ent):
        try:
            if elf.is64:
                n, info, other, shndx, value, size = r.u("IBBHQQ", pos)
            else:
                n, value, size, info, other, shndx = r.u("IIIBBH", pos)
        except ELFError:
            break
        out.append(Symbol(r.cstr(stroff + n), value, size, info, other, shndx))
    return out


def _parse_symbols(elf: ELF, r: _Reader) -> None:
    for sec in elf.sections:
        if sec.sh_type == SHT_DYNSYM:
            elf.dynsyms = _read_symtab(elf, r, sec)
        elif sec.sh_type == SHT_SYMTAB:
            elf.symtab = _read_symtab(elf, r, sec)


def _apply_versions(elf: ELF, r: _Reader) -> None:
    versym = next((s for s in elf.sections if s.sh_type == SHT_GNU_VERSYM), None)
    if versym is None or not elf.dynsyms:
        return

    names: dict[int, str] = {}
    for sec in elf.sections:
        if sec.link >= len(elf.sections):
            continue
        stroff = elf.sections[sec.link].offset
        if sec.sh_type == SHT_GNU_VERNEED:
            pos = sec.offset
            for _ in range(sec.info):
                try:
                    _, cnt, _, aux, nxt = r.u("HHIII", pos)
                except ELFError:
                    break
                apos = pos + aux
                for _ in range(cnt):
                    try:
                        _, _, other, nameoff, anext = r.u("IHHII", apos)
                    except ELFError:
                        break
                    names[other & 0x7FFF] = r.cstr(stroff + nameoff)
                    if not anext:
                        break
                    apos += anext
                if not nxt:
                    break
                pos += nxt
        elif sec.sh_type == SHT_GNU_VERDEF:
            pos = sec.offset
            for _ in range(sec.info):
                try:
                    _, _, ndx, cnt, _, aux, nxt = r.u("HHHHIII", pos)
                except ELFError:
                    break
                if cnt:
                    try:
                        nameoff, _ = r.u("II", pos + aux)
                        names[ndx & 0x7FFF] = r.cstr(stroff + nameoff)
                    except ELFError:
                        pass
                if not nxt:
                    break
                pos += nxt

    updated: list[Symbol] = []
    for i, sym in enumerate(elf.dynsyms):
        try:
            idx = r.u16(versym.offset + i * 2) & 0x7FFF
        except ELFError:
            idx = 0
        ver = names.get(idx) if idx > 1 else None
        updated.append(Symbol(sym.name, sym.value, sym.size, sym.info,
                              sym.other, sym.shndx, ver))
    elf.dynsyms = updated


def safe_parse(path: Path) -> ELF | None:
    try:
        return parse(path)
    except (ELFError, OSError, struct.error, IndexError):
        return None
