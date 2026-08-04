from __future__ import annotations

import concurrent.futures
import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Sequence

from .config import Config
from .elf import is_elf
from .models import FunctionGroup, FunctionInfo
from .progress import ProgressBar, get_logger

logger = get_logger()

_STT_FUNC = "STT_FUNC"


def _pyelftools_available() -> bool:
    try:
        import elftools  # noqa: F401
        return True
    except ImportError:
        return False


def _r2pipe_available() -> bool:
    try:
        import r2pipe  # noqa: F401
        return True
    except ImportError:
        return False


def _symbol_functions(
    elf, path: Path, min_size: int
) -> tuple[list[FunctionInfo], set[int], int]:
    text = elf.get_section_by_name(".text")
    if text is None:
        return [], set(), 0

    text_addr = text["sh_addr"]
    text_data = text.data()            # raw .text bytes, read exactly once
    text_len = len(text_data)

    symtab = elf.get_section_by_name(".symtab") or elf.get_section_by_name(".dynsym")
    if symtab is None:
        return [], set(), text_addr

    functions: list[FunctionInfo] = []
    known: set[int] = set()
    for sym in symtab.iter_symbols():
        if sym["st_info"]["type"] != _STT_FUNC:
            continue
        addr = sym["st_value"] & ~1                 # mask the Thumb bit on ARM
        size = sym["st_size"]
        if size < min_size or addr in known:        # drop aliases at same addr
            continue
        off = addr - text_addr
        if off < 0 or off + size > text_len:        # PLT/init stubs, .text only
            continue
        known.add(addr)
        code = text_data[off:off + size]
        functions.append(
            FunctionInfo(
                binary=path,
                name=sym.name or f"unnamed_{addr:x}",
                size=size,
                opcode_hash=hashlib.sha256(code).hexdigest(),
                offset=addr,
            )
        )
    return functions, known, text_addr


def _discover_unsymbolized(
    path: Path, known: set[int], elf_text_addr: int, min_size: int, analysis_cmd: str
) -> list[FunctionInfo]:
    import r2pipe

    functions: list[FunctionInfo] = []
    r2 = None
    try:
        r2 = r2pipe.open(str(path), flags=["-2"])   # -2 silences r2's stderr
        r2.cmd(analysis_cmd)

        r2_text = next(
            (s for s in (r2.cmdj("iSj") or []) if s.get("name") == ".text"), None
        )
        if not r2_text:
            return functions
        r2_text_start = r2_text["vaddr"]
        r2_text_end = r2_text_start + r2_text["vsize"]
        delta = r2_text_start - elf_text_addr        # r2 space -> link space

        for fn in r2.cmdj("aflj") or []:
            addr, size = fn["offset"], fn["size"]
            if size < min_size or not (r2_text_start <= addr < r2_text_end):
                continue
            link_addr = addr - delta
            if link_addr in known:                   # already have it as a symbol
                continue
            hexbytes = r2.cmd(f"p8 {size} @ {addr}")
            if not hexbytes:
                continue
            try:
                code = bytes.fromhex("".join(hexbytes.split()))
            except ValueError:
                continue
            functions.append(
                FunctionInfo(
                    binary=path,
                    name=fn.get("name") or f"unnamed_{link_addr:x}",
                    size=size,
                    opcode_hash=hashlib.sha256(code).hexdigest(),
                    offset=link_addr,
                )
            )
        return functions
    except Exception as exc:  # noqa: BLE001 - analysis errors must not abort the scan
        logger.debug("radare2 discovery failed for %s: %s", path, exc)
        return functions
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:  # noqa: BLE001 - r2 may already be gone
                pass


def _extract_functions(
    path: Path, min_size: int, discover: bool, analysis_cmd: str
) -> list[FunctionInfo]:
    from elftools.elf.elffile import ELFFile

    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            functions, known, text_addr = _symbol_functions(elf, path, min_size)
    except Exception as exc:  # noqa: BLE001 - a bad file must not abort the scan
        logger.debug("Failed to read symbols from %s: %s", path, exc)
        return []

    if discover:
        # Empty symbol table => effectively stripped => let r2 do full analysis.
        cmd = analysis_cmd if known else "aaa"
        functions += _discover_unsymbolized(path, known, text_addr, min_size, cmd)
    return functions


def find_duplicate_functions(
    config: Config, binaries: Sequence[Path]
) -> list[FunctionGroup]:
    elf_binaries = [p for p in binaries if is_elf(p)]
    if not elf_binaries:
        logger.info("No ELF binaries to analyze for duplicate functions.")
        return []

    if not _pyelftools_available():
        logger.warning(
            "Skipping duplicate-function analysis: pyelftools is not installed. "
            "Install it with: pip install pyelftools"
        )
        return []

    min_size = config.dup_func_min_size
    want_discover = getattr(config, "dup_func_discover", True)
    analysis_cmd = getattr(config, "dup_func_r2_analysis", "aa;aac")

    discover = bool(want_discover) and _r2pipe_available()
    if want_discover and not discover:
        logger.warning(
            "Unsymbolised-function discovery requested but r2pipe is not "
            "installed; analysing symbolised functions only. "
            "Install it with: pip install r2pipe"
        )

    logger.info(
        "Analyzing %d ELF binaries (%s)...",
        len(elf_binaries),
        "symbols + radare2 discovery" if discover else "symbols only",
    )

    functions: list[FunctionInfo] = []
    bar = ProgressBar(len(elf_binaries))
    # The symbol layer is pure-Python and GIL-bound, so processes (not threads)
    # give real parallelism here; each worker spawns its own r2 subprocess when
    # discovery is enabled.
    with concurrent.futures.ProcessPoolExecutor(max_workers=config.threads) as pool:
        futures = [
            pool.submit(_extract_functions, p, min_size, discover, analysis_cmd)
            for p in elf_binaries
        ]
        for done in concurrent.futures.as_completed(futures):
            functions.extend(done.result())
            bar.update()

    # Group by exact opcode hash. With a cryptographic hash of the raw bytes, a
    # shared hash already implies identical bytes and therefore identical size,
    # so the original size sub-bucketing was redundant and is dropped.
    by_hash: dict[str, list[FunctionInfo]] = defaultdict(list)
    for func in functions:
        by_hash[func.opcode_hash].append(func)

    groups: list[FunctionGroup] = []
    for opcode_hash, dupes in by_hash.items():
        if len(dupes) < 2:
            continue
        groups.append(
            FunctionGroup(
                functions=tuple(dupes),
                opcode_hash=opcode_hash,
                size=dupes[0].size,
            )
        )

    return sorted(groups, key=lambda g: g.wasted, reverse=True)