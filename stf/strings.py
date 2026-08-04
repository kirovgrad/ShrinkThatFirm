from __future__ import annotations

import concurrent.futures
import re
from dataclasses import dataclass
from pathlib import Path
from typing import AbstractSet

from .elf import is_elf
from .fs import walk_files
from .progress import ProgressBar, get_logger

logger = get_logger()

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{5,}")


def _strings_from_file(path: Path, min_len: int, max_size: int) -> list[str] | None:
    try:
        if path.stat().st_size > max_size:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    hits = _ASCII_RUN.findall(data)
    if not hits:
        return None
    return [h.decode() for h in hits if len(h) >= min_len] or None


@dataclass
class StringIndex:
    entries: dict[Path, list[str]]

    def __len__(self) -> int:
        return len(self.entries)

    @classmethod
    def collect(
        cls,
        root: Path,
        threads: int = 8,
        min_len: int = 7,
        max_file_size: int = 64 * 1024 * 1024,
        show_progress: bool = True,
        exclude: AbstractSet[Path] = frozenset(),
    ) -> "StringIndex":
        files = []
        for path in walk_files(root, exclude):
            try:
                if path.exists():
                    files.append(path)
            except OSError:
                continue

        logger.info("Collecting strings from %d files...", len(files))

        entries: dict[Path, list[str]] = {}
        bar = ProgressBar(len(files), enabled=show_progress)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_strings_from_file, path, min_len, max_file_size): path
                for path in files
            }
            for done in concurrent.futures.as_completed(futures):
                strings = done.result()
                if strings:
                    entries[futures[done]] = strings
                bar.update()

        # ELF files first: they are far more likely to be searched.
        ordered = sorted(entries.items(), key=lambda kv: (not is_elf(kv[0]), kv[0].as_posix()))
        return cls(dict(ordered))

    def contains(
        self,
        needle: str,
        skip: set[str] | frozenset[str] = frozenset(),
        only_elf: bool = False,
    ) -> bool:
        pattern = re.compile(rf"\b{re.escape(needle)}\b")
        for path, strings in self.entries.items():
            if path.name in skip:
                continue
            if only_elf and not is_elf(path):
                continue
            if pattern.search(" ".join(strings)):
                return True
        return False
