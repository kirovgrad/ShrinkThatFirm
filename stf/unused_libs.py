from __future__ import annotations

import concurrent.futures
from pathlib import Path
from typing import AbstractSet

from .config import Config
from .elf import parse_needed_libraries
from .fs import index_elf_objects, walk_files
from .models import UnusedEntry
from .progress import ProgressBar, get_logger
from .strings import StringIndex

logger = get_logger()


def collect_needed_references(root: Path, threads: int, exclude: AbstractSet[Path] = frozenset()) -> set[str]:
    elf_files = [path for path in walk_files(root, exclude) if path.is_file()]

    needed: set[str] = set()
    bar = ProgressBar(len(elf_files))
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(parse_needed_libraries, path) for path in elf_files]
        for done in concurrent.futures.as_completed(futures):
            needed |= done.result()
            bar.update()
    return needed


def _is_used(names: set[str], needed_refs: set[str], index: StringIndex) -> bool:
    for name in names:
        if name in needed_refs:
            return True
    for name in names:
        if index.contains(name, skip=names):
            return True
    return False


def find_unused_libraries(config: Config, string_index: StringIndex) -> list[UnusedEntry]:
    objects = index_elf_objects(config.root, libs_only=True, exclude=config.exclude)
    logger.info("Found %d shared libraries", len(objects))

    all_names: set[str] = set()
    for main, symlinks in objects.items():
        all_names.add(main.name)
        all_names.update(s.name for s in symlinks)
    all_names.discard("/dev/null")

    logger.info("Scanning for DT_NEEDED references...")
    needed_refs = collect_needed_references(config.root, config.threads, config.exclude)

    logger.info("Checking %d libraries for usage...", len(objects))
    bar = ProgressBar(len(objects))
    unused: list[UnusedEntry] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as pool:
        future_to_key = {
            pool.submit(_is_used, {main.name, *(s.name for s in symlinks)}, needed_refs, string_index): (main, symlinks)
            for main, symlinks in objects.items()
        }
        for done in concurrent.futures.as_completed(future_to_key):
            main, symlinks = future_to_key[done]
            if not done.result():
                unused.append(UnusedEntry(main_path=main, symlinks=tuple(symlinks)))
            bar.update()

    return sorted(unused, key=lambda e: e.size, reverse=True)
