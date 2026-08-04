from __future__ import annotations

import concurrent.futures

from .config import Config
from .fs import index_elf_objects
from .models import UnusedEntry
from .progress import ProgressBar, get_logger
from .strings import StringIndex

logger = get_logger()


def _is_used(names: set[str], index: StringIndex) -> bool:
    for name in names:
        if index.contains(name, skip=names):
            return True
    return False


def find_unused_binaries(config: Config, string_index: StringIndex) -> list[UnusedEntry]:
    objects = index_elf_objects(config.root, libs_only=False, exclude=config.exclude)
    logger.info("Found %d non-library ELF files", len(objects))
    if not objects:
        return []

    logger.info("Checking %d binaries for usage...", len(objects))
    bar = ProgressBar(len(objects))
    unused: list[UnusedEntry] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as pool:
        future_to_key = {
            pool.submit(_is_used, {main.name, *(s.name for s in symlinks)}, string_index): (main, symlinks)
            for main, symlinks in objects.items()
        }
        for done in concurrent.futures.as_completed(future_to_key):
            main, symlinks = future_to_key[done]
            if not done.result():
                unused.append(UnusedEntry(main_path=main, symlinks=tuple(symlinks)))
            bar.update()

    return sorted(unused, key=lambda e: e.size, reverse=True)
