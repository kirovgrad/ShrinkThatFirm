from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from pathlib import Path
from typing import AbstractSet, Iterator

from .elf import is_elf
from .models import CollectedFile


def walk_files(root: Path, exclude: AbstractSet[Path] = frozenset()) -> Iterator[Path]:
    excluded = {p.resolve() for p in exclude}
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        dirnames[:] = [
            name
            for name in dirnames
            if (base / name).resolve() not in excluded
        ]
        for name in filenames:
            yield base / name


def md5(path: str | Path, chunk_size: int = 65536) -> str:
    """Streaming MD5 digest of a file."""
    digest = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_files(root: Path, exclude: AbstractSet[Path] = frozenset()) -> list[CollectedFile]:
    files: list[CollectedFile] = []
    for path in walk_files(root, exclude):
        try:
            st = path.lstat()
        except OSError:
            continue
        if st.st_mode & 0o170000 != 0o100000:  # not a regular file
            continue
        files.append(
            CollectedFile(
                path=path,
                size=st.st_size,
                mtime=st.st_mtime,
                md5=md5(path),
            )
        )
    return sorted(files, key=lambda f: f.path.as_posix())


def _is_so_name(name: str) -> bool:
    return name.endswith(".so") or ".so." in name


def index_elf_objects(
    root: Path, libs_only: bool = False, exclude: AbstractSet[Path] = frozenset()
) -> dict[Path, list[Path]]:
    objects: dict[Path, list[Path]] = defaultdict(list)

    for path in walk_files(root, exclude):
        is_lib = _is_so_name(path.name)
        if is_lib != libs_only:
            continue

        if path.is_symlink():
            try:
                target = path.resolve()
            except (OSError, RuntimeError):
                continue
            if target.exists() and is_elf(target):
                objects[target].append(path)
        elif is_elf(path):
            objects.setdefault(path, [])

    return dict(sorted(objects.items(), key=lambda kv: kv[0].as_posix()))
