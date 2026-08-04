from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CollectedFile:
    path: Path
    size: int
    md5: str
    mtime: float


@dataclass(frozen=True)
class FunctionInfo:
    binary: Path
    name: str
    size: int
    opcode_hash: str
    offset: int


@dataclass(frozen=True)
class FunctionGroup:
    functions: tuple[FunctionInfo, ...]
    opcode_hash: str
    size: int

    @property
    def wasted(self) -> int:
        return self.size * (len(self.functions) - 1)


@dataclass(frozen=True)
class FileGroup:
    md5: str
    file_size: int
    paths: tuple[Path, ...]

    @property
    def count(self) -> int:
        return len(self.paths)

    @property
    def wasted(self) -> int:
        return self.file_size * (self.count - 1)


@dataclass(frozen=True)
class UnusedEntry:
    main_path: Path
    symlinks: tuple[Path, ...] = ()

    @property
    def all_paths(self) -> tuple[Path, ...]:
        return (self.main_path, *self.symlinks)

    @property
    def size(self) -> int:
        total = 0
        for path in self.all_paths:
            try:
                total += path.stat().st_size
            except OSError:
                continue
        return total
