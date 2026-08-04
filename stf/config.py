from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    root: Path
    threads: int = 8
    output_dir: Path = field(default_factory=lambda: Path("reports"))

    #: Paths (e.g. the report output dir when it lives inside ``root``) that
    #: must never be scanned.
    exclude: frozenset[Path] = frozenset()

    #: Minimum length (in bytes) of a printable run to be treated as a string.
    string_min_len: int = 7

    #: Functions smaller than this are ignored when looking for duplicated code.
    dup_func_min_size: int = 100

    #: Only read files no larger than this when collecting strings (bytes).
    max_string_file_size: int = 64 * 1024 * 1024

    #: Report file names (written into ``output_dir``).
    report_files: dict[str, str] = field(
        default_factory=lambda: {
            "duplicate_files": "duplicated_files_report.txt",
            "duplicate_functions": "duplicated_functions_report.txt",
            "unused_libraries": "unused_library_report.txt",
            "unused_binaries": "unused_binary_report.txt",
            "summary": "summary.txt",
        }
    )

    def ensure_output_dir(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir
