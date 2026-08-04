from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .config import Config
from .models import FileGroup, FunctionGroup, UnusedEntry

_UNIT = 1024.0


def _fmt_size(size: int) -> str:
    kb = size / _UNIT
    mb = kb / _UNIT
    return f"{size} bytes ({kb:.2f} KB, {mb:.2f} MB)"


def _fmt_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


@dataclass
class ScanResults:
    duplicated_files: list[FileGroup] = field(default_factory=list)
    duplicated_functions: list[FunctionGroup] = field(default_factory=list)
    unused_libraries: list[UnusedEntry] = field(default_factory=list)
    unused_binaries: list[UnusedEntry] = field(default_factory=list)

    def total_wasted(self) -> int:
        return (
            sum(g.wasted for g in self.duplicated_files)
            + sum(g.wasted for g in self.duplicated_functions)
            + sum(e.size for e in self.unused_libraries)
            + sum(e.size for e in self.unused_binaries)
        )


def _write_report(path: Path, lines: Sequence[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def report_duplicate_files(config: Config, groups: list[FileGroup], root: Path) -> Path:
    lines = ["Duplicate Files Analysis Report", "==============================="]
    for group in groups:
        lines += [
            f"\nHash: {group.md5}",
            f"Number of duplicates: {group.count}",
            f"Total size: {group.file_size * group.count} Bytes",
            f"Wasted space: {group.wasted} Bytes",
            "Files:",
            *(
                f"  - {path.name} ({group.file_size} bytes) [Location: {_fmt_path(path, root)}]"
                for path in group.paths
            ),
            "----------------------------------------",
        ]
    lines += [
        "\n\nSummary:",
        f"  - Total duplicate hashes found: {sum(g.count - 1 for g in groups)}",
        f"  - Total wasted space: {_fmt_size(sum(g.wasted for g in groups))}",
    ]
    out = config.ensure_output_dir() / config.report_files["duplicate_files"]
    _write_report(out, lines)
    return out


def report_duplicate_functions(config: Config, groups: list[FunctionGroup]) -> Path:
    if not groups:
        out = config.ensure_output_dir() / config.report_files["duplicate_functions"]
        _write_report(out, ["No similar functions found across binaries."])
        return out

    lines = ["Similar functions found across binaries:\n"]
    for group in groups:
        lines.append(f"=== Function Group (Size: ~{group.size} bytes) ===")
        lines.append(f"Opcode Hash: {group.opcode_hash}")
        for func in group.functions:
            lines += [
                f"- Binary: {func.binary}",
                f"  Function: {func.name}",
                f"  Offset: {hex(func.offset)}",
                f"  Size: {func.size} bytes",
            ]
        lines.append("")

    dup_num = sum(len(g.functions) for g in groups)
    wasted = sum(g.wasted for g in groups)
    lines += [
        "Summary:",
        f"  - Total duplicate functions found: {dup_num}",
        f"  - Total wasted space: {_fmt_size(wasted)}",
    ]

    out = config.ensure_output_dir() / config.report_files["duplicate_functions"]
    _write_report(out, lines)
    return out


def report_unused(config: Config, entries: list[UnusedEntry], root: Path, kind: str) -> Path:
    title = {
        "libraries": "Unused Libraries Analysis Report",
        "binaries": "Unused Binary Executables Analysis Report",
    }[kind]

    lines = [title, "==============================="]
    for entry in entries:
        lines.append(f"\nMain Binary: {_fmt_path(entry.main_path, root)}" if kind == "binaries"
                     else f"\nMain library: {_fmt_path(entry.main_path, root)}")
        if entry.symlinks:
            lines.append("Symlinks:")
            lines += [f"  - {_fmt_path(s, root)}" for s in entry.symlinks]
        else:
            lines.append("No symlinks")

    total_size = sum(e.size for e in entries)
    unit_label = "binaries" if kind == "binaries" else "libraries"
    lines += [
        "\n\nSummary:",
        f"  - Total unused {unit_label}: {len(entries)}",
        f"  - Total wasted space: {_fmt_size(total_size)}",
    ]

    out = config.ensure_output_dir() / config.report_files[f"unused_{kind}"]
    _write_report(out, lines)
    return out


def report_summary(config: Config, results: ScanResults, root: Path) -> Path:
    total = results.total_wasted()
    lines = [
        "ShrinkThatFirm Summary",
        "======================",
        f"Root filesystem: {root}",
        "",
        f"  - Duplicated files:      {len(results.duplicated_files)} groups "
        f"({_fmt_size(sum(g.wasted for g in results.duplicated_files))})",
        f"  - Duplicated functions:  {len(results.duplicated_functions)} groups "
        f"({_fmt_size(sum(g.wasted for g in results.duplicated_functions))})",
        f"  - Unused libraries:      {len(results.unused_libraries)} "
        f"({_fmt_size(sum(e.size for e in results.unused_libraries))})",
        f"  - Unused binaries:       {len(results.unused_binaries)} "
        f"({_fmt_size(sum(e.size for e in results.unused_binaries))})",
        "",
        f"  - Total wasted space: {_fmt_size(total)}",
    ]
    out = config.ensure_output_dir() / config.report_files["summary"]
    _write_report(out, lines)
    return out
