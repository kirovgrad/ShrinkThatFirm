from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

from .config import Config
from .dup_files import find_duplicate_files
from .dup_funcs import find_duplicate_functions
from .fs import collect_files
from .progress import get_logger, setup_logging
from .report import (
    ScanResults,
    report_duplicate_files,
    report_duplicate_functions,
    report_summary,
    report_unused,
)
from .strings import StringIndex
from .unused_bins import find_unused_binaries
from .unused_libs import find_unused_libraries

logger = get_logger()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stf",
        description="Analyze a firmware filesystem to find shrinkable waste.",
    )
    parser.add_argument("root", help="Path to the extracted firmware filesystem.")
    parser.add_argument(
        "-t", "--threads", type=int, default=8,
        help="Number of parallel worker threads (default: 8).",
    )
    parser.add_argument(
        "-o", "--output-dir", type=Path, default=Path("reports"),
        help="Directory where reports are written (default: ./reports).",
    )
    parser.add_argument(
        "--min-string-len", type=int, default=7,
        help="Minimum length of a printable run to be treated as a string.",
    )
    parser.add_argument(
        "--min-func-size", type=int, default=100,
        help="Ignore functions smaller than this when looking for duplicates.",
    )
    parser.add_argument(
        "--no-dup-funcs", action="store_true",
        help="Skip the radare2 duplicate-function analysis (requires r2pipe).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    return parser


def validate_args(args: argparse.Namespace) -> Config:
    if not args.root or not os.path.isdir(args.root):
        raise SystemExit(f"Error: '{args.root}' is not a valid directory")
    if args.threads < 1:
        raise SystemExit(f"Error: threads must be >= 1, got {args.threads}")
    return Config(
        root=Path(args.root).resolve(),
        threads=args.threads,
        output_dir=args.output_dir,
        string_min_len=args.min_string_len,
        dup_func_min_size=args.min_func_size,
    )


def _exclude_output_dir(config: Config) -> Config:
    try:
        config.output_dir.resolve().relative_to(config.root.resolve())
    except ValueError:
        return config
    return replace(config, exclude=frozenset({config.output_dir.resolve()}))


def run(config: Config, skip_dup_funcs: bool = False) -> ScanResults:
    """Execute the full analysis pipeline and return the aggregated results."""
    config = _exclude_output_dir(config)
    results = ScanResults()

    logger.info("Step 1/5: Collecting filesystem files...")
    files = collect_files(config.root, config.exclude)
    logger.info("Collected %d files", len(files))

    logger.info("Step 2/5: Searching for duplicated files...")
    results.duplicated_files = find_duplicate_files(files)
    logger.info("Found %d duplicate groups", len(results.duplicated_files))

    logger.info("Step 3/5: Collecting strings for reference search...")
    string_index = StringIndex.collect(
        config.root,
        threads=config.threads,
        min_len=config.string_min_len,
        max_file_size=config.max_string_file_size,
        exclude=config.exclude,
    )
    logger.info("Indexed %d files with strings", len(string_index))

    logger.info("Step 4/5: Searching for unused libraries...")
    results.unused_libraries = find_unused_libraries(config, string_index)
    logger.info("Found %d unused libraries", len(results.unused_libraries))

    logger.info("Step 5/5: Searching for unused binary executables...")
    results.unused_binaries = find_unused_binaries(config, string_index)
    logger.info("Found %d unused binaries", len(results.unused_binaries))

    if not skip_dup_funcs:
        logger.info("Extra: searching for duplicated functions (radare2)...")
        results.duplicated_functions = find_duplicate_functions(config, [f.path for f in files])
        logger.info("Found %d duplicated function groups", len(results.duplicated_functions))

    return results


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(verbose=args.verbose)

    config = validate_args(args)
    logger.info("Analyzing %s with %d threads (output: %s)",
                config.root, config.threads, config.output_dir)

    results = run(config, skip_dup_funcs=args.no_dup_funcs)

    out_dir = config.ensure_output_dir()
    report_duplicate_files(config, results.duplicated_files, config.root)
    report_duplicate_functions(config, results.duplicated_functions)
    report_unused(config, results.unused_libraries, config.root, "libraries")
    report_unused(config, results.unused_binaries, config.root, "binaries")
    summary_path = report_summary(config, results, config.root)

    total = results.total_wasted()
    logger.info("Reports written to %s", out_dir)
    print(f"Summary: total wasted space in {config.root} is "
          f"{total} bytes ({total / 1024:.2f} KB, {total / 1024 / 1024:.2f} MB)")
    print(f"Detailed report: {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
