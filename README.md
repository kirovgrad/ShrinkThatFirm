# ShrinkThatFirm

ShrinkThatFirm analyzes extracted firmware filesystems to identify wasted space.
It finds several types of shrinkable waste:

- **Duplicate files** - identical files that appear multiple times
- **Duplicate functions** - same function code compiled into multiple binaries
- **Unused libraries** - shared libraries nothing links to
- **Unused binaries** - executables nothing references
- **Dead functions** - functions inside binaries that are never called (requires IDA Pro)

## Two Analysis Modes

This project provides two modes of analysis:

### 1. Fast Static Analysis (`stf`)

Quick analysis using only strings and ELF parsing. No disassembly required.

**Usage:**
```bash
python -m stf <firmware_root> [-t THREADS] [-o OUTPUT_DIR] [options]
```

**Options:**
- `firmware_root` - Path to the extracted firmware filesystem (required)
- `-t, --threads N` - Worker threads (default: 8)
- `-o, --output-dir PATH` - Where reports are written (default: ./reports)
- `--min-string-len N` - Minimum string length to index (default: 7)
- `--min-func-size N` - Minimum function size for duplicate detection (default: 100)
- `--no-dup-funcs` - Skip radare2 duplicate function analysis
- `-v, --verbose` - Enable debug logging

**Example:**
```bash
python -m stf /path/to/firmware/extracted -t 4 -o my_reports
```

**Reports generated:**
- `duplicated_files_report.txt`
- `duplicated_functions_report.txt`
- `unused_library_report.txt`
- `unused_binary_report.txt`
- `summary.txt`

### 2. Precise Dead Function Analysis (`ida_finder`)

Uses IDA Pro to disassemble binaries and find functions that are never called.
More accurate than string-based analysis but requires IDA Pro 9+ and takes longer.

**Usage:**
```bash
python -m ida_finder.driver <firmware_root> [TARGETS...] [options]
```

**Options:**
- `firmware_root` - Path to the extracted firmware filesystem (required)
- `TARGETS` - Directories or files to analyze; omit for the whole image
- `-o, --outdir PATH` - Output directory (default: stf-out)
- `-j, --jobs N` - Concurrent IDA workers (default: CPU cores / 2)
- `-T, --target-path PATH` - Additional target path (repeatable)
- `--all` - Analyze the whole image
- `--timeout SECONDS` - Per-binary timeout (default: 1800)
- `--ignore NAME` - Skip binaries with this basename
- `--link-only` - Stop after building link graph (skip IDA disassembly)
- `--include-dead-files` - Also analyze unreachable binaries
- `--extra-root PATH` - Additional entry point path
- `-v, --verbose` - Enable debug logging

**Example:**
```bash
# Analyze just /usr/sbin in the firmware
python -m ida_finder.driver /path/to/firmware /usr/sbin -o results

# Quick link graph only (no IDA needed)
python -m ida_finder.driver /path/to/firmware --link-only -o graph_out

# Full image analysis with 4 workers
python -m ida_finder.driver /path/to/firmware --all -j 4 -o full_scan
```

**Phase 1 - Link Graph (fast, no IDA):**
Builds a complete picture of the firmware's dynamic linking by parsing all ELFs:
- `DT_NEEDED`, `DT_SONAME`, `RPATH`/`RUNPATH` with `$ORIGIN`
- Versioned `.dynsym` entries
- IFUNCs and kernel module symbols

Produces `scope.json`, `dead_files.json`, and `root_spec.json`.

**Phase 2 - IDA Analysis (slow, requires IDA Pro):**
Disassembles targeted binaries to find unreachable functions. Outputs per-binary JSON files with:
- `live` - Functions reachable from entry points
- `dead` - Functions with no references
- `unreachable_but_address_taken` - Pointers exist but call site unresolvable
- `dead_small` - Below size threshold, likely compiler artifacts

**Generate human-readable report:**
```bash
python -m ida_finder.report results
```

## Project Layout

```
ShrinkThatFirm/
├── stf/                    # Fast static analysis
│   ├── cli.py              # argument parsing + pipeline orchestration
│   ├── config.py           # immutable per-run Config
│   ├── models.py           # CollectedFile / FunctionGroup / UnusedEntry ...
│   ├── elf.py              # pure-Python ELF parsing (is_elf, DT_NEEDED)
│   ├── fs.py               # filesystem walking, md5, lib/binary indexing
│   ├── strings.py          # parallel string collection + indexed word search
│   ├── dup_files.py        # duplicate file detection
│   ├── dup_funcs.py        # duplicate function detection (r2pipe)
│   ├── unused_libs.py      # unused shared library detection
│   ├── unused_bins.py      # unused binary detection
│   ├── report.py           # text report generation + summary
│   └── progress.py         # logging setup + progress bar
├── ida_finder/             # IDA-based dead-code analysis
│   ├── linkgraph.py        # firmware-wide link graph builder
│   ├── driver.py           # orchestration for the IDA stage
│   ├── idb_script.py       # in-IDA dead-function analysis
│   ├── elfinfo.py          # dependency-free ELF reader
│   └── report.py           # aggregate per-binary results
└── tests/                  # test suite
```

## Installation

```bash
pip install -e .
```

**Optional dependencies:**
- `r2pipe` - For duplicate function analysis (`pip install r2pipe`)

## Understanding the Results

**Unused libraries/binaries** means nothing in the firmware references them. They can be deleted to save space. However:
- A library may be loaded via `dlopen()` at runtime
- Names in compressed data may be missed by string search

**Dead functions** means IDA's disassembly shows no code path calls them. Before deleting:
- Verify the binary isn't loaded via dlopen/dlsym
- Check if function addresses are taken and called indirectly
- Small functions (<100 bytes) are marked separately as likely compiler artifacts
