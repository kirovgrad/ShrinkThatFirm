# ShrinkThatFirm

A from-scratch, more maintainable rewrite of the original firmware-shrinking
analyzer. It finds the same four classes of waste, plus the IDA-based unused
function analysis, without the original's sharp edges.

## What changed

| Concern | Original | Rewrite |
| --- | --- | --- |
| Intermediate CSV | files written to CWD then re-parsed by hand | in-memory typed records (`models.CollectedFile`) |
| Shared state | global `utils._STRINGCOLLECT` mutated from `main.py` | explicit `StringIndex` object passed to finders |
| `DT_NEEDED` parsing | external `readelf` + text parsing | pure-Python `elf.parse_needed_libraries` (no external binary, 32/64-bit, both endians) |
| Shell usage | `grep ... | head -1` built via string interpolation | no shell; regex over the in-memory string index |
| Exception handling | `except: pass` everywhere | narrow, logged handlers |
| Path handling | `os.path` + `full_path.index(root)` | `pathlib` + `relative_to` |
| Windows-only habits | `file.split("\\")[-1]` | `Path.name` |
| Reports | hard-coded CWD filenames | configurable `--output-dir` (default `./reports`) |
| Progress | ad-hoc `printProgressBar` | thread-safe `ProgressBar` (`stderr` logs keep it clean) |
| Entry point | `python main.py <fsdir> <threads>` | `python -m stf <root> [options]` |

## Layout

```
ShrinkThatFirm/
├── stf/                    # Basic firmware analysis CLI
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

## Basic Usage (stf/)

```bash
python -m stf <fsdir> [-t THREADS] [-o REPORTS_DIR] [--no-dup-funcs]
```

* `fsdir` — path to the extracted firmware filesystem (required).
* `-t/--threads` — worker threads (default 8).
* `-o/--output-dir` — where reports are written (default `./reports`).
* `--no-dup-funcs` — skip the radare2 duplicate-function analysis.
* `--min-func-size`, `--min-string-len` — analysis tuning knobs.

Reports written: `duplicated_files_report.txt`, `duplicated_functions_report.txt`,
`unused_library_report.txt`, `unused_binary_report.txt` and `summary.txt`.

## IDA-Based Dead Code Analysis (ida_finder/)

The ida_finder module provides more precise dead function detection using IDA Pro.
It operates in two phases with two scopes.

### Context set vs. target set

The link graph is always built over the **whole image**, because import
resolution and `dlsym` evidence are only correct if every file is considered —
a function in `/usr/lib/libfoo.so` may be reachable only from
`/www/cgi-bin/status`. Narrowing the input would silently manufacture dead
code.

What you narrow is the **target set**: which binaries actually get
disassembled and reported on.

```bash
python -m ida_finder.driver ROOT [TARGET ...]
```

* `ROOT` — the extracted filesystem. Always scanned in full.
* `TARGET` — zero or more directories or files to check for dead code.
  Omit for the whole image, or pass `--all` explicitly.

Targets accept either form, so both of these work:

```bash
python -m ida_finder.driver /fw/squashfs-root /usr/sbin          # image-absolute
python -m ida_finder.driver /fw/squashfs-root /fw/squashfs-root/usr/sbin
```

Multiple targets, mixing directories and single files:

```bash
python -m ida_finder.driver /fw/squashfs-root /usr/sbin /www/cgi-bin \
       -T /lib/libvendor.so.1 -o out -j 8
```

A target that resolves outside `ROOT`, or matches no ELF files, is a hard
error rather than a silent empty run.

### Phase 1 — link graph (no IDA, seconds, exact)

```bash
python -m ida_finder.driver /path/to/rootfs /usr/sbin -o out --link-only
```

Parses every ELF in the image (32/64-bit, LE **and BE**) and resolves the real
dynamic-linking graph: `DT_NEEDED`, `DT_SONAME`, `RPATH`/`RUNPATH` with
`$ORIGIN`, versioned `.dynsym`, IFUNCs, `__ksymtab` for `.ko` files.

Produces:

* `scope.json` — what was context, what was target.
* `dead_files.json` — whole binaries and libraries nothing references, each
  flagged `in_scope`. Usually the single biggest size win in an image, and
  provable without disassembly.
* `root_spec.json` — one entry per ELF in the image, carrying `file_live`,
  `in_scope`, and the exports that some other object actually has an
  **undefined dynsym entry** for, with the evidence for each.

### Phase 2 — intra-binary reachability (IDA 9 idalib)

```bash
python -m ida_finder.driver /path/to/rootfs /usr/sbin -o out -j 8 --timeout 900
python -m ida_finder.report out
```

One IDA process per worker, one result file per binary, per-binary timeout.
In-scope binaries that phase 1 proved unreachable are skipped — there is no
point enumerating dead functions inside a file you can delete whole — unless
you pass `--include-dead-files`.

### Verdicts

| verdict | meaning | action |
|---|---|---|
| `live` | reachable from a root | keep |
| `dead` | no reference, or only from unreachable code | remove after spot-check |
| `unreachable_but_address_taken` | pointer stored somewhere unresolvable | needs a trace |
| `dead_small` | under `STF_MIN_FUNC_SIZE` | low value, elevated risk |

### Running the IDA script by hand

File > Script file..., with environment variables:

* `STF_ROOT_SPEC` — path to `root_spec.json`
* `STF_RESULT_JSON` — where to write this binary's result
* `STF_MIN_FUNC_SIZE` — small-function threshold (default 0 = report everything)

## Optional dependencies

* `r2pipe` — required only for the duplicate-function analysis step
  (`pip install r2pipe`); the other four steps run without it.
* IDA Pro 9+ — required for the unused-function analysis via `ida_finder`

## Notes on accuracy (inherited from the original design)

The "unused" analyses are heuristics, not proofs:

* a library may be `dlopen`ed at runtime; the string search tries to catch
  that, but names in compressed/obfuscated data will be missed,
* C functions invoked through function pointers that IDA cannot resolve may be
  flagged unused (PRIVATE functions, inlined small functions), which is why the
  small-function filter defaults to keeping functions under 140 bytes
  (`STF_MIN_FUNC_SIZE`).
