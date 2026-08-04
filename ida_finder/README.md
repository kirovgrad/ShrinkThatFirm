# shrink-that-firm — rewritten dead-code finder

Two phases instead of one, and two *scopes*.

## Context set vs. target set

The link graph is always built over the **whole image**, because import
resolution and `dlsym` evidence are only correct if every file is considered —
a function in `/usr/lib/libfoo.so` may be reachable only from
`/www/cgi-bin/status`. Narrowing the input would silently manufacture dead
code.

What you narrow is the **target set**: which binaries actually get
disassembled and reported on.

```
ida_finder.driver ROOT [TARGET ...]
```

* `ROOT` — the extracted filesystem. Always scanned in full.
* `TARGET` — zero or more directories or files to check for dead code.
  Omit for the whole image, or pass `--all` explicitly.

Targets accept either form, so both of these work:

```
python -m ida_finder.driver /fw/squashfs-root /usr/sbin          # image-absolute
python -m ida_finder.driver /fw/squashfs-root /fw/squashfs-root/usr/sbin
```

Multiple targets, mixing directories and single files:

```
python -m ida_finder.driver /fw/squashfs-root /usr/sbin /www/cgi-bin \
       -T /lib/libvendor.so.1 -o out -j 8
```

A target that resolves outside `ROOT`, or matches no ELF files, is a hard
error rather than a silent empty run.

## Phase 1 — link graph (no IDA, seconds, exact)

```
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

## Phase 2 — intra-binary reachability (IDA 9 idalib)

```
python -m ida_finder.driver /path/to/rootfs /usr/sbin -o out -j 8 --timeout 900
python -m stf.report out
```

One IDA process per worker, one result file per binary, per-binary timeout.
In-scope binaries that phase 1 proved unreachable are skipped — there is no
point enumerating dead functions inside a file you can delete whole — unless
you pass `--include-dead-files`.

## Verdicts

| verdict | meaning | action |
|---|---|---|
| `live` | reachable from a root | keep |
| `dead` | no reference, or only from unreachable code | remove after spot-check |
| `unreachable_but_address_taken` | pointer stored somewhere unresolvable | needs a trace |
| `dead_small` | under `STF_MIN_FUNC_SIZE` | low value, elevated risk |

## Running the IDA script by hand

File > Script file..., with environment variables:

* `STF_ROOT_SPEC` — path to `root_spec.json`
* `STF_RESULT_JSON` — where to write this binary's result
* `STF_MIN_FUNC_SIZE` — small-function threshold (default 0 = report everything)
