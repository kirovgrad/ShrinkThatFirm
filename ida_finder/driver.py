from __future__ import annotations

import argparse
import json
import logging
import multiprocessing as mp
import os
import queue
import sys
import time
from pathlib import Path

from .linkgraph import analyze

_SCRIPT = Path(__file__).parent / "idb_script.py"
log = logging.getLogger("stf")


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(processName)-12s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )


def _worker(job_q, done_q, script: str, spec_path: str, outdir: str,
            timeout: int, verbose: bool) -> None:
    _setup_logging(verbose)
    import idapro
    import ida_idaapi

    while True:
        try:
            job = job_q.get(timeout=5)
        except queue.Empty:
            continue
        if job is None:
            break

        rel, abs_path = job
        out_file = Path(outdir) / (rel.strip("/").replace("/", "__") + ".json")
        started = time.time()
        try:
            log.info("analysing %s", rel)
            idapro.open_database(abs_path, True)
            try:
                ida_idaapi.IDAPython_ExecScript(script, {
                    "ROOT_SPEC": spec_path,
                    "RESULT_JSON": str(out_file),
                    "BINARY_KEY": rel,
                })
            finally:
                idapro.close_database(save=False)
            done_q.put((rel, "ok", time.time() - started))
        except Exception as exc:  # noqa: BLE001 - one bad binary must not stop the run
            log.warning("failed on %s: %s", rel, exc)
            done_q.put((rel, f"error: {exc}", time.time() - started))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ida_finder.driver",
        description="Find dead functions across a firmware filesystem using IDA 9 idalib.",
        epilog=(
            "The link graph is always built over the whole image given by ROOT, "
            "because import and dlsym evidence is only correct if every file is "
            "considered. TARGET narrows which binaries are then disassembled. "
            "Omit TARGET to analyse the whole image."
        ),
    )
    p.add_argument("root", type=Path, help="extracted firmware filesystem (context set)")
    p.add_argument("target", nargs="*", default=[],
                   help="directories or files to analyse for dead code; may be host "
                        "paths under ROOT or image-absolute paths like /usr/sbin. "
                        "Default: the whole image.")
    p.add_argument("-T", "--target-path", action="append", default=[],
                   dest="extra_targets",
                   help="additional target path (repeatable; same forms as TARGET)")
    p.add_argument("--all", action="store_true",
                   help="analyse the whole image, ignoring any TARGET given")
    p.add_argument("-o", "--outdir", type=Path, default=Path("stf-out"))
    p.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 4) // 2),
                   help="concurrent IDA workers")
    p.add_argument("--timeout", type=int, default=1800,
                   help="per-binary wall clock limit in seconds")
    p.add_argument("--ignore", nargs="*", default=[],
                   help="basenames to skip entirely")
    p.add_argument("--include-dead-files", action="store_true",
                   help="also analyse in-scope binaries the link graph proved unreachable")
    p.add_argument("--link-only", action="store_true",
                   help="stop after the link graph; do not run IDA")
    p.add_argument("--extra-root", action="append", default=[],
                   help="absolute in-image path to treat as a live entry point")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    if not args.root.is_dir():
        log.error("%s is not a directory", args.root)
        return 1

    args.outdir.mkdir(parents=True, exist_ok=True)

    log.info("phase 1: building link graph over the whole image at %s", args.root)
    graph = analyze(args.root, args.extra_root)

    requested = [] if args.all else [str(t) for t in args.target] + list(args.extra_targets)
    try:
        scope = graph.resolve_scope(requested)
    except ValueError as exc:
        log.error("%s", exc)
        return 2

    spec_path = args.outdir / "root_spec.json"
    spec = graph.export_root_spec(spec_path, scope)

    dead_files = graph.dead_files()
    (args.outdir / "dead_files.json").write_text(json.dumps(
        [{"path": n.rel, "size": n.size, "arch": n.elf.arch if n.elf else None,
          "in_scope": n.rel in scope}
         for n in dead_files], indent=1))

    total_elf = sum(1 for n in graph.nodes.values() if n.elf)
    scoped_dead = [n for n in dead_files if n.rel in scope]
    (args.outdir / "scope.json").write_text(json.dumps({
        "root": str(args.root.resolve()),
        "targets": requested or ["<whole image>"],
        "context_elf_count": total_elf,
        "scope_elf_count": len(scope),
        "scope": sorted(scope),
    }, indent=1))

    log.info("  context: %d ELF objects, %d unreachable (%s bytes)",
             total_elf, len(dead_files), f"{sum(n.size for n in dead_files):,}")
    log.info("  target : %d ELF objects in scope (%s)",
             len(scope), ", ".join(requested) if requested else "whole image")
    if scoped_dead:
        log.info("  %d in-scope files are themselves unreachable (%s bytes) - "
                 "delete these before bothering with their functions",
                 len(scoped_dead), f"{sum(n.size for n in scoped_dead):,}")

    if args.link_only:
        log.info("stopping after link graph (--link-only)")
        return 0

    ignore = set(args.ignore)
    jobs = [
        (rel, d["abs_path"]) for rel, d in spec.items()
        if d["in_scope"] and Path(rel).name not in ignore
        and (d["file_live"] or args.include_dead_files)
    ]

    skipped = len(scope) - len(jobs)
    if skipped > 0:
        log.info("  skipping %d in-scope binaries (unreachable or ignored); "
                 "use --include-dead-files to analyse them anyway", skipped)

    if not jobs:
        log.warning("nothing to analyse in the requested scope")
        return 0

    log.info("phase 2: %d binaries across %d IDA workers", len(jobs), args.jobs)

    mp.set_start_method("spawn", force=True)
    job_q: mp.Queue = mp.Queue()
    done_q: mp.Queue = mp.Queue()

    for job in jobs:
        job_q.put(job)
    for _ in range(args.jobs):
        job_q.put(None)

    workers = [
        mp.Process(target=_worker,
                   args=(job_q, done_q, str(_SCRIPT), str(spec_path),
                         str(args.outdir), args.timeout, args.verbose),
                   name=f"ida-{i}")
        for i in range(args.jobs)
    ]
    for w in workers:
        w.start()

    completed, failures = 0, []
    deadline = time.time() + args.timeout * max(1, len(jobs))
    while completed < len(jobs) and time.time() < deadline:
        if not any(w.is_alive() for w in workers):
            break
        try:
            rel, status, elapsed = done_q.get(timeout=2)
        except queue.Empty:
            continue
        completed += 1
        if status != "ok":
            failures.append((rel, status))
        pct = 100 * completed / max(1, len(jobs))
        print(f"\r  [{completed}/{len(jobs)}] {pct:5.1f}%  {rel[:60]:<60}",
              end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)

    for w in workers:
        w.join(timeout=args.timeout)
        if w.is_alive():
            log.warning("terminating stuck worker %s", w.name)
            w.terminate()

    if failures:
        (args.outdir / "failures.json").write_text(json.dumps(dict(failures), indent=1))
        log.warning("%d binaries failed; see failures.json", len(failures))

    log.info("done. per-binary results in %s", args.outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
