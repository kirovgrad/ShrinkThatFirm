from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def load_results(outdir: Path) -> list[dict]:
    out = []
    for p in sorted(outdir.glob("*.json")):
        if p.name in {"root_spec.json", "dead_files.json", "failures.json", "report.json"}:
            continue
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if "functions" in data:
            out.append(data)
    return out


def summarise(outdir: Path) -> dict:
    results = load_results(outdir)
    dead_files = json.loads((outdir / "dead_files.json").read_text()) \
        if (outdir / "dead_files.json").exists() else []
    spec = json.loads((outdir / "root_spec.json").read_text()) \
        if (outdir / "root_spec.json").exists() else {}
    scope_meta = json.loads((outdir / "scope.json").read_text()) \
        if (outdir / "scope.json").exists() else {}

    per_binary, tally = [], Counter()
    for r in results:
        counts = Counter(f["verdict"] for f in r["functions"])
        tally.update(counts)
        dead = [f for f in r["functions"] if f["verdict"] == "dead"]
        per_binary.append({
            "binary": r["binary"],
            "total_functions": r["functions_total"],
            "counts": dict(counts),
            "removable_bytes": sum(f["size"] for f in dead),
            "top_dead": sorted(dead, key=lambda f: -f["size"])[:20],
        })

    per_binary.sort(key=lambda b: -b["removable_bytes"])

    # Unused exports are only actionable for binaries we were asked about,
    # even though the evidence came from the whole image.
    unused_exports = {
        rel: d["dead_export_names"]
        for rel, d in spec.items()
        if d.get("in_scope", True) and d.get("dead_export_names")
    }
    scoped_dead_files = [f for f in dead_files if f.get("in_scope", True)]

    return {
        "scope": {
            "root": scope_meta.get("root"),
            "targets": scope_meta.get("targets", ["<whole image>"]),
            "context_elf_count": scope_meta.get("context_elf_count"),
            "scope_elf_count": scope_meta.get("scope_elf_count"),
        },
        "totals": {
            "binaries_analysed": len(results),
            "unreachable_files_in_scope": len(scoped_dead_files),
            "unreachable_file_bytes_in_scope": sum(f["size"] for f in scoped_dead_files),
            "unreachable_files_image_wide": len(dead_files),
            "unreachable_file_bytes_image_wide": sum(f["size"] for f in dead_files),
            "function_verdicts": dict(tally),
            "removable_function_bytes": sum(b["removable_bytes"] for b in per_binary),
        },
        "unreachable_files": scoped_dead_files[:200],
        "unreachable_files_out_of_scope": [f for f in dead_files
                                           if not f.get("in_scope", True)][:200],
        "exports_nobody_imports": {k: v[:50] for k, v in list(unused_exports.items())[:100]},
        "per_binary": per_binary,
    }


def render(summary: dict) -> str:
    t, sc = summary["totals"], summary["scope"]
    targets = ", ".join(sc.get("targets") or ["<whole image>"])
    lines = [
        "shrink-that-firm report",
        "=" * 60,
        f"image root                 : {sc.get('root')}",
        f"analysis target            : {targets}",
        f"context / target ELF count : {sc.get('context_elf_count')} / {sc.get('scope_elf_count')}",
        "",
        f"binaries analysed          : {t['binaries_analysed']}",
        f"unreachable files in scope : {t['unreachable_files_in_scope']}  "
        f"({t['unreachable_file_bytes_in_scope']:,} bytes)",
        f"  image-wide, for reference: {t['unreachable_files_image_wide']}  "
        f"({t['unreachable_file_bytes_image_wide']:,} bytes)",
        f"removable function bytes   : {t['removable_function_bytes']:,}",
        "",
        "function verdicts:",
    ]
    for verdict, n in sorted(t["function_verdicts"].items(), key=lambda kv: -kv[1]):
        lines.append(f"  {verdict:35} {n:>7}")

    lines += ["", "biggest wins by binary:", "-" * 60]
    for b in summary["per_binary"][:25]:
        lines.append(f"  {b['binary'][:40]:<40} {b['removable_bytes']:>9,} bytes "
                     f"({b['counts'].get('dead', 0)}/{b['total_functions']} funcs)")

    if summary["unreachable_files"]:
        lines += ["", "unreachable files in scope (delete these first):", "-" * 60]
        for f in summary["unreachable_files"][:25]:
            lines.append(f"  {f['path'][:50]:<50} {f['size']:>9,} bytes")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="stf.report")
    p.add_argument("outdir", type=Path)
    p.add_argument("--json", action="store_true", help="emit raw JSON instead of text")
    args = p.parse_args(argv)

    summary = summarise(args.outdir)
    (args.outdir / "report.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1) if args.json else render(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
