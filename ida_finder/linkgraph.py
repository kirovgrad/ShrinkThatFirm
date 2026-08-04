from __future__ import annotations

import json
import os
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from .elfinfo import ELF, is_elf, safe_parse

# Default loader search path inside an embedded rootfs.
DEFAULT_LIBDIRS = (
    "/lib", "/usr/lib", "/lib/tls", "/usr/local/lib",
    "/lib32", "/usr/lib32", "/lib64", "/usr/lib64",
)

# Files that start execution: if a binary is named here, it is a root.
INIT_HINTS = (
    "etc/inittab", "etc/init.d", "etc/rc.d", "etc/rcS", "etc/rc.local",
    "etc/preinit", "init", "sbin/init", "etc/profile", "etc/services",
    "lib/systemd/system", "etc/systemd/system", "etc/xinetd.d",
)

DL_FUNCS = {"dlopen", "dlsym", "dlvsym", "dlmopen"}

_PATH_RE = re.compile(rb"(?:/[A-Za-z0-9_.+-]+){2,}")
_IDENT_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{4,127}")


@dataclass
class FileNode:
    path: Path
    rel: str
    elf: ELF | None = None
    is_text: bool = False
    size: int = 0
    # populated during analysis
    deps: set[str] = field(default_factory=set)          # resolved rel paths
    dependents: set[str] = field(default_factory=set)
    live: bool = False
    live_reason: str = ""


@dataclass
class LinkGraph:
    root: Path
    nodes: dict[str, FileNode] = field(default_factory=dict)
    by_soname: dict[str, str] = field(default_factory=dict)
    by_basename: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # symbol name -> rel paths that define it / need it
    providers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    importers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    # rel path -> {export name: [evidence strings]}
    live_exports: dict[str, dict[str, list[str]]] = field(default_factory=dict)

    # ------------------------------------------------------------------ scan

    @classmethod
    def scan(cls, root: Path, follow_symlinks: bool = False) -> LinkGraph:
        g = cls(root=root.resolve())
        for dirpath, _, names in os.walk(g.root):
            for name in names:
                p = Path(dirpath) / name
                try:
                    if p.is_symlink() and not follow_symlinks:
                        # Symlinks still matter for name resolution (busybox,
                        # libfoo.so -> libfoo.so.1) so record them cheaply.
                        rel = "/" + str(p.relative_to(g.root)).replace("\\", "/")
                        g.by_basename[name].append(rel)
                        continue
                    if not p.is_file():
                        continue
                    st = p.stat()
                except OSError:
                    continue

                rel = "/" + str(p.relative_to(g.root)).replace("\\", "/")
                node = FileNode(path=p, rel=rel, size=st.st_size)
                if is_elf(p):
                    node.elf = safe_parse(p)
                else:
                    node.is_text = _looks_textual(p)
                g.nodes[rel] = node
                g.by_basename[name].append(rel)
                if node.elf and node.elf.soname:
                    g.by_soname.setdefault(node.elf.soname, rel)
        return g

    # ------------------------------------------------------- symbol indexes

    def index_symbols(self) -> None:
        for rel, node in self.nodes.items():
            if not node.elf:
                continue
            for name in node.elf.exports():
                self.providers[name].add(rel)
            for name in node.elf.imports():
                self.importers[name].add(rel)

    # ------------------------------------------------------ dependency edges

    def _resolve_needed(self, node: FileNode, soname: str) -> str | None:
        if soname in self.by_soname:
            return self.by_soname[soname]
        # RUNPATH / RPATH, with $ORIGIN expanded relative to the object.
        origin = str(Path(node.rel).parent).replace("\\", "/")
        for entry in (node.elf.runpath if node.elf else []):
            cand = entry.replace("$ORIGIN", origin).replace("${ORIGIN}", origin)
            hit = self.nodes.get(f"{cand.rstrip('/')}/{soname}")
            if hit:
                return hit.rel
        for d in DEFAULT_LIBDIRS:
            hit = self.nodes.get(f"{d}/{soname}")
            if hit:
                return hit.rel
        matches = self.by_basename.get(soname)
        return matches[0] if matches else None

    def build_edges(self) -> None:
        for rel, node in self.nodes.items():
            if not node.elf:
                continue
            for soname in node.elf.needed:
                target = self._resolve_needed(node, soname)
                if target:
                    node.deps.add(target)
                    if target in self.nodes:
                        self.nodes[target].dependents.add(rel)

    # ----------------------------------------------------- file reachability

    def mark_live_files(self, extra_roots: list[str] | None = None) -> None:
        referenced: dict[str, str] = {}

        for rel, node in self.nodes.items():
            if not (node.is_text or node.elf is None):
                continue
            if not any(h in rel for h in INIT_HINTS) and not node.is_text:
                continue
            try:
                blob = node.path.read_bytes()[:4 << 20]
            except OSError:
                continue
            for m in _PATH_RE.finditer(blob):
                cand = m.group(0).decode("ascii", "ignore")
                if cand in self.nodes:
                    referenced.setdefault(cand, f"path reference in {rel}")
                else:
                    for hit in self.by_basename.get(cand.rsplit("/", 1)[-1], []):
                        referenced.setdefault(hit, f"basename reference in {rel}")

        for rel in (extra_roots or []):
            referenced.setdefault(rel, "user-supplied root")

        # Executables in the usual bin dirs are assumed launchable.
        for rel, node in self.nodes.items():
            if not node.elf or node.elf.is_kernel_module:
                continue
            if node.elf.soname:
                continue
            if any(rel.startswith(d) for d in ("/bin/", "/sbin/", "/usr/bin/",
                                               "/usr/sbin/", "/usr/local/bin/",
                                               "/www/cgi-bin/", "/cgi-bin/")):
                referenced.setdefault(rel, "executable in PATH directory")

        queue = deque(referenced)
        for rel, why in referenced.items():
            self.nodes[rel].live = True
            self.nodes[rel].live_reason = why
        while queue:
            cur = self.nodes[queue.popleft()]
            for dep in cur.deps:
                dn = self.nodes.get(dep)
                if dn and not dn.live:
                    dn.live = True
                    dn.live_reason = f"DT_NEEDED of {cur.rel}"
                    queue.append(dep)

    def dead_files(self) -> list[FileNode]:
        return sorted(
            (n for n in self.nodes.values() if n.elf and not n.live),
            key=lambda n: -n.size,
        )

    # ------------------------------------------------- live export resolution

    def compute_live_exports(self, dlsym_scan: bool = True) -> None:
        dl_users = self._dlsym_users() if dlsym_scan else {}
        dyn_names = self._dynamic_name_evidence(dl_users) if dlsym_scan else {}

        for rel, node in self.nodes.items():
            if not node.elf:
                continue
            result: dict[str, list[str]] = {}

            # An executable's own dynsym exports only matter if something
            # dlopen()s it, which is vanishingly rare.  Libraries are the case
            # that counts.
            for name in node.elf.exports():
                evidence: list[str] = []
                for importer in self.importers.get(name, ()):  # exact link edge
                    if importer == rel:
                        continue
                    imp = self.nodes.get(importer)
                    if imp and rel in self._transitive_deps(importer):
                        evidence.append(f"undefined dynsym in {importer}")
                    elif imp and imp.live:
                        # Provider not in this importer's DT_NEEDED closure -
                        # still possible via LD_PRELOAD or a broken build.
                        evidence.append(f"undefined dynsym in {importer} (no direct link edge)")
                for src in dyn_names.get(name, ()):
                    if src != rel:
                        evidence.append(f"dlsym-candidate string in {src}")
                if evidence:
                    result[name] = evidence[:8]

            self.live_exports[rel] = result

    # ------------------------------------------------------- analysis scope

    def resolve_scope(self, entries: list[str] | None) -> set[str]:
        elfs = {rel for rel, n in self.nodes.items() if n.elf}
        if not entries:
            return elfs

        selected: set[str] = set()
        for entry in entries:
            prefix = self._to_image_path(entry)
            if prefix is None:
                raise ValueError(
                    f"{entry!r} is not inside the firmware root {self.root}. "
                    "Pass a path under the root, or an image-absolute path like /usr/bin."
                )
            if prefix in elfs:
                selected.add(prefix)
                continue
            base = prefix.rstrip("/")
            hits = {rel for rel in elfs if rel == base or rel.startswith(base + "/")}
            if not hits:
                raise ValueError(f"{entry!r} matched no ELF files (resolved to {prefix!r})")
            selected |= hits
        return selected

    def _to_image_path(self, entry: str) -> str | None:
        p = Path(entry)
        if p.exists():
            try:
                resolved = p.resolve()
                if resolved == self.root:
                    return "/"
                return "/" + str(resolved.relative_to(self.root)).replace("\\", "/")
            except (ValueError, OSError):
                pass
        img = "/" + entry.lstrip("/")
        img_normalized = img.replace("\\", "/")
        return img_normalized if img_normalized == "/" or (self.root / img_normalized.lstrip("/")).exists() else None

    def _transitive_deps(self, rel: str) -> set[str]:
        cache = getattr(self, "_tdc", None)
        if cache is None:
            cache = self._tdc = {}
        if rel in cache:
            return cache[rel]
        seen: set[str] = set()
        stack = [rel]
        while stack:
            cur = stack.pop()
            for dep in self.nodes.get(cur, FileNode(Path(), cur)).deps:
                if dep not in seen:
                    seen.add(dep)
                    stack.append(dep)
        cache[rel] = seen
        return seen

    def _dlsym_users(self) -> set[str]:
        return {
            rel for rel, n in self.nodes.items()
            if n.elf and (n.elf.imports() & DL_FUNCS)
        }

    def _dynamic_name_evidence(self, dl_users: set[str]) -> dict[str, set[str]]:
        known = set(self.providers)
        out: dict[str, set[str]] = defaultdict(set)
        for rel, node in self.nodes.items():
            is_dl = rel in dl_users
            if node.elf and not is_dl:
                continue
            try:
                blob = node.path.read_bytes()[:8 << 20]
            except OSError:
                continue
            if node.elf:
                # Only .rodata: .dynstr trivially contains every symbol name
                # and would make this test tautological.
                sec = node.elf.section(".rodata")
                blob = blob[sec.offset:sec.offset + sec.size] if sec else b""
            for m in _IDENT_RE.finditer(blob):
                name = m.group(0).decode("ascii", "ignore")
                if name in known:
                    out[name].add(rel)
        return out

    # ----------------------------------------------------------------- output

    def export_root_spec(self, out_path: Path, scope: set[str] | None = None) -> dict:        spec = {}
        for rel, node in self.nodes.items():
            if not node.elf:
                continue
            elf = node.elf
            live = self.live_exports.get(rel, {})
            addrs = {
                s.value for s in elf.export_symbols()
                if s.name in live and s.value
            }
            spec[rel] = {
                "abs_path": str(node.path),
                "arch": elf.arch,
                "file_live": node.live,
                "file_live_reason": node.live_reason,
                "in_scope": scope is None or rel in scope,
                "is_kernel_module": elf.is_kernel_module,
                "entry": elf.entry,
                "init_fini": sorted(set(elf.init_fini)),
                "ifunc_resolvers": sorted(elf.ifunc_resolvers()),
                "live_export_names": sorted(live),
                "live_export_addrs": sorted(addrs),
                "dead_export_names": sorted(set(elf.exports()) - set(live)),
                "evidence": live,
            }
        out_path.write_text(json.dumps(spec, indent=1))
        return spec


def _looks_textual(path: Path) -> bool:
    try:
        chunk = path.open("rb").read(2048)
    except OSError:
        return False
    if not chunk:
        return False
    if b"\x00" in chunk:
        return False
    printable = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(chunk) > 0.9


def analyze(root: Path, extra_roots: list[str] | None = None) -> LinkGraph:
    g = LinkGraph.scan(root)
    g.index_symbols()
    g.build_edges()
    g.mark_live_files(extra_roots)
    g.compute_live_exports()
    return g
