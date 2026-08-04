from __future__ import annotations

import json
import os
from collections import deque

_ROOT_SPEC = globals().get("ROOT_SPEC") or os.environ.get("STF_ROOT_SPEC", "")
_RESULT_JSON = globals().get("RESULT_JSON") or os.environ.get("STF_RESULT_JSON", "")
_MIN_SIZE = int(globals().get("MIN_FUNC_SIZE") or os.environ.get("STF_MIN_FUNC_SIZE", "0"))

try:
    import ida_bytes
    import ida_entry
    import ida_funcs
    import ida_ida
    import ida_nalt
    import ida_name
    import ida_segment
    import ida_xref
    import idaapi
    import idautils
    import idc
except ImportError:  # importable outside IDA for linting/testing
    ida_bytes = ida_entry = ida_funcs = ida_ida = ida_nalt = None
    ida_name = ida_segment = ida_xref = idaapi = idautils = idc = None

# Segments that can hold function pointers.  .bss is included because IDA
# still records the offset xref created by the code that writes into it.
PTR_SEGMENTS = (
    ".rodata", ".data", ".data.rel.ro", ".data.rel.ro.local", ".data1",
    ".got", ".got.plt", ".init_array", ".fini_array", ".preinit_array",
    ".ctors", ".dtors", ".bss", ".rdata", ".sdata", ".picdata",
)

CODE_SEGMENTS = (".text", ".plt", ".init", ".fini", ".text.unlikely", ".ARM.extab")


# --------------------------------------------------------------- primitives

def _is_be() -> bool:
    try:
        return ida_ida.inf_is_be()
    except AttributeError:
        return idaapi.get_inf_structure().is_be()


def _ptr_size() -> int:
    try:
        return 8 if ida_ida.inf_is_64bit() else 4
    except AttributeError:
        return 8 if idaapi.get_inf_structure().is_64bit() else 4


def _is_arm() -> bool:
    try:
        return ida_ida.inf_get_procname().lower().startswith("arm")
    except AttributeError:
        return idaapi.get_inf_structure().procname.lower().startswith("arm")


_PTRSZ = None
_ARM = False


def _read_ptr(ea: int) -> int:
    val = ida_bytes.get_qword(ea) if _PTRSZ == 8 else ida_bytes.get_dword(ea)
    if val in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        return 0
    return val & ~1 if _ARM else val


def _seg_name(ea: int) -> str:
    seg = ida_segment.getseg(ea)
    return ida_segment.get_segm_name(seg) if seg else ""


def _in_code(ea: int) -> bool:
    return _seg_name(ea) in CODE_SEGMENTS


def _func_start(ea: int) -> int | None:
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None


def _all_items(func) -> list:
    out = []
    it = ida_funcs.func_tail_iterator_t(func)
    ok = it.main()
    while ok:
        chunk = it.chunk()
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != idc.BADADDR:
            out.append(ea)
            ea = idc.next_head(ea, chunk.end_ea)
        ok = it.next()
    return out


def _func_size(func) -> int:
    total = 0
    it = ida_funcs.func_tail_iterator_t(func)
    ok = it.main()
    while ok:
        c = it.chunk()
        total += c.end_ea - c.start_ea
        ok = it.next()
    return total


# ------------------------------------------------------------- call graph

def direct_callees(func_ea: int) -> set[int]:
    out: set[int] = set()
    func = ida_funcs.get_func(func_ea)
    if not func:
        return out

    call_types = (ida_xref.fl_CN, ida_xref.fl_CF)
    jump_types = (ida_xref.fl_JN, ida_xref.fl_JF)

    for ea in _all_items(func):
        for xref in idautils.XrefsFrom(ea, 0):
            target = _func_start(xref.to)
            if target is None or target == func.start_ea:
                continue
            if xref.type in call_types:
                out.add(target)
            elif xref.type in jump_types and target == xref.to:
                out.add(target)          # tail call
            elif xref.type == ida_xref.dr_O and target == xref.to:
                out.add(target)          # address taken directly in an insn
    return out


def address_taken_map() -> dict[int, list[int]]:
    taken: dict[int, list[int]] = {}
    for func_ea in idautils.Functions():
        sites = []
        for ref in idautils.XrefsTo(func_ea, 0):
            if ref.type in (ida_xref.dr_O, ida_xref.dr_R, ida_xref.dr_W):
                if not _in_code(ref.frm) or ref.type == ida_xref.dr_O:
                    sites.append(ref.frm)
        if sites:
            taken[func_ea] = sites
    return taken


# --------------------------------------------------- pointer table discovery

def scan_pointer_tables() -> dict[int, list[int]]:
    tables: dict[int, list[int]] = {}
    starts = set(idautils.Functions())

    for segname in PTR_SEGMENTS:
        seg = idaapi.get_segm_by_name(segname)
        if not seg:
            continue
        if seg.type == idaapi.SEG_BSS:
            # No file bytes to read; pointers land here at runtime.  The code
            # that writes them leaves an offset xref, so address_taken_map()
            # is what covers this case.
            continue
        ea = seg.start_ea - (seg.start_ea % _PTRSZ)
        run_start, run = None, []

        while ea < seg.end_ea:
            val = _read_ptr(ea)
            if val in starts:
                if run_start is None:
                    run_start = ea
                run.append(val)
            else:
                if run_start is not None:
                    tables[run_start] = run
                run_start, run = None, []
            ea += _PTRSZ

        if run_start is not None:
            tables[run_start] = run

    return tables


def table_referrers(table_ea: int, span: int) -> set[int]:
    out: set[int] = set()
    for ea in range(table_ea, table_ea + span, _PTRSZ):
        for ref in idautils.DataRefsTo(ea):
            fs = _func_start(ref)
            if fs is not None:
                out.add(fs)
    return out


# --------------------------------------------------------------------- roots

def collect_roots(spec: dict) -> dict[int, str]:
    roots: dict[int, str] = {}

    def add(ea, why):
        if ea and ea != idc.BADADDR:
            fs = _func_start(ea) or ea
            roots.setdefault(fs, why)

    add(ida_ida.inf_get_start_ea() if hasattr(ida_ida, "inf_get_start_ea") else idc.BADADDR,
        "ELF entry point")
    add(ida_name.get_name_ea(0, "main"), "main")
    for name in ("_init", "_fini", "__libc_csu_init"):
        add(ida_name.get_name_ea(0, name), f"DT_{name.strip('_').upper()}")

    # Link-graph supplied roots: these are the exports somebody actually imports.
    for ea in spec.get("live_export_addrs", ()):
        add(ea, "export imported by another binary")
    for ea in spec.get("init_fini", ()):
        add(ea, "DT_INIT/FINI or init_array")
    for ea in spec.get("ifunc_resolvers", ()):
        add(ea, "STT_GNU_IFUNC resolver")

    # Constructor arrays, read from the database as a cross-check.
    for segname in (".preinit_array", ".init_array", ".fini_array", ".ctors", ".dtors"):
        seg = idaapi.get_segm_by_name(segname)
        if not seg:
            continue
        for ea in range(seg.start_ea, seg.end_ea, _PTRSZ):
            add(_read_ptr(ea), f"{segname} entry")

    # Kernel modules: init/exit and everything in an ops struct.
    if spec.get("is_kernel_module"):
        for name in ("init_module", "cleanup_module"):
            add(ida_name.get_name_ea(0, name), "kernel module entry")

    # An export we could not tie to an importer is still reachable if the image
    # is loaded with LD_PRELOAD or dlopen'd; keep it as a *weak* root so it is
    # reported separately rather than silently deleted.
    return roots


# ------------------------------------------------------------------ analysis

def reachable(roots: dict[int, str], tables: dict[int, list[int]]) -> tuple[set[int], dict[int, str]]:
    table_span = {ea: len(v) * _PTRSZ for ea, v in tables.items()}
    referrer_index: dict[int, list[int]] = {}
    for tea, funcs in tables.items():
        for r in table_referrers(tea, table_span[tea]):
            referrer_index.setdefault(r, []).append(tea)

    live: set[int] = set()
    why: dict[int, str] = {}
    queue = deque(roots)
    for ea, reason in roots.items():
        why[ea] = reason

    while queue:
        cur = queue.popleft()
        if cur in live:
            continue
        live.add(cur)

        for callee in direct_callees(cur):
            if callee not in live:
                why.setdefault(callee, f"called by {idc.get_func_name(cur)}")
                queue.append(callee)

        for tea in referrer_index.get(cur, ()):
            for target in tables[tea]:
                if target not in live:
                    why.setdefault(target, f"pointer table {tea:#x} used by {idc.get_func_name(cur)}")
                    queue.append(target)

    return live, why


def classify(live: set[int], taken: dict[int, list[int]], reasons: dict[int, str]) -> list[dict]:
    out: list[dict] = []
    for func_ea in idautils.Functions():
        f = ida_funcs.get_func(func_ea)
        if not f or not _in_code(func_ea):
            continue
        name = idc.get_func_name(func_ea) or ""
        size = _func_size(f)
        has_any_xref = any(True for _ in idautils.XrefsTo(func_ea, 0))

        if func_ea in live:
            verdict, why = "live", reasons.get(func_ea, "reachable")
        elif func_ea in taken:
            verdict = "unreachable_but_address_taken"
            why = f"address stored at {', '.join(hex(a) for a in taken[func_ea][:4])}"
        elif not has_any_xref:
            verdict, why = "dead", "no code or data reference anywhere in this binary"
        else:
            verdict, why = "dead", "only referenced from code that is itself unreachable"

        if verdict != "live" and size < _MIN_SIZE:
            verdict, why = "dead_small", f"below size threshold ({size} bytes), likely an inlined leftover"

        out.append({
            "name": name,
            "ea": func_ea,
            "size": size,
            "verdict": verdict,
            "why": why,
            "thunk": bool(f.flags & ida_funcs.FUNC_THUNK),
            "lib": bool(f.flags & ida_funcs.FUNC_LIB),
        })
    return out


def define_referenced_code() -> int:
    added = 0
    for seg_ea in idautils.Segments():
        if not _in_code(seg_ea):
            continue
        seg = ida_segment.getseg(seg_ea)
        ea = seg.start_ea
        while ea < seg.end_ea:
            if ida_funcs.get_func(ea) is None and ida_bytes.is_code(ida_bytes.get_flags(ea)):
                if any(True for _ in idautils.XrefsTo(ea, 0)):
                    if ida_funcs.add_func(ea):
                        added += 1
            nxt = idc.next_head(ea, seg.end_ea)
            ea = nxt if nxt != idc.BADADDR and nxt > ea else ea + 1
    return added


def main() -> None:
    global _PTRSZ, _ARM
    _PTRSZ, _ARM = _ptr_size(), _is_arm()

    idaapi.auto_wait()

    spec = {}
    if _ROOT_SPEC:
        try:
            with open(_ROOT_SPEC) as fh:
                all_specs = json.load(fh)
            spec = all_specs.get(globals().get("BINARY_KEY", ""), {}) or {}
        except (OSError, ValueError):
            spec = {}

    added = define_referenced_code()
    if added:
        idaapi.auto_wait()

    tables = scan_pointer_tables()
    roots = collect_roots(spec)
    live, reasons = reachable(roots, tables)
    taken = address_taken_map()
    functions = classify(live, taken, reasons)

    dead = [f for f in functions if f["verdict"].startswith("dead")]
    report = {
        "binary": ida_nalt.get_root_filename(),
        "input_file": ida_nalt.get_input_file_path(),
        "arch": {"ptr_size": _PTRSZ, "big_endian": _is_be(), "arm": _ARM},
        "root_count": len(roots),
        "roots": {hex(k): v for k, v in sorted(roots.items())},
        "pointer_tables": len(tables),
        "functions_total": len(functions),
        "functions_defined_by_us": added,
        "dead_bytes": sum(f["size"] for f in dead),
        "functions": functions,
    }

    # One file per binary: the original had four processes doing
    # read-modify-write on a single result.json with no lock, which loses
    # results non-deterministically.
    out = _RESULT_JSON or f"{ida_nalt.get_root_filename()}.stf.json"
    with open(out, "w") as fh:
        json.dump(report, fh)


if idc is not None:
    main()
