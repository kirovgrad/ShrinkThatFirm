import idaapi
import idautils
import idc
import struct
import ida_name
import ida_segment
import ida_entry
import ida_nalt
import ida_funcs
import ida_xref
import ida_search

import re
import json

def parse_data_segment(segm_name):
    seg = idaapi.get_segm_by_name(segm_name)
    if not seg:
        return {}

    start = seg.start_ea
    end = seg.end_ea

    named_eas = sorted(
        ea for ea in range(start, end)
        if idc.get_name(ea, ida_name.GN_VISIBLE).startswith(("g_", "off_", "unk_", "dword_"))
    )
    
    arrays_with_funcs = {}

    for i, ea in enumerate(named_eas):
        name = idc.get_name(ea, ida_name.GN_VISIBLE)

        next_addr = named_eas[i + 1] if i + 1 < len(named_eas) else end
        size = next_addr - ea

        if size <= 0:
            continue

        data = idaapi.get_bytes(ea, size)
        if not data:
            continue

        for j in range(0, len(data), 4):
            if j + 4 <= len(data):
                val_le = struct.unpack("<I", data[j:j+4])[0]

                if idc.get_func_name(val_le):
                    arrays_with_funcs.setdefault(ea, []).append(val_le)

                elif idc.get_name(val_le, ida_name.GN_VISIBLE).startswith(("g_", "off_", "unk_", "dword_")):
                    arrays_with_funcs.setdefault(ea, []).append(val_le)

    return arrays_with_funcs


def find_array_references(array_ea):
    refs = set()
    result = []

    for ptr in idautils.DataRefsTo(array_ea):
        refs.add(ptr)

    for ref in refs:
        if func_name := idc.get_func_name(ref):
            if func_name not in result:
                result.append(func_name)

    return result


def get_functions_xrefing_var(var_ea):
    visited_vars = set()
    found_funcs = set()

    def walk_var(ea):
        if ea in visited_vars:
            return
        visited_vars.add(ea)

        for xref in idautils.XrefsTo(ea):
            if xref.type not in (ida_xref.dr_O, ida_xref.dr_W, ida_xref.dr_R):  
                continue

            frm = xref.frm
            seg = ida_segment.getseg(frm)
            if not seg:
                continue

            segname = ida_segment.get_segm_name(seg)

            if segname in (".data", ".data.rel.ro"):
                # another variable points to our var -> recurse
                walk_var(frm)
            else:
                # check if inside a function
                pfn = ida_funcs.get_func(frm)
                if pfn:
                    found_funcs.add(idc.get_func_name(pfn.start_ea))

    walk_var(var_ea)
    return list(found_funcs)


def check_segment(ea, semg_name):
    segm = ida_segment.getseg(ea)
    name = ida_segment.get_segm_name(segm)
    return name == semg_name


def get_called_functions(func_ea):
    called_funcs = set()
    func = ida_funcs.get_func(func_ea)
    if not func:
        return called_funcs

    ea = func.start_ea
    while ea < func.end_ea:
        for i in idautils.XrefsFrom(ea, ida_xref.XREF_FAR):
            if i.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                pass
                
            elif i.type in (ida_xref.fl_JN, ida_xref.fl_JF):
                target_func = ida_funcs.get_func(i.to)
                if target_func and target_func.start_ea == i.to:
                    pass
                    
                else:
                    continue
                    
            elif i.type == ida_xref.dr_O and idc.get_func_name(i.to):
                pass
                
            else:
                continue

            called_funcs.add(ida_funcs.get_func(i.to).start_ea)
                
        ea = idc.next_head(ea, func.end_ea)

    return called_funcs


def get_exported_funcs():
    result = []

    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        result.append(ea)

    return result


def find_unneeded_and_delete(exported_funcs):
    with open("collected_strings.json", "r") as col:
        collected_strings = json.load(col)
    
    root_filename = ida_nalt.get_root_filename()
    
    combined_other_set = set()
    asp_strings = []
    
    for file, strings in collected_strings.items():
        if os.path.basename(file) == root_filename:
            continue

        if file.endswith(".asp"):
            asp_strings.extend(s for s in strings if "%" in s and "<" in s)
        else:
            combined_other_set.update(strings)
    
    funcs_to_keep = []
    
    for func_ea in exported_funcs:
        func_name = idc.get_func_name(func_ea)
        if not func_name:
            continue
        
        if not (func_name[0].isalpha() and (func_name[0].isupper() or "_" in func_name[1:])):
            continue
        
        if func_name in combined_other_set:
            funcs_to_keep.append(func_ea)
            continue
        
        pat = re.compile(rf"<%{re.escape(func_name)}.*%>")
        if any(pat.search(s) for s in asp_strings):
            funcs_to_keep.append(func_ea)
    
    exported_funcs[:] = funcs_to_keep


def is_function_pointer(addr):
    return idaapi.get_func(addr) is not None


def goer(array, visited, array_result):
    functions  = set()

    for i in array:
        if is_function_pointer(i):
            functions.add(i)
        else:
            if i in array_result.keys() and i not in visited:
                visited.add(i)
                functions.update(goer(array_result[i], visited, array_result))

    return functions


def array_resolver(array_result):
    result = {}
    
    for key, value_list in array_result.items():
        visited = set()
        functions = goer(value_list, visited, array_result)
        if functions:
            result[key] = [f for f in functions] 

    return result


def find_arrays_with_func():
    arrays_with_funcs = {}
    for seg_name in [".data", ".data.rel.ro"]:
        arrays_with_funcs.update(parse_data_segment(seg_name))

    arrays_with_funcs = array_resolver(arrays_with_funcs)
  
    funcs_refs = []
    if len(arrays_with_funcs):
        for var_addr, references in arrays_with_funcs.items():
            refs = find_array_references(var_addr)
            if len(refs):
                funcs_refs.append((refs, references))

    return funcs_refs


def find_main_function(current_filename, need_to_process):
    if not any([".ko" in current_filename, ".so" in current_filename]):
        main_func = ida_name.get_name_ea(0, "main")
        if main_func == idc.BADADDR:
            libc_start = ida_name.get_name_ea(0, "__libc_start_main")
            for ref in idautils.CodeRefsTo(libc_start, True):
                need_to_process.append(ida_funcs.get_func(ref).start_ea)
        else:
            need_to_process.append(main_func)


def process_funcs(need_to_process, funcs_refs):
    counter = 0
    processed_funcs = set()

    while counter < len(need_to_process):
        current_func = need_to_process[counter]
        if current_func in processed_funcs:
            counter += 1
            continue
        processed_funcs.add(current_func)

        current_func_name = idc.get_name(current_func)
        current_func_calls = get_called_functions(current_func)

        for callee in current_func_calls:
            if callee not in processed_funcs:
                need_to_process.append(callee)

        for ref in funcs_refs:
            if current_func_name in ref[0]:
                for ea in ref[1]:
                    # ea = ida_name.get_name_ea(0, i)
                    if ea not in processed_funcs:
                        need_to_process.append(ea)

        counter += 1

    return processed_funcs


def find_init_fini_functions():
    result = []

    for func in idautils.Functions():
        for ref in idautils.DataRefsTo(func):
            segm = ida_segment.getseg(ref)
            if ida_segment.get_segm_name(segm) in [".init_array", ".fini_array"]:
                result.append(func)

    return result


def resolve_not_funcs():
    ea = ida_search.find_not_func(1, True)

    while ea != idc.BADADDR:
        ida_funcs.add_func(ea)
        ea = ida_search.find_not_func(ea, True)


def filter_small_funcs():
    result = []

    for func in idautils.Functions():
        if check_segment(func, ".text"):
            func_size = ida_funcs.get_func(func).end_ea - ida_funcs.get_func(func).start_ea
            if func_size < 140: # <=== VARIABLE
                result.append(func)

    return result

def main():
    # Resolve all not defined functions
    resolve_not_funcs()

    # Get current filename
    current_filename = ida_nalt.get_root_filename()

    # Find all functions from global arrays
    funcs_refs = find_arrays_with_func()

    need_to_process = []

    # Define the beginning of main function
    find_main_function(current_filename, need_to_process)
    
    # Get export functions and extend need_to_process list with them
    exported_funcs = get_exported_funcs()
    if len(exported_funcs):
        find_unneeded_and_delete(exported_funcs)

    need_to_process.extend(exported_funcs)

    # Extend need_to_process with initial and finish functions
    need_to_process.extend(find_init_fini_functions())

    # Extend need_to_process with small functions, considering them as inlined
    # need_to_process.extend(filter_small_funcs())

    # Process functions and find unused ones
    processed_funcs = process_funcs(need_to_process, funcs_refs)

    combined_size = 0
    unneeded_funcs = []

    for func in idautils.Functions():
        if func not in processed_funcs:
            if not idc.get_name(func)[0].isalpha():
                continue

            if check_segment(func, ".text"):
                func_size = ida_funcs.get_func(func).end_ea - ida_funcs.get_func(func).start_ea
                combined_size += func_size
                unneeded_funcs.append((idc.get_name(func), func, func_size))


    result_dict = {current_filename: unneeded_funcs}
    with open("result.json", "r") as output_file:
        tmp = json.load(output_file)

    tmp.update(result_dict)
    with open("result.json", "w") as output_file:
        json.dump(tmp, output_file)


main()