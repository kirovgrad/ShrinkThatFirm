import os
import sys
import hashlib

try:
	import r2pipe
except:
	sys.path.insert(0, "/home/emin/.local/lib/python3.13/site-packages")
	import r2pipe

from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Set
from utils import *

@dataclass
class FunctionInfo:
	binary_path: str
	function_name: str
	size: int
	opcode_hash: str
	binary_offset : int

def analyze_elf_r2pipe(filepath):
	try:
		r2 = r2pipe.open(filepath)
		r2.cmd("aaa")

		sections = r2.cmdj("iSj")
		text_section = next((sec for sec in sections if sec['name'] == '.text'), None)

		if not text_section:
			return []

		text_start = text_section['vaddr']
		text_end = text_start + text_section['vsize']

		functions_list = []

		functions = r2.cmdj("aflj")
		for func in functions:
			addr = func["offset"]
			size = func["size"]
			name = func["name"]

			if size < 100:
				continue
			
			if text_start <= addr < text_end:
				opcodes = r2.cmd(f"p8 {size} @ {addr}")
				if not opcodes:
					continue

				opcode_hash = hashlib.sha256(opcodes.encode()).hexdigest()

				functions_list.append(FunctionInfo(
					binary_path=filepath,
					binary_offset=addr,
					function_name=name or f"unnamed_{addr:x}",
					size=size,
					opcode_hash=opcode_hash
				))
		
		r2.quit()
		return functions_list

	except:
		return []

def find_duplicated_functions(root_dir):
	print(f"  - Scanning {root_dir} for ELF binaries...")
	files_to_process = []
	all_functions: List[FunctionInfo] = []
	
	for root, _, files in os.walk(root_dir):
		for filename in files:
			filepath = os.path.join(root, filename)
			if not os.path.islink(filepath) and check_elf(filepath):
				files_to_process.append(filepath)

	print(f"  - Checking ELF files for duplicated functions...")

	files_len = len(files_to_process)
	for index, file in enumerate(files_to_process):
		if files_len > 1:
			printProgressBar(index, files_len - 1)

		all_functions.extend(analyze_elf_r2pipe(file))
	
	hash_groups: Dict[str, List[FunctionInfo]] = defaultdict(list)
	for func in all_functions:
		hash_groups[func.opcode_hash].append(func)
	
	similar_functions = []
	for opcode_hash, functions in hash_groups.items():
		if len(functions) > 1:
			size_groups: Dict[int, List[FunctionInfo]] = defaultdict(list)
			for func in functions:
				size_groups[round(func.size * 0.1)].append(func)
			
			for size_key, similar_funcs in size_groups.items():
				if len(similar_funcs) > 1:
					similar_functions.append(similar_funcs)

	dup_functions_num = 0
	total_wasted = 0
	
	with open("duplicated_functions_report.txt", 'w') as f:
		if not similar_functions:
			f.write("No similar functions found across binaries.\n")
			return
		
		f.write("Similar functions found across binaries:\n\n")
		for group in similar_functions:
			f.write(f"=== Function Group (Size: ~{group[0].size} bytes) ===\n")
			f.write(f"Opcode Hash: {group[0].opcode_hash}\n")
			for func in group:
				f.write(f"- Binary: {func.binary_path}\n")
				f.write(f"  Function: {func.function_name}\n")
				f.write(f"  Offset: {hex(func.binary_offset)}\n")
				f.write(f"  Size: {func.size} bytes\n")
			f.write("\n")

			dup_functions_num += len(group)
			total_wasted += (len(group) * group[0].size) - group[0].size

		hashes_found = f"  - Total duplicate functions found: {dup_functions_num}"
		wasted_memory = f"  - Total wasted space: {total_wasted} bytes ({total_wasted / 1024:.2f} KB, {total_wasted / 1024 / 1024:.2f} MB)"

		f.write("Summary:\n")
		f.write(hashes_found + "\n")
		f.write(wasted_memory)

	print(hashes_found)
	print(wasted_memory)
	print("  - Saved report in: duplicated_functions_report.txt")

	return total_wasted

if __name__ == '__main__':
	find_duplicated_functions(sys.argv[1])