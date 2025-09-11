#!/usr/bin/env python3

import os, re, sys
import hashlib
import argparse
import subprocess
import concurrent.futures
import lief
import r2pipe
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Set

_STRINGCOLLECT = {}
_PATTERN = re.compile(rb'[\x20-\x7E]{7,}')

@dataclass
class FunctionInfo:
	binary_path: str
	function_name: str
	size: int
	opcode_hash: str
	binary_offset : int

def parse_args():
	parser = argparse.ArgumentParser(description='Find unused shared libraries')
	parser.add_argument('--root', default='/', help='Root directory to search')
	parser.add_argument('--threads', type=int, default=8, help='Number of parallel threads')
	return parser.parse_args()

def md5(fname):
	hash_md5 = hashlib.md5()
	with open(fname, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()

def check_elf(filepath):
	with open(filepath, "rb") as file:
		return file.read(4) == b"\x7FELF"

def printProgressBar(iteration, total, length=50):
	percent = ("{0:.1f}").format(100 * (iteration / float(total)))
	filled_length = int(length * iteration // total)
	bar = "█" * filled_length + "-" * (length - filled_length)

	sys.stdout.write(f"\r|{bar}| {percent}%")
	sys.stdout.flush()

	if iteration == total:
		sys.stdout.write("\n")

def _strings_from_file(path, root_dir):
	try:
		with open(path, 'rb') as f:
			hits = _PATTERN.findall(f.read())
			if not hits:
				return None
			return simplify_path(path, root_dir), [h.decode() for h in hits]
	except:
		return None

def collect_strings(root_dir, max_workers=8):
	print('  - Collecting strings...')

	global _STRINGCOLLECT
	with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
		tasks = [
			pool.submit(_strings_from_file, os.path.join(dp, fn), root_dir)
			for dp, _, fns in os.walk(root_dir)
			for fn in fns
			if os.path.exists(os.path.join(dp, fn))
		]

		total = len(tasks)
		for idx, fut in enumerate(concurrent.futures.as_completed(tasks), 1):
			out = fut.result()
			if out:
				key, strings = out
				_STRINGCOLLECT[key] = strings
			if total > 1:
				printProgressBar(idx, total)

	_STRINGCOLLECT = dict(sorted(_STRINGCOLLECT.items(), key=lambda item: check_elf(item[0]), reverse=True))

def collect_fs_files(root_dir):
	with open("collected_fs.csv", "w") as collect_file:
		for dirpath, _, filenames in os.walk(root_dir):
			for filename in filenames:
				filepath = os.path.join(dirpath, filename)
				if os.path.islink(filepath):
					continue
				file_name = os.path.basename(filepath)
				file_size = os.path.getsize(filepath)
				file_ctime = os.path.getctime(filepath)
				file_md5 = md5(filepath)
				collect_file.writelines(
					f"{file_name},{file_size},{file_ctime},{filepath},{file_md5}\n"
				)

def find_duplicated_files():
	duplicate_dict = {}
	total_wasted = 0
	total_duplicates = 0

	with open("collected_fs.csv", "r") as collected_fs:
		lines = collected_fs.readlines()

		for line in lines:
			splitted = line.split(",")
			duplicate_dict.setdefault(
				splitted[4], {"dup_num": 0, "total_size": 0, "wasted": 0, "files": []}
			)
			duplicate_dict[splitted[4]]['dup_num'] += 1
			duplicate_dict[splitted[4]]['total_size'] += int(splitted[1], 10)
			duplicate_dict[splitted[4]]['wasted'] = duplicate_dict[splitted[4]]['total_size'] - (
				duplicate_dict[splitted[4]]['total_size'] // duplicate_dict[splitted[4]]['dup_num']
			)
			duplicate_dict[splitted[4]]['files'].append(splitted[3])

	sorted_data = dict(sorted(
		duplicate_dict.items(),
		key=lambda item: item[1]['wasted'],
		reverse=True
	))

	with open("duplicated_files_report.txt", "w") as dups:
		dups.write("Duplicate Files Analysis Report\n")
		dups.write("===============================\n")

		for key, value in sorted_data.items():
			if value['dup_num'] > 1:
				total_wasted += value['wasted']
				total_duplicates += value['dup_num'] - 1

				dups.write(f"\nHash: {key}")
				dups.write(f"Number of duplicates: {value['dup_num']}\n")
				dups.write(f"Total size: {value['total_size']} Bytes\n")
				dups.write(f"Wasted space: {value['wasted']} Bytes\n")
				dups.write("Files:\n")
				for i in value['files']:
					dups.write(
						f"  - {os.path.basename(i)} ({value['total_size'] // value['dup_num']} bytes) [Location: {i}]\n"
					)
				dups.write("----------------------------------------")

			else:
				break

		hashes_found = f"  - Total duplicate hashes found: {total_duplicates}"
		wasted_memory = f"  - Total wasted space: {total_wasted} bytes ({total_wasted / 1024:.2f} KB, {total_wasted / 1024 / 1024:.2f} MB)"

		dups.write("\n\nSummary:")
		dups.write("\n" + hashes_found)
		dups.write("\n" + wasted_memory)

	print(hashes_found)
	print(wasted_memory)
	print("  - Saved report in: duplicated_files_report.txt")

	return total_wasted

def simplify_path(full_path, root):
	try:
		return full_path[full_path.index(root):]
	except:
		return full_path

def find_binary_files(root_dir, find_so=True):
	lib_dict = defaultdict(list)
	
	for dirpath, _, filenames in os.walk(root_dir, followlinks=False):
		for filename in filenames:
			full_path = os.path.join(dirpath, filename)
			
			if not (filename.endswith('.so') or '.so.' in filename) if find_so else \
			   (filename.endswith('.so') or '.so.' in filename):
				continue
			
			if not os.path.exists(full_path):
				continue
			
			if not check_elf(full_path):
				continue
			
			if os.path.islink(full_path):
				try:
					real_path = os.path.realpath(full_path)
					if os.path.exists(real_path) and check_elf(real_path):
						lib_dict[simplify_path(real_path, root_dir)].append(
							simplify_path(full_path, root_dir)
						)
				except (OSError, RuntimeError):
					continue
			else:
				lib_dict[simplify_path(full_path, root_dir)]
	
	return lib_dict

def get_needed_libs(binary_path):
	"""Get NEEDED section entries from a binary using readelf"""
	try:
		result = subprocess.run(
			['readelf', '-d', binary_path],
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			text=True,
			check=True
		)
		needed = []
		for line in result.stdout.splitlines():
			if 'NEEDED' in line:
				lib = line.split('[')[1].split(']')[0].strip()
				needed.append(lib)
		return needed
	except (subprocess.CalledProcessError, IndexError):
		return []

def process_file(filepath, lib_names):
	"""Process a single file to check for needed libraries"""
	if not os.access(filepath, os.X_OK):
		return set()
	
	try:
		needed = get_needed_libs(filepath)
		return {lib for lib in needed if lib in lib_names}
	except Exception:
		return set()

def scan_needed_sections(root_dir, lib_names, max_workers=8):
	"""Scan all binaries for NEEDED sections containing given library names"""
	needed_refs = set()
	lib_names = set(lib_names)  # Convert to set for faster lookups
	
	# Collect all files to process
	files_to_process = []
	for dirpath, _, filenames in os.walk(root_dir):
		for filename in filenames:
			filepath = os.path.join(dirpath, filename)
			files_to_process.append(filepath)
	
	# Process files in parallel
	with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
		# Submit all tasks
		futures = [
			executor.submit(process_file, filepath, lib_names)
			for filepath in files_to_process
		]
		
		# Collect results as they complete
		for future in futures:
			needed_refs.update(future.result())
	
	return needed_refs

def is_lib_used(lib, symlinks, needed_refs, root_dir):
	try:
		names_to_check = {os.path.basename(lib)} if lib != "/dev/null" else set()
		names_to_check.update(os.path.basename(link) for link in symlinks)
		
		for name in names_to_check:
			if name in needed_refs:
				return True

		for lib in names_to_check:
			if search_with_grep(lib, names_to_check, root_dir):
				return True 

		return False
	except:
		return False

def search_with_grep(to_search, skip_files, root_dir):
	pattern = rf'\b{to_search}\b'

	if len(_STRINGCOLLECT):
		for i in _STRINGCOLLECT:
			if os.path.basename(i) in skip_files:
				continue

			if re.search(pattern, " ".join(_STRINGCOLLECT[i])):
				return True

		return False

	try:
		skip_args = []
		for f in skip_files:
			skip_args.extend(['--exclude', os.path.basename(f)])

		skip_str = ' '.join(f"'{arg}'" for arg in skip_args)
		cmd = f"grep -arlm 1 {skip_str} -e '{pattern}' '{root_dir}' | head -1"

		proc = subprocess.run(
			cmd,
			shell=True,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			text=True
		)
		return bool(proc.stdout.strip())
	except Exception:
		return False

def find_unused_libs(root_dir, threads):
	print("  - Searching for shared libs...")
	lib_dict = find_binary_files(root_dir)

	print(f"  - Found {len(lib_dict)} shared libraries")

	# Get all possible library names (including symlinks)
	all_lib_names = set()
	for lib, symlinks in lib_dict.items():
		if lib != "/dev/null":
			all_lib_names.add(os.path.basename(lib))

		all_lib_names.update(os.path.basename(link) for link in symlinks)

	print("  - Scanning binaries for NEEDED sections...")
	needed_refs = scan_needed_sections(root_dir, all_lib_names, threads)

	print("  - Checking for unused libraries...")
	unused_libs = {}
	total_size = 0

	with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
		futures = {
			executor.submit(
				is_lib_used,
				lib,
				symlinks,
				needed_refs,
				root_dir
			): (lib, symlinks)
			for lib, symlinks in lib_dict.items()
		}
		
		futures_len = len(futures)

		for index, future in enumerate(concurrent.futures.as_completed(futures)):
			if futures_len > 1:
				printProgressBar(index, futures_len - 1)

			lib, symlinks = futures[future]
			if not future.result():
				unused_libs[lib] = symlinks
				try:
					total_size += os.path.getsize(lib)
					for symlink in symlinks:
						total_size += os.path.getsize(symlink)
				except OSError:
					continue

	unused_num = f"  - Total unused libraries: {len(unused_libs)}"
	unused_mem = f"  - Total wasted space: {total_size} bytes ({total_size / 1024:.2f} KB, {total_size / 1024 / 1024:.2f} MB)"

	with open("unused_library_report.txt", "w") as unused:
		unused.write("Unused Libraries Analysis Report\n")
		unused.write("===============================\n")

		for lib, symlinks in unused_libs.items():
			unused.write(f"\nMain library: {lib}")
			if symlinks:
				unused.write("\nSymlinks:")
				for link in symlinks:
					unused.write(f"\n  - {link}")
			else:
				unused.write("\nNo symlinks")

		unused.write("\n\nSummary:")
		unused.write("\n" + unused_num)
		unused.write("\n" + unused_mem)

	print(unused_num)
	print(unused_mem)
	print("  - Saved report in: unused_library_report.txt")

	return total_size

def get_function_opcodes(binary, function):
	section = binary.section_from_virtual_address(function.address)
	if not section:
		return b''
	
	offset = function.address - section.virtual_address
	return section.content[offset:offset+function.size]

def analyze_elf_binary(filepath):
	try:
		binary = lief.parse(filepath)
		if not binary or not isinstance(binary, lief.ELF.Binary):
			return []
		
		functions = []
		for function in binary.functions:
			# Minimal function size is 100 bytes
			if function.size < 100:
				continue

			opcodes = get_function_opcodes(binary, function)
			if not opcodes:
				continue
				
			opcode_hash = hashlib.sha256(opcodes).hexdigest()
			functions.append(FunctionInfo(
				binary_path=filepath,
				function_name=function.name or f"unnamed_{function.address:x}",
				size=function.size,
				opcode_hash=opcode_hash
			))
		
		return functions
	
	except Exception as e:
		print(f"  - Error processing {filepath}: {str(e)}")
		return []

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
	
	# Process all ELF files in root_dir
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
	
	# Group functions by opcode hash
	hash_groups: Dict[str, List[FunctionInfo]] = defaultdict(list)
	for func in all_functions:
		hash_groups[func.opcode_hash].append(func)
	
	# Filter groups with similar functions (size within 10% difference)
	similar_functions = []
	for opcode_hash, functions in hash_groups.items():
		if len(functions) > 1:
			# Group by similar size (±10%)
			size_groups: Dict[int, List[FunctionInfo]] = defaultdict(list)
			for func in functions:
				size_groups[round(func.size * 0.1)].append(func)
			
			for size_key, similar_funcs in size_groups.items():
				if len(similar_funcs) > 1:
					similar_functions.append(similar_funcs)

	dup_functions_num = 0
	total_wasted = 0
	
	# Write results to file
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

def is_bin_used(binary, symlinks, root_dir):
	try:
		names_to_check = {os.path.basename(binary)} if binary != "/dev/null" else set()
		names_to_check.update(os.path.basename(link) for link in symlinks)

		for _bin in names_to_check:
			if search_with_grep(_bin, names_to_check, root_dir):
				return True

		return False
	except:
		raise False

def find_unused_bins(root_dir, threads):
	print(f"  - Searching for ELF binary executables...")
	bin_dict = find_binary_files(root_dir, False)

	print(f"  - Found {len(bin_dict)} ELF binary executables")
	print("  - Searching for unused binaries...")

	unused_bins = {}
	total_size = 0

	with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
		futures = {
			executor.submit(
				is_bin_used,
				binary,
				symlinks,
				root_dir
			) : (binary, symlinks)
			for binary, symlinks in bin_dict.items()
		}

		futures_len = len(futures)
		for index, future in enumerate(concurrent.futures.as_completed(futures)):
			if futures_len > 1:
				printProgressBar(index, futures_len - 1)

			binary, symlinks = futures[future]
			if not future.result():
				unused_bins[binary] = symlinks
				try:
					total_size += os.path.getsize(binary)
					for symlink in symlinks:
						total_size += os.path.getsize(symlink)
				except OSError:
					continue

	unused_num = f"  - Total unused binaries: {len(unused_bins)}"
	unused_mem = f"  - Total wasted space: {total_size} bytes ({total_size / 1024:.2f} KB, {total_size / 1024 / 1024:.2f} MB)"

	with open("unused_binary_report.txt", "w") as unused:
		unused.write("Unused Binary Executables Analysis Report\n")
		unused.write("===============================\n")

		for binary, symlinks in unused_bins.items():
			unused.write(f"\nMain Binary: {binary}")
			if symlinks:
				unused.write("\nSymlinks:")
				for link in symlinks:
					unused.write(f"\n  - {link}")
			else:
				unused.write("\nNo symlinks")

		unused.write("\n\nSummary:")
		unused.write("\n" + unused_num)
		unused.write("\n" + unused_mem)

	print(unused_num)
	print(unused_mem)
	print("  - Saved report in: unused_binary_report.txt")

	return total_size


def get_imports(filepath):
	try:
		elf = lief.parse(filepath)
		return [i.name for i in elf.imported_symbols]
	except Exception as e:
		return []

def get_exports(filepath):
	try:
		elf = lief.parse(filepath)
		return [i.name for i in elf.exported_symbols]
	except Exception as e:
		return []

def get_binaries_functions(root_dir):
	files_to_process = {}

	for root, _, files in os.walk(root_dir):
		for filename in files:
			full_path = os.path.join(root, filename)
			
			if not os.path.exists(full_path) or not check_elf(full_path) or full_path.endswith(".ko"):
				continue
			
			try:
				if os.path.islink(full_path):
					real_path = os.path.realpath(full_path)
					if not (os.path.exists(real_path) and check_elf(real_path)):
						continue
						
					real_path_short = simplify_path(real_path, root_dir)
					simplified_path = simplify_path(full_path, root_dir)
					
					if real_path_short not in files_to_process:
						files_to_process[real_path_short] = {
							'imports': get_imports(real_path),
							'exports': get_exports(real_path),
							'symlinks': []
						}
					
					files_to_process[real_path_short]['symlinks'].append(simplified_path)
				else:
					simplified_path = simplify_path(full_path, root_dir)
					files_to_process[simplified_path] = {
						'imports': get_imports(full_path),
						'exports': get_exports(full_path)
					}
					
			except (OSError, RuntimeError):
				continue

	return files_to_process


def find_unused_funcs(root_dir, threads):
	print("  - Searching for ELF binaries...")
	files_to_process = get_binaries_functions(root_dir)

	all_imports = []
	for key, value in files_to_process.items():
		all_imports.extend(value['imports'])

	for key, value in files_to_process.items():
		for func in value['exports']:
			pass


def main():
	args = parse_args()

	if not os.path.isdir(args.root):
		print(f"Error: {args.root} is not a valid directory")
		return

	if args.threads > (os.cpu_count() + 2):
		print(f"Error: threads number is too high. Recomended threads: {os.cpu_count() + 2}.")
		return

	print("Step 1: Collecting fs files...")
	# collect_fs_files(args.root)

	print("Step 2: Searching for duplicated files...")
	# dup_files = find_duplicated_files()

	print("Step 3: Searching for duplicated functions...")
	# dup_funcs = find_duplicated_functions(args.root)

	print("Step 4: Collecting binary strings for search...")
	collect_strings(args.root, args.threads)

	print("Step 4: Searching for unused libraries...")
	unused_libs = find_unused_libs(args.root, args.threads)

	print("Step 5: Searching for unused binary executables...")
	# unused_bins = find_unused_bins(args.root, args.threads)

	print("Step 6: Searching for unused functions in shared libraries...")
	# unused_funcs = find_unused_funcs(args.root, args.threads)

	# total_wasted = dup_files + unused_libs + unused_bins
	# print(f"Summary:\n  - Total wasted memory in {args.root} filesystem is {total_wasted} bytes ({total_wasted / 1024:.2f} KB, {total_wasted / 1024 / 1024:.2f} MB)")

if __name__ == '__main__':

	main()
