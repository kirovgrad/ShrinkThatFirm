import os
import subprocess
import concurrent.futures

from utils import *

def get_needed_libs(binary_path):
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
	if not os.access(filepath, os.X_OK):
		return set()
	
	try:
		needed = get_needed_libs(filepath)
		return {lib for lib in needed if lib in lib_names}
	except Exception:
		return set()

def scan_needed_sections(root_dir, lib_names, max_workers=8):
	needed_refs = set()
	lib_names = set(lib_names)
	
	files_to_process = []
	for dirpath, _, filenames in os.walk(root_dir):
		for filename in filenames:
			filepath = os.path.join(dirpath, filename)
			files_to_process.append(filepath)
	
	with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
		futures = [
			executor.submit(process_file, filepath, lib_names)
			for filepath in files_to_process
		]
		
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