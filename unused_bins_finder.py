import os
import concurrent.futures

from utils import *

def is_bin_used(binary, symlinks, root_dir):
	try:
		names_to_check = {os.path.basename(binary)} if binary != "/dev/null" else set()
		names_to_check.update(os.path.basename(link) for link in symlinks)

		for _bin in names_to_check:
			if search_with_grep(_bin, names_to_check, root_dir):
				return True
		return False
	except:
		return False

def find_unused_bins(root_dir, threads):
	print(f"  - Searching for ELF binary executables...")
	bin_dict = find_binary_files(root_dir, False)

	print(f"  - Found ELF binary executables: {len(bin_dict)}")

	if not len(bin_dict):
		return 0
	
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