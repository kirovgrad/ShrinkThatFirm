import os
import argparse

import utils
from fs_collector import collect_fs_files
from dup_files_finder import find_duplicated_files
from dup_funcs_finder import find_duplicated_functions
from string_collector import collect_strings
from unused_libs_finder import find_unused_libs
from unused_bins_finder import find_unused_bins
from unused_funcs_finder import find_unused_funcs

def parse_args():
	parser = argparse.ArgumentParser(description='Find unused shared libraries')
	parser.add_argument('--root', default='/', help='Root directory to search')
	parser.add_argument('--threads', type=int, default=8, help='Number of parallel threads')
	return parser.parse_args()

def main():
	args = parse_args()

	if not os.path.isdir(args.root):
		print(f"Error: {args.root} is not a valid directory")
		return

	if args.threads > (os.cpu_count() + 2):
		print(f"Error: threads number is too high. Recomended threads: {os.cpu_count() + 2}.")
		return

	# Gather all files info in given firmware directory into csv file
	print("Step 1: Collecting fs files...")
	collect_fs_files(args.root)

	# Analyze files info from previous step to find duplicate files
	print("Step 2: Searching for duplicated files...")
	dup_files = find_duplicated_files()

	# Analyze binary files in directory to find duplicated functions in one or several binaries
	print("Step 3: Searching for duplicated functions...")
	dup_funcs = find_duplicated_functions(args.root)

	# Collect strings from all binaries for better performance in the next step
	print("Step 4: Collecting binary strings for search...")
	utils._STRINGCOLLECT = collect_strings(args.root, args.threads)

	# Search for usage of a shared library and find unused ones
	print("Step 4: Searching for unused libraries...")
	unused_libs = find_unused_libs(args.root, args.threads)

	# Search for usage of bin executables
	print("Step 5: Searching for unused binary executables...")
	unused_bins = find_unused_bins(args.root, args.threads)

	total_wasted = dup_files + dup_funcs + unused_libs + unused_bins
	print(f"Summary:\n  - Total wasted memory in {args.root} filesystem is {total_wasted} bytes ({total_wasted / 1024:.2f} KB, {total_wasted / 1024 / 1024:.2f} MB)")

if __name__ == '__main__':
	main()