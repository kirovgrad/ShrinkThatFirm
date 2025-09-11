import os
import re
import sys
import subprocess

from collections import defaultdict

_STRINGCOLLECT = {}

def check_elf(filepath):
	try:
		with open(filepath, "rb") as file:
			return file.read(4) == b"\x7FELF"
	except:
		return False

def printProgressBar(iteration, total, length=50):
	percent = ("{0:.1f}").format(100 * (iteration / float(total)))
	filled_length = int(length * iteration // total)
	bar = "█" * filled_length + "-" * (length - filled_length)

	sys.stdout.write(f"\r|{bar}| {percent}%")
	sys.stdout.flush()

	if iteration == total:
		sys.stdout.write("\n")

def simplify_path(full_path, root):
	try:
		return full_path[full_path.index(root):]
	except:
		return full_path

def find_binary_files(root_dir, find_so=True):
	lib_dict = defaultdict(list)
	
	for dirpath, _, filenames in os.walk(root_dir):
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

def search_function(to_search, skip_files):	
	pattern = rf'\b{to_search}\b'
	result = ""

	for i in _STRINGCOLLECT:
		if os.path.basename(i) in skip_files:
			continue

		if not check_elf(i):
			continue

		result += (" ".join(_STRINGCOLLECT[i]) + " ")

	return re.search(pattern, result)


def search_with_grep(to_search, skip_files, root_dir, only_binary=False):
	pattern = rf'\b{to_search}\b'

	if len(_STRINGCOLLECT):
		for i in _STRINGCOLLECT:
			if os.path.basename(i) in skip_files:
				continue

			if only_binary and not check_elf(i):
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