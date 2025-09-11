import ida
import ida_idaapi

import json
import os, sys, re
import concurrent.futures

def simplify_path(full_path, root):
	try:
		return full_path[full_path.index(root):]
	except:
		return full_path

def is_elf(filename):
	try:
		with open(filename, "rb") as file:
			return file.read(4) == b"\x7FELF"
	except:
		return False

def strings_from_file(filename):
	_PATTERN = re.compile(rb'[\x20-\x7E]{5,}')
	try:
		with open(filename, "rb") as file:
			hits = _PATTERN.findall(file.read())
			return [i.decode(errors="ignore") for i in hits] if len(hits) else None
	except:
		return None

def collect_strings(root_dir):
	collected_strings = {}

	def process_file(full_path):
		current_file_strings = strings_from_file(full_path)
		if current_file_strings:
			return simplify_path(full_path, root_dir), current_file_strings

		return None

	files = []

	executables = []

	for dirpath, _, filenames in os.walk(root_dir):
		for filename in filenames:
			full_path = os.path.join(dirpath, filename)

			if not os.path.exists(full_path):
				continue

			if os.path.islink(full_path):
				continue

			if filename.endswith(".asp"):
				files.append(full_path)
				
			elif is_elf(full_path):
				files.append(full_path)
				executables.append(full_path)

	with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
		results = executor.map(process_file, files)

	for result in results:
		if result:
			key, value = result
			collected_strings[key] = value

	return collected_strings, executables


def process_with_ida(check_file):
	print("Opening IDA Pro...")
	ida.open_database(check_file, True)

	print("Runnign the IDA script...")
	ida_idaapi.IDAPython_ExecScript("ida_unused_funcs_script.py", globals())

	ida.close_database(save=False)
	print("IDA Pro is closed.")


def main(root_dir):
	print("Collecting strings from executables...")
	collected_strings, executables = collect_strings(root_dir)

	with open("collected_strings.json", "w") as col:
		json.dump(collected_strings, col)

	with open("result.json", "w") as result_file:
		json.dump({}, result_file)

	ignore = ["libc.so"]

	for file in executables:
		if file.split("\\")[-1] in ignore:
			continue

		try:
			process_with_ida(file)

		except Exception as e:
			with open("output_errors.txt", "a") as output:
				output.write(f"Error processing file: {file} {e}\n")
			continue

	print("Finish processing.")


if __name__ == '__main__':
	check_dir = sys.argv[1]

	if not os.path.isdir(check_dir):
		print(f"Directory {check_dir} does not exist.")
		exit(1)

	main(check_dir)