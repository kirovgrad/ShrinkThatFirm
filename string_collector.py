import os, re
import concurrent.futures

from utils import *

_PATTERN = re.compile(rb'[\x20-\x7E]{7,}')

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
	result_dict = {}
	
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
				result_dict[key] = strings
			if total > 1:
				printProgressBar(idx, total)

	return dict(sorted(result_dict.items(), key=lambda item: check_elf(item[0]), reverse=True))