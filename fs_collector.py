import os
import sys
import hashlib

def md5(fname):
	hash_md5 = hashlib.md5()
	with open(fname, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()

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

if __name__ == '__main__':
	collect_fs_files(sys.argv[1])