import os

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