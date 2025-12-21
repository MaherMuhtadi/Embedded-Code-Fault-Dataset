import os
import json


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
INPUT_FILES = [
    (os.path.join(PARENT_DIR, "subset1", "subset.jsonl"), "Toyota-ITC"),
    (os.path.join(PARENT_DIR, "subset2", "subset.jsonl"), "Big-Vul")
]
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "dataset.jsonl")


def merge_subsets():
    all_rows = []

    for input_file, source in INPUT_FILES:
        if not os.path.exists(input_file):
            print(f"Warning: {input_file} does not exist, skipping...")
            continue

        print(f"Processing {input_file}...")
        entries = 0

        with open(input_file, "r", encoding="utf-8") as fin:
            for line in fin:
                if not line.strip():
                    continue

                try:
                    row = json.loads(line)
                    
                    if source == "Toyota-ITC":
                        directory = row.get("Directory", "")
                        filename = os.path.basename(directory)
                        fault_type = filename.replace(".c", "")

                        # Handle specific naming inconsistency
                        if fault_type == "free_nondynamically_allocated_memory":
                            fault_type = "free_nondynamic_allocated_memory"
                            
                    else:
                        fault_type = row.get("CWE ID", "")
                    
                    ordered_row = {
                        "Source": source,
                        "Type": fault_type,
                        "Code": row.get("Code", ""),
                        "Label": row.get("Label", "")
                    }
                    
                    all_rows.append(ordered_row)
                    entries += 1
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON in {input_file}: {e}")
                    continue

        print(f"  Added {entries} entries from {input_file}")

    print(f"\nSorting {len(all_rows)} entries by Source and Type...")
    all_rows.sort(key=lambda x: (x["Source"], x["Type"]))

    print(f"Writing sorted entries to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fout:
        for row in all_rows:
            fout.write(json.dumps(row) + "\n")

    print(f"Dataset saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    merge_subsets()
