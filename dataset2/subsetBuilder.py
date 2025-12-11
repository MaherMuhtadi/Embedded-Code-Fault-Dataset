import os
import json


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
INPUT_FILE = os.path.join(SCRIPT_DIR, "dataset.jsonl")
EXTRACTED_IDS_FILE = os.path.join(PARENT_DIR, "faultTypes", "extracted_ids.json")


def load_extracted_cwes(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return set(data["CWE_IDs"])


def count_matching_rows():
    extracted_cwes = load_extracted_cwes(EXTRACTED_IDS_FILE)
    print(f"Loaded {len(extracted_cwes)} CWE IDs from extracted_ids.json")

    count = 0
    unique_matched_cwes = set()

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            row = json.loads(line)
            cwe = row.get("CWE ID", "").strip()

            if cwe in extracted_cwes:
                count += 1
                unique_matched_cwes.add(cwe)  # Track unique CWE IDs

    print(f"\nRows with CWE IDs present in extracted_ids.json: {count}")
    print(f"Unique CWE IDs in those rows: {len(unique_matched_cwes)}")
    print("List of unique CWE IDs:", sorted(unique_matched_cwes))


if __name__ == "__main__":
    count_matching_rows()
