import os
import json


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
INPUT_FILE = os.path.join(SCRIPT_DIR, "extractedData.jsonl")
EXTRACTED_IDS_FILE = os.path.join(PARENT_DIR, "faultTypes", "extracted_ids.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "subset.jsonl")


def load_extracted_cwes(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return set(data["CWE_IDs"])


def build_subset():
    extracted_cwes = load_extracted_cwes(EXTRACTED_IDS_FILE)
    print(f"Loaded {len(extracted_cwes)} CWE IDs...")

    kept = 0

    with open(INPUT_FILE, "r", encoding="utf-8") as fin, \
         open(OUTPUT_FILE, "w", encoding="utf-8") as fout:

        for line in fin:
            if not line.strip():
                continue

            row = json.loads(line)
            cwe = row.get("CWE ID", "").strip()
            lang = row.get("Language", "").strip()

            if cwe in extracted_cwes and lang == "C":
                fout.write(json.dumps(row) + "\n")
                kept += 1

    print(f"Saved {kept} matching rows to subset.jsonl")


if __name__ == "__main__":
    build_subset()
