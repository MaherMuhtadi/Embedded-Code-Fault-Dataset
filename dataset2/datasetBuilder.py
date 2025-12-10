import ijson
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(SCRIPT_DIR, "MSR_data_cleaned.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "dataset.jsonl")

with open(INPUT_FILE, "rb") as f, open(OUTPUT_FILE, "w") as out:

    # Stream key–value pairs from the root dict
    parser = ijson.kvitems(f, "")

    for key, row in parser:
        # Only keep vulnerable samples and drop missing or unchanged functions
        if str(row.get("vul")) != "1":
            continue
        if not row.get("func_before") or not row.get("func_after"):
            continue
        if row.get("func_before") == row.get("func_after"):
            continue

        cwe = row.get("CWE ID")
        lang = row.get("lang")

        # func_before → label=1
        out.write(json.dumps({
            "CWE ID": cwe,
            "Language": lang,
            "Code": row.get("func_before"),
            "Label": 1
        }) + "\n")

        # func_after → label=0
        out.write(json.dumps({
            "CWE ID": cwe,
            "Language": lang,
            "Code": row.get("func_after"),
            "Label": 0
        }) + "\n")
