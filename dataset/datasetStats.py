import json
import os
from collections import Counter


def non_blank_loc(code):
    if not isinstance(code, str):
        return 0
    return sum(1 for line in code.splitlines() if line.strip())


def load_fault_to_cwe_map(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    mapping = {}
    for entry in data:
        file_name = str(entry.get("File Name", "")).strip()
        if not file_name:
            continue
        cwe_ids = []
        for cwe in entry.get("CWE IDs", []):
            cwe_str = str(cwe).strip()
            if cwe_str:
                cwe_ids.append(cwe_str)
        mapping[file_name] = cwe_ids
    return mapping


def compute_stats(path, fault_to_cwe):
    stats = {
        "total_lines": 0,
        "blank_lines": 0,
        "invalid_json_lines": 0,
        "total_rows": 0,
        "source_distribution": {},
        "label_distribution": {},
        "type_distribution": {},
        "code_field_missing": 0,
        "code_field_not_string": 0,
        "empty_code_rows": 0,
        "non_blank_loc": {
            "min": None,
            "max": None,
            "average": 0.0,
            "sum": 0,
            "rows_counted": 0,
            "min_row_line_number": None,
            "max_row_line_number": None,
        },
    }

    source_counter = Counter()
    label_counter = Counter()
    type_counter = Counter()

    with open(path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            stats["total_lines"] += 1
            raw = line.strip()

            if not raw:
                stats["blank_lines"] += 1
                continue

            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                stats["invalid_json_lines"] += 1
                continue

            stats["total_rows"] += 1
            source_counter[str(row.get("Source", "<MISSING>"))] += 1
            label_counter[str(row.get("Label", "<MISSING>"))] += 1
            type_value = str(row.get("Type", "<MISSING>"))
            if type_value.startswith("CWE-"):
                type_counter[type_value] += 1
            else:
                mapped_cwes = fault_to_cwe.get(type_value, [])
                if not mapped_cwes:
                    stats["non_cwe_type_unmapped"] += 1
                for cwe in mapped_cwes:
                    type_counter[cwe] += 1

            if "Code" not in row:
                stats["code_field_missing"] += 1
                continue

            code = row["Code"]
            if not isinstance(code, str):
                stats["code_field_not_string"] += 1
                continue

            loc = non_blank_loc(code)
            if loc == 0:
                stats["empty_code_rows"] += 1

            loc_stats = stats["non_blank_loc"]
            loc_stats["sum"] += loc
            loc_stats["rows_counted"] += 1

            if loc_stats["min"] is None or loc < loc_stats["min"]:
                loc_stats["min"] = loc
                loc_stats["min_row_line_number"] = line_number

            if loc_stats["max"] is None or loc > loc_stats["max"]:
                loc_stats["max"] = loc
                loc_stats["max_row_line_number"] = line_number

    if stats["non_blank_loc"]["rows_counted"]:
        rows_counted = stats["non_blank_loc"]["rows_counted"]
        stats["non_blank_loc"]["average"] = stats["non_blank_loc"]["sum"] / rows_counted

    stats["source_distribution"] = dict(sorted(source_counter.items(), key=lambda x: x[0]))
    stats["label_distribution"] = dict(sorted(label_counter.items(), key=lambda x: x[0]))
    stats["type_distribution"] = dict(sorted(type_counter.items(), key=lambda x: x[0]))

    return stats


def print_stats(stats):
    print("Dataset statistics")
    print(f"Total file lines: {stats['total_lines']}")
    print(f"Blank lines: {stats['blank_lines']}")
    print(f"Invalid JSON lines: {stats['invalid_json_lines']}")
    print(f"Total parsed rows: {stats['total_rows']}")
    print()

    print("Distributions")
    print(f"Source: {stats['source_distribution']}")
    print(f"Label: {stats['label_distribution']}")
    print(f"Type (CWE only): {stats['type_distribution']}")
    print()

    print("Code field quality")
    print(f"Missing Code field: {stats['code_field_missing']}")
    print(f"Code field not string: {stats['code_field_not_string']}")
    print(f"Rows with zero non-blank code lines in Code string: {stats['empty_code_rows']}")
    print()

    loc = stats["non_blank_loc"]
    print("Non-blank code lines from Code string value")
    print(f"Rows counted (with Code as string): {loc['rows_counted']}")
    print(f"Min non-blank code lines: {loc['min']} (dataset line {loc['min_row_line_number']})")
    print(f"Max non-blank code lines: {loc['max']} (dataset line {loc['max_row_line_number']})")
    print(f"Average non-blank code lines: {loc['average']:.2f}")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(script_dir, "dataset.jsonl")
    output_path = os.path.join(script_dir, "dataset_stats.json")
    faults_path = os.path.normpath(
        os.path.join(script_dir, "..", "itcFaultTypes", "faults.json")
    )

    fault_to_cwe = load_fault_to_cwe_map(faults_path)

    stats = compute_stats(input_path, fault_to_cwe)
    print_stats(stats)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print()
    print(f"Saved JSON stats to: {os.path.abspath(output_path)}")


if __name__ == "__main__":
    main()