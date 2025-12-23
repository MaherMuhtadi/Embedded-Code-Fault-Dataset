import json
import math
import os
import random
from collections import Counter, defaultdict


# Per-source stratified split (70/10/20) on Type/Label, then concat
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
INPUT_PATH = os.path.join(SCRIPT_DIR, "dataset.jsonl")
OUT_DIR = os.path.join(SCRIPT_DIR, "partitions")
ITC_FAULTS_PATH = os.path.normpath(os.path.join(PARENT_DIR, "itcFaultTypes", "faults.json"))

RANDOM_SEED = 1337

TRAIN_RATIO = 0.70
VAL_RATIO = 0.10
TEST_RATIO = 0.20

REQUIRED_KEYS = ["Source", "Type", "Code", "Label"]


def read_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {i} in {path}: {e}") from e
            rows.append(obj)
    return rows


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def validate_rows(rows):
    for i, row in enumerate(rows):
        missing = [key for key in REQUIRED_KEYS if key not in row]
        if missing:
            raise ValueError(f"Row {i} missing required keys: {missing}")


def allocate_counts(count, ratios):
    """Split count items into train/val/test using ratios; keep totals exact."""
    if count <= 0:
        return 0, 0, 0

    expected = [count * r for r in ratios]
    allocated = [math.floor(x) for x in expected]
    remainder = count - sum(allocated)

    fractional = [(expected[i] - allocated[i], i) for i in range(3)]
    fractional.sort(reverse=True)
    for _, idx in fractional[:remainder]:
        allocated[idx] += 1

    if count >= 3:
        for idx in (1, 2):  # ensure val/test not empty when possible
            if allocated[idx] == 0:
                donor = max(range(3), key=lambda t: allocated[t])
                if allocated[donor] > 1:
                    allocated[donor] -= 1
                    allocated[idx] += 1

    if sum(allocated) != count:
        allocated[0] += count - sum(allocated)

    return tuple(allocated)


def make_stratum_key(row):
    return str(row.get("Type", "")), str(row.get("Label", ""))


def compute_stats(splits):
    stats = {"splits": {}}
    for split_name, rows in splits.items():
        stats["splits"][split_name] = {
            "num_rows": len(rows),
            "by_source": dict(Counter(r["Source"] for r in rows)),
            "by_label": dict(Counter(r["Label"] for r in rows)),
            "by_type": dict(Counter(r["Type"] for r in rows)),
            "by_source_label_type": {
                " | ".join(map(str, k)): v
                for k, v in Counter(
                    (r["Source"], r["Label"], r["Type"]) for r in rows
                ).items()
            },
        }
    return stats


def load_fault_cwe_map(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    mapping = {}
    for entry in data:
        file_name = entry.get("File Name")
        if not file_name:
            continue
        mapping[str(file_name)] = [str(cwe) for cwe in entry.get("CWE IDs", []) if cwe]
    return mapping


def compute_cwe_extremes(rows, fault_cwe_map, top_n=10):
    cwe_counts = Counter()

    for row in rows:
        cwes = set()
        type_val = str(row.get("Type", ""))

        if type_val.startswith("CWE-"):
            cwes.add(type_val)
        else:
            mapped = fault_cwe_map.get(type_val, [])
            for cwe in mapped:
                cwes.add(str(cwe))

        for cwe in cwes:
            cwe_counts[cwe] += 1

    most_common = sorted(cwe_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    least_common = sorted(cwe_counts.items(), key=lambda kv: (kv[1], kv[0]))

    top = [{"type": cwe, "count": count} for cwe, count in most_common[:top_n]]
    bottom = [{"type": cwe, "count": count} for cwe, count in least_common[:top_n]]

    return {
        "totals": dict(cwe_counts),
        "top_10": top,
        "bottom_10": bottom,
    }


def main():
    split_ratios = (TRAIN_RATIO, VAL_RATIO, TEST_RATIO)
    if abs(sum(split_ratios) - 1.0) > 1e-6:
        raise ValueError("TRAIN_RATIO + VAL_RATIO + TEST_RATIO must sum to 1.0")

    rng = random.Random(RANDOM_SEED)

    rows = read_jsonl(INPUT_PATH)
    validate_rows(rows)

    rows_by_source = defaultdict(list)
    for row in rows:
        rows_by_source[row["Source"]].append(row)

    train_rows = []
    val_rows = []
    test_rows = []

    for _, source_rows in rows_by_source.items():
        strata = defaultdict(list)
        for row in source_rows:
            strata[make_stratum_key(row)].append(row)

        source_train = []
        source_val = []
        source_test = []

        for group in strata.values():
            rng.shuffle(group)
            n_train, n_val, n_test = allocate_counts(len(group), split_ratios)
            source_train.extend(group[:n_train])
            source_val.extend(group[n_train:n_train + n_val])
            source_test.extend(group[n_train + n_val:n_train + n_val + n_test])

        rng.shuffle(source_train)
        rng.shuffle(source_val)
        rng.shuffle(source_test)

        train_rows.extend(source_train)
        val_rows.extend(source_val)
        test_rows.extend(source_test)

    rng.shuffle(train_rows)
    rng.shuffle(val_rows)
    rng.shuffle(test_rows)

    os.makedirs(OUT_DIR, exist_ok=True)
    write_jsonl(os.path.join(OUT_DIR, "train.jsonl"), train_rows)
    write_jsonl(os.path.join(OUT_DIR, "val.jsonl"), val_rows)
    write_jsonl(os.path.join(OUT_DIR, "test.jsonl"), test_rows)

    fault_cwe_map = load_fault_cwe_map(ITC_FAULTS_PATH)

    split_stats = compute_stats({
        "train": train_rows,
        "val": val_rows,
        "test": test_rows,
    })

    split_stats["cwe"] = compute_cwe_extremes(rows, fault_cwe_map)

    with open(os.path.join(OUT_DIR, "split_stats.json"), "w", encoding="utf-8") as f:
        json.dump(split_stats, f, indent=2, ensure_ascii=False)

    print("Split complete")
    print(f"Train: {len(train_rows)}")
    print(f"Val:   {len(val_rows)}")
    print(f"Test:  {len(test_rows)}")
    print(f"Sources: {sorted(rows_by_source.keys())}")


if __name__ == "__main__":
    main()
