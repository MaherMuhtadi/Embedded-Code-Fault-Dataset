import os
import re
import json
from typing import List, Dict
import pdfplumber


# Paths

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
EXTRACTED_IDS_PATH = os.path.join(PARENT_DIR, "faultTypes", "extracted_ids.json")

PDF_PATH = os.path.join(SCRIPT_DIR, "certData", "SEI_CERT_C_Coding_Standard_2016_Edition.pdf")
SAMPLES_ROOT = os.path.join(SCRIPT_DIR, "certData", "sei-cert-ccs-samples")

OUTPUT_DIR = os.path.join(SCRIPT_DIR, "vectorKB", "cert")
OUTPUT_JSONL = os.path.join(SCRIPT_DIR, "vectorKB", "all_cert_docs.jsonl")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Rule header in PDF, e.g. "5.1 INT30-C. Ensure that unsigned integer operations do not wrap"
RULE_HEADER_RE = re.compile(r"^\d+\.\d+\s+([A-Z]{3}\d{2}-C)\.\s+(.+)$")

# Rule ID pattern in filenames / code, e.g. INT30-C, MEM35-C, ARR37-C
RULE_ID_RE = re.compile(r"[A-Z]{3}\d{2}-C")


# Common helpers

def norm_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def chunk_text(text: str, max_chars: int = 1500) -> List[str]:
    text = norm_ws(text)
    if not text:
        return []
    sentences = re.split(r"(?<=[.!?])\s+", text)
    chunks, cur = [], ""
    for s in sentences:
        if not s:
            continue
        if len(cur) + len(s) + 1 <= max_chars:
            cur = (cur + " " + s).strip()
        else:
            if cur:
                chunks.append(cur)
            cur = s
    if cur:
        chunks.append(cur)
    return chunks


# Load target CERT rule IDs

def load_target_rule_ids() -> set:
    with open(EXTRACTED_IDS_PATH, "r", encoding="utf-8") as f:
        ids_json = json.load(f)
    rules = set(ids_json.get("SEI_CERT_C_Rules", []))
    print(f"[INFO] Loaded {len(rules)} target CERT rules from {EXTRACTED_IDS_PATH}")
    return rules

TARGET_RULE_IDS = load_target_rule_ids()


# Parse PDF: get rule descriptions (no code needed from PDF)

def extract_rules_from_pdf(pdf_path: str) -> Dict[str, Dict]:
    print(f"[PDF] Parsing rules from: {pdf_path}")
    rules: Dict[str, Dict] = {}

    with pdfplumber.open(pdf_path) as pdf:
        lines: List[str] = []
        for page in pdf.pages:
            text = page.extract_text() or ""
            for raw in text.splitlines():
                line = raw.strip()
                if line:
                    lines.append(line)

    current_rule_id = None
    current_title = None
    body_lines: List[str] = []

    for line in lines:
        m = RULE_HEADER_RE.match(line)
        if m:
            # commit previous rule
            if current_rule_id:
                rules[current_rule_id] = {
                    "rule_id": current_rule_id,
                    "title": current_title,
                    "raw_text": "\n".join(body_lines)
                }
            current_rule_id = m.group(1)
            current_title = m.group(2)
            body_lines = []
        else:
            if current_rule_id:
                body_lines.append(line)

    # flush last rule
    if current_rule_id and current_rule_id not in rules:
        rules[current_rule_id] = {
            "rule_id": current_rule_id,
            "title": current_title,
            "raw_text": "\n".join(body_lines)
        }

    print(f"[PDF] Found {len(rules)} rules total in PDF")
    return rules


def split_description_from_pdf(raw_text: str) -> str:
    text = raw_text

    # Look for the earliest occurrence of any example heading
    markers = [
        "Noncompliant Code Example",
        "Noncompliant Code Example 1",
        "Noncompliant Code Example 2",
        "Compliant Solution",
        "Compliant Solution 1",
        "Compliant Solution 2",
    ]
    positions = [text.find(m) for m in markers if text.find(m) != -1]

    if not positions:
        # No explicit example headings; keep full text as description
        return text

    first_pos = min(positions)
    return text[:first_pos]


def build_docs_from_pdf(rules_from_pdf: Dict[str, Dict]) -> Dict[str, List[Dict]]:
    per_rule_docs: Dict[str, List[Dict]] = {}

    for rule_id, data in rules_from_pdf.items():
        if rule_id not in TARGET_RULE_IDS:
            continue

        title = data["title"]
        raw = data["raw_text"]

        desc = split_description_from_pdf(raw)
        desc = norm_ws(desc)
        if not desc:
            print(f"[PDF] {rule_id}: no description text extracted, skipping.")
            continue

        chunks = chunk_text(desc, max_chars=1500)

        docs = []
        for i, chunk in enumerate(chunks):
            doc = {
                "id": f"{rule_id}_pdf_{i}",
                "source": "CERT_PDF",
                "cert_rule": rule_id,
                "title": title,
                "kind": "description",
                "text": chunk,
            }
            docs.append(doc)

        per_rule_docs[rule_id] = docs
        print(f"[PDF] {rule_id}: {len(docs)} description chunk(s)")

    return per_rule_docs


# Parse GitHub samples: compliant & noncompliant code

def infer_rule_id(path: str, content: str) -> str:
    # Try path first
    m = RULE_ID_RE.findall(path)
    if m:
        return m[0]
    # Fallback to content
    m2 = RULE_ID_RE.findall(content)
    if m2:
        return m2[0]
    return ""


def infer_code_kind(path: str) -> str:
    lower = path.lower()
    if any(k in lower for k in ["noncompliant", "bad", "unsafe", "vuln"]):
        return "noncompliant"
    if any(k in lower for k in ["compliant", "good", "safe", "fix"]):
        return "compliant"
    return "unknown"


def build_docs_from_samples() -> Dict[str, List[Dict]]:
    per_rule_docs: Dict[str, List[Dict]] = {}

    print(f"[SAMPLES] Scanning structured repo at: {SAMPLES_ROOT}/rules")

    rules_root = os.path.join(SAMPLES_ROOT, "rules")
    if not os.path.isdir(rules_root):
        print("[ERROR] Expected directory 'rules/' inside the repo.")
        return per_rule_docs

    # Traverse: rules/<category>/<number>/
    for category in os.listdir(rules_root):
        cat_path = os.path.join(rules_root, category)
        if not os.path.isdir(cat_path):
            continue

        for num in os.listdir(cat_path):
            rule_path = os.path.join(cat_path, num)
            if not os.path.isdir(rule_path):
                continue

            # Build CERT rule ID: e.g. arr/30 → ARR30-C
            rule_id = f"{category.upper()}{num}-C"

            # Only keep rules relevant to faultTypes/extracted_ids.json
            if rule_id not in TARGET_RULE_IDS:
                continue

            # Output storage
            per_rule_docs.setdefault(rule_id, [])

            # Inspect files inside the rule folder
            for fname in os.listdir(rule_path):
                if not fname.lower().endswith(".c"):
                    continue

                full_path = os.path.join(rule_path, fname)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    print(f"[WARN] Could not read {full_path}: {e}")
                    continue

                rel_path = os.path.relpath(full_path, SAMPLES_ROOT).replace("\\", "/")

                # Determine whether file is compliant or noncompliant
                lower = fname.lower()

                if lower.startswith("nc"):
                    kind = "noncompliant"
                elif lower.startswith("c"):
                    kind = "compliant"
                else:
                    # The README says all samples follow nc* or c*,
                    # so unknown ones are extremely rare, but we label them anyway.
                    kind = "unknown"

                doc = {
                    "id": f"{rule_id}_samples_{fname}",
                    "source": "CERT_SAMPLES",
                    "cert_rule": rule_id,
                    "file_path": rel_path,
                    "kind": kind,
                    "text": content.replace("\r", "")
                }

                per_rule_docs[rule_id].append(doc)

            print(f"[SAMPLES] {rule_id}: {len(per_rule_docs[rule_id])} sample files")

    return per_rule_docs


# Combine PDF + samples, save per rule + global JSONL

def main():
    rules_pdf_raw = extract_rules_from_pdf(PDF_PATH)
    pdf_docs = build_docs_from_pdf(rules_pdf_raw)
    sample_docs = build_docs_from_samples()

    all_docs = []

    # Merge by rule_id, but only for target rules
    for rule_id in sorted(TARGET_RULE_IDS):
        combined = []
        if rule_id in pdf_docs:
            combined.extend(pdf_docs[rule_id])
        if rule_id in sample_docs:
            combined.extend(sample_docs[rule_id])

        if not combined:
            print(f"[WARN] {rule_id}: no PDF or sample docs found.")
            continue

        # Save per-rule JSON
        out_path = os.path.join(OUTPUT_DIR, f"{rule_id}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2, ensure_ascii=False)
        print(f"[OK] {rule_id}: {len(combined)} docs → {out_path}")

        all_docs.extend(combined)

    # Save combined JSONL
    os.makedirs(os.path.dirname(OUTPUT_JSONL), exist_ok=True)
    with open(OUTPUT_JSONL, "w", encoding="utf-8") as f:
        for d in all_docs:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")

    print(f"\n[FINAL] Total CERT docs: {len(all_docs)}")
    print(f"[FINAL] Combined JSONL: {OUTPUT_JSONL}")


if __name__ == "__main__":
    main()
