import os
import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any


# Paths

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
CWE_XML_PATH = os.path.join(SCRIPT_DIR, "cweData", "cwec_v4.18.xml")
EXTRACTED_IDS_PATH = os.path.join(PARENT_DIR, "faultTypes", "extracted_ids.json")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "vectorKB", "cwe")
OUTPUT_JSONL = os.path.join(SCRIPT_DIR, "vectorKB", "all_cwe_docs.jsonl")

os.makedirs(OUTPUT_DIR, exist_ok=True)


# Helpers

def clean(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


def extract_text(elem: ET.Element) -> str:
    if elem is None:
        return ""
    return clean(" ".join(elem.itertext()))


def chunk_text(text: str, max_chars: int = 1500) -> List[str]:
    text = clean(text)
    if not text:
        return []

    sentences = re.split(r"(?<=[.!?])\s+", text)
    chunks, current = [], ""

    for s in sentences:
        if len(current) + len(s) + 1 <= max_chars:
            current = (current + " " + s).strip()
        else:
            if current:
                chunks.append(current)
            current = s

    if current:
        chunks.append(current)

    return chunks


# Load target CWE IDs

with open(EXTRACTED_IDS_PATH, "r", encoding="utf-8") as f:
    ids_json = json.load(f)

target_cwe_ids = set(ids_json.get("CWE_IDs", []))
numeric_ids = {cid.split("-")[1] for cid in target_cwe_ids}


# Parse CWE XML with correct namespace

print(f"Parsing CWE XML from: {CWE_XML_PATH}")

tree = ET.parse(CWE_XML_PATH)
root = tree.getroot()

# Important — CWE 4.18 uses this namespace:
ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

# Find all Weakness entries properly
weakness_elems = root.findall(".//cwe:Weaknesses/cwe:Weakness", ns)
print(f"Found {len(weakness_elems)} Weakness entries in XML.")


# Process Weaknesses

all_docs: List[Dict[str, Any]] = []

for w in weakness_elems:
    wid = w.attrib.get("ID")  # numeric string
    if wid not in numeric_ids:
        continue

    cwe_id = f"CWE-{wid}"
    name = w.attrib.get("Name", cwe_id)

    url = f"https://cwe.mitre.org/data/definitions/{wid}.html"

    # Extract main fields
    desc = extract_text(w.find("cwe:Description", ns))
    extended = extract_text(w.find("cwe:Extended_Description", ns))

    # Extract consequences
    consequences = [
        extract_text(cons)
        for cons in w.findall(".//cwe:Consequence", ns)
    ]
    consequences = [c for c in consequences if c]

    # Extract mitigations
    mitigations = [
        extract_text(m)
        for m in w.findall(".//cwe:Mitigation", ns)
    ]
    mitigations = [m for m in mitigations if m]

    # Extract detection methods
    detection_methods = [
        extract_text(dm)
        for dm in w.findall(".//cwe:Detection_Method", ns)
    ]
    detection_methods = [d for d in detection_methods if d]

    # Combine into a single text blob
    combined_parts = []

    if desc:
        combined_parts.append(f"Description: {desc}")
    if extended:
        combined_parts.append(f"Extended Description: {extended}")
    if consequences:
        combined_parts.append("Consequences: " + " ".join(consequences))
    if mitigations:
        combined_parts.append("Mitigations: " + " ".join(mitigations))
    if detection_methods:
        combined_parts.append("Detection Methods: " + " ".join(detection_methods))

    combined_text = clean(" ".join(combined_parts))
    if not combined_text:
        print(f"[WARN] CWE {cwe_id} had no content. Skipping.")
        continue

    # Chunk text for vector embedding
    chunks = chunk_text(combined_text, max_chars=1500)

    cwe_docs = []
    for i, chunk in enumerate(chunks):
        doc = {
            "id": f"{cwe_id}_{i}",
            "source": "CWE",
            "cwe_id": cwe_id,
            "title": name,
            "text": chunk,
            "url": url
        }
        cwe_docs.append(doc)
        all_docs.append(doc)

    # Save per-CWE file
    out_path = os.path.join(OUTPUT_DIR, f"{cwe_id}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cwe_docs, f, indent=2, ensure_ascii=False)

    print(f"[OK] {cwe_id}: {len(cwe_docs)} chunks saved → {out_path}")


# Save combined JSONL

with open(OUTPUT_JSONL, "w", encoding="utf-8") as f:
    for d in all_docs:
        f.write(json.dumps(d, ensure_ascii=False) + "\n")

print(f"\nDone! Total CWE chunks: {len(all_docs)}")
print(f"Combined JSONL saved to: {OUTPUT_JSONL}")
