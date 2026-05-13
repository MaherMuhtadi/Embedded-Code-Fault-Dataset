# Embedded Code Fault Dataset

This repository contains the data-curation pipeline for a reusable [embedded C fault dataset](dataset/dataset.jsonl) and retrieval knowledge base. It is intended for training and evaluating embedded C fault-detection models and related retrieval-based tooling. It combines two sources of embedded C code:

1. [Toyota ITC benchmark](https://github.com/regehr/itc-benchmarks) samples for synthetic embedded code faults.
2. [Big-Vul](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset) samples for real world embedded code faults.

Each sample is represented at function level. For Toyota ITC, the extracted function is kept together with any referenced helpers, relevant type definitions, global variables, and macros needed for local semantic completeness. For Big-Vul, the curated rows keep the vulnerable function and its patched counterpart as labeled samples, and the Big-Vul subset was filtered to C-language rows whose CWE identifiers overlap with the Toyota ITC fault taxonomy so that both sources describe comparable fault families.

The repository also builds a vector knowledge base from [CWE entries](https://cwe.mitre.org/data/) and [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/spaces/c/pages/87152044/SEI+CERT+C+Coding+Standard) so the dataset can be paired with supporting security documentation.

## Table of Contents

- [Artifacts](#artifacts)
- [Dataset Schema](#dataset-schema)
  - [Field Descriptions](#field-descriptions)
  - [Dataset Statistics](#dataset-statistics)
  - [Fault Categories](#fault-categories)
- [Knowledge Base Schema](#knowledge-base-schema)
  - [CWE Documents](#cwe-documents)
  - [SEI CERT C Documents](#sei-cert-c-documents)
  - [Knowledge Base Coverage](#knowledge-base-coverage)
- [Requirements](#requirements)
  - [External Data](#external-data)
- [Installation](#installation)
- [Running the Pipeline](#running-the-pipeline)
  - [1. Build the Toyota ITC subset](#1-build-the-toyota-itc-subset)
  - [2. Extract and filter Big-Vul data](#2-extract-and-filter-big-vul-data)
  - [3. Merge the two subsets into one dataset](#3-merge-the-two-subsets-into-one-dataset)
  - [4. Create the train/test split](#4-create-the-traintest-split)
  - [5. Generate dataset statistics](#5-generate-dataset-statistics)
  - [6. Build the knowledge base](#6-build-the-knowledge-base)
- [Outputs](#outputs)
- [Example Usage](#example-usage)
  - [Loading the dataset for training](#loading-the-dataset-for-training)
  - [Querying the knowledge base](#querying-the-knowledge-base)
- [Citation](#citation)
- [License](#license)
- [Notes](#notes)

## Artifacts

- `dataset/` - final dataset merge, statistics, and train/test partitioning scripts.
- `subset1/` - Toyota ITC benchmark parser and subset builder.
- `subset2/` - Big-Vul extraction and subset builder.
- `knowledgeBase/` - CWE and SEI CERT C documentation parsers and vector knowledge-base builder.
- `itcFaultTypes/` - fault/CWE mappings used across the pipeline.

## Dataset Schema

Each record in the dataset is a JSON object with the following structure:

```json
{
  "Source": "Toyota-ITC" | "Big-Vul",
  "Type": "<fault_type_or_cwe_id>",
  "Code": "<c_code_snippet>",
  "Label": 0 | 1
}
```

### Field Descriptions

| Field    | Type    | Description                                                                                                                                                                       |
| -------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Source` | String  | Data source: `"Toyota-ITC"` for synthetic benchmarks or `"Big-Vul"` for real-world vulnerabilities                                                                                |
| `Type`   | String  | Fault type identifier. For Toyota-ITC: fault name (e.g., `"buffer_overrun_dynamic"`). For Big-Vul: CWE ID (e.g., `"CWE-189"`)                                                     |
| `Code`   | String  | Function-level C code snippet. Whitespace-normalized, comments removed. Includes target function with helpers, type defs, globals, and macros as needed for semantic completeness |
| `Label`  | Integer | Binary label: `0` for non-faulty code, `1` for faulty code                                                                                                                        |

### Dataset Statistics

- **Total samples**: 4,034
- **Toyota-ITC samples**: 1,268 (31%)
- **Big-Vul samples**: 2,766 (69%)
- **Label distribution**: Perfectly balanced (2,017 faulty, 2,017 non-faulty)
- **Fault types covered**: 44 CWE IDs across 9 defect categories
- **Code length range**: 1–161 lines (average ~25 lines)
- **Train/test split**: 70/30 (2,814 train, 1,220 test), stratified by source and type

### Fault Categories

The dataset covers the following 9 Toyota ITC defect categories:

1. **Concurrency defects** – Race conditions, deadlocks, improper locking (CWE-190, -362, -667, -675, -764, -765, -833, -843)
2. **Dynamic memory defects** – Heap buffer overflows, incorrect size calculations (CWE-122, -1260, -131, -463, -786)
3. **Inappropriate code** – Dead code, improper conditions, unchecked returns (CWE-252, -398, -484, -561, -563, -570, -571, -703)
4. **Misc defects** – Various other issues including dead code and improper termination (CWE-393, -457, -563, -835, -843)
5. **Numerical defects** – Integer overflow/underflow, divide-by-zero, type conversion errors (CWE-1335, -189, -190, -191, -196, -369, -476, -681)
6. **Pointer-related defects** – Pointer arithmetic, type casting, function pointer issues (CWE-465, -469, -476, -480, -628, -824, -843)
7. **Resource management defects** – Memory leaks, use-after-free, double-free, improper cleanup (CWE-121, -401, -415, -416, -476, -561, -562, -590, -825, -835, -908)
8. **Stack-related defects** – Stack buffer overflows, stack-based vulnerabilities (CWE-121, -416, -786)
9. **Static memory defects** – Static buffer access and overflow issues (CWE-121, -786)

## Knowledge Base Schema

Each document in the knowledge base is a JSON object with one of two structures:

### CWE Documents

```json
{
  "id": "<cwe_id>_<chunk_index>",
  "source": "CWE",
  "cwe_id": "CWE-<number>",
  "title": "<weakness_title>",
  "text": "<description_chunk>",
  "url": "https://cwe.mitre.org/data/definitions/<number>.html"
}
```

### SEI CERT C Documents

```json
{
  "id": "<rule_id>_<type>_<filename>",
  "source": "CERT_PDF" | "CERT_SAMPLES",
  "cert_rule": "<rule_id>",
  "title": "<rule_title>",
  "kind": "description" | "compliant" | "noncompliant",
  "text": "<document_text_or_code>",
  "file_path": "<path_to_sample_file>"
}
```

### Knowledge Base Coverage

- **CWE IDs**: 44 CWE entries with descriptions, consequences, mitigations, and detection methods
- **SEI CERT C rules**: 34 SEI CERT C coding standard rules with textual descriptions and compliant/noncompliant code examples
- **Total documents**: ~3,000+ semantically chunked KB entries
- **Embedding model**: Nomic Embed Text v1.5 (768 dimensions)
- **Index**: FAISS inner-product index (normalized for cosine similarity)

## Requirements

Ensure that the following are already set up:

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager
- Access to the external source datasets described below

### External Data

Before running the scripts, download or place the following inputs in the expected locations:

1. **Toyota ITC Benchmarks**: Download and extract the [regehr/itc-benchmarks](https://github.com/regehr/itc-benchmarks) repository into the `subset1/itc-benchmarks/` directory.

2. **Big-Vul MSR Dataset**: Download the `MSR_data_cleaned.json` file from the [ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset) repository. Alternatively, download directly from [this Google Drive link](https://drive.google.com/file/d/1deNsPfeh77h1SHjJURYOeyCR96JgxB_A/view?usp=sharing). Place it in the `subset2/` directory as `MSR_data_cleaned.json`.

3. **SEI CERT C Coding Standard PDF**: Download the latest SEI CERT C Coding Standard PDF from [https://www.sei.cmu.edu/forms/secure-coding-form/](https://www.sei.cmu.edu/forms/secure-coding-form/). Place it in `knowledgeBase/certData/SEI_CERT_C_Coding_Standard_2016_Edition.pdf` (or update the path in `certParser.py` if using a different version).

4. **SEI CERT C Code Samples**: Download and extract the [dyesmar/sei-cert-ccs-samples](https://github.com/dyesmar/sei-cert-ccs-samples) repository into the `knowledgeBase/certData/sei-cert-ccs-samples/` directory.

5. **CWE XML Data**: The `knowledgeBase/cweData/cwec_v4.18.xml` file is already included in this repository. If you need a different CWE version, download it from [https://cwe.mitre.org/data/](https://cwe.mitre.org/data/).

The mapping file `itcFaultTypes/extracted_ids.json` is also required and is already included. It drives the Toyota ITC to CWE/CERT mappings used for filtering and knowledge-base construction.

## Installation

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and script execution. Ensure you have `uv` installed, then sync dependencies:

```bash
uv sync
```

This reads `pyproject.toml` and installs all required dependencies.

## Running the Pipeline

### 1. Build the Toyota ITC subset

```bash
uv run python subset1/subsetBuilder.py
```

This reads the ITC benchmark sources under `subset1/itc-benchmarks/` and writes `subset1/subset.jsonl`.

### 2. Extract and filter Big-Vul data

```bash
uv run python subset2/extractData.py
uv run python subset2/subsetBuilder.py
```

The first script streams `subset2/MSR_data_cleaned.json` into `subset2/extractedData.jsonl`. The second script filters that file to C-language rows whose CWE IDs appear in `itcFaultTypes/extracted_ids.json`, producing `subset2/subset.jsonl`.

### 3. Merge the two subsets into one dataset

```bash
uv run python dataset/datasetBuilder.py
```

This combines `subset1/subset.jsonl` and `subset2/subset.jsonl` into `dataset/dataset.jsonl`.

### 4. Create the train/test split

```bash
uv run python dataset/partitionDataset.py
```

This produces:

- `dataset/partitions/train.jsonl`
- `dataset/partitions/test.jsonl`
- `dataset/partitions/split_stats.json`

### 5. Generate dataset statistics

```bash
uv run python dataset/datasetStats.py
```

This writes `dataset/dataset_stats.json` and prints summary counts to the console, including source, label, type, and basic code-length statistics.

### 6. Build the knowledge base

```bash
uv run python knowledgeBase/cweParser.py
uv run python knowledgeBase/certParser.py
uv run python knowledgeBase/kbBuilder.py
```

These scripts generate the document chunks and vector artifacts under `knowledgeBase/vectorKB/`, including the FAISS index, embedding matrix, and JSONL metadata. The KB is built from 44 CWE IDs and 34 SEI CERT C rules relevant to the curated dataset.

## Outputs

After a full rebuild, the main generated artifacts are:

- `subset1/subset.jsonl`
- `subset2/extractedData.jsonl`
- `subset2/subset.jsonl`
- `dataset/dataset.jsonl`
- `dataset/dataset_stats.json`
- `dataset/partitions/train.jsonl`
- `dataset/partitions/test.jsonl`
- `dataset/partitions/split_stats.json`
- `knowledgeBase/vectorKB/all_cwe_docs.jsonl`
- `knowledgeBase/vectorKB/all_cert_docs.jsonl`
- `knowledgeBase/vectorKB/vector_meta.jsonl`
- `knowledgeBase/vectorKB/embedding_matrix.npy`
- `knowledgeBase/vectorKB/faiss_index.bin`

The knowledge-base documents are chunked into semantically coherent pieces before embedding. The resulting vectors are normalized and indexed with FAISS for cosine-style similarity search.

## Example Usage

### Loading the dataset for training

```python
import json

# Load training data
with open('dataset/partitions/train.jsonl', 'r') as f:
    train_data = [json.loads(line) for line in f]

print(f"Loaded {len(train_data)} training samples")
for sample in train_data[:2]:
    print(f"Source: {sample['Source']}, Type: {sample['Type']}, Label: {sample['Label']}")
    print(f"Code length: {len(sample['Code'])} chars\n")
```

### Querying the knowledge base

```python
import numpy as np
import faiss
import json
from nomic import embed

# Load FAISS index and metadata
index = faiss.read_index('knowledgeBase/vectorKB/faiss_index.bin')
embeddings = np.load('knowledgeBase/vectorKB/embedding_matrix.npy')

with open('knowledgeBase/vectorKB/vector_meta.jsonl', 'r') as f:
    metadata = [json.loads(line) for line in f]

# Embed a query about buffer overflows
query = "buffer overflow detection and prevention"
query_vec = embed.text([query], model="nomic-embed-text-v1.5")["embeddings"][0]
query_vec = query_vec / np.linalg.norm(query_vec)  # normalize

# Search
k = 5
similarities, indices = index.search(np.array([query_vec]).astype('float32'), k)

for idx in indices[0]:
    doc = metadata[idx]
    print(f"Title: {doc['title']}")
    print(f"Source: {doc['source']}")
    print(f"Text: {doc['text'][:200]}...\n")
```

## Citation

If you use this dataset in your research, please cite the original data sources:

- J. Regehr, "Static analysis benchmarks from Toyota ITC," GitHub, [Online]. Available: https://github.com/regehr/itc-benchmarks. [Accessed: Nov. 18, 2025].

- J. Fan, Y. Li, S. Wang, and T. N. Nguyen, "A C/C++ code vulnerability dataset with code changes and CVE summaries," in Proc. 17th Int. Conf. Mining Softw. Repositories (MSR), New York, NY, USA, Sep. 2020, pp. 508–512, doi: 10.1145/3379597.3387501.

Additional references for the knowledge base:

- **CWE**: [Common Weakness Enumeration](https://cwe.mitre.org/data/)
- **SEI CERT C**: [SEI CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/spaces/c/pages/87152044/SEI+CERT+C+Coding+Standard)

This repository and its generated artifacts are part of the following works:

- M. Muhtadi, Q. H. Mahmoud, and A. Azim, "Adaptive Self-Prompting in Agentic LLM Frameworks for Code Fault Detection," Software, vol. 5, no. 2, art. no. 16, 2026. doi:10.3390/software5020016. [Online]. Available: https://www.mdpi.com/2674-113X/5/2/16

- M. Muhtadi, "Adaptive self-prompting in agentic LLM frameworks for embedded code fault detection," M.S. thesis, Ontario Tech University, 2026. [Online]. Available: https://hdl.handle.net/10155/2091

## License

This curation pipeline is provided as-is. Please ensure compliance with the licenses of the original datasets (Toyota ITC and Big-Vul) and external sources (CWE and SEI CERT C Coding Standard) when using the generated data.

## Notes

- The scripts assume the repository layout shown in the project tree.
- Several steps are data-heavy and may take time to complete on the first run.
- If you only need to inspect the generated artifacts, many of them are already checked into the repository.
- The dataset excludes Big-Vul functions longer than 4000 characters to stay within typical LLM context windows.
