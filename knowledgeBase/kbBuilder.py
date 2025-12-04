import os
import json
import numpy as np
from tqdm import tqdm
from typing import List, Dict

import faiss
from nomic import embed


# Paths

CWE_JSONL = "knowledgeBase/vectorKB/all_cwe_docs.jsonl"
CERT_JSONL = "knowledgeBase/vectorKB/all_cert_docs.jsonl"

OUT_DIR = "knowledgeBase/vectorKB"
META_OUT = os.path.join(OUT_DIR, "vector_meta.jsonl")
FAISS_OUT = os.path.join(OUT_DIR, "faiss_index.bin")
EMB_MATRIX_OUT = os.path.join(OUT_DIR, "embedding_matrix.npy")

os.makedirs(OUT_DIR, exist_ok=True)


# Helpers

def load_jsonl(path: str) -> List[Dict]:
    docs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            docs.append(json.loads(line))
    return docs


def get_embeddings(texts: List[str], batch_size: int = 32):
    vectors = []

    for i in tqdm(range(0, len(texts), batch_size), desc="Embedding"):
        batch = texts[i:i+batch_size]
        result = embed.text(
            texts=batch,
            model="nomic-embed-text-v1.5",
        )
        emb = result["embeddings"]
        vectors.extend(emb)

    return np.array(vectors).astype("float32")


def normalize(v: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(v, axis=1, keepdims=True)
    return v / norms


# Build KB

def main():
    print("[INFO] Loading CWE docs...")
    cwe_docs = load_jsonl(CWE_JSONL)

    print("[INFO] Loading CERT docs...")
    cert_docs = load_jsonl(CERT_JSONL)

    all_docs = cwe_docs + cert_docs
    print(f"[INFO] Total chunks loaded: {len(all_docs)}")

    # Extract text chunks
    texts = [d["text"] for d in all_docs]

    # Embedding
    print("[INFO] Embedding chunks with nomic-embed-text-v1.5...")
    embeddings = get_embeddings(texts)
    print(f"[OK] Embedding matrix shape: {embeddings.shape}")

    # Normalize for cosine similarity via inner product
    embeddings = normalize(embeddings)

    # Build FAISS index
    dim = embeddings.shape[1]
    print(f"[INFO] Building FAISS index (dim={dim})")

    # Inner product index approximates cosine similarity when vectors normalized
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)

    # Save outputs
    print(f"[INFO] Saving FAISS index → {FAISS_OUT}")
    faiss.write_index(index, FAISS_OUT)

    print(f"[INFO] Saving embedding matrix → {EMB_MATRIX_OUT}")
    np.save(EMB_MATRIX_OUT, embeddings)

    print(f"[INFO] Saving metadata JSONL → {META_OUT}")
    with open(META_OUT, "w", encoding="utf-8") as f:
        for doc in all_docs:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")

    print("\n[FINAL] Vector KB successfully created!")
    print(f"[FINAL] Total vectors: {len(all_docs)}")
    print(f"[FINAL] Dim: {dim}")
    print(f"[FINAL] Files written:\n  - {FAISS_OUT}\n  - {META_OUT}\n  - {EMB_MATRIX_OUT}")


if __name__ == "__main__":
    main()
