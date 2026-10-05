#!/usr/bin/env python3
"""
IDCE Offline Embedding Script
==============================
Uses sentence-transformers/all-MiniLM-L6-v2 (80 MB) to generate 64-d
per-statement embeddings from ir_graph_features.json files.

Usage:
  # Embed all raw SSA files (runs idce --ml-extract first internally):
  python3 ml/embed.py --input-dir ml_data/raw --out-dir ml_data/embeddings

  # Embed a single ir_graph_features.json directly:
  python3 ml/embed.py --json path/to/ir_graph_features.json --out-dir ml_data/embeddings

Output: ml_data/embeddings/<stem>.npy
  Shape: [num_nodes_total, 64] — one embedding row per statement in order.
  A matching ml_data/embeddings/<stem>_ids.npy stores [stmt_id, func_idx] pairs.

The model is cached by HuggingFace in ~/.cache/torch/sentence_transformers.
On NTFS drives: cache is on the ext4 ~ home — no issues.
"""

import argparse
import os
import json
import sys
import numpy as np

_MODEL = None


def get_model():
    global _MODEL
    if _MODEL is None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            print("[embed] ERROR: sentence-transformers not installed.")
            print("  Run: pip install sentence-transformers")
            sys.exit(1)
        print("[embed] Loading MiniLM-L6-v2 (first run downloads ~80 MB)...")
        _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
        print("[embed] Model ready.")
    return _MODEL


def embed_json(json_path: str, out_dir: str) -> str:
    """
    Embed all statements in a single ir_graph_features.json.
    Returns path to the saved .npy file.
    """
    with open(json_path, "r") as f:
        data = json.load(f)

    texts = []
    meta  = []  # (stmt_id, func_idx)

    for f_idx, func in enumerate(data.get("functions", [])):
        for node in func.get("nodes", []):
            texts.append(node.get("text", ""))
            meta.append((node["id"], f_idx))

    if not texts:
        return None

    model = get_model()
    # Batch encode — returns [N, 384] float32; we PCA-reduce to 64-d inline
    embeddings_384 = model.encode(
        texts, batch_size=128, show_progress_bar=False, convert_to_numpy=True
    )  # [N, 384]

    # Simple linear projection to 64-d using a fixed random seed projection
    # (consistent across runs — same seed → same projection matrix)
    rng = np.random.default_rng(seed=42)
    proj = rng.standard_normal((384, 64)).astype(np.float32)
    proj /= np.linalg.norm(proj, axis=0, keepdims=True)  # column-normalize
    embeddings_64 = embeddings_384 @ proj  # [N, 64]

    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(json_path))[0]
    emb_path = os.path.join(out_dir, f"{stem}.npy")
    ids_path = os.path.join(out_dir, f"{stem}_ids.npy")

    np.save(emb_path, embeddings_64.astype(np.float32))
    np.save(ids_path, np.array(meta, dtype=np.int64))
    return emb_path


def embed_runtime(texts: list[str]) -> np.ndarray:
    """
    Embed a list of SSA statement strings at inference time.
    Returns [N, 64] float32 numpy array.
    Used by inference.py when no cached embedding exists.
    """
    model = get_model()
    emb = model.encode(
        texts, batch_size=64, show_progress_bar=False, convert_to_numpy=True
    ).astype(np.float32)  # [N, 384]

    rng = np.random.default_rng(seed=42)
    proj = rng.standard_normal((384, 64)).astype(np.float32)
    proj /= np.linalg.norm(proj, axis=0, keepdims=True)
    return emb @ proj  # [N, 64]


def main():
    parser = argparse.ArgumentParser(description="Offline MiniLM embedding for IDCE")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input-dir", help="Directory of ir_graph_features.json files")
    group.add_argument("--json",       help="Single ir_graph_features.json file")
    parser.add_argument("--out-dir", default="ml_data/embeddings",
                        help="Output directory for .npy files")
    args = parser.parse_args()

    if args.json:
        p = embed_json(args.json, args.out_dir)
        if p: print(f"[embed] Saved → {p}")
    else:
        files = [
            os.path.join(args.input_dir, f)
            for f in os.listdir(args.input_dir)
            if f.endswith(".json")
        ]
        print(f"[embed] Processing {len(files)} files...")
        for i, fp in enumerate(files):
            p = embed_json(fp, args.out_dir)
            if p and (i + 1) % 20 == 0:
                print(f"[embed] {i+1}/{len(files)} done")
        print(f"[embed] Complete. Embeddings saved to {args.out_dir}/")


if __name__ == "__main__":
    main()
