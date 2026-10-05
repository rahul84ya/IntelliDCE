#!/usr/bin/env python3
"""
IDCE Continuous Learning — Feedback Fine-Tuner
===============================================
Reads corrections.jsonl (user thumbs-down events) and fine-tunes the
last two layers of HybridDCEModel with a low LR.

Usage:
  python3 ml/feedback.py \
      --corrections ml_data/corrections.jsonl \
      --model       ml_data/dce_model.pt \
      --graph-dir   ml_data/feedback_graphs \
      [--dry-run]   (validate corrections file only, no training)

Corrections format (one JSON per line):
  {"id": 42, "graph_file": "run_abc/tmp_ir_graph.json", "correct": false,
   "timestamp": "...", "graph_hash": "..."}

When correct=false: the node was predicted dead but the user says it's LIVE.
When correct=true:  the user confirmed a dead-store prediction (positive signal).

The script saves the updated model to the same path, preserving the original
as ml_data/dce_model_backup.pt.
"""

import argparse
import json
import os
import sys
import shutil
from pathlib import Path

import torch
import torch.nn as nn
from torch_geometric.data import Data, DataLoader as GeoLoader

# Inline import so this script is runnable standalone
sys.path.insert(0, str(Path(__file__).parent))
from model import HybridDCEModel
from embed import embed_runtime


DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
IN_CHANNELS = 72
STRUCT_DIM   = 8
EMB_DIM      = 64


def load_corrections(path: str) -> list[dict]:
    if not os.path.exists(path):
        print(f"[feedback] No corrections file at {path}")
        return []
    corrections = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                corrections.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return corrections


def build_graph_from_json(json_path: str, corrected_ids: dict[int, int]) -> Data | None:
    """
    Build a PyG Data object from an ir_graph_features.json.
    corrected_ids: {stmt_id: label_override}  1=dead, 0=live
    Returns None if graph_path doesn't exist or has no nodes.
    """
    if not os.path.exists(json_path):
        return None

    with open(json_path) as f:
        data = json.load(f)

    texts = []
    feats = []
    labels = []
    id_to_idx = {}

    for func in data.get("functions", []):
        for node in func.get("nodes", []):
            idx = len(texts)
            id_to_idx[node["id"]] = idx
            texts.append(node.get("text", ""))
            f_vec = node.get("features", [0.0] * STRUCT_DIM)
            # Pad or truncate to STRUCT_DIM
            f_vec = (f_vec + [0.0] * STRUCT_DIM)[:STRUCT_DIM]
            feats.append(f_vec)
            # Default label: unknown → use 0 (live)
            labels.append(corrected_ids.get(node["id"], 0))

    if not texts:
        return None

    emb = embed_runtime(texts)  # [N, 64]
    struct = torch.tensor(feats, dtype=torch.float)  # [N, 8]
    x = torch.cat([torch.from_numpy(emb), struct], dim=1)  # [N, 72]
    y = torch.tensor(labels, dtype=torch.float)

    # Build edges
    edges = [[], []]
    for func in data.get("functions", []):
        for edge in func.get("edges", []):
            s = id_to_idx.get(edge.get("source"))
            t = id_to_idx.get(edge.get("target"))
            if s is not None and t is not None:
                edges[0].append(s)
                edges[1].append(t)

    edge_index = torch.tensor(edges, dtype=torch.long) if edges[0] else \
                 torch.zeros((2, 0), dtype=torch.long)

    return Data(x=x, edge_index=edge_index, y=y)


def fine_tune(model_path: str, graphs: list[Data], dry_run: bool = False):
    if dry_run:
        print(f"[feedback] DRY RUN — would fine-tune on {len(graphs)} graphs.")
        return

    if not os.path.exists(model_path):
        print(f"[feedback] No model at {model_path}. Train first with ml/train.py.")
        return

    # Backup
    backup = model_path.replace(".pt", "_backup.pt")
    shutil.copy2(model_path, backup)
    print(f"[feedback] Backed up model → {backup}")

    model = HybridDCEModel(in_channels=IN_CHANNELS).to(DEVICE)
    model.load_state_dict(torch.load(model_path, map_location=DEVICE, weights_only=True))

    # Freeze everything except last 2 layers
    for name, param in model.named_parameters():
        param.requires_grad = name.startswith("gat") or name.startswith("classifier")

    optimizer = torch.optim.Adam(
        filter(lambda p: p.requires_grad, model.parameters()), lr=1e-4
    )
    criterion = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor([2.0]).to(DEVICE)  # corrections tend to be minority
    )

    loader = GeoLoader(graphs, batch_size=8, shuffle=True)
    model.train()

    for epoch in range(1, 6):  # 5 lightweight epochs
        total_loss = 0.0
        for batch in loader:
            batch = batch.to(DEVICE)
            optimizer.zero_grad()
            out = model(batch.x, batch.edge_index)
            loss = criterion(out, batch.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"[feedback] Epoch {epoch}/5 | Loss: {total_loss / max(len(loader),1):.4f}")

    torch.save(model.state_dict(), model_path)
    print(f"[feedback] Fine-tuned model saved → {model_path}")


def main():
    parser = argparse.ArgumentParser(description="IDCE Feedback Fine-Tuner")
    parser.add_argument("--corrections",  default="ml_data/corrections.jsonl")
    parser.add_argument("--model",        default="ml_data/dce_model.pt")
    parser.add_argument("--graph-dir",    default="ml_data/feedback_graphs",
                        help="Directory where feedback graphs are cached")
    parser.add_argument("--dry-run",      action="store_true")
    args = parser.parse_args()

    corrections = load_corrections(args.corrections)
    if not corrections:
        print("[feedback] No corrections to process.")
        return

    print(f"[feedback] Found {len(corrections)} correction entries.")

    # Group corrections by graph file
    graph_corrections: dict[str, dict[int, int]] = {}
    for c in corrections:
        gf = c.get("graph_file", "")
        if not gf:
            continue
        if gf not in graph_corrections:
            graph_corrections[gf] = {}
        # correct=false means user rejected dead prediction → label=0 (live)
        # correct=true  means user confirmed dead prediction → label=1 (dead)
        label = 0 if not c.get("correct", True) else 1
        graph_corrections[gf][c["id"]] = label

    graphs = []
    for gf, cid_map in graph_corrections.items():
        g = build_graph_from_json(gf, cid_map)
        if g is not None:
            graphs.append(g)

    print(f"[feedback] Built {len(graphs)} feedback graphs with corrections.")

    if not graphs:
        print("[feedback] No valid graphs found. Ensure graph_file paths exist.")
        return

    fine_tune(args.model, graphs, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
