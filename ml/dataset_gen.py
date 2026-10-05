#!/usr/bin/env python3
"""
IDCE Dataset Generator — Hybrid 72-d Node Features
====================================================
Feature vector per node: [MiniLM_64d | structural_8d]
  structural_8d:
    [0] opcode        (0-5)
    [1] side_effect   (0/1)
    [2] after_terminal(0/1)
    [3] use_count     (int)
    [4] post_dom_depth(int, approx)
    [5] is_phi        (0/1)
    [6] loop_depth    (int, approx)
    [7] is_branch_target (0/1)
    [8] is_func_call  (0/1)
    [9] is_io         (0/1)

Label: 1=dead, 0=live  (from comparing pre- vs post-classical-DCE IR)

Usage:
  python3 ml/dataset_gen.py
  Reads:  ml_data/raw/*.txt   (SSA input files)
  Writes: ml_data/processed/dataset.pt
"""

import json
import os
import subprocess
import glob
import sys
from pathlib import Path

import torch
from torch_geometric.data import Data

sys.path.insert(0, str(Path(__file__).parent))
from embed import embed_runtime

RAW_DIR = "ml_data/raw"
OUT_DIR = "ml_data/processed"
IDCE_BIN = "/home/vyrion/tmp_build/idce"   # ext4 binary — NTFS safe
STRUCT_DIM = 10
EMB_DIM    = 64


def process_file(filepath: str) -> list[Data] | None:
    base_name  = os.path.basename(filepath).split(".")[0]
    out_folder = f"ml_data/tmp_{base_name}"

    # Run classical DCE to get ground-truth labels
    cmd = f'"{IDCE_BIN}" --ml-extract {out_folder}'
    try:
        with open(filepath) as inp:
            subprocess.run(
                cmd, shell=True, stdin=inp, check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
    except subprocess.CalledProcessError:
        return None

    pre_path  = f"{out_folder}/ir_graph_features.json"
    post_path = f"{out_folder}/ir_graph_optimized.json"

    if not os.path.exists(pre_path) or not os.path.exists(post_path):
        return None

    with open(pre_path)  as f: unopt = json.load(f)
    with open(post_path) as f: opt   = json.load(f)

    # Nodes that survived classical DCE → live
    survived = set()
    for func in opt["functions"]:
        for node in func["nodes"]:
            survived.add(node["id"])

    graphs = []
    for func in unopt["functions"]:
        nodes = func.get("nodes", [])
        edges = func.get("edges", [])
        if not nodes:
            continue

        id_to_idx = {n["id"]: i for i, n in enumerate(nodes)}

        texts   = [n.get("text", "")                          for n in nodes]
        feats   = [(n.get("features", [0]*STRUCT_DIM) + [0]*STRUCT_DIM)[:STRUCT_DIM]
                   for n in nodes]
        
        # Determine labels: 1=dead, 0=live. 
        # Inject HARD NEGATIVES: if it's a function call (feat[8]==1) or IO (feat[9]==1), force to 0.
        labels = []
        for i, n in enumerate(nodes):
            f = feats[i]
            is_func = f[8] if len(f) > 8 else 0
            is_io = f[9] if len(f) > 9 else 0
            is_dead = 0 if n["id"] in survived else 1
            if is_func or is_io:
                is_dead = 0
            labels.append(is_dead)

        # MiniLM embeddings [N, 64]
        emb     = embed_runtime(texts)                         # np [N, 64]
        emb_t   = torch.tensor(emb, dtype=torch.float)
        struct_t= torch.tensor(feats, dtype=torch.float)
        x       = torch.cat([emb_t, struct_t], dim=1)         # [N, 72]
        y       = torch.tensor(labels, dtype=torch.long)

        # Build edge index
        src_list, tgt_list, edge_types = [], [], []
        type_map = {"CFG": 0, "DFG": 1, "CFG_BRANCH": 2, "PDG": 3}
        for e in edges:
            s = id_to_idx.get(e.get("source"))
            t = id_to_idx.get(e.get("target"))
            if s is not None and t is not None:
                src_list.append(s)
                tgt_list.append(t)
                edge_types.append(type_map.get(e.get("type", "CFG"), 0))

        if src_list:
            edge_index = torch.tensor([src_list, tgt_list], dtype=torch.long)
            edge_attr  = torch.tensor(edge_types, dtype=torch.long).unsqueeze(1)
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)
            edge_attr  = torch.zeros((0, 1), dtype=torch.long)

        graphs.append(Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y))

    # Cleanup
    subprocess.run(f"rm -rf {out_folder}", shell=True)
    return graphs


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    all_graphs = []

    files = glob.glob(f"{RAW_DIR}/*.txt") + glob.glob(f"{RAW_DIR}/*.ssa")
    print(f"[dataset_gen] Processing {len(files)} SSA files → PyG dataset...")

    for i, fp in enumerate(files):
        graphs = process_file(fp)
        if graphs:
            all_graphs.extend(graphs)
        if (i + 1) % 10 == 0:
            print(f"[dataset_gen] {i+1}/{len(files)} files processed, "
                  f"{len(all_graphs)} graphs so far.")

    if not all_graphs:
        print("[dataset_gen] WARNING: No graphs generated. Check ml_data/raw/ for SSA files.")
    else:
        torch.save(all_graphs, f"{OUT_DIR}/dataset.pt")
        total_nodes = sum(g.num_nodes for g in all_graphs)
        total_dead  = sum(g.y.sum().item() for g in all_graphs)
        print(f"[dataset_gen] Done. {len(all_graphs)} graphs, "
              f"{total_nodes} nodes, {int(total_dead)} dead labels.")
        print(f"[dataset_gen] Saved → {OUT_DIR}/dataset.pt")
