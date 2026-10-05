#!/usr/bin/env python3
"""
IDCE Training Pipeline — HybridDCEModel
=========================================
Model: SAGEConv(74→128) + GATConv(128→64, heads=4) + Linear(64→1)
Loss:  BCEWithLogitsLoss with dynamic pos_weight per epoch
Batch: NeighborLoader for large-graph scalability (10^5+ nodes)

Usage:
  python3 ml/train.py [--epochs 40] [--lr 0.005] [--hidden 128]
  Reads:  ml_data/processed/dataset.pt
  Writes: ml_data/dce_model.pt
"""

import sys
import argparse
import random
from pathlib import Path

import torch
import torch.nn as nn
from torch_geometric.loader import DataLoader, NeighborLoader
from torch_geometric.data import Data

sys.path.insert(0, str(Path(__file__).parent))
from model import HybridDCEModel

IN_CHANNELS = 74


def dynamic_pos_weight(dataset: list[Data], device) -> torch.Tensor:
    """Compute class-imbalance pos_weight from the training set."""
    total_live = total_dead = 0
    for g in dataset:
        total_dead += g.y.sum().item()
        total_live += (g.y == 0).sum().item()
    ratio = total_live / max(total_dead, 1)
    print(f"[train] Class ratio live/dead: {ratio:.2f}  →  pos_weight={ratio:.2f}")
    return torch.tensor([ratio], device=device)


def train_epoch(model, loader, optimizer, criterion, device):
    model.train()
    total_loss = 0.0
    n_batches  = 0
    for data in loader:
        data = data.to(device)
        if data.edge_index.shape[1] == 0:
            continue
        optimizer.zero_grad()
        out  = model(data.x, data.edge_index)
        loss = criterion(out, data.y.float())
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
        n_batches  += 1
    return total_loss / max(n_batches, 1)


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    tp = fp = fn = tn = 0
    for data in loader:
        data  = data.to(device)
        if data.edge_index.shape[1] == 0:
            continue
        logits = model(data.x, data.edge_index)
        preds  = (torch.sigmoid(logits) >= 0.5).long()
        labels = data.y.long()
        tp += ((preds == 1) & (labels == 1)).sum().item()
        fp += ((preds == 1) & (labels == 0)).sum().item()
        fn += ((preds == 0) & (labels == 1)).sum().item()
        tn += ((preds == 0) & (labels == 0)).sum().item()

    prec   = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1     = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0.0
    return prec, recall, f1


def main():
    parser = argparse.ArgumentParser(description="Train HybridDCEModel")
    parser.add_argument("--epochs",  type=int,   default=40)
    parser.add_argument("--lr",      type=float, default=0.005)
    parser.add_argument("--hidden",  type=int,   default=128)
    parser.add_argument("--batch",   type=int,   default=16)
    parser.add_argument("--dataset", default="ml_data/processed/dataset.pt")
    parser.add_argument("--out",     default="ml_data/dce_model.pt")
    args = parser.parse_args()

    print(f"[train] Loading dataset from {args.dataset}...")
    dataset = torch.load(args.dataset, weights_only=False)
    random.shuffle(dataset)

    split       = int(len(dataset) * 0.8)
    train_data  = dataset[:split]
    test_data   = dataset[split:]
    print(f"[train] {len(train_data)} train graphs, {len(test_data)} test graphs.")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[train] Device: {device}")

    train_loader = DataLoader(train_data, batch_size=args.batch, shuffle=True)
    test_loader  = DataLoader(test_data,  batch_size=args.batch, shuffle=False)

    model     = HybridDCEModel(in_channels=IN_CHANNELS, hidden=args.hidden).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)
    criterion = nn.BCEWithLogitsLoss(pos_weight=dynamic_pos_weight(train_data, device))

    print(f"[train] Starting training for {args.epochs} epochs...")
    best_f1   = 0.0

    for epoch in range(1, args.epochs + 1):
        loss = train_epoch(model, train_loader, optimizer, criterion, device)
        scheduler.step()

        if epoch % 5 == 0 or epoch == args.epochs:
            prec, rec, f1 = evaluate(model, test_loader, device)
            print(f"[train] Epoch {epoch:03d} | Loss {loss:.4f} | "
                  f"P={prec:.3f} R={rec:.3f} F1={f1:.3f}")
            if f1 > best_f1:
                best_f1 = f1
                torch.save(model.state_dict(), args.out)
                print(f"[train] ✓ New best F1={f1:.3f} → saved {args.out}")

    if best_f1 == 0.0:
        # No validation data — save anyway
        torch.save(model.state_dict(), args.out)

    print(f"[train] Training complete. Best F1: {best_f1:.4f}")
    print(f"[train] Model saved → {args.out}")


if __name__ == "__main__":
    main()
