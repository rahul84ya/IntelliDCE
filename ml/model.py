"""
IDCE HybridDCEModel
====================
Architecture:
  - Input: 74-d node features (64-d MiniLM embed + 10 structural)
  - GNN Stage 1: SAGEConv(74 → 128)
  - GNN Stage 2: GATConv(128 → 64, heads=4, concat=False)
    └─ Attention coefficients saved for explainability
  - Classifier: Linear(64 → 1) → logit (BCEWithLogitsLoss)

Outputs per forward():
  - logits   : [N] float — dead-code score (raw)
  - attn     : [E, 4] float — per-edge, per-head attention weights
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, GATConv


class HybridDCEModel(nn.Module):
    def __init__(self, in_channels: int = 74, hidden: int = 128, gat_heads: int = 4):
        super().__init__()
        self.sage = SAGEConv(in_channels, hidden)
        # GATConv in concat=False mode → output is heads-averaged → hidden//heads per head
        self.gat  = GATConv(hidden, hidden // gat_heads, heads=gat_heads,
                             concat=False, dropout=0.2)
        self.classifier = nn.Linear(hidden // gat_heads, 1)
        self.dropout = nn.Dropout(p=0.25)

    def forward(self, x, edge_index, return_attention: bool = False):
        # Stage 1: GraphSAGE aggregation
        x = self.sage(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)

        # Stage 2: Graph Attention
        if return_attention:
            x, (edge_idx, attn_weights) = self.gat(
                x, edge_index, return_attention_weights=True
            )
        else:
            x = self.gat(x, edge_index)
        x = F.relu(x)

        logits = self.classifier(x).squeeze(-1)  # [N]

        if return_attention:
            return logits, attn_weights          # attn_weights: [E, heads]
        return logits
