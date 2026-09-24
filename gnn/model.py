"""AIShield - GraphSAGE Neural Network Architecture.

Implements a 2-layer GraphSAGE classifier for predicting potential cluster membership.
Outputs raw logits for numerically stable BCEWithLogitsLoss training.
"""

from typing import Optional
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv


class GraphSAGEClassifier(nn.Module):
    """2-layer GraphSAGE model for graph-based incident cluster classification."""

    def __init__(
        self,
        in_channels: int = 30,
        hidden_dim: int = 32,
        dropout_p: float = 0.2,
    ) -> None:
        super().__init__()
        self.in_channels = in_channels
        self.hidden_dim = hidden_dim
        self.dropout_p = dropout_p

        # Layer 1: Neighborhood aggregation
        self.conv1 = SAGEConv(in_channels, hidden_dim, aggr="mean")
        # Layer 2: 2-hop neighborhood aggregation
        self.conv2 = SAGEConv(hidden_dim, hidden_dim, aggr="mean")
        # Output Linear projection
        self.fc = nn.Linear(hidden_dim, 1)
        self.dropout = nn.Dropout(p=dropout_p)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Forward pass computing raw logits.

        Args:
            x: Node feature tensor [num_nodes, in_channels]
            edge_index: Graph edge indices [2, num_edges]

        Returns:
            Raw unnormalized logits tensor [num_nodes]
        """
        # Layer 1
        h = self.conv1(x, edge_index)
        h = F.relu(h)
        h = self.dropout(h)

        # Layer 2
        h = self.conv2(h, edge_index)
        h = F.relu(h)

        # Classifier
        logits = self.fc(h).squeeze(-1)
        return logits

    @torch.no_grad()
    def predict_proba(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Compute sigmoid-activated probabilities for inference in [0.0, 1.0]."""
        self.eval()
        logits = self.forward(x, edge_index)
        # Squeeze in case of single node
        if logits.dim() == 0:
            logits = logits.unsqueeze(0)
        return torch.sigmoid(logits)
