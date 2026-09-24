"""AIShield - GNN Model Trainer.

Handles small-data safety, weak supervision training, honest evaluation,
and persistence for GraphSAGE on CPU.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Tuple
import networkx as nx
import numpy as np
import torch
import torch.nn as nn
from torch_geometric.data import Data

from .dataset import GNNGraphDataset
from .feature_builder import GNNFeatureBuilder
from .model import GraphSAGEClassifier

logger = logging.getLogger("AIShield.GNNTrainer")


class GNNTrainer:
    """Trainer for GraphSAGE incident cluster membership classifier."""

    MODEL_VERSION = "1.0.0"
    DEFAULT_MIN_TRAIN_NODES = 6
    DEFAULT_MIN_VAL_NODES = 4

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
        hidden_dim: int = 32,
        lr: float = 0.01,
        epochs: int = 80,
        dropout: float = 0.2,
        random_seed: int = 42,
        min_train_nodes: int = DEFAULT_MIN_TRAIN_NODES,
    ) -> None:
        self.model_path = Path(model_path) if model_path else Path("models/gnn_campaign_model.pt")
        self.metadata_path = Path(metadata_path) if metadata_path else Path("models/gnn_metadata.json")
        self.hidden_dim = hidden_dim
        self.lr = lr
        self.epochs = epochs
        self.dropout = dropout
        self.random_seed = random_seed
        self.min_train_nodes = min_train_nodes

    def _set_seed(self) -> None:
        """Establish deterministic random seeds across Python, NumPy, and PyTorch."""
        random.seed(self.random_seed)
        np.random.seed(self.random_seed)
        torch.manual_seed(self.random_seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.random_seed)

    def train(
        self,
        graph: nx.Graph,
        incidents: List[Dict[str, Any]],
        similarity_threshold: float = 0.65,
    ) -> Dict[str, Any]:
        """Execute GNN training with small-data safety and weak supervision.

        Returns status dictionary and metadata.
        """
        self._set_seed()
        num_nodes = len(incidents)

        # 1. Dataset Size Safety Guard
        if num_nodes < self.min_train_nodes:
            logger.info(
                "Insufficient incidents for GNN training (%d < %d). Returning INSUFFICIENT_DATA.",
                num_nodes,
                self.min_train_nodes,
            )
            return {
                "training_status": "INSUFFICIENT_DATA",
                "evaluation_status": "INSUFFICIENT_DATA",
                "message": f"At least {self.min_train_nodes} incidents with connection structure are required for GNN training (found {num_nodes}).",
                "training_node_count": num_nodes,
                "training_edge_count": graph.number_of_edges() if graph else 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # 2. Build Dataset & Weak Labels
        data = GNNGraphDataset.from_networkx(
            graph=graph,
            incidents=incidents,
            generate_labels=True,
            threshold=similarity_threshold,
        )

        y = data.y
        pos_count = int((y == 1.0).sum().item())
        neg_count = int((y == 0.0).sum().item())

        # 3. Class Diversity Safety Guard
        if pos_count == 0 or neg_count == 0:
            logger.info(
                "Weak label distribution lacks class diversity (pos=%d, neg=%d). Returning INSUFFICIENT_DATA.",
                pos_count,
                neg_count,
            )
            return {
                "training_status": "INSUFFICIENT_DATA",
                "evaluation_status": "INSUFFICIENT_DATA",
                "message": "Both positive (clustered) and negative (isolated) incidents are required for meaningful GNN training (class diversity required).",
                "training_node_count": num_nodes,
                "training_edge_count": graph.number_of_edges() if graph else 0,
                "positive_label_count": pos_count,
                "negative_label_count": neg_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # 4. Train / Validation Split
        # Only split if dataset is large enough for a statistically meaningful validation set
        val_eval_possible = (num_nodes >= 10 and min(pos_count, neg_count) >= 2)
        train_mask = torch.ones(num_nodes, dtype=torch.bool)
        val_mask = torch.zeros(num_nodes, dtype=torch.bool)

        if val_eval_possible:
            # Deterministic stratified split (approx 75% train / 25% val)
            pos_indices = [i for i, label in enumerate(y.tolist()) if label == 1.0]
            neg_indices = [i for i, label in enumerate(y.tolist()) if label == 0.0]

            val_pos_count = max(1, len(pos_indices) // 4)
            val_neg_count = max(1, len(neg_indices) // 4)

            val_idx_set = set(pos_indices[:val_pos_count] + neg_indices[:val_neg_count])
            for i in range(num_nodes):
                if i in val_idx_set:
                    val_mask[i] = True
                    train_mask[i] = False

        # 5. Model & Optimizer Setup
        in_dim = GNNFeatureBuilder.FEATURE_DIM
        model = GraphSAGEClassifier(
            in_channels=in_dim,
            hidden_dim=self.hidden_dim,
            dropout_p=self.dropout,
        )
        model.train()

        criterion = nn.BCEWithLogitsLoss()
        optimizer = torch.optim.Adam(
            model.parameters(),
            lr=self.lr,
            weight_decay=1e-4,
        )

        x = data.x
        edge_index = data.edge_index

        # 6. Training Loop (CPU)
        loss_history = []
        for epoch in range(self.epochs):
            optimizer.zero_grad()
            logits = model(x, edge_index)
            loss = criterion(logits[train_mask], y[train_mask])
            loss.backward()
            optimizer.step()
            loss_history.append(float(loss.item()))

        final_loss = round(loss_history[-1], 4) if loss_history else 0.0

        # 7. Evaluation Metrics (Honest, No Fake Numbers)
        model.eval()
        with torch.no_grad():
            preds_prob = torch.sigmoid(model(x, edge_index)).cpu().numpy()
            y_np = y.cpu().numpy()

        eval_status = "INSUFFICIENT_DATA"
        metrics: Dict[str, Any] = {}

        if val_eval_possible and int(val_mask.sum().item()) >= self.DEFAULT_MIN_VAL_NODES:
            eval_status = "EVALUATED"
            val_y = y_np[val_mask.numpy()]
            val_prob = preds_prob[val_mask.numpy()]
            val_pred = (val_prob >= 0.5).astype(int)

            tp = int(np.sum((val_pred == 1) & (val_y == 1)))
            tn = int(np.sum((val_pred == 0) & (val_y == 0)))
            fp = int(np.sum((val_pred == 1) & (val_y == 0)))
            fn = int(np.sum((val_pred == 0) & (val_y == 1)))

            acc = float((tp + tn) / max(1, len(val_y)))
            prec = float(tp / max(1, tp + fp)) if (tp + fp) > 0 else 0.0
            rec = float(tp / max(1, tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = float(2 * prec * rec / max(1e-6, prec + rec)) if (prec + rec) > 0 else 0.0

            metrics = {
                "validation_nodes": int(val_mask.sum().item()),
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
            }
        else:
            eval_status = "INSUFFICIENT_DATA"
            metrics = {
                "note": "Dataset too small for a separated validation split. Model trained on available nodes.",
            }

        # 8. Model Persistence (Weights + Metadata)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)

        torch.save(model.state_dict(), str(self.model_path))

        metadata = {
            "model_version": self.MODEL_VERSION,
            "feature_schema": GNNFeatureBuilder.get_feature_schema(),
            "hidden_dim": self.hidden_dim,
            "dropout_p": self.dropout,
            "learning_rate": self.lr,
            "epochs": self.epochs,
            "random_seed": self.random_seed,
            "weak_label_rule": "Connected cluster >= 3 nodes with mean similarity >= threshold",
            "similarity_threshold": similarity_threshold,
            "label_source": GNNGraphDataset.LABEL_SOURCE,
            "training_node_count": num_nodes,
            "training_edge_count": graph.number_of_edges() if graph else 0,
            "positive_label_count": pos_count,
            "negative_label_count": neg_count,
            "final_loss": final_loss,
            "training_status": "READY",
            "evaluation_status": eval_status,
            "metrics": metrics,
            "training_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        logger.info(
            "GNN training complete. Saved model to %s and metadata to %s.",
            self.model_path,
            self.metadata_path,
        )

        return metadata
