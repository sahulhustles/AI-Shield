"""AIShield - GNN Threat Cluster Analysis Service.

Thread-safe service orchestrating GraphSAGE model training, metadata management,
and inference on top of Module 5 relationship graphs.
"""

import logging
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Union

from database.db import get_db_path
from gnn.predictor import GNNPredictor
from gnn.trainer import GNNTrainer
from services.graph_service import ThreatGraphService

logger = logging.getLogger("AIShield.GNNThreatService")


class GNNThreatService:
    """Orchestrates GNN model training and prediction on threat relationship graphs."""

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        model_path: Optional[Union[str, Path]] = None,
        metadata_path: Optional[Union[str, Path]] = None,
        min_train_nodes: int = 6,
        hidden_dim: int = 32,
        lr: float = 0.01,
        epochs: int = 80,
        dropout: float = 0.2,
        random_seed: int = 42,
    ) -> None:
        self.db_path = get_db_path(db_path)
        self.model_path = Path(model_path) if model_path else Path("models/gnn_campaign_model.pt")
        self.metadata_path = Path(metadata_path) if metadata_path else Path("models/gnn_metadata.json")

        self.trainer = GNNTrainer(
            model_path=self.model_path,
            metadata_path=self.metadata_path,
            hidden_dim=hidden_dim,
            lr=lr,
            epochs=epochs,
            dropout=dropout,
            random_seed=random_seed,
            min_train_nodes=min_train_nodes,
        )

        self.predictor = GNNPredictor(
            model_path=self.model_path,
            metadata_path=self.metadata_path,
        )

        self.graph_service = ThreatGraphService(db_path=self.db_path)
        self._training_lock = threading.Lock()
        self._is_training = False

    @property
    def is_training(self) -> bool:
        """Check whether a background training cycle is actively running."""
        with self._training_lock:
            return self._is_training

    def get_status(self) -> Dict[str, Any]:
        """Return operational status and metadata for GNN model."""
        meta = self.predictor.get_metadata()
        has_model = self.predictor.is_model_available()

        training_status = meta.get("training_status", "NOT_TRAINED")
        if self._is_training:
            training_status = "TRAINING"
        elif not has_model and training_status == "NOT_TRAINED":
            # Check if incident count is insufficient
            incidents = self.graph_service.load_incidents()
            if len(incidents) < self.trainer.min_train_nodes:
                training_status = "INSUFFICIENT_DATA"

        return {
            "status": training_status,
            "training_status": training_status,
            "has_model": has_model,
            "is_training": self._is_training,
            "model_version": meta.get("model_version", "N/A"),
            "training_node_count": meta.get("training_node_count", 0),
            "training_edge_count": meta.get("training_edge_count", 0),
            "positive_label_count": meta.get("positive_label_count", 0),
            "negative_label_count": meta.get("negative_label_count", 0),
            "evaluation_status": meta.get("evaluation_status", "INSUFFICIENT_DATA"),
            "metrics": meta.get("metrics", {}),
            "training_timestamp": meta.get("training_timestamp"),
            "label_source": meta.get("label_source", "module5_weak_supervision"),
            "min_train_nodes": self.trainer.min_train_nodes,
        }

    def train(self, similarity_threshold: float = 0.65) -> Dict[str, Any]:
        """Trigger GNN training against current database incidents.

        Thread-safe: Rejects concurrent training attempts.
        """
        if not self._training_lock.acquire(blocking=False):
            return {
                "success": False,
                "error": "A GNN training process is already in progress.",
                "training_status": "TRAINING",
            }

        self._is_training = True
        try:
            threshold = self.graph_service.validate_threshold(similarity_threshold)
            incidents = self.graph_service.load_incidents()
            graph = self.graph_service.build_graph(threshold=threshold, incidents=incidents)

            result = self.trainer.train(
                graph=graph,
                incidents=incidents,
                similarity_threshold=threshold,
            )

            # Reload predictor if model was successfully saved
            if result.get("training_status") == "READY":
                self.predictor.load_model()

            return {
                "success": True,
                **result,
            }
        except Exception as exc:
            logger.exception("Error during GNN training: %s", exc)
            return {
                "success": False,
                "error": str(exc),
                "training_status": "ERROR",
            }
        finally:
            self._is_training = False
            self._training_lock.release()

    def predict(self, similarity_threshold: float = 0.65) -> Dict[str, Any]:
        """Perform GNN inference on the current incident relationship graph."""
        threshold = self.graph_service.validate_threshold(similarity_threshold)
        incidents = self.graph_service.load_incidents()
        graph = self.graph_service.build_graph(threshold=threshold, incidents=incidents)

        result = self.predictor.predict(graph=graph, incidents=incidents)
        return {
            "success": True,
            "threshold": threshold,
            **result,
        }

    def get_explanation(
        self,
        incident_id: str,
        similarity_threshold: float = 0.65,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve prediction and graph statistics for a single incident ID."""
        pred_res = self.predict(similarity_threshold=similarity_threshold)
        clean_id = str(incident_id).strip()

        for p in pred_res.get("predictions", []):
            if p["incident_id"] == clean_id:
                return p

        return None
