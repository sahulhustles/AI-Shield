"""AIShield - GNN Model Predictor & Graph Explainer.

Loads the trained GraphSAGE model and performs inference to estimate
cluster membership probability with explanatory graph statistics.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import networkx as nx
import numpy as np
import torch

from .dataset import GNNGraphDataset
from .feature_builder import GNNFeatureBuilder
from .model import GraphSAGEClassifier

logger = logging.getLogger("AIShield.GNNPredictor")


class GNNPredictor:
    """Predictor for estimating potential cluster membership on incident graphs."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
    ) -> None:
        self.model_path = Path(model_path) if model_path else Path("models/gnn_campaign_model.pt")
        self.metadata_path = Path(metadata_path) if metadata_path else Path("models/gnn_metadata.json")
        self._model: Optional[GraphSAGEClassifier] = None
        self._metadata: Optional[Dict[str, Any]] = None

    def is_model_available(self) -> bool:
        """Check whether saved model weights and metadata exist."""
        return self.model_path.exists() and self.metadata_path.exists()

    def get_metadata(self) -> Dict[str, Any]:
        """Load and return model training metadata."""
        if not self.metadata_path.exists():
            return {
                "model_version": "N/A",
                "training_status": "NOT_TRAINED",
                "evaluation_status": "INSUFFICIENT_DATA",
                "training_node_count": 0,
                "training_edge_count": 0,
            }

        try:
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error("Failed to read GNN metadata: %s", e)
            return {"training_status": "ERROR", "error": str(e)}

    def load_model(self) -> bool:
        """Load GraphSAGE model weights onto CPU."""
        if not self.is_model_available():
            return False

        try:
            metadata = self.get_metadata()
            hidden_dim = int(metadata.get("hidden_dim", 32))
            dropout_p = float(metadata.get("dropout_p", 0.2))
            in_dim = GNNFeatureBuilder.FEATURE_DIM

            model = GraphSAGEClassifier(
                in_channels=in_dim,
                hidden_dim=hidden_dim,
                dropout_p=dropout_p,
            )
            state_dict = torch.load(str(self.model_path), map_location="cpu", weights_only=True)
            model.load_state_dict(state_dict)
            model.eval()
            self._model = model
            self._metadata = metadata
            return True
        except Exception as exc:
            logger.exception("Failed to load GNN model weights: %s", exc)
            self._model = None
            return False

    @classmethod
    def classify_probability(cls, prob: float) -> str:
        """Map analytical cluster probability to risk likelihood bands."""
        if prob >= 0.70:
            return "HIGH_LIKELIHOOD"
        elif prob >= 0.40:
            return "POSSIBLE"
        else:
            return "LOW_LIKELIHOOD"

    def predict(
        self,
        graph: nx.Graph,
        incidents: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Perform GNN inference on incident relationship graph."""
        if not incidents:
            return {
                "status": "NO_DATA",
                "message": "No incidents provided for GNN analysis.",
                "predictions": [],
                "summary": {"total_nodes": 0, "high_likelihood_count": 0, "possible_count": 0, "low_likelihood_count": 0},
            }

        if self._model is None:
            if not self.load_model():
                return {
                    "status": "NOT_TRAINED",
                    "message": "GNN model has not been trained yet. Train the model using POST /api/gnn/train.",
                    "predictions": [],
                    "summary": {"total_nodes": len(incidents), "high_likelihood_count": 0, "possible_count": 0, "low_likelihood_count": 0},
                }

        # Build PyG Data
        data = GNNGraphDataset.from_networkx(
            graph=graph,
            incidents=incidents,
            generate_labels=False,
        )

        with torch.no_grad():
            probs = self._model.predict_proba(data.x, data.edge_index).cpu().numpy()

        incidents_by_id = {str(inc.get("incident_id")): inc for inc in incidents}
        component_size_map: Dict[str, int] = {}
        if graph is not None and graph.number_of_nodes() > 0:
            for comp in nx.connected_components(graph):
                c_size = len(comp)
                for node_id in comp:
                    component_size_map[str(node_id)] = c_size

        predictions: List[Dict[str, Any]] = []
        high_cnt = 0
        poss_cnt = 0
        low_cnt = 0

        for idx, inc_id in enumerate(data.node_ids):
            prob = float(probs[idx])
            prob_clamped = round(max(0.0, min(1.0, prob)), 4)
            classification = self.classify_probability(prob_clamped)

            if classification == "HIGH_LIKELIHOOD":
                high_cnt += 1
            elif classification == "POSSIBLE":
                poss_cnt += 1
            else:
                low_cnt += 1

            # Graph context statistics
            neighbor_sims = []
            neighbor_threats = []
            deg = 0

            if graph is not None and inc_id in graph:
                deg = graph.degree(inc_id)
                for _, v, d in graph.edges(inc_id, data=True):
                    neighbor_sims.append(float(d.get("similarity", 0.0)))
                    v_inc = incidents_by_id.get(str(v))
                    if v_inc:
                        neighbor_threats.append(float(v_inc.get("threat_score", 0.0)))

            avg_sim = round(float(np.mean(neighbor_sims)), 4) if neighbor_sims else 0.0
            avg_threat = round(float(np.mean(neighbor_threats)), 2) if neighbor_threats else 0.0
            cluster_size = component_size_map.get(inc_id, 1)

            predictions.append({
                "incident_id": inc_id,
                "cluster_membership_probability": prob_clamped,
                "probability_percent": round(prob_clamped * 100.0, 1),
                "classification": classification,
                "explanation": {
                    "neighbor_count": deg,
                    "average_neighbor_similarity": avg_sim,
                    "cluster_size": cluster_size,
                    "average_neighbor_threat_score": avg_threat,
                },
            })

        # Sort predictions: highest probability first
        predictions.sort(key=lambda p: -p["cluster_membership_probability"])

        return {
            "status": "READY",
            "model_version": self._metadata.get("model_version", "1.0.0") if self._metadata else "1.0.0",
            "predictions": predictions,
            "summary": {
                "total_nodes": len(predictions),
                "high_likelihood_count": high_cnt,
                "possible_count": poss_cnt,
                "low_likelihood_count": low_cnt,
            },
        }
