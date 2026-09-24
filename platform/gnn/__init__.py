"""AIShield - Graph Neural Network (GNN) Package.

Exports core GNN components for learned graph-based threat cluster analysis.
"""

from .dataset import GNNGraphDataset
from .feature_builder import GNNFeatureBuilder
from .model import GraphSAGEClassifier
from .predictor import GNNPredictor
from .trainer import GNNTrainer

__all__ = [
    "GNNFeatureBuilder",
    "GraphSAGEClassifier",
    "GNNGraphDataset",
    "GNNTrainer",
    "GNNPredictor",
]
