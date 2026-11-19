"""AIShield - Graph Neural Network (GNN) Package.

Exports core GNN components for learned graph-based threat cluster analysis.
"""

import typing

# Apply Python 3.14+ PEP 695 compatibility patch for torch_geometric signature inspection
try:
    import torch_geometric.inspector as _insp

    _orig_eval_type = _insp.eval_type

    def _compat_eval_type(value: typing.Any, _globals: typing.Dict[str, typing.Any]) -> typing.Type:
        if isinstance(value, str):
            value = typing.ForwardRef(value)
        try:
            return typing._eval_type(value, _globals, None)
        except TypeError:
            return typing._eval_type(value, _globals, None, ())

    _insp.eval_type = _compat_eval_type
except Exception:
    pass

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
