"""AIShield - GNN Graph Dataset & Weak Supervision Label Generator.

Converts Module 5 NetworkX similarity graphs into PyTorch Geometric Data structures
and assigns weak supervision labels from Module 5 clustering heuristics.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx
import numpy as np
import torch
from torch_geometric.data import Data

from .feature_builder import GNNFeatureBuilder


class GNNGraphDataset:
    """Handles PyG Data conversion and weak supervision labeling for incident graphs."""

    DEFAULT_MIN_CLUSTER_SIZE = 3
    LABEL_SOURCE = "module5_weak_supervision"

    @classmethod
    def generate_weak_labels(
        cls,
        graph: nx.Graph,
        incident_ids: List[str],
        min_cluster_size: int = DEFAULT_MIN_CLUSTER_SIZE,
        threshold: float = 0.65,
    ) -> Tuple[torch.Tensor, Dict[str, Any]]:
        """Generate weak silver labels derived from Module 5 connected cluster heuristics.

        Label = 1.0 if node is part of a connected component of size >= min_cluster_size
                    with mean edge similarity >= threshold.
        Label = 0.0 otherwise.

        DO NOT treat these labels as ground truth.
        """
        n = len(incident_ids)
        if n == 0:
            return torch.empty((0,), dtype=torch.float32), {
                "label_source": cls.LABEL_SOURCE,
                "positive_count": 0,
                "negative_count": 0,
                "cluster_count": 0,
            }

        positive_node_ids: Set[str] = set()

        if graph.number_of_nodes() >= min_cluster_size and graph.number_of_edges() > 0:
            # Analyze connected components
            for comp in nx.connected_components(graph):
                if len(comp) >= min_cluster_size:
                    sub_G = graph.subgraph(comp)
                    edge_sims = [
                        d.get("similarity", 0.0)
                        for _, _, d in sub_G.edges(data=True)
                    ]
                    avg_sim = float(np.mean(edge_sims)) if edge_sims else 0.0
                    if avg_sim >= threshold:
                        positive_node_ids.update(comp)

        labels = [
            1.0 if inc_id in positive_node_ids else 0.0
            for inc_id in incident_ids
        ]

        pos_count = sum(1 for y in labels if y == 1.0)
        neg_count = n - pos_count

        label_meta = {
            "label_source": cls.LABEL_SOURCE,
            "positive_count": pos_count,
            "negative_count": neg_count,
            "positive_ratio": round(pos_count / n, 4) if n > 0 else 0.0,
            "min_cluster_size": min_cluster_size,
            "similarity_threshold": threshold,
            "identified_cluster_nodes": len(positive_node_ids),
        }

        return torch.tensor(labels, dtype=torch.float32), label_meta

    @classmethod
    def from_networkx(
        cls,
        graph: nx.Graph,
        incidents: List[Dict[str, Any]],
        generate_labels: bool = True,
        threshold: float = 0.65,
    ) -> Data:
        """Convert NetworkX graph and incident list into PyTorch Geometric Data."""
        incident_ids = [str(inc.get("incident_id", "")) for inc in incidents]
        node_to_idx = {inc_id: idx for idx, inc_id in enumerate(incident_ids)}
        num_nodes = len(incidents)

        # 1. Node Features [num_nodes, 30]
        x_mat = GNNFeatureBuilder.build_feature_matrix(incidents, graph=graph)
        x_tensor = torch.from_numpy(x_mat)

        # 2. Edge Index [2, 2 * num_edges] and Edge Attr [2 * num_edges, 1]
        src_list = []
        dst_list = []
        attr_list = []

        if graph is not None:
            for u, v, d in graph.edges(data=True):
                u_str = str(u)
                v_str = str(v)
                if u_str in node_to_idx and v_str in node_to_idx:
                    u_idx = node_to_idx[u_str]
                    v_idx = node_to_idx[v_str]
                    sim = float(d.get("similarity", 0.0))

                    # Bidirected edges for PyG
                    src_list.extend([u_idx, v_idx])
                    dst_list.extend([v_idx, u_idx])
                    attr_list.extend([[sim], [sim]])

        if src_list:
            edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
            edge_attr = torch.tensor(attr_list, dtype=torch.float32)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
            edge_attr = torch.empty((0, 1), dtype=torch.float32)

        data = Data(
            x=x_tensor,
            edge_index=edge_index,
            edge_attr=edge_attr,
            num_nodes=num_nodes,
        )
        data.node_ids = incident_ids

        # 3. Optional Weak Labels
        if generate_labels:
            y_tensor, label_meta = cls.generate_weak_labels(
                graph=graph,
                incident_ids=incident_ids,
                threshold=threshold,
            )
            data.y = y_tensor
            data.label_meta = label_meta

        return data
