"""AIShield - GNN Feature Builder.

Constructs deterministic numeric node feature vectors for incident nodes in the
relationship graph without target or label leakage.
"""

import json
import math
from typing import Any, Dict, List, Optional
import networkx as nx
import numpy as np


class GNNFeatureBuilder:
    """Extracts and normalizes numeric feature representations for incident nodes."""

    FEATURE_SCHEMA_VERSION = "1.0.0"

    CATEGORIES = [
        "Normal",
        "Phishing",
        "Disinformation",
        "Manipulation",
        "Propaganda",
        "Spam",
        "Other",
    ]

    RISK_LEVELS = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    AI_LABELS = [
        "Human",
        "AI-generated",
    ]

    FEATURE_ORDER = [
        # Continuous forensic & text metrics (14)
        "ai_probability",
        "human_probability",
        "confidence",
        "threat_score_scaled",
        "word_count_log",
        "sentence_count_log",
        "avg_word_length_scaled",
        "avg_sentence_length_scaled",
        "vocabulary_richness",
        "urgency_score_scaled",
        "manipulation_score_scaled",
        "cta_score_scaled",
        "unverified_claims_scaled",
        "authority_pattern_scaled",
        # Graph topological features (3)
        "node_degree_normalized",
        "degree_centrality",
        "avg_neighbor_similarity",
        # One-hot category (7)
        "cat_Normal",
        "cat_Phishing",
        "cat_Disinformation",
        "cat_Manipulation",
        "cat_Propaganda",
        "cat_Spam",
        "cat_Other",
        # One-hot risk level (4)
        "risk_LOW",
        "risk_MEDIUM",
        "risk_HIGH",
        "risk_CRITICAL",
        # One-hot AI label (2)
        "label_Human",
        "label_AI-generated",
    ]

    FEATURE_DIM = len(FEATURE_ORDER)  # 30

    @classmethod
    def get_feature_schema(cls) -> Dict[str, Any]:
        """Return the immutable schema and feature order metadata."""
        return {
            "schema_version": cls.FEATURE_SCHEMA_VERSION,
            "feature_dim": cls.FEATURE_DIM,
            "feature_order": list(cls.FEATURE_ORDER),
            "categories": list(cls.CATEGORIES),
            "risk_levels": list(cls.RISK_LEVELS),
            "ai_labels": list(cls.AI_LABELS),
        }

    @classmethod
    def extract_node_features(
        cls,
        incident: Dict[str, Any],
        graph: Optional[nx.Graph] = None,
        centrality_map: Optional[Dict[str, float]] = None,
    ) -> np.ndarray:
        """Extract a single incident's 30-dim numeric feature vector.

        Strictly excludes any cluster IDs or campaign labels to prevent label leakage.
        """
        node_id = str(incident.get("incident_id", ""))

        # 1. Base Probabilities & Threat Score
        ai_prob = max(0.0, min(1.0, float(incident.get("ai_probability", 0.5))))
        human_prob = max(0.0, min(1.0, float(incident.get("human_probability", 1.0 - ai_prob))))
        confidence = max(0.0, min(1.0, float(incident.get("confidence", max(ai_prob, human_prob)))))
        threat_score = float(incident.get("threat_score", 0.0))
        threat_score_scaled = max(0.0, min(1.0, threat_score / 100.0))

        # 2. Text Analysis Metrics
        text_analysis = incident.get("text_analysis") or {}
        if isinstance(text_analysis, str):
            try:
                text_analysis = json.loads(text_analysis)
            except Exception:
                text_analysis = {}

        raw_words = float(text_analysis.get("word_count", 0.0))
        raw_sentences = float(text_analysis.get("sentence_count", 1.0))
        raw_avg_word_len = float(text_analysis.get("avg_word_length", 5.0))
        raw_avg_sent_len = float(text_analysis.get("avg_sentence_length", raw_words))
        vocab_richness = float(text_analysis.get("vocabulary_richness", 0.5))

        word_count_log = max(0.0, min(1.0, math.log1p(raw_words) / 10.0))
        sentence_count_log = max(0.0, min(1.0, math.log1p(raw_sentences) / 5.0))
        avg_word_length_scaled = max(0.0, min(1.0, raw_avg_word_len / 15.0))
        avg_sentence_length_scaled = max(0.0, min(1.0, raw_avg_sent_len / 50.0))
        vocab_richness_clamped = max(0.0, min(1.0, vocab_richness))

        # 3. Threat Component Scores
        component_scores = incident.get("component_scores") or {}
        if isinstance(component_scores, str):
            try:
                component_scores = json.loads(component_scores)
            except Exception:
                component_scores = {}

        urgency_score = float(component_scores.get("urgency", 0.0)) / 100.0
        manipulation_score = float(component_scores.get("manipulation", 0.0)) / 100.0
        cta_score = float(component_scores.get("cta", component_scores.get("call_to_action", 0.0))) / 100.0
        unverified_claims = float(component_scores.get("unverified_claims", 0.0)) / 100.0
        authority_patterns = float(component_scores.get("authority_patterns", 0.0)) / 100.0

        # 4. Graph Structural Features
        node_deg_norm = 0.0
        deg_centrality = 0.0
        avg_neighbor_sim = 0.0

        if graph is not None and node_id in graph:
            deg = graph.degree(node_id)
            node_deg_norm = max(0.0, min(1.0, float(deg) / 20.0))
            if centrality_map is not None:
                deg_centrality = float(centrality_map.get(node_id, 0.0))
            else:
                deg_centrality = float(deg) / max(1, graph.number_of_nodes() - 1) if graph.number_of_nodes() > 1 else 0.0

            # Neighbor similarities
            neighbor_sims = [
                d.get("similarity", 0.0)
                for _, _, d in graph.edges(node_id, data=True)
            ]
            if neighbor_sims:
                avg_neighbor_sim = float(np.mean(neighbor_sims))

        # 5. One-Hot Category
        raw_cat = str(incident.get("category", "Normal"))
        cat_one_hot = [1.0 if raw_cat == c else 0.0 for c in cls.CATEGORIES]
        if sum(cat_one_hot) == 0:
            cat_one_hot[-1] = 1.0  # Default to "Other"

        # 6. One-Hot Risk Level
        raw_risk = str(incident.get("risk_level", "LOW")).upper()
        risk_one_hot = [1.0 if raw_risk == r else 0.0 for r in cls.RISK_LEVELS]
        if sum(risk_one_hot) == 0:
            risk_one_hot[0] = 1.0  # Default to "LOW"

        # 7. One-Hot AI Label
        raw_label = str(incident.get("ai_label", "Human"))
        label_one_hot = [1.0 if raw_label == l else 0.0 for l in cls.AI_LABELS]
        if sum(label_one_hot) == 0:
            label_one_hot[0] = 1.0  # Default to "Human"

        vector = [
            ai_prob,
            human_prob,
            confidence,
            threat_score_scaled,
            word_count_log,
            sentence_count_log,
            avg_word_length_scaled,
            avg_sentence_length_scaled,
            vocab_richness_clamped,
            max(0.0, min(1.0, urgency_score)),
            max(0.0, min(1.0, manipulation_score)),
            max(0.0, min(1.0, cta_score)),
            max(0.0, min(1.0, unverified_claims)),
            max(0.0, min(1.0, authority_patterns)),
            node_deg_norm,
            deg_centrality,
            avg_neighbor_sim,
            *cat_one_hot,
            *risk_one_hot,
            *label_one_hot,
        ]

        return np.array(vector, dtype=np.float32)

    @classmethod
    def build_feature_matrix(
        cls,
        incidents: List[Dict[str, Any]],
        graph: Optional[nx.Graph] = None,
    ) -> np.ndarray:
        """Build feature matrix [N, 30] for ordered list of incidents."""
        if not incidents:
            return np.empty((0, cls.FEATURE_DIM), dtype=np.float32)

        centrality_map = None
        if graph is not None and graph.number_of_nodes() > 0:
            try:
                centrality_map = nx.degree_centrality(graph)
            except Exception:
                centrality_map = None

        features = [
            cls.extract_node_features(inc, graph=graph, centrality_map=centrality_map)
            for inc in incidents
        ]
        return np.vstack(features)
