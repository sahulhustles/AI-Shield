"""AIShield - Module 5: Threat Relationship Graph & Campaign Detection Service.

Builds deterministic relationship graphs based on TF-IDF cosine similarity,
detects connected incident clusters, and identifies potential campaigns using NetworkX.
"""

from collections import Counter
from datetime import datetime, timezone
import math
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import networkx as nx
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from database.db import db_session, get_db_path


class ThreatGraphService:
    """Service for constructing threat relationship graphs and identifying potential campaigns."""

    DEFAULT_SIMILARITY_THRESHOLD = 0.65
    MIN_SIMILARITY_THRESHOLD = 0.50
    MAX_SIMILARITY_THRESHOLD = 0.95
    DEFAULT_INCIDENTS_LIMIT = 50
    MAX_INCIDENTS_LIMIT = 500
    MIN_CAMPAIGN_CLUSTER_SIZE = 3

    SUPPORTED_CATEGORIES = [
        "Normal",
        "Phishing",
        "Disinformation",
        "Manipulation",
        "Propaganda",
        "Spam",
        "Other",
    ]

    RISK_RANK = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize ThreatGraphService with database path."""
        self.db_path = get_db_path(db_path)

    @classmethod
    def validate_threshold(cls, threshold: Optional[Union[float, int, str]]) -> float:
        """Validate and convert the similarity threshold parameter.

        Raises:
            ValueError: If threshold is not numeric or outside [0.50, 0.95].
        """
        if threshold is None:
            return cls.DEFAULT_SIMILARITY_THRESHOLD

        try:
            val = float(threshold)
        except (ValueError, TypeError):
            raise ValueError(f"Similarity threshold must be a numeric value, got '{threshold}'.")

        if not (cls.MIN_SIMILARITY_THRESHOLD <= val <= cls.MAX_SIMILARITY_THRESHOLD):
            raise ValueError(
                f"Similarity threshold must be between {cls.MIN_SIMILARITY_THRESHOLD} and {cls.MAX_SIMILARITY_THRESHOLD}, got {val}."
            )

        return round(val, 4)

    @classmethod
    def preprocess_text(cls, text: Optional[str]) -> str:
        """Normalize whitespace and case for text similarity calculation.

        Does NOT modify the stored incident content in SQLite.
        """
        if not text or not isinstance(text, str):
            return ""
        # Lowercase, replace newlines/tabs with space, collapse repeated whitespace
        cleaned = re.sub(r"\s+", " ", text.strip().lower())
        return cleaned

    def load_incidents(self, limit: int = DEFAULT_INCIDENTS_LIMIT) -> List[Dict[str, Any]]:
        """Retrieve the most recent incidents from SQLite up to the bounded limit (default 50)."""
        safe_limit = max(1, min(self.MAX_INCIDENTS_LIMIT, int(limit))) if isinstance(limit, (int, float)) else self.DEFAULT_INCIDENTS_LIMIT

        sql = """
        SELECT incident_id, created_at, content, content_hash, ai_label, ai_probability,
               threat_score, risk_level, category
        FROM incidents
        ORDER BY created_at DESC, id DESC
        LIMIT ?;
        """

        with db_session(self.db_path) as conn:
            rows = conn.execute(sql, (safe_limit,)).fetchall()

        incidents = []
        for r in rows:
            incidents.append({
                "incident_id": r["incident_id"],
                "created_at": r["created_at"],
                "content": r["content"],
                "content_hash": r["content_hash"],
                "ai_label": r["ai_label"],
                "ai_probability": float(r["ai_probability"]),
                "threat_score": float(r["threat_score"]),
                "risk_level": r["risk_level"],
                "category": r["category"],
            })

        return incidents

    def build_similarity_matrix(self, incidents: List[Dict[str, Any]]) -> np.ndarray:
        """Compute pairwise cosine similarity matrix using TF-IDF over normalized content.

        Returns empty (0, 0) matrix if fewer than 2 incidents.
        """
        if len(incidents) < 2:
            return np.empty((len(incidents), len(incidents)))

        corpus = [self.preprocess_text(inc["content"]) for inc in incidents]

        # Use unigram and bigram TF-IDF with sublinear scaling
        vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=1,
            token_pattern=r"(?u)\b\w+\b",
        )

        try:
            tfidf_matrix = vectorizer.fit_transform(corpus)
            sim_matrix = cosine_similarity(tfidf_matrix)
            # Ensure similarity values are strictly clamped in [0.0, 1.0]
            np.clip(sim_matrix, 0.0, 1.0, out=sim_matrix)
            return sim_matrix
        except Exception:
            return np.zeros((len(incidents), len(incidents)))

    def build_graph(
        self,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        incidents: Optional[List[Dict[str, Any]]] = None,
    ) -> nx.Graph:
        """Build an undirected NetworkX graph from incident nodes and similarity edges."""
        threshold_val = self.validate_threshold(threshold)

        if incidents is None:
            incidents = self.load_incidents()

        G = nx.Graph()

        if len(incidents) < 2:
            # If 0 or 1 incident, populate nodes without edges
            for inc in incidents:
                G.add_node(str(inc.get("incident_id", "")), **{
                    "created_at": str(inc.get("created_at", "")),
                    "content_hash": str(inc.get("content_hash", "")),
                    "ai_label": str(inc.get("ai_label", "Human")),
                    "ai_probability": float(inc.get("ai_probability", 0.0)),
                    "threat_score": float(inc.get("threat_score", 0.0)),
                    "risk_level": str(inc.get("risk_level", "LOW")),
                    "category": str(inc.get("category", "Normal")),
                })
            return G

        # Add all nodes
        for inc in incidents:
            G.add_node(str(inc.get("incident_id", "")), **{
                "created_at": str(inc.get("created_at", "")),
                "content_hash": str(inc.get("content_hash", "")),
                "ai_label": str(inc.get("ai_label", "Human")),
                "ai_probability": float(inc.get("ai_probability", 0.0)),
                "threat_score": float(inc.get("threat_score", 0.0)),
                "risk_level": str(inc.get("risk_level", "LOW")),
                "category": str(inc.get("category", "Normal")),
            })

        # Calculate similarity matrix
        sim_matrix = self.build_similarity_matrix(incidents)
        n = len(incidents)

        # Populate relationship edges strictly for upper triangle (no self-edges, no duplicate pairs)
        for i in range(n):
            for j in range(i + 1, n):
                sim = float(sim_matrix[i, j])
                if sim >= threshold_val:
                    u = incidents[i]["incident_id"]
                    v = incidents[j]["incident_id"]
                    G.add_edge(u, v, similarity=round(sim, 4))

        return G

    def detect_clusters(self, graph: nx.Graph) -> List[Dict[str, Any]]:
        """Identify connected components (clusters of related incidents).

        Returns clusters with 2 or more connected incidents, ordered by size descending.
        """
        if graph.number_of_nodes() < 2 or graph.number_of_edges() == 0:
            return []

        # Find connected components containing at least 2 incidents
        components = [comp for comp in nx.connected_components(graph) if len(comp) >= 2]
        # Sort components by size descending, then deterministically by minimum incident ID
        components.sort(key=lambda c: (-len(c), sorted(list(c))[0]))

        clusters = []
        for idx, comp in enumerate(components):
            comp_nodes = sorted(list(comp))
            sub_G = graph.subgraph(comp)
            edge_sims = [d["similarity"] for u, v, d in sub_G.edges(data=True) if "similarity" in d]
            avg_sim = round(float(np.mean(edge_sims)), 4) if edge_sims else 0.0

            clusters.append({
                "cluster_id": f"CL-{idx + 1:03d}",
                "incident_count": len(comp_nodes),
                "incident_ids": comp_nodes,
                "average_similarity": avg_sim,
                "edge_count": sub_G.number_of_edges(),
            })

        return clusters

    def detect_campaigns(
        self,
        graph: nx.Graph,
        clusters: List[Dict[str, Any]],
        incidents_map: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Detect potential campaigns from connected clusters with >= 3 incidents."""
        campaign_candidates = [cl for cl in clusters if cl["incident_count"] >= self.MIN_CAMPAIGN_CLUSTER_SIZE]
        if not campaign_candidates:
            return []

        campaigns = []
        for cl in campaign_candidates:
            inc_ids = cl["incident_ids"]
            comp_incidents = [inc_map for inc_id in inc_ids if (inc_map := incidents_map.get(inc_id))]

            if len(comp_incidents) < self.MIN_CAMPAIGN_CLUSTER_SIZE:
                continue

            # Metrics
            avg_sim = float(cl["average_similarity"])
            cluster_cohesion = round(avg_sim * 100.0, 2)

            threat_scores = [inc["threat_score"] for inc in comp_incidents]
            avg_threat_score = round(float(np.mean(threat_scores)), 2)

            ai_probs = [inc["ai_probability"] for inc in comp_incidents]
            avg_ai_prob = round(float(np.mean(ai_probs)), 4)

            # Risk distribution & Highest risk level
            risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            highest_rank = 1
            highest_risk_label = "LOW"
            for inc in comp_incidents:
                r_lvl = inc["risk_level"]
                if r_lvl in risk_dist:
                    risk_dist[r_lvl] += 1
                rank = self.RISK_RANK.get(r_lvl, 1)
                if rank > highest_rank:
                    highest_rank = rank
                    highest_risk_label = r_lvl

            # Category distribution & Primary category
            cat_counts = Counter(inc["category"] for inc in comp_incidents)
            cat_dist = {cat: cat_counts.get(cat, 0) for cat in self.SUPPORTED_CATEGORIES}

            # Primary category: max frequency, tie-break alphabetically
            primary_cat = sorted(cat_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]

            # Timestamps
            created_dts = []
            for inc in comp_incidents:
                try:
                    dt = datetime.fromisoformat(inc["created_at"])
                    created_dts.append(dt)
                except Exception:
                    pass

            if created_dts:
                min_dt = min(created_dts)
                max_dt = max(created_dts)
                start_time = min_dt.isoformat()
                end_time = max_dt.isoformat()
                duration_hours = round(max(0.0, (max_dt - min_dt).total_seconds() / 3600.0), 2)
            else:
                start_time = comp_incidents[0]["created_at"]
                end_time = comp_incidents[-1]["created_at"]
                duration_hours = 0.0

            # Deterministic Campaign Risk Formula:
            # 50% Avg Threat Score + 30% Avg AI Prob (0-100) + 20% Cluster Cohesion (0-100)
            raw_campaign_risk = (0.50 * avg_threat_score) + (0.30 * (avg_ai_prob * 100.0)) + (0.20 * cluster_cohesion)
            campaign_risk_score = round(max(0.0, min(100.0, raw_campaign_risk)), 2)

            # Campaign Risk Level
            if campaign_risk_score >= 80.0:
                campaign_risk_level = "CRITICAL"
            elif campaign_risk_score >= 60.0:
                campaign_risk_level = "HIGH"
            elif campaign_risk_score >= 30.0:
                campaign_risk_level = "MEDIUM"
            else:
                campaign_risk_level = "LOW"

            campaigns.append({
                "cluster_id": cl["cluster_id"],
                "incident_count": len(inc_ids),
                "incident_ids": inc_ids,
                "average_similarity": avg_sim,
                "cluster_cohesion": cluster_cohesion,
                "average_threat_score": avg_threat_score,
                "average_ai_probability": avg_ai_prob,
                "campaign_risk_score": campaign_risk_score,
                "risk_level": campaign_risk_level,
                "highest_risk_level": highest_risk_label,
                "primary_category": primary_cat,
                "risk_distribution": risk_dist,
                "category_distribution": cat_dist,
                "start_time": start_time,
                "end_time": end_time,
                "duration_hours": duration_hours,
            })

        # Sort campaigns deterministically: highest risk score first, then earliest start_time
        campaigns.sort(key=lambda c: (-c["campaign_risk_score"], c["start_time"], c["incident_ids"][0]))

        # Assign deterministic campaign IDs: CAMP-001, CAMP-002, etc.
        for idx, camp in enumerate(campaigns):
            camp["campaign_id"] = f"CAMP-{idx + 1:03d}"

        return campaigns

    def get_graph_data(
        self,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        limit: int = DEFAULT_INCIDENTS_LIMIT,
    ) -> Dict[str, Any]:
        """Generate comprehensive, JSON-serializable graph structure, clusters, and campaigns for the top N incidents."""
        threshold_val = self.validate_threshold(threshold)
        incidents = self.load_incidents(limit=limit)
        incidents_map = {inc["incident_id"]: inc for inc in incidents}

        if len(incidents) < 2:
            return {
                "threshold": threshold_val,
                "nodes": [
                    {
                        "id": inc["incident_id"],
                        "created_at": inc["created_at"],
                        "content_hash": inc["content_hash"],
                        "ai_label": inc["ai_label"],
                        "ai_probability": inc["ai_probability"],
                        "threat_score": inc["threat_score"],
                        "risk_level": inc["risk_level"],
                        "category": inc["category"],
                    }
                    for inc in incidents
                ],
                "edges": [],
                "clusters": [],
                "campaigns": [],
                "summary": {
                    "incident_count": len(incidents),
                    "edge_count": 0,
                    "cluster_count": 0,
                    "campaign_count": 0,
                },
            }

        graph = self.build_graph(threshold=threshold_val, incidents=incidents)
        clusters = self.detect_clusters(graph)
        campaigns = self.detect_campaigns(graph, clusters, incidents_map)

        # Format Nodes (without heavy raw content)
        nodes = []
        for node_id, data in graph.nodes(data=True):
            nodes.append({
                "id": str(node_id),
                "created_at": str(data.get("created_at", "")),
                "content_hash": str(data.get("content_hash", "")),
                "ai_label": str(data.get("ai_label", "Human")),
                "ai_probability": float(data.get("ai_probability", 0.0)),
                "threat_score": float(data.get("threat_score", 0.0)),
                "risk_level": str(data.get("risk_level", "LOW")),
                "category": str(data.get("category", "Normal")),
            })

        # Format Edges
        edges = []
        for u, v, data in graph.edges(data=True):
            edges.append({
                "source": str(u),
                "target": str(v),
                "similarity": float(data.get("similarity", 0.0)),
            })

        return {
            "threshold": threshold_val,
            "nodes": nodes,
            "edges": edges,
            "clusters": clusters,
            "campaigns": campaigns,
            "summary": {
                "incident_count": len(nodes),
                "edge_count": len(edges),
                "cluster_count": len(clusters),
                "campaign_count": len(campaigns),
            },
        }

    def get_campaigns_list(
        self,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        limit: int = DEFAULT_INCIDENTS_LIMIT,
    ) -> List[Dict[str, Any]]:
        """Retrieve detected potential campaigns for a given threshold and incident limit."""
        graph_data = self.get_graph_data(threshold=threshold, limit=limit)
        return graph_data["campaigns"]

    def get_campaign_by_id(
        self,
        campaign_id: str,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        limit: int = DEFAULT_INCIDENTS_LIMIT,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve single campaign summary by its deterministic campaign ID."""
        if not campaign_id or not isinstance(campaign_id, str):
            return None

        clean_id = campaign_id.strip().upper()
        campaigns = self.get_campaigns_list(threshold=threshold, limit=limit)

        for camp in campaigns:
            if camp["campaign_id"].upper() == clean_id:
                return camp

        return None
