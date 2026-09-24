import json
from pathlib import Path
import numpy as np
import pytest
import torch

from app import create_app
from database.db import db_session, init_db
from gnn import (
    GNNFeatureBuilder,
    GNNGraphDataset,
    GNNPredictor,
    GNNTrainer,
    GraphSAGEClassifier,
)
from models.detector import AIDetector
from services.forensic_service import ForensicService
from services.gnn_service import GNNThreatService
from services.graph_service import ThreatGraphService


@pytest.fixture
def test_client(tmp_path):
    """Provide a Flask test client with an isolated temporary SQLite database."""
    db_file = tmp_path / "test_api_gnn.db"
    init_db(db_file)

    model_path = Path("models/detector_model.joblib").resolve()
    dataset_path = Path("data/dataset.csv").resolve()
    detector = AIDetector(model_path=model_path, dataset_path=dataset_path)
    if detector.model_exists():
        detector.load_model()
    else:
        detector.train(save_model=False)

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_file,
        "DETECTOR": detector,
    })

    with app.test_client() as client:
        yield client


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary database path for isolated GNN tests."""
    db_file = tmp_path / "test_gnn.db"
    init_db(db_file)
    return db_file


@pytest.fixture
def forensic_srv(temp_db_path):
    """Provide a ForensicService connected to the temporary database."""
    return ForensicService(db_path=temp_db_path)


@pytest.fixture
def graph_srv(temp_db_path):
    """Provide a ThreatGraphService connected to the temporary database."""
    return ThreatGraphService(db_path=temp_db_path)


@pytest.fixture
def gnn_paths(tmp_path):
    """Provide temporary model and metadata file paths."""
    model_file = tmp_path / "gnn_model.pt"
    meta_file = tmp_path / "gnn_meta.json"
    return model_file, meta_file


@pytest.fixture
def populated_gnn_db(forensic_srv, graph_srv):
    """Populate database with 4 highly similar phishing incidents and 4 unrelated normal incidents (8 total)."""
    # 4 highly similar phishing incidents (cluster)
    phish_variants = [
        "CRITICAL ALERT: Unauthorized bank access detected on your account. Verify your banking credentials immediately.",
        "CRITICAL ALERT: Unauthorized bank access detected on your account. Verify your banking credentials immediately today.",
        "CRITICAL ALERT: Unauthorized bank access detected on your account. Verify your banking credentials immediately now.",
        "CRITICAL ALERT: Unauthorized bank access detected on your account. Verify your banking credentials immediately online.",
    ]

    for idx, text in enumerate(phish_variants):
        forensic_srv.create_incident(
            content=text,
            prediction={"label": "AI-generated", "ai_probability": 0.90, "human_probability": 0.10, "confidence": 0.90},
            text_analysis={"character_count": len(text), "word_count": len(text.split()), "sentence_count": 2, "avg_word_length": 5.2, "avg_sentence_length": 12.0, "vocabulary_richness": 0.75},
            threat_analysis={
                "threat_score": 85.0,
                "risk_level": "CRITICAL",
                "category": "Phishing",
                "indicators": [{"type": "urgency", "severity": "high", "count": 2, "description": "Urgency"}],
                "reasons": ["Urgency detected"],
                "component_scores": {"ai_likelihood": 90.0, "urgency": 85.0, "manipulation": 80.0, "cta": 90.0, "unverified_claims": 50.0, "authority_patterns": 70.0},
            },
        )

    # 4 completely unrelated normal incidents
    normal_texts = [
        "The local botanical gardens will host an orchid and bonsai tree showcase this weekend.",
        "A practical guide to baking homemade sourdough bread using ancient wheat grains.",
        "Astronomers discover a new exoplanet with potential atmospheric water vapor signatures.",
        "Urban planning initiatives focus on expanding cycling infrastructure and pedestrian parks.",
    ]

    for text in normal_texts:
        forensic_srv.create_incident(
            content=text,
            prediction={"label": "Human", "ai_probability": 0.05, "human_probability": 0.95, "confidence": 0.95},
            text_analysis={"character_count": len(text), "word_count": len(text.split()), "sentence_count": 1, "avg_word_length": 5.0, "avg_sentence_length": 15.0, "vocabulary_richness": 0.90},
            threat_analysis={
                "threat_score": 10.0,
                "risk_level": "LOW",
                "category": "Normal",
                "indicators": [],
                "reasons": ["No indicators"],
                "component_scores": {"ai_likelihood": 5.0, "urgency": 0.0, "manipulation": 0.0, "cta": 0.0, "unverified_claims": 0.0, "authority_patterns": 0.0},
            },
        )

    return graph_srv


# -----------------------------------------------------------------------------
# 1. Dependency & Environment Tests
# -----------------------------------------------------------------------------

def test_gnn_dependency_availability():
    """Verify PyTorch and PyTorch Geometric SAGEConv and Data are importable on CPU."""
    assert torch is not None
    from torch_geometric.nn import SAGEConv
    from torch_geometric.data import Data
    assert SAGEConv is not None
    assert Data is not None


# -----------------------------------------------------------------------------
# 2. Feature Builder Tests
# -----------------------------------------------------------------------------

def test_feature_builder_dimension_and_schema():
    """Verify feature builder produces exact 30-dim vector and deterministic schema."""
    schema = GNNFeatureBuilder.get_feature_schema()
    assert schema["feature_dim"] == 30
    assert len(schema["feature_order"]) == 30
    assert "cat_Normal" in schema["feature_order"]
    assert "risk_CRITICAL" in schema["feature_order"]
    assert "label_AI-generated" in schema["feature_order"]


def test_categorical_one_hot_encodings():
    """Verify categorical features use exact one-hot vectors."""
    incident = {
        "incident_id": "INC-001",
        "category": "Phishing",
        "risk_level": "HIGH",
        "ai_label": "AI-generated",
        "ai_probability": 0.85,
        "threat_score": 75.0,
    }
    vec = GNNFeatureBuilder.extract_node_features(incident)
    assert len(vec) == 30

    # Phishing is 2nd in CATEGORIES (index 17 + 1 = 18 in vector)
    cat_start = 17
    assert vec[cat_start + 1] == 1.0  # cat_Phishing
    assert sum(vec[cat_start : cat_start + 7]) == 1.0  # Exactly one category active

    # HIGH is 3rd in RISK_LEVELS (index 24 + 2 = 26 in vector)
    risk_start = 24
    assert vec[risk_start + 2] == 1.0  # risk_HIGH
    assert sum(vec[risk_start : risk_start + 4]) == 1.0

    # AI-generated is 2nd in AI_LABELS (index 28 + 1 = 29 in vector)
    label_start = 28
    assert vec[label_start + 1] == 1.0  # label_AI-generated
    assert sum(vec[label_start : label_start + 2]) == 1.0


def test_zero_target_leakage_in_features():
    """Verify that cluster IDs, campaign IDs, or weak labels are excluded from features."""
    incident = {
        "incident_id": "INC-LEAK-TEST",
        "cluster_id": "CL-001",
        "campaign_id": "CAMP-001",
        "is_campaign": True,
        "label": 1.0,
        "threat_score": 90.0,
    }
    vec = GNNFeatureBuilder.extract_node_features(incident)
    schema = GNNFeatureBuilder.get_feature_schema()
    for name in schema["feature_order"]:
        assert "cluster" not in name.lower()
        assert "campaign" not in name.lower()
        assert "target" not in name.lower()
    assert len(vec) == 30


def test_feature_values_bounded():
    """Verify continuous features are strictly bounded within [0.0, 1.0]."""
    incident = {
        "incident_id": "INC-BOUNDS",
        "ai_probability": 1.5,  # Unclamped input
        "threat_score": 150.0,  # Unclamped input
        "text_analysis": json.dumps({"word_count": 5000, "sentence_count": 200, "vocabulary_richness": 1.0}),
        "component_scores": json.dumps({"urgency": 100.0, "manipulation": 100.0}),
    }
    vec = GNNFeatureBuilder.extract_node_features(incident)
    assert np.all(vec >= 0.0)
    assert np.all(vec <= 1.0)


# -----------------------------------------------------------------------------
# 3. Dataset & Weak Supervision Tests
# -----------------------------------------------------------------------------

def test_graph_dataset_empty():
    """Verify dataset conversion on 0 incidents returns empty Data."""
    data = GNNGraphDataset.from_networkx(None, [], generate_labels=True)
    assert data.num_nodes == 0
    assert data.x.shape == (0, 30)
    assert data.edge_index.shape == (2, 0)
    assert len(data.y) == 0


def test_weak_label_generation_heuristics(populated_gnn_db):
    """Verify connected components >= 3 with similarity >= threshold get weak label 1.0."""
    graph_srv = populated_gnn_db
    incidents = graph_srv.load_incidents()
    graph = graph_srv.build_graph(threshold=0.65, incidents=incidents)

    data = GNNGraphDataset.from_networkx(graph, incidents, generate_labels=True, threshold=0.65)
    assert data.num_nodes == 8
    assert data.label_meta["label_source"] == "module5_weak_supervision"
    assert data.label_meta["positive_count"] == 4
    assert data.label_meta["negative_count"] == 4

    phishing_ids = {inc["incident_id"] for inc in incidents if inc["category"] == "Phishing"}
    for idx, inc_id in enumerate(data.node_ids):
        if inc_id in phishing_ids:
            assert data.y[idx].item() == 1.0
        else:
            assert data.y[idx].item() == 0.0


# -----------------------------------------------------------------------------
# 4. Model Architecture Tests
# -----------------------------------------------------------------------------

def test_graphsage_model_forward_and_shapes():
    """Verify GraphSAGEClassifier computes raw logits and sigmoid probabilities on CPU."""
    model = GraphSAGEClassifier(in_channels=30, hidden_dim=16, dropout_p=0.1)
    x = torch.randn(5, 30)
    edge_index = torch.tensor([[0, 1, 2, 3], [1, 0, 3, 2]], dtype=torch.long)

    # Forward returns raw logits
    logits = model(x, edge_index)
    assert logits.shape == (5,)

    # predict_proba returns sigmoid probabilities in [0, 1]
    probs = model.predict_proba(x, edge_index)
    assert probs.shape == (5,)
    assert (probs >= 0.0).all() and (probs <= 1.0).all()


# -----------------------------------------------------------------------------
# 5. Trainer & Small-Data Safety Tests
# -----------------------------------------------------------------------------

def test_trainer_insufficient_data_node_count(gnn_paths):
    """Verify training with fewer than min_train_nodes (6) returns INSUFFICIENT_DATA."""
    model_path, meta_path = gnn_paths
    trainer = GNNTrainer(model_path=model_path, metadata_path=meta_path, min_train_nodes=6)

    # Only 3 incidents
    incidents = [{"incident_id": f"INC-{i}", "content": f"Text {i}"} for i in range(3)]
    res = trainer.train(graph=None, incidents=incidents)
    assert res["training_status"] == "INSUFFICIENT_DATA"
    assert "required for GNN training" in res["message"]
    assert not model_path.exists()


def test_trainer_insufficient_data_class_imbalance(gnn_paths):
    """Verify training when all nodes have identical weak labels returns INSUFFICIENT_DATA."""
    model_path, meta_path = gnn_paths
    trainer = GNNTrainer(model_path=model_path, metadata_path=meta_path, min_train_nodes=6)

    # 6 isolated incidents with 0 edges -> all get label 0.0
    incidents = [
        {
            "incident_id": f"INC-ISO-{i}",
            "created_at": "2026-08-18T00:00:00Z",
            "content": f"Completely unique topic number {i} about unrelated astronomy and chemistry.",
            "content_hash": f"hash_{i}",
            "ai_label": "Human",
            "ai_probability": 0.1,
            "threat_score": 10.0,
            "risk_level": "LOW",
            "category": "Normal",
        }
        for i in range(6)
    ]
    graph = ThreatGraphService().build_graph(threshold=0.65, incidents=incidents)
    res = trainer.train(graph=graph, incidents=incidents)
    assert res["training_status"] == "INSUFFICIENT_DATA"
    assert "class diversity" in res["message"]


def test_trainer_successful_training_and_persistence(populated_gnn_db, gnn_paths):
    """Verify trainer trains successfully on 8-node dataset and persists .pt and .json files."""
    model_path, meta_path = gnn_paths
    graph_srv = populated_gnn_db
    incidents = graph_srv.load_incidents()
    graph = graph_srv.build_graph(threshold=0.65, incidents=incidents)

    trainer = GNNTrainer(
        model_path=model_path,
        metadata_path=meta_path,
        hidden_dim=16,
        epochs=30,
        random_seed=42,
        min_train_nodes=6,
    )
    result = trainer.train(graph=graph, incidents=incidents, similarity_threshold=0.65)

    assert result["training_status"] == "READY"
    assert result["training_node_count"] == 8
    assert result["label_source"] == "module5_weak_supervision"
    assert model_path.exists()
    assert meta_path.exists()

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["model_version"] == "1.0.0"
    assert meta["feature_schema"]["feature_dim"] == 30


# -----------------------------------------------------------------------------
# 6. Predictor & Reload Parity Tests
# -----------------------------------------------------------------------------

def test_predictor_model_reload_parity(populated_gnn_db, gnn_paths):
    """Verify loaded model produces deterministic predictions matching in-memory output."""
    model_path, meta_path = gnn_paths
    graph_srv = populated_gnn_db
    incidents = graph_srv.load_incidents()
    graph = graph_srv.build_graph(threshold=0.65, incidents=incidents)

    trainer = GNNTrainer(
        model_path=model_path,
        metadata_path=meta_path,
        hidden_dim=16,
        epochs=20,
        random_seed=42,
    )
    trainer.train(graph=graph, incidents=incidents)

    predictor1 = GNNPredictor(model_path=model_path, metadata_path=meta_path)
    res1 = predictor1.predict(graph=graph, incidents=incidents)

    predictor2 = GNNPredictor(model_path=model_path, metadata_path=meta_path)
    res2 = predictor2.predict(graph=graph, incidents=incidents)

    assert res1["status"] == "READY"
    assert len(res1["predictions"]) == 8
    assert len(res2["predictions"]) == 8

    # Check numerical parity across predictions
    probs1 = [p["cluster_membership_probability"] for p in res1["predictions"]]
    probs2 = [p["cluster_membership_probability"] for p in res2["predictions"]]
    for p1, p2 in zip(probs1, probs2):
        assert abs(p1 - p2) < 1e-5


def test_predictor_probability_classification_bands():
    """Verify classification thresholds: <0.40 LOW, 0.40-0.69 POSSIBLE, >=0.70 HIGH."""
    assert GNNPredictor.classify_probability(0.85) == "HIGH_LIKELIHOOD"
    assert GNNPredictor.classify_probability(0.70) == "HIGH_LIKELIHOOD"
    assert GNNPredictor.classify_probability(0.69) == "POSSIBLE"
    assert GNNPredictor.classify_probability(0.40) == "POSSIBLE"
    assert GNNPredictor.classify_probability(0.39) == "LOW_LIKELIHOOD"
    assert GNNPredictor.classify_probability(0.05) == "LOW_LIKELIHOOD"


def test_predictor_graph_explanations(populated_gnn_db, gnn_paths):
    """Verify each prediction includes graph explanation context."""
    model_path, meta_path = gnn_paths
    graph_srv = populated_gnn_db
    incidents = graph_srv.load_incidents()
    graph = graph_srv.build_graph(threshold=0.65, incidents=incidents)

    trainer = GNNTrainer(model_path=model_path, metadata_path=meta_path, epochs=15)
    trainer.train(graph=graph, incidents=incidents)

    predictor = GNNPredictor(model_path=model_path, metadata_path=meta_path)
    res = predictor.predict(graph=graph, incidents=incidents)

    for pred in res["predictions"]:
        exp = pred["explanation"]
        assert "neighbor_count" in exp
        assert "average_neighbor_similarity" in exp
        assert "cluster_size" in exp
        assert "average_neighbor_threat_score" in exp
        assert exp["cluster_size"] >= 1


# -----------------------------------------------------------------------------
# 7. Service & Thread-Safety Tests
# -----------------------------------------------------------------------------

def test_gnn_service_methods(temp_db_path, gnn_paths):
    """Verify GNNThreatService get_status, train, and predict methods."""
    model_path, meta_path = gnn_paths
    service = GNNThreatService(
        db_path=temp_db_path,
        model_path=model_path,
        metadata_path=meta_path,
        min_train_nodes=6,
    )

    # Empty DB
    status = service.get_status()
    assert status["status"] == "INSUFFICIENT_DATA"
    assert status["has_model"] is False

    # Predict without training
    pred_res = service.predict()
    assert pred_res["status"] == "NO_DATA"


# -----------------------------------------------------------------------------
# 8. REST API Endpoint Tests
# -----------------------------------------------------------------------------

def test_api_gnn_status_endpoint(test_client):
    """Test GET /api/gnn/status returns HTTP 200 with status fields."""
    resp = test_client.get("/api/gnn/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "training_status" in data
    assert "has_model" in data
    assert "model_version" in data


def test_api_gnn_train_endpoint(test_client):
    """Test POST /api/gnn/train triggers training route."""
    resp = test_client.post("/api/gnn/train", json={"threshold": 0.65})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "training_status" in data


def test_api_gnn_predictions_endpoint(test_client):
    """Test GET /api/gnn/predictions returns structured prediction response."""
    resp = test_client.get("/api/gnn/predictions?threshold=0.65")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "status" in data
    assert "predictions" in data


def test_api_gnn_analyze_endpoint(test_client):
    """Test POST /api/gnn/analyze returns inference results."""
    resp = test_client.post("/api/gnn/analyze", json={"threshold": 0.65})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "predictions" in data


def test_gnn_service_thread_safe_lock(temp_db_path, gnn_paths):
    """Verify concurrent training invocations are rejected with conflict error."""
    model_path, meta_path = gnn_paths
    service = GNNThreatService(
        db_path=temp_db_path,
        model_path=model_path,
        metadata_path=meta_path,
        min_train_nodes=6,
    )

    # Acquire lock directly to simulate active training in background
    assert service._training_lock.acquire(blocking=False)
    service._is_training = True

    try:
        # Concurrent training attempt must fail safely
        res = service.train()
        assert res["success"] is False
        assert res["training_status"] == "TRAINING"
        assert "already in progress" in res["error"]
    finally:
        service._is_training = False
        service._training_lock.release()


def test_controlled_fixture_training_and_inference(populated_gnn_db, gnn_paths):
    """Verify controlled fixture training: probabilities in [0,1], all nodes predicted, positive weak-label nodes have higher mean probability than negative nodes."""
    model_path, meta_path = gnn_paths
    graph_srv = populated_gnn_db
    incidents = graph_srv.load_incidents()
    graph = graph_srv.build_graph(threshold=0.65, incidents=incidents)

    trainer = GNNTrainer(
        model_path=model_path,
        metadata_path=meta_path,
        hidden_dim=16,
        epochs=40,
        random_seed=42,
    )
    train_res = trainer.train(graph=graph, incidents=incidents, similarity_threshold=0.65)
    assert train_res["training_status"] == "READY"

    predictor = GNNPredictor(model_path=model_path, metadata_path=meta_path)
    pred_res = predictor.predict(graph=graph, incidents=incidents)

    assert pred_res["status"] == "READY"
    assert len(pred_res["predictions"]) == 8

    phishing_ids = {inc["incident_id"] for inc in incidents if inc["category"] == "Phishing"}
    normal_ids = {inc["incident_id"] for inc in incidents if inc["category"] == "Normal"}

    pos_probs = []
    neg_probs = []

    for pred in pred_res["predictions"]:
        p_val = pred["cluster_membership_probability"]
        assert 0.0 <= p_val <= 1.0
        if pred["incident_id"] in phishing_ids:
            pos_probs.append(p_val)
        elif pred["incident_id"] in normal_ids:
            neg_probs.append(p_val)

    assert len(pos_probs) == 4
    assert len(neg_probs) == 4
    # The learned GraphSAGE model must assign higher average cluster probability to connected phishing nodes than isolated normal nodes
    assert np.mean(pos_probs) > np.mean(neg_probs)
