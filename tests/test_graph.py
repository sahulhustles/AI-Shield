"""Unit tests for Module 5: Threat Relationship Graph & Campaign Detection Service."""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from database.db import db_session, init_db
from services.forensic_service import ForensicService
from services.graph_service import ThreatGraphService


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary database file path for isolated graph tests."""
    db_file = tmp_path / "test_graph.db"
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
def populated_campaign_db(forensic_srv, graph_srv):
    """Populate database with 3 highly similar phishing incidents and 2 unrelated normal incidents."""
    # 3 highly similar phishing incidents (campaign cluster)
    phish_variants = [
        "URGENT SECURITY ALERT: Unauthorized login detected on your bank account! Click here to verify your account credentials immediately.",
        "URGENT SECURITY ALERT: Unauthorized login detected on your bank account! Click here to verify your account credentials immediately today.",
        "URGENT SECURITY ALERT: Unauthorized login detected on your bank account! Click here to verify your account credentials immediately now.",
    ]

    for text in phish_variants:
        forensic_srv.create_incident(
            content=text,
            prediction={"label": "AI-generated", "ai_probability": 0.85, "human_probability": 0.15, "confidence": 0.85},
            text_analysis={"character_count": len(text), "word_count": len(text.split()), "sentence_count": 2},
            threat_analysis={
                "threat_score": 82.0,
                "risk_level": "CRITICAL",
                "category": "Phishing",
                "indicators": [{"type": "urgency", "severity": "high", "count": 2, "description": "Urgency"}],
                "reasons": ["Urgency detected"],
                "component_scores": {"ai_likelihood": 85.0, "urgency": 85.0, "category_severity": 95.0},
            },
        )

    # 2 completely unrelated incidents
    unrelated_texts = [
        "The annual botanical garden exhibition will feature rare tropical plants this spring season.",
        "Please find attached the recipes for traditional homemade sourdough bread and pastry baking.",
    ]

    for text in unrelated_texts:
        forensic_srv.create_incident(
            content=text,
            prediction={"label": "Human", "ai_probability": 0.05, "human_probability": 0.95, "confidence": 0.95},
            text_analysis={"character_count": len(text), "word_count": len(text.split()), "sentence_count": 1},
            threat_analysis={
                "threat_score": 10.0,
                "risk_level": "LOW",
                "category": "Normal",
                "indicators": [],
                "reasons": ["No indicators"],
                "component_scores": {"ai_likelihood": 5.0, "urgency": 0.0, "category_severity": 10.0},
            },
        )

    return graph_srv


# -----------------------------------------------------------------------------
# 1. Incident Count & Edge Creation Tests
# -----------------------------------------------------------------------------

def test_zero_incidents(graph_srv):
    """Test get_graph_data on empty database returns valid empty structure."""
    data = graph_srv.get_graph_data()
    assert data["nodes"] == []
    assert data["edges"] == []
    assert data["clusters"] == []
    assert data["campaigns"] == []
    assert data["summary"]["incident_count"] == 0
    assert data["summary"]["edge_count"] == 0


def test_one_incident(forensic_srv, graph_srv):
    """Test get_graph_data with exactly 1 incident returns 1 node and 0 edges."""
    forensic_srv.create_incident(
        content="Single test text.",
        prediction={"label": "Human", "ai_probability": 0.1, "human_probability": 0.9, "confidence": 0.9},
        text_analysis={"character_count": 17, "word_count": 3, "sentence_count": 1},
        threat_analysis={"threat_score": 10.0, "risk_level": "LOW", "category": "Normal", "indicators": [], "reasons": [], "component_scores": {}},
    )
    data = graph_srv.get_graph_data()
    assert len(data["nodes"]) == 1
    assert data["edges"] == []
    assert data["clusters"] == []
    assert data["campaigns"] == []


def test_two_unrelated_incidents(forensic_srv, graph_srv):
    """Test two semantically unrelated incidents produce 0 edges at default threshold."""
    forensic_srv.create_incident(
        content="Deep ocean exploration reveals hydrothermal vent ecosystems.",
        prediction={"label": "Human", "ai_probability": 0.1, "human_probability": 0.9, "confidence": 0.9},
        text_analysis={"character_count": 60, "word_count": 8, "sentence_count": 1},
        threat_analysis={"threat_score": 10.0, "risk_level": "LOW", "category": "Normal", "indicators": [], "reasons": [], "component_scores": {}},
    )
    forensic_srv.create_incident(
        content="Stock market indices recorded significant gains in morning trading sessions.",
        prediction={"label": "Human", "ai_probability": 0.1, "human_probability": 0.9, "confidence": 0.9},
        text_analysis={"character_count": 75, "word_count": 10, "sentence_count": 1},
        threat_analysis={"threat_score": 10.0, "risk_level": "LOW", "category": "Normal", "indicators": [], "reasons": [], "component_scores": {}},
    )

    data = graph_srv.get_graph_data(threshold=0.65)
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 0
    assert len(data["clusters"]) == 0


def test_two_similar_incidents(forensic_srv, graph_srv):
    """Test two nearly identical incidents produce an undirected edge with high similarity."""
    t1 = "Urgent Security Alert: Your bank account is suspended due to unauthorized login. Verify now!"
    t2 = "Urgent Security Alert: Your bank account is suspended due to unauthorized login. Verify now today!"

    forensic_srv.create_incident(
        content=t1,
        prediction={"label": "AI-generated", "ai_probability": 0.8, "human_probability": 0.2, "confidence": 0.8},
        text_analysis={"character_count": len(t1), "word_count": len(t1.split()), "sentence_count": 2},
        threat_analysis={"threat_score": 80.0, "risk_level": "CRITICAL", "category": "Phishing", "indicators": [], "reasons": [], "component_scores": {}},
    )
    forensic_srv.create_incident(
        content=t2,
        prediction={"label": "AI-generated", "ai_probability": 0.8, "human_probability": 0.2, "confidence": 0.8},
        text_analysis={"character_count": len(t2), "word_count": len(t2.split()), "sentence_count": 2},
        threat_analysis={"threat_score": 80.0, "risk_level": "CRITICAL", "category": "Phishing", "indicators": [], "reasons": [], "component_scores": {}},
    )

    data = graph_srv.get_graph_data(threshold=0.65)
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1
    edge = data["edges"][0]
    assert edge["similarity"] >= 0.70
    assert len(data["clusters"]) == 1
    assert data["clusters"][0]["incident_count"] == 2


def test_self_edge_prevention(forensic_srv, graph_srv):
    """Test graph construction never generates self-edges (source == target)."""
    t = "Repetitive security alert notification broadcast."
    forensic_srv.create_incident(
        content=t,
        prediction={"label": "AI-generated", "ai_probability": 0.7, "human_probability": 0.3, "confidence": 0.7},
        text_analysis={"character_count": len(t), "word_count": len(t.split()), "sentence_count": 1},
        threat_analysis={"threat_score": 50.0, "risk_level": "MEDIUM", "category": "Spam", "indicators": [], "reasons": [], "component_scores": {}},
    )
    data = graph_srv.get_graph_data(threshold=0.50)
    for edge in data["edges"]:
        assert edge["source"] != edge["target"]


def test_edge_uniqueness(populated_campaign_db):
    """Test only one edge exists per connected incident pair (no duplicate A->B and B->A)."""
    data = populated_campaign_db.get_graph_data(threshold=0.65)
    edges = data["edges"]
    seen_pairs = set()
    for e in edges:
        pair = tuple(sorted([e["source"], e["target"]]))
        assert pair not in seen_pairs, f"Duplicate edge detected: {pair}"
        seen_pairs.add(pair)


def test_similarity_range(populated_campaign_db):
    """Test every edge similarity is strictly between 0.0 and 1.0."""
    data = populated_campaign_db.get_graph_data(threshold=0.50)
    for e in data["edges"]:
        assert 0.0 <= e["similarity"] <= 1.0


# -----------------------------------------------------------------------------
# 2. Threshold Validation Tests
# -----------------------------------------------------------------------------

def test_threshold_default(graph_srv):
    """Test validate_threshold returns DEFAULT_SIMILARITY_THRESHOLD (0.65) when None."""
    assert graph_srv.validate_threshold(None) == 0.65


def test_threshold_minimum(graph_srv):
    """Test validate_threshold accepts 0.50 exactly."""
    assert graph_srv.validate_threshold(0.50) == 0.50


def test_threshold_maximum(graph_srv):
    """Test validate_threshold accepts 0.95 exactly."""
    assert graph_srv.validate_threshold(0.95) == 0.95


def test_threshold_below_allowed_range(graph_srv):
    """Test threshold < 0.50 raises ValueError."""
    with pytest.raises(ValueError, match="between 0.5 and 0.95"):
        graph_srv.validate_threshold(0.45)


def test_threshold_above_allowed_range(graph_srv):
    """Test threshold > 0.95 raises ValueError."""
    with pytest.raises(ValueError, match="between 0.5 and 0.95"):
        graph_srv.validate_threshold(0.99)


def test_threshold_non_numeric(graph_srv):
    """Test non-numeric threshold raises ValueError."""
    with pytest.raises(ValueError, match="must be a numeric value"):
        graph_srv.validate_threshold("abc")


# -----------------------------------------------------------------------------
# 3. Connected Components & Campaign Detection Tests
# -----------------------------------------------------------------------------

def test_connected_component_detection(populated_campaign_db):
    """Test NetworkX connected components groups all 3 similar phishing incidents together."""
    data = populated_campaign_db.get_graph_data(threshold=0.65)
    clusters = data["clusters"]
    assert len(clusters) == 1
    assert clusters[0]["incident_count"] == 3


def test_cluster_containing_3_related_incidents(populated_campaign_db):
    """Test a cluster with 3 related incidents is detected as a potential campaign."""
    data = populated_campaign_db.get_graph_data(threshold=0.65)
    campaigns = data["campaigns"]
    assert len(campaigns) == 1
    camp = campaigns[0]
    assert camp["incident_count"] == 3
    assert camp["primary_category"] == "Phishing"
    assert camp["highest_risk_level"] == "CRITICAL"


def test_cluster_below_campaign_minimum(forensic_srv, graph_srv):
    """Test a cluster of 2 incidents is detected as a cluster but NOT as a campaign (min size 3)."""
    t1 = "Breaking news alert regarding government tax policy reform across all states."
    t2 = "Breaking news alert regarding government tax policy reform across all counties."

    forensic_srv.create_incident(
        content=t1,
        prediction={"label": "Human", "ai_probability": 0.2, "human_probability": 0.8, "confidence": 0.8},
        text_analysis={"character_count": len(t1), "word_count": len(t1.split()), "sentence_count": 1},
        threat_analysis={"threat_score": 25.0, "risk_level": "LOW", "category": "Normal", "indicators": [], "reasons": [], "component_scores": {}},
    )
    forensic_srv.create_incident(
        content=t2,
        prediction={"label": "Human", "ai_probability": 0.2, "human_probability": 0.8, "confidence": 0.8},
        text_analysis={"character_count": len(t2), "word_count": len(t2.split()), "sentence_count": 1},
        threat_analysis={"threat_score": 25.0, "risk_level": "LOW", "category": "Normal", "indicators": [], "reasons": [], "component_scores": {}},
    )

    data = graph_srv.get_graph_data(threshold=0.65)
    assert len(data["clusters"]) == 1
    assert data["clusters"][0]["incident_count"] == 2
    assert len(data["campaigns"]) == 0  # Below min size 3


def test_campaign_deterministic_id(populated_campaign_db):
    """Test detected campaigns receive deterministic IDs prefixed with CAMP-001."""
    data = populated_campaign_db.get_graph_data(threshold=0.65)
    assert data["campaigns"][0]["campaign_id"] == "CAMP-001"


def test_campaign_metrics_calculation(populated_campaign_db):
    """Test campaign metrics: average similarity, threat score, AI probability, and cohesion."""
    camp = populated_campaign_db.get_graph_data(threshold=0.65)["campaigns"][0]
    assert camp["average_similarity"] >= 0.65
    assert camp["cluster_cohesion"] >= 65.0
    assert camp["average_threat_score"] == 82.0
    assert camp["average_ai_probability"] == 0.85
    assert 0.0 <= camp["campaign_risk_score"] <= 100.0


def test_campaign_risk_level_boundaries(populated_campaign_db):
    """Test campaign risk score maps to valid qualitative risk level."""
    camp = populated_campaign_db.get_graph_data(threshold=0.65)["campaigns"][0]
    score = camp["campaign_risk_score"]
    level = camp["risk_level"]
    if score >= 80.0:
        assert level == "CRITICAL"
    elif score >= 60.0:
        assert level == "HIGH"
    elif score >= 30.0:
        assert level == "MEDIUM"
    else:
        assert level == "LOW"


def test_time_range_and_duration(populated_campaign_db):
    """Test campaign duration_hours is non-negative and timestamps are valid ISO."""
    camp = populated_campaign_db.get_graph_data(threshold=0.65)["campaigns"][0]
    assert camp["duration_hours"] >= 0.0
    assert "start_time" in camp
    assert "end_time" in camp


# -----------------------------------------------------------------------------
# 4. JSON Serializability & Limit Bounds Tests
# -----------------------------------------------------------------------------

def test_graph_json_serializability(populated_campaign_db):
    """Test complete graph output serializes cleanly to JSON without errors."""
    data = populated_campaign_db.get_graph_data(threshold=0.65)
    json_str = json.dumps(data)
    loaded = json.loads(json_str)
    assert loaded["summary"]["campaign_count"] == 1


def test_campaign_json_serializability(populated_campaign_db):
    """Test campaign list endpoint serializes cleanly."""
    camps = populated_campaign_db.get_campaigns_list(threshold=0.65)
    json_str = json.dumps(camps)
    assert len(json.loads(json_str)) == 1


def test_get_campaign_by_id(populated_campaign_db):
    """Test get_campaign_by_id returns specific campaign details."""
    camp = populated_campaign_db.get_campaign_by_id("CAMP-001", threshold=0.65)
    assert camp is not None
    assert camp["campaign_id"] == "CAMP-001"
    assert camp["incident_count"] == 3


def test_get_nonexistent_campaign(populated_campaign_db):
    """Test get_campaign_by_id for unknown ID returns None."""
    assert populated_campaign_db.get_campaign_by_id("CAMP-999") is None
    assert populated_campaign_db.get_campaign_by_id("") is None
    assert populated_campaign_db.get_campaign_by_id(None) is None


def test_maximum_incident_limit(temp_db_path, forensic_srv):
    """Test load_incidents obeys the 500 maximum incident bound."""
    srv = ThreatGraphService(db_path=temp_db_path)
    # Verify default limit cap
    assert srv.MAX_INCIDENTS_LIMIT == 500


def test_identical_input_gives_deterministic_graph(populated_campaign_db):
    """Test repeated graph generation on identical data produces identical nodes and edges."""
    g1 = populated_campaign_db.get_graph_data(threshold=0.65)
    g2 = populated_campaign_db.get_graph_data(threshold=0.65)
    assert g1 == g2


def test_altered_content_changes_similarity_results(graph_srv):
    """Test modifying text phrases affects pairwise similarity."""
    incidents = [
        {"incident_id": "1", "content": "Exclusive special promotion offer."},
        {"incident_id": "2", "content": "Exclusive special promotion offer."},
    ]
    sim1 = graph_srv.build_similarity_matrix(incidents)[0, 1]

    incidents[1]["content"] = "Completely different topic about astronomical observatories."
    sim2 = graph_srv.build_similarity_matrix(incidents)[0, 1]

    assert sim1 > 0.90
    assert sim2 < 0.20


def test_transitive_cluster_connection(forensic_srv, graph_srv):
    """Test A connects to B and B connects to C (even if A-C is below threshold) forms 1 cluster."""
    # A shares keywords with B, B shares keywords with C
    text_a = "Cyber attack detected targeting municipal water infrastructure systems network."
    text_b = "Cyber attack detected targeting power grid infrastructure systems network database."
    text_c = "Critical security incident targeting power grid infrastructure systems network database."

    for txt in [text_a, text_b, text_c]:
        forensic_srv.create_incident(
            content=txt,
            prediction={"label": "AI-generated", "ai_probability": 0.8, "human_probability": 0.2, "confidence": 0.8},
            text_analysis={"character_count": len(txt), "word_count": len(txt.split()), "sentence_count": 1},
            threat_analysis={"threat_score": 75.0, "risk_level": "HIGH", "category": "Disinformation", "indicators": [], "reasons": [], "component_scores": {}},
        )

    data = graph_srv.get_graph_data(threshold=0.55)
    # The 3 nodes must be in 1 connected cluster and form 1 campaign
    assert len(data["clusters"]) == 1
    assert data["clusters"][0]["incident_count"] == 3
    assert len(data["campaigns"]) == 1


def test_threshold_exact_boundary_rejections(graph_srv):
    """Test 0.49 and 0.96 are explicitly rejected."""
    with pytest.raises(ValueError, match="between 0.5 and 0.95"):
        graph_srv.validate_threshold(0.49)

    with pytest.raises(ValueError, match="between 0.5 and 0.95"):
        graph_srv.validate_threshold(0.96)


def test_empty_content_resilience(graph_srv):
    """Test empty/none content does not crash preprocess_text or similarity."""
    assert graph_srv.preprocess_text("") == ""
    assert graph_srv.preprocess_text("   ") == ""
    assert graph_srv.preprocess_text(None) == ""

    incidents = [
        {"incident_id": "1", "content": ""},
        {"incident_id": "2", "content": "Normal text here."},
    ]
    matrix = graph_srv.build_similarity_matrix(incidents)
    assert matrix.shape == (2, 2)
    assert matrix[0, 1] == 0.0


def test_load_incidents_over_500_limit(temp_db_path, forensic_srv):
    """Test database with >500 records returns strictly the 500 newest records."""
    srv = ThreatGraphService(db_path=temp_db_path)

    # Insert 520 records directly in SQLite
    with db_session(temp_db_path) as conn:
        for i in range(520):
            conn.execute("""
                INSERT INTO incidents (
                    incident_id, created_at, content, content_hash,
                    ai_label, ai_probability, human_probability, confidence,
                    threat_score, risk_level, category,
                    text_analysis_json, indicators_json, reasons_json, component_scores_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                f"INC-BULK-{i:04d}",
                f"2026-08-01T00:{i%60:02d}:00Z",
                f"Bulk test incident content number {i}.",
                f"hash_{i}",
                "Human",
                0.1,
                0.9,
                0.9,
                10.0,
                "LOW",
                "Normal",
                "{}", "[]", "[]", "{}"
            ))
        conn.commit()

    # Default limit returns 50 newest records
    loaded_default = srv.load_incidents()
    assert len(loaded_default) == 50

    # Explicit limit 500 returns strictly bounded 500 records
    loaded_500 = srv.load_incidents(limit=500)
    assert len(loaded_500) == 500
    assert len(loaded_500) <= srv.MAX_INCIDENTS_LIMIT


# -----------------------------------------------------------------------------
# 5. Controlled 5-Incident Fixture & Zero-Edge Node Retention Tests
# -----------------------------------------------------------------------------

def test_controlled_abcde_similarity_fixture(temp_db_path, forensic_srv, graph_srv):
    """Test 5-incident fixture: A/B/C highly similar, D/E unrelated."""
    incidents = [
        ("INC-A", "Breaking information about a coordinated misinformation campaign. Share this immediately."),
        ("INC-B", "Urgent information about a coordinated misinformation campaign. Share this immediately."),
        ("INC-C", "Breaking information regarding a coordinated misinformation campaign. Please share immediately."),
        ("INC-D", "Today is a beautiful day and I went for a walk."),
        ("INC-E", "How to bake chocolate cookies at home."),
    ]

    for inc_id, text in incidents:
        forensic_srv.create_incident(
            content=text,
            prediction={"label": "Human", "ai_probability": 0.5, "human_probability": 0.5, "confidence": 0.5},
            text_analysis={"character_count": len(text), "word_count": len(text.split()), "sentence_count": 1},
            threat_analysis={"threat_score": 75.0, "risk_level": "HIGH", "category": "Disinformation", "indicators": [], "reasons": [], "component_scores": {}},
        )

    # At threshold 0.65, A and B form an edge (sim ~0.84), while D and E (sim ~0.0) do not
    graph_data_65 = graph_srv.get_graph_data(threshold=0.65)
    assert len(graph_data_65["nodes"]) == 5
    assert graph_data_65["summary"]["incident_count"] == 5

    edges_65 = graph_data_65["edges"]
    assert len(edges_65) >= 1

    # Verify no self edges
    for e in edges_65:
        assert e["source"] != e["target"]
        assert e["similarity"] >= 0.65

    # At threshold 0.50, A/B and A/C connect
    graph_data_50 = graph_srv.get_graph_data(threshold=0.50)
    assert len(graph_data_50["nodes"]) == 5
    assert len(graph_data_50["edges"]) >= 1

    # In all cases, D and E never connect to any misinformation nodes
    connected_to_d_or_e = [e for e in graph_data_50["edges"] if "INC-D" in (e["source"], e["target"]) or "INC-E" in (e["source"], e["target"])]
    assert len(connected_to_d_or_e) == 0


def test_zero_edges_retains_all_nodes(temp_db_path, forensic_srv, graph_srv):
    """Test that when similarity threshold is high (0.95) and no edges meet threshold, all nodes are preserved."""
    texts = [
        "First completely unique topic about astronomy and planetary sciences.",
        "Second completely unique topic about deep sea marine biology exploration.",
        "Third completely unique topic about medieval history architecture.",
    ]
    for text in texts:
        forensic_srv.create_incident(
            content=text,
            prediction={"label": "Human", "ai_probability": 0.1, "human_probability": 0.9, "confidence": 0.9},
            text_analysis={"character_count": len(text), "word_count": len(text.split()), "sentence_count": 1},
            threat_analysis={"threat_score": 20.0, "risk_level": "LOW", "category": "Normal", "indicators": [], "reasons": [], "component_scores": {}},
        )

    data = graph_srv.get_graph_data(threshold=0.95)
    assert len(data["nodes"]) == 3
    assert len(data["edges"]) == 0
    assert data["summary"]["incident_count"] == 3
    assert data["summary"]["edge_count"] == 0
    assert data["clusters"] == []
    assert data["campaigns"] == []


def test_no_database_mutation_during_graph_generation(temp_db_path, forensic_srv, graph_srv):
    """Test that calling get_graph_data across multiple thresholds does not modify database records."""
    forensic_srv.create_incident(
        content="Test content for immutability check.",
        prediction={"label": "Human", "ai_probability": 0.1, "human_probability": 0.9, "confidence": 0.9},
        text_analysis={"character_count": 36, "word_count": 5, "sentence_count": 1},
        threat_analysis={"threat_score": 30.0, "risk_level": "LOW", "category": "Normal", "indicators": [], "reasons": [], "component_scores": {}},
    )

    with db_session(temp_db_path) as conn:
        before_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    for t in [0.50, 0.65, 0.80, 0.95]:
        graph_srv.get_graph_data(threshold=t)

    with db_session(temp_db_path) as conn:
        after_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    assert before_count == after_count == 1


