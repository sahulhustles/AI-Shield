"""Integration tests for AIShield Flask REST API endpoints and views."""

import json
from pathlib import Path
import pytest

from app import create_app
from database.db import init_db
from models.detector import AIDetector


@pytest.fixture
def test_client(tmp_path):
    """Provide a Flask test client with an isolated temporary SQLite database and pre-trained detector."""
    db_file = tmp_path / "test_api.db"
    init_db(db_file)

    # Initialize a fast real detector model for the test
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


def test_get_root(test_client):
    """Test GET / returns 200 OK and renders index page."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert b"AIShield" in response.data


def test_post_analyze_valid_text(test_client):
    """Test POST /api/analyze with valid text returns Module 1 & 2 outputs."""
    response = test_client.post(
        "/api/analyze",
        json={"text": "URGENT SECURITY ALERT: Unauthorized login detected! Verify account immediately."},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "prediction" in data
    assert "text_analysis" in data
    assert "threat_analysis" in data
    assert "threat_score" in data["threat_analysis"]
    assert "risk_level" in data["threat_analysis"]


def test_post_analyze_empty_text(test_client):
    """Test POST /api/analyze with empty string returns HTTP 400."""
    response = test_client.post("/api/analyze", json={"text": "   "})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Empty input" in data["error"]


def test_post_analyze_missing_json(test_client):
    """Test POST /api/analyze without JSON Content-Type returns HTTP 400."""
    response = test_client.post("/api/analyze", data="plain text data")
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False


def test_post_analyze_missing_text_key(test_client):
    """Test POST /api/analyze with missing 'text' key returns HTTP 400."""
    response = test_client.post("/api/analyze", json={"wrong_key": "some text"})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Missing required field" in data["error"]


def test_post_analyze_invalid_type(test_client):
    """Test POST /api/analyze with non-string text returns HTTP 400."""
    response = test_client.post("/api/analyze", json={"text": 12345})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Invalid field type" in data["error"]


def test_post_analyze_max_length_exceeded(test_client):
    """Test POST /api/analyze with text exceeding max length returns HTTP 400."""
    oversized = "a" * 50001
    response = test_client.post("/api/analyze", json={"text": oversized})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "exceeds maximum allowed length" in data["error"]


# -----------------------------------------------------------------------------
# Module 3 Forensics Endpoints Tests
# -----------------------------------------------------------------------------

def test_post_incident_success(test_client):
    """Test POST /api/incidents creates a persistent incident and returns HTTP 201."""
    # First analyze
    analyze_res = test_client.post("/api/analyze", json={"text": "Official Security Notice: Password expired."})
    assert analyze_res.status_code == 200
    analysis = analyze_res.get_json()

    # Now create incident
    response = test_client.post("/api/incidents", json={
        "text": "Official Security Notice: Password expired.",
        "prediction": analysis["prediction"],
        "text_analysis": analysis["text_analysis"],
        "threat_analysis": analysis["threat_analysis"],
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data["success"] is True
    assert "incident" in data
    assert data["incident"]["incident_id"].startswith("INC-")
    assert "content_hash" in data["incident"]


def test_post_incident_invalid_payload(test_client):
    """Test POST /api/incidents with missing fields returns HTTP 400."""
    response = test_client.post("/api/incidents", json={"text": "Only text without analysis"})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Missing required fields" in data["error"]


def test_get_incidents_list(test_client):
    """Test GET /api/incidents returns a list of summary records."""
    analyze_res = test_client.post("/api/analyze", json={"text": "Sample text for history test."})
    analysis = analyze_res.get_json()
    test_client.post("/api/incidents", json={
        "text": "Sample text for history test.",
        "prediction": analysis["prediction"],
        "text_analysis": analysis["text_analysis"],
        "threat_analysis": analysis["threat_analysis"],
    })

    response = test_client.get("/api/incidents?limit=10")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert isinstance(data["incidents"], list)
    assert len(data["incidents"]) >= 1


def test_get_single_incident(test_client):
    """Test GET /api/incidents/<id> returns complete stored snapshot."""
    analyze_res = test_client.post("/api/analyze", json={"text": "Sample text for single view test."})
    analysis = analyze_res.get_json()
    create_res = test_client.post("/api/incidents", json={
        "text": "Sample text for single view test.",
        "prediction": analysis["prediction"],
        "text_analysis": analysis["text_analysis"],
        "threat_analysis": analysis["threat_analysis"],
    })
    inc_id = create_res.get_json()["incident"]["incident_id"]

    response = test_client.get(f"/api/incidents/{inc_id}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["incident"]["incident_id"] == inc_id
    assert data["incident"]["content"] == "Sample text for single view test."


def test_get_nonexistent_incident(test_client):
    """Test GET /api/incidents/<id> for non-existent ID returns HTTP 404."""
    response = test_client.get("/api/incidents/INC-00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert "was not found" in data["error"]


def test_verify_incident_integrity(test_client):
    """Test POST /api/incidents/<id>/verify validates cryptographic integrity."""
    analyze_res = test_client.post("/api/analyze", json={"text": "Sample text for integrity check."})
    analysis = analyze_res.get_json()
    create_res = test_client.post("/api/incidents", json={
        "text": "Sample text for integrity check.",
        "prediction": analysis["prediction"],
        "text_analysis": analysis["text_analysis"],
        "threat_analysis": analysis["threat_analysis"],
    })
    inc_id = create_res.get_json()["incident"]["incident_id"]

    response = test_client.post(f"/api/incidents/{inc_id}/verify")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["verified"] is True
    assert data["stored_hash"] == data["calculated_hash"]


def test_html_incident_views(test_client):
    """Test GET /incidents and GET /incidents/<id> render HTML templates."""
    res_list = test_client.get("/incidents")
    assert res_list.status_code == 200
    assert b"Incident History" in res_list.data

    analyze_res = test_client.post("/api/analyze", json={"text": "Sample text for HTML detail view."})
    analysis = analyze_res.get_json()
    create_res = test_client.post("/api/incidents", json={
        "text": "Sample text for HTML detail view.",
        "prediction": analysis["prediction"],
        "text_analysis": analysis["text_analysis"],
        "threat_analysis": analysis["threat_analysis"],
    })
    inc_id = create_res.get_json()["incident"]["incident_id"]

    res_detail = test_client.get(f"/incidents/{inc_id}")
    assert res_detail.status_code == 200
    assert b"Forensic Incident Detail" in res_detail.data
    assert inc_id.encode("utf-8") in res_detail.data


# -----------------------------------------------------------------------------
# Module 4 Threat Intelligence & Dashboard Endpoints Tests
# -----------------------------------------------------------------------------

def test_html_dashboard_view(test_client):
    """Test GET /dashboard renders HTML dashboard page."""
    response = test_client.get("/dashboard")
    assert response.status_code == 200
    assert b"Threat Intelligence Dashboard" in response.data


def test_api_dashboard_summary(test_client):
    """Test GET /api/dashboard/summary returns summary stats."""
    response = test_client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "summary" in data
    assert "total_incidents" in data["summary"]
    assert "average_threat_score" in data["summary"]


def test_api_dashboard_recent(test_client):
    """Test GET /api/dashboard/recent returns recent records list."""
    response = test_client.get("/api/dashboard/recent?limit=5")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert isinstance(data["recent"], list)


def test_api_dashboard_high_risk(test_client):
    """Test GET /api/dashboard/high-risk returns high risk records list."""
    response = test_client.get("/api/dashboard/high-risk?limit=5")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert isinstance(data["high_risk"], list)


def test_api_dashboard_distribution(test_client):
    """Test GET /api/dashboard/distribution returns risk, category, and AI distributions."""
    response = test_client.get("/api/dashboard/distribution")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "risk" in data
    assert "categories" in data
    assert "ai" in data
    assert "LOW" in data["risk"]
    assert "Phishing" in data["categories"]


def test_api_dashboard_trend(test_client):
    """Test GET /api/dashboard/trend returns chronological daily trend."""
    response = test_client.get("/api/dashboard/trend")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert isinstance(data["trend"], list)


def test_api_dashboard_incidents_search_and_filter(test_client):
    """Test GET /api/dashboard/incidents with search filters and pagination."""
    # Create incident
    analyze_res = test_client.post("/api/analyze", json={"text": "Urgent alert: Account suspension."})
    analysis = analyze_res.get_json()
    test_client.post("/api/incidents", json={
        "text": "Urgent alert: Account suspension.",
        "prediction": analysis["prediction"],
        "text_analysis": analysis["text_analysis"],
        "threat_analysis": analysis["threat_analysis"],
    })

    # Search with valid params
    response = test_client.get("/api/dashboard/incidents?q=Account&page=1&page_size=10&sort=date&order=desc")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "items" in data
    assert "pagination" in data
    assert data["pagination"]["page"] == 1


def test_api_dashboard_incidents_invalid_params(test_client):
    """Test GET /api/dashboard/incidents with invalid filter parameters returns HTTP 400."""
    response = test_client.get("/api/dashboard/incidents?risk_level=INVALID_RISK")
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Invalid risk_level filter" in data["error"]


# -----------------------------------------------------------------------------
# Module 5 Threat Relationship Graph & Campaigns Endpoints Tests
# -----------------------------------------------------------------------------

def test_html_graph_view(test_client):
    """Test GET /graph renders HTML graph relationship visualizer page."""
    response = test_client.get("/graph")
    assert response.status_code == 200
    assert b"Threat Relationship Graph" in response.data


def test_api_graph_default_threshold(test_client):
    """Test GET /api/graph returns graph structure with default threshold 0.65."""
    response = test_client.get("/api/graph")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["threshold"] == 0.65
    assert "nodes" in data
    assert "edges" in data
    assert "clusters" in data
    assert "campaigns" in data
    assert "summary" in data


def test_api_graph_custom_threshold(test_client):
    """Test GET /api/graph with valid custom threshold 0.75."""
    response = test_client.get("/api/graph?threshold=0.75")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["threshold"] == 0.75


def test_api_graph_invalid_threshold(test_client):
    """Test GET /api/graph with invalid threshold returns HTTP 400."""
    res_low = test_client.get("/api/graph?threshold=0.30")
    assert res_low.status_code == 400
    assert "between 0.5 and 0.95" in res_low.get_json()["error"]

    res_high = test_client.get("/api/graph?threshold=1.20")
    assert res_high.status_code == 400

    res_str = test_client.get("/api/graph?threshold=not-a-number")
    assert res_str.status_code == 400


def test_api_campaigns_list(test_client):
    """Test GET /api/campaigns returns campaign list."""
    response = test_client.get("/api/campaigns")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "campaigns" in data
    assert "count" in data


def test_api_campaign_detail_nonexistent(test_client):
    """Test GET /api/campaigns/<id> for non-existent campaign returns HTTP 404."""
    response = test_client.get("/api/campaigns/CAMP-NONEXISTENT")
    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert "was not found" in data["error"]


# =============================================================================
# Stage 6A API Integration Tests - Source Posts & Ingestion
# =============================================================================

def test_api_post_source_post_success(test_client):
    """Test POST /api/source-posts with valid payload returns HTTP 201 Created."""
    payload = {
        "source": "manual",
        "source_id": "test-api-manual-1",
        "content": "This is an external source post submitted manually.",
        "author_name": "Analyst1",
        "published_at": "2026-08-18T10:00:00Z",
        "metadata": {"origin": "web-input", "verified": True},
    }
    response = test_client.post("/api/source-posts", json=payload)
    assert response.status_code == 201
    data = response.get_json()
    assert data["success"] is True
    assert data["duplicate"] is False
    assert "source_post" in data
    assert data["source_post"]["source"] == "manual"
    assert data["source_post"]["source_id"] == "test-api-manual-1"
    assert data["source_post"]["status"] == "RECEIVED"
    assert data["source_post"]["content_hash"] is not None


def test_api_post_source_post_duplicate(test_client):
    """Test POST /api/source-posts with duplicate (source, source_id) returns HTTP 200 with duplicate=True."""
    payload = {
        "source": "bluesky",
        "source_id": "bsky-dup-check-1",
        "content": "Original announcement post.",
    }
    # First submission
    res1 = test_client.post("/api/source-posts", json=payload)
    assert res1.status_code == 201
    assert res1.get_json()["duplicate"] is False

    # Second submission with same (source, source_id)
    res2 = test_client.post("/api/source-posts", json=payload)
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2["success"] is True
    assert data2["duplicate"] is True
    assert "already exists" in data2["message"]
    assert data2["source_post"]["source_id"] == "bsky-dup-check-1"


def test_api_post_source_post_missing_fields(test_client):
    """Test POST /api/source-posts with missing required fields returns HTTP 400."""
    response = test_client.post("/api/source-posts", json={"source": "manual"})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Missing required fields" in data["error"]


def test_api_post_source_post_unsupported_source(test_client):
    """Test POST /api/source-posts with unsupported source returns HTTP 400."""
    response = test_client.post(
        "/api/source-posts",
        json={"source": "twitter", "source_id": "123", "content": "Hello world"},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Unsupported source" in data["error"]


def test_api_post_source_post_empty_content(test_client):
    """Test POST /api/source-posts with empty content returns HTTP 400."""
    response = test_client.post(
        "/api/source-posts",
        json={"source": "manual", "source_id": "empty-1", "content": "   "},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "content" in data["error"]


def test_api_post_source_post_non_json(test_client):
    """Test POST /api/source-posts without JSON Content-Type returns HTTP 400."""
    response = test_client.post("/api/source-posts", data="non-json string")
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False


def test_api_get_source_post_by_key(test_client):
    """Test GET /api/source-posts/<source>/<source_id> retrieves stored record."""
    # Create record
    test_client.post(
        "/api/source-posts",
        json={"source": "mastodon", "source_id": "masto-get-1", "content": "Content to get"},
    )

    # Retrieve record
    response = test_client.get("/api/source-posts/mastodon/masto-get-1")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["source_post"]["source"] == "mastodon"
    assert data["source_post"]["source_id"] == "masto-get-1"


def test_api_get_source_post_by_key_not_found(test_client):
    """Test GET /api/source-posts/<source>/<source_id> for missing record returns HTTP 404."""
    response = test_client.get("/api/source-posts/mastodon/non-existent-id-999")
    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert "was not found" in data["error"]


def test_api_get_source_post_by_key_unsupported_source(test_client):
    """Test GET /api/source-posts/<source>/<source_id> for unsupported source returns HTTP 400."""
    response = test_client.get("/api/source-posts/unsupported_platform/some-id")
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Unsupported source" in data["error"]


def test_api_list_source_posts(test_client):
    """Test GET /api/source-posts returns list of stored source posts."""
    test_client.post("/api/source-posts", json={"source": "youtube", "source_id": "yt-list-1", "content": "Video 1"})
    test_client.post("/api/source-posts", json={"source": "youtube", "source_id": "yt-list-2", "content": "Video 2"})

    response = test_client.get("/api/source-posts?limit=10&source=youtube")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "source_posts" in data
    assert data["count"] >= 2


def test_api_list_source_posts_invalid_params(test_client):
    """Test GET /api/source-posts with invalid limit or filter returns HTTP 400."""
    res_bad_limit = test_client.get("/api/source-posts?limit=500")
    assert res_bad_limit.status_code == 400

    res_bad_source = test_client.get("/api/source-posts?source=unknown_src")
    assert res_bad_source.status_code == 400

    res_bad_status = test_client.get("/api/source-posts?status=INVALID_STATUS")
    assert res_bad_status.status_code == 400


# =============================================================================
# Stage 6F API Integration Tests - Analysis Pipeline & Status
# =============================================================================

def test_api_get_source_post_analysis_status(test_client):
    """Test GET /api/source-posts/<id>/analysis-status returns processing status."""
    # 1. Create post
    res_create = test_client.post(
        "/api/source-posts",
        json={"source": "manual", "source_id": "status-check-1", "content": "Sample content"},
    )
    post_id = res_create.get_json()["source_post"]["id"]

    # 2. Check status
    res_status = test_client.get(f"/api/source-posts/{post_id}/analysis-status")
    assert res_status.status_code == 200
    data = res_status.get_json()
    assert data["success"] is True
    assert data["source_post_id"] == post_id
    assert data["status"] == "RECEIVED"
    assert data["attempts"] == 0
    assert data["incident_id"] is None


def test_api_get_source_post_analysis_status_not_found(test_client):
    """Test GET /api/source-posts/<id>/analysis-status returns 404 for missing post."""
    res = test_client.get("/api/source-posts/999999/analysis-status")
    assert res.status_code == 404
    data = res.get_json()
    assert data["success"] is False
    assert "not found" in data["error"]


def test_api_ingestion_status_enhanced_metrics(test_client):
    """Test GET /api/ingestion/status returns comprehensive Stage 6F metrics."""
    res = test_client.get("/api/ingestion/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    status = data["status"]
    assert "source_posts_received" in status
    assert "source_posts_analyzed" in status
    assert "source_posts_skipped" in status
    assert "source_posts_failed" in status
    assert "incidents_generated" in status
    assert "analysis_errors" in status
    assert "pipeline_metrics" in status



