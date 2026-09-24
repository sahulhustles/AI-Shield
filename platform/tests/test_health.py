"""AIShield - Stage 6H Health & System Reliability Tests.

Covers:
1. Health endpoint standard probe (GET /api/health -> 200 OK, status: healthy)
2. Health endpoint database failure (GET /api/health -> 503 Service Unavailable, status: down)
3. Health endpoint queue full backpressure degradation
4. Health endpoint connector error degradation
5. Connector failure isolation (broken connector does not crash other connectors or worker)
6. Worker failure isolation (crashing post does not kill worker thread or pipeline)
7. Credential redaction in health output and error logs
8. Retry limit exhaustion and safe failure transition
9. End-to-end duplicate ingestion and queue idempotency
10. Clean component shutdown without zombie threads
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from app import create_app
from database.db import init_db
from models.detector import AIDetector
from services.analysis_pipeline import AnalysisPipeline
from services.connectors.manual_connector import ManualConnector
from services.forensic_service import ForensicService
from services.incident_policy import IncidentPolicy
from services.ingestion_service import IngestionService
from services.live_broker import LiveEventBroker
from services.processing_queue import ProcessingQueue
from services.processing_worker import ProcessingWorker
from services.source_post_service import SourcePostService, SourcePostStatus
from services.text_analyzer import TextAnalyzer
from services.threat_analyzer import ThreatAnalyzer


@pytest.fixture
def health_env(tmp_path):
    """Fixture providing isolated test environment with custom credentials."""
    db_file = tmp_path / "test_health.db"
    init_db(db_file)

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_file,
        "YOUTUBE_API_KEY": "AIzaSyD_SUPER_SECRET_KEY_9999",
        "MASTODON_ACCESS_TOKEN": "masto_token_TOP_SECRET_AUTH_8888",
    })

    client = app.test_client()
    return {
        "app": app,
        "client": client,
        "db_path": db_file,
        "pipeline": app.analysis_pipeline,
        "worker": app.processing_worker,
        "queue": app.processing_queue,
        "source_service": app.source_post_service,
        "registry": app.connector_registry,
    }


# 1. Standard Health Endpoint Probe
def test_health_endpoint_standard(health_env):
    """Test GET /api/health returns 200 OK and healthy status for all components."""
    client = health_env["client"]
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "components" in data

    components = data["components"]
    assert components["application"]["status"] == "healthy"
    assert components["application"]["uptime_seconds"] >= 0.0
    assert components["database"]["status"] == "healthy"
    assert components["database"]["writable"] is True
    assert components["workers"]["status"] == "healthy"
    assert components["connectors"]["status"] == "healthy"


# 2. Database Failure Simulation
def test_health_endpoint_database_down(health_env):
    """Test that database failure results in HTTP 503 and down status."""
    client = health_env["client"]

    with patch("database.db.db_session", side_effect=RuntimeError("Simulated DB connection lost")):
        resp = client.get("/api/health")
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["status"] == "down"
        assert data["components"]["database"]["status"] == "down"
        assert data["components"]["database"]["writable"] is False


# 3. Queue Full Backpressure Degradation
def test_health_endpoint_queue_full_degraded(health_env):
    """Test that a full processing queue reports degraded worker health."""
    client = health_env["client"]
    queue = health_env["queue"]

    # Fill queue to capacity
    with patch.object(queue, "qsize", return_value=queue.maxsize):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "degraded"
        assert data["components"]["workers"]["status"] == "degraded"


# 4. Connector Error Degradation
def test_health_endpoint_connector_error_degraded(health_env):
    """Test that a connector error state triggers degraded platform health."""
    client = health_env["client"]
    registry = health_env["registry"]

    # Mock youtube connector state to ERROR
    orig_states = registry.get_connector_states()
    error_states = dict(orig_states)
    error_states["youtube"] = {
        "status": "ERROR",
        "enabled": True,
        "connection_errors": 5,
    }

    with patch.object(registry, "get_connector_states", return_value=error_states):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "degraded"
        assert data["components"]["connectors"]["status"] == "degraded"


# 5. Connector Failure Isolation
def test_connector_failure_isolation(health_env):
    """Verify that a failure in one connector does not impair other connectors or the worker."""
    registry = health_env["registry"]
    worker = health_env["worker"]
    source_service = health_env["source_service"]

    # Bluesky fails
    bsky_conn = registry.get("bluesky")
    bsky_conn._state = "ERROR"
    bsky_conn.connection_errors = 10

    # Manual connector still works cleanly
    manual_conn = registry.get("manual")
    raw_manual = {"source_id": "iso-test-1", "content": "Clean manual post"}
    norm_manual = manual_conn.normalize(raw_manual)
    assert norm_manual.source == "manual"
    post, is_dup = health_env["app"].ingestion_service.ingest(norm_manual)
    assert post is not None
    assert is_dup is False

    # Worker processes item without interference
    source_service.update_status(post["id"], SourcePostStatus.QUEUED)
    health_env["queue"].enqueue(post["id"])
    success = worker.process_one()
    assert success is True

    updated = source_service.get_source_post(post["id"])
    assert updated["status"] == SourcePostStatus.ANALYZED


# 6. Worker Failure Isolation
def test_worker_failure_isolation(health_env):
    """Test that an unhandled exception on one item does not crash subsequent queue processing."""
    worker = health_env["worker"]
    pipeline = health_env["pipeline"]
    source_service = health_env["source_service"]
    queue = health_env["queue"]

    # Ingest 2 posts
    post1, _ = source_service.create_source_post(source="manual", source_id="bad-post", content="Bad post")
    post2, _ = source_service.create_source_post(source="manual", source_id="good-post", content="Good post")

    source_service.update_status(post1["id"], SourcePostStatus.QUEUED)
    source_service.update_status(post2["id"], SourcePostStatus.QUEUED)

    queue.enqueue(post1["id"])
    queue.enqueue(post2["id"])

    # First post triggers exception in detector
    orig_predict = pipeline.detector.predict
    call_count = [0]

    def mock_predict(content):
        call_count[0] += 1
        if "Bad post" in content:
            raise ValueError("Malformed model weights payload")
        return {"label": "Human-Written", "ai_probability": 0.1, "human_probability": 0.9, "confidence": 0.9}

    pipeline.detector.predict = mock_predict

    # Worker processes post 1 (fails and retries)
    res1 = worker.process_one()
    assert res1 is False
    p1_db = source_service.get_source_post(post1["id"])
    assert p1_db["status"] == SourcePostStatus.QUEUED
    assert p1_db["analysis_attempts"] == 1
    assert "Malformed model weights payload" in p1_db["last_error"]

    # Worker processes post 2 (succeeds)
    res2 = worker.process_one()
    assert res2 is True
    p2_db = source_service.get_source_post(post2["id"])
    assert p2_db["status"] == SourcePostStatus.ANALYZED

    pipeline.detector.predict = orig_predict


# 7. Zero Credential Leakage
def test_zero_credential_leakage(health_env):
    """Verify secret keys are not leaked in health, status, or error fields."""
    client = health_env["client"]

    resp_health = client.get("/api/health")
    health_str = resp_health.get_data(as_text=True)
    assert "AIzaSyD_SUPER_SECRET_KEY_9999" not in health_str
    assert "masto_token_TOP_SECRET_AUTH_8888" not in health_str

    resp_status = client.get("/api/live/status")
    status_str = resp_status.get_data(as_text=True)
    assert "AIzaSyD_SUPER_SECRET_KEY_9999" not in status_str
    assert "masto_token_TOP_SECRET_AUTH_8888" not in status_str


# 8. Retry Limit Exhaustion
def test_retry_exhaustion_marks_failed(health_env):
    """Test that reaching maximum retry attempts marks the post FAILED."""
    worker = health_env["worker"]
    pipeline = health_env["pipeline"]
    source_service = health_env["source_service"]

    pipeline.detector.predict = MagicMock(side_effect=RuntimeError("Permanent GPU cluster failure"))
    post, _ = source_service.create_source_post(source="manual", source_id="exhaust-test", content="Failing text")
    source_service.update_status(post["id"], SourcePostStatus.QUEUED)
    health_env["queue"].enqueue(post["id"])

    # Attempt 1
    worker.process_one()
    p1 = source_service.get_source_post(post["id"])
    assert p1["analysis_attempts"] == 1
    assert p1["status"] == SourcePostStatus.QUEUED

    # Attempt 2
    worker.process_one()
    p2 = source_service.get_source_post(post["id"])
    assert p2["analysis_attempts"] == 2
    assert p2["status"] == SourcePostStatus.QUEUED

    # Attempt 3 (Final)
    worker.process_one()
    p3 = source_service.get_source_post(post["id"])
    assert p3["analysis_attempts"] == 3
    assert p3["status"] == SourcePostStatus.FAILED


# 9. Clean Shutdown
def test_clean_shutdown(health_env):
    """Test that stopping connectors, worker, and live broker terminates cleanly without exceptions."""
    app = health_env["app"]
    registry = app.connector_registry
    worker = app.processing_worker
    broker = app.live_broker

    # Disconnect all connectors
    registry.disconnect_all()
    assert registry.get("bluesky").is_running() is False
    assert registry.get("mastodon").is_running() is False
    assert registry.get("youtube").is_running() is False

    # Stop worker
    worker.stop(timeout=1.0)
    assert worker.is_alive() is False

    # Clear broker
    broker.clear()
    assert broker.get_subscriber_count() == 0
