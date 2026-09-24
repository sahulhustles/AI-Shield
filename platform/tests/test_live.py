"""AIShield - Stage 6G Live Monitoring Dashboard Tests.

Covers:
1. Status endpoint (/api/live/status)
2. Source connector states
3. Live metrics update
4. Recent event retrieval (/api/live/feed)
5. High-risk incident alert generation
6. SSE frame formatting
7. Keepalive formatting
8. Client disconnect & cleanup
9. Subscriber capacity limit enforcement
10. Source filtering in live feed
11. Zero credential leakage
12. API error resilience & 404/500 handling
"""

import json
from unittest.mock import MagicMock
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
def test_env(tmp_path):
    """Fixture providing isolated database, broker, pipeline, and test client."""
    db_file = tmp_path / "test_live.db"
    init_db(db_file)

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_file,
        "MAX_SSE_SUBSCRIBERS": 3,
        "SSE_KEEPALIVE_INTERVAL_SECONDS": 1.0,
        "YOUTUBE_API_KEY": "SECRET_YOUTUBE_KEY_12345",
        "MASTODON_ACCESS_TOKEN": "SECRET_MASTODON_TOKEN_ABCDE",
    })

    client = app.test_client()
    return {
        "app": app,
        "client": client,
        "db_path": db_file,
        "broker": app.live_broker,
        "pipeline": app.analysis_pipeline,
        "source_service": app.source_post_service,
        "forensic_service": app.forensic_service,
    }


# 1. Page render test (/live)
def test_live_page_render(test_env):
    """Test that GET /live returns 200 OK and renders HTML with expected title and elements."""
    client = test_env["client"]
    resp = client.get("/live")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Live Monitoring" in html
    assert "AIShield" in html
    assert "connectors-grid" in html
    assert "live-feed-table" in html


# 2. Status endpoint test (/api/live/status)
def test_live_status_endpoint(test_env):
    """Test GET /api/live/status returns valid JSON structure and subscriber counters."""
    client = test_env["client"]
    resp = client.get("/api/live/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "live_status" in data
    ls = data["live_status"]
    assert "active_subscribers" in ls
    assert "connector_states" in ls
    assert "pipeline_metrics" in ls
    assert ls["active_subscribers"] == 0
    assert ls["max_subscribers"] == 3


# 3. Source status test
def test_source_connector_states(test_env):
    """Test that all connector states (bluesky, mastodon, youtube, worker) are reported."""
    client = test_env["client"]
    resp = client.get("/api/live/status")
    states = resp.get_json()["live_status"]["connector_states"]

    assert "bluesky" in states
    assert "mastodon" in states
    assert "youtube" in states
    assert "worker" in states


# 4. Metrics update test
def test_metrics_reporting(test_env):
    """Test that status counters reflect ingested and processed posts."""
    client = test_env["client"]
    source_service = test_env["source_service"]

    # Ingest 2 posts
    post1, _ = source_service.create_source_post(
        source="manual",
        source_id="live-m-1",
        content="Post one",
    )
    post2, _ = source_service.create_source_post(
        source="bluesky",
        source_id="live-m-2",
        content="Post two",
    )
    source_service.mark_analyzed(post1["id"])

    resp = client.get("/api/live/status")
    ls = resp.get_json()["live_status"]
    assert ls["source_posts_received"] == 2
    assert ls["source_posts_analyzed"] == 1


# 5. Recent event retrieval (/api/live/feed)
def test_recent_event_retrieval(test_env):
    """Test GET /api/live/feed returns published events in reverse chronological order."""
    client = test_env["client"]
    broker = test_env["broker"]

    broker.publish_event("source_post", {"id": 1, "source": "manual", "content_snippet": "First"})
    broker.publish_event("source_post", {"id": 2, "source": "bluesky", "content_snippet": "Second"})

    resp = client.get("/api/live/feed?limit=10")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["count"] == 2
    events = data["events"]
    # Newest first
    assert events[0]["data"]["id"] == 2
    assert events[1]["data"]["id"] == 1


# 6. High-risk event publication
def test_high_risk_event_alert_generation(test_env):
    """Test that analyzing a high-risk post publishes an incident_alert event."""
    pipeline = test_env["pipeline"]
    source_service = test_env["source_service"]
    broker = test_env["broker"]

    # Mock high threat
    pipeline.detector.predict = MagicMock(return_value={
        "label": "AI-Generated",
        "ai_probability": 0.95,
        "human_probability": 0.05,
        "confidence": 0.95,
    })
    pipeline.threat_analyzer.analyze = MagicMock(return_value={
        "threat_score": 88.0,
        "risk_level": "CRITICAL",
        "category": "Phishing",
        "indicators": [],
        "reasons": [],
        "component_scores": {},
    })

    post, _ = source_service.create_source_post(
        source="youtube",
        source_id="crit-yt-alert-unique-1",
        content="Urgent critical account alert verify password immediately",
    )

    res = pipeline.process_source_post(post["id"])
    assert res["incident_created"] is True

    # Verify event broker received incident_alert
    recent = broker.get_recent_events(limit=10)
    alert_event = next((e for e in recent if e["type"] == "incident_alert"), None)
    assert alert_event is not None
    assert alert_event["data"]["risk_level"] == "CRITICAL"
    assert alert_event["data"]["threat_score"] == 88.0
    assert alert_event["data"]["source"] == "youtube"


# 7. SSE formatting test
def test_sse_message_formatting():
    """Test that LiveEventBroker.format_sse_message produces compliant SSE frames."""
    msg = LiveEventBroker.format_sse_message("source_post", {"id": 42, "status": "ANALYZED"})
    assert msg.startswith("event: source_post\n")
    assert "data: " in msg
    assert '"id": 42' in msg
    assert msg.endswith("\n\n")


# 8. Keepalive formatting test
def test_sse_keepalive_formatting():
    """Test that LiveEventBroker.format_keepalive produces SSE comment format."""
    comment = LiveEventBroker.format_keepalive()
    assert comment == ": keepalive\n\n"


# 9. Client disconnect & cleanup test
def test_client_disconnect_cleanup(test_env):
    """Test that registering and unregistering listener updates subscriber count cleanly."""
    broker = test_env["broker"]
    assert broker.get_subscriber_count() == 0

    q = broker.register_listener()
    assert q is not None
    assert broker.get_subscriber_count() == 1

    broker.unregister_listener(q)
    assert broker.get_subscriber_count() == 0


# 10. Subscriber capacity limit enforcement
def test_subscriber_limit_enforcement(test_env):
    """Test that registering more than max_subscribers (3) returns None and HTTP 503."""
    broker = test_env["broker"]
    client = test_env["client"]

    # Fill capacity (max 3)
    q1 = broker.register_listener()
    q2 = broker.register_listener()
    q3 = broker.register_listener()
    assert broker.get_subscriber_count() == 3

    # 4th registration should be rejected
    q4 = broker.register_listener()
    assert q4 is None

    # HTTP endpoint returns 503
    resp = client.get("/api/live/events")
    assert resp.status_code == 503
    data = resp.get_json()
    assert data["success"] is False
    assert "capacity reached" in data["error"].lower()

    # Cleanup
    broker.unregister_listener(q1)
    broker.unregister_listener(q2)
    broker.unregister_listener(q3)
    assert broker.get_subscriber_count() == 0


# 11. Source filtering in live feed
def test_source_filtering(test_env):
    """Test filtering recent events by source."""
    broker = test_env["broker"]
    client = test_env["client"]

    broker.publish_event("source_post", {"id": 1, "source": "bluesky", "content": "bsky post"})
    broker.publish_event("source_post", {"id": 2, "source": "mastodon", "content": "masto post"})
    broker.publish_event("source_post", {"id": 3, "source": "youtube", "content": "yt post"})
    broker.publish_event("source_post", {"id": 4, "source": "bluesky", "content": "bsky post 2"})

    # Filter bluesky
    resp_bsky = client.get("/api/live/feed?source=bluesky")
    assert resp_bsky.status_code == 200
    events_bsky = resp_bsky.get_json()["events"]
    assert len(events_bsky) == 2
    for e in events_bsky:
        assert e["data"]["source"] == "bluesky"

    # Filter youtube
    resp_yt = client.get("/api/live/feed?source=youtube")
    events_yt = resp_yt.get_json()["events"]
    assert len(events_yt) == 1
    assert events_yt[0]["data"]["source"] == "youtube"


# 12. Zero credential leakage verification
def test_no_credential_leakage(test_env):
    """Verify that live status and feed never expose secret API keys or tokens."""
    client = test_env["client"]
    resp_status = client.get("/api/live/status")
    status_text = resp_status.get_data(as_text=True)
    assert "SECRET_YOUTUBE_KEY_12345" not in status_text
    assert "SECRET_MASTODON_TOKEN_ABCDE" not in status_text

    resp_feed = client.get("/api/live/feed")
    feed_text = resp_feed.get_data(as_text=True)
    assert "SECRET_YOUTUBE_KEY_12345" not in feed_text
    assert "SECRET_MASTODON_TOKEN_ABCDE" not in feed_text


# 13. API Error handling resilience
def test_live_api_error_handling(test_env):
    """Test that unexpected server exceptions return structured JSON 500 responses."""
    client = test_env["client"]
    broker = test_env["broker"]

    # Mock get_recent_events to raise an exception
    orig_get = broker.get_recent_events
    broker.get_recent_events = MagicMock(side_effect=RuntimeError("Simulated broker crash"))

    resp = client.get("/api/live/feed")
    assert resp.status_code == 500
    data = resp.get_json()
    assert data["success"] is False
    assert "internal error" in data["error"].lower()

    broker.get_recent_events = orig_get
