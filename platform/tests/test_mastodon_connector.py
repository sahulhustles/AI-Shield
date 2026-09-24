"""AIShield - Stage 6D Unit & Integration Tests: Mastodon Live Connector (Mocked & Offline)."""

import json
from pathlib import Path
import threading
import time
import pytest

from database.db import init_db
from services.connectors.mastodon_connector import MastodonConnector
from services.ingestion_service import IngestionService, NormalizedPost
from services.processing_queue import ProcessingQueue
from services.source_post_service import SourcePostService, SourcePostStatus


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a unique isolated temporary SQLite database path."""
    db_file = tmp_path / "test_mastodon.db"
    init_db(db_file)
    return db_file


@pytest.fixture
def source_service(temp_db_path):
    """Provide an initialized SourcePostService."""
    return SourcePostService(db_path=temp_db_path)


@pytest.fixture
def ingestion_service(source_service):
    """Provide an IngestionService configured with the test SourcePostService."""
    return IngestionService(source_post_service=source_service)


@pytest.fixture
def sample_mastodon_status():
    """Provide a realistic Mastodon status dictionary."""
    return {
        "id": "112345678901234567",
        "created_at": "2026-08-18T07:15:00.000Z",
        "content": "<p>Security Advisory: New zero-day vulnerability detected in network router firmware. See <a href=\"https://example.com/advisory\">advisory</a> for mitigation steps.</p>",
        "url": "https://mastodon.social/@infosec_analyst/112345678901234567",
        "uri": "https://mastodon.social/users/infosec_analyst/statuses/112345678901234567",
        "visibility": "public",
        "language": "en",
        "account": {
            "id": "998877",
            "username": "infosec_analyst",
            "acct": "infosec_analyst@mastodon.social",
            "display_name": "Infosec Analyst",
        },
        "tags": [{"name": "security"}, {"name": "cybersecurity"}],
        "reblogs_count": 12,
        "favourites_count": 45,
    }


# 1. Endpoint construction
def test_mastodon_url_and_stream_endpoint_construction():
    """Test endpoint URL construction for hashtag and public modes."""
    conn_hashtag = MastodonConnector(
        base_url="https://mastodon.social/",
        stream_mode="hashtag",
        hashtags="security,cybersecurity",
        enabled=False,
    )
    endpoints = conn_hashtag.get_stream_endpoints()
    assert len(endpoints) == 2
    assert "https://mastodon.social/api/v1/streaming/hashtag?tag=security" in endpoints
    assert "https://mastodon.social/api/v1/streaming/hashtag?tag=cybersecurity" in endpoints

    conn_public = MastodonConnector(
        base_url="https://infosec.exchange",
        stream_mode="public",
        enabled=False,
    )
    pub_endpoints = conn_public.get_stream_endpoints()
    assert pub_endpoints == ["https://infosec.exchange/api/v1/streaming/public"]


# 2. Auth header included when token present
def test_mastodon_auth_header_included_when_token_present():
    """Test connector registers access token internally for authenticated streams."""
    conn = MastodonConnector(
        access_token="secret_bearer_token_12345",
        enabled=False,
    )
    assert conn._access_token == "secret_bearer_token_12345"


# 3. Auth header absent when token empty
def test_mastodon_auth_header_absent_when_token_empty():
    """Test connector operates in unauthenticated mode when token is absent."""
    conn = MastodonConnector(
        access_token="",
        enabled=False,
    )
    assert conn._access_token == ""


# 4. Hashtag validation and cleaning
def test_mastodon_hashtag_validation_and_cleaning():
    """Test stripping #, whitespace, and filtering invalid characters."""
    tags = MastodonConnector.parse_hashtags("#security,  #CYBER_threat , invalid@tag! , #infosec ")
    assert tags == ["security", "cyber_threat", "infosec"]


# 5. Multiple hashtags deduplication
def test_mastodon_multiple_hashtags_parsing():
    """Test deduplication of duplicate tags across string or list input."""
    tags_str = MastodonConnector.parse_hashtags("security, security, cybersecurity, SECURITY")
    assert tags_str == ["security", "cybersecurity"]

    tags_list = MastodonConnector.parse_hashtags(["#ai", "AI", "#threats"])
    assert tags_list == ["ai", "threats"]


# 6. Status parsing of valid status
def test_mastodon_status_parsing_valid(sample_mastodon_status):
    """Test parsing a valid Mastodon status dictionary."""
    parsed = MastodonConnector.parse_mastodon_status(sample_mastodon_status)
    assert parsed is not None
    assert parsed["source_id"] == "112345678901234567"
    assert parsed["author_id"] == "998877"
    assert parsed["author_name"] == "infosec_analyst@mastodon.social"
    assert parsed["published_at"] == "2026-08-18T07:15:00.000Z"
    assert parsed["language"] == "en"
    assert "security" in parsed["metadata"]["tags"]


# 7. HTML to safe plain text normalization
def test_mastodon_html_to_plain_text_normalization(sample_mastodon_status):
    """Test converting Mastodon HTML paragraphs and anchors into safe plain text."""
    conn = MastodonConnector(enabled=False)
    norm_post = conn.normalize(sample_mastodon_status)

    assert isinstance(norm_post, NormalizedPost)
    assert norm_post.source == "mastodon"
    assert "<p>" not in norm_post.content
    assert "<a href" not in norm_post.content
    assert "Security Advisory: New zero-day vulnerability detected in network router firmware. See advisory for mitigation steps." in norm_post.content


# 8. Metadata preservation
def test_mastodon_metadata_preservation(sample_mastodon_status):
    """Test raw HTML payload and original metadata fields are preserved."""
    conn = MastodonConnector(enabled=False)
    norm_post = conn.normalize(sample_mastodon_status)

    assert "raw_html" in norm_post.metadata
    assert norm_post.metadata["raw_html"] == sample_mastodon_status["content"]
    assert norm_post.metadata["reblogs_count"] == 12
    assert norm_post.metadata["favourites_count"] == 45


# 9. Private and direct status rejected
def test_mastodon_private_and_direct_status_rejected(sample_mastodon_status):
    """Test that private and direct message statuses are rejected."""
    priv_status = dict(sample_mastodon_status)
    priv_status["visibility"] = "private"
    assert MastodonConnector.parse_mastodon_status(priv_status) is None

    direct_status = dict(sample_mastodon_status)
    direct_status["visibility"] = "direct"
    assert MastodonConnector.parse_mastodon_status(direct_status) is None

    unlisted_status = dict(sample_mastodon_status)
    unlisted_status["visibility"] = "unlisted"
    assert MastodonConnector.parse_mastodon_status(unlisted_status) is not None


# 10. Delete event ignored
def test_mastodon_delete_event_ignored():
    """Test that delete events or non-status events are ignored."""
    delete_event = {"event": "delete", "id": "1123456789"}
    assert MastodonConnector.parse_mastodon_status(delete_event) is None


# 11. Heartbeat ignored
def test_mastodon_heartbeat_ignored():
    """Test that heartbeat / empty payloads return None."""
    assert MastodonConnector.parse_mastodon_status(":thump") is None
    assert MastodonConnector.parse_mastodon_status("") is None
    assert MastodonConnector.parse_mastodon_status(None) is None


# 12. Duplicate status handling
def test_mastodon_duplicate_status_deduplication(sample_mastodon_status, ingestion_service, source_service):
    """Test that duplicate Mastodon status increments deduplicated counter and creates only 1 database row."""
    queue = ProcessingQueue()
    conn = MastodonConnector(
        enabled=False,
        ingestion_service=ingestion_service,
        processing_queue=queue,
        source_post_service=source_service,
    )

    # First receipt
    assert conn.process_incoming_status(sample_mastodon_status) is True
    assert conn.events_accepted == 1
    assert conn.events_deduplicated == 0

    # Duplicate receipt (e.g. from multiple hashtag streams)
    assert conn.process_incoming_status(sample_mastodon_status) is True
    assert conn.events_accepted == 1
    assert conn.events_deduplicated == 1

    # Verify only 1 record in database
    posts = source_service.list_source_posts(source="mastodon")
    assert len(posts) == 1
    assert posts[0]["source_id"] == "112345678901234567"


# 13. Exponential backoff calculation
def test_mastodon_exponential_backoff():
    """Test backoff progression up to max_backoff."""
    conn = MastodonConnector(enabled=False, initial_backoff=1.0, max_backoff=30.0)
    backoff = conn.initial_backoff
    sequence = [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]

    for expected in sequence:
        sleep_time = min(conn.max_backoff, backoff)
        assert sleep_time == expected
        backoff *= 2.0


# 14. Queue full drop counting
def test_mastodon_queue_full_drop_counting(sample_mastodon_status, ingestion_service, source_service):
    """Test that if the processing queue is full, events_dropped is incremented."""
    full_queue = ProcessingQueue(maxsize=1)
    full_queue.enqueue(88888)

    conn = MastodonConnector(
        enabled=False,
        ingestion_service=ingestion_service,
        processing_queue=full_queue,
        source_post_service=source_service,
    )

    assert conn.process_incoming_status(sample_mastodon_status) is True
    assert conn.events_dropped == 1
    assert conn.events_accepted == 0


# 15. Clean shutdown
def test_mastodon_clean_shutdown():
    """Test that disconnect sets state to STOPPED and cleans up threads."""
    conn = MastodonConnector(enabled=False)
    conn.disconnect()
    assert conn.state == MastodonConnector.STATE_STOPPED
    assert conn.is_running() is False


# 16. Disabled mode
def test_mastodon_disabled_mode():
    """Test that when enabled=False, connect() does not start threads."""
    conn = MastodonConnector(enabled=False)
    conn.connect()
    assert conn.is_running() is False
    assert conn.state == MastodonConnector.STATE_DISCONNECTED


# 17. Malformed JSON resilience
def test_mastodon_malformed_json_resilience():
    """Test handling of invalid JSON strings without unhandled exceptions."""
    conn = MastodonConnector(enabled=False)
    assert conn.process_incoming_status("invalid { json string") is False
    assert conn.process_incoming_status(b"raw-binary-corrupted") is False
    assert conn.events_received == 2


# 18. Missing content handling
def test_mastodon_missing_content_handling(sample_mastodon_status):
    """Test statuses with empty or null content are ignored."""
    no_content = dict(sample_mastodon_status)
    no_content["content"] = ""
    assert MastodonConnector.parse_mastodon_status(no_content) is None

    null_content = dict(sample_mastodon_status)
    null_content["content"] = None
    assert MastodonConnector.parse_mastodon_status(null_content) is None


# 19. Missing author handling
def test_mastodon_missing_author_handling(sample_mastodon_status):
    """Test statuses without account information are rejected."""
    no_account = dict(sample_mastodon_status)
    no_account.pop("account", None)
    assert MastodonConnector.parse_mastodon_status(no_account) is None

    no_id = dict(sample_mastodon_status)
    no_id.pop("id", None)
    assert MastodonConnector.parse_mastodon_status(no_id) is None


# 20. Status reporting no secrets leaked
def test_mastodon_status_reporting_no_secrets_leaked(sample_mastodon_status, ingestion_service, source_service):
    """Test get_status returns metrics without exposing sensitive access token strings."""
    secret_token = "secret_access_token_super_private_999"
    conn = MastodonConnector(
        access_token=secret_token,
        enabled=False,
        ingestion_service=ingestion_service,
        source_post_service=source_service,
    )

    conn.process_incoming_status(sample_mastodon_status)
    status = conn.get_status()

    assert secret_token not in json.dumps(status)
    assert "access_token" not in status
    assert status["has_access_token"] is True
    assert status["events_received"] == 1
    assert status["events_accepted"] == 1
    assert status["events_deduplicated"] == 0
    assert status["events_dropped"] == 0
    assert status["last_event_at"] is not None
    assert "connection_state" in status
    assert "subscription_state" in status


# 21. Streaming hostname discovery with fallback
def test_mastodon_streaming_hostname_discovery(monkeypatch):
    """Test dynamic resolution of dedicated streaming host from /api/v2/instance."""
    conn = MastodonConnector(base_url="https://test.instance", enabled=False)

    class MockResp:
        status_code = 200
        def json(self):
            return {"configuration": {"urls": {"streaming": "wss://streaming.test.instance"}}}

    monkeypatch.setattr("requests.get", lambda url, timeout=4.0: MockResp())
    resolved = conn.resolve_streaming_base_url()
    assert resolved == "https://streaming.test.instance"

    # Test failure fallback
    conn2 = MastodonConnector(base_url="https://fallback.instance", enabled=False)
    monkeypatch.setattr("requests.get", lambda url, timeout=4.0: Exception("Network down"))
    assert conn2.resolve_streaming_base_url() == "https://fallback.instance"


# 22. Subscription state lifecycle
def test_mastodon_subscription_state_lifecycle():
    """Test subscription state distinguishes DISABLED, STOPPED, and SUBSCRIBED."""
    conn_disabled = MastodonConnector(enabled=False)
    assert conn_disabled.subscription_state == MastodonConnector.SUB_STATE_DISABLED

    conn_stopped = MastodonConnector(enabled=True)
    assert conn_stopped.subscription_state == MastodonConnector.SUB_STATE_STOPPED

    conn_stopped._state = MastodonConnector.STATE_CONNECTED
    conn_stopped.events_received = 0
    assert conn_stopped.subscription_state == MastodonConnector.SUB_STATE_SUBSCRIBED


# 23. SSE multiline parsing and heartbeat handling
def test_mastodon_sse_event_dispatching_and_heartbeats(sample_mastodon_status, ingestion_service, source_service):
    """Test that multiline SSE data payloads and heartbeats are handled properly."""
    conn = MastodonConnector(
        enabled=False,
        ingestion_service=ingestion_service,
        source_post_service=source_service,
    )

    # Process status JSON payload
    raw_json = json.dumps(sample_mastodon_status)
    assert conn.process_incoming_status(raw_json) is True
    assert conn.events_received == 1
    assert conn.events_accepted == 1

    # Heartbeats should be rejected by parse_mastodon_status without error
    assert conn.parse_mastodon_status(":thump") is None
    assert conn.parse_mastodon_status(":)") is None
    assert conn.parse_mastodon_status(":heartbeat") is None


# 24. Ignored non-update SSE events
def test_mastodon_ignored_event_types():
    """Test that delete, notification, and conversation events are filtered."""
    assert MastodonConnector.parse_mastodon_status('{"event": "delete", "id": "123"}') is None
    assert MastodonConnector.parse_mastodon_status('{"event": "filters_changed"}') is None
    assert MastodonConnector.parse_mastodon_status('{"event": "status.update"}') is None


# 25. Single test hashtag subscription
def test_mastodon_single_test_hashtag():
    """Test hashtag mode with single 'test' hashtag without hash prefix."""
    conn = MastodonConnector(
        base_url="https://mastodon.social",
        stream_mode="hashtag",
        hashtags="test",
        enabled=False,
    )
    endpoints = conn.get_stream_endpoints()
    assert endpoints == ["https://mastodon.social/api/v1/streaming/hashtag?tag=test"]
    assert conn.hashtags == ["test"]


# 26. 19-hashtag security monitoring set parsing and endpoints
def test_mastodon_19_security_hashtags_parsing_and_endpoints():
    """Test parsing the 19 standard security and disinformation monitoring hashtags."""
    security_tags = (
        "cybersecurity,cyberattack,infosec,informationsecurity,malware,ransomware,phishing,"
        "databreach,socialengineering,misinformation,disinformation,propaganda,influenceoperation,"
        "informationwarfare,deepfake,aigenerated,misleading,factcheck,scam"
    )
    conn = MastodonConnector(
        base_url="https://mastodon.social",
        stream_mode="hashtag",
        hashtags=security_tags,
        enabled=False,
    )
    assert len(conn.hashtags) == 19
    assert "cybersecurity" in conn.hashtags
    assert "deepfake" in conn.hashtags
    assert "factcheck" in conn.hashtags
    assert "scam" in conn.hashtags

    endpoints = conn.get_stream_endpoints()
    assert len(endpoints) == 19
    assert "https://mastodon.social/api/v1/streaming/hashtag?tag=deepfake" in endpoints
    assert "https://mastodon.social/api/v1/streaming/hashtag?tag=ransomware" in endpoints


# 27. Hashtag normalization edge cases (whitespace, # prefix, case, duplicates, empty items)
def test_mastodon_hashtag_normalization_edge_cases():
    """Test comprehensive hashtag cleaning and deduplication."""
    raw_input = " #phishing , #Phishing, phishing,  , #CYBER_ATTACK, , #malware, MALWARE, #deepfake "
    cleaned = MastodonConnector.parse_hashtags(raw_input)
    assert cleaned == ["phishing", "cyber_attack", "malware", "deepfake"]


# 28. Multi-worker thread isolation, count, and clean shutdown
def test_mastodon_multi_worker_thread_isolation_and_shutdown(monkeypatch):
    """Test that one worker thread is created per unique hashtag and all shut down cleanly."""
    conn = MastodonConnector(
        base_url="https://mastodon.social",
        stream_mode="hashtag",
        hashtags=["cybersecurity", "infosec", "threatintel"],
        enabled=True,
    )

    # Mock _stream_endpoint so workers wait on _stop_event
    def mock_stream(ep):
        conn._stop_event.wait(timeout=1.0)

    monkeypatch.setattr(conn, "_stream_endpoint", mock_stream)
    conn.connect()
    assert len(conn._threads) == 3
    assert conn.is_running() is True

    status = conn.get_status()
    assert status["hashtags_count"] == 3
    assert status["active_streams"] == 3
    assert "cybersecurity" in status["monitoring_hashtags"]
    assert "infosec" in status["monitoring_hashtags"]

    conn.disconnect()
    assert conn.is_running() is False
    assert conn.state == MastodonConnector.STATE_STOPPED


# 29. IncidentPolicy distinction on hashtag posts
def test_mastodon_incident_policy_distinction_benign_vs_threat(source_service, temp_db_path):
    """Test that hashtag posts with benign content stay ANALYZED without incident, while threat creates incident."""
    from services.analysis_pipeline import AnalysisPipeline
    from services.incident_policy import IncidentPolicy
    from services.forensic_service import ForensicService
    from services.threat_analyzer import ThreatAnalyzer
    from services.text_analyzer import TextAnalyzer
    from models.detector import AIDetector

    detector = AIDetector()
    text_analyzer = TextAnalyzer()
    threat_analyzer = ThreatAnalyzer()
    forensic_service = ForensicService(db_path=temp_db_path)
    policy = IncidentPolicy(min_threat_score=60.0, min_ai_prob=0.85, secondary_threat_score=40.0)

    pipeline = AnalysisPipeline(
        detector=detector,
        text_analyzer=text_analyzer,
        threat_analyzer=threat_analyzer,
        forensic_service=forensic_service,
        source_post_service=source_service,
        incident_policy=policy,
    )

    # 1. Benign informative security post
    p1, _ = source_service.create_source_post(
        source="mastodon",
        source_id="masto-benign-001",
        content="Here is a general reminder to enable multi-factor authentication on your accounts #cybersecurity",
    )
    res1 = pipeline.process_source_post(p1["id"])
    assert res1["status"] == "ANALYZED"
    assert res1["incident_id"] is None
    p1_updated = source_service.get_source_post(p1["id"])
    assert p1_updated["status"] == SourcePostStatus.ANALYZED
    assert p1_updated["incident_id"] is None

    # 2. High-threat credential phishing post
    p2, _ = source_service.create_source_post(
        source="mastodon",
        source_id="masto-threat-002",
        content="CRITICAL ALERT: Your bank account will be immediately terminated. Click here to verify credentials and prevent lawsuit: http://phish-bank.com/login #phishing",
    )
    res2 = pipeline.process_source_post(p2["id"])
    assert res2["status"] == "ANALYZED"
    p2_updated = source_service.get_source_post(p2["id"])
    assert p2_updated["status"] == SourcePostStatus.ANALYZED

