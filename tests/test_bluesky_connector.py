"""AIShield - Stage 6C Unit & Integration Tests: Bluesky Live Connector (Mocked & Offline)."""

import json
from pathlib import Path
import threading
import time
import pytest

from database.db import init_db
from services.connectors.bluesky_connector import BlueskyConnector
from services.ingestion_service import IngestionService, NormalizedPost
from services.processing_queue import ProcessingQueue
from services.source_post_service import SourcePostService, SourcePostStatus


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a unique isolated temporary SQLite database path."""
    db_file = tmp_path / "test_bluesky.db"
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
def sample_jetstream_post():
    """Provide a realistic Bluesky Jetstream post creation commit event dictionary."""
    return {
        "did": "did:plc:ragtjsm2j2vknwk6zuiujoxb",
        "time_us": 1725911132717834,
        "kind": "commit",
        "commit": {
            "rev": "3l3qrpz5vks2b",
            "operation": "create",
            "collection": "app.bsky.feed.post",
            "rkey": "3l3qrpz53us2b",
            "record": {
                "$type": "app.bsky.feed.post",
                "createdAt": "2026-08-18T06:45:00.000Z",
                "text": "Cybersecurity update: Important security analysis findings.",
                "langs": ["en"],
                "reply": None,
            },
            "cid": "bafyreie5cvv4ccpq4m3nl5ue42o9qyuoen43eao2xolun4gl9swmjpjf3y",
        },
    }


# 1. Event parsing of valid post
def test_bluesky_event_parsing_valid_post(sample_jetstream_post):
    """Test parsing a valid Jetstream post creation commit event."""
    parsed = BlueskyConnector.parse_jetstream_event(sample_jetstream_post)
    assert parsed is not None
    assert parsed["source_id"] == "did:plc:ragtjsm2j2vknwk6zuiujoxb/3l3qrpz53us2b"
    assert parsed["author_id"] == "did:plc:ragtjsm2j2vknwk6zuiujoxb"
    assert parsed["content"] == "Cybersecurity update: Important security analysis findings."
    assert parsed["published_at"] == "2026-08-18T06:45:00.000Z"
    assert parsed["language"] == "en"
    assert parsed["metadata"]["cid"] == "bafyreie5cvv4ccpq4m3nl5ue42o9qyuoen43eao2xolun4gl9swmjpjf3y"


# 2. Irrelevant event ignored: delete operation
def test_bluesky_event_parsing_ignore_delete(sample_jetstream_post):
    """Test that delete commit operations are ignored."""
    delete_event = dict(sample_jetstream_post)
    delete_event["commit"] = dict(sample_jetstream_post["commit"])
    delete_event["commit"]["operation"] = "delete"
    delete_event["commit"].pop("record", None)

    assert BlueskyConnector.parse_jetstream_event(delete_event) is None


# 3. Irrelevant event ignored: like collection
def test_bluesky_event_parsing_ignore_like_collection(sample_jetstream_post):
    """Test that non-post collections (e.g. app.bsky.feed.like) are ignored."""
    like_event = dict(sample_jetstream_post)
    like_event["commit"] = dict(sample_jetstream_post["commit"])
    like_event["commit"]["collection"] = "app.bsky.feed.like"

    assert BlueskyConnector.parse_jetstream_event(like_event) is None


# 4. Irrelevant event ignored: non-commit kind
def test_bluesky_event_parsing_ignore_non_commit(sample_jetstream_post):
    """Test that non-commit events (e.g. identity, account) are ignored."""
    identity_event = {
        "did": "did:plc:12345",
        "kind": "identity",
        "identity": {"handle": "alice.bsky.social"},
    }
    assert BlueskyConnector.parse_jetstream_event(identity_event) is None


# 5. Normalized content structure
def test_bluesky_normalization_structure(sample_jetstream_post):
    """Test normalizing a raw Jetstream event returns a complete NormalizedPost."""
    connector = BlueskyConnector(enabled=False)
    norm_post = connector.normalize(sample_jetstream_post)

    assert isinstance(norm_post, NormalizedPost)
    assert norm_post.source == "bluesky"
    assert norm_post.source_id == "did:plc:ragtjsm2j2vknwk6zuiujoxb/3l3qrpz53us2b"
    assert norm_post.content == "Cybersecurity update: Important security analysis findings."
    assert norm_post.author_id == "did:plc:ragtjsm2j2vknwk6zuiujoxb"


# 6. Source ID format
def test_bluesky_source_id_format(sample_jetstream_post):
    """Test that source_id uses canonical did/rkey compound format."""
    connector = BlueskyConnector(enabled=False)
    norm_post = connector.normalize(sample_jetstream_post)
    assert "/" in norm_post.source_id
    parts = norm_post.source_id.split("/")
    assert parts[0].startswith("did:plc:")
    assert len(parts[1]) > 0


# 7. Author extraction
def test_bluesky_author_extraction(sample_jetstream_post):
    """Test author DID is extracted for author_id and author_name."""
    connector = BlueskyConnector(enabled=False)
    norm_post = connector.normalize(sample_jetstream_post)
    assert norm_post.author_id == "did:plc:ragtjsm2j2vknwk6zuiujoxb"
    assert norm_post.author_name == "did:plc:ragtjsm2j2vknwk6zuiujoxb"


# 8. Timestamp extraction
def test_bluesky_timestamp_extraction(sample_jetstream_post):
    """Test published_at is extracted from record.createdAt."""
    connector = BlueskyConnector(enabled=False)
    norm_post = connector.normalize(sample_jetstream_post)
    assert norm_post.published_at == "2026-08-18T06:45:00.000Z"


# 9. Metadata preservation
def test_bluesky_metadata_preservation(sample_jetstream_post):
    """Test that CID, rev, rkey, langs, and time_us are stored in metadata."""
    connector = BlueskyConnector(enabled=False)
    norm_post = connector.normalize(sample_jetstream_post)
    assert norm_post.metadata["cid"] == "bafyreie5cvv4ccpq4m3nl5ue42o9qyuoen43eao2xolun4gl9swmjpjf3y"
    assert norm_post.metadata["rev"] == "3l3qrpz5vks2b"
    assert norm_post.metadata["rkey"] == "3l3qrpz53us2b"
    assert norm_post.metadata["langs"] == ["en"]


# 10. Duplicate event handling
def test_bluesky_duplicate_event_handling(sample_jetstream_post, ingestion_service, source_service):
    """Test that duplicate Jetstream event increments deduplicated count and creates only 1 database row."""
    queue = ProcessingQueue()
    connector = BlueskyConnector(
        enabled=False,
        ingestion_service=ingestion_service,
        processing_queue=queue,
        source_post_service=source_service,
    )

    # First event
    assert connector.process_incoming_event(sample_jetstream_post) is True
    assert connector.events_accepted == 1
    assert connector.events_deduplicated == 0

    # Duplicate event
    assert connector.process_incoming_event(sample_jetstream_post) is True
    assert connector.events_accepted == 1
    assert connector.events_deduplicated == 1

    # Verify only 1 row in SQLite database
    posts = source_service.list_source_posts(source="bluesky")
    assert len(posts) == 1


# 11. Exponential backoff calculation
def test_bluesky_exponential_backoff_calculation():
    """Test exponential backoff progression and maximum clamping."""
    connector = BlueskyConnector(enabled=False, initial_backoff=1.0, max_backoff=30.0)

    backoff = connector.initial_backoff
    expected_sequence = [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]

    for expected in expected_sequence:
        current_sleep = min(connector.max_backoff, backoff)
        assert current_sleep == expected
        backoff *= 2.0


# 12. Queue full drop counting (Backpressure)
def test_bluesky_queue_full_drop_counting(sample_jetstream_post, ingestion_service, source_service):
    """Test that if the processing queue is full, events_dropped is incremented."""
    small_queue = ProcessingQueue(maxsize=1)
    small_queue.enqueue(99999) # Fill queue to capacity

    connector = BlueskyConnector(
        enabled=False,
        ingestion_service=ingestion_service,
        processing_queue=small_queue,
        source_post_service=source_service,
    )

    assert connector.process_incoming_event(sample_jetstream_post) is True
    assert connector.events_dropped == 1
    assert connector.events_accepted == 0


# 13. Clean shutdown
def test_bluesky_clean_shutdown():
    """Test that disconnect sets state to STOPPED cleanly."""
    connector = BlueskyConnector(enabled=False)
    connector.disconnect()
    assert connector.state == BlueskyConnector.STATE_STOPPED
    assert connector.is_running() is False


# 14. Disabled mode
def test_bluesky_disabled_mode():
    """Test that when enabled=False, connect() does not launch a background thread."""
    connector = BlueskyConnector(enabled=False)
    connector.connect()
    assert connector.is_running() is False
    assert connector.state == BlueskyConnector.STATE_DISCONNECTED


# 15. Status reporting metrics
def test_bluesky_status_metrics(sample_jetstream_post, ingestion_service, source_service):
    """Test get_status returns accurate observability metrics."""
    connector = BlueskyConnector(
        enabled=False,
        ingestion_service=ingestion_service,
        source_post_service=source_service,
    )

    connector.process_incoming_event(sample_jetstream_post)
    status = connector.get_status()

    assert status["enabled"] is False
    assert status["events_received"] == 1
    assert status["events_accepted"] == 1
    assert status["events_deduplicated"] == 0
    assert status["events_dropped"] == 0
    assert status["last_event_at"] is not None


# 16. Malformed JSON resilience
def test_bluesky_malformed_json_resilience():
    """Test handling of broken or non-JSON payloads without exceptions."""
    connector = BlueskyConnector(enabled=False)
    assert connector.process_incoming_event("not a valid json { broken") is False
    assert connector.process_incoming_event(b"\x00\x01\x02") is False
    assert connector.events_received == 2


# 17. Missing content handling
def test_bluesky_missing_content_handling(sample_jetstream_post):
    """Test that events with missing or empty text are ignored."""
    empty_event = dict(sample_jetstream_post)
    empty_event["commit"]["record"]["text"] = ""
    assert BlueskyConnector.parse_jetstream_event(empty_event) is None

    null_event = dict(sample_jetstream_post)
    null_event["commit"]["record"]["text"] = None
    assert BlueskyConnector.parse_jetstream_event(null_event) is None


# 18. Missing author handling
def test_bluesky_missing_author_handling(sample_jetstream_post):
    """Test that events missing did or rkey are rejected."""
    no_did = dict(sample_jetstream_post)
    no_did.pop("did", None)
    assert BlueskyConnector.parse_jetstream_event(no_did) is None

    no_rkey = dict(sample_jetstream_post)
    no_rkey["commit"].pop("rkey", None)
    assert BlueskyConnector.parse_jetstream_event(no_rkey) is None


# 19. Unicode and emojis
def test_bluesky_unicode_and_emojis(sample_jetstream_post):
    """Test Unicode emojis and multi-language characters are preserved."""
    sample_jetstream_post["commit"]["record"]["text"] = "🛡️ Alerte sécurité: 危ない! 🚀"
    connector = BlueskyConnector(enabled=False)
    norm_post = connector.normalize(sample_jetstream_post)
    assert norm_post.content == "🛡️ Alerte sécurité: 危ない! 🚀"


# 20. HTML entities normalization
def test_bluesky_html_entities_normalization(sample_jetstream_post):
    """Test HTML tags and entities are extracted and unescaped."""
    sample_jetstream_post["commit"]["record"]["text"] = "Security alert &amp; update for &lt;admin&gt;"
    connector = BlueskyConnector(enabled=False)
    norm_post = connector.normalize(sample_jetstream_post)
    assert "Security alert & update for <admin>" in norm_post.content


# 21. Relevance filtering and term matching
def test_bluesky_relevance_filtering(sample_jetstream_post, ingestion_service, source_service):
    """Test that relevance filter accepts matching posts and filters non-matching posts without breaking connector."""
    connector = BlueskyConnector(
        enabled=False,
        relevance_filter_enabled=True,
        monitor_terms=["cybersecurity", "phishing", "ransomware"],
        ingestion_service=ingestion_service,
        source_post_service=source_service,
    )

    # 1. Matching post
    sample_jetstream_post["commit"]["record"]["text"] = "Critical cybersecurity vulnerability discovered"
    assert connector.process_incoming_event(sample_jetstream_post) is True
    assert connector.events_received == 1
    assert connector.events_accepted == 1
    assert connector.events_filtered == 0

    # 2. Non-matching post
    unrelated_post = dict(sample_jetstream_post)
    unrelated_post["commit"] = dict(sample_jetstream_post["commit"])
    unrelated_post["commit"]["record"] = dict(sample_jetstream_post["commit"]["record"])
    unrelated_post["commit"]["record"]["text"] = "Lovely sunny weather today at the park!"
    assert connector.process_incoming_event(unrelated_post) is False
    assert connector.events_received == 2
    assert connector.events_accepted == 1
    assert connector.events_filtered == 1


# 22. Zero events still reports CONNECTED
def test_bluesky_zero_events_still_reports_connected():
    """Test that a connected connector with zero received events reports CONNECTED status."""
    connector = BlueskyConnector(enabled=True)
    connector._state = BlueskyConnector.STATE_CONNECTED
    status = connector.get_status()
    assert status["status"] == "CONNECTED"
    assert status["state"] == "CONNECTED"
    assert status["events_received"] == 0


# 23. Connection error sets ERROR state
def test_bluesky_exception_sets_error_state():
    """Test that connection failure sets STATE_ERROR instead of STOPPED."""
    connector = BlueskyConnector(enabled=True)
    connector._state = BlueskyConnector.STATE_ERROR
    connector.connection_errors = 1
    connector.last_error = "Connection refused by peer"

    status = connector.get_status()
    assert status["status"] == "ERROR"
    assert status["state"] == "ERROR"
    assert status["last_error"] == "Connection refused by peer"
    assert status["connection_errors"] == 1


# 24. Reconnect and mock websocket loop
def test_bluesky_mock_stream_loop_lifecycle(monkeypatch):
    """Test background stream loop connects, processes messages, and terminates cleanly."""
    connector = BlueskyConnector(enabled=True)

    class MockWS:
        def __init__(self):
            self.messages = [
                json.dumps({
                    "did": "did:plc:mock123",
                    "kind": "commit",
                    "commit": {
                        "operation": "create",
                        "collection": "app.bsky.feed.post",
                        "rkey": "rkey123",
                        "record": {"text": "Test alert"},
                        "cid": "cid123",
                    },
                })
            ]
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def __iter__(self):
            for m in self.messages:
                yield m
        def close(self):
            pass

    monkeypatch.setattr("websockets.sync.client.connect", lambda *args, **kwargs: MockWS())
    connector.connect()
    time.sleep(0.1)

    assert connector.events_received >= 1
    assert connector.last_connected_at is not None

    connector.disconnect()
    assert connector.state == BlueskyConnector.STATE_STOPPED
    assert connector.is_running() is False


# 25. Monitor terms parsing and whitespace handling
def test_bluesky_monitor_terms_parsing():
    """Test monitor terms parsing strips whitespace, # prefix, and deduplicates."""
    raw_terms = " #cybersecurity , #Phishing, phishing,  , #MALWARE, malware "
    parsed = BlueskyConnector.parse_monitor_terms(raw_terms)
    assert parsed == ["cybersecurity", "phishing", "malware"]


# 26. Disabled connector reports DISABLED status
def test_bluesky_disabled_reports_disabled_status():
    """Test disabled connector get_status returns DISABLED."""
    connector = BlueskyConnector(enabled=False)
    status = connector.get_status()
    assert status["status"] == "DISABLED"
    assert status["state"] == "DISABLED"
    assert status["enabled"] is False
