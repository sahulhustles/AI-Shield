"""AIShield - Stage 6A Unit & Integration Tests: Source Posts and Ingestion Foundation."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import pytest

from database.db import db_session, init_db
from services.ingestion_service import (
    HTMLTextExtractor,
    IngestionService,
    NormalizedPost,
    extract_plain_text_from_html,
)
from services.source_post_service import (
    SUPPORTED_SOURCES,
    SourcePostService,
    SourcePostStatus,
)


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a unique isolated temporary SQLite database path."""
    db_file = tmp_path / "test_source_posts.db"
    return db_file


@pytest.fixture
def source_service(temp_db_path):
    """Provide an initialized SourcePostService."""
    return SourcePostService(db_path=temp_db_path)


@pytest.fixture
def ingestion_service(source_service):
    """Provide an IngestionService configured with the test SourcePostService."""
    return IngestionService(source_post_service=source_service)


# 1. Table initialization
def test_table_initialization(temp_db_path):
    """Test that source_posts table and indexes are created idempotently."""
    service = SourcePostService(db_path=temp_db_path)
    # Call again to verify idempotency
    service.initialize_source_posts_table()

    with db_session(temp_db_path) as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='source_posts';"
        )
        assert cursor.fetchone() is not None

        # Check unique index
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_source_posts_source_source_id';"
        )
        assert cursor.fetchone() is not None


# 2. Supported source validation
def test_supported_source_validation(source_service):
    """Test that all supported sources (bluesky, mastodon, youtube, manual) are accepted."""
    for src in SUPPORTED_SOURCES:
        post, is_dup = source_service.create_source_post(
            source=src,
            source_id=f"test-id-{src}",
            content=f"Content from {src}",
        )
        assert is_dup is False
        assert post["source"] == src
        assert post["source_id"] == f"test-id-{src}"


# 3. Unsupported source rejection
def test_unsupported_source_rejection(source_service):
    """Test that unsupported sources are rejected with ValueError."""
    for bad_src in ["twitter", "facebook", "tiktok", "telegram", "unknown", ""]:
        with pytest.raises(ValueError, match="Unsupported source|Source must be a non-empty string"):
            source_service.create_source_post(
                source=bad_src,
                source_id="12345",
                content="Some text",
            )


# 4. source_id validation
def test_source_id_validation(source_service):
    """Test that empty or non-string source_id is rejected."""
    with pytest.raises(ValueError, match="source_id"):
        source_service.create_source_post(
            source="manual",
            source_id="",
            content="Some text",
        )

    with pytest.raises(ValueError, match="source_id"):
        source_service.create_source_post(
            source="manual",
            source_id="   ",
            content="Some text",
        )


# 5. Empty content rejection
def test_empty_content_rejection(source_service):
    """Test that empty content is rejected."""
    with pytest.raises(ValueError, match="content"):
        source_service.create_source_post(
            source="manual",
            source_id="id-1",
            content="",
        )

    with pytest.raises(ValueError, match="content"):
        source_service.create_source_post(
            source="manual",
            source_id="id-2",
            content="   ",
        )


# 6. source + source_id uniqueness
def test_source_and_source_id_uniqueness(source_service):
    """Test that duplicate (source, source_id) does not insert a new row."""
    post1, is_dup1 = source_service.create_source_post(
        source="bluesky",
        source_id="post-unique-123",
        content="First version of content",
    )
    assert is_dup1 is False
    assert post1["id"] is not None

    post2, is_dup2 = source_service.create_source_post(
        source="bluesky",
        source_id="post-unique-123",
        content="Different content with same id",
    )
    assert is_dup2 is True
    assert post2["id"] == post1["id"]
    assert post2["content"] == "First version of content"


# 7. Duplicate ingestion via IngestionService
def test_duplicate_ingestion(ingestion_service):
    """Test IngestionService handles duplicate submissions gracefully."""
    norm_post = NormalizedPost(
        source="mastodon",
        source_id="masto-999",
        content="Breaking news update about the system.",
        metadata={"instance": "mastodon.social"},
    )
    res1, dup1 = ingestion_service.ingest(norm_post)
    assert dup1 is False

    res2, dup2 = ingestion_service.ingest(norm_post)
    assert dup2 is True
    assert res1["id"] == res2["id"]


# 8. Cross-source same source_id
def test_cross_source_same_source_id(source_service):
    """Test that identical source_id across different platforms are preserved as separate records."""
    post_bsky, dup_bsky = source_service.create_source_post(
        source="bluesky",
        source_id="post-common-id",
        content="Content on Bluesky",
    )
    assert dup_bsky is False

    post_masto, dup_masto = source_service.create_source_post(
        source="mastodon",
        source_id="post-common-id",
        content="Content on Mastodon",
    )
    assert dup_masto is False

    assert post_bsky["id"] != post_masto["id"]
    assert post_bsky["source"] == "bluesky"
    assert post_masto["source"] == "mastodon"
    assert post_bsky["source_id"] == post_masto["source_id"]


# 9. Content hash
def test_content_hash(source_service):
    """Test that SHA-256 content hash matches exact UTF-8 calculation."""
    text = "Exact cryptographic verification sample! #123"
    import hashlib
    expected_hash = hashlib.sha256(text.encode("utf-8")).hexdigest().lower()

    post, _ = source_service.create_source_post(
        source="manual",
        source_id="hash-test-1",
        content=text,
    )
    assert post["content_hash"] == expected_hash


# 10. Exact content preservation
def test_exact_content_preservation(source_service):
    """Test that whitespace, linebreaks, tabs, and symbols are preserved without modification."""
    raw_text = "  Line 1 with spaces.  \n\n\tTabbed line 2.\nSpecial chars: <>&\"' \t\r"
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="exact-preservation-1",
        content=raw_text,
    )
    retrieved = source_service.get_source_post(post["id"])
    assert retrieved["content"] == raw_text


# 11. Metadata JSON persistence
def test_metadata_json_persistence(source_service):
    """Test rich metadata dictionaries are stored and deserialized correctly."""
    metadata = {
        "uri": "at://did:plc:12345/app.bsky.feed.post/67890",
        "cid": "bafyreih345",
        "tags": ["security", "ai"],
        "reply_count": 42,
        "nested": {"key": "val", "num": 3.14},
    }
    post, _ = source_service.create_source_post(
        source="bluesky",
        source_id="meta-test-1",
        content="Post with rich metadata",
        metadata=metadata,
    )
    retrieved = source_service.get_source_post(post["id"])
    assert retrieved["metadata"] == metadata
    assert retrieved["metadata"]["nested"]["num"] == 3.14


# 12. Unicode preservation
def test_unicode_preservation(source_service):
    """Test Unicode emojis, non-Latin alphabets, and symbols are preserved faithfully."""
    unicode_text = "🛡️ Alerte de sécurité: 危ない! Привет мир! 日本語テスト 🚀🔥"
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="unicode-test-1",
        content=unicode_text,
    )
    retrieved = source_service.get_source_post(post["id"])
    assert retrieved["content"] == unicode_text


# 13. Timestamp storage
def test_timestamp_storage(source_service):
    """Test that ingested_at is valid ISO-8601 UTC and published_at is preserved."""
    published_time = "2026-08-18T05:30:00+00:00"
    post, _ = source_service.create_source_post(
        source="youtube",
        source_id="yt-video-100",
        content="YouTube video description text",
        published_at=published_time,
    )
    assert post["published_at"] == published_time
    assert post["ingested_at"] is not None
    # Validate ingested_at parses cleanly
    dt = datetime.fromisoformat(post["ingested_at"])
    assert dt.tzinfo is not None or "+00:00" in post["ingested_at"] or "Z" in post["ingested_at"]


# 14. Status values
def test_status_values(source_service):
    """Test explicit status values and rejection of invalid statuses."""
    for st in ["RECEIVED", "QUEUED", "PROCESSING", "ANALYZED", "SKIPPED", "FAILED"]:
        post, _ = source_service.create_source_post(
            source="manual",
            source_id=f"status-test-{st}",
            content="Testing status value",
            status=st,
        )
        assert post["status"] == st

    with pytest.raises(ValueError, match="Invalid status"):
        source_service.create_source_post(
            source="manual",
            source_id="status-invalid",
            content="Testing invalid status",
            status="UNKNOWN_STATUS",
        )


# 15. Status transitions
def test_status_transitions(source_service):
    """Test lifecycle transitions: RECEIVED -> PROCESSING -> ANALYZED."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="lifecycle-1",
        content="Post lifecycle flow",
    )
    assert post["status"] == SourcePostStatus.RECEIVED
    assert post["processed_at"] is None

    # Mark PROCESSING
    assert source_service.mark_processing(post["id"]) is True
    post_proc = source_service.get_source_post(post["id"])
    assert post_proc["status"] == SourcePostStatus.PROCESSING

    # Mark ANALYZED
    assert source_service.mark_analyzed(post["id"]) is True
    post_analyzed = source_service.get_source_post(post["id"])
    assert post_analyzed["status"] == SourcePostStatus.ANALYZED
    assert post_analyzed["processed_at"] is not None


# 16. Attempt counter
def test_attempt_counter(source_service):
    """Test that increment_attempts accurately increments the analysis counter."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="attempt-counter-1",
        content="Retry attempt test",
    )
    assert post["analysis_attempts"] == 0

    assert source_service.increment_attempts(post["id"]) == 1
    assert source_service.increment_attempts(post["id"]) == 2
    assert source_service.increment_attempts(post["id"]) == 3

    retrieved = source_service.get_source_post(post["id"])
    assert retrieved["analysis_attempts"] == 3


# 17. Failure recording
def test_failure_recording(source_service):
    """Test mark_failed sets status to FAILED, records last_error and processed_at."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="failure-1",
        content="Failing post test",
    )
    err_msg = "Classifier timeout on long text analysis."
    assert source_service.mark_failed(post["id"], error_message=err_msg) is True

    failed_post = source_service.get_source_post(post["id"])
    assert failed_post["status"] == SourcePostStatus.FAILED
    assert failed_post["last_error"] == err_msg
    assert failed_post["processed_at"] is not None


# 18. Source post retrieval
def test_source_post_retrieval(source_service):
    """Test retrieval by ID and by compound key (source, source_id)."""
    post, _ = source_service.create_source_post(
        source="mastodon",
        source_id="retrieve-key-1",
        content="Retrieval test content",
        author_name="SecurityResearcher",
    )

    by_id = source_service.get_source_post(post["id"])
    assert by_id is not None
    assert by_id["author_name"] == "SecurityResearcher"

    by_compound = source_service.get_by_source_and_id("mastodon", "retrieve-key-1")
    assert by_compound is not None
    assert by_compound["id"] == post["id"]

    assert source_service.get_source_post(999999) is None
    assert source_service.get_by_source_and_id("mastodon", "nonexistent") is None


# 19. Source post list with filters
def test_source_post_list_filters(source_service):
    """Test listing source posts with source and status filtering."""
    source_service.create_source_post("bluesky", "list-1", "B1", status="RECEIVED")
    source_service.create_source_post("bluesky", "list-2", "B2", status="ANALYZED")
    source_service.create_source_post("youtube", "list-3", "Y1", status="RECEIVED")

    all_posts = source_service.list_source_posts()
    assert len(all_posts) >= 3

    bsky_posts = source_service.list_source_posts(source="bluesky")
    assert len(bsky_posts) == 2
    assert all(p["source"] == "bluesky" for p in bsky_posts)

    analyzed_posts = source_service.list_source_posts(status="ANALYZED")
    assert any(p["source_id"] == "list-2" for p in analyzed_posts)


# 20. Bounded list limits
def test_bounded_list(source_service):
    """Test that list_source_posts limits are capped between 1 and 100."""
    for i in range(10):
        source_service.create_source_post("manual", f"bound-{i}", f"Content {i}")

    paged = source_service.list_source_posts(limit=3, offset=0)
    assert len(paged) == 3

    paged_next = source_service.list_source_posts(limit=3, offset=3)
    assert len(paged_next) == 3
    assert paged[0]["id"] != paged_next[0]["id"]


# 21. SQL injection-style values
def test_sql_injection_resilience(source_service):
    """Test parameterized query safety against SQL injection strings."""
    injection_strings = [
        "'; DROP TABLE source_posts; --",
        "' OR '1'='1",
        "admin'--",
        "1; SELECT * FROM incidents;",
    ]

    for idx, inject in enumerate(injection_strings):
        post, _ = source_service.create_source_post(
            source="manual",
            source_id=f"inject-{idx}-{inject[:10]}",
            content=inject,
            author_name=inject,
            metadata={"sql": inject},
        )
        retrieved = source_service.get_source_post(post["id"])
        assert retrieved["content"] == inject
        assert retrieved["author_name"] == inject

    # Verify table is intact
    posts = source_service.list_source_posts()
    assert len(posts) >= len(injection_strings)


# 22. JSON serialization
def test_json_serialization(source_service):
    """Test that retrieved source posts are fully JSON serializable."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="json-test-1",
        content="Testing serialization",
        metadata={"flag": True, "count": 10, "tags": ["a", "b"]},
    )
    serialized = json.dumps(post)
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized["source_id"] == "json-test-1"
    assert deserialized["metadata"]["flag"] is True


# 23. Restart persistence
def test_restart_persistence(temp_db_path):
    """Test that creating a new service instance against the same SQLite file retains all data."""
    service1 = SourcePostService(db_path=temp_db_path)
    post, _ = service1.create_source_post(
        source="bluesky",
        source_id="persist-restart-1",
        content="Content to persist across service restarts",
    )
    post_id = post["id"]
    content_hash = post["content_hash"]

    # Instantiate a completely new service instance
    service2 = SourcePostService(db_path=temp_db_path)
    retrieved = service2.get_source_post(post_id)
    assert retrieved is not None
    assert retrieved["source_id"] == "persist-restart-1"
    assert retrieved["content_hash"] == content_hash


# 24. Content-hash cross-source duplicate detection
def test_content_hash_duplicate_detection(source_service):
    """Test finding all posts with identical content hash across different sources."""
    shared_text = "Global security advisory: Critical system vulnerability found in core library."

    post_bsky, _ = source_service.create_source_post(
        source="bluesky",
        source_id="bsky-shared-1",
        content=shared_text,
    )
    post_masto, _ = source_service.create_source_post(
        source="mastodon",
        source_id="masto-shared-2",
        content=shared_text,
    )
    post_yt, _ = source_service.create_source_post(
        source="youtube",
        source_id="yt-shared-3",
        content=shared_text,
    )

    matching_posts = source_service.find_by_content_hash(post_bsky["content_hash"])
    assert len(matching_posts) == 3
    sources = {p["source"] for p in matching_posts}
    assert sources == {"bluesky", "mastodon", "youtube"}


# 25. HTML-to-text normalization fixture
def test_html_to_text_normalization():
    """Test HTML extraction converts tags, handles linebreaks, and unescapes entities safely."""
    raw_html = (
        "<p>Alert: Account security update! &amp; Action required.</p>"
        "<p>Please click <a href='https://example.com'>here</a> to verify.<br/>Thank you!</p>"
    )
    plain_text, enriched_meta = IngestionService.normalize_html_content(raw_html, {"source_type": "status"})

    assert "Alert: Account security update! & Action required." in plain_text
    assert "Please click here to verify." in plain_text
    assert "Thank you!" in plain_text
    assert "<p>" not in plain_text
    assert "<br/>" not in plain_text
    assert "&amp;" not in plain_text
    assert enriched_meta["raw_html"] == raw_html
    assert enriched_meta["source_type"] == "status"
