"""AIShield - Stage 6E Unit & Integration Tests: YouTube Keyword Polling Connector (Mocked & Offline)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import requests

from database.db import init_db
from services.connectors.youtube_connector import YouTubeConnector
from services.ingestion_service import IngestionService, NormalizedPost
from services.processing_queue import ProcessingQueue
from services.source_post_service import SourcePostService, SourcePostStatus


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a unique isolated temporary SQLite database path."""
    db_file = tmp_path / "test_youtube.db"
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
def sample_youtube_item():
    """Provide a realistic YouTube search API video item dictionary."""
    return {
        "kind": "youtube#searchResult",
        "etag": "etag_12345",
        "id": {
            "kind": "youtube#video",
            "videoId": "dQw4w9WgXcQ",
        },
        "snippet": {
            "publishedAt": "2026-08-18T07:30:00Z",
            "channelId": "UCuAXFkgsw1L7xaCfnd5JJOw",
            "title": "Critical Infrastructure Cyber Attack Threat Briefing",
            "description": "Comprehensive analysis of new ransomware vectors targeting energy infrastructure and industrial control systems.",
            "thumbnails": {
                "default": {
                    "url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/default.jpg",
                    "width": 120,
                    "height": 90,
                },
                "high": {
                    "url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg",
                    "width": 480,
                    "height": 360,
                },
            },
            "channelTitle": "CyberDefenders Intelligence",
            "liveBroadcastContent": "none",
        },
    }


# 1. API request parameter construction
def test_youtube_api_request_construction():
    """Test query parameter construction for search API requests."""
    conn = YouTubeConnector(
        api_key="test_fake_api_key_999",
        queries="cybersecurity threat,phishing",
        region_code="US",
        language="en",
        max_results=15,
        enabled=False,
    )

    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"items": []}
        mock_get.return_value = mock_resp

        conn.fetch_once("cybersecurity threat")

        assert mock_get.called
        args, kwargs = mock_get.call_args
        assert args[0] == "https://www.googleapis.com/youtube/v3/search"
        params = kwargs["params"]
        assert params["part"] == "snippet"
        assert params["q"] == "cybersecurity threat"
        assert params["type"] == "video"
        assert params["maxResults"] == 15
        assert params["order"] == "date"
        assert params["regionCode"] == "US"
        assert params["relevanceLanguage"] == "en"
        assert params["key"] == "test_fake_api_key_999"


# 2. API key handling
def test_youtube_api_key_header_or_param_handling():
    """Test API key is retained internally but never leaked."""
    conn = YouTubeConnector(api_key="super_secret_yt_key_xyz", enabled=False)
    assert conn._api_key == "super_secret_yt_key_xyz"
    status = conn.get_status()
    assert "super_secret_yt_key_xyz" not in json.dumps(status)
    assert status["has_api_key"] is True


# 3. Query parsing and cleaning
def test_youtube_query_parsing_and_cleaning():
    """Test parsing, trimming, and deduplicating search queries."""
    queries = YouTubeConnector.parse_queries("cybersecurity,  phishing scam , Cybersecurity, ai threats ")
    assert queries == ["cybersecurity", "phishing scam", "ai threats"]

    queries_list = YouTubeConnector.parse_queries(["#malware", "ransomware", "#malware"])
    assert queries_list == ["#malware", "ransomware"]


# 4. Video item parsing
def test_youtube_video_item_parsing(sample_youtube_item):
    """Test parsing a raw YouTube search video item into standardized dictionary."""
    parsed = YouTubeConnector.parse_youtube_item(sample_youtube_item)
    assert parsed is not None
    assert parsed["source_id"] == "dQw4w9WgXcQ"
    assert parsed["author_id"] == "UCuAXFkgsw1L7xaCfnd5JJOw"
    assert parsed["author_name"] == "CyberDefenders Intelligence"
    assert parsed["title"] == "Critical Infrastructure Cyber Attack Threat Briefing"
    assert "ransomware vectors" in parsed["description"]
    assert parsed["published_at"] == "2026-08-18T07:30:00Z"
    assert "https://i.ytimg.com/vi/dQw4w9WgXcQ/default.jpg" in parsed["metadata"]["thumbnail_url"]


# 5. Source ID and URL
def test_youtube_source_id_and_url(sample_youtube_item):
    """Test source_id is videoId and source_url is canonical watch URL."""
    conn = YouTubeConnector(enabled=False)
    norm_post = conn.normalize(sample_youtube_item)
    assert norm_post.source == "youtube"
    assert norm_post.source_id == "dQw4w9WgXcQ"
    assert norm_post.source_url == "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


# 6. Title and description combination
def test_youtube_content_title_description_combination(sample_youtube_item):
    """Test title and description are concatenated cleanly with double newline."""
    conn = YouTubeConnector(enabled=False)
    norm_post = conn.normalize(sample_youtube_item)

    expected_prefix = "Critical Infrastructure Cyber Attack Threat Briefing\n\nComprehensive analysis"
    assert norm_post.content.startswith(expected_prefix)


# 7. Channel metadata extraction
def test_youtube_channel_author_extraction(sample_youtube_item):
    """Test channel ID and channel title extraction."""
    conn = YouTubeConnector(enabled=False)
    norm_post = conn.normalize(sample_youtube_item)
    assert norm_post.author_id == "UCuAXFkgsw1L7xaCfnd5JJOw"
    assert norm_post.author_name == "CyberDefenders Intelligence"


# 8. Published timestamp extraction
def test_youtube_published_timestamp_extraction(sample_youtube_item):
    """Test publishedAt timestamp is retained."""
    conn = YouTubeConnector(enabled=False)
    norm_post = conn.normalize(sample_youtube_item)
    assert norm_post.published_at == "2026-08-18T07:30:00Z"


# 9. Metadata preservation
def test_youtube_metadata_preservation(sample_youtube_item):
    """Test metadata fields are preserved in normalized post."""
    conn = YouTubeConnector(enabled=False)
    norm_post = conn.normalize(sample_youtube_item)
    assert norm_post.metadata["videoId"] == "dQw4w9WgXcQ"
    assert norm_post.metadata["channelId"] == "UCuAXFkgsw1L7xaCfnd5JJOw"
    assert norm_post.metadata["thumbnail_url"] is not None


# 10. Duplicate video deduplication
def test_youtube_duplicate_video_deduplication(sample_youtube_item, ingestion_service, source_service):
    """Test duplicate video item across queries increments items_deduplicated and creates 1 row."""
    queue = ProcessingQueue()
    conn = YouTubeConnector(
        api_key="test_key",
        enabled=False,
        ingestion_service=ingestion_service,
        processing_queue=queue,
        source_post_service=source_service,
    )

    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"items": [sample_youtube_item]}
        mock_get.return_value = mock_resp

        # Poll 1
        res1 = conn.fetch_once("query1")
        assert len(res1) == 1
        assert conn.items_accepted == 1
        assert conn.items_deduplicated == 0

        # Poll 2 with identical video
        res2 = conn.fetch_once("query2")
        assert len(res2) == 1
        assert conn.items_accepted == 1
        assert conn.items_deduplicated == 1

        # Check database
        posts = source_service.list_source_posts(source="youtube")
        assert len(posts) == 1
        assert posts[0]["source_id"] == "dQw4w9WgXcQ"


# 11. HTTP 400 Bad Request
def test_youtube_http_400_bad_request():
    """Test handling of HTTP 400 without unhandled exception."""
    conn = YouTubeConnector(api_key="test_key", enabled=False)
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request: Invalid parameter value"
        mock_get.return_value = mock_resp

        res = conn.fetch_once("query")
        assert res == []
        assert conn.connection_errors == 1
        assert conn.state == YouTubeConnector.STATE_ERROR


# 12. HTTP 401 Unauthorized
def test_youtube_http_401_unauthorized():
    """Test handling of HTTP 401 invalid API key."""
    conn = YouTubeConnector(api_key="invalid_key", enabled=False)
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "API key not valid."
        mock_get.return_value = mock_resp

        res = conn.fetch_once("query")
        assert res == []
        assert conn.connection_errors == 1
        assert conn.state == YouTubeConnector.STATE_ERROR


# 13. HTTP 403 Quota exceeded
def test_youtube_http_403_quota_exceeded():
    """Test handling of HTTP 403 quota exceeded."""
    conn = YouTubeConnector(api_key="test_key", enabled=False)
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "The request cannot be completed because you have exceeded your quota."
        mock_get.return_value = mock_resp

        res = conn.fetch_once("query")
        assert res == []
        assert conn.quota_errors == 1
        assert conn.state == YouTubeConnector.STATE_QUOTA_LIMIT_REACHED


# 14. HTTP 429 Rate limited
def test_youtube_http_429_rate_limited():
    """Test handling of HTTP 429 rate limit."""
    conn = YouTubeConnector(api_key="test_key", enabled=False)
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "Too Many Requests"
        mock_get.return_value = mock_resp

        res = conn.fetch_once("query")
        assert res == []
        assert conn.quota_errors == 1
        assert conn.state == YouTubeConnector.STATE_ERROR


# 15. HTTP 500 Transient error
def test_youtube_http_500_transient_error():
    """Test handling of HTTP 500 server error."""
    conn = YouTubeConnector(api_key="test_key", enabled=False)
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_get.return_value = mock_resp

        res = conn.fetch_once("query")
        assert res == []
        assert conn.connection_errors == 1
        assert conn.state == YouTubeConnector.STATE_ERROR


# 16. Request timeout handling
def test_youtube_timeout_handling():
    """Test request timeout handling."""
    conn = YouTubeConnector(api_key="test_key", enabled=False)
    with patch("requests.get", side_effect=requests.Timeout("Connection timed out")):
        res = conn.fetch_once("query")
        assert res == []
        assert conn.connection_errors == 1
        assert conn.state == YouTubeConnector.STATE_ERROR


# 17. Malformed JSON response resilience
def test_youtube_malformed_json_resilience():
    """Test handling of invalid JSON response from server."""
    conn = YouTubeConnector(api_key="test_key", enabled=False)
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_resp

        res = conn.fetch_once("query")
        assert res == []


# 18. Daily quota safety limit enforcement
def test_youtube_daily_quota_limit_enforcement():
    """Test that reaching max_requests_per_day stops requests and sets QUOTA_LIMIT_REACHED."""
    conn = YouTubeConnector(
        api_key="test_key",
        max_requests_per_day=2,
        enabled=False,
    )

    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"items": []}
        mock_get.return_value = mock_resp

        # Request 1
        conn.fetch_once("q1")
        assert conn.requests_today == 1

        # Request 2
        conn.fetch_once("q2")
        assert conn.requests_today == 2

        # Request 3 - should be halted locally by quota safety check
        conn.fetch_once("q3")
        assert conn.requests_today == 2 # Did not increment
        assert conn.state == YouTubeConnector.STATE_QUOTA_LIMIT_REACHED
        assert mock_get.call_count == 2 # 3rd request was prevented


# 19. Disabled mode
def test_youtube_disabled_mode():
    """Test that when enabled=False, connect() does not start background thread."""
    conn = YouTubeConnector(api_key="test_key", enabled=False)
    conn.connect()
    assert conn.is_running() is False
    assert conn.state == YouTubeConnector.STATE_DISCONNECTED


# 20. No API key behavior
def test_youtube_no_api_key_mode():
    """Test fetch_once aborts cleanly when API key is empty."""
    conn = YouTubeConnector(api_key="", enabled=False)
    res = conn.fetch_once("query")
    assert res == []
    assert conn.state == YouTubeConnector.STATE_ERROR


# 21. Status reporting with zero secret leakage
def test_youtube_status_reporting_no_secrets_leaked():
    """Test get_status includes metrics while redacting raw API key."""
    secret_key = "AIzaSySecretApiKey123456789"
    conn = YouTubeConnector(api_key=secret_key, enabled=False)
    status = conn.get_status()

    assert secret_key not in json.dumps(status)
    assert "api_key" not in status
    assert status["has_api_key"] is True
    assert "max_requests_per_day" in status
    assert "poll_count" in status
    assert "requests_made" in status
