"""Unit tests for Module 3: Digital Forensics & Incident Records Service."""

from datetime import datetime
import hashlib
import json
from pathlib import Path
import pytest
import sqlite3

from database.db import db_session, get_db_connection, init_db
from services.forensic_service import ForensicService


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary database file path for isolated tests."""
    return tmp_path / "test_forensics.db"


@pytest.fixture
def service(temp_db_path):
    """Provide a ForensicService connected to the temporary test database."""
    return ForensicService(db_path=temp_db_path)


@pytest.fixture
def sample_analysis_payload():
    """Provide a valid sample analysis payload matching Modules 1 & 2 outputs."""
    return {
        "content": "Official Security Alert: Your account is suspended due to unauthorized login detected! Verify your account immediately by clicking the link within 24 hours.",
        "prediction": {
            "label": "AI-generated",
            "ai_probability": 0.78,
            "human_probability": 0.22,
            "confidence": 0.78,
        },
        "text_analysis": {
            "character_count": 158,
            "word_count": 23,
            "sentence_count": 2,
            "average_word_length": 5.91,
            "average_sentence_length": 11.5,
            "vocabulary_richness": 0.956,
            "punctuation_count": 3,
            "question_mark_count": 0,
            "exclamation_mark_count": 1,
            "repeated_word_count": 1,
        },
        "threat_analysis": {
            "threat_score": 74.2,
            "risk_level": "HIGH",
            "category": "Phishing",
            "indicators": [
                {
                    "type": "urgency",
                    "severity": "high",
                    "count": 2,
                    "description": "Urgency and artificial time pressure phrasing.",
                },
                {
                    "type": "credential_phishing",
                    "severity": "high",
                    "count": 2,
                    "description": "Credential harvesting or account suspension prompt.",
                },
            ],
            "reasons": [
                "2 urgency-related expressions were detected urging rapid action.",
                "2 credential or account verification prompts characteristic of phishing were detected.",
            ],
            "component_scores": {
                "ai_likelihood": 78.0,
                "urgency": 65.0,
                "manipulation": 35.0,
                "call_to_action": 85.0,
                "unverified_claims": 0.0,
                "authority_patterns": 35.0,
                "category_severity": 95.0,
            },
        },
    }


def test_database_initialization(temp_db_path):
    """Test database file and parent directories are created on initialization."""
    assert not temp_db_path.exists()
    init_db(temp_db_path)
    assert temp_db_path.exists()


def test_incident_table_creation(temp_db_path):
    """Test incidents table and indices are created with correct schema."""
    init_db(temp_db_path)
    with db_session(temp_db_path) as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents';")
        assert cursor.fetchone() is not None

        # Check indexes
        idx_cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index';")
        index_names = {row["name"] for row in idx_cursor.fetchall()}
        assert "idx_incidents_incident_id" in index_names
        assert "idx_incidents_created_at" in index_names
        assert "idx_incidents_content_hash" in index_names


def test_unique_incident_ids(service, sample_analysis_payload):
    """Test every created incident receives a unique UUID-based ID prefixed with INC-."""
    inc1 = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    inc2 = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )

    assert inc1["incident_id"].startswith("INC-")
    assert inc2["incident_id"].startswith("INC-")
    assert inc1["incident_id"] != inc2["incident_id"]


def test_utc_timestamp_format(service, sample_analysis_payload):
    """Test created_at is stored in valid ISO-8601 UTC format with timezone."""
    inc = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    ts = inc["created_at"]
    assert isinstance(ts, str)
    dt = datetime.fromisoformat(ts)
    assert dt.tzinfo is not None  # Must be timezone-aware


def test_sha256_hash_format(service):
    """Test SHA-256 fingerprint is exactly 64 lowercase hexadecimal characters."""
    h = service.calculate_content_hash("Sample test string.")
    assert isinstance(h, str)
    assert len(h) == 64
    assert h == h.lower()
    assert all(c in "0123456789abcdef" for c in h)


def test_known_sha256_hash(service):
    """Test SHA-256 calculation matches known cryptographic test vector."""
    # SHA-256 for "hello world"
    expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert service.calculate_content_hash("hello world") == expected


def test_exact_text_hash_behavior(service):
    """Test hash preserves exact byte sequence (case, spacing, and trailing punctuation)."""
    h_exact = service.calculate_content_hash("URGENT: Act Now!!!")
    h_lower = service.calculate_content_hash("urgent: act now!!!")
    h_spaces = service.calculate_content_hash("URGENT:   Act Now!!!")

    assert h_exact != h_lower
    assert h_exact != h_spaces


def test_exact_byte_string_variations_produce_distinct_hashes(service):
    """Audit test: Verify specific test string variations produce distinct hashes."""
    s1 = "Hello world"
    s2 = "hello world"
    s3 = "Hello  world"
    s4 = "Hello world\n"

    h1 = service.calculate_content_hash(s1)
    h2 = service.calculate_content_hash(s2)
    h3 = service.calculate_content_hash(s3)
    h4 = service.calculate_content_hash(s4)

    hashes = {h1, h2, h3, h4}
    assert len(hashes) == 4, f"Hashes collided for distinct byte representations: {hashes}"


def test_changed_text_produces_different_hash(service):
    """Test even a 1-character modification completely changes the hash."""
    h1 = service.calculate_content_hash("Suspicious link here: http://example.com/a")
    h2 = service.calculate_content_hash("Suspicious link here: http://example.com/b")
    assert h1 != h2


def test_incident_creation(service, sample_analysis_payload):
    """Test creating an incident persists all fields and returns summary."""
    res = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )

    assert "incident_id" in res
    assert "created_at" in res
    assert "content_hash" in res
    assert res["ai_label"] == "AI-generated"
    assert res["ai_probability"] == 0.78
    assert res["threat_score"] == 74.2
    assert res["risk_level"] == "HIGH"
    assert res["category"] == "Phishing"


def test_incident_retrieval(service, sample_analysis_payload):
    """Test retrieving an incident returns the complete stored snapshot."""
    created = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    inc_id = created["incident_id"]

    retrieved = service.get_incident(inc_id)
    assert retrieved is not None
    assert retrieved["incident_id"] == inc_id
    assert retrieved["content"] == sample_analysis_payload["content"]
    assert retrieved["content_hash"] == created["content_hash"]

    # Check Module 1 snapshot
    assert retrieved["prediction"]["label"] == "AI-generated"
    assert retrieved["prediction"]["ai_probability"] == 0.78
    assert retrieved["text_analysis"]["word_count"] == 23

    # Check Module 2 snapshot
    assert retrieved["threat_analysis"]["threat_score"] == 74.2
    assert retrieved["threat_analysis"]["risk_level"] == "HIGH"
    assert retrieved["threat_analysis"]["category"] == "Phishing"
    assert len(retrieved["threat_analysis"]["indicators"]) == 2
    assert len(retrieved["threat_analysis"]["reasons"]) == 2
    assert retrieved["threat_analysis"]["component_scores"]["ai_likelihood"] == 78.0


def test_incident_list(service, sample_analysis_payload):
    """Test listing incidents returns summary records without full raw content."""
    service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )

    incidents = service.list_incidents(limit=10)
    assert len(incidents) >= 1
    item = incidents[0]
    assert "incident_id" in item
    assert "created_at" in item
    assert "content_hash" in item
    assert "threat_score" in item
    assert "content" not in item  # Full content excluded from list endpoint


def test_newest_first_ordering(service, sample_analysis_payload):
    """Test incident list orders records newest first."""
    p1 = service.create_incident(
        "First submitted text.",
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    p2 = service.create_incident(
        "Second submitted text.",
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )

    items = service.list_incidents(limit=10)
    assert items[0]["incident_id"] == p2["incident_id"]
    assert items[1]["incident_id"] == p1["incident_id"]


def test_missing_incident(service):
    """Test requesting non-existent incident returns None."""
    assert service.get_incident("INC-non-existent-id") is None
    assert service.get_incident("") is None
    assert service.get_incident(None) is None


def test_snapshot_persistence(service, sample_analysis_payload):
    """Test structured JSON components are parsed accurately on retrieval."""
    created = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    rec = service.get_incident(created["incident_id"])
    assert isinstance(rec["text_analysis"], dict)
    assert isinstance(rec["threat_analysis"]["indicators"], list)
    assert isinstance(rec["threat_analysis"]["reasons"], list)
    assert isinstance(rec["threat_analysis"]["component_scores"], dict)


def test_no_recalculation_on_retrieval(service, sample_analysis_payload):
    """Test historical values are strictly loaded from database without recalculation."""
    created = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    rec = service.get_incident(created["incident_id"])

    assert rec["prediction"]["confidence"] == sample_analysis_payload["prediction"]["confidence"]
    assert rec["threat_analysis"]["threat_score"] == sample_analysis_payload["threat_analysis"]["threat_score"]


def test_invalid_ai_probability(service, sample_analysis_payload):
    """Test out-of-range AI probability raises ValueError."""
    bad_pred = dict(sample_analysis_payload["prediction"], ai_probability=1.5)
    with pytest.raises(ValueError, match="between 0.0 and 1.0"):
        service.create_incident(
            sample_analysis_payload["content"],
            bad_pred,
            sample_analysis_payload["text_analysis"],
            sample_analysis_payload["threat_analysis"],
        )


def test_invalid_human_probability(service, sample_analysis_payload):
    """Test negative human probability raises ValueError."""
    bad_pred = dict(sample_analysis_payload["prediction"], human_probability=-0.2)
    with pytest.raises(ValueError, match="between 0.0 and 1.0"):
        service.create_incident(
            sample_analysis_payload["content"],
            bad_pred,
            sample_analysis_payload["text_analysis"],
            sample_analysis_payload["threat_analysis"],
        )


def test_invalid_confidence(service, sample_analysis_payload):
    """Test non-numeric confidence raises ValueError."""
    bad_pred = dict(sample_analysis_payload["prediction"], confidence="high")
    with pytest.raises(ValueError, match="numeric value"):
        service.create_incident(
            sample_analysis_payload["content"],
            bad_pred,
            sample_analysis_payload["text_analysis"],
            sample_analysis_payload["threat_analysis"],
        )


def test_invalid_threat_score(service, sample_analysis_payload):
    """Test threat score > 100 raises ValueError."""
    bad_threat = dict(sample_analysis_payload["threat_analysis"], threat_score=105.0)
    with pytest.raises(ValueError, match="between 0.0 and 100.0"):
        service.create_incident(
            sample_analysis_payload["content"],
            sample_analysis_payload["prediction"],
            sample_analysis_payload["text_analysis"],
            bad_threat,
        )


def test_invalid_risk_level(service, sample_analysis_payload):
    """Test unrecognized risk level string raises ValueError."""
    bad_threat = dict(sample_analysis_payload["threat_analysis"], risk_level="EXTREME_DANGER")
    with pytest.raises(ValueError, match="Invalid risk_level"):
        service.create_incident(
            sample_analysis_payload["content"],
            sample_analysis_payload["prediction"],
            sample_analysis_payload["text_analysis"],
            bad_threat,
        )


def test_invalid_category(service, sample_analysis_payload):
    """Test unrecognized category string raises ValueError."""
    bad_threat = dict(sample_analysis_payload["threat_analysis"], category="SuperMalware")
    with pytest.raises(ValueError, match="Invalid category"):
        service.create_incident(
            sample_analysis_payload["content"],
            sample_analysis_payload["prediction"],
            sample_analysis_payload["text_analysis"],
            bad_threat,
        )


def test_empty_content(service, sample_analysis_payload):
    """Test empty content raises ValueError."""
    with pytest.raises(ValueError, match="cannot be empty or whitespace-only"):
        service.create_incident(
            "   ",
            sample_analysis_payload["prediction"],
            sample_analysis_payload["text_analysis"],
            sample_analysis_payload["threat_analysis"],
        )


def test_invalid_payload(service):
    """Test non-string content or non-dict inputs raise ValueError."""
    with pytest.raises(ValueError, match="must be a string"):
        service.create_incident(12345, {}, {}, {})


def test_transaction_rollback_on_failure(service, temp_db_path):
    """Test database transaction rolls back if an insertion error occurs."""
    with pytest.raises(Exception):
        service.create_incident(None, {}, {}, {})

    # Ensure table count remains 0
    with db_session(temp_db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM incidents;").fetchone()[0]
        assert count == 0


def test_integrity_verification_success(service, sample_analysis_payload):
    """Test cryptographic integrity verification succeeds for unmodified records."""
    created = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    inc_id = created["incident_id"]

    verification = service.verify_incident_integrity(inc_id)
    assert verification is not None
    assert verification["verified"] is True
    assert verification["stored_hash"] == verification["calculated_hash"]


def test_integrity_verification_failure_if_tampered(service, temp_db_path, sample_analysis_payload):
    """Test cryptographic integrity check detects if database content was altered directly."""
    created = service.create_incident(
        sample_analysis_payload["content"],
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    inc_id = created["incident_id"]

    # Directly tamper with stored content in SQLite table
    with db_session(temp_db_path) as conn:
        with conn:
            conn.execute("UPDATE incidents SET content = ? WHERE incident_id = ?;", ("Tampered content modified directly in database.", inc_id))

    verification = service.verify_incident_integrity(inc_id)
    assert verification is not None
    assert verification["verified"] is False
    assert verification["stored_hash"] != verification["calculated_hash"]


def test_xss_and_unicode_content_preservation(service, sample_analysis_payload):
    """Test raw scripts, HTML, quotes, and emojis are preserved byte-for-byte in storage and hash."""
    raw_xss = "<script>alert('XSS attack')</script>\nLine 2: \"quoted\" & 'single' \u2014 \u2764\ufe0f Unicode!"
    created = service.create_incident(
        raw_xss,
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )

    rec = service.get_incident(created["incident_id"])
    assert rec["content"] == raw_xss
    assert rec["content_hash"] == hashlib.sha256(raw_xss.encode("utf-8")).hexdigest().lower()

    # Integrity verification
    verification = service.verify_incident_integrity(created["incident_id"])
    assert verification["verified"] is True


def test_xss_payload_vectors(service, sample_analysis_payload):
    """Audit test: Verify diverse XSS vectors are stored exactly and verified cryptographically."""
    xss_vectors = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<div>test</div>",
        '<img src="javascript:alert(\'xss\')">',
    ]

    for vec in xss_vectors:
        created = service.create_incident(
            vec,
            sample_analysis_payload["prediction"],
            sample_analysis_payload["text_analysis"],
            sample_analysis_payload["threat_analysis"],
        )
        rec = service.get_incident(created["incident_id"])
        assert rec["content"] == vec
        assert rec["content_hash"] == hashlib.sha256(vec.encode("utf-8")).hexdigest().lower()

        verif = service.verify_incident_integrity(created["incident_id"])
        assert verif["verified"] is True


def test_database_persistence_across_service_restarts(temp_db_path, sample_analysis_payload):
    """Audit test: Simulate app restart by instantiating a fresh ForensicService on existing DB file."""
    srv1 = ForensicService(db_path=temp_db_path)
    created = srv1.create_incident(
        "Persisted text before restart",
        sample_analysis_payload["prediction"],
        sample_analysis_payload["text_analysis"],
        sample_analysis_payload["threat_analysis"],
    )
    inc_id = created["incident_id"]

    # Fresh service instance
    srv2 = ForensicService(db_path=temp_db_path)
    rec = srv2.get_incident(inc_id)
    assert rec is not None
    assert rec["content"] == "Persisted text before restart"
    assert rec["content_hash"] == created["content_hash"]
