"""AIShield - Stage 6F Automatic Real-Time Analysis Pipeline Unit & Integration Tests."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from database.db import init_db
from models.detector import AIDetector
from services.analysis_pipeline import AnalysisPipeline
from services.forensic_service import ForensicService
from services.incident_policy import IncidentPolicy
from services.processing_queue import ProcessingQueue
from services.processing_worker import ProcessingWorker
from services.source_post_service import SourcePostService, SourcePostStatus
from services.text_analyzer import TextAnalyzer
from services.threat_analyzer import ThreatAnalyzer


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a clean isolated SQLite database."""
    db_file = tmp_path / "test_pipeline.db"
    init_db(db_file)
    return db_file


@pytest.fixture
def source_service(temp_db_path):
    """Provide an initialized SourcePostService."""
    return SourcePostService(db_path=temp_db_path)


@pytest.fixture
def forensic_service(temp_db_path):
    """Provide an initialized ForensicService."""
    return ForensicService(db_path=temp_db_path)


@pytest.fixture
def text_analyzer():
    """Provide TextAnalyzer instance."""
    return TextAnalyzer()


@pytest.fixture
def threat_analyzer():
    """Provide ThreatAnalyzer instance."""
    return ThreatAnalyzer()


@pytest.fixture
def mock_detector():
    """Provide a mock AIDetector returning realistic probabilities."""
    detector = MagicMock(spec=AIDetector)
    detector.predict.return_value = {
        "label": "AI-Generated",
        "ai_probability": 0.92,
        "human_probability": 0.08,
        "confidence": 0.92,
    }
    return detector


@pytest.fixture
def pipeline(mock_detector, text_analyzer, threat_analyzer, forensic_service, source_service):
    """Provide a standard AnalysisPipeline fixture."""
    return AnalysisPipeline(
        detector=mock_detector,
        text_analyzer=text_analyzer,
        threat_analyzer=threat_analyzer,
        forensic_service=forensic_service,
        source_post_service=source_service,
        incident_policy=IncidentPolicy(min_threat_score=60.0, min_ai_prob=0.85, secondary_threat_score=40.0),
        max_attempts=3,
    )


# 1. Successful Processing
def test_successful_processing(pipeline, source_service):
    """Test standard end-to-end processing of an ingested post."""
    post, _ = source_service.create_source_post(
        source="bluesky",
        source_id="pipe-1",
        content="General normal update about network configuration and server maintenance.",
    )
    res = pipeline.process_source_post(post["id"])

    assert res["success"] is True
    assert res["status"] == SourcePostStatus.ANALYZED
    updated = source_service.get_source_post(post["id"])
    assert updated["status"] == SourcePostStatus.ANALYZED
    assert updated["processed_at"] is not None


# 2. Low-risk post
def test_low_risk_post(pipeline, source_service, forensic_service):
    """Test low risk post is marked ANALYZED with incident_id=NULL."""
    pipeline.detector.predict.return_value = {
        "label": "Human-Written",
        "ai_probability": 0.05,
        "human_probability": 0.95,
        "confidence": 0.95,
    }
    post, _ = source_service.create_source_post(
        source="mastodon",
        source_id="pipe-low-1",
        content="The quarterly technology meetup will be held on Friday at 5 PM.",
    )
    res = pipeline.process_source_post(post["id"])

    assert res["incident_created"] is False
    assert res["incident_id"] is None
    updated = source_service.get_source_post(post["id"])
    assert updated["status"] == SourcePostStatus.ANALYZED
    assert updated["incident_id"] is None

    # Verify no incident record created
    incidents = forensic_service.list_incidents()
    assert len(incidents) == 0


# 3. High-risk post
def test_high_risk_post(pipeline, source_service, forensic_service):
    """Test high risk post creates forensic incident and links ID."""
    pipeline.detector.predict.return_value = {
        "label": "AI-Generated",
        "ai_probability": 0.95,
        "human_probability": 0.05,
        "confidence": 0.95,
    }
    pipeline.threat_analyzer.analyze = MagicMock(return_value={
        "threat_score": 75.0,
        "risk_level": "HIGH",
        "category": "Phishing",
        "indicators": [{"type": "urgency", "severity": "high", "count": 2}],
        "reasons": ["Urgent phishing attack"],
        "component_scores": {"urgency": 80.0},
    })
    malicious_text = "URGENT ACTION REQUIRED! Your bank account is suspended immediately! Click link to verify your password and credentials now: http://fake-bank-auth.com"
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-high-1",
        content=malicious_text,
    )
    res = pipeline.process_source_post(post["id"])

    assert res["incident_created"] is True
    assert res["incident_id"] is not None
    assert res["risk_level"] in ("HIGH", "CRITICAL")

    updated = source_service.get_source_post(post["id"])
    assert updated["status"] == SourcePostStatus.ANALYZED
    assert updated["incident_id"] == res["incident_id"]

    # Verify incident record in ForensicService
    inc = forensic_service.get_incident(res["incident_id"])
    assert inc is not None
    assert inc["content"] == malicious_text
    assert inc["source_post_id"] == post["id"]


# 4. Critical-risk post
def test_critical_risk_post(pipeline, source_service, forensic_service):
    """Test critical risk post creates incident and verifies category."""
    pipeline.threat_analyzer.analyze = MagicMock(return_value={
        "threat_score": 92.0,
        "risk_level": "CRITICAL",
        "category": "Disinformation",
        "indicators": [{"type": "unverified_claims", "severity": "high", "count": 4}],
        "reasons": ["Critical disinformation campaign"],
        "component_scores": {"unverified_claims": 90.0},
    })
    critical_text = "CRITICAL ALERT: Emergency nuclear evacuation notice! Immediate threat detected! Evacuate now and download patch immediately from emergency-alert-patch.ru"
    post, _ = source_service.create_source_post(
        source="youtube",
        source_id="pipe-crit-1",
        content=critical_text,
    )
    res = pipeline.process_source_post(post["id"])

    assert res["incident_created"] is True
    inc = forensic_service.get_incident(res["incident_id"])
    assert inc["threat_analysis"]["threat_score"] >= 60.0


# 5. Incident creation verification
def test_incident_creation(pipeline, source_service, forensic_service):
    """Test incident creation details, content hash, and snapshots."""
    pipeline.threat_analyzer.analyze = MagicMock(return_value={
        "threat_score": 70.0,
        "risk_level": "HIGH",
        "category": "Phishing",
        "indicators": [{"type": "credential_phishing", "severity": "high", "count": 2}],
        "reasons": ["Phishing threat detected"],
        "component_scores": {"credential_phishing": 75.0},
    })
    text = "Security Alert: Phishing campaign detected targeting all executive emails with fake credentials portal."
    post, _ = source_service.create_source_post(
        source="bluesky",
        source_id="pipe-inc-1",
        content=text,
    )
    res = pipeline.process_source_post(post["id"])
    assert res["incident_created"] is True

    inc = forensic_service.get_incident(res["incident_id"])
    assert inc["content_hash"] == ForensicService.calculate_content_hash(text)
    assert inc["source_post_id"] == post["id"]


# 6. No incident creation when below threshold
def test_no_incident_creation(pipeline, source_service, forensic_service):
    """Test standard conversational content does not generate incident."""
    pipeline.detector.predict.return_value = {
        "label": "Human-Written",
        "ai_probability": 0.10,
        "human_probability": 0.90,
        "confidence": 0.90,
    }
    post, _ = source_service.create_source_post(
        source="mastodon",
        source_id="pipe-no-inc",
        content="Enjoying the sunny morning in the park with a cup of coffee.",
    )
    res = pipeline.process_source_post(post["id"])
    assert res["incident_created"] is False
    assert res["incident_id"] is None
    assert forensic_service.list_incidents() == []


# 7. Module 1 failure handling
def test_module_1_failure(pipeline, source_service):
    """Test that failure in Module 1 detector triggers retry and sets QUEUED status."""
    pipeline.detector.predict.side_effect = RuntimeError("GPU inference timeout")
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-mod1-fail",
        content="Some text to analyze",
    )

    with pytest.raises(RuntimeError) as exc_info:
        pipeline.process_source_post(post["id"])
    assert "GPU inference timeout" in str(exc_info.value)

    updated = source_service.get_source_post(post["id"])
    assert updated["status"] == SourcePostStatus.QUEUED
    assert updated["analysis_attempts"] == 1
    assert "GPU inference timeout" in updated["last_error"]


# 8. Module 2 failure handling
def test_module_2_failure(pipeline, source_service):
    """Test that failure in Module 2 threat analyzer triggers retry."""
    pipeline.threat_analyzer.analyze = MagicMock(side_effect=ValueError("Threat rule engine parse error"))
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-mod2-fail",
        content="Some threat text",
    )

    with pytest.raises(RuntimeError):
        pipeline.process_source_post(post["id"])

    updated = source_service.get_source_post(post["id"])
    assert updated["status"] == SourcePostStatus.QUEUED
    assert updated["analysis_attempts"] == 1
    assert "Threat rule engine parse error" in updated["last_error"]


# 9. Incident persistence failure handling
def test_incident_persistence_failure(pipeline, source_service):
    """Test that failure during ForensicService.create_incident triggers retry."""
    pipeline.threat_analyzer.analyze = MagicMock(return_value={
        "threat_score": 75.0,
        "risk_level": "HIGH",
        "category": "Phishing",
        "indicators": [],
        "reasons": [],
        "component_scores": {},
    })
    pipeline.forensic_service.create_incident = MagicMock(side_effect=RuntimeError("Database lock failure"))
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-forensic-fail",
        content="Urgent phishing password credential steal http://evil.com",
    )

    with pytest.raises(RuntimeError):
        pipeline.process_source_post(post["id"])

    updated = source_service.get_source_post(post["id"])
    assert updated["status"] == SourcePostStatus.QUEUED
    assert updated["incident_id"] is None


# 10. Retry lifecycle
def test_retry_lifecycle(pipeline, source_service):
    """Test retry attempts increment and status changes across multiple failures."""
    pipeline.detector.predict.side_effect = RuntimeError("Intermittent AI timeout")
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-retry-steps",
        content="Content for retry",
    )

    # Attempt 1
    with pytest.raises(RuntimeError):
        pipeline.process_source_post(post["id"])
    p1 = source_service.get_source_post(post["id"])
    assert p1["analysis_attempts"] == 1
    assert p1["status"] == SourcePostStatus.QUEUED

    # Attempt 2
    with pytest.raises(RuntimeError):
        pipeline.process_source_post(post["id"])
    p2 = source_service.get_source_post(post["id"])
    assert p2["analysis_attempts"] == 2
    assert p2["status"] == SourcePostStatus.QUEUED


# 11. Maximum retries exceeded
def test_maximum_retries_exceeded(pipeline, source_service):
    """Test that reaching max attempts transitions status to FAILED."""
    pipeline.detector.predict.side_effect = RuntimeError("Persistent failure")
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-max-retries",
        content="Content for max retries",
    )

    # Run 3 attempts
    for _ in range(3):
        with pytest.raises(RuntimeError):
            pipeline.process_source_post(post["id"])

    p_final = source_service.get_source_post(post["id"])
    assert p_final["analysis_attempts"] == 3
    assert p_final["status"] == SourcePostStatus.FAILED
    assert "Exceeded max attempts" in p_final["last_error"]


# 12. Duplicate queue item handling
def test_duplicate_queue_item(pipeline, source_service):
    """Test that processing an already ANALYZED post returns immediately without re-analyzing."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-dup-queue",
        content="Already analyzed content",
    )
    # First execution
    res1 = pipeline.process_source_post(post["id"])
    assert res1["status"] == SourcePostStatus.ANALYZED

    # Second execution (e.g. duplicate dequeued item)
    res2 = pipeline.process_source_post(post["id"])
    assert res2["status"] == SourcePostStatus.ANALYZED
    assert res2["already_analyzed"] is True


# 13. Already analyzed post idempotency
def test_already_analyzed_post(pipeline, source_service):
    """Test post marked ANALYZED remains unchanged."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-already-analyzed",
        content="Test content",
    )
    source_service.mark_analyzed(post["id"], incident_id="INC-PREEXISTING-99")

    res = pipeline.process_source_post(post["id"])
    assert res["already_analyzed"] is True
    assert res["incident_id"] == "INC-PREEXISTING-99"


# 14. Existing incident link preservation
def test_existing_incident_link(pipeline, source_service, forensic_service):
    """Test that if a post already has an incident_id, a new incident is not created."""
    pipeline.threat_analyzer.analyze = MagicMock(return_value={
        "threat_score": 80.0,
        "risk_level": "HIGH",
        "category": "Phishing",
        "indicators": [],
        "reasons": [],
        "component_scores": {},
    })
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-exist-inc",
        content="Urgent alert credentials http://phish.com",
    )
    # First run creates incident
    res1 = pipeline.process_source_post(post["id"])
    inc1 = res1["incident_id"]
    assert inc1 is not None

    # Count incidents
    all_incidents = forensic_service.list_incidents()
    assert len(all_incidents) == 1

    # Second run should not create second incident
    res2 = pipeline.process_source_post(post["id"])
    assert res2["incident_id"] == inc1
    assert len(forensic_service.list_incidents()) == 1


# 15. Source-post to incident link bidirectional verification
def test_source_post_to_incident_link(pipeline, source_service, forensic_service):
    """Verify bidirectional link: source_posts.incident_id and incidents.source_post_id."""
    pipeline.threat_analyzer.analyze = MagicMock(return_value={
        "threat_score": 85.0,
        "risk_level": "CRITICAL",
        "category": "Phishing",
        "indicators": [],
        "reasons": [],
        "component_scores": {},
    })
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-link-check",
        content="URGENT! Malicious ransomware threat detected immediately click http://malware.org",
    )
    res = pipeline.process_source_post(post["id"])
    incident_id = res["incident_id"]

    post_db = source_service.get_source_post(post["id"])
    incident_db = forensic_service.get_incident(incident_id)

    assert post_db["incident_id"] == incident_id
    assert incident_db["source_post_id"] == post["id"]


# 16. Rollback on failure
def test_rollback_on_failure(pipeline, source_service, forensic_service):
    """Test that DB state is clean if failure occurs mid-pipeline."""
    pipeline.threat_analyzer.analyze = MagicMock(side_effect=Exception("Critical analysis failure"))
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-rollback",
        content="Phishing credentials steal text",
    )

    with pytest.raises(RuntimeError):
        pipeline.process_source_post(post["id"])

    assert forensic_service.list_incidents() == []
    post_db = source_service.get_source_post(post["id"])
    assert post_db["status"] == SourcePostStatus.QUEUED


# 17. Status transitions
def test_status_transitions(pipeline, source_service):
    """Verify lifecycle progression: RECEIVED -> QUEUED -> PROCESSING -> ANALYZED."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-transitions",
        content="Normal text for status transition test",
    )
    assert post["status"] == SourcePostStatus.RECEIVED

    source_service.update_status(post["id"], SourcePostStatus.QUEUED)
    p_q = source_service.get_source_post(post["id"])
    assert p_q["status"] == SourcePostStatus.QUEUED

    pipeline.process_source_post(post["id"])
    p_a = source_service.get_source_post(post["id"])
    assert p_a["status"] == SourcePostStatus.ANALYZED


# 18. Processed timestamp population
def test_processed_timestamp(pipeline, source_service):
    """Verify processed_at timestamp is set upon completion."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="pipe-time-test",
        content="Some simple text",
    )
    assert post["processed_at"] is None

    pipeline.process_source_post(post["id"])
    updated = source_service.get_source_post(post["id"])
    assert updated["processed_at"] is not None
    assert "T" in updated["processed_at"]


# 19. IncidentPolicy thresholds
def test_incident_policy_thresholds():
    """Test custom threshold configuration in IncidentPolicy."""
    policy = IncidentPolicy(min_threat_score=80.0, min_ai_prob=0.90, secondary_threat_score=50.0)

    # Score 65 is below 80 -> should NOT create incident
    should_create, _ = policy.evaluate(
        ai_prediction={"ai_probability": 0.50},
        text_analysis={},
        threat_analysis={"threat_score": 65.0, "risk_level": "MEDIUM"},
    )
    assert should_create is False

    # Score 85 >= 80 -> should create incident
    should_create, _ = policy.evaluate(
        ai_prediction={"ai_probability": 0.50},
        text_analysis={},
        threat_analysis={"threat_score": 85.0, "risk_level": "HIGH"},
    )
    assert should_create is True


# 20. Pipeline determinism
def test_pipeline_determinism(pipeline, source_service):
    """Test that pipeline produces consistent, deterministic results for identical content."""
    text = "Important Security Notice: Patch your servers against zero-day vulnerabilities."

    post1, _ = source_service.create_source_post(source="bluesky", source_id="det-1", content=text)
    post2, _ = source_service.create_source_post(source="mastodon", source_id="det-2", content=text)

    res1 = pipeline.process_source_post(post1["id"])
    res2 = pipeline.process_source_post(post2["id"])

    assert res1["threat_score"] == res2["threat_score"]
    assert res1["risk_level"] == res2["risk_level"]
    assert res1["category"] == res2["category"]
    assert res1["incident_created"] == res2["incident_created"]
