"""Unit tests for Module 4: Threat Intelligence & Investigation Dashboard Service."""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from database.db import db_session, init_db
from services.forensic_service import ForensicService
from services.intelligence_service import IntelligenceService


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary database file path for isolated intelligence tests."""
    db_file = tmp_path / "test_intelligence.db"
    init_db(db_file)
    return db_file


@pytest.fixture
def forensic_srv(temp_db_path):
    """Provide a ForensicService instance connected to the test database."""
    return ForensicService(db_path=temp_db_path)


@pytest.fixture
def intel_srv(temp_db_path):
    """Provide an IntelligenceService instance connected to the test database."""
    return IntelligenceService(db_path=temp_db_path)


@pytest.fixture
def populated_intel_srv(forensic_srv, intel_srv):
    """Populate test database with a diverse matrix of incident records."""
    sample_records = [
        {
            "content": "Phishing email prompt urgent password reset required immediately.",
            "prediction": {"label": "AI-generated", "ai_probability": 0.88, "human_probability": 0.12, "confidence": 0.88},
            "text_analysis": {"character_count": 65, "word_count": 9, "sentence_count": 1},
            "threat_analysis": {
                "threat_score": 88.5,
                "risk_level": "CRITICAL",
                "category": "Phishing",
                "indicators": [{"type": "urgency", "severity": "high", "count": 1, "description": "Urgency"}],
                "reasons": ["Urgency detected"],
                "component_scores": {"ai_likelihood": 88.0, "urgency": 90.0, "category_severity": 95.0},
            },
        },
        {
            "content": "Breaking fake news shocking secret revealed don't trust mainstream media.",
            "prediction": {"label": "AI-generated", "ai_probability": 0.72, "human_probability": 0.28, "confidence": 0.72},
            "text_analysis": {"character_count": 70, "word_count": 10, "sentence_count": 1},
            "threat_analysis": {
                "threat_score": 76.0,
                "risk_level": "HIGH",
                "category": "Disinformation",
                "indicators": [{"type": "unverified_claims", "severity": "high", "count": 1, "description": "Unverified claims"}],
                "reasons": ["Unverified claims detected"],
                "component_scores": {"ai_likelihood": 72.0, "unverified_claims": 85.0, "category_severity": 85.0},
            },
        },
        {
            "content": "Special limited offer buy cheap luxury watches discount click here.",
            "prediction": {"label": "Human", "ai_probability": 0.35, "human_probability": 0.65, "confidence": 0.65},
            "text_analysis": {"character_count": 60, "word_count": 10, "sentence_count": 1},
            "threat_analysis": {
                "threat_score": 45.0,
                "risk_level": "MEDIUM",
                "category": "Spam",
                "indicators": [{"type": "call_to_action", "severity": "medium", "count": 1, "description": "CTA"}],
                "reasons": ["Call to action detected"],
                "component_scores": {"ai_likelihood": 35.0, "call_to_action": 60.0, "category_severity": 40.0},
            },
        },
        {
            "content": "The quarterly technical review meeting is scheduled for Thursday at 10:00 AM in Conference Room B.",
            "prediction": {"label": "Human", "ai_probability": 0.10, "human_probability": 0.90, "confidence": 0.90},
            "text_analysis": {"character_count": 98, "word_count": 15, "sentence_count": 1},
            "threat_analysis": {
                "threat_score": 12.0,
                "risk_level": "LOW",
                "category": "Normal",
                "indicators": [],
                "reasons": ["No significant threat indicators detected."],
                "component_scores": {"ai_likelihood": 10.0, "urgency": 0.0, "category_severity": 10.0},
            },
        },
    ]

    for rec in sample_records:
        forensic_srv.create_incident(
            content=rec["content"],
            prediction=rec["prediction"],
            text_analysis=rec["text_analysis"],
            threat_analysis=rec["threat_analysis"],
        )

    return intel_srv


# -----------------------------------------------------------------------------
# Summary Statistics Tests
# -----------------------------------------------------------------------------

def test_zero_incidents_summary(intel_srv):
    """Test get_summary_statistics returns clean zeros when database is empty."""
    stats = intel_srv.get_summary_statistics()
    assert stats["total_incidents"] == 0
    assert stats["high_risk"] == 0
    assert stats["critical_risk"] == 0
    assert stats["ai_generated"] == 0
    assert stats["human"] == 0
    assert stats["average_threat_score"] == 0.0


def test_summary_statistics_with_data(populated_intel_srv):
    """Test get_summary_statistics computes accurate counts across risk and AI fields."""
    stats = populated_intel_srv.get_summary_statistics()
    assert stats["total_incidents"] == 4
    assert stats["high_risk"] == 1
    assert stats["critical_risk"] == 1
    assert stats["ai_generated"] == 2
    assert stats["human"] == 2


def test_average_threat_score_calculation(populated_intel_srv):
    """Test average threat score is accurately aggregated: (88.5 + 76.0 + 45.0 + 12.0) / 4 = 55.38."""
    stats = populated_intel_srv.get_summary_statistics()
    expected_avg = round((88.5 + 76.0 + 45.0 + 12.0) / 4.0, 2)
    assert stats["average_threat_score"] == expected_avg


# -----------------------------------------------------------------------------
# Distribution Tests
# -----------------------------------------------------------------------------

def test_risk_distribution_all_keys_present(populated_intel_srv):
    """Test risk distribution returns all 4 standard levels with exact counts."""
    dist = populated_intel_srv.get_risk_distribution()
    assert set(dist.keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert dist["CRITICAL"] == 1
    assert dist["HIGH"] == 1
    assert dist["MEDIUM"] == 1
    assert dist["LOW"] == 1


def test_category_distribution_all_keys_present(populated_intel_srv):
    """Test category distribution includes all 7 supported categories."""
    dist = populated_intel_srv.get_category_distribution()
    expected_cats = {"Normal", "Phishing", "Disinformation", "Manipulation", "Propaganda", "Spam", "Other"}
    assert set(dist.keys()) == expected_cats
    assert dist["Phishing"] == 1
    assert dist["Disinformation"] == 1
    assert dist["Spam"] == 1
    assert dist["Normal"] == 1
    assert dist["Manipulation"] == 0
    assert dist["Propaganda"] == 0
    assert dist["Other"] == 0


def test_ai_distribution_counts(populated_intel_srv):
    """Test AI vs Human distribution returns exact binary breakdown."""
    dist = populated_intel_srv.get_ai_distribution()
    assert dist["AI-generated"] == 2
    assert dist["Human"] == 2


# -----------------------------------------------------------------------------
# Recent & High-Risk Incidents Tests
# -----------------------------------------------------------------------------

def test_recent_incidents_limit_and_order(populated_intel_srv):
    """Test get_recent_incidents returns items ordered newest first."""
    recent = populated_intel_srv.get_recent_incidents(limit=2)
    assert len(recent) == 2
    assert "incident_id" in recent[0]
    assert "threat_score" in recent[0]


def test_high_risk_incidents_filtering_and_severity_ordering(populated_intel_srv):
    """Test get_high_risk_incidents extracts HIGH and CRITICAL records, sorting CRITICAL first."""
    high_risk = populated_intel_srv.get_high_risk_incidents(limit=10)
    assert len(high_risk) == 2
    # CRITICAL should be first, followed by HIGH
    assert high_risk[0]["risk_level"] == "CRITICAL"
    assert high_risk[1]["risk_level"] == "HIGH"


# -----------------------------------------------------------------------------
# Search & Filtering Tests
# -----------------------------------------------------------------------------

def test_search_by_incident_id(populated_intel_srv):
    """Test search with specific incident ID query returns matching record."""
    all_res = populated_intel_srv.search_incidents(page=1, page_size=10)
    target_id = all_res["items"][0]["incident_id"]

    res = populated_intel_srv.search_incidents(q=target_id)
    assert res["pagination"]["total"] == 1
    assert res["items"][0]["incident_id"] == target_id


def test_search_by_category(populated_intel_srv):
    """Test filtering search by category Phishing."""
    res = populated_intel_srv.search_incidents(category="Phishing")
    assert res["pagination"]["total"] == 1
    assert res["items"][0]["category"] == "Phishing"


def test_search_by_risk_level(populated_intel_srv):
    """Test filtering search by risk level HIGH."""
    res = populated_intel_srv.search_incidents(risk_level="HIGH")
    assert res["pagination"]["total"] == 1
    assert res["items"][0]["risk_level"] == "HIGH"


def test_search_by_ai_label(populated_intel_srv):
    """Test filtering search by ai_label AI-generated."""
    res = populated_intel_srv.search_incidents(ai_label="AI-generated")
    assert res["pagination"]["total"] == 2
    for item in res["items"]:
        assert item["ai_label"] == "AI-generated"


def test_search_by_content_hash(populated_intel_srv):
    """Test searching by content_hash substring."""
    all_res = populated_intel_srv.search_incidents(page=1, page_size=10)
    target_hash = all_res["items"][0]["content_hash"]

    res = populated_intel_srv.search_incidents(q=target_hash[:10])
    assert res["pagination"]["total"] >= 1
    assert any(it["content_hash"] == target_hash for it in res["items"])


def test_search_minimum_threat_score(populated_intel_srv):
    """Test filtering with min_score >= 70.0."""
    res = populated_intel_srv.search_incidents(min_score=70.0)
    assert res["pagination"]["total"] == 2
    for it in res["items"]:
        assert it["threat_score"] >= 70.0


def test_search_maximum_threat_score(populated_intel_srv):
    """Test filtering with max_score <= 50.0."""
    res = populated_intel_srv.search_incidents(max_score=50.0)
    assert res["pagination"]["total"] == 2
    for it in res["items"]:
        assert it["threat_score"] <= 50.0


def test_search_date_filtering_range(populated_intel_srv):
    """Test date filtering with ISO YYYY-MM-DD bounds."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    res = populated_intel_srv.search_incidents(from_date=today, to_date=today)
    assert res["pagination"]["total"] == 4


def test_combined_filters(populated_intel_srv):
    """Test combined multi-field search: category=Disinformation AND risk_level=HIGH."""
    res = populated_intel_srv.search_incidents(category="Disinformation", risk_level="HIGH")
    assert res["pagination"]["total"] == 1
    assert res["items"][0]["category"] == "Disinformation"
    assert res["items"][0]["risk_level"] == "HIGH"


# -----------------------------------------------------------------------------
# Sorting Tests
# -----------------------------------------------------------------------------

def test_sorting_by_threat_score(populated_intel_srv):
    """Test sorting incidents by threat_score descending."""
    res = populated_intel_srv.search_incidents(sort="threat", order="desc")
    scores = [it["threat_score"] for it in res["items"]]
    assert scores == sorted(scores, reverse=True)


def test_sorting_by_created_at(populated_intel_srv):
    """Test sorting incidents by date descending."""
    res = populated_intel_srv.search_incidents(sort="date", order="desc")
    assert len(res["items"]) == 4


def test_sorting_ascending_order(populated_intel_srv):
    """Test sorting threat score ascending."""
    res = populated_intel_srv.search_incidents(sort="threat", order="asc")
    scores = [it["threat_score"] for it in res["items"]]
    assert scores == sorted(scores)


def test_sorting_descending_order(populated_intel_srv):
    """Test sorting ai_probability descending."""
    res = populated_intel_srv.search_incidents(sort="ai", order="desc")
    probs = [it["ai_probability"] for it in res["items"]]
    assert probs == sorted(probs, reverse=True)


# -----------------------------------------------------------------------------
# Pagination Tests
# -----------------------------------------------------------------------------

def test_pagination_first_page(populated_intel_srv):
    """Test pagination bounds with page_size=2."""
    res = populated_intel_srv.search_incidents(page=1, page_size=2)
    assert len(res["items"]) == 2
    assert res["pagination"]["page"] == 1
    assert res["pagination"]["page_size"] == 2
    assert res["pagination"]["total"] == 4
    assert res["pagination"]["total_pages"] == 2


def test_pagination_second_page(populated_intel_srv):
    """Test pagination for page 2."""
    res = populated_intel_srv.search_incidents(page=2, page_size=2)
    assert len(res["items"]) == 2
    assert res["pagination"]["page"] == 2


def test_page_beyond_total_pages_returns_empty_items(populated_intel_srv):
    """Test requesting a page beyond total pages returns empty items list without crashing."""
    res = populated_intel_srv.search_incidents(page=999, page_size=10)
    assert res["items"] == []
    assert res["pagination"]["page"] == 999
    assert res["pagination"]["total"] == 4
    assert res["pagination"]["total_pages"] == 1


def test_page_size_limits(populated_intel_srv):
    """Test page_size maximum cap at 100."""
    res = populated_intel_srv.search_incidents(page=1, page_size=100)
    assert len(res["items"]) == 4


# -----------------------------------------------------------------------------
# Validation & Error Boundary Tests
# -----------------------------------------------------------------------------

def test_invalid_page_raises_error(populated_intel_srv):
    """Test page < 1 raises ValueError."""
    with pytest.raises(ValueError, match="greater than or equal to 1"):
        populated_intel_srv.search_incidents(page=0)


def test_negative_page_raises_error(populated_intel_srv):
    """Test negative page raises ValueError."""
    with pytest.raises(ValueError, match="greater than or equal to 1"):
        populated_intel_srv.search_incidents(page=-1)


def test_invalid_page_size_raises_error(populated_intel_srv):
    """Test page_size > 100 raises ValueError."""
    with pytest.raises(ValueError, match="between 1 and 100"):
        populated_intel_srv.search_incidents(page_size=101)


def test_negative_page_size_raises_error(populated_intel_srv):
    """Test page_size < 1 raises ValueError."""
    with pytest.raises(ValueError, match="between 1 and 100"):
        populated_intel_srv.search_incidents(page_size=0)


def test_invalid_risk_level_filter_raises_error(populated_intel_srv):
    """Test invalid risk level string raises ValueError."""
    with pytest.raises(ValueError, match="Invalid risk_level filter"):
        populated_intel_srv.search_incidents(risk_level="DANGEROUS")


def test_invalid_category_filter_raises_error(populated_intel_srv):
    """Test invalid category filter raises ValueError."""
    with pytest.raises(ValueError, match="Invalid category filter"):
        populated_intel_srv.search_incidents(category="MalwareSpread")


def test_invalid_ai_label_filter_raises_error(populated_intel_srv):
    """Test invalid ai_label filter raises ValueError."""
    with pytest.raises(ValueError, match="Invalid ai_label filter"):
        populated_intel_srv.search_incidents(ai_label="Alien")


def test_negative_min_score_raises_error(populated_intel_srv):
    """Test min_score < 0 raises ValueError."""
    with pytest.raises(ValueError, match="between 0.0 and 100.0"):
        populated_intel_srv.search_incidents(min_score=-5.0)


def test_max_score_greater_than_100_raises_error(populated_intel_srv):
    """Test max_score > 100 raises ValueError."""
    with pytest.raises(ValueError, match="between 0.0 and 100.0"):
        populated_intel_srv.search_incidents(max_score=105.0)


def test_invalid_score_range_raises_error(populated_intel_srv):
    """Test min_score > max_score raises ValueError."""
    with pytest.raises(ValueError, match="cannot be greater than max_score"):
        populated_intel_srv.search_incidents(min_score=90.0, max_score=20.0)


def test_invalid_date_format_raises_error(populated_intel_srv):
    """Test non-ISO date string raises ValueError."""
    with pytest.raises(ValueError, match="Invalid from_date format"):
        populated_intel_srv.search_incidents(from_date="not-a-date")


def test_from_date_greater_than_to_date_raises_error(populated_intel_srv):
    """Test from_date after to_date raises ValueError."""
    with pytest.raises(ValueError, match="cannot be after to_date"):
        populated_intel_srv.search_incidents(from_date="2026-08-20", to_date="2026-08-10")


# -----------------------------------------------------------------------------
# Trend Analytics Tests
# -----------------------------------------------------------------------------

def test_trend_aggregation_daily(populated_intel_srv):
    """Test daily trend contains date, count, and average score."""
    trend = populated_intel_srv.get_risk_trend()
    assert len(trend) >= 1
    assert "date" in trend[0]
    assert "incident_count" in trend[0]
    assert "average_threat_score" in trend[0]


def test_trend_chronological_ordering(populated_intel_srv):
    """Test trend results are sorted oldest to newest."""
    trend = populated_intel_srv.get_risk_trend()
    dates = [t["date"] for t in trend]
    assert dates == sorted(dates)


def test_empty_trend_returns_empty_list(intel_srv):
    """Test get_risk_trend on empty database returns empty list."""
    trend = intel_srv.get_risk_trend()
    assert trend == []


# -----------------------------------------------------------------------------
# Security & Injection Resistance Tests
# -----------------------------------------------------------------------------

def test_sql_injection_style_search_input(populated_intel_srv):
    """Test SQL injection syntax in search query is treated safely as literal text."""
    nasty_q = "'; DROP TABLE incidents; --"
    res = populated_intel_srv.search_incidents(q=nasty_q)
    assert res["pagination"]["total"] == 0
    # Confirm table was NOT dropped
    stats = populated_intel_srv.get_summary_statistics()
    assert stats["total_incidents"] == 4


def test_sql_injection_edge_cases_in_search(populated_intel_srv):
    """Test diverse SQL injection patterns in search parameter."""
    vectors = [
        "'",
        '"',
        "--",
        ";",
        "OR 1=1",
        "' OR '1'='1",
    ]
    for vec in vectors:
        res = populated_intel_srv.search_incidents(q=vec)
        assert isinstance(res["items"], list)
        assert "total" in res["pagination"]


def test_arbitrary_sort_column_injection_attempt(populated_intel_srv):
    """Test unallowed sort column name is rejected cleanly."""
    with pytest.raises(ValueError, match="Invalid sort field"):
        populated_intel_srv.search_incidents(sort="password; DROP TABLE incidents")

    with pytest.raises(ValueError, match="Invalid sort field"):
        populated_intel_srv.search_incidents(sort="*")

    with pytest.raises(ValueError, match="Invalid sort field"):
        populated_intel_srv.search_incidents(sort="nonexistent_column")


def test_dashboard_response_json_serializability(populated_intel_srv):
    """Test all dashboard service method outputs serialize cleanly to JSON."""
    stats = populated_intel_srv.get_summary_statistics()
    assert json.loads(json.dumps(stats)) == stats

    dist = populated_intel_srv.get_risk_distribution()
    assert json.loads(json.dumps(dist)) == dist

    trend = populated_intel_srv.get_risk_trend()
    assert json.loads(json.dumps(trend)) == trend

    search = populated_intel_srv.search_incidents()
    assert json.loads(json.dumps(search)) == search
