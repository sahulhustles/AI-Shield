"""Unit tests for Module 2: ThreatAnalyzer service class."""

import json
import pytest
from services.threat_analyzer import ThreatAnalyzer


@pytest.fixture
def analyzer():
    """Fixture providing a ThreatAnalyzer instance."""
    return ThreatAnalyzer()


def test_normal_text(analyzer):
    """Test standard neutral text produces low threat score and Normal category."""
    text = "We planted sunflowers in the backyard garden this morning. They should bloom by late summer."
    res = analyzer.analyze(text)

    assert isinstance(res, dict)
    assert res["category"] == "Normal"
    assert res["risk_level"] == "LOW"
    assert res["threat_score"] <= 29.0
    assert len(res["indicators"]) == 0
    assert len(res["reasons"]) > 0


def test_empty_text(analyzer):
    """Test empty string raises ValueError."""
    with pytest.raises(ValueError, match="Input text cannot be empty or whitespace-only."):
        analyzer.analyze("")


def test_whitespace_text(analyzer):
    """Test whitespace-only string raises ValueError."""
    with pytest.raises(ValueError, match="Input text cannot be empty or whitespace-only."):
        analyzer.analyze("   \n\t  ")


def test_invalid_input_type(analyzer):
    """Test non-string inputs (None, int, list, dict) raise ValueError."""
    with pytest.raises(ValueError, match="Input text cannot be None."):
        analyzer.analyze(None)

    with pytest.raises(ValueError, match="Input text must be a string"):
        analyzer.analyze(12345)

    with pytest.raises(ValueError, match="Input text must be a string"):
        analyzer.analyze(["some", "text"])


def test_urgency_indicator(analyzer):
    """Test detection of urgency phrases."""
    text = "CRITICAL ALERT: Urgent action required! You must do this immediately before it is too late within 24 hours."
    res = analyzer.analyze(text)

    urgency_ind = next((ind for ind in res["indicators"] if ind["type"] == "urgency"), None)
    assert urgency_ind is not None
    assert urgency_ind["count"] >= 3
    assert urgency_ind["severity"] in ["medium", "high"]
    assert res["component_scores"]["urgency"] > 50.0


def test_manipulation_indicator(analyzer):
    """Test detection of emotional and conspiratorial manipulation cues."""
    text = "Wake up people! They are hiding the real story and they don't want you to know. Share before deleted!"
    res = analyzer.analyze(text)

    man_ind = next((ind for ind in res["indicators"] if ind["type"] == "manipulation"), None)
    assert man_ind is not None
    assert man_ind["count"] >= 2
    assert res["component_scores"]["manipulation"] > 50.0


def test_call_to_action_indicator(analyzer):
    """Test detection of repetitive suspicious call-to-action prompts."""
    text = "Click here to download now! Forward this to all your contacts and verify now."
    res = analyzer.analyze(text)

    cta_ind = next((ind for ind in res["indicators"] if ind["type"] == "call_to_action"), None)
    assert cta_ind is not None
    assert cta_ind["count"] >= 2
    assert res["component_scores"]["call_to_action"] > 50.0


def test_unverified_claim_indicator(analyzer):
    """Test detection of sensationalized unverified claims."""
    text = "Shocking truth revealed by insider reveals secret information with 100% guaranteed undeniable proof!"
    res = analyzer.analyze(text)

    unc_ind = next((ind for ind in res["indicators"] if ind["type"] == "unverified_claims"), None)
    assert unc_ind is not None
    assert unc_ind["count"] >= 3
    assert res["component_scores"]["unverified_claims"] > 50.0


def test_authority_indicator(analyzer):
    """Test detection of authority and official notice impersonation."""
    text = "Official notice from the government announcement and official security team alert regarding your status."
    res = analyzer.analyze(text)

    aut_ind = next((ind for ind in res["indicators"] if ind["type"] == "authority_impersonation"), None)
    assert aut_ind is not None
    assert aut_ind["count"] >= 2
    assert res["component_scores"]["authority_patterns"] > 50.0


def test_category_detection(analyzer):
    """Test that detect_categories returns a recognized category."""
    valid_categories = {"Normal", "Phishing", "Disinformation", "Manipulation", "Propaganda", "Spam", "Other"}
    text = "Just having coffee at the downtown cafe."
    indicators = analyzer.detect_indicators(text)
    category, scores = analyzer.detect_categories(indicators)

    assert category in valid_categories
    assert isinstance(scores, dict)


def test_phishing_like_example(analyzer):
    """Test phishing attack payload categorized as Phishing with elevated risk."""
    phishing_text = (
        "Official Security Alert: Your account is suspended due to unauthorized login detected! "
        "Verify your account and confirm your password immediately by clicking the link within 24 hours."
    )
    res = analyzer.analyze(phishing_text)

    assert res["category"] == "Phishing"
    assert res["threat_score"] >= 50.0
    assert res["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"]


def test_disinformation_like_example(analyzer):
    """Test conspiracy/disinformation text categorized as Disinformation."""
    disinfo_text = (
        "Shocking truth: Leaked information and classified evidence confirmed by insiders! "
        "They are hiding this miracle cure from the public. People need to know!"
    )
    res = analyzer.analyze(disinfo_text)

    assert res["category"] in ["Disinformation", "Manipulation"]
    assert res["threat_score"] >= 40.0


def test_normal_category(analyzer):
    """Test benign everyday paragraphs receive Normal category."""
    benign_text = "I went to the grocery store to buy organic milk, apples, and whole wheat sourdough bread."
    res = analyzer.analyze(benign_text)

    assert res["category"] == "Normal"
    assert res["risk_level"] == "LOW"


def test_propaganda_category(analyzer):
    """Test state/institutional authority combined with heavy emotional manipulation."""
    text = (
        "Official government announcement: You must obey all state directives! "
        "Mainstream media won't tell you the truth, but insider reveals secret information. Wake up and resist now!"
    )
    res = analyzer.analyze(text)
    assert res["category"] in ["Propaganda", "Manipulation", "Disinformation"]
    assert res["threat_score"] >= 40.0


def test_spam_category(analyzer):
    """Test high promotional call-to-action without credential attack."""
    text = "Limited time offer! Claim your prize now and click here to redeem now before it expires today! Forward this to your friends."
    res = analyzer.analyze(text)
    assert res["category"] in ["Spam", "Manipulation"]
    assert res["threat_score"] >= 30.0


def test_other_category_fallback(analyzer):
    """Test diffuse elevated indicator signals fall back gracefully to Other when no single category dominates."""
    indicator_results = {
        "urgency": {"count": 1, "score": 35.0, "severity": "low", "matched_patterns": []},
        "manipulation": {"count": 0, "score": 0.0, "severity": "none", "matched_patterns": []},
        "call_to_action": {"count": 0, "score": 0.0, "severity": "none", "matched_patterns": []},
        "unverified_claims": {"count": 0, "score": 0.0, "severity": "none", "matched_patterns": []},
        "authority_impersonation": {"count": 0, "score": 0.0, "severity": "none", "matched_patterns": []},
        "credential_phishing": {"count": 0, "score": 0.0, "severity": "none", "matched_patterns": []},
    }
    cat, scores = analyzer.detect_categories(indicator_results)
    assert cat in ["Other", "Normal", "Spam"]


def test_overlapping_patterns_deduplication(analyzer):
    """Test that overlapping phrases within the same indicator group are not double-counted."""
    text = "Official security alert and official notice regarding account status."
    indicators = analyzer.detect_indicators(text)
    aut_count = indicators["authority_impersonation"]["count"]
    # "Official security alert" should count as 1 match, not 2 overlapping matches for "official security alert" and "security alert"
    assert aut_count == 2  # "official security alert" (1) + "official notice" (1)


def test_negation_across_sentence_boundary(analyzer):
    """Test that a negation in a previous sentence does NOT suppress indicators in the following sentence."""
    text = "I do not agree with the prior assessment. Urgent action required immediately!"
    res = analyzer.analyze(text)

    # "Urgent" in the second sentence should be detected
    assert res["component_scores"]["urgency"] > 0.0
    urg_ind = next((ind for ind in res["indicators"] if ind["type"] == "urgency"), None)
    assert urg_ind is not None
    assert urg_ind["count"] >= 1


def test_score_range(analyzer):
    """Test that threat scores are strictly clamped in [0.0, 100.0]."""
    test_cases = [
        "Quiet sunny morning.",
        "URGENT ACT NOW CLICK HERE VERIFY PASSWORD BEFORE SUSPENDED ACCOUNT OFFICIAL NOTICE LEAKED INFORMATION!",
        "A neutral essay regarding solar panel engineering and thermal conductivity.",
    ]
    for text in test_cases:
        res = analyzer.analyze(text)
        assert 0.0 <= res["threat_score"] <= 100.0


def test_deterministic_score(analyzer):
    """Test that multiple analyses on the same text yield strictly identical scores."""
    text = "Urgent: official notice regarding your account status. Click here immediately."
    pred = {"ai_probability": 0.82, "human_probability": 0.18, "confidence": 0.82}

    res1 = analyzer.analyze(text, module1_prediction=pred)
    res2 = analyzer.analyze(text, module1_prediction=pred)

    assert res1["threat_score"] == res2["threat_score"]
    assert res1["risk_level"] == res2["risk_level"]
    assert res1["category"] == res2["category"]
    assert res1["component_scores"] == res2["component_scores"]


def test_risk_boundaries(analyzer):
    """Test explicit risk boundary mappings."""
    assert analyzer.determine_risk_level(0.0) == "LOW"
    assert analyzer.determine_risk_level(29.0) == "LOW"
    assert analyzer.determine_risk_level(29.1) == "MEDIUM"
    assert analyzer.determine_risk_level(30.0) == "MEDIUM"
    assert analyzer.determine_risk_level(59.0) == "MEDIUM"
    assert analyzer.determine_risk_level(59.5) == "HIGH"
    assert analyzer.determine_risk_level(60.0) == "HIGH"
    assert analyzer.determine_risk_level(79.0) == "HIGH"
    assert analyzer.determine_risk_level(79.5) == "CRITICAL"
    assert analyzer.determine_risk_level(80.0) == "CRITICAL"
    assert analyzer.determine_risk_level(100.0) == "CRITICAL"


def test_indicator_explanations(analyzer):
    """Test that reasons list contains descriptive, explainable text."""
    text = "Act now! Secret information they are hiding from you. Share this immediately!"
    res = analyzer.analyze(text)

    assert isinstance(res["reasons"], list)
    assert len(res["reasons"]) >= 2
    for r in res["reasons"]:
        assert isinstance(r, str)
        assert len(r) > 10


def test_component_scores(analyzer):
    """Test component scores dictionary structure and bounds."""
    text = "Official notice: urgent account verification."
    res = analyzer.analyze(text)

    scores = res["component_scores"]
    assert isinstance(scores, dict)
    expected_components = {"urgency", "manipulation", "call_to_action", "unverified_claims", "authority_patterns", "category_severity"}
    assert expected_components.issubset(scores.keys())

    for comp, val in scores.items():
        assert 0.0 <= val <= 100.0


def test_valid_module1_prediction_integration(analyzer):
    """Test that valid Module 1 prediction is properly factored into the score."""
    text = "Standard informative paragraph on climate metrics."
    pred_high_ai = {"ai_probability": 0.95, "human_probability": 0.05, "confidence": 0.95}
    pred_low_ai = {"ai_probability": 0.05, "human_probability": 0.95, "confidence": 0.95}

    res_high = analyzer.analyze(text, module1_prediction=pred_high_ai)
    res_low = analyzer.analyze(text, module1_prediction=pred_low_ai)

    assert res_high["component_scores"]["ai_likelihood"] == 95.0
    assert res_low["component_scores"]["ai_likelihood"] == 5.0
    assert res_high["threat_score"] > res_low["threat_score"]


def test_invalid_module1_prediction(analyzer):
    """Test invalid Module 1 prediction values raise ValueError."""
    text = "Valid text"

    # Out of bounds probability (> 1.0)
    with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
        analyzer.analyze(text, module1_prediction={"ai_probability": 1.5, "human_probability": 0.1, "confidence": 0.9})

    # Missing required keys
    with pytest.raises(ValueError, match="missing required keys"):
        analyzer.analyze(text, module1_prediction={"ai_probability": 0.5})

    # Invalid non-numeric type
    with pytest.raises(ValueError, match="must be a numeric"):
        analyzer.analyze(text, module1_prediction={"ai_probability": "high", "human_probability": 0.2, "confidence": 0.8})

    # Probabilities do not sum to 1.0
    with pytest.raises(ValueError, match="probabilities must sum approximately to 1.0"):
        analyzer.analyze(text, module1_prediction={"ai_probability": 0.1, "human_probability": 0.1, "confidence": 0.1})


def test_missing_module1_prediction(analyzer):
    """Test analyzer operates cleanly with fallback when Module 1 prediction is omitted."""
    text = "Urgent: do this now immediately!"
    res = analyzer.analyze(text, module1_prediction=None)

    assert isinstance(res, dict)
    assert res["component_scores"]["ai_likelihood"] == 0.0
    assert 0.0 <= res["threat_score"] <= 100.0


def test_json_serializability(analyzer):
    """Test that complete output dictionary is fully JSON-serializable."""
    text = "Official warning: unauthorized login detected on your account. Click here to verify now."
    pred = {"ai_probability": 0.75, "human_probability": 0.25, "confidence": 0.75}

    res = analyzer.analyze(text, module1_prediction=pred)
    json_str = json.dumps(res)

    assert isinstance(json_str, str)
    loaded = json.loads(json_str)
    assert loaded["category"] == res["category"]
    assert loaded["threat_score"] == res["threat_score"]


def test_negation_awareness(analyzer):
    """Test that negated urgency words do not trigger urgency indicator."""
    text_negated = "Please review this document at your convenience; this task is not urgent and there is no hurry."
    text_urgent = "Please review this document immediately; this task is urgent and requires immediate action."

    res_neg = analyzer.analyze(text_negated)
    res_urg = analyzer.analyze(text_urgent)

    assert res_neg["component_scores"]["urgency"] == 0.0
    assert res_urg["component_scores"]["urgency"] > 0.0
    assert res_neg["threat_score"] < res_urg["threat_score"]
