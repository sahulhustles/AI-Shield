"""AIShield - Centralized Incident Creation Policy (Stage 6F).

Evaluates AI detection, text metrics, and threat analysis results to decide
whether an analyzed source post warrants an immutable forensic incident.
"""

import logging
from typing import Any, Dict, Optional, Set, Tuple

from config import (
    INCIDENT_POLICY_MIN_AI_PROBABILITY,
    INCIDENT_POLICY_MIN_THREAT_SCORE,
    INCIDENT_POLICY_SECONDARY_THREAT_SCORE,
)

logger = logging.getLogger("AIShield.IncidentPolicy")


class IncidentPolicy:
    """Configurable decision policy governing forensic incident generation."""

    def __init__(
        self,
        min_threat_score: Optional[float] = None,
        min_ai_prob: Optional[float] = None,
        secondary_threat_score: Optional[float] = None,
        high_risk_levels: Optional[Set[str]] = None,
    ) -> None:
        """Initialize IncidentPolicy with configurable numeric thresholds."""
        self.min_threat_score = (
            float(min_threat_score)
            if min_threat_score is not None
            else INCIDENT_POLICY_MIN_THREAT_SCORE
        )
        self.min_ai_prob = (
            float(min_ai_prob)
            if min_ai_prob is not None
            else INCIDENT_POLICY_MIN_AI_PROBABILITY
        )
        self.secondary_threat_score = (
            float(secondary_threat_score)
            if secondary_threat_score is not None
            else INCIDENT_POLICY_SECONDARY_THREAT_SCORE
        )
        self.high_risk_levels = (
            {lvl.upper() for lvl in high_risk_levels}
            if high_risk_levels is not None
            else {"HIGH", "CRITICAL"}
        )

    def evaluate(
        self,
        ai_prediction: Dict[str, Any],
        text_analysis: Dict[str, Any],
        threat_analysis: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Evaluate analysis components and return (should_create_incident, reason).

        Criteria:
        1. Explicit HIGH or CRITICAL risk_level.
        2. threat_score >= min_threat_score (default 60.0).
        3. ai_probability >= min_ai_prob (default 0.85) AND threat_score >= secondary_threat_score (default 40.0).
        """
        threat_score = float(threat_analysis.get("threat_score", 0.0))
        risk_level = str(threat_analysis.get("risk_level", "LOW")).upper()
        ai_prob = float(ai_prediction.get("ai_probability", 0.0))

        # Rule 1: High / Critical risk level
        if risk_level in self.high_risk_levels:
            return (
                True,
                f"Risk level '{risk_level}' meets forensic incident creation threshold.",
            )

        # Rule 2: Primary threat score threshold
        if threat_score >= self.min_threat_score:
            return (
                True,
                f"Threat score {threat_score:.1f} exceeds primary threshold of {self.min_threat_score:.1f}.",
            )

        # Rule 3: High AI probability combined with secondary threat score
        if ai_prob >= self.min_ai_prob and threat_score >= self.secondary_threat_score:
            return (
                True,
                f"Elevated AI probability ({ai_prob:.2f}) with threat score ({threat_score:.1f} >= {self.secondary_threat_score:.1f}) meets secondary threshold.",
            )

        # Non-incident threshold
        return (
            False,
            f"Content evaluated below incident thresholds (Threat: {threat_score:.1f}, Risk: {risk_level}, AI: {ai_prob:.2f}). Marked ANALYZED without incident.",
        )
