"""AIShield - Module 2: Threat Analysis & Risk Scoring.

Provides rule-based linguistic threat detection, content categorization,
deterministic risk scoring (0-100), and explainable evidence generation.
"""

from collections import Counter
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple, Union


class ThreatAnalyzer:
    """Evaluates text for linguistic manipulation, deception, phishing, and threat signals."""

    # Explicit risk level boundaries
    RISK_BOUNDARIES = [
        (29.0, "LOW"),
        (59.0, "MEDIUM"),
        (79.0, "HIGH"),
        (100.0, "CRITICAL"),
    ]

    # Category severity base scores (0 to 100 scale)
    CATEGORY_SEVERITY_WEIGHTS = {
        "Phishing": 95.0,
        "Disinformation": 85.0,
        "Propaganda": 80.0,
        "Manipulation": 70.0,
        "Spam": 45.0,
        "Other": 40.0,
        "Normal": 0.0,
    }

    # Negation prefix terms for contextual suppression
    NEGATION_TERMS = {
        "not", "no", "never", "isnt", "isn't", "wasnt", "wasn't", "dont", "don't",
        "doesnt", "doesn't", "didnt", "didn't", "hardly", "unlikely", "without"
    }

    # Heuristic indicator rule definitions (multi-word patterns and phrases)
    INDICATOR_RULES = {
        "urgency": [
            r"\burgent(ly)?\b",
            r"\bimmediate(ly)?\b",
            r"\bact now\b",
            r"\bdo this now\b",
            r"\bbefore it is too late\b",
            r"\blast chance\b",
            r"\blimited time\b",
            r"\bimmediate action required\b",
            r"\bexpires (today|soon|within)\b",
            r"\bwithin \d+ hours\b",
            r"\bhurry( up)?\b",
            r"\btime is running out\b",
            r"\bcritical alert\b",
            r"\baction required\b",
            r"\baccount (is |has been )?suspended\b",
            r"\baccount (is |has been )?locked\b",
        ],
        "manipulation": [
            r"\beveryone must\b",
            r"\byou must\b",
            r"\bthey are hiding\b",
            r"\bdon't trust\b",
            r"\bdont trust\b",
            r"\bwake up\b",
            r"\bpeople need to know\b",
            r"\bthey don't want you to know\b",
            r"\bthey dont want you to know\b",
            r"\bopen your eyes\b",
            r"\bdo your own research\b",
            r"\bmainstream media won't tell you\b",
            r"\bthey are lying\b",
            r"\bstop being sheep\b",
            r"\bresist now\b",
            r"\bshare before deleted\b",
            r"\bunauthorized (login|access|activity)\b",
            r"\bsecurity compromised\b",
        ],
        "call_to_action": [
            r"\bclick(ing)? (here|this|the link|on the link)\b",
            r"\bforward(ing)? this\b",
            r"\bshare(ing)? this\b",
            r"\bsend(ing)? this\b",
            r"\bsign up immediately\b",
            r"\bverify (now|your account|your password|your identity|your details)\b",
            r"\bconfirm (your password|your account|your identity|your email)\b",
            r"\bdownload(ing)? (now|this|the file)\b",
            r"\bupdate your account\b",
            r"\bclaim (your )?(prize|reward)\b",
            r"\bfollow (this )?link\b",
            r"\bopen this attachment\b",
            r"\btap here\b",
            r"\bredeem now\b",
        ],
        "unverified_claims": [
            r"\bsecret information\b",
            r"\bshocking truth\b",
            r"\bconfirmed by insiders\b",
            r"\bleaked (information|documents|files|evidence)\b",
            r"\bhidden truth\b",
            r"\bthey are hiding this\b",
            r"\b100% guaranteed\b",
            r"\bmiracle cure\b",
            r"\bundeniable proof\b",
            r"\bwhat they won't tell you\b",
            r"\binsider reveals\b",
            r"\banonymous source confirms\b",
            r"\bclassified evidence\b",
        ],
        "authority_impersonation": [
            r"\bofficial (notice|warning|alert|announcement|security|message)\b",
            r"\b(official )?security (alert|department|team|notice|warning)\b",
            r"\bgovernment announcement\b",
            r"\bauthorized message\b",
            r"\binternal revenue service\b",
            r"\birs notice\b",
            r"\baccount suspension department\b",
            r"\bfraud prevention team\b",
            r"\blaw enforcement alert\b",
            r"\bcourt notice\b",
            r"\bsystem administrator alert\b",
            r"\bfederal agency warning\b",
        ],
        "credential_phishing": [
            r"\bverify your account\b",
            r"\baccount (is |has been )?suspended\b",
            r"\blogin to restore\b",
            r"\b(enter|confirm) your password\b",
            r"\bbilling failure\b",
            r"\bsecurity compromised\b",
            r"\breactivate account\b",
            r"\bunauthorized (login|access) detected\b",
            r"\bverify billing details\b",
            r"\breset your security credentials\b",
            r"\bunusual sign-in activity\b",
            r"\baccount (is )?locked\b",
            r"\bsecurity credentials expired\b",
        ],
    }

    # Short, human-readable indicator explanations
    INDICATOR_DESCRIPTIONS = {
        "urgency": "Urgency and artificial time pressure phrasing.",
        "manipulation": "Emotional manipulation or conspiracy-oriented pressure phrasing.",
        "call_to_action": "Suspicious or repetitive call-to-action prompt.",
        "unverified_claims": "Sensational unverified claim styled as insider knowledge.",
        "authority_impersonation": "Language imitating institutional or authority entities.",
        "credential_phishing": "Credential harvesting or account suspension prompt.",
    }

    def __init__(self) -> None:
        """Initialize the ThreatAnalyzer instance."""
        pass

    def _normalize_text(self, text: str) -> str:
        """Normalize text for consistent rule-based pattern matching."""
        if not text:
            return ""
        norm = unicodedata.normalize("NFKC", text).lower()
        # Collapse multiple spaces and linebreaks to single space
        return re.sub(r"\s+", " ", norm).strip()

    def _validate_inputs(
        self,
        text: Any,
        module1_prediction: Optional[Any] = None,
        text_analysis: Optional[Any] = None,
    ) -> None:
        """Validate input parameters rigorously.

        Raises:
            ValueError: If input text or prediction structures are malformed.
        """
        if text is None:
            raise ValueError("Input text cannot be None.")
        if not isinstance(text, str):
            raise ValueError(f"Input text must be a string, got {type(text).__name__}.")
        if not text.strip():
            raise ValueError("Input text cannot be empty or whitespace-only.")

        # Validate Module 1 prediction if supplied
        if module1_prediction is not None:
            if not isinstance(module1_prediction, dict):
                raise ValueError(
                    f"module1_prediction must be a dictionary, got {type(module1_prediction).__name__}."
                )

            required_keys = {"ai_probability", "human_probability", "confidence"}
            if not required_keys.issubset(module1_prediction.keys()):
                raise ValueError(
                    f"module1_prediction is missing required keys {required_keys - set(module1_prediction.keys())}."
                )

            ai_prob = module1_prediction["ai_probability"]
            human_prob = module1_prediction["human_probability"]
            conf = module1_prediction["confidence"]

            for name, val in [("ai_probability", ai_prob), ("human_probability", human_prob), ("confidence", conf)]:
                if not isinstance(val, (int, float)) or isinstance(val, bool):
                    raise ValueError(f"module1_prediction['{name}'] must be a numeric float/int, got {type(val).__name__}.")
                if not (0.0 <= val <= 1.0):
                    raise ValueError(f"module1_prediction['{name}'] must be between 0.0 and 1.0, got {val}.")

            # Validate approximate probability sum
            if abs((ai_prob + human_prob) - 1.0) > 0.06:
                raise ValueError(
                    f"module1_prediction probabilities must sum approximately to 1.0, got {ai_prob + human_prob}."
                )

        # Validate text_analysis if supplied
        if text_analysis is not None:
            if not isinstance(text_analysis, dict):
                raise ValueError(
                    f"text_analysis must be a dictionary, got {type(text_analysis).__name__}."
                )

    def _is_negated(self, text: str, match_start_idx: int) -> bool:
        """Check if a matched phrase is directly preceded by a negation term within the same sentence/clause (up to 3 words)."""
        prefix = text[:match_start_idx].strip()
        if not prefix:
            return False

        # Isolate the current clause after the nearest sentence-ending punctuation
        clause_break = max(
            prefix.rfind("."),
            prefix.rfind("!"),
            prefix.rfind("?"),
            prefix.rfind(";"),
            prefix.rfind("\n"),
        )
        if clause_break != -1:
            clause = prefix[clause_break + 1:].strip()
        else:
            clause = prefix

        if not clause:
            return False

        # Get up to 3 preceding words in this clause
        preceding_words = re.findall(r"\b[\w']+\b", clause)[-3:]
        for w in preceding_words:
            if w.lower() in self.NEGATION_TERMS:
                return True
        return False

    def detect_indicators(self, text: str) -> Dict[str, Dict[str, Any]]:
        """Detect matched linguistic indicators with negation awareness and intensity capping.

        Eliminates overlapping spans within the same indicator group.

        Returns:
            Dict mapping indicator group name to its match metrics:
            {
                "count": int,
                "score": float (0-100),
                "severity": "none" | "low" | "medium" | "high",
                "matched_patterns": List[str]
            }
        """
        normalized = self._normalize_text(text)
        indicator_results = {}

        for group, patterns in self.INDICATOR_RULES.items():
            candidate_matches = []

            for pattern in patterns:
                for match in re.finditer(pattern, normalized):
                    # Filter out negated mentions within the clause
                    if not self._is_negated(normalized, match.start()):
                        candidate_matches.append((match.start(), match.end(), match.group(0)))

            # Sort candidate matches by start ascending, then length descending
            candidate_matches.sort(key=lambda m: (m[0], -(m[1] - m[0])))

            # Deduplicate overlapping character spans within the group
            non_overlapping = []
            last_end = -1
            for start, end, match_text in candidate_matches:
                if start >= last_end:
                    non_overlapping.append(match_text)
                    last_end = end

            count = len(non_overlapping)

            # Intensity scoring with diminishing returns to avoid single-keyword bias
            if count == 0:
                score = 0.0
                severity = "none"
            elif count == 1:
                score = 35.0
                severity = "low"
            elif count == 2:
                score = 65.0
                severity = "medium"
            elif count == 3:
                score = 85.0
                severity = "high"
            else:
                score = 100.0
                severity = "high"

            indicator_results[group] = {
                "count": count,
                "score": float(score),
                "severity": severity,
                "matched_patterns": non_overlapping,
            }

        return indicator_results

    def detect_categories(
        self,
        indicator_results: Dict[str, Dict[str, Any]],
        ai_prob: Optional[float] = None,
    ) -> Tuple[str, Dict[str, float]]:
        """Classify content into a primary category using transparent heuristic scores.

        Categories:
            - Normal
            - Phishing
            - Disinformation
            - Manipulation
            - Propaganda
            - Spam
            - Other

        Returns:
            Tuple of (primary_category_name, category_candidate_scores)
        """
        urg_score = indicator_results.get("urgency", {}).get("score", 0.0)
        man_score = indicator_results.get("manipulation", {}).get("score", 0.0)
        cta_score = indicator_results.get("call_to_action", {}).get("score", 0.0)
        unc_score = indicator_results.get("unverified_claims", {}).get("score", 0.0)
        aut_score = indicator_results.get("authority_impersonation", {}).get("score", 0.0)
        phish_score = indicator_results.get("credential_phishing", {}).get("score", 0.0)

        # Calculate candidate scores for each category
        scores = {
            "Phishing": (phish_score * 0.50) + (cta_score * 0.25) + (urg_score * 0.25),
            "Disinformation": (unc_score * 0.55) + (man_score * 0.25) + (aut_score * 0.20),
            "Manipulation": (man_score * 0.60) + (urg_score * 0.20) + (cta_score * 0.20),
            "Propaganda": (aut_score * 0.45) + (man_score * 0.35) + (unc_score * 0.20),
            "Spam": (cta_score * 0.60) + (urg_score * 0.40) if phish_score < 20.0 else 0.0,
        }

        # Deterministic priority order for tie-breaking
        priority_order = ["Phishing", "Disinformation", "Manipulation", "Propaganda", "Spam"]
        max_score = max(scores.values())

        if max_score < 25.0:
            # Check if any indicator group is elevated despite diffuse category signals
            max_indicator_score = max(
                (res.get("score", 0.0) for res in indicator_results.values()),
                default=0.0,
            )
            if max_indicator_score >= 35.0:
                primary_category = "Other"
            else:
                primary_category = "Normal"
        else:
            # Select top candidate respecting deterministic priority
            top_candidates = [cat for cat in priority_order if abs(scores[cat] - max_score) < 1e-5]
            primary_category = top_candidates[0] if top_candidates else "Other"

        return primary_category, scores

    def calculate_threat_score(
        self,
        indicator_results: Dict[str, Dict[str, Any]],
        category: str,
        module1_prediction: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, Dict[str, float]]:
        """Calculate a deterministic, normalized threat score between 0.0 and 100.0.

        Formula weights (when AI evidence is available):
            - AI Likelihood:           20%
            - Urgency / Pressure:      15%
            - Manipulation:            20%
            - Suspicious CTA:          15%
            - Unverified Claims:       15%
            - Authority Impersonation: 10%
            - Category Severity:        5%

        Returns:
            Tuple of (overall_threat_score, component_scores_dict)
        """
        urg_score = indicator_results.get("urgency", {}).get("score", 0.0)
        man_score = indicator_results.get("manipulation", {}).get("score", 0.0)
        cta_score = indicator_results.get("call_to_action", {}).get("score", 0.0)
        unc_score = indicator_results.get("unverified_claims", {}).get("score", 0.0)
        aut_score = indicator_results.get("authority_impersonation", {}).get("score", 0.0)
        cat_severity = self.CATEGORY_SEVERITY_WEIGHTS.get(category, 0.0)

        component_scores = {
            "urgency": float(urg_score),
            "manipulation": float(man_score),
            "call_to_action": float(cta_score),
            "unverified_claims": float(unc_score),
            "authority_patterns": float(aut_score),
            "category_severity": float(cat_severity),
        }

        if module1_prediction is not None and "ai_probability" in module1_prediction:
            ai_prob = float(module1_prediction["ai_probability"])
            ai_score = ai_prob * 100.0
            component_scores["ai_likelihood"] = float(ai_score)

            raw_score = (
                (0.20 * ai_score)
                + (0.15 * urg_score)
                + (0.20 * man_score)
                + (0.15 * cta_score)
                + (0.15 * unc_score)
                + (0.10 * aut_score)
                + (0.05 * cat_severity)
            )
        else:
            # Rebalance remaining 80% weight proportionally when AI evidence is omitted
            component_scores["ai_likelihood"] = 0.0
            raw_subtotal = (
                (0.15 * urg_score)
                + (0.20 * man_score)
                + (0.15 * cta_score)
                + (0.15 * unc_score)
                + (0.10 * aut_score)
                + (0.05 * cat_severity)
            )
            raw_score = raw_subtotal / 0.80

        # Strictly clamp threat score between 0.0 and 100.0
        threat_score = max(0.0, min(100.0, float(raw_score)))
        return threat_score, component_scores

    @classmethod
    def determine_risk_level(cls, score: float) -> str:
        """Map a numeric threat score (0-100) to an explicit qualitative risk level.

        Explicit boundaries:
            0 - 29:   LOW
            30 - 59:  MEDIUM
            60 - 79:  HIGH
            80 - 100: CRITICAL
        """
        # Numerical normalization
        score_val = max(0.0, min(100.0, float(score)))

        if score_val <= 29.0:
            return "LOW"
        elif score_val <= 59.0:
            return "MEDIUM"
        elif score_val <= 79.0:
            return "HIGH"
        else:
            return "CRITICAL"

    def _generate_explanations(
        self,
        threat_score: float,
        risk_level: str,
        category: str,
        indicator_results: Dict[str, Dict[str, Any]],
        module1_prediction: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Generate 2-4 concise, factual, and evidence-backed explanations for the score."""
        reasons = []

        # 1. Quantified indicator evidence
        urg_count = indicator_results.get("urgency", {}).get("count", 0)
        if urg_count == 1:
            reasons.append("One urgency-related expression was detected urging rapid action.")
        elif urg_count > 1:
            reasons.append(f"{urg_count} urgency-related expressions were detected urging rapid action.")

        phish_count = indicator_results.get("credential_phishing", {}).get("count", 0)
        if phish_count == 1:
            reasons.append("One credential or account verification prompt characteristic of phishing was detected.")
        elif phish_count > 1:
            reasons.append(f"{phish_count} credential or account verification prompts characteristic of phishing were detected.")

        man_count = indicator_results.get("manipulation", {}).get("count", 0)
        if man_count == 1:
            reasons.append("One emotional or conspiratorial manipulation phrase was identified.")
        elif man_count > 1:
            reasons.append(f"{man_count} emotional or conspiratorial manipulation phrases were identified.")

        cta_count = indicator_results.get("call_to_action", {}).get("count", 0)
        if cta_count == 1:
            reasons.append("One suspicious call-to-action prompt was detected.")
        elif cta_count > 1:
            reasons.append(f"{cta_count} suspicious call-to-action prompts were detected.")

        unc_count = indicator_results.get("unverified_claims", {}).get("count", 0)
        if unc_count == 1:
            reasons.append("One sensational unverified claim pattern was observed.")
        elif unc_count > 1:
            reasons.append(f"{unc_count} sensational unverified claim patterns were observed.")

        aut_count = indicator_results.get("authority_impersonation", {}).get("count", 0)
        if aut_count == 1:
            reasons.append("One phrase referencing institutional authority or official alerts was detected.")
        elif aut_count > 1:
            reasons.append(f"{aut_count} phrases referencing institutional authority or official alerts were detected.")

        # 2. Category classification explanation
        if category != "Normal":
            reasons.append(f"Content classified as '{category}' due to dominant indicator signals.")

        # 3. AI detection contribution explanation
        if module1_prediction is not None:
            ai_prob = float(module1_prediction.get("ai_probability", 0.0))
            if ai_prob >= 0.70:
                reasons.append(f"Module 1 observed elevated synthetic AI likelihood ({ai_prob * 100:.1f}%).")
            elif ai_prob <= 0.30 and not reasons:
                reasons.append("Linguistic patterns align closely with natural human-written communication.")

        # 4. Fallback for clean neutral content
        if not reasons:
            reasons.append("No significant manipulation, urgency, or deceptive threat indicators were detected.")
            reasons.append("Linguistic structure is consistent with standard, low-risk written communication.")

        # Limit to top 4 most informative reasons
        return reasons[:4]

    def analyze(
        self,
        text: Any,
        module1_prediction: Optional[Dict[str, Any]] = None,
        text_analysis: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute full Module 2 threat analysis and risk scoring.

        Args:
            text: Input string to evaluate.
            module1_prediction: Optional prediction output from Module 1 (AIDetector).
            text_analysis: Optional text statistics output from Module 1 (TextAnalyzer).

        Returns:
            Dict matching the standard Module 2 contract:
            {
                "threat_score": float,
                "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
                "category": str,
                "indicators": List[Dict],
                "reasons": List[str],
                "component_scores": Dict[str, float]
            }
        """
        # 1. Input Validation
        self._validate_inputs(text, module1_prediction, text_analysis)

        # 2. Indicator Detection
        indicator_results = self.detect_indicators(text)

        # 3. Category Detection
        ai_prob = module1_prediction.get("ai_probability") if module1_prediction else None
        category, _ = self.detect_categories(indicator_results, ai_prob=ai_prob)

        # 4. Threat Score & Component Scores Calculation
        threat_score, component_scores = self.calculate_threat_score(
            indicator_results, category, module1_prediction
        )

        # 5. Risk Level Mapping
        risk_level = self.determine_risk_level(threat_score)

        # 6. Explanation & Evidence Formatting
        reasons = self._generate_explanations(
            threat_score, risk_level, category, indicator_results, module1_prediction
        )

        # 7. Formulate structured evidence items
        evidence_indicators = []
        for group, res in indicator_results.items():
            if res["count"] > 0:
                evidence_indicators.append({
                    "type": group,
                    "severity": res["severity"],
                    "count": int(res["count"]),
                    "description": self.INDICATOR_DESCRIPTIONS.get(group, f"Indicators of type '{group}' detected."),
                })

        return {
            "threat_score": float(threat_score),
            "risk_level": str(risk_level),
            "category": str(category),
            "indicators": evidence_indicators,
            "reasons": reasons,
            "component_scores": component_scores,
        }
