"""AIShield - Automatic Real-Time Analysis Pipeline (Stage 6F).

Orchestrates the sequential processing of ingested source posts through:
1. Module 1 AI Detection & Text Analysis
2. Module 2 Threat Scoring & Categorization
3. IncidentPolicy Evaluation
4. Module 3 Forensic Incident Creation & Cryptographic Linking
"""

from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, Optional

from config import MAX_PROCESSING_ATTEMPTS
from models.detector import AIDetector
from services.forensic_service import ForensicService
from services.incident_policy import IncidentPolicy
from services.processing_worker import sanitize_error_message
from services.source_post_service import SourcePostService, SourcePostStatus
from services.text_analyzer import TextAnalyzer
from services.threat_analyzer import ThreatAnalyzer

logger = logging.getLogger("AIShield.AnalysisPipeline")


class AnalysisPipeline:
    """Orchestrates end-to-end analysis and forensic incident generation for source posts."""

    def __init__(
        self,
        detector: AIDetector,
        text_analyzer: TextAnalyzer,
        threat_analyzer: ThreatAnalyzer,
        forensic_service: ForensicService,
        source_post_service: SourcePostService,
        incident_policy: Optional[IncidentPolicy] = None,
        max_attempts: int = MAX_PROCESSING_ATTEMPTS,
        live_broker: Optional[Any] = None,
    ) -> None:
        """Initialize AnalysisPipeline with tested Module 1-3 services and optional live event broker."""
        self.detector = detector
        self.text_analyzer = text_analyzer
        self.threat_analyzer = threat_analyzer
        self.forensic_service = forensic_service
        self.source_post_service = source_post_service
        self.incident_policy = incident_policy or IncidentPolicy()
        self.max_attempts = max(1, int(max_attempts))
        self.live_broker = live_broker

        self._lock = threading.Lock()
        self.posts_analyzed: int = 0
        self.incidents_generated: int = 0
        self.posts_skipped_incident: int = 0
        self.analysis_errors: int = 0
        self.retries_attempted: int = 0

    def process_source_post(self, source_post_id: Any) -> Dict[str, Any]:
        """Execute the end-to-end analysis lifecycle for a single source_post_id or source post dict.

        Lifecycle:
        1. Fetch source post from database.
        2. Verify idempotency (return if already analyzed).
        3. Increment attempts counter and mark PROCESSING.
        4. Run Module 1 AI Detector and Text Analyzer.
        5. Run Module 2 Threat Analyzer with Module 1 outputs.
        6. Apply IncidentPolicy to determine if an incident is required.
        7. If required, atomically create incident via ForensicService and link ID.
        8. If not required, mark ANALYZED with incident_id=NULL.
        9. Handle transient failures with retries up to max_attempts.
        """
        if isinstance(source_post_id, dict):
            source_post_id = source_post_id.get("id")

        if source_post_id is None:
            err = "Source post ID cannot be None."
            logger.warning(err)
            return {
                "source_post_id": None,
                "status": "INVALID_ID",
                "error": err,
                "success": False,
            }

        source_post_id = int(source_post_id)

        # Step 1: Load source post
        post = self.source_post_service.get_source_post(source_post_id)
        if not post:
            err = f"Source post with ID {source_post_id} not found."
            logger.warning(err)
            return {
                "source_post_id": source_post_id,
                "status": "NOT_FOUND",
                "error": err,
                "success": False,
            }

        # Step 2: Idempotency check — avoid re-analyzing already completed posts
        if post.get("status") == SourcePostStatus.ANALYZED:
            logger.info(
                "Source post %s is already ANALYZED (incident_id=%s). Skipping duplicate analysis.",
                source_post_id,
                post.get("incident_id"),
            )
            return {
                "source_post_id": source_post_id,
                "status": SourcePostStatus.ANALYZED,
                "incident_id": post.get("incident_id"),
                "already_analyzed": True,
                "success": True,
            }

        # Step 3: Increment attempts and transition to PROCESSING if not already done by worker
        if post.get("status") != SourcePostStatus.PROCESSING:
            attempts = self.source_post_service.increment_attempts(source_post_id)
            self.source_post_service.mark_processing(source_post_id)
        else:
            attempts = post.get("analysis_attempts", 0)
            if attempts == 0:
                attempts = self.source_post_service.increment_attempts(source_post_id)

        content = post.get("content", "")

        try:
            # Step 4: Run Module 1 (AI Detector & Text Analyzer)
            ai_prediction = self.detector.predict(content)
            text_metrics = self.text_analyzer.analyze(content)

            # Step 5: Run Module 2 (Threat Analyzer)
            threat_analysis = self.threat_analyzer.analyze(
                content,
                module1_prediction=ai_prediction,
                text_analysis=text_metrics,
            )

            # Step 6: Evaluate centralized IncidentPolicy
            should_create_incident, policy_reason = self.incident_policy.evaluate(
                ai_prediction=ai_prediction,
                text_analysis=text_metrics,
                threat_analysis=threat_analysis,
            )

            incident_id = None
            if should_create_incident:
                # Step 7: Idempotent incident creation
                # Verify whether an incident was already attached concurrently
                current_post = self.source_post_service.get_source_post(source_post_id)
                if current_post and current_post.get("incident_id"):
                    incident_id = current_post["incident_id"]
                    logger.info("Source post %s already linked to incident %s.", source_post_id, incident_id)
                else:
                    incident_record = self.forensic_service.create_incident(
                        content=content,
                        prediction=ai_prediction,
                        text_analysis=text_metrics,
                        threat_analysis=threat_analysis,
                        source_post_id=source_post_id,
                    )
                    incident_id = incident_record["incident_id"]
                    with self._lock:
                        self.incidents_generated += 1

                # Link incident and mark post ANALYZED
                self.source_post_service.link_incident(source_post_id, incident_id)
                logger.info(
                    "Source post %s -> Created & Linked Forensic Incident %s (%s).",
                    source_post_id,
                    incident_id,
                    threat_analysis.get("risk_level"),
                )
            else:
                # Step 8: Mark ANALYZED without incident
                self.source_post_service.mark_analyzed(source_post_id, incident_id=None)
                with self._lock:
                    self.posts_skipped_incident += 1
                logger.info(
                    "Source post %s -> Analyzed without incident (%s).",
                    source_post_id,
                    policy_reason,
                )

            with self._lock:
                self.posts_analyzed += 1

            # Step 9: Publish live real-time event & incident alert if live broker is attached
            if self.live_broker is not None:
                try:
                    event_payload = {
                        "id": source_post_id,
                        "source": post.get("source"),
                        "source_id": post.get("source_id"),
                        "author_name": post.get("author_name") or post.get("author_id"),
                        "status": SourcePostStatus.ANALYZED,
                        "content_snippet": content[:120] if content else "",
                        "ai_probability": float(ai_prediction.get("ai_probability", 0.0)),
                        "threat_score": float(threat_analysis.get("threat_score", 0.0)),
                        "risk_level": str(threat_analysis.get("risk_level", "LOW")),
                        "category": str(threat_analysis.get("category", "Normal")),
                        "incident_id": incident_id,
                        "processed_at": datetime.now(timezone.utc).isoformat(),
                    }
                    self.live_broker.publish_event("source_post", event_payload)

                    if should_create_incident and str(threat_analysis.get("risk_level", "")).upper() in ("HIGH", "CRITICAL"):
                        alert_payload = {
                            "incident_id": incident_id,
                            "source": post.get("source"),
                            "source_id": post.get("source_id"),
                            "author_name": post.get("author_name") or post.get("author_id") or "Anonymous",
                            "risk_level": str(threat_analysis.get("risk_level", "HIGH")),
                            "threat_score": float(threat_analysis.get("threat_score", 0.0)),
                            "ai_probability": float(ai_prediction.get("ai_probability", 0.0)),
                            "category": str(threat_analysis.get("category", "Phishing")),
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "content_snippet": content[:120] if content else "",
                        }
                        self.live_broker.publish_event("incident_alert", alert_payload)
                except Exception as b_exc:
                    logger.debug("Failed to publish live event: %s", b_exc)

            return {
                "source_post_id": source_post_id,
                "status": SourcePostStatus.ANALYZED,
                "incident_id": incident_id,
                "incident_created": should_create_incident,
                "policy_reason": policy_reason,
                "threat_score": threat_analysis.get("threat_score"),
                "risk_level": threat_analysis.get("risk_level"),
                "category": threat_analysis.get("category"),
                "ai_probability": ai_prediction.get("ai_probability"),
                "attempts": attempts,
                "success": True,
            }

        except Exception as exc:
            # Step 9: Failure handling and retry tracking
            raw_err = str(exc)
            sanitized_err = sanitize_error_message(raw_err)
            logger.error("Analysis failed for source post %s (attempt %s): %s", source_post_id, attempts, sanitized_err)

            with self._lock:
                self.analysis_errors += 1

            if attempts < self.max_attempts:
                with self._lock:
                    self.retries_attempted += 1
                self.source_post_service.update_status(
                    source_post_id,
                    SourcePostStatus.QUEUED,
                    error=f"Attempt {attempts} failed: {sanitized_err}",
                )
            else:
                self.source_post_service.mark_failed(
                    source_post_id,
                    error_message=f"Exceeded max attempts ({self.max_attempts}): {sanitized_err}",
                )

            raise RuntimeError(f"Pipeline failure on source post {source_post_id}: {sanitized_err}") from exc

    def get_metrics(self) -> Dict[str, Any]:
        """Return operational pipeline counters and metrics."""
        with self._lock:
            return {
                "posts_analyzed": self.posts_analyzed,
                "incidents_generated": self.incidents_generated,
                "posts_skipped_incident": self.posts_skipped_incident,
                "analysis_errors": self.analysis_errors,
                "retries_attempted": self.retries_attempted,
            }
