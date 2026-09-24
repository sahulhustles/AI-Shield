"""AIShield - Module 3: Digital Forensics & Incident Records Service.

Provides persistent SQLite incident recording, exact SHA-256 fingerprinting,
immutable analysis snapshots, and cryptographic integrity verification.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from database.db import db_session, get_db_path, init_db


class ForensicService:
    """Manages creation, snapshot persistence, retrieval, and verification of forensic incident records."""

    SUPPORTED_CATEGORIES = {
        "Normal",
        "Phishing",
        "Disinformation",
        "Manipulation",
        "Propaganda",
        "Spam",
        "Other",
    }

    SUPPORTED_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize ForensicService with a target database path."""
        self.db_path = get_db_path(db_path)
        self.initialize_database()

    def initialize_database(self) -> None:
        """Ensure database file, tables, and indexes are initialized."""
        init_db(self.db_path)

    @classmethod
    def calculate_content_hash(cls, text: str) -> str:
        """Generate a deterministic SHA-256 fingerprint of the exact raw text.

        The hash represents the unaltered byte sequence without lowercasing,
        whitespace stripping, or normalization.

        Raises:
            ValueError: If input is not a string.
        """
        if text is None or not isinstance(text, str):
            raise ValueError(f"Content to hash must be a string, got {type(text).__name__}.")
        return hashlib.sha256(text.encode("utf-8")).hexdigest().lower()

    def validate_incident_payload(
        self,
        content: Any,
        prediction: Any,
        text_analysis: Any,
        threat_analysis: Any,
    ) -> None:
        """Validate all required fields and numeric bounds for incident creation.

        Raises:
            ValueError: If any field fails type, presence, or value boundary validation.
        """
        # 1. Validate content
        if content is None:
            raise ValueError("Incident content cannot be None.")
        if not isinstance(content, str):
            raise ValueError(f"Incident content must be a string, got {type(content).__name__}.")
        if not content.strip():
            raise ValueError("Incident content cannot be empty or whitespace-only.")

        # 2. Validate Module 1 prediction
        if not isinstance(prediction, dict):
            raise ValueError(f"prediction must be a dictionary, got {type(prediction).__name__}.")

        req_pred_keys = {"label", "ai_probability", "human_probability", "confidence"}
        if not req_pred_keys.issubset(prediction.keys()):
            raise ValueError(f"prediction is missing required keys: {req_pred_keys - set(prediction.keys())}")

        ai_prob = prediction["ai_probability"]
        human_prob = prediction["human_probability"]
        conf = prediction["confidence"]
        ai_label = prediction["label"]

        if not isinstance(ai_label, str) or not ai_label.strip():
            raise ValueError("prediction['label'] must be a non-empty string.")

        for k, v in [("ai_probability", ai_prob), ("human_probability", human_prob), ("confidence", conf)]:
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                raise ValueError(f"prediction['{k}'] must be a numeric value, got {type(v).__name__}.")
            if not (0.0 <= float(v) <= 1.0):
                raise ValueError(f"prediction['{k}'] must be between 0.0 and 1.0, got {v}.")

        # 3. Validate Module 1 text_analysis
        if not isinstance(text_analysis, dict):
            raise ValueError(f"text_analysis must be a dictionary, got {type(text_analysis).__name__}.")

        req_text_keys = {"character_count", "word_count", "sentence_count"}
        if not req_text_keys.issubset(text_analysis.keys()):
            raise ValueError(f"text_analysis is missing required keys: {req_text_keys - set(text_analysis.keys())}")

        # 4. Validate Module 2 threat_analysis
        if not isinstance(threat_analysis, dict):
            raise ValueError(f"threat_analysis must be a dictionary, got {type(threat_analysis).__name__}.")

        req_threat_keys = {"threat_score", "risk_level", "category", "indicators", "reasons", "component_scores"}
        if not req_threat_keys.issubset(threat_analysis.keys()):
            raise ValueError(f"threat_analysis is missing required keys: {req_threat_keys - set(threat_analysis.keys())}")

        threat_score = threat_analysis["threat_score"]
        risk_level = threat_analysis["risk_level"]
        category = threat_analysis["category"]

        if not isinstance(threat_score, (int, float)) or isinstance(threat_score, bool):
            raise ValueError(f"threat_analysis['threat_score'] must be numeric, got {type(threat_score).__name__}.")
        if not (0.0 <= float(threat_score) <= 100.0):
            raise ValueError(f"threat_analysis['threat_score'] must be between 0.0 and 100.0, got {threat_score}.")

        if not isinstance(risk_level, str) or risk_level.upper() not in self.SUPPORTED_RISK_LEVELS:
            raise ValueError(f"Invalid risk_level '{risk_level}'. Supported: {sorted(self.SUPPORTED_RISK_LEVELS)}")

        if not isinstance(category, str) or category not in self.SUPPORTED_CATEGORIES:
            raise ValueError(f"Invalid category '{category}'. Supported: {sorted(self.SUPPORTED_CATEGORIES)}")

        if not isinstance(threat_analysis.get("indicators"), list):
            raise ValueError("threat_analysis['indicators'] must be a list.")

        if not isinstance(threat_analysis.get("reasons"), list):
            raise ValueError("threat_analysis['reasons'] must be a list.")

        if not isinstance(threat_analysis.get("component_scores"), dict):
            raise ValueError("threat_analysis['component_scores'] must be a dictionary.")

    def create_incident(
        self,
        content: str,
        prediction: Dict[str, Any],
        text_analysis: Dict[str, Any],
        threat_analysis: Dict[str, Any],
        source_post_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Atomically create and persist a forensic incident record in SQLite.

        Returns:
            Dict containing incident summary metadata.
        """
        # Validate payload rigorously before writing to SQLite
        self.validate_incident_payload(content, prediction, text_analysis, threat_analysis)

        # Generate unique incident ID and timezone-aware UTC timestamp
        incident_id = f"INC-{uuid.uuid4()}"
        created_at = datetime.now(timezone.utc).isoformat()
        content_hash = self.calculate_content_hash(content)

        # Serialize structured components safely to JSON snapshots
        text_analysis_json = json.dumps(text_analysis)
        indicators_json = json.dumps(threat_analysis.get("indicators", []))
        reasons_json = json.dumps(threat_analysis.get("reasons", []))
        component_scores_json = json.dumps(threat_analysis.get("component_scores", {}))

        insert_sql = """
        INSERT INTO incidents (
            incident_id, created_at, content, content_hash,
            ai_label, ai_probability, human_probability, confidence,
            threat_score, risk_level, category,
            text_analysis_json, indicators_json, reasons_json, component_scores_json,
            source_post_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        with db_session(self.db_path) as conn:
            try:
                with conn:
                    conn.execute(
                        insert_sql,
                        (
                            incident_id,
                            created_at,
                            content,
                            content_hash,
                            str(prediction["label"]),
                            float(prediction["ai_probability"]),
                            float(prediction["human_probability"]),
                            float(prediction["confidence"]),
                            float(threat_analysis["threat_score"]),
                            str(threat_analysis["risk_level"]).upper(),
                            str(threat_analysis["category"]),
                            text_analysis_json,
                            indicators_json,
                            reasons_json,
                            component_scores_json,
                            source_post_id,
                        ),
                    )
            except Exception as e:
                raise RuntimeError(f"Database insertion failed for incident {incident_id}: {e}") from e

        return {
            "incident_id": incident_id,
            "created_at": created_at,
            "content_hash": content_hash,
            "ai_label": str(prediction["label"]),
            "ai_probability": float(prediction["ai_probability"]),
            "threat_score": float(threat_analysis["threat_score"]),
            "risk_level": str(threat_analysis["risk_level"]).upper(),
            "category": str(threat_analysis["category"]),
            "source_post_id": source_post_id,
        }

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve complete immutable forensic incident snapshot from database.

        Never recalculates or reruns analysis.
        """
        if not incident_id or not isinstance(incident_id, str):
            return None

        select_sql = """
        SELECT * FROM incidents WHERE incident_id = ? LIMIT 1;
        """

        with db_session(self.db_path) as conn:
            cursor = conn.execute(select_sql, (incident_id.strip(),))
            row = cursor.fetchone()

        if row is None:
            return None

        # Safely parse stored JSON snapshots with fallback
        try:
            text_analysis = json.loads(row["text_analysis_json"])
        except Exception:
            text_analysis = {}

        try:
            indicators = json.loads(row["indicators_json"])
        except Exception:
            indicators = []

        try:
            reasons = json.loads(row["reasons_json"])
        except Exception:
            reasons = []

        try:
            component_scores = json.loads(row["component_scores_json"])
        except Exception:
            component_scores = {}

        source_post_id = None
        if "source_post_id" in row.keys() and row["source_post_id"] is not None:
            source_post_id = int(row["source_post_id"])

        return {
            "incident_id": str(row["incident_id"]),
            "created_at": str(row["created_at"]),
            "content": str(row["content"]),
            "content_hash": str(row["content_hash"]),
            "source_post_id": source_post_id,
            "prediction": {
                "label": str(row["ai_label"]),
                "ai_probability": float(row["ai_probability"]),
                "human_probability": float(row["human_probability"]),
                "confidence": float(row["confidence"]),
            },
            "text_analysis": text_analysis,
            "threat_analysis": {
                "threat_score": float(row["threat_score"]),
                "risk_level": str(row["risk_level"]),
                "category": str(row["category"]),
                "indicators": indicators,
                "reasons": reasons,
                "component_scores": component_scores,
            },
        }

    def list_incidents(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List summary incident records ordered newest first.

        Does not return full content payload.
        """
        # Validate pagination bounds
        safe_limit = max(1, min(200, int(limit))) if isinstance(limit, int) else 50
        safe_offset = max(0, int(offset)) if isinstance(offset, int) else 0

        select_sql = """
        SELECT incident_id, created_at, content_hash, ai_label, ai_probability,
               threat_score, risk_level, category
        FROM incidents
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?;
        """

        with db_session(self.db_path) as conn:
            cursor = conn.execute(select_sql, (safe_limit, safe_offset))
            rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append({
                "incident_id": str(r["incident_id"]),
                "created_at": str(r["created_at"]),
                "content_hash": str(r["content_hash"]),
                "ai_label": str(r["ai_label"]),
                "ai_probability": float(r["ai_probability"]),
                "threat_score": float(r["threat_score"]),
                "risk_level": str(r["risk_level"]),
                "category": str(r["category"]),
            })
        return results

    def verify_incident_integrity(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Verify the cryptographic integrity of a stored incident record.

        Recalculates SHA-256 from the stored raw content and compares it against
        the stored content_hash.
        """
        incident = self.get_incident(incident_id)
        if incident is None:
            return None

        stored_hash = incident["content_hash"]
        calculated_hash = self.calculate_content_hash(incident["content"])

        return {
            "incident_id": incident["incident_id"],
            "stored_hash": stored_hash,
            "calculated_hash": calculated_hash,
            "verified": bool(stored_hash == calculated_hash),
        }
