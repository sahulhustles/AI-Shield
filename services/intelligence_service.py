"""AIShield - Module 4: Threat Intelligence & Investigation Dashboard Service.

Provides read-only analytical aggregations, risk trend tracking, distribution insights,
and multi-dimensional parameterized incident search over stored Module 3 SQLite records.
"""

from datetime import datetime
import math
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

from database.db import db_session, get_db_path


class IntelligenceService:
    """Service providing read-only analytical and search capabilities over stored incident records."""

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

    SUPPORTED_AI_LABELS = {"AI-generated", "Human"}

    SORT_ALLOWLIST = {
        "date": "created_at",
        "created_at": "created_at",
        "threat": "threat_score",
        "threat_score": "threat_score",
        "ai": "ai_probability",
        "ai_probability": "ai_probability",
        "category": "category",
        "risk": "risk_level",
        "risk_level": "risk_level",
    }

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize IntelligenceService with a database path."""
        self.db_path = get_db_path(db_path)

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Compute aggregate summary metrics over all stored incidents in SQLite.

        Returns sensible zero values if table is empty.
        """
        sql = """
        SELECT
            COUNT(*) as total_incidents,
            SUM(CASE WHEN UPPER(risk_level) = 'HIGH' THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN UPPER(risk_level) = 'CRITICAL' THEN 1 ELSE 0 END) as critical_risk,
            SUM(CASE WHEN ai_label LIKE '%AI%' THEN 1 ELSE 0 END) as ai_generated,
            SUM(CASE WHEN ai_label LIKE '%Human%' THEN 1 ELSE 0 END) as human,
            AVG(threat_score) as average_threat_score
        FROM incidents;
        """

        with db_session(self.db_path) as conn:
            row = conn.execute(sql).fetchone()

        if row is None or row["total_incidents"] == 0:
            return {
                "total_incidents": 0,
                "high_risk": 0,
                "critical_risk": 0,
                "ai_generated": 0,
                "human": 0,
                "average_threat_score": 0.0,
            }

        avg_score = float(row["average_threat_score"]) if row["average_threat_score"] is not None else 0.0

        return {
            "total_incidents": int(row["total_incidents"]),
            "high_risk": int(row["high_risk"] or 0),
            "critical_risk": int(row["critical_risk"] or 0),
            "ai_generated": int(row["ai_generated"] or 0),
            "human": int(row["human"] or 0),
            "average_threat_score": round(avg_score, 2),
        }

    def get_risk_distribution(self) -> Dict[str, int]:
        """Compute distribution of incidents by risk level.

        Always returns all 4 levels (LOW, MEDIUM, HIGH, CRITICAL) including zeros.
        """
        counts = {level: 0 for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}

        sql = """
        SELECT UPPER(risk_level) as r_level, COUNT(*) as count
        FROM incidents
        GROUP BY UPPER(risk_level);
        """

        with db_session(self.db_path) as conn:
            rows = conn.execute(sql).fetchall()

        for r in rows:
            level = r["r_level"]
            if level in counts:
                counts[level] = int(r["count"])

        return counts

    def get_category_distribution(self) -> Dict[str, int]:
        """Compute distribution of incidents across all supported categories.

        Always returns all supported categories including zeros.
        """
        counts = {cat: 0 for cat in [
            "Normal",
            "Phishing",
            "Disinformation",
            "Manipulation",
            "Propaganda",
            "Spam",
            "Other",
        ]}

        sql = """
        SELECT category, COUNT(*) as count
        FROM incidents
        GROUP BY category;
        """

        with db_session(self.db_path) as conn:
            rows = conn.execute(sql).fetchall()

        for r in rows:
            cat = r["category"]
            if cat in counts:
                counts[cat] = int(r["count"])

        return counts

    def get_ai_distribution(self) -> Dict[str, int]:
        """Compute distribution between AI-generated and Human classifications."""
        counts = {"AI-generated": 0, "Human": 0}

        sql = """
        SELECT ai_label, COUNT(*) as count
        FROM incidents
        GROUP BY ai_label;
        """

        with db_session(self.db_path) as conn:
            rows = conn.execute(sql).fetchall()

        for r in rows:
            label = r["ai_label"]
            if label in counts:
                counts[label] = int(r["count"])
            elif "AI" in str(label):
                counts["AI-generated"] += int(r["count"])
            elif "Human" in str(label):
                counts["Human"] += int(r["count"])

        return counts

    def get_risk_trend(self) -> List[Dict[str, Any]]:
        """Compute daily time-series aggregation of incident activity in UTC.

        Returns list of {date, incident_count, average_threat_score} sorted oldest to newest.
        """
        sql = """
        SELECT
            substr(created_at, 1, 10) as day_date,
            COUNT(*) as incident_count,
            AVG(threat_score) as avg_score
        FROM incidents
        GROUP BY substr(created_at, 1, 10)
        ORDER BY day_date ASC;
        """

        with db_session(self.db_path) as conn:
            rows = conn.execute(sql).fetchall()

        trend = []
        for r in rows:
            day = r["day_date"]
            if day:
                trend.append({
                    "date": str(day),
                    "incident_count": int(r["incident_count"]),
                    "average_threat_score": round(float(r["avg_score"] or 0.0), 2),
                })
        return trend

    def get_recent_incidents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent incident records ordered newest first."""
        safe_limit = max(1, min(100, int(limit))) if isinstance(limit, int) else 10

        sql = """
        SELECT incident_id, created_at, content_hash, ai_label, ai_probability,
               threat_score, risk_level, category
        FROM incidents
        ORDER BY created_at DESC, id DESC
        LIMIT ?;
        """

        with db_session(self.db_path) as conn:
            rows = conn.execute(sql, (safe_limit,)).fetchall()

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

    def get_high_risk_incidents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve high-risk and critical incidents sorted by severity and threat score."""
        safe_limit = max(1, min(100, int(limit))) if isinstance(limit, int) else 10

        sql = """
        SELECT incident_id, created_at, content_hash, ai_label, ai_probability,
               threat_score, risk_level, category
        FROM incidents
        WHERE UPPER(risk_level) IN ('HIGH', 'CRITICAL')
        ORDER BY
            CASE UPPER(risk_level) WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END ASC,
            threat_score DESC,
            created_at DESC
        LIMIT ?;
        """

        with db_session(self.db_path) as conn:
            rows = conn.execute(sql, (safe_limit,)).fetchall()

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

    def search_incidents(
        self,
        q: Optional[str] = None,
        risk_level: Optional[str] = None,
        category: Optional[str] = None,
        ai_label: Optional[str] = None,
        min_score: Optional[Union[int, float, str]] = None,
        max_score: Optional[Union[int, float, str]] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        sort: str = "date",
        order: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """Perform parameterized, validated multi-filter search and pagination over incidents."""
        # 1. Validate pagination
        try:
            p = int(page)
            ps = int(page_size)
        except (ValueError, TypeError):
            raise ValueError("Parameters 'page' and 'page_size' must be integers.")

        if p < 1:
            raise ValueError("Parameter 'page' must be greater than or equal to 1.")
        if ps < 1 or ps > 100:
            raise ValueError("Parameter 'page_size' must be between 1 and 100.")

        # 2. Validate sorting
        sort_clean = str(sort).lower().strip() if sort else "date"
        if sort_clean not in self.SORT_ALLOWLIST:
            raise ValueError(f"Invalid sort field '{sort}'. Allowed: {sorted(list(set(self.SORT_ALLOWLIST.keys())))}")
        sort_column = self.SORT_ALLOWLIST[sort_clean]

        order_clean = str(order).lower().strip() if order else "desc"
        if order_clean not in {"asc", "desc"}:
            raise ValueError(f"Invalid sort order '{order}'. Allowed: ['asc', 'desc']")

        # 3. Validate and build filters
        where_clauses = ["1=1"]
        params: List[Any] = []

        # Text query (searches across public identifier, hash, category, risk, ai_label)
        if q and isinstance(q, str) and q.strip():
            query_term = f"%{q.strip()}%"
            where_clauses.append(
                "(incident_id LIKE ? OR content_hash LIKE ? OR category LIKE ? OR risk_level LIKE ? OR ai_label LIKE ?)"
            )
            params.extend([query_term, query_term, query_term, query_term, query_term])

        # Risk level filter
        if risk_level and str(risk_level).strip() and str(risk_level).upper() != "ALL":
            r_clean = str(risk_level).upper().strip()
            if r_clean not in self.SUPPORTED_RISK_LEVELS:
                raise ValueError(f"Invalid risk_level filter '{risk_level}'. Supported: {sorted(self.SUPPORTED_RISK_LEVELS)}")
            where_clauses.append("UPPER(risk_level) = ?")
            params.append(r_clean)

        # Category filter
        if category and str(category).strip() and str(category) != "ALL":
            c_clean = str(category).strip()
            if c_clean not in self.SUPPORTED_CATEGORIES:
                raise ValueError(f"Invalid category filter '{category}'. Supported: {sorted(self.SUPPORTED_CATEGORIES)}")
            where_clauses.append("category = ?")
            params.append(c_clean)

        # AI Label filter
        if ai_label and str(ai_label).strip() and str(ai_label) != "ALL":
            ai_clean = str(ai_label).strip()
            if ai_clean not in self.SUPPORTED_AI_LABELS:
                raise ValueError(f"Invalid ai_label filter '{ai_label}'. Supported: {sorted(self.SUPPORTED_AI_LABELS)}")
            where_clauses.append("ai_label = ?")
            params.append(ai_clean)

        # Min score filter
        parsed_min_score = None
        if min_score is not None and str(min_score).strip():
            try:
                parsed_min_score = float(min_score)
            except ValueError:
                raise ValueError(f"min_score must be a numeric value, got '{min_score}'.")
            if not (0.0 <= parsed_min_score <= 100.0):
                raise ValueError(f"min_score must be between 0.0 and 100.0, got {parsed_min_score}.")
            where_clauses.append("threat_score >= ?")
            params.append(parsed_min_score)

        # Max score filter
        parsed_max_score = None
        if max_score is not None and str(max_score).strip():
            try:
                parsed_max_score = float(max_score)
            except ValueError:
                raise ValueError(f"max_score must be a numeric value, got '{max_score}'.")
            if not (0.0 <= parsed_max_score <= 100.0):
                raise ValueError(f"max_score must be between 0.0 and 100.0, got {parsed_max_score}.")
            where_clauses.append("threat_score <= ?")
            params.append(parsed_max_score)

        if parsed_min_score is not None and parsed_max_score is not None and parsed_min_score > parsed_max_score:
            raise ValueError(f"min_score ({parsed_min_score}) cannot be greater than max_score ({parsed_max_score}).")

        # Date range filters (expects YYYY-MM-DD or ISO timestamp substring)
        parsed_from_date = None
        if from_date and str(from_date).strip():
            fd_clean = str(from_date).strip()[:10]
            try:
                parsed_from_date = datetime.strptime(fd_clean, "%Y-%m-%d")
            except ValueError:
                raise ValueError(f"Invalid from_date format '{from_date}'. Expected format: YYYY-MM-DD.")
            where_clauses.append("substr(created_at, 1, 10) >= ?")
            params.append(fd_clean)

        parsed_to_date = None
        if to_date and str(to_date).strip():
            td_clean = str(to_date).strip()[:10]
            try:
                parsed_to_date = datetime.strptime(td_clean, "%Y-%m-%d")
            except ValueError:
                raise ValueError(f"Invalid to_date format '{to_date}'. Expected format: YYYY-MM-DD.")
            where_clauses.append("substr(created_at, 1, 10) <= ?")
            params.append(td_clean)

        if parsed_from_date and parsed_to_date and parsed_from_date > parsed_to_date:
            raise ValueError(f"from_date ({from_date}) cannot be after to_date ({to_date}).")

        where_sql = " AND ".join(where_clauses)

        # 4. Count matching records
        count_sql = f"SELECT COUNT(*) as total FROM incidents WHERE {where_sql};"

        with db_session(self.db_path) as conn:
            total_count = conn.execute(count_sql, params).fetchone()["total"]

        total_pages = math.ceil(total_count / ps) if total_count > 0 else 0

        # 5. Fetch paginated records
        offset = (p - 1) * ps
        select_sql = f"""
        SELECT incident_id, created_at, content_hash, ai_label, ai_probability,
               threat_score, risk_level, category
        FROM incidents
        WHERE {where_sql}
        ORDER BY {sort_column} {order_clean.upper()}, id DESC
        LIMIT ? OFFSET ?;
        """

        query_params = list(params) + [ps, offset]

        with db_session(self.db_path) as conn:
            rows = conn.execute(select_sql, query_params).fetchall()

        items = []
        for r in rows:
            items.append({
                "incident_id": str(r["incident_id"]),
                "created_at": str(r["created_at"]),
                "content_hash": str(r["content_hash"]),
                "ai_label": str(r["ai_label"]),
                "ai_probability": float(r["ai_probability"]),
                "threat_score": float(r["threat_score"]),
                "risk_level": str(r["risk_level"]),
                "category": str(r["category"]),
            })

        return {
            "items": items,
            "pagination": {
                "page": p,
                "page_size": ps,
                "total": int(total_count),
                "total_pages": int(total_pages),
            },
        }
