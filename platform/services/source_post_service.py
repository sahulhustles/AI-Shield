"""AIShield - Stage 6A: Source Post Service.

Manages persistence, unique source-item deduplication, status transitions,
and retrieval for incoming raw external source posts.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from database.db import db_session, get_db_path, init_db


class SourcePostStatus:
    """Explicit lifecycle status constants for source posts."""

    RECEIVED = "RECEIVED"
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    ANALYZED = "ANALYZED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"

    ALL: Set[str] = {
        RECEIVED,
        QUEUED,
        PROCESSING,
        ANALYZED,
        SKIPPED,
        FAILED,
    }


# Supported source identifiers (extensible for future platform connectors)
SUPPORTED_SOURCES: Set[str] = {
    "bluesky",
    "mastodon",
    "youtube",
    "manual",
}


class SourcePostService:
    """Service managing SQLite persistence and lifecycle for raw external source posts."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize SourcePostService with database path."""
        self.db_path = get_db_path(db_path)
        self.initialize_source_posts_table()

    def initialize_source_posts_table(self) -> None:
        """Ensure database and source_posts table/indexes exist."""
        init_db(self.db_path)

    @classmethod
    def calculate_content_hash(cls, content: str) -> str:
        """Generate a deterministic SHA-256 fingerprint of the exact raw content bytes.

        Represents unaltered UTF-8 byte sequence without lowercasing or whitespace stripping.
        """
        if content is None or not isinstance(content, str):
            raise ValueError(f"Content to hash must be a string, got {type(content).__name__}.")
        return hashlib.sha256(content.encode("utf-8")).hexdigest().lower()

    @classmethod
    def validate_source(cls, source: str) -> str:
        """Validate that source is supported."""
        if not source or not isinstance(source, str):
            raise ValueError("Source must be a non-empty string.")
        s_clean = source.strip().lower()
        if s_clean not in SUPPORTED_SOURCES:
            raise ValueError(
                f"Unsupported source '{source}'. Supported sources: {sorted(SUPPORTED_SOURCES)}"
            )
        return s_clean

    @classmethod
    def validate_status(cls, status: str) -> str:
        """Validate that status is one of the allowed explicit lifecycle values."""
        if not status or not isinstance(status, str):
            raise ValueError("Status must be a non-empty string.")
        st_clean = status.strip().upper()
        if st_clean not in SourcePostStatus.ALL:
            raise ValueError(
                f"Invalid status '{status}'. Allowed statuses: {sorted(SourcePostStatus.ALL)}"
            )
        return st_clean

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a SQLite database row to a structured dictionary."""
        try:
            metadata = json.loads(row["metadata_json"])
        except Exception:
            metadata = {}

        incident_id = None
        if "incident_id" in row.keys() and row["incident_id"] is not None:
            incident_id = str(row["incident_id"])

        return {
            "id": int(row["id"]),
            "source": str(row["source"]),
            "source_id": str(row["source_id"]),
            "source_url": str(row["source_url"]) if row["source_url"] is not None else None,
            "author_id": str(row["author_id"]) if row["author_id"] is not None else None,
            "author_name": str(row["author_name"]) if row["author_name"] is not None else None,
            "content": str(row["content"]),
            "published_at": str(row["published_at"]) if row["published_at"] is not None else None,
            "language": str(row["language"]) if row["language"] is not None else None,
            "metadata": metadata,
            "content_hash": str(row["content_hash"]),
            "ingested_at": str(row["ingested_at"]),
            "status": str(row["status"]),
            "analysis_attempts": int(row["analysis_attempts"]),
            "last_error": str(row["last_error"]) if row["last_error"] is not None else None,
            "processed_at": str(row["processed_at"]) if row["processed_at"] is not None else None,
            "incident_id": incident_id,
        }

    def create_source_post(
        self,
        source: str,
        source_id: str,
        content: str,
        source_url: Optional[str] = None,
        author_id: Optional[str] = None,
        author_name: Optional[str] = None,
        published_at: Optional[str] = None,
        language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        status: str = SourcePostStatus.RECEIVED,
    ) -> Tuple[Dict[str, Any], bool]:
        """Persist a new source post in SQLite or return the existing record if duplicate.

        Returns:
            Tuple of (source_post_dict, is_duplicate)
        """
        # Validate required inputs
        source_clean = self.validate_source(source)
        status_clean = self.validate_status(status)

        if source_id is None or not isinstance(source_id, str) or not source_id.strip():
            raise ValueError("source_id must be a non-empty string.")
        source_id_clean = source_id.strip()

        if content is None or not isinstance(content, str) or not content.strip():
            raise ValueError("content must be a non-empty string.")

        # Compute content hash on exact UTF-8 bytes
        content_hash = self.calculate_content_hash(content)
        ingested_at = datetime.now(timezone.utc).isoformat()

        # Metadata validation and serialization
        meta_dict = metadata if isinstance(metadata, dict) else {}
        try:
            metadata_json = json.dumps(meta_dict)
        except (TypeError, ValueError) as err:
            raise ValueError(f"metadata must be JSON serializable: {err}") from err

        insert_sql = """
        INSERT INTO source_posts (
            source, source_id, source_url, author_id, author_name,
            content, published_at, language, metadata_json,
            content_hash, ingested_at, status, analysis_attempts,
            last_error, processed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL);
        """

        with db_session(self.db_path) as conn:
            try:
                with conn:
                    cursor = conn.execute(
                        insert_sql,
                        (
                            source_clean,
                            source_id_clean,
                            source_url,
                            author_id,
                            author_name,
                            content,
                            published_at,
                            language,
                            metadata_json,
                            content_hash,
                            ingested_at,
                            status_clean,
                        ),
                    )
                    row_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                # Duplicate post for this (source, source_id)
                existing = self.get_by_source_and_id(source_clean, source_id_clean)
                if existing is not None:
                    return existing, True
                raise

        # Fetch created row
        created = self.get_source_post(row_id)
        if created is None:
            raise RuntimeError(f"Failed to retrieve newly created source post with id {row_id}.")
        return created, False

    def get_source_post(self, post_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single source post by its auto-increment ID."""
        if not isinstance(post_id, int):
            try:
                post_id = int(post_id)
            except (ValueError, TypeError):
                return None

        select_sql = "SELECT * FROM source_posts WHERE id = ? LIMIT 1;"
        with db_session(self.db_path) as conn:
            cursor = conn.execute(select_sql, (post_id,))
            row = cursor.fetchone()

        if row is None:
            return None
        return self._row_to_dict(row)

    def get_by_source_and_id(self, source: str, source_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single source post by its compound natural key (source, source_id)."""
        if not source or not source_id:
            return None

        source_clean = str(source).strip().lower()
        source_id_clean = str(source_id).strip()

        select_sql = "SELECT * FROM source_posts WHERE source = ? AND source_id = ? LIMIT 1;"
        with db_session(self.db_path) as conn:
            cursor = conn.execute(select_sql, (source_clean, source_id_clean))
            row = cursor.fetchone()

        if row is None:
            return None
        return self._row_to_dict(row)

    def list_source_posts(
        self,
        limit: int = 50,
        offset: int = 0,
        source: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List summary source posts with bounded limit and optional filtering."""
        safe_limit = max(1, min(100, int(limit))) if isinstance(limit, (int, str)) else 50
        safe_offset = max(0, int(offset)) if isinstance(offset, (int, str)) else 0

        where_clauses = ["1=1"]
        params: List[Any] = []

        if source and str(source).strip():
            where_clauses.append("source = ?")
            params.append(str(source).strip().lower())

        if status and str(status).strip():
            where_clauses.append("status = ?")
            params.append(str(status).strip().upper())

        where_sql = " AND ".join(where_clauses)
        select_sql = f"""
        SELECT * FROM source_posts
        WHERE {where_sql}
        ORDER BY ingested_at DESC, id DESC
        LIMIT ? OFFSET ?;
        """
        params.extend([safe_limit, safe_offset])

        with db_session(self.db_path) as conn:
            cursor = conn.execute(select_sql, params)
            rows = cursor.fetchall()

        return [self._row_to_dict(r) for r in rows]

    def find_by_content_hash(self, content_hash: str) -> List[Dict[str, Any]]:
        """Find all source posts matching a given content hash across all sources."""
        if not content_hash or not isinstance(content_hash, str):
            return []

        select_sql = """
        SELECT * FROM source_posts
        WHERE content_hash = ?
        ORDER BY ingested_at DESC, id DESC;
        """
        with db_session(self.db_path) as conn:
            cursor = conn.execute(select_sql, (content_hash.strip().lower(),))
            rows = cursor.fetchall()

        return [self._row_to_dict(r) for r in rows]

    def update_status(
        self,
        post_id: int,
        status: str,
        error: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> bool:
        """Update the lifecycle status, optional error, and optional incident_id for a source post."""
        status_clean = self.validate_status(status)

        processed_at = None
        if status_clean in {SourcePostStatus.ANALYZED, SourcePostStatus.SKIPPED, SourcePostStatus.FAILED}:
            processed_at = datetime.now(timezone.utc).isoformat()

        update_sql = """
        UPDATE source_posts
        SET status = ?,
            last_error = ?,
            processed_at = COALESCE(?, processed_at),
            incident_id = COALESCE(?, incident_id)
        WHERE id = ?;
        """

        with db_session(self.db_path) as conn:
            with conn:
                cursor = conn.execute(update_sql, (status_clean, error, processed_at, incident_id, post_id))
                return cursor.rowcount > 0

    def mark_processing(self, post_id: int) -> bool:
        """Mark a source post as actively PROCESSING."""
        return self.update_status(post_id, SourcePostStatus.PROCESSING)

    def mark_analyzed(self, post_id: int, incident_id: Optional[str] = None) -> bool:
        """Mark a source post as successfully ANALYZED with optional linked incident_id."""
        return self.update_status(post_id, SourcePostStatus.ANALYZED, incident_id=incident_id)

    def link_incident(self, post_id: int, incident_id: str) -> bool:
        """Atomically link an incident_id to a source_post and mark it ANALYZED."""
        if not incident_id or not isinstance(incident_id, str):
            raise ValueError("Incident ID must be a non-empty string.")
        return self.update_status(post_id, SourcePostStatus.ANALYZED, incident_id=incident_id.strip())

    def mark_failed(self, post_id: int, error_message: str) -> bool:
        """Mark a source post as FAILED with the given error message."""
        return self.update_status(post_id, SourcePostStatus.FAILED, error=error_message)

    def mark_skipped(self, post_id: int, reason: Optional[str] = None) -> bool:
        """Mark a source post as SKIPPED with an optional reason."""
        return self.update_status(post_id, SourcePostStatus.SKIPPED, error=reason)

    def increment_attempts(self, post_id: int) -> int:
        """Increment analysis_attempts counter by 1 and return the updated count."""
        update_sql = """
        UPDATE source_posts
        SET analysis_attempts = analysis_attempts + 1
        WHERE id = ?;
        """
        select_sql = "SELECT analysis_attempts FROM source_posts WHERE id = ?;"

        with db_session(self.db_path) as conn:
            with conn:
                conn.execute(update_sql, (post_id,))
                row = conn.execute(select_sql, (post_id,)).fetchone()

        if row is None:
            return 0
        return int(row["analysis_attempts"])

    def count_by_status(self) -> Dict[str, int]:
        """Return counts of source posts grouped by status."""
        query = "SELECT status, COUNT(*) as count FROM source_posts GROUP BY status;"
        counts = {st: 0 for st in SourcePostStatus.ALL}
        with db_session(self.db_path) as conn:
            cursor = conn.execute(query)
            for row in cursor.fetchall():
                st = str(row["status"]).upper()
                counts[st] = int(row["count"])
        return counts
