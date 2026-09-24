"""AIShield - Manual Connector (Stage 6B).

Connector for receiving manual/test submissions and normalizing them into NormalizedPost.
"""

from typing import Any, Dict, List, Optional

from services.connectors.base_connector import BaseConnector
from services.ingestion_service import IngestionService, NormalizedPost


class ManualConnector(BaseConnector):
    """Connector for manual input and automated integration testing."""

    def __init__(self) -> None:
        """Initialize ManualConnector state."""
        self._running: bool = False
        self._buffer: List[Dict[str, Any]] = []

    @property
    def source_name(self) -> str:
        """Return the connector source name."""
        return "manual"

    def connect(self) -> None:
        """Activate the manual connector."""
        self._running = True

    def disconnect(self) -> None:
        """Deactivate the manual connector."""
        self._running = False
        self._buffer.clear()

    def is_running(self) -> bool:
        """Check if connector is active."""
        return self._running

    def receive(self) -> Optional[Dict[str, Any]]:
        """Retrieve next item from the manual input buffer if present."""
        if not self._running or not self._buffer:
            return None
        return self._buffer.pop(0)

    def submit_raw(self, raw_item: Dict[str, Any]) -> None:
        """Stage a raw manual item into the connector buffer."""
        if not isinstance(raw_item, dict):
            raise ValueError(f"raw_item must be a dictionary, got {type(raw_item).__name__}.")
        self._buffer.append(raw_item)

    def normalize(self, raw_item: Any) -> NormalizedPost:
        """Transform raw manual input dictionary into a validated NormalizedPost.

        Handles HTML content extraction cleanly while preserving raw HTML in metadata.
        """
        if not isinstance(raw_item, dict):
            raise ValueError(f"raw_item must be a dictionary, got {type(raw_item).__name__}.")

        source_id = raw_item.get("source_id")
        if not source_id or not isinstance(source_id, str):
            raise ValueError("Manual raw item must contain a non-empty string 'source_id'.")

        raw_content = raw_item.get("content")
        if not raw_content or not isinstance(raw_content, str) or not raw_content.strip():
            raise ValueError("Manual raw item must contain a non-empty string 'content'.")

        metadata = raw_item.get("metadata", {})
        if metadata is None:
            metadata = {}
        elif not isinstance(metadata, dict):
            raise ValueError(f"metadata must be a dictionary, got {type(metadata).__name__}.")

        # Handle HTML extraction if present
        plain_content, enriched_meta = IngestionService.normalize_html_content(raw_content, metadata)
        final_content = plain_content if plain_content else raw_content.strip()

        return NormalizedPost(
            source=self.source_name,
            source_id=source_id.strip(),
            content=final_content,
            source_url=raw_item.get("source_url"),
            author_id=raw_item.get("author_id"),
            author_name=raw_item.get("author_name"),
            published_at=raw_item.get("published_at"),
            language=raw_item.get("language"),
            metadata=enriched_meta,
        )
