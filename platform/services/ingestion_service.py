"""AIShield - Stage 6A: Ingestion Service.

Defines normalized post representations, validation rules, HTML-to-text extraction,
and ingestion workflow into SourcePostService.
"""

from dataclasses import dataclass, field
from datetime import datetime
import html
from html.parser import HTMLParser
import re
from typing import Any, Dict, Optional, Tuple, Union

from services.source_post_service import (
    SUPPORTED_SOURCES,
    SourcePostService,
    SourcePostStatus,
)


class HTMLTextExtractor(HTMLParser):
    """Safe HTML to plain text extractor.

    Converts block tags and line breaks to appropriate spacing,
    strips markup safely, and preserves textual content.
    """

    def __init__(self) -> None:
        super().__init__()
        self.result = []
        self._block_tags = {"p", "div", "li", "article", "section", "h1", "h2", "h3", "h4", "h5", "h6"}

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "br":
            self.result.append("\n")
        elif tag in self._block_tags:
            if self.result and not self.result[-1].endswith("\n"):
                self.result.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._block_tags:
            if self.result and not self.result[-1].endswith("\n"):
                self.result.append("\n")

    def handle_data(self, data: str) -> None:
        self.result.append(data)

    def get_text(self) -> str:
        raw_text = "".join(self.result)
        # Decode any residual HTML entities
        unescaped = html.unescape(raw_text)
        # Collapse multiple empty lines to max 2 linebreaks, strip leading/trailing
        cleaned = re.sub(r"\n{3,}", "\n\n", unescaped)
        return cleaned.strip()


def extract_plain_text_from_html(html_content: str) -> str:
    """Safely extract plain text from an HTML content string."""
    if not html_content or not isinstance(html_content, str):
        return ""
    parser = HTMLTextExtractor()
    try:
        parser.feed(html_content)
        parser.close()
        text = parser.get_text()
        return text if text else html.unescape(re.sub(r"<[^>]+>", "", html_content)).strip()
    except Exception:
        # Fallback to regex tag stripping with entity unescaping
        return html.unescape(re.sub(r"<[^>]+>", " ", html_content)).strip()


@dataclass
class NormalizedPost:
    """Normalized representation of an external source item."""

    source: str
    source_id: str
    content: str
    source_url: Optional[str] = None
    author_id: Optional[str] = None
    author_name: Optional[str] = None
    published_at: Optional[str] = None
    language: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and normalize field types on creation."""
        if not isinstance(self.source, str):
            raise ValueError(f"source must be a string, got {type(self.source).__name__}.")
        self.source = self.source.strip().lower()

        if not isinstance(self.source_id, str):
            raise ValueError(f"source_id must be a string, got {type(self.source_id).__name__}.")
        self.source_id = self.source_id.strip()

        if not isinstance(self.content, str):
            raise ValueError(f"content must be a string, got {type(self.content).__name__}.")

        if self.metadata is None:
            self.metadata = {}
        elif not isinstance(self.metadata, dict):
            raise ValueError(f"metadata must be a dictionary, got {type(self.metadata).__name__}.")


class IngestionService:
    """Service providing validation, HTML normalization, and ingestion workflows."""

    def __init__(self, source_post_service: Optional[SourcePostService] = None) -> None:
        """Initialize IngestionService with SourcePostService dependency."""
        self.source_post_service = source_post_service or SourcePostService()

    @classmethod
    def validate_normalized_post(cls, post: NormalizedPost) -> None:
        """Validate all required fields, constraints, and formats of a NormalizedPost.

        Raises:
            ValueError: If any validation rule is violated.
        """
        if post is None:
            raise ValueError("NormalizedPost cannot be None.")

        # Source validation
        if not post.source:
            raise ValueError("source cannot be empty.")
        if post.source not in SUPPORTED_SOURCES:
            raise ValueError(
                f"Unsupported source '{post.source}'. Supported sources: {sorted(SUPPORTED_SOURCES)}"
            )

        # Source ID validation
        if not post.source_id:
            raise ValueError("source_id cannot be empty or whitespace-only.")

        # Content validation
        if not post.content or not post.content.strip():
            raise ValueError("content cannot be empty or whitespace-only.")

        # Published at format validation (if provided)
        if post.published_at is not None and str(post.published_at).strip():
            pub_str = str(post.published_at).strip()
            # Standard ISO-8601 validation
            try:
                # Replace 'Z' with '+00:00' for standard python fromisoformat
                iso_candidate = pub_str.replace("Z", "+00:00")
                datetime.fromisoformat(iso_candidate)
            except ValueError as err:
                raise ValueError(
                    f"Invalid published_at format '{post.published_at}'. Must be valid ISO-8601 string: {err}"
                ) from err

    @classmethod
    def normalize_html_content(
        cls,
        html_content: str,
        raw_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Extract clean plain text from HTML content while preserving raw content in metadata.

        Returns:
            Tuple of (plain_text_content, enriched_metadata)
        """
        plain_text = extract_plain_text_from_html(html_content)
        meta = dict(raw_metadata) if isinstance(raw_metadata, dict) else {}
        if "raw_html" not in meta and "<" in html_content and ">" in html_content:
            meta["raw_html"] = html_content
        return plain_text, meta

    def ingest(self, post: NormalizedPost) -> Tuple[Dict[str, Any], bool]:
        """Validate and persist a NormalizedPost into the SQLite database.

        Returns:
            Tuple of (source_post_dict, is_duplicate)
        """
        self.validate_normalized_post(post)

        return self.source_post_service.create_source_post(
            source=post.source,
            source_id=post.source_id,
            content=post.content,
            source_url=post.source_url,
            author_id=post.author_id,
            author_name=post.author_name,
            published_at=post.published_at,
            language=post.language,
            metadata=post.metadata,
            status=SourcePostStatus.RECEIVED,
        )
