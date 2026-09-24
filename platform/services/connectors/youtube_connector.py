"""AIShield - Real YouTube Keyword Polling Connector (Stage 6E).

Uses the official YouTube Data API v3 (search.list endpoint) to periodically
poll security queries, normalize video metadata into NormalizedPost instances,
and enforce daily quota safety limits.
"""

from datetime import datetime, timezone
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Union

import requests

from config import (
    YOUTUBE_API_KEY,
    YOUTUBE_ENABLED,
    YOUTUBE_LANGUAGE,
    YOUTUBE_MAX_REQUESTS_PER_DAY,
    YOUTUBE_MAX_RESULTS,
    YOUTUBE_POLL_INTERVAL_SECONDS,
    YOUTUBE_QUERIES,
    YOUTUBE_REGION_CODE,
)
from services.connectors.base_connector import BaseConnector
from services.ingestion_service import IngestionService, NormalizedPost
from services.processing_queue import ProcessingQueue
from services.source_post_service import SourcePostService, SourcePostStatus

logger = logging.getLogger("AIShield.YouTubeConnector")


class YouTubeConnector(BaseConnector):
    """Keyword polling connector for YouTube Data API v3 with quota safety limits."""

    STATE_CONNECTED = "CONNECTED"
    STATE_CONNECTING = "CONNECTING"
    STATE_POLLING = "POLLING"
    STATE_IDLE = "IDLE"
    STATE_QUOTA_LIMIT_REACHED = "QUOTA_LIMIT_REACHED"
    STATE_ERROR = "ERROR"
    STATE_DISCONNECTED = "DISCONNECTED"
    STATE_STOPPED = "STOPPED"

    SEARCH_ENDPOINT = "https://www.googleapis.com/youtube/v3/search"

    def __init__(
        self,
        api_key: Optional[str] = None,
        queries: Optional[Union[str, List[str]]] = None,
        region_code: Optional[str] = None,
        language: Optional[str] = None,
        poll_interval: Optional[int] = None,
        max_results: Optional[int] = None,
        max_requests_per_day: Optional[int] = None,
        enabled: Optional[bool] = None,
        ingestion_service: Optional[IngestionService] = None,
        processing_queue: Optional[ProcessingQueue] = None,
        source_post_service: Optional[SourcePostService] = None,
    ) -> None:
        """Initialize YouTubeConnector with configuration and quota limits."""
        self._api_key = api_key if api_key is not None else YOUTUBE_API_KEY
        self.queries = self.parse_queries(queries if queries is not None else YOUTUBE_QUERIES)
        self.region_code = region_code if region_code is not None else YOUTUBE_REGION_CODE
        self.language = language if language is not None else YOUTUBE_LANGUAGE
        self.poll_interval = max(1, int(poll_interval if poll_interval is not None else YOUTUBE_POLL_INTERVAL_SECONDS))
        self.max_results = min(50, max(1, int(max_results if max_results is not None else YOUTUBE_MAX_RESULTS)))
        self.max_requests_per_day = max(1, int(max_requests_per_day if max_requests_per_day is not None else YOUTUBE_MAX_REQUESTS_PER_DAY))
        self.enabled = YOUTUBE_ENABLED if enabled is None else bool(enabled)
        self.ingestion_service = ingestion_service
        self.processing_queue = processing_queue
        self.source_post_service = source_post_service

        # Runtime state
        self._state: str = self.STATE_STOPPED if self.enabled else self.STATE_DISCONNECTED
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Observability & Quota Metrics
        self.poll_count: int = 0
        self.requests_made: int = 0
        self.requests_today: int = 0
        self.last_request_date: str = ""
        self.items_received: int = 0
        self.items_accepted: int = 0
        self.items_deduplicated: int = 0
        self.items_dropped: int = 0
        self.quota_errors: int = 0
        self.connection_errors: int = 0
        self.last_poll_at: Optional[str] = None
        self.last_event_at: Optional[str] = None

    @property
    def source_name(self) -> str:
        """Return registered source identifier."""
        return "youtube"

    @property
    def state(self) -> str:
        """Return current connector state."""
        return self._state

    def is_running(self) -> bool:
        """Return True if background polling thread is active."""
        return self._thread is not None and self._thread.is_alive()

    def receive(self) -> Optional[Any]:
        """Fetch next item; in polling mode, fetch_once performs batch retrieval."""
        return None

    @classmethod
    def parse_queries(cls, query_input: Union[str, List[str]]) -> List[str]:
        """Clean, split, and deduplicate search queries."""
        if not query_input:
            return []

        raw_list = []
        if isinstance(query_input, str):
            raw_list = [q.strip() for q in query_input.split(",") if q.strip()]
        elif isinstance(query_input, list):
            raw_list = [str(q).strip() for q in query_input if str(q).strip()]

        cleaned: List[str] = []
        seen = set()
        for q in raw_list:
            if q and q.lower() not in seen:
                seen.add(q.lower())
                cleaned.append(q)
        return cleaned

    @classmethod
    def parse_youtube_item(cls, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract standardized video item metadata from YouTube search result dictionary."""
        if not item or not isinstance(item, dict):
            return None

        # Verify video ID
        id_field = item.get("id")
        video_id = None
        if isinstance(id_field, dict):
            if id_field.get("kind") != "youtube#video":
                return None
            video_id = id_field.get("videoId")
        elif isinstance(id_field, str):
            video_id = id_field

        if not video_id or not isinstance(video_id, str) or not video_id.strip():
            return None
        video_id = video_id.strip()

        snippet = item.get("snippet")
        if not isinstance(snippet, dict):
            return None

        title = snippet.get("title", "").strip()
        description = snippet.get("description", "").strip()
        if not title and not description:
            return None

        channel_id = snippet.get("channelId", "")
        channel_title = snippet.get("channelTitle", "")
        published_at = snippet.get("publishedAt")
        thumbnails = snippet.get("thumbnails", {})
        thumb_url = None
        if isinstance(thumbnails, dict):
            thumb_url = (
                thumbnails.get("default", {}).get("url")
                or thumbnails.get("medium", {}).get("url")
                or thumbnails.get("high", {}).get("url")
            )

        metadata = {
            "videoId": video_id,
            "channelId": channel_id,
            "channelTitle": channel_title,
            "title": title,
            "description": description,
            "thumbnail_url": thumb_url,
            "publishedAt": published_at,
            "liveBroadcastContent": snippet.get("liveBroadcastContent"),
        }

        return {
            "source_id": video_id,
            "source_url": f"https://www.youtube.com/watch?v={video_id}",
            "author_id": channel_id or "unknown",
            "author_name": channel_title or channel_id or "unknown",
            "title": title,
            "description": description,
            "published_at": published_at,
            "metadata": metadata,
        }

    def normalize(self, raw_item: Any) -> NormalizedPost:
        """Transform raw YouTube video search item into NormalizedPost."""
        if isinstance(raw_item, dict) and "source_id" in raw_item:
            parsed = raw_item
        else:
            parsed = self.parse_youtube_item(raw_item)
            if parsed is None:
                raise ValueError("Cannot normalize invalid or non-video YouTube payload.")

        title = parsed.get("title", "")
        description = parsed.get("description", "")
        if title and description:
            combined = f"{title}\n\n{description}"
        else:
            combined = title or description or parsed.get("content", "")

        metadata = parsed.get("metadata", {})
        plain_content, enriched_meta = IngestionService.normalize_html_content(combined, metadata)
        final_content = plain_content if plain_content else combined.strip()

        return NormalizedPost(
            source=self.source_name,
            source_id=parsed["source_id"],
            content=final_content,
            source_url=parsed.get("source_url", f"https://www.youtube.com/watch?v={parsed['source_id']}"),
            author_id=parsed.get("author_id"),
            author_name=parsed.get("author_name"),
            published_at=parsed.get("published_at"),
            language=self.language,
            metadata=enriched_meta,
        )

    def fetch_once(self, query: Optional[str] = None) -> List[Dict[str, Any]]:
        """Perform a single controlled search request against YouTube Data API v3."""
        q = query or (self.queries[0] if self.queries else "cybersecurity")

        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._lock:
            if self.last_request_date != today_str:
                self.last_request_date = today_str
                self.requests_today = 0

            # Quota safety check
            if self.requests_today >= self.max_requests_per_day:
                self._state = self.STATE_QUOTA_LIMIT_REACHED
                logger.warning(
                    "YouTube daily safety request limit reached (%s/%s). Stopping requests.",
                    self.requests_today,
                    self.max_requests_per_day,
                )
                return []

            if not self._api_key:
                self._state = self.STATE_ERROR
                logger.warning("YouTube API key is missing. Cannot fetch YouTube videos.")
                return []

            self.requests_made += 1
            self.requests_today += 1

        params: Dict[str, Any] = {
            "part": "snippet",
            "q": q,
            "type": "video",
            "maxResults": self.max_results,
            "order": "date",
            "key": self._api_key,
        }
        if self.region_code:
            params["regionCode"] = self.region_code
        if self.language:
            params["relevanceLanguage"] = self.language

        try:
            resp = requests.get(self.SEARCH_ENDPOINT, params=params, timeout=10.0)

            if resp.status_code == 401:
                with self._lock:
                    self.connection_errors += 1
                self._state = self.STATE_ERROR
                logger.error("YouTube API authorization failed (HTTP 401). Invalid API key.")
                return []

            if resp.status_code == 403:
                with self._lock:
                    self.quota_errors += 1
                self._state = self.STATE_QUOTA_LIMIT_REACHED
                logger.warning("YouTube Data API returned HTTP 403 (Quota Exceeded or Forbidden).")
                return []

            if resp.status_code == 429:
                with self._lock:
                    self.quota_errors += 1
                self._state = self.STATE_ERROR
                logger.warning("YouTube Data API returned HTTP 429 (Rate Limited).")
                return []

            if resp.status_code != 200:
                with self._lock:
                    self.connection_errors += 1
                self._state = self.STATE_ERROR
                logger.warning("YouTube API request failed with HTTP %s: %s", resp.status_code, resp.text[:200])
                return []

            try:
                data = resp.json()
            except (ValueError, json.JSONDecodeError):
                with self._lock:
                    self.connection_errors += 1
                self._state = self.STATE_ERROR
                logger.warning("YouTube API returned malformed or non-JSON response.")
                return []
            items = data.get("items", [])
            ingested_records: List[Dict[str, Any]] = []

            for item in items:
                with self._lock:
                    self.items_received += 1
                    self.last_event_at = datetime.now(timezone.utc).isoformat()

                parsed = self.parse_youtube_item(item)
                if parsed is None:
                    continue

                try:
                    norm_post = self.normalize(parsed)
                except ValueError:
                    continue

                if self.ingestion_service is not None:
                    post_record, is_duplicate = self.ingestion_service.ingest(norm_post)
                    post_id = post_record["id"]

                    if is_duplicate:
                        with self._lock:
                            self.items_deduplicated += 1
                    else:
                        if self.source_post_service is not None:
                            self.source_post_service.update_status(post_id, SourcePostStatus.QUEUED)

                        if self.processing_queue is not None:
                            enqueued = self.processing_queue.enqueue(post_id, block=False)
                            if enqueued:
                                with self._lock:
                                    self.items_accepted += 1
                            else:
                                with self._lock:
                                    self.items_dropped += 1
                        else:
                            with self._lock:
                                self.items_accepted += 1

                    ingested_records.append(post_record)
                else:
                    with self._lock:
                        self.items_accepted += 1
                    ingested_records.append(parsed)

            self._state = self.STATE_CONNECTED
            return ingested_records

        except requests.RequestException as exc:
            with self._lock:
                self.connection_errors += 1
            self._state = self.STATE_ERROR
            logger.warning("YouTube network request error: %s", exc)
            return []

    def _run_poll_loop(self) -> None:
        """Periodic background polling loop."""
        while not self._stop_event.is_set():
            self._state = self.STATE_POLLING
            logger.info("Executing YouTube polling cycle across %s queries...", len(self.queries))

            for q in self.queries:
                if self._stop_event.is_set():
                    break
                self.fetch_once(q)
                if self._state == self.STATE_QUOTA_LIMIT_REACHED:
                    break

            with self._lock:
                self.poll_count += 1
                self.last_poll_at = datetime.now(timezone.utc).isoformat()

            if self._state != self.STATE_QUOTA_LIMIT_REACHED:
                self._state = self.STATE_IDLE

            # Sleep interruptibly until next poll cycle
            self._stop_event.wait(timeout=self.poll_interval)

        self._state = self.STATE_STOPPED
        logger.info("YouTube connector polling loop stopped.")

    def connect(self) -> None:
        """Start the background polling worker thread if enabled."""
        if not self.enabled:
            logger.info("YouTube connector is disabled (YOUTUBE_ENABLED=false). Not starting polling.")
            self._state = self.STATE_DISCONNECTED
            return

        if self.is_running():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_poll_loop,
            name="AIShield-YouTubePoller",
            daemon=True,
        )
        self._thread.start()

    def disconnect(self) -> None:
        """Stop background polling worker thread cleanly."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._state = self.STATE_STOPPED

    def get_status(self) -> Dict[str, Any]:
        """Return operational state and metrics without exposing the secret API key."""
        with self._lock:
            effective_state = self.state
            if not self.enabled:
                effective_state = "DISABLED"
            elif self.is_running() and self._state == self.STATE_STOPPED:
                effective_state = self.STATE_CONNECTING

            return {
                "status": effective_state,
                "state": effective_state,
                "connection_state": effective_state,
                "running": self.is_running(),
                "enabled": self.enabled,
                "has_api_key": bool(self._api_key),
                "queries": self.queries,
                "queries_count": len(self.queries),
                "poll_interval_seconds": self.poll_interval,
                "poll_count": self.poll_count,
                "requests_made": self.requests_made,
                "requests_today": self.requests_today,
                "max_requests_per_day": self.max_requests_per_day,
                "events_received": self.items_received,
                "events_accepted": self.items_accepted,
                "events_deduplicated": self.items_deduplicated,
                "events_dropped": self.items_dropped,
                "items_received": self.items_received,
                "items_accepted": self.items_accepted,
                "items_deduplicated": self.items_deduplicated,
                "items_dropped": self.items_dropped,
                "quota_errors": self.quota_errors,
                "connection_errors": self.connection_errors,
                "last_poll_at": self.last_poll_at,
                "last_event_at": self.last_event_at,
            }
