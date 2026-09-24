"""AIShield - Real Bluesky Live Connector (Stage 6C).

Connects to the Bluesky Jetstream WebSocket, parses post creation commits,
normalizes them into NormalizedPost instances, and feeds the ingestion queue.
"""

from datetime import datetime, timezone
import json
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Union
import urllib.parse

import requests
import websockets.sync.client

from config import (
    BLUESKY_ENABLED,
    BLUESKY_JETSTREAM_URL,
    BLUESKY_MONITOR_TERMS,
    BLUESKY_PING_INTERVAL,
    BLUESKY_PING_TIMEOUT,
    BLUESKY_RECONNECT_INITIAL_BACKOFF,
    BLUESKY_RECONNECT_MAX_BACKOFF,
    BLUESKY_RELEVANCE_FILTER_ENABLED,
)
from services.connectors.base_connector import BaseConnector
from services.ingestion_service import IngestionService, NormalizedPost
from services.processing_queue import ProcessingQueue
from services.source_post_service import SourcePostService, SourcePostStatus

logger = logging.getLogger("AIShield.BlueskyConnector")


class BlueskyConnector(BaseConnector):
    """Live WebSocket connector subscribing to Bluesky public Jetstream feed."""

    STATE_CONNECTED = "CONNECTED"
    STATE_CONNECTING = "CONNECTING"
    STATE_DISCONNECTED = "DISCONNECTED"
    STATE_ERROR = "ERROR"
    STATE_STOPPED = "STOPPED"

    def __init__(
        self,
        jetstream_url: Optional[str] = None,
        enabled: Optional[bool] = None,
        relevance_filter_enabled: Optional[bool] = None,
        monitor_terms: Optional[Union[str, List[str]]] = None,
        ingestion_service: Optional[IngestionService] = None,
        processing_queue: Optional[ProcessingQueue] = None,
        source_post_service: Optional[SourcePostService] = None,
        initial_backoff: float = BLUESKY_RECONNECT_INITIAL_BACKOFF,
        max_backoff: float = BLUESKY_RECONNECT_MAX_BACKOFF,
    ) -> None:
        """Initialize BlueskyConnector with configuration and optional pipeline services."""
        self.jetstream_url = jetstream_url or BLUESKY_JETSTREAM_URL
        self.enabled = BLUESKY_ENABLED if enabled is None else bool(enabled)
        self.relevance_filter_enabled = (
            BLUESKY_RELEVANCE_FILTER_ENABLED
            if relevance_filter_enabled is None
            else bool(relevance_filter_enabled)
        )
        self.monitor_terms = self.parse_monitor_terms(
            monitor_terms if monitor_terms is not None else BLUESKY_MONITOR_TERMS
        )
        self.ingestion_service = ingestion_service
        self.processing_queue = processing_queue
        self.source_post_service = source_post_service
        self.initial_backoff = max(0.1, float(initial_backoff))
        self.max_backoff = max(self.initial_backoff, float(max_backoff))

        # Runtime states
        self._state: str = self.STATE_STOPPED if self.enabled else self.STATE_DISCONNECTED
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._active_ws = None
        self._lock = threading.RLock()

        # Observability Metrics
        self.events_received: int = 0
        self.events_accepted: int = 0
        self.events_filtered: int = 0
        self.events_deduplicated: int = 0
        self.events_dropped: int = 0
        self.connection_errors: int = 0
        self.last_connected_at: Optional[str] = None
        self.last_event_at: Optional[str] = None
        self.last_error: Optional[str] = None

    @property
    def source_name(self) -> str:
        """Return registered source identifier."""
        return "bluesky"

    @property
    def state(self) -> str:
        """Return current connector state."""
        return self._state

    def is_running(self) -> bool:
        """Return True if connector thread is active."""
        return self._thread is not None and self._thread.is_alive()

    @classmethod
    def parse_monitor_terms(cls, term_input: Union[str, List[str]]) -> List[str]:
        """Clean, validate, and deduplicate monitoring terms."""
        if not term_input:
            return []
        raw_terms = []
        if isinstance(term_input, str):
            raw_terms = [t.strip() for t in term_input.split(",") if t.strip()]
        elif isinstance(term_input, list):
            raw_terms = [str(t).strip() for t in term_input if str(t).strip()]

        cleaned: List[str] = []
        seen = set()
        for term in raw_terms:
            t = term.lstrip("#").strip().lower()
            if not t:
                continue
            if t not in seen:
                seen.add(t)
                cleaned.append(t)
        return cleaned

    def matches_relevance(self, text: str) -> bool:
        """Check if content matches any configured monitoring term (case-insensitive)."""
        if not self.relevance_filter_enabled or not self.monitor_terms:
            return True
        if not text:
            return False
        lower_text = text.lower()
        for term in self.monitor_terms:
            if term in lower_text:
                return True
        return False

    def receive(self) -> Optional[Any]:
        """Not used in streaming mode; events are pushed directly via callbacks."""
        return None

    @classmethod
    def parse_jetstream_event(cls, raw_data: Union[str, bytes, dict]) -> Optional[Dict[str, Any]]:
        """Parse raw Jetstream message into standardized event data.

        Returns None if event is not a valid post-create commit.
        """
        if not raw_data:
            return None

        # Parse JSON payload safely
        if isinstance(raw_data, (str, bytes)):
            try:
                data = json.loads(raw_data)
            except Exception:
                return None
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            return None

        if not isinstance(data, dict):
            return None

        # Filter strictly for commit operations creating app.bsky.feed.post records
        if data.get("kind") != "commit":
            return None

        commit = data.get("commit")
        if not isinstance(commit, dict):
            return None

        if commit.get("operation") != "create":
            return None

        if commit.get("collection") != "app.bsky.feed.post":
            return None

        record = commit.get("record")
        if not isinstance(record, dict):
            return None

        text = record.get("text")
        if text is None or not isinstance(text, str) or not text.strip():
            return None

        did = data.get("did")
        if not did or not isinstance(did, str):
            return None

        rkey = commit.get("rkey")
        if not rkey or not isinstance(rkey, str):
            return None

        cid = commit.get("cid")
        created_at = record.get("createdAt")
        langs = record.get("langs")
        language = langs[0] if (isinstance(langs, list) and langs) else None
        reply = record.get("reply")

        source_id = f"{did}/{rkey}"
        source_url = f"https://bsky.app/profile/{did}/post/{rkey}"

        return {
            "source_id": source_id,
            "source_url": source_url,
            "author_id": did,
            "author_name": did,
            "content": text,
            "published_at": created_at,
            "language": language,
            "metadata": {
                "cid": cid,
                "rev": commit.get("rev"),
                "did": did,
                "rkey": rkey,
                "langs": langs,
                "reply": reply,
                "time_us": data.get("time_us"),
            },
        }

    _did_handle_cache: Dict[str, str] = {}
    _cache_lock = threading.Lock()

    @classmethod
    def resolve_did_handle(cls, did: str, timeout: float = 0.8) -> str:
        """Resolve a Bluesky DID to a human-readable handle (e.g. @user.bsky.social) with thread-safe caching."""
        if not did or not isinstance(did, str) or not did.startswith("did:"):
            return did or "unknown"

        with cls._cache_lock:
            if did in cls._did_handle_cache:
                return cls._did_handle_cache[did]

        # Resolve via public Bluesky AppView directory API
        try:
            url = f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={urllib.parse.quote(did)}"
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "AIShield-BlueskyConnector/1.0"})
            if resp.status_code == 200:
                profile = resp.json()
                handle = profile.get("handle")
                if handle:
                    formatted_handle = f"@{handle}" if not str(handle).startswith("@") else str(handle)
                    with cls._cache_lock:
                        if len(cls._did_handle_cache) > 10000:
                            cls._did_handle_cache.clear()
                        cls._did_handle_cache[did] = formatted_handle
                    return formatted_handle
        except Exception:
            pass

        return did

    def normalize(self, raw_item: Any) -> NormalizedPost:
        """Transform raw Jetstream payload into a NormalizedPost."""
        parsed = self.parse_jetstream_event(raw_item)
        if parsed is None:
            # If already parsed or flat dictionary
            if isinstance(raw_item, dict) and "source_id" in raw_item and "content" in raw_item:
                parsed = raw_item
            else:
                raise ValueError("Cannot normalize invalid or non-post Bluesky event payload.")

        raw_content = parsed["content"]
        raw_meta = parsed.get("metadata", {})
        plain_text, enriched_meta = IngestionService.normalize_html_content(raw_content, raw_meta)
        final_content = plain_text if plain_text else raw_content.strip()

        author_id = parsed.get("author_id")
        raw_author_name = parsed.get("author_name") or author_id

        # Automatically resolve DID to handle if network is available
        author_name = self.resolve_did_handle(raw_author_name) if (raw_author_name and str(raw_author_name).startswith("did:")) else raw_author_name

        return NormalizedPost(
            source=self.source_name,
            source_id=parsed["source_id"],
            content=final_content,
            source_url=parsed.get("source_url"),
            author_id=author_id,
            author_name=author_name,
            published_at=parsed.get("published_at"),
            language=parsed.get("language"),
            metadata=enriched_meta,
        )

    def process_incoming_event(self, raw_data: Union[str, bytes, dict]) -> bool:
        """Process, validate, deduplicate, and enqueue an incoming Jetstream event.

        Returns:
            bool: True if event was accepted or deduplicated, False if ignored/malformed.
        """
        with self._lock:
            self.events_received += 1
            self.last_event_at = datetime.now(timezone.utc).isoformat()

        parsed = self.parse_jetstream_event(raw_data)
        if parsed is None:
            return False

        # Relevance filtering check
        content = parsed.get("content", "")
        if not self.matches_relevance(content):
            with self._lock:
                self.events_filtered += 1
            logger.debug("Bluesky event filtered (no monitoring term match): %s", parsed.get("source_id"))
            return False

        try:
            normalized_post = self.normalize(parsed)
        except ValueError:
            return False

        if self.ingestion_service is not None:
            try:
                post_record, is_duplicate = self.ingestion_service.ingest(normalized_post)
                post_id = post_record["id"]

                if is_duplicate:
                    with self._lock:
                        self.events_deduplicated += 1
                    return True

                # New post: set status to QUEUED and push to processing queue
                if self.source_post_service is not None:
                    self.source_post_service.update_status(post_id, SourcePostStatus.QUEUED)

                if self.processing_queue is not None:
                    enqueued = self.processing_queue.enqueue(post_id, block=False)
                    if enqueued:
                        with self._lock:
                            self.events_accepted += 1
                        logger.info("Bluesky post accepted: post_id=%s, source_id=%s", post_id, normalized_post.source_id)
                    else:
                        with self._lock:
                            self.events_dropped += 1
                        logger.warning("Ingestion queue is full. Dropping Bluesky post id %s.", post_id)
                else:
                    with self._lock:
                        self.events_accepted += 1
                    logger.info("Bluesky post accepted: post_id=%s, source_id=%s", post_id, normalized_post.source_id)
                return True

            except Exception as exc:
                logger.exception("Error ingesting Bluesky event: %s", exc)
                return False
        else:
            with self._lock:
                self.events_accepted += 1
            return True

    def _run_stream_loop(self) -> None:
        """Background connection and reconnection loop with exponential backoff."""
        backoff = self.initial_backoff

        while not self._stop_event.is_set():
            self._state = self.STATE_CONNECTING
            logger.info("Connecting to Bluesky Jetstream at: %s", self.jetstream_url)

            try:
                with websockets.sync.client.connect(
                    self.jetstream_url,
                    open_timeout=10.0,
                    close_timeout=5.0,
                    ping_interval=BLUESKY_PING_INTERVAL,
                    ping_timeout=BLUESKY_PING_TIMEOUT,
                ) as ws:
                    self._active_ws = ws
                    self._state = self.STATE_CONNECTED
                    self.last_connected_at = datetime.now(timezone.utc).isoformat()
                    self.last_error = None
                    backoff = self.initial_backoff
                    logger.info("Connected to Bluesky Jetstream successfully.")

                    for message in ws:
                        if self._stop_event.is_set():
                            break
                        self.process_incoming_event(message)

            except Exception as exc:
                if self._stop_event.is_set():
                    break
                with self._lock:
                    self.connection_errors += 1
                    self.last_error = str(exc)
                self._state = self.STATE_ERROR
                logger.warning("Bluesky WebSocket connection error: %s. Retrying in %.1fs...", exc, backoff)

                # Wait with interruptible stop_event
                self._stop_event.wait(timeout=backoff)
                backoff = min(self.max_backoff, backoff * 2.0)

            finally:
                self._active_ws = None

        self._state = self.STATE_STOPPED
        logger.info("Bluesky connector background loop terminated.")

    def connect(self) -> None:
        """Start the background streaming worker if enabled."""
        if not self.enabled:
            logger.info("Bluesky connector is disabled (BLUESKY_ENABLED=false). Not starting live stream.")
            self._state = self.STATE_DISCONNECTED
            return

        if self.is_running():
            return

        self._stop_event.clear()
        self._state = self.STATE_CONNECTING
        self._thread = threading.Thread(
            target=self._run_stream_loop,
            name="AIShield-BlueskyStream",
            daemon=True,
        )
        self._thread.start()

    def disconnect(self) -> None:
        """Gracefully disconnect and terminate the background streaming worker."""
        self._stop_event.set()
        if self._active_ws is not None:
            try:
                self._active_ws.close()
            except Exception:
                pass

        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        self._state = self.STATE_STOPPED

    def get_status(self) -> Dict[str, Any]:
        """Return structured operational status and observability metrics."""
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
                "endpoint": self.jetstream_url,
                "relevance_filter_enabled": self.relevance_filter_enabled,
                "monitor_terms": self.monitor_terms,
                "monitor_terms_count": len(self.monitor_terms),
                "last_connected_at": self.last_connected_at,
                "last_event_at": self.last_event_at,
                "last_error": self.last_error,
                "events_received": self.events_received,
                "events_accepted": self.events_accepted,
                "events_filtered": self.events_filtered,
                "events_deduplicated": self.events_deduplicated,
                "events_dropped": self.events_dropped,
                "connection_errors": self.connection_errors,
            }
