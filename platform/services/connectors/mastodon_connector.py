"""AIShield - Real Mastodon Live Connector (Stage 6D).

Connects to the Mastodon Streaming API (Server-Sent Events / HTTP stream),
parses status creation events, cleans HTML into safe plain text, and feeds the ingestion queue.
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

from config import (
    MASTODON_ACCESS_TOKEN,
    MASTODON_BASE_URL,
    MASTODON_ENABLED,
    MASTODON_HASHTAGS,
    MASTODON_RECONNECT_INITIAL_BACKOFF,
    MASTODON_RECONNECT_MAX_BACKOFF,
    MASTODON_STREAM_MODE,
)
from services.connectors.base_connector import BaseConnector
from services.ingestion_service import IngestionService, NormalizedPost
from services.processing_queue import ProcessingQueue
from services.source_post_service import SourcePostService, SourcePostStatus

logger = logging.getLogger("AIShield.MastodonConnector")


class MastodonConnector(BaseConnector):
    """Live streaming connector subscribing to Mastodon public or hashtag streams."""

    STATE_CONNECTED = "CONNECTED"
    STATE_CONNECTING = "CONNECTING"
    STATE_DISCONNECTED = "DISCONNECTED"
    STATE_ERROR = "ERROR"
    STATE_STOPPED = "STOPPED"

    SUB_STATE_DISABLED = "DISABLED"
    SUB_STATE_STOPPED = "STOPPED"
    SUB_STATE_CONNECTING = "CONNECTING"
    SUB_STATE_SUBSCRIBED = "SUBSCRIBED"
    SUB_STATE_NO_EVENTS = "NO_EVENTS"
    SUB_STATE_ERROR = "ERROR"

    def __init__(
        self,
        base_url: Optional[str] = None,
        access_token: Optional[str] = None,
        stream_mode: Optional[str] = None,
        hashtags: Optional[Union[str, List[str]]] = None,
        enabled: Optional[bool] = None,
        ingestion_service: Optional[IngestionService] = None,
        processing_queue: Optional[ProcessingQueue] = None,
        source_post_service: Optional[SourcePostService] = None,
        initial_backoff: float = MASTODON_RECONNECT_INITIAL_BACKOFF,
        max_backoff: float = MASTODON_RECONNECT_MAX_BACKOFF,
    ) -> None:
        """Initialize MastodonConnector with configuration and optional pipeline services."""
        self.base_url = (base_url or MASTODON_BASE_URL).rstrip("/")
        self._access_token = access_token if access_token is not None else MASTODON_ACCESS_TOKEN
        self.stream_mode = (stream_mode or MASTODON_STREAM_MODE).strip().lower()
        self.hashtags = self.parse_hashtags(hashtags if hashtags is not None else MASTODON_HASHTAGS)
        self.enabled = MASTODON_ENABLED if enabled is None else bool(enabled)
        self.ingestion_service = ingestion_service
        self.processing_queue = processing_queue
        self.source_post_service = source_post_service
        self.initial_backoff = max(0.1, float(initial_backoff))
        self.max_backoff = max(self.initial_backoff, float(max_backoff))

        # Runtime states
        self._state: str = self.STATE_STOPPED if self.enabled else self.STATE_DISCONNECTED
        self._subscription_state: str = self.SUB_STATE_STOPPED if self.enabled else self.SUB_STATE_DISABLED
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._active_sessions: List[requests.Session] = []
        self._lock = threading.RLock()

        # Observability Metrics
        self.events_received: int = 0
        self.events_accepted: int = 0
        self.events_deduplicated: int = 0
        self.events_dropped: int = 0
        self.connection_errors: int = 0
        self.last_connected_at: Optional[str] = None
        self.last_event_at: Optional[str] = None

    @property
    def source_name(self) -> str:
        """Return registered source identifier."""
        return "mastodon"

    @property
    def state(self) -> str:
        """Return current connector connection state."""
        return self._state

    @property
    def subscription_state(self) -> str:
        """Return current subscription state."""
        with self._lock:
            if not self.enabled:
                return self.SUB_STATE_DISABLED
            if self._state == self.STATE_STOPPED:
                return self.SUB_STATE_STOPPED
            if self._state == self.STATE_ERROR:
                return self.SUB_STATE_ERROR
            if self._state == self.STATE_CONNECTING:
                return self.SUB_STATE_CONNECTING
            if self._state == self.STATE_CONNECTED:
                if self.events_received == 0:
                    return self.SUB_STATE_SUBSCRIBED
                return self.SUB_STATE_SUBSCRIBED
            return self._subscription_state

    def is_running(self) -> bool:
        """Return True if any stream worker thread is active."""
        return any(t.is_alive() for t in self._threads)

    def receive(self) -> Optional[Any]:
        """Not used in streaming mode; events are pushed directly via callbacks."""
        return None

    @classmethod
    def parse_hashtags(cls, tag_input: Union[str, List[str]]) -> List[str]:
        """Clean, validate, and deduplicate hashtag input."""
        if not tag_input:
            return []

        raw_tags = []
        if isinstance(tag_input, str):
            raw_tags = [t.strip() for t in tag_input.split(",") if t.strip()]
        elif isinstance(tag_input, list):
            raw_tags = [str(t).strip() for t in tag_input if str(t).strip()]

        cleaned: List[str] = []
        seen = set()
        for tag in raw_tags:
            # Strip leading hash
            t = tag.lstrip("#").strip().lower()
            if not t:
                continue
            # Validate alphanumeric + underscore
            if re.match(r"^[a-zA-Z0-9_\u0080-\uffff]+$", t) and t not in seen:
                seen.add(t)
                cleaned.append(t)

        return cleaned

    def resolve_streaming_base_url(self) -> str:
        """Resolve dedicated streaming host for the instance if distinct (e.g., mastodon.social -> streaming.mastodon.social)."""
        if hasattr(self, "_resolved_streaming_url") and self._resolved_streaming_url:
            return self._resolved_streaming_url
        try:
            resp = requests.get(f"{self.base_url}/api/v2/instance", timeout=4.0)
            if resp.status_code == 200:
                data = resp.json()
                streaming_url = data.get("configuration", {}).get("urls", {}).get("streaming")
                if streaming_url:
                    http_stream_url = re.sub(r"^wss://", "https://", streaming_url).rstrip("/")
                    self._resolved_streaming_url = http_stream_url
                    return http_stream_url
        except Exception:
            pass
        self._resolved_streaming_url = self.base_url
        return self.base_url

    def get_stream_endpoints(self) -> List[str]:
        """Construct Mastodon streaming API endpoint URLs based on configured mode."""
        if self.stream_mode == "public":
            return [f"{self.base_url}/api/v1/streaming/public"]
        elif self.stream_mode == "hashtag":
            if not self.hashtags:
                return [f"{self.base_url}/api/v1/streaming/hashtag?tag=cybersecurity"]
            return [f"{self.base_url}/api/v1/streaming/hashtag?tag={urllib.parse.quote(tag)}" for tag in self.hashtags]
        else:
            return [f"{self.base_url}/api/v1/streaming/public"]

    @classmethod
    def parse_mastodon_status(cls, raw_data: Union[str, bytes, dict]) -> Optional[Dict[str, Any]]:
        """Parse raw Mastodon status JSON into normalized event dictionary.

        Returns None for deleted statuses, heartbeats, or private/direct content.
        """
        if not raw_data:
            return None

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

        # Ignore private or direct visibility statuses (safety & privacy boundary)
        visibility = data.get("visibility", "public")
        if visibility in ("direct", "private"):
            return None

        # Verify required status fields
        status_id = data.get("id")
        if not status_id:
            return None
        source_id = str(status_id)

        raw_content = data.get("content")
        if raw_content is None or not isinstance(raw_content, str) or not raw_content.strip():
            return None

        account = data.get("account")
        if not isinstance(account, dict):
            return None

        author_id = str(account.get("id", "")) if account.get("id") else "unknown"
        author_name = account.get("acct") or account.get("username") or account.get("display_name") or author_id

        published_at = data.get("created_at")
        language = data.get("language")
        source_url = data.get("url") or data.get("uri")

        metadata = {
            "uri": data.get("uri"),
            "visibility": visibility,
            "tags": [t.get("name") for t in data.get("tags", []) if isinstance(t, dict)],
            "account_username": account.get("username"),
            "account_display_name": account.get("display_name"),
            "reblogs_count": data.get("reblogs_count"),
            "favourites_count": data.get("favourites_count"),
            "spoiler_text": data.get("spoiler_text"),
        }

        return {
            "source_id": source_id,
            "source_url": source_url,
            "author_id": author_id,
            "author_name": author_name,
            "content": raw_content,
            "published_at": published_at,
            "language": language,
            "metadata": metadata,
        }

    def normalize(self, raw_item: Any) -> NormalizedPost:
        """Transform raw Mastodon status into a NormalizedPost with safe plain text."""
        parsed = self.parse_mastodon_status(raw_item)
        if parsed is None:
            if isinstance(raw_item, dict) and "source_id" in raw_item and "content" in raw_item:
                parsed = raw_item
            else:
                raise ValueError("Cannot normalize invalid or non-status Mastodon payload.")

        raw_content = parsed["content"]
        raw_meta = parsed.get("metadata", {})
        plain_text, enriched_meta = IngestionService.normalize_html_content(raw_content, raw_meta)
        final_content = plain_text if plain_text else raw_content.strip()

        return NormalizedPost(
            source=self.source_name,
            source_id=parsed["source_id"],
            content=final_content,
            source_url=parsed.get("source_url"),
            author_id=parsed.get("author_id"),
            author_name=parsed.get("author_name"),
            published_at=parsed.get("published_at"),
            language=parsed.get("language"),
            metadata=enriched_meta,
        )

    def process_incoming_status(self, raw_data: Union[str, bytes, dict]) -> bool:
        """Process, validate, deduplicate, and enqueue an incoming Mastodon status.

        Returns:
            bool: True if status was accepted or deduplicated, False if ignored/malformed.
        """
        with self._lock:
            self.events_received += 1
            self.last_event_at = datetime.now(timezone.utc).isoformat()

        parsed = self.parse_mastodon_status(raw_data)
        if parsed is None:
            logger.debug("Mastodon payload ignored: unparseable or non-status event.")
            return False

        try:
            normalized_post = self.normalize(parsed)
        except ValueError as e:
            logger.debug("Mastodon payload ignored: normalization error (%s).", e)
            return False

        if self.ingestion_service is not None:
            try:
                post_record, is_duplicate = self.ingestion_service.ingest(normalized_post)
                post_id = post_record["id"]

                if is_duplicate:
                    with self._lock:
                        self.events_deduplicated += 1
                    logger.info("Mastodon duplicate post deduplicated: post_id=%s, source_id=%s", post_id, normalized_post.source_id)
                    return True

                # New status: set status to QUEUED and push to processing queue
                if self.source_post_service is not None:
                    self.source_post_service.update_status(post_id, SourcePostStatus.QUEUED)

                if self.processing_queue is not None:
                    enqueued = self.processing_queue.enqueue(post_id, block=False)
                    if enqueued:
                        with self._lock:
                            self.events_accepted += 1
                        logger.info("Mastodon post accepted: post_id=%s, source_id=%s, author=%s", post_id, normalized_post.source_id, normalized_post.author_name)
                    else:
                        with self._lock:
                            self.events_dropped += 1
                        logger.warning("Ingestion queue is full. Dropping Mastodon post id %s.", post_id)
                else:
                    with self._lock:
                        self.events_accepted += 1
                    logger.info("Mastodon post accepted: post_id=%s, source_id=%s", post_id, normalized_post.source_id)
                return True

            except Exception as exc:
                logger.exception("Error ingesting Mastodon status: %s", exc)
                return False
        else:
            with self._lock:
                self.events_accepted += 1
            logger.info("Mastodon post accepted: source_id=%s (no ingestion service)", normalized_post.source_id)
            return True

    def _stream_endpoint(self, endpoint_url: str) -> None:
        """Background streaming worker for a single endpoint with exponential backoff."""
        backoff = self.initial_backoff

        headers = {
            "User-Agent": "AIShield-MastodonConnector/1.0",
            "Accept": "text/event-stream",
        }
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"

        while not self._stop_event.is_set():
            self._state = self.STATE_CONNECTING

            target_url = endpoint_url
            try:
                streaming_base = self.resolve_streaming_base_url()
                if streaming_base and streaming_base != self.base_url:
                    target_url = target_url.replace(self.base_url, streaming_base)
            except Exception:
                target_url = endpoint_url

            logger.info("Connecting to Mastodon stream at: %s", target_url)

            session = requests.Session()
            with self._lock:
                self._active_sessions.append(session)

            try:
                with session.get(target_url, headers=headers, stream=True, timeout=(10.0, 60.0)) as resp:
                    if resp.status_code == 401:
                        logger.error("Mastodon authorization failed (HTTP 401). Check MASTODON_ACCESS_TOKEN.")
                        self._state = self.STATE_ERROR
                        with self._lock:
                            self.connection_errors += 1
                        # Wait max backoff before retrying
                        self._stop_event.wait(timeout=self.max_backoff)
                        continue

                    if resp.status_code != 200:
                        logger.warning("Mastodon stream returned HTTP %s for %s.", resp.status_code, target_url)
                        self._state = self.STATE_ERROR
                        with self._lock:
                            self.connection_errors += 1
                        self._stop_event.wait(timeout=backoff)
                        backoff = min(self.max_backoff, backoff * 2.0)
                        continue

                    self._state = self.STATE_CONNECTED
                    self.last_connected_at = datetime.now(timezone.utc).isoformat()
                    backoff = self.initial_backoff
                    logger.info("Mastodon stream connected: %s", target_url)
                    logger.info("Mastodon subscription established for endpoint: %s (mode: %s)", target_url, self.stream_mode)

                    event_name: Optional[str] = None
                    data_buffer: List[str] = []

                    for raw_line in resp.iter_lines(decode_unicode=True):
                        if self._stop_event.is_set():
                            break

                        if raw_line is None:
                            continue

                        line = raw_line.strip()

                        # Heartbeat comments e.g. :thump or :) or :heartbeat
                        if line.startswith(":"):
                            logger.debug("Mastodon heartbeat received from: %s (%s)", target_url, line)
                            continue

                        # Empty line signals dispatch of buffered event
                        if not line:
                            if data_buffer:
                                full_data = "\n".join(data_buffer)
                                if event_name == "update" or event_name is None:
                                    logger.info("Mastodon update event received from: %s", target_url)
                                    self.process_incoming_status(full_data)
                                else:
                                    logger.debug("Mastodon event ignored: type=%s", event_name)
                                data_buffer = []
                                event_name = None
                            continue

                        if line.startswith("event:"):
                            event_name = line[len("event:"):].strip()
                        elif line.startswith("data:"):
                            data_content = line[len("data:"):].strip()
                            data_buffer.append(data_content)
                            # Fast dispatch for single-line JSON without newline separator
                            if event_name == "update" and data_content.startswith("{") and data_content.endswith("}"):
                                logger.info("Mastodon update event received from: %s", target_url)
                                self.process_incoming_status(data_content)
                                data_buffer = []
                                event_name = None

            except Exception as exc:
                if self._stop_event.is_set():
                    break
                with self._lock:
                    self.connection_errors += 1
                self._state = self.STATE_ERROR
                logger.warning("Mastodon streaming error: %s. Retrying in %.1fs...", exc, backoff)

                self._stop_event.wait(timeout=backoff)
                backoff = min(self.max_backoff, backoff * 2.0)

            finally:
                with self._lock:
                    if session in self._active_sessions:
                        self._active_sessions.remove(session)
                try:
                    session.close()
                except Exception:
                    pass

        self._state = self.STATE_STOPPED

    def connect(self) -> None:
        """Start streaming worker threads if enabled."""
        if not self.enabled:
            logger.info("Mastodon connector is disabled (MASTODON_ENABLED=false). Not starting live stream.")
            self._state = self.STATE_DISCONNECTED
            return

        if self.is_running():
            return

        self._stop_event.clear()
        endpoints = self.get_stream_endpoints()

        for idx, ep in enumerate(endpoints):
            t = threading.Thread(
                target=self._stream_endpoint,
                args=(ep,),
                name=f"AIShield-MastodonStream-{idx}",
                daemon=True,
            )
            self._threads.append(t)
            t.start()

    def disconnect(self) -> None:
        """Gracefully disconnect and terminate streaming worker threads."""
        self._stop_event.set()

        with self._lock:
            for s in list(self._active_sessions):
                try:
                    s.close()
                except Exception:
                    pass
            self._active_sessions.clear()

        for t in self._threads:
            if t.is_alive():
                t.join(timeout=2.0)

        self._threads.clear()
        self._state = self.STATE_STOPPED

    def get_status(self) -> Dict[str, Any]:
        """Return structured operational status and observability metrics without secrets."""
        with self._lock:
            active_count = sum(1 for t in self._threads if t.is_alive())
            return {
                "status": self.state,
                "state": self.state,
                "connection_state": self.state,
                "subscription_state": self.subscription_state,
                "running": self.is_running(),
                "enabled": self.enabled,
                "base_url": self.base_url,
                "stream_mode": self.stream_mode,
                "hashtags": self.hashtags,
                "hashtags_count": len(self.hashtags),
                "active_streams": active_count,
                "monitoring_hashtags": ", ".join(self.hashtags),
                "has_access_token": bool(self._access_token),
                "last_connected_at": self.last_connected_at,
                "last_event_at": self.last_event_at,
                "events_received": self.events_received,
                "events_accepted": self.events_accepted,
                "events_deduplicated": self.events_deduplicated,
                "events_dropped": self.events_dropped,
                "connection_errors": self.connection_errors,
            }
