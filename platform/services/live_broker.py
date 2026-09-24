"""AIShield - Live Event Broker for Server-Sent Events (SSE) & Dashboard (Stage 6G).

Provides thread-safe event publishing, subscriber queue management,
bounded recent event caching, and formatted SSE event streams.
"""

from collections import deque
from datetime import datetime, timezone
import json
import logging
import queue
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from config import MAX_SSE_SUBSCRIBERS, SSE_KEEPALIVE_INTERVAL_SECONDS

logger = logging.getLogger("AIShield.LiveBroker")


class LiveEventBroker:
    """Manages real-time event distribution for live monitoring clients."""

    def __init__(
        self,
        max_subscribers: int = MAX_SSE_SUBSCRIBERS,
        keepalive_interval: float = SSE_KEEPALIVE_INTERVAL_SECONDS,
        recent_events_capacity: int = 100,
    ) -> None:
        """Initialize event broker with capacity and subscriber constraints."""
        self.max_subscribers = max(1, int(max_subscribers))
        self.keepalive_interval = max(1.0, float(keepalive_interval))
        self.recent_events_capacity = max(10, int(recent_events_capacity))

        self._lock = threading.Lock()
        self._subscribers: Set[queue.Queue] = set()
        self._recent_events: deque = deque(maxlen=self.recent_events_capacity)

    def register_listener(self) -> Optional[queue.Queue]:
        """Register a new SSE client listener queue if under capacity limit."""
        with self._lock:
            if len(self._subscribers) >= self.max_subscribers:
                logger.warning(
                    "SSE listener capacity limit reached (%s/%s). Rejecting subscription.",
                    len(self._subscribers),
                    self.max_subscribers,
                )
                return None

            q: queue.Queue = queue.Queue(maxsize=200)
            self._subscribers.add(q)
            logger.info("New SSE client subscribed. Active listeners: %s", len(self._subscribers))
            return q

    def unregister_listener(self, q: queue.Queue) -> None:
        """Unregister an SSE client listener queue cleanly."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)
                logger.info("SSE client disconnected. Remaining listeners: %s", len(self._subscribers))

    def get_subscriber_count(self) -> int:
        """Return current number of active SSE listeners."""
        with self._lock:
            return len(self._subscribers)

    def publish_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast an event to all active listener queues and append to recent cache."""
        if not event_type or not isinstance(data, dict):
            return

        payload = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with self._lock:
            # Append to bounded sliding window
            self._recent_events.append(payload)

            # Copy current subscribers list to avoid holding lock during enqueue
            subscribers_snapshot = list(self._subscribers)

        for q in subscribers_snapshot:
            try:
                q.put_nowait((event_type, payload))
            except queue.Full:
                # Client is slow; drop non-blocking to prevent backpressure stalls
                logger.debug("Client subscriber queue full. Dropped live event.")

    @classmethod
    def format_sse_message(cls, event_type: str, payload: Any) -> str:
        """Format an SSE frame conforming to text/event-stream specifications."""
        serialized = json.dumps(payload)
        return f"event: {event_type}\ndata: {serialized}\n\n"

    @classmethod
    def format_keepalive(cls) -> str:
        """Format an SSE comment heartbeat to keep connections open."""
        return ": keepalive\n\n"

    def get_recent_events(
        self,
        limit: int = 50,
        source_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return bounded cached recent events in reverse chronological order (newest first)."""
        safe_limit = max(1, min(100, int(limit)))
        filter_clean = source_filter.strip().lower() if source_filter else None

        with self._lock:
            events_list = list(self._recent_events)

        # Reverse to get newest first
        events_list.reverse()

        if filter_clean and filter_clean != "all":
            filtered = []
            for ev in events_list:
                data = ev.get("data", {})
                src = str(data.get("source", "")).lower()
                if src == filter_clean:
                    filtered.append(ev)
            return filtered[:safe_limit]

        return events_list[:safe_limit]

    def clear(self) -> None:
        """Clear cached events and unregister all subscribers (useful for test resets)."""
        with self._lock:
            self._recent_events.clear()
            self._subscribers.clear()
