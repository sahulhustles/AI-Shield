"""AIShield - Ingestion Processing Queue (Stage 6B).

Thread-safe, bounded in-memory FIFO queue for source post IDs.
"""

import queue
import threading
from typing import Optional, Set

from config import QUEUE_MAX_SIZE


class ProcessingQueue:
    """Thread-safe bounded queue storing source post IDs for asynchronous processing."""

    def __init__(self, maxsize: int = QUEUE_MAX_SIZE) -> None:
        """Initialize ProcessingQueue with maxsize capacity."""
        self.maxsize = maxsize
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._enqueued_ids: Set[int] = set()
        self._lock = threading.Lock()

    def enqueue(
        self,
        source_post_id: int,
        block: bool = True,
        timeout: Optional[float] = None,
    ) -> bool:
        """Enqueue a source_post_id if not already queued and within capacity.

        Returns:
            bool: True if successfully enqueued, False if full or already enqueued.
        """
        if not isinstance(source_post_id, int) or source_post_id <= 0:
            try:
                source_post_id = int(source_post_id)
                if source_post_id <= 0:
                    raise ValueError
            except (ValueError, TypeError):
                raise ValueError(f"source_post_id must be a positive integer, got {source_post_id}.")

        with self._lock:
            if source_post_id in self._enqueued_ids:
                # Already in queue
                return False

        try:
            self._queue.put(source_post_id, block=block, timeout=timeout)
            with self._lock:
                self._enqueued_ids.add(source_post_id)
            return True
        except queue.Full:
            return False

    def dequeue(
        self,
        block: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[int]:
        """Retrieve next source_post_id from the queue.

        Returns:
            Optional[int]: The next source_post_id, or None if queue is empty/timed out.
        """
        try:
            return self._queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

    def task_done(self, source_post_id: Optional[int] = None) -> None:
        """Signal that a dequeued task has completed and release tracking."""
        if source_post_id is not None:
            with self._lock:
                self._enqueued_ids.discard(source_post_id)
        try:
            self._queue.task_done()
        except ValueError:
            pass

    def release_id(self, source_post_id: int) -> None:
        """Release source_post_id tracking without affecting underlying task counter."""
        with self._lock:
            self._enqueued_ids.discard(source_post_id)

    def qsize(self) -> int:
        """Return the current number of items in the queue."""
        return self._queue.qsize()

    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return self._queue.empty()

    def is_full(self) -> bool:
        """Check if queue is at maximum capacity."""
        return self._queue.full()

    def clear(self) -> None:
        """Drain all items from the queue and reset tracking."""
        with self._lock:
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except (queue.Empty, ValueError):
                    break
            self._enqueued_ids.clear()
