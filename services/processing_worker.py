"""AIShield - Ingestion Processing Worker (Stage 6B).

Background worker consuming source post IDs from ProcessingQueue,
managing status transitions, invoking processing callbacks, and handling retries.
"""

import logging
import re
import threading
import time
from typing import Any, Callable, Dict, Optional

from config import MAX_PROCESSING_ATTEMPTS
from services.processing_queue import ProcessingQueue
from services.source_post_service import SourcePostService, SourcePostStatus

logger = logging.getLogger("AIShield.Worker")


def sanitize_error_message(err_str: str) -> str:
    """Scrub potential credentials, tokens, or private secrets from error messages."""
    if not err_str:
        return "Unknown error"
    # Mask bearer tokens, keys, passwords, auth headers
    cleaned = re.sub(r"(bearer\s+)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED]", err_str, flags=re.IGNORECASE)
    cleaned = re.sub(r"(key|token|secret|password|passwd|pwd)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{6,}['\"]?", r"\1=[REDACTED]", cleaned, flags=re.IGNORECASE)
    return cleaned[:500]


class ProcessingWorker:
    """Worker claiming source posts from queue, driving lifecycle transitions and retries."""

    def __init__(
        self,
        queue: ProcessingQueue,
        source_post_service: Optional[SourcePostService] = None,
        process_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        max_attempts: int = MAX_PROCESSING_ATTEMPTS,
    ) -> None:
        """Initialize worker with dependencies and retry limits."""
        self.queue = queue
        self.source_post_service = source_post_service or SourcePostService()
        self.process_callback = process_callback
        self.max_attempts = max(1, int(max_attempts))

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._is_active = False

    def process_item(self, post_id: int) -> bool:
        """Execute the processing and retry lifecycle for a single source_post_id."""
        post = self.source_post_service.get_source_post(post_id)
        if post is None:
            logger.warning("Source post id %s not found in database. Skipping.", post_id)
            self.queue.task_done(post_id)
            return False

        # 1. Claim post: change status to PROCESSING
        self.source_post_service.mark_processing(post_id)

        # 2. Increment analysis attempts
        attempts = self.source_post_service.increment_attempts(post_id)

        # 3. Execute callback if configured
        if self.process_callback is not None:
            try:
                # Invoke registered pipeline hook (supports callback(post_id), callback(post), or AnalysisPipeline)
                try:
                    self.process_callback(post_id)
                except TypeError:
                    self.process_callback(post)
                # Success: release from queue tracking
                self.queue.task_done(post_id)
                return True
            except Exception as exc:
                raw_err = str(exc)
                clean_err = sanitize_error_message(raw_err)
                logger.warning("Processing failed for post %s (attempt %s/%s): %s", post_id, attempts, self.max_attempts, clean_err)

                # Retry logic
                if attempts < self.max_attempts:
                    # Mark QUEUED and re-enqueue
                    self.source_post_service.update_status(post_id, SourcePostStatus.QUEUED, error=clean_err)
                    self.queue.task_done(post_id)
                    self.queue.enqueue(post_id)
                else:
                    # Max attempts reached: Mark FAILED
                    self.source_post_service.mark_failed(post_id, error_message=clean_err)
                    self.queue.task_done(post_id)
                return False
        else:
            # Placeholder stage: no callback attached.
            # Do NOT pretend analysis occurred. Item remains in PROCESSING.
            self.queue.task_done(post_id)
            return True

    def process_one(self, timeout: Optional[float] = 0.1) -> bool:
        """Process one item from the queue synchronously (useful for deterministic tests)."""
        post_id = self.queue.dequeue(block=True, timeout=timeout)
        if post_id is None:
            return False
        return self.process_item(post_id)

    def _run_loop(self) -> None:
        """Main background loop."""
        self._is_active = True
        while not self._stop_event.is_set():
            post_id = self.queue.dequeue(block=True, timeout=0.2)
            if post_id is not None:
                self.process_item(post_id)
        self._is_active = False

    def start(self) -> None:
        """Start the background worker thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="AIShield-WorkerThread", daemon=True)
        self._thread.start()

    def stop(self, timeout: Optional[float] = 2.0) -> None:
        """Stop the background worker thread gracefully."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._is_active = False

    def is_alive(self) -> bool:
        """Check if worker thread is alive."""
        return self._thread is not None and self._thread.is_alive()
