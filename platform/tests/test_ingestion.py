"""AIShield - Stage 6B Tests: Connector Framework and Processing Queue."""

from pathlib import Path
import threading
import time
import pytest

from app import create_app
from database.db import init_db
from models.detector import AIDetector
from services.connectors import BaseConnector, ConnectorRegistry, ManualConnector
from services.ingestion_service import IngestionService, NormalizedPost
from services.processing_queue import ProcessingQueue
from services.processing_worker import ProcessingWorker, sanitize_error_message
from services.source_post_service import SourcePostService, SourcePostStatus


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a unique isolated temporary SQLite database path."""
    db_file = tmp_path / "test_stage_6b.db"
    return db_file


@pytest.fixture
def source_service(temp_db_path):
    """Provide an initialized SourcePostService."""
    return SourcePostService(db_path=temp_db_path)


@pytest.fixture
def test_queue():
    """Provide an empty ProcessingQueue."""
    return ProcessingQueue(maxsize=10)


@pytest.fixture
def test_client(temp_db_path):
    """Provide a Flask test client with Stage 6B services configured."""
    init_db(temp_db_path)

    # Initialize a fast real detector model for the test
    model_path = Path("models/detector_model.joblib").resolve()
    dataset_path = Path("data/dataset.csv").resolve()
    detector = AIDetector(model_path=model_path, dataset_path=dataset_path)
    if detector.model_exists():
        detector.load_model()
    else:
        detector.train(save_model=False)

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": temp_db_path,
        "DETECTOR": detector,
    })

    with app.test_client() as client:
        yield client


# =============================================================================
# Connector Framework Tests
# =============================================================================

def test_connector_registry_initialization():
    """Test registry initialization, source listing, and default connector states."""
    registry = ConnectorRegistry(auto_register_defaults=True)

    sources = registry.list_sources()
    assert set(sources) == {"bluesky", "manual", "mastodon", "youtube"}

    # Manual connector should be active
    manual = registry.get("manual")
    assert manual is not None
    assert manual.source_name == "manual"
    assert manual.is_running() is True

    # In Stage 6E, Bluesky, Mastodon, and YouTube are all registered connectors reporting lifecycle states
    states = registry.get_connector_states()
    assert states["manual"]["status"] == "available"
    assert states["manual"]["running"] is True
    assert states["bluesky"]["status"] in ("STOPPED", "DISCONNECTED", "CONNECTED", "available", "not_configured")
    assert states["mastodon"]["status"] in ("STOPPED", "DISCONNECTED", "CONNECTED", "available", "not_configured")
    assert states["youtube"]["status"] in ("STOPPED", "DISCONNECTED", "CONNECTED", "POLLING", "IDLE", "available", "not_configured")


def test_custom_connector_registration():
    """Test registering a custom connector implementing BaseConnector."""
    class CustomTestConnector(BaseConnector):
        @property
        def source_name(self) -> str:
            return "custom_source"

        def connect(self) -> None:
            pass

        def disconnect(self) -> None:
            pass

        def is_running(self) -> bool:
            return True

        def receive(self):
            return None

        def normalize(self, raw_item):
            return NormalizedPost(source="custom_source", source_id="1", content="test")

    registry = ConnectorRegistry(auto_register_defaults=False)
    custom_conn = CustomTestConnector()
    registry.register(custom_conn)

    retrieved = registry.get("custom_source")
    assert retrieved is custom_conn

    with pytest.raises(TypeError):
        registry.register("not-a-connector")


def test_manual_connector_normalization():
    """Test ManualConnector normalizes dictionary payloads and strips HTML safely."""
    connector = ManualConnector()
    raw_payload = {
        "source_id": "man-test-101",
        "content": "<p>Security announcement with <b>important</b> details.</p>",
        "author_name": "SecAnalyst",
        "metadata": {"test_flag": True},
    }

    norm_post = connector.normalize(raw_payload)
    assert isinstance(norm_post, NormalizedPost)
    assert norm_post.source == "manual"
    assert norm_post.source_id == "man-test-101"
    assert "Security announcement with important details." in norm_post.content
    assert "<p>" not in norm_post.content
    assert norm_post.metadata["test_flag"] is True
    assert "raw_html" in norm_post.metadata


def test_manual_connector_lifecycle():
    """Test ManualConnector connect, disconnect, and buffer operations."""
    connector = ManualConnector()
    assert connector.is_running() is False

    connector.connect()
    assert connector.is_running() is True

    connector.submit_raw({"source_id": "b-1", "content": "Buffer item 1"})
    received = connector.receive()
    assert received is not None
    assert received["source_id"] == "b-1"

    assert connector.receive() is None

    connector.disconnect()
    assert connector.is_running() is False


# =============================================================================
# Processing Queue Tests
# =============================================================================

def test_processing_queue_basic_operations(test_queue):
    """Test enqueue, dequeue, task_done, qsize, and is_empty on ProcessingQueue."""
    assert test_queue.is_empty() is True
    assert test_queue.qsize() == 0

    assert test_queue.enqueue(101) is True
    assert test_queue.enqueue(102) is True
    assert test_queue.qsize() == 2
    assert test_queue.is_empty() is False

    item1 = test_queue.dequeue(block=False)
    assert item1 == 101
    test_queue.task_done(item1)

    item2 = test_queue.dequeue(block=False)
    assert item2 == 102
    test_queue.task_done(item2)

    assert test_queue.is_empty() is True
    assert test_queue.dequeue(block=False) is None


def test_processing_queue_duplicate_prevention(test_queue):
    """Test that the queue prevents re-enqueuing an item ID that is already in flight."""
    assert test_queue.enqueue(201) is True
    # Attempting to enqueue same ID while in queue returns False
    assert test_queue.enqueue(201) is False
    assert test_queue.qsize() == 1

    item = test_queue.dequeue(block=False)
    assert item == 201
    test_queue.task_done(item)

    # After task_done, the same ID can be enqueued again if needed
    assert test_queue.enqueue(201) is True


def test_processing_queue_bounded_size():
    """Test that a bounded queue respects capacity limits and reports is_full."""
    small_queue = ProcessingQueue(maxsize=2)
    assert small_queue.enqueue(1) is True
    assert small_queue.enqueue(2) is True
    assert small_queue.is_full() is True

    # Third item cannot be added without blocking
    assert small_queue.enqueue(3, block=False) is False
    assert small_queue.qsize() == 2


def test_processing_queue_clear(test_queue):
    """Test clearing and draining the queue."""
    test_queue.enqueue(1)
    test_queue.enqueue(2)
    test_queue.enqueue(3)
    assert test_queue.qsize() == 3

    test_queue.clear()
    assert test_queue.is_empty() is True
    assert test_queue.qsize() == 0


# =============================================================================
# Processing Worker Tests
# =============================================================================

def test_worker_claim_and_processing_lifecycle(source_service, test_queue):
    """Test that worker claims item, transitions status to PROCESSING, and increments attempts."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="worker-lifecycle-1",
        content="Post to be claimed by worker",
    )
    source_service.update_status(post["id"], SourcePostStatus.QUEUED)
    test_queue.enqueue(post["id"])

    called = []
    def mock_callback(p):
        called.append(p["id"])

    worker = ProcessingWorker(
        queue=test_queue,
        source_post_service=source_service,
        process_callback=mock_callback,
    )

    # Process one item synchronously
    assert worker.process_one() is True
    assert called == [post["id"]]

    updated_post = source_service.get_source_post(post["id"])
    assert updated_post["status"] == SourcePostStatus.PROCESSING
    assert updated_post["analysis_attempts"] == 1
    assert test_queue.is_empty() is True


def test_worker_retry_behavior(source_service, test_queue):
    """Test worker retry behavior when attempts < max_attempts."""
    post, _ = source_service.create_source_post(
        source="manual",
        source_id="worker-retry-1",
        content="Failing post retry test",
    )
    test_queue.enqueue(post["id"])

    def failing_callback(p):
        raise RuntimeError("Transient analysis connection failure.")

    worker = ProcessingWorker(
        queue=test_queue,
        source_post_service=source_service,
        process_callback=failing_callback,
        max_attempts=3,
    )

    # Attempt 1: fails, should set QUEUED and re-enqueue
    assert worker.process_one() is False
    post_att1 = source_service.get_source_post(post["id"])
    assert post_att1["status"] == SourcePostStatus.QUEUED
    assert post_att1["analysis_attempts"] == 1
    assert "Transient analysis connection failure." in post_att1["last_error"]
    assert test_queue.qsize() == 1

    # Attempt 2: fails again, should set QUEUED and re-enqueue
    assert worker.process_one() is False
    post_att2 = source_service.get_source_post(post["id"])
    assert post_att2["status"] == SourcePostStatus.QUEUED
    assert post_att2["analysis_attempts"] == 2
    assert test_queue.qsize() == 1

    # Attempt 3: fails and hits max_attempts, should mark FAILED and not re-enqueue
    assert worker.process_one() is False
    post_att3 = source_service.get_source_post(post["id"])
    assert post_att3["status"] == SourcePostStatus.FAILED
    assert post_att3["analysis_attempts"] == 3
    assert post_att3["processed_at"] is not None
    assert test_queue.is_empty() is True


def test_worker_sanitized_error_recording(source_service, test_queue):
    """Test that sensitive credentials or bearer tokens are redacted in error messages."""
    sensitive_err = "Auth failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret and token=super_secret_token_12345"
    sanitized = sanitize_error_message(sensitive_err)

    assert "super_secret_token_12345" not in sanitized
    assert "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret" not in sanitized
    assert "[REDACTED]" in sanitized

    post, _ = source_service.create_source_post(
        source="manual",
        source_id="sanitize-err-1",
        content="Testing error sanitization",
    )
    test_queue.enqueue(post["id"])

    def leaking_callback(p):
        raise ValueError(sensitive_err)

    worker = ProcessingWorker(
        queue=test_queue,
        source_post_service=source_service,
        process_callback=leaking_callback,
        max_attempts=1,
    )
    worker.process_one()

    failed_post = source_service.get_source_post(post["id"])
    assert failed_post["status"] == SourcePostStatus.FAILED
    assert "super_secret_token_12345" not in failed_post["last_error"]
    assert "[REDACTED]" in failed_post["last_error"]


def test_worker_thread_lifecycle(source_service, test_queue):
    """Test background worker thread start, processing, and graceful shutdown."""
    processed = threading.Event()

    def thread_callback(p):
        processed.set()

    worker = ProcessingWorker(
        queue=test_queue,
        source_post_service=source_service,
        process_callback=thread_callback,
    )

    worker.start()
    assert worker.is_alive() is True

    post, _ = source_service.create_source_post(
        source="manual",
        source_id="worker-thread-1",
        content="Threaded worker item",
    )
    test_queue.enqueue(post["id"])

    # Wait for processing event
    assert processed.wait(timeout=2.0) is True

    worker.stop(timeout=2.0)
    assert worker.is_alive() is False


# =============================================================================
# REST API Endpoint Tests
# =============================================================================

def test_api_ingestion_status(test_client):
    """Test GET /api/ingestion/status returns queue size, worker count, and connector states."""
    response = test_client.get("/api/ingestion/status")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    status = data["status"]
    assert "queue_size" in status
    assert "active_workers" in status
    assert "registered_sources" in status
    assert "connector_states" in status
    assert "manual" in status["connector_states"]
    assert status["connector_states"]["manual"]["status"] == "available"


def test_api_ingestion_test_endpoint_success(test_client):
    """Test POST /api/ingestion/test creates post, sets QUEUED, enqueues, and returns 201."""
    payload = {
        "source_id": "test-ingest-api-1",
        "content": "<p>Security advisory regarding API token rotation.</p>",
        "author_name": "IngestionTester",
        "metadata": {"test_source": "manual_suite"},
    }

    response = test_client.post("/api/ingestion/test", json=payload)
    assert response.status_code == 201
    data = response.get_json()
    assert data["success"] is True
    assert data["duplicate"] is False
    assert data["enqueued"] is True
    assert data["source_post"]["source"] == "manual"
    assert data["source_post"]["status"] == "QUEUED"
    assert "Security advisory regarding API token rotation." in data["source_post"]["content"]

    # Verify queue status increment
    status_res = test_client.get("/api/ingestion/status")
    assert status_res.status_code == 200
    assert status_res.get_json()["status"]["queue_size"] >= 1


def test_api_ingestion_test_endpoint_duplicate(test_client):
    """Test POST /api/ingestion/test handles duplicate submissions with duplicate=True."""
    payload = {
        "source_id": "test-ingest-dup-1",
        "content": "Duplicate test message.",
    }

    res1 = test_client.post("/api/ingestion/test", json=payload)
    assert res1.status_code == 201
    assert res1.get_json()["duplicate"] is False

    res2 = test_client.post("/api/ingestion/test", json=payload)
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2["success"] is True
    assert data2["duplicate"] is True
    assert data2["enqueued"] is False
    assert "already exists" in data2["message"]


def test_api_ingestion_test_endpoint_invalid_payload(test_client):
    """Test POST /api/ingestion/test rejects invalid or missing fields."""
    # Missing content
    res_missing_content = test_client.post("/api/ingestion/test", json={"source_id": "123"})
    assert res_missing_content.status_code == 400
    assert "content" in res_missing_content.get_json()["error"]

    # Missing source_id
    res_missing_id = test_client.post("/api/ingestion/test", json={"content": "abc"})
    assert res_missing_id.status_code == 400
    assert "source_id" in res_missing_id.get_json()["error"]

    # Non-JSON
    res_non_json = test_client.post("/api/ingestion/test", data="plain-text")
    assert res_non_json.status_code == 400
