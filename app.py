"""AIShield - Web Application and REST API.

Module 1: AI-Generated Content Detection
Module 2: Threat Analysis & Risk Scoring
Module 3: Digital Forensics & Incident Records
Module 4: Threat Intelligence & Investigation Dashboard
Module 5: Threat Relationship Graph & Campaign Detection
"""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import queue
import signal
import sys
import time
from typing import Optional, Tuple, Union
from flask import Flask, current_app, jsonify, render_template, request, Response

from config import (
    BLUESKY_ENABLED,
    BLUESKY_JETSTREAM_URL,
    BLUESKY_MONITOR_TERMS,
    BLUESKY_RELEVANCE_FILTER_ENABLED,
    INCIDENT_POLICY_MIN_AI_PROBABILITY,
    INCIDENT_POLICY_MIN_THREAT_SCORE,
    INCIDENT_POLICY_SECONDARY_THREAT_SCORE,
    MASTODON_ACCESS_TOKEN,
    MASTODON_BASE_URL,
    MASTODON_ENABLED,
    MASTODON_HASHTAGS,
    MASTODON_STREAM_MODE,
    MAX_PROCESSING_ATTEMPTS,
    MAX_SSE_SUBSCRIBERS,
    MAX_TEXT_LENGTH,
    QUEUE_MAX_SIZE,
    SSE_KEEPALIVE_INTERVAL_SECONDS,
    WORKER_COUNT,
    YOUTUBE_API_KEY,
    YOUTUBE_ENABLED,
    YOUTUBE_LANGUAGE,
    YOUTUBE_MAX_REQUESTS_PER_DAY,
    YOUTUBE_MAX_RESULTS,
    YOUTUBE_POLL_INTERVAL_SECONDS,
    YOUTUBE_QUERIES,
    YOUTUBE_REGION_CODE,
    GNN_ENABLED,
    GNN_MODEL_PATH,
    GNN_METADATA_PATH,
    GNN_MIN_TRAIN_NODES,
    GNN_HIDDEN_DIM,
    GNN_LEARNING_RATE,
    GNN_EPOCHS,
    GNN_DROPOUT,
    GNN_RANDOM_SEED,
)
from models.detector import AIDetector
from services.analysis_pipeline import AnalysisPipeline
from services.connectors import (
    BaseConnector,
    BlueskyConnector,
    ConnectorRegistry,
    ManualConnector,
    MastodonConnector,
    YouTubeConnector,
)
from services.forensic_service import ForensicService
from services.gnn_service import GNNThreatService
from services.graph_service import ThreatGraphService
from services.incident_policy import IncidentPolicy
from services.ingestion_service import IngestionService, NormalizedPost
from services.intelligence_service import IntelligenceService
from services.live_broker import LiveEventBroker
from services.processing_queue import ProcessingQueue
from services.processing_worker import ProcessingWorker
from services.source_post_service import SUPPORTED_SOURCES, SourcePostService, SourcePostStatus
from services.text_analyzer import TextAnalyzer
from services.threat_analyzer import ThreatAnalyzer

# Configure logging format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("AIShield")

# Maximum permitted character length for input texts (prevents DoS via gigantic payloads)
MAX_TEXT_LENGTH = 50000


def init_detector(app: Flask) -> AIDetector:
    """Initialize, train (if needed), and load the AIDetector model.

    Uses Pathlib to guarantee robust path resolution regardless of working directory.
    """
    root_path = Path(app.root_path).resolve()
    model_path = root_path / "models" / "detector_model.joblib"
    dataset_path = root_path / "data" / "dataset.csv"
    report_path = root_path / "models" / "evaluation_report.json"

    detector = AIDetector(
        model_path=model_path,
        dataset_path=dataset_path,
        report_path=report_path,
    )

    if detector.model_exists():
        try:
            logger.info("Loading pre-trained model artifact from: %s", model_path)
            detector.load_model()
            logger.info("Model loaded successfully into memory.")
        except Exception as err:
            logger.warning("Failed to load existing model (%s). Retraining...", err)
            try:
                metrics = detector.train(save_model=True)
                logger.info("Retrained model successfully. Evaluation metrics: %s", metrics)
            except Exception as train_err:
                logger.critical("Failed to train model on startup: %s", train_err)
                raise RuntimeError(f"Startup failed: Unable to train model from dataset at {dataset_path}: {train_err}") from train_err
    else:
        logger.info("Pre-trained model artifact not found. Initializing auto-training from: %s", dataset_path)
        try:
            metrics = detector.train(save_model=True)
            logger.info("Model trained and saved to %s. Evaluation metrics: %s", model_path, metrics)
        except Exception as err:
            logger.critical("Fatal startup failure during model initialization: %s", err)
            raise RuntimeError(f"Startup failed: Unable to initialize model from {dataset_path}: {err}") from err

    return detector


def create_app(test_config: Optional[dict] = None) -> Flask:
    """Application factory for AIShield Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.start_time = time.time()

    if test_config:
        app.config.update(test_config)

    # Initialize services
    text_analyzer = TextAnalyzer()
    threat_analyzer = ThreatAnalyzer()

    # Initialize forensic, intelligence, graph, and source post services (SQLite database auto-created)
    db_path = app.config.get("DATABASE_PATH")
    forensic_service = ForensicService(db_path=db_path)
    intelligence_service = IntelligenceService(db_path=db_path)
    graph_service = ThreatGraphService(db_path=db_path)
    source_post_service = SourcePostService(db_path=db_path)
    ingestion_service = IngestionService(source_post_service=source_post_service)

    # Initialize or load detector model
    if app.config.get("TESTING") and "DETECTOR" in app.config:
        detector = app.config["DETECTOR"]
    else:
        detector = init_detector(app)

    # Initialize live event broker (Stage 6G)
    max_subscribers = app.config.get("MAX_SSE_SUBSCRIBERS", MAX_SSE_SUBSCRIBERS)
    keepalive_interval = app.config.get("SSE_KEEPALIVE_INTERVAL_SECONDS", SSE_KEEPALIVE_INTERVAL_SECONDS)
    live_broker = LiveEventBroker(max_subscribers=max_subscribers, keepalive_interval=keepalive_interval)

    # Initialize connector registry, processing queue, and Stage 6F analysis pipeline
    queue_max_size = app.config.get("QUEUE_MAX_SIZE", QUEUE_MAX_SIZE)
    processing_queue = ProcessingQueue(maxsize=queue_max_size)
    max_attempts = app.config.get("MAX_PROCESSING_ATTEMPTS", MAX_PROCESSING_ATTEMPTS)

    incident_policy = IncidentPolicy(
        min_threat_score=app.config.get("INCIDENT_POLICY_MIN_THREAT_SCORE", INCIDENT_POLICY_MIN_THREAT_SCORE),
        min_ai_prob=app.config.get("INCIDENT_POLICY_MIN_AI_PROBABILITY", INCIDENT_POLICY_MIN_AI_PROBABILITY),
        secondary_threat_score=app.config.get("INCIDENT_POLICY_SECONDARY_THREAT_SCORE", INCIDENT_POLICY_SECONDARY_THREAT_SCORE),
    )

    analysis_pipeline = AnalysisPipeline(
        detector=detector,
        text_analyzer=text_analyzer,
        threat_analyzer=threat_analyzer,
        forensic_service=forensic_service,
        source_post_service=source_post_service,
        incident_policy=incident_policy,
        max_attempts=max_attempts,
        live_broker=live_broker,
    )

    processing_worker = ProcessingWorker(
        queue=processing_queue,
        source_post_service=source_post_service,
        process_callback=analysis_pipeline.process_source_post,
        max_attempts=max_attempts,
    )

    # Initialize Bluesky connector
    bluesky_enabled = app.config.get("BLUESKY_ENABLED", BLUESKY_ENABLED)
    bluesky_url = app.config.get("BLUESKY_JETSTREAM_URL", BLUESKY_JETSTREAM_URL)
    bluesky_filter_enabled = app.config.get("BLUESKY_RELEVANCE_FILTER_ENABLED", BLUESKY_RELEVANCE_FILTER_ENABLED)
    bluesky_terms = app.config.get("BLUESKY_MONITOR_TERMS", BLUESKY_MONITOR_TERMS)
    bluesky_connector = BlueskyConnector(
        jetstream_url=bluesky_url,
        enabled=bluesky_enabled,
        relevance_filter_enabled=bluesky_filter_enabled,
        monitor_terms=bluesky_terms,
        ingestion_service=ingestion_service,
        processing_queue=processing_queue,
        source_post_service=source_post_service,
    )

    # Initialize Mastodon connector
    mastodon_enabled = app.config.get("MASTODON_ENABLED", MASTODON_ENABLED)
    mastodon_base_url = app.config.get("MASTODON_BASE_URL", MASTODON_BASE_URL)
    mastodon_token = app.config.get("MASTODON_ACCESS_TOKEN", MASTODON_ACCESS_TOKEN)
    mastodon_mode = app.config.get("MASTODON_STREAM_MODE", MASTODON_STREAM_MODE)
    mastodon_tags = app.config.get("MASTODON_HASHTAGS", MASTODON_HASHTAGS)

    mastodon_connector = MastodonConnector(
        base_url=mastodon_base_url,
        access_token=mastodon_token,
        stream_mode=mastodon_mode,
        hashtags=mastodon_tags,
        enabled=mastodon_enabled,
        ingestion_service=ingestion_service,
        processing_queue=processing_queue,
        source_post_service=source_post_service,
    )

    # Initialize YouTube connector
    youtube_enabled = app.config.get("YOUTUBE_ENABLED", YOUTUBE_ENABLED)
    youtube_key = app.config.get("YOUTUBE_API_KEY", YOUTUBE_API_KEY)
    youtube_queries = app.config.get("YOUTUBE_QUERIES", YOUTUBE_QUERIES)
    youtube_region = app.config.get("YOUTUBE_REGION_CODE", YOUTUBE_REGION_CODE)
    youtube_lang = app.config.get("YOUTUBE_LANGUAGE", YOUTUBE_LANGUAGE)
    youtube_interval = app.config.get("YOUTUBE_POLL_INTERVAL_SECONDS", YOUTUBE_POLL_INTERVAL_SECONDS)
    youtube_max_res = app.config.get("YOUTUBE_MAX_RESULTS", YOUTUBE_MAX_RESULTS)
    youtube_max_reqs = app.config.get("YOUTUBE_MAX_REQUESTS_PER_DAY", YOUTUBE_MAX_REQUESTS_PER_DAY)

    youtube_connector = YouTubeConnector(
        api_key=youtube_key,
        queries=youtube_queries,
        region_code=youtube_region,
        language=youtube_lang,
        poll_interval=youtube_interval,
        max_results=youtube_max_res,
        max_requests_per_day=youtube_max_reqs,
        enabled=youtube_enabled,
        ingestion_service=ingestion_service,
        processing_queue=processing_queue,
        source_post_service=source_post_service,
    )

    connector_registry = ConnectorRegistry(
        bluesky_connector=bluesky_connector,
        mastodon_connector=mastodon_connector,
        youtube_connector=youtube_connector,
    )

    # If enabled and not in testing, start live background stream(s) / poller
    if bluesky_enabled and not app.config.get("TESTING"):
        bluesky_connector.connect()

    if mastodon_enabled and not app.config.get("TESTING"):
        mastodon_connector.connect()

    if youtube_enabled and not app.config.get("TESTING"):
        youtube_connector.connect()

    if not app.config.get("TESTING"):
        processing_worker.start()

    # Initialize GNN Threat Cluster Service
    gnn_model_path = app.config.get("GNN_MODEL_PATH", GNN_MODEL_PATH)
    gnn_meta_path = app.config.get("GNN_METADATA_PATH", GNN_METADATA_PATH)
    gnn_min_nodes = app.config.get("GNN_MIN_TRAIN_NODES", GNN_MIN_TRAIN_NODES)
    gnn_hidden_dim = app.config.get("GNN_HIDDEN_DIM", GNN_HIDDEN_DIM)
    gnn_lr = app.config.get("GNN_LEARNING_RATE", GNN_LEARNING_RATE)
    gnn_epochs = app.config.get("GNN_EPOCHS", GNN_EPOCHS)
    gnn_dropout = app.config.get("GNN_DROPOUT", GNN_DROPOUT)
    gnn_seed = app.config.get("GNN_RANDOM_SEED", GNN_RANDOM_SEED)

    gnn_service = GNNThreatService(
        db_path=db_path,
        model_path=gnn_model_path,
        metadata_path=gnn_meta_path,
        min_train_nodes=gnn_min_nodes,
        hidden_dim=gnn_hidden_dim,
        lr=gnn_lr,
        epochs=gnn_epochs,
        dropout=gnn_dropout,
        random_seed=gnn_seed,
    )

    # Attach service instances to app
    app.detector = detector
    app.text_analyzer = text_analyzer
    app.threat_analyzer = threat_analyzer
    app.forensic_service = forensic_service
    app.intelligence_service = intelligence_service
    app.graph_service = graph_service
    app.gnn_service = gnn_service
    app.source_post_service = source_post_service
    app.ingestion_service = ingestion_service
    app.connector_registry = connector_registry
    app.bluesky_connector = bluesky_connector
    app.mastodon_connector = mastodon_connector
    app.youtube_connector = youtube_connector
    app.processing_queue = processing_queue
    app.processing_worker = processing_worker
    app.incident_policy = incident_policy
    app.analysis_pipeline = analysis_pipeline
    app.live_broker = live_broker

    # =========================================================================
    # HTML View Routes
    # =========================================================================

    @app.route("/", methods=["GET"])
    def index():
        """Render the primary single-page user interface."""
        return render_template("index.html")

    @app.route("/incidents", methods=["GET"])
    def incidents_view():
        """Render the incident history listing page."""
        return render_template("incidents.html")

    @app.route("/incidents/<incident_id>", methods=["GET"])
    def incident_detail_view(incident_id: str):
        """Render the detailed forensic snapshot page for a specific incident."""
        forensic_srv = getattr(current_app, "forensic_service", app.forensic_service)
        incident = forensic_srv.get_incident(incident_id)
        if incident is None:
            return render_template("incidents.html", error=f"Incident '{incident_id}' was not found."), 404
        return render_template("incident_detail.html", incident=incident)

    @app.route("/dashboard", methods=["GET"])
    def dashboard_view():
        """Render the threat intelligence and investigation dashboard."""
        return render_template("dashboard.html")

    @app.route("/graph", methods=["GET"])
    def graph_view():
        """Render the threat relationship graph & campaign detection interface."""
        return render_template("graph.html")

    @app.route("/live", methods=["GET"])
    def live_monitoring_view():
        """Render the real-time live ingestion and analysis monitoring dashboard."""
        return render_template("live.html")

    @app.route("/favicon.ico", methods=["GET"])
    def favicon():
        """Handle favicon request gracefully with 204 No Content."""
        return Response(status=204)

    # =========================================================================
    # REST API Routes - Analysis (Modules 1 & 2)
    # =========================================================================

    @app.route("/api/analyze", methods=["POST"])
    def analyze_text() -> Tuple[Response, int]:
        """Analyze submitted text for AI probability, structural statistics, and threat risk scoring.

        Expected JSON body:
            {
                "text": "String to be analyzed"
            }
        """
        # 1. Validate that the request contains JSON
        if not request.is_json:
            return jsonify({
                "success": False,
                "error": "Invalid request: Content-Type must be 'application/json' with a valid JSON payload.",
            }), 400

        data = request.get_json(silent=True)
        if data is None or not isinstance(data, dict):
            return jsonify({
                "success": False,
                "error": "Invalid request: Request body must be a valid JSON object.",
            }), 400

        # 2. Validate that the 'text' key is present
        if "text" not in data:
            return jsonify({
                "success": False,
                "error": "Missing required field: 'text' is required in the JSON payload.",
            }), 400

        text = data["text"]

        # 3. Validate text type and content
        if not isinstance(text, str):
            return jsonify({
                "success": False,
                "error": "Invalid field type: 'text' must be a string.",
            }), 400

        cleaned_text = text.strip()
        if not cleaned_text:
            return jsonify({
                "success": False,
                "error": "Empty input: 'text' cannot be empty or contain only whitespace.",
            }), 400

        # 4. Validate maximum length (preventing resource exhaustion)
        if len(text) > MAX_TEXT_LENGTH:
            return jsonify({
                "success": False,
                "error": f"Input text exceeds maximum allowed length of {MAX_TEXT_LENGTH:,} characters.",
            }), 400

        # 5. Run prediction, text analysis, and threat analysis safely
        try:
            detector_service = getattr(current_app, "detector", app.detector)
            analyzer_service = getattr(current_app, "text_analyzer", app.text_analyzer)
            threat_service = getattr(current_app, "threat_analyzer", app.threat_analyzer)

            # Module 1 Output
            prediction = detector_service.predict(text)
            text_analysis = analyzer_service.analyze(text)

            # Module 2 Output (consumes Module 1 output)
            threat_analysis = threat_service.analyze(
                text,
                module1_prediction=prediction,
                text_analysis=text_analysis,
            )

            return jsonify({
                "success": True,
                "prediction": prediction,
                "text_analysis": text_analysis,
                "threat_analysis": threat_analysis,
            }), 200

        except ValueError as val_err:
            logger.warning("Validation error during analysis: %s", val_err)
            return jsonify({
                "success": False,
                "error": str(val_err),
            }), 400

        except Exception as exc:
            # Log traceback internally without exposing details to client
            logger.exception("Unexpected error during text analysis: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while processing the text. Please try again.",
            }), 500

    # =========================================================================
    # REST API Routes - Digital Forensics & Incidents (Module 3)
    # =========================================================================

    @app.route("/api/incidents", methods=["POST"])
    def create_incident_record() -> Tuple[Response, int]:
        """Persist a completed analysis as an immutable forensic incident record in SQLite.

        Expected JSON body:
            {
                "text": "Exact submitted text",
                "prediction": { ... },
                "text_analysis": { ... },
                "threat_analysis": { ... }
            }
        """
        if not request.is_json:
            return jsonify({
                "success": False,
                "error": "Invalid request: Content-Type must be 'application/json'.",
            }), 400

        data = request.get_json(silent=True)
        if data is None or not isinstance(data, dict):
            return jsonify({
                "success": False,
                "error": "Invalid request: Request body must be a JSON object.",
            }), 400

        # Validate presence of required keys
        required_keys = {"text", "prediction", "text_analysis", "threat_analysis"}
        if not required_keys.issubset(data.keys()):
            return jsonify({
                "success": False,
                "error": f"Missing required fields for incident creation: {list(required_keys - set(data.keys()))}",
            }), 400

        try:
            forensic_srv = getattr(current_app, "forensic_service", app.forensic_service)
            incident_summary = forensic_srv.create_incident(
                content=data["text"],
                prediction=data["prediction"],
                text_analysis=data["text_analysis"],
                threat_analysis=data["threat_analysis"],
            )

            return jsonify({
                "success": True,
                "incident": incident_summary,
            }), 201

        except ValueError as val_err:
            logger.warning("Validation failed for incident creation: %s", val_err)
            return jsonify({
                "success": False,
                "error": str(val_err),
            }), 400

        except Exception as exc:
            logger.exception("Unexpected error while saving incident: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while saving the incident record.",
            }), 500

    @app.route("/api/incidents", methods=["GET"])
    def list_incident_records() -> Tuple[Response, int]:
        """List summary incident records ordered newest first."""
        try:
            limit_str = request.args.get("limit", "50")
            offset_str = request.args.get("offset", "0")

            try:
                limit = int(limit_str)
                offset = int(offset_str)
            except ValueError:
                return jsonify({
                    "success": False,
                    "error": "Query parameters 'limit' and 'offset' must be integers.",
                }), 400

            if limit < 1 or limit > 200 or offset < 0:
                return jsonify({
                    "success": False,
                    "error": "Limit must be between 1 and 200, and offset must be non-negative.",
                }), 400

            forensic_srv = getattr(current_app, "forensic_service", app.forensic_service)
            incidents = forensic_srv.list_incidents(limit=limit, offset=offset)

            return jsonify({
                "success": True,
                "incidents": incidents,
                "count": len(incidents),
            }), 200

        except Exception as exc:
            logger.exception("Unexpected error retrieving incident list: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving incident records.",
            }), 500

    @app.route("/api/incidents/<incident_id>", methods=["GET"])
    def get_incident_record(incident_id: str) -> Tuple[Response, int]:
        """Retrieve complete immutable forensic snapshot for a single incident."""
        try:
            forensic_srv = getattr(current_app, "forensic_service", app.forensic_service)
            incident = forensic_srv.get_incident(incident_id)

            if incident is None:
                return jsonify({
                    "success": False,
                    "error": f"Incident record '{incident_id}' was not found.",
                }), 404

            return jsonify({
                "success": True,
                "incident": incident,
            }), 200

        except Exception as exc:
            logger.exception("Unexpected error retrieving incident %s: %s", incident_id, exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving the incident.",
            }), 500

    @app.route("/api/incidents/<incident_id>/verify", methods=["POST"])
    def verify_incident_record_integrity(incident_id: str) -> Tuple[Response, int]:
        """Perform cryptographic SHA-256 integrity verification against stored content."""
        try:
            forensic_srv = getattr(current_app, "forensic_service", app.forensic_service)
            result = forensic_srv.verify_incident_integrity(incident_id)

            if result is None:
                return jsonify({
                    "success": False,
                    "error": f"Incident record '{incident_id}' was not found.",
                }), 404

            return jsonify({
                "success": True,
                **result,
            }), 200

        except Exception as exc:
            logger.exception("Unexpected error verifying incident %s: %s", incident_id, exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred during cryptographic verification.",
            }), 500

    # =========================================================================
    # REST API Routes - Threat Intelligence & Investigation Dashboard (Module 4)
    # =========================================================================

    @app.route("/api/dashboard/summary", methods=["GET"])
    def dashboard_summary() -> Tuple[Response, int]:
        """Retrieve aggregate summary counts and average risk metrics."""
        try:
            intel_srv = getattr(current_app, "intelligence_service", app.intelligence_service)
            stats = intel_srv.get_summary_statistics()
            return jsonify({
                "success": True,
                "summary": stats,
            }), 200
        except Exception as exc:
            logger.exception("Unexpected error retrieving dashboard summary: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving dashboard summary statistics.",
            }), 500

    @app.route("/api/dashboard/recent", methods=["GET"])
    def dashboard_recent() -> Tuple[Response, int]:
        """Retrieve recent incident records."""
        try:
            limit = int(request.args.get("limit", 10))
            intel_srv = getattr(current_app, "intelligence_service", app.intelligence_service)
            recent = intel_srv.get_recent_incidents(limit=limit)
            return jsonify({
                "success": True,
                "recent": recent,
            }), 200
        except Exception as exc:
            logger.exception("Unexpected error retrieving recent incidents: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving recent incidents.",
            }), 500

    @app.route("/api/dashboard/high-risk", methods=["GET"])
    def dashboard_high_risk() -> Tuple[Response, int]:
        """Retrieve high-risk and critical incidents for investigation."""
        try:
            limit = int(request.args.get("limit", 10))
            intel_srv = getattr(current_app, "intelligence_service", app.intelligence_service)
            high_risk = intel_srv.get_high_risk_incidents(limit=limit)
            return jsonify({
                "success": True,
                "high_risk": high_risk,
            }), 200
        except Exception as exc:
            logger.exception("Unexpected error retrieving high risk incidents: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving high-risk incidents.",
            }), 500

    @app.route("/api/dashboard/distribution", methods=["GET"])
    def dashboard_distribution() -> Tuple[Response, int]:
        """Retrieve risk, category, and AI classification distributions."""
        try:
            intel_srv = getattr(current_app, "intelligence_service", app.intelligence_service)
            risk_dist = intel_srv.get_risk_distribution()
            cat_dist = intel_srv.get_category_distribution()
            ai_dist = intel_srv.get_ai_distribution()
            return jsonify({
                "success": True,
                "risk": risk_dist,
                "categories": cat_dist,
                "ai": ai_dist,
            }), 200
        except Exception as exc:
            logger.exception("Unexpected error retrieving distributions: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while calculating incident distributions.",
            }), 500

    @app.route("/api/dashboard/trend", methods=["GET"])
    def dashboard_trend() -> Tuple[Response, int]:
        """Retrieve daily chronological threat activity and average score trend."""
        try:
            intel_srv = getattr(current_app, "intelligence_service", app.intelligence_service)
            trend = intel_srv.get_risk_trend()
            return jsonify({
                "success": True,
                "trend": trend,
            }), 200
        except Exception as exc:
            logger.exception("Unexpected error retrieving threat trend: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while calculating threat trend.",
            }), 500

    @app.route("/api/dashboard/incidents", methods=["GET"])
    def dashboard_search_incidents() -> Tuple[Response, int]:
        """Multi-filter search, sorting, and pagination across stored incidents."""
        try:
            q = request.args.get("q")
            risk_level = request.args.get("risk_level")
            category = request.args.get("category")
            ai_label = request.args.get("ai_label")
            min_score = request.args.get("min_score")
            max_score = request.args.get("max_score")
            from_date = request.args.get("from_date")
            to_date = request.args.get("to_date")
            sort = request.args.get("sort", "date")
            order = request.args.get("order", "desc")
            page = request.args.get("page", 1)
            page_size = request.args.get("page_size", 20)

            intel_srv = getattr(current_app, "intelligence_service", app.intelligence_service)
            results = intel_srv.search_incidents(
                q=q,
                risk_level=risk_level,
                category=category,
                ai_label=ai_label,
                min_score=min_score,
                max_score=max_score,
                from_date=from_date,
                to_date=to_date,
                sort=sort,
                order=order,
                page=page,
                page_size=page_size,
            )

            return jsonify({
                "success": True,
                **results,
            }), 200

        except ValueError as val_err:
            logger.warning("Validation error in dashboard search: %s", val_err)
            return jsonify({
                "success": False,
                "error": str(val_err),
            }), 400

        except Exception as exc:
            logger.exception("Unexpected error in dashboard search: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while searching incident records.",
            }), 500

    # =========================================================================
    # REST API Routes - Threat Relationship Graph & Campaign Detection (Module 5)
    # =========================================================================

    @app.route("/api/graph", methods=["GET"])
    def get_threat_relationship_graph() -> Tuple[Response, int]:
        """Generate and retrieve relationship graph, similarity edges, and detected campaigns."""
        try:
            threshold_param = request.args.get("threshold")
            limit_param = request.args.get("limit")
            graph_srv = getattr(current_app, "graph_service", app.graph_service)

            if threshold_param is not None:
                threshold = graph_srv.validate_threshold(threshold_param)
            else:
                threshold = graph_srv.DEFAULT_SIMILARITY_THRESHOLD

            if limit_param is not None:
                try:
                    limit = int(limit_param)
                except (ValueError, TypeError):
                    limit = graph_srv.DEFAULT_INCIDENTS_LIMIT
            else:
                limit = graph_srv.DEFAULT_INCIDENTS_LIMIT

            graph_data = graph_srv.get_graph_data(threshold=threshold, limit=limit)

            return jsonify({
                "success": True,
                **graph_data,
            }), 200

        except ValueError as val_err:
            logger.warning("Validation error in graph API: %s", val_err)
            return jsonify({
                "success": False,
                "error": str(val_err),
            }), 400

        except Exception as exc:
            logger.exception("Unexpected error generating relationship graph: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while generating the relationship graph.",
            }), 500

    @app.route("/api/campaigns", methods=["GET"])
    def list_potential_campaigns() -> Tuple[Response, int]:
        """List detected potential campaigns from connected clusters."""
        try:
            threshold_param = request.args.get("threshold")
            limit_param = request.args.get("limit")
            graph_srv = getattr(current_app, "graph_service", app.graph_service)

            if threshold_param is not None:
                threshold = graph_srv.validate_threshold(threshold_param)
            else:
                threshold = graph_srv.DEFAULT_SIMILARITY_THRESHOLD

            if limit_param is not None:
                try:
                    limit = int(limit_param)
                except (ValueError, TypeError):
                    limit = graph_srv.DEFAULT_INCIDENTS_LIMIT
            else:
                limit = graph_srv.DEFAULT_INCIDENTS_LIMIT

            campaigns = graph_srv.get_campaigns_list(threshold=threshold, limit=limit)

            return jsonify({
                "success": True,
                "threshold": threshold,
                "campaigns": campaigns,
                "count": len(campaigns),
            }), 200

        except ValueError as val_err:
            logger.warning("Validation error in campaigns API: %s", val_err)
            return jsonify({
                "success": False,
                "error": str(val_err),
            }), 400

        except Exception as exc:
            logger.exception("Unexpected error listing campaigns: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while detecting potential campaigns.",
            }), 500

    @app.route("/api/campaigns/<campaign_id>", methods=["GET"])
    def get_campaign_detail(campaign_id: str) -> Tuple[Response, int]:
        """Retrieve detail and metrics for a specific deterministic campaign ID."""
        try:
            threshold_param = request.args.get("threshold")
            graph_srv = getattr(current_app, "graph_service", app.graph_service)

            if threshold_param is not None:
                threshold = graph_srv.validate_threshold(threshold_param)
            else:
                threshold = graph_srv.DEFAULT_SIMILARITY_THRESHOLD

            campaign = graph_srv.get_campaign_by_id(campaign_id, threshold=threshold)

            if campaign is None:
                return jsonify({
                    "success": False,
                    "error": f"Campaign '{campaign_id}' was not found at threshold {threshold}.",
                }), 404

            return jsonify({
                "success": True,
                "threshold": threshold,
                "campaign": campaign,
            }), 200

        except ValueError as val_err:
            logger.warning("Validation error in campaign detail API: %s", val_err)
            return jsonify({
                "success": False,
                "error": str(val_err),
            }), 400

        except Exception as exc:
            logger.exception("Unexpected error retrieving campaign detail %s: %s", campaign_id, exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving the campaign details.",
            }), 500

    # =========================================================================
    # REST API Routes - GNN Threat Cluster Analysis
    # =========================================================================

    @app.route("/api/gnn/status", methods=["GET"])
    def get_gnn_model_status() -> Tuple[Response, int]:
        """Retrieve operational status, metadata, and evaluation metrics for GNN model."""
        try:
            gnn_srv = getattr(current_app, "gnn_service", app.gnn_service)
            status_data = gnn_srv.get_status()
            return jsonify({
                "success": True,
                **status_data,
            }), 200
        except Exception as exc:
            logger.exception("Error retrieving GNN status: %s", exc)
            return jsonify({
                "success": False,
                "error": "Failed to retrieve GNN model status.",
            }), 500

    @app.route("/api/gnn/train", methods=["POST"])
    def train_gnn_model() -> Tuple[Response, int]:
        """Trigger on-demand GNN training against current database incidents."""
        try:
            gnn_srv = getattr(current_app, "gnn_service", app.gnn_service)
            req_data = request.get_json(silent=True) or {}
            threshold_param = req_data.get("threshold", request.args.get("threshold", 0.65))

            try:
                threshold = float(threshold_param)
            except (ValueError, TypeError):
                threshold = 0.65

            result = gnn_srv.train(similarity_threshold=threshold)
            if not result.get("success", False):
                if result.get("training_status") == "TRAINING":
                    return jsonify(result), 409
                return jsonify(result), 400

            return jsonify(result), 200
        except Exception as exc:
            logger.exception("Error during GNN training route: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred during GNN model training.",
            }), 500

    @app.route("/api/gnn/predictions", methods=["GET"])
    def get_gnn_predictions() -> Tuple[Response, int]:
        """Retrieve GNN cluster membership predictions for stored incidents."""
        try:
            gnn_srv = getattr(current_app, "gnn_service", app.gnn_service)
            threshold_param = request.args.get("threshold", 0.65)
            try:
                threshold = float(threshold_param)
            except (ValueError, TypeError):
                threshold = 0.65

            result = gnn_srv.predict(similarity_threshold=threshold)
            return jsonify(result), 200
        except Exception as exc:
            logger.exception("Error retrieving GNN predictions: %s", exc)
            return jsonify({
                "success": False,
                "error": "Failed to retrieve GNN cluster predictions.",
            }), 500

    @app.route("/api/gnn/analyze", methods=["POST"])
    def run_gnn_analysis() -> Tuple[Response, int]:
        """Run GNN inference on current incident relationship graph."""
        try:
            gnn_srv = getattr(current_app, "gnn_service", app.gnn_service)
            req_data = request.get_json(silent=True) or {}
            threshold_param = req_data.get("threshold", request.args.get("threshold", 0.65))
            try:
                threshold = float(threshold_param)
            except (ValueError, TypeError):
                threshold = 0.65

            result = gnn_srv.predict(similarity_threshold=threshold)
            return jsonify(result), 200
        except Exception as exc:
            logger.exception("Error during GNN analysis route: %s", exc)
            return jsonify({
                "success": False,
                "error": "Failed to run GNN graph analysis.",
            }), 500

    # =========================================================================
    # REST API Routes - Source Posts & Ingestion Foundation (Stage 6A)
    # =========================================================================

    @app.route("/api/source-posts", methods=["POST"])
    def create_source_post_record() -> Tuple[Response, int]:
        """Ingest a normalized external source post.

        Expected JSON body:
            {
                "source": "manual" | "bluesky" | "mastodon" | "youtube",
                "source_id": "unique-id-on-platform",
                "content": "Raw or normalized text content",
                "source_url": "https://...",
                "author_id": "...",
                "author_name": "...",
                "published_at": "2026-08-18T06:00:00Z",
                "language": "en",
                "metadata": { ... }
            }
        """
        if not request.is_json:
            return jsonify({
                "success": False,
                "error": "Invalid request: Content-Type must be 'application/json'.",
            }), 400

        data = request.get_json(silent=True)
        if data is None or not isinstance(data, dict):
            return jsonify({
                "success": False,
                "error": "Invalid request: Request body must be a JSON object.",
            }), 400

        required_keys = {"source", "source_id", "content"}
        missing = required_keys - set(data.keys())
        if missing:
            return jsonify({
                "success": False,
                "error": f"Missing required fields for source post: {sorted(list(missing))}",
            }), 400

        source = data.get("source")
        source_id = data.get("source_id")
        content = data.get("content")

        if not isinstance(source, str) or not source.strip():
            return jsonify({
                "success": False,
                "error": "Invalid field: 'source' must be a non-empty string.",
            }), 400

        if not isinstance(source_id, str) or not source_id.strip():
            return jsonify({
                "success": False,
                "error": "Invalid field: 'source_id' must be a non-empty string.",
            }), 400

        if not isinstance(content, str) or not content.strip():
            return jsonify({
                "success": False,
                "error": "Invalid field: 'content' must be a non-empty string.",
            }), 400

        if len(content) > MAX_TEXT_LENGTH:
            return jsonify({
                "success": False,
                "error": f"Input content exceeds maximum allowed length of {MAX_TEXT_LENGTH:,} characters.",
            }), 400

        metadata = data.get("metadata", {})
        if metadata is not None and not isinstance(metadata, dict):
            return jsonify({
                "success": False,
                "error": "Invalid field: 'metadata' must be a dictionary.",
            }), 400

        try:
            normalized_post = NormalizedPost(
                source=source,
                source_id=source_id,
                content=content,
                source_url=data.get("source_url"),
                author_id=data.get("author_id"),
                author_name=data.get("author_name"),
                published_at=data.get("published_at"),
                language=data.get("language"),
                metadata=metadata or {},
            )

            ingest_srv = getattr(current_app, "ingestion_service", app.ingestion_service)
            post_record, is_duplicate = ingest_srv.ingest(normalized_post)

            if is_duplicate:
                return jsonify({
                    "success": True,
                    "duplicate": True,
                    "message": "Source post already exists for this (source, source_id).",
                    "source_post": post_record,
                }), 200

            return jsonify({
                "success": True,
                "duplicate": False,
                "source_post": post_record,
            }), 201

        except ValueError as val_err:
            logger.warning("Validation error in source post ingestion: %s", val_err)
            return jsonify({
                "success": False,
                "error": str(val_err),
            }), 400

        except Exception as exc:
            logger.exception("Unexpected error ingesting source post: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while ingesting the source post.",
            }), 500

    @app.route("/api/source-posts/<source>/<source_id>", methods=["GET"])
    def get_source_post_by_key(source: str, source_id: str) -> Tuple[Response, int]:
        """Retrieve a stored source post by its compound key (source, source_id)."""
        try:
            source_clean = source.strip().lower()
            if source_clean not in SUPPORTED_SOURCES:
                return jsonify({
                    "success": False,
                    "error": f"Unsupported source '{source}'. Supported sources: {sorted(SUPPORTED_SOURCES)}",
                }), 400

            source_srv = getattr(current_app, "source_post_service", app.source_post_service)
            post_record = source_srv.get_by_source_and_id(source_clean, source_id.strip())

            if post_record is None:
                return jsonify({
                    "success": False,
                    "error": f"Source post '{source}/{source_id}' was not found.",
                }), 404

            return jsonify({
                "success": True,
                "source_post": post_record,
            }), 200

        except Exception as exc:
            logger.exception("Unexpected error retrieving source post %s/%s: %s", source, source_id, exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving the source post.",
            }), 500

    @app.route("/api/source-posts", methods=["GET"])
    def list_source_posts_records() -> Tuple[Response, int]:
        """Retrieve bounded list of source posts with optional source and status filters."""
        try:
            limit_str = request.args.get("limit", "50")
            offset_str = request.args.get("offset", "0")
            source_filter = request.args.get("source")
            status_filter = request.args.get("status")

            try:
                limit = int(limit_str)
                offset = int(offset_str)
            except ValueError:
                return jsonify({
                    "success": False,
                    "error": "Query parameters 'limit' and 'offset' must be integers.",
                }), 400

            if limit < 1 or limit > 100 or offset < 0:
                return jsonify({
                    "success": False,
                    "error": "Limit must be between 1 and 100, and offset must be non-negative.",
                }), 400

            if source_filter and str(source_filter).strip().lower() not in SUPPORTED_SOURCES:
                return jsonify({
                    "success": False,
                    "error": f"Unsupported source filter '{source_filter}'. Supported: {sorted(SUPPORTED_SOURCES)}",
                }), 400

            if status_filter and str(status_filter).strip().upper() not in SourcePostStatus.ALL:
                return jsonify({
                    "success": False,
                    "error": f"Invalid status filter '{status_filter}'. Allowed: {sorted(SourcePostStatus.ALL)}",
                }), 400

            source_srv = getattr(current_app, "source_post_service", app.source_post_service)
            posts = source_srv.list_source_posts(
                limit=limit,
                offset=offset,
                source=source_filter,
                status=status_filter,
            )

            return jsonify({
                "success": True,
                "source_posts": posts,
                "count": len(posts),
            }), 200

        except Exception as exc:
            logger.exception("Unexpected error listing source posts: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving source posts.",
            }), 500

    # =========================================================================
    # REST API Routes - Connector Framework & Analysis Pipeline (Stage 6B & 6F)
    # =========================================================================

    @app.route("/api/source-posts/<int:post_id>/analysis-status", methods=["GET"])
    def get_source_post_analysis_status(post_id: int) -> Tuple[Response, int]:
        """Return real-time processing and analysis status for a single source post."""
        try:
            source_srv = getattr(current_app, "source_post_service", app.source_post_service)
            post = source_srv.get_source_post(post_id)
            if not post:
                return jsonify({
                    "success": False,
                    "error": f"Source post with ID {post_id} not found.",
                }), 404

            return jsonify({
                "success": True,
                "source_post_id": post["id"],
                "status": post["status"],
                "attempts": post["analysis_attempts"],
                "incident_id": post.get("incident_id"),
                "processed_at": post.get("processed_at"),
                "last_error": post.get("last_error"),
            }), 200

        except Exception as exc:
            logger.exception("Unexpected error retrieving analysis status for post %s: %s", post_id, exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving analysis status.",
            }), 500

    @app.route("/api/ingestion/status", methods=["GET"])
    def ingestion_status() -> Tuple[Response, int]:
        """Retrieve operational status for the ingestion queue, workers, pipeline, and connectors."""
        try:
            queue_srv = getattr(current_app, "processing_queue", app.processing_queue)
            registry_srv = getattr(current_app, "connector_registry", app.connector_registry)
            worker_srv = getattr(current_app, "processing_worker", app.processing_worker)
            pipeline_srv = getattr(current_app, "analysis_pipeline", app.analysis_pipeline)
            source_srv = getattr(current_app, "source_post_service", app.source_post_service)

            active_workers = 1 if (worker_srv and worker_srv.is_alive()) else 0

            # Gather aggregate source post counts by status
            counts = source_srv.count_by_status() if (source_srv and hasattr(source_srv, "count_by_status")) else {}
            pipeline_metrics = pipeline_srv.get_metrics() if (pipeline_srv and hasattr(pipeline_srv, "get_metrics")) else {}

            total_received = sum(counts.values()) if counts else 0
            analyzed_count = counts.get(SourcePostStatus.ANALYZED, 0)
            skipped_count = counts.get(SourcePostStatus.SKIPPED, 0)
            failed_count = counts.get(SourcePostStatus.FAILED, 0)

            return jsonify({
                "success": True,
                "status": {
                    "queue_size": queue_srv.qsize() if queue_srv else 0,
                    "active_workers": active_workers,
                    "source_posts_received": total_received,
                    "source_posts_analyzed": analyzed_count,
                    "source_posts_skipped": skipped_count,
                    "source_posts_failed": failed_count,
                    "incidents_generated": pipeline_metrics.get("incidents_generated", 0),
                    "analysis_errors": pipeline_metrics.get("analysis_errors", 0),
                    "pipeline_metrics": pipeline_metrics,
                    "registered_sources": registry_srv.list_sources() if registry_srv else [],
                    "connector_states": registry_srv.get_connector_states() if registry_srv else {},
                },
            }), 200

        except Exception as exc:
            logger.exception("Unexpected error retrieving ingestion status: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving ingestion status.",
            }), 500

    @app.route("/api/ingestion/test", methods=["POST"])
    def test_manual_ingestion() -> Tuple[Response, int]:
        """Testing endpoint: Normalizes and ingests manual source post, marks QUEUED, and enqueues to processing queue."""
        if not request.is_json:
            return jsonify({
                "success": False,
                "error": "Invalid request: Content-Type must be 'application/json'.",
            }), 400

        data = request.get_json(silent=True)
        if data is None or not isinstance(data, dict):
            return jsonify({
                "success": False,
                "error": "Invalid request: Request body must be a JSON object.",
            }), 400

        if not data.get("source_id"):
            return jsonify({
                "success": False,
                "error": "Missing required field: 'source_id' is required.",
            }), 400

        if not data.get("content") or not str(data.get("content")).strip():
            return jsonify({
                "success": False,
                "error": "Missing required field: 'content' must be non-empty.",
            }), 400

        try:
            registry_srv = getattr(current_app, "connector_registry", app.connector_registry)
            manual_conn = registry_srv.get("manual") if registry_srv else ManualConnector()
            if manual_conn is None:
                manual_conn = ManualConnector()

            normalized_post = manual_conn.normalize(data)

            ingest_srv = getattr(current_app, "ingestion_service", app.ingestion_service)
            source_srv = getattr(current_app, "source_post_service", app.source_post_service)
            queue_srv = getattr(current_app, "processing_queue", app.processing_queue)

            post_record, is_duplicate = ingest_srv.ingest(normalized_post)
            post_id = post_record["id"]

            enqueued = False
            if not is_duplicate:
                # Update status to QUEUED and push to processing queue
                source_srv.update_status(post_id, SourcePostStatus.QUEUED)
                post_record["status"] = SourcePostStatus.QUEUED
                if queue_srv is not None:
                    enqueued = queue_srv.enqueue(post_id)

                return jsonify({
                    "success": True,
                    "source_post_id": post_id,
                    "enqueued": enqueued,
                    "duplicate": False,
                    "source_post": post_record,
                }), 201
            else:
                return jsonify({
                    "success": True,
                    "source_post_id": post_id,
                    "enqueued": False,
                    "duplicate": True,
                    "message": "Source post already exists for this (source, source_id).",
                    "source_post": post_record,
                }), 200

        except ValueError as val_err:
            logger.warning("Validation error in test ingestion: %s", val_err)
            return jsonify({
                "success": False,
                "error": str(val_err),
            }), 400

        except Exception as exc:
            logger.exception("Unexpected error in test ingestion: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred during test ingestion.",
            }), 500

    # =========================================================================
    # REST API Routes - Live Monitoring & Real-Time SSE Streams (Stage 6G)
    # =========================================================================

    @app.route("/api/live/events", methods=["GET"])
    def live_events_stream():
        """Server-Sent Events (SSE) real-time streaming endpoint."""
        broker = getattr(current_app, "live_broker", app.live_broker)
        if broker is None:
            return jsonify({
                "success": False,
                "error": "Live event streaming is not configured.",
            }), 503

        q = broker.register_listener()
        if q is None:
            return jsonify({
                "success": False,
                "error": "Live event subscriber capacity reached. Please use polling or try again later.",
            }), 503

        def stream_generator():
            try:
                # Send initial state snapshot upon establishing stream
                registry_srv = getattr(current_app, "connector_registry", app.connector_registry)
                queue_srv = getattr(current_app, "processing_queue", app.processing_queue)
                worker_srv = getattr(current_app, "processing_worker", app.processing_worker)
                pipeline_srv = getattr(current_app, "analysis_pipeline", app.analysis_pipeline)
                source_srv = getattr(current_app, "source_post_service", app.source_post_service)

                counts = source_srv.count_by_status() if source_srv else {}
                pipeline_metrics = pipeline_srv.get_metrics() if pipeline_srv else {}

                conn_states = registry_srv.get_connector_states() if registry_srv else {}
                conn_states["worker"] = {
                    "state": "CONNECTED" if (worker_srv and worker_srv.is_alive()) else "PROCESSING",
                    "active_workers": 1 if (worker_srv and worker_srv.is_alive()) else 0,
                }

                initial_data = {
                    "queue_size": queue_srv.qsize() if queue_srv else 0,
                    "active_workers": 1 if (worker_srv and worker_srv.is_alive()) else 0,
                    "source_posts_received": sum(counts.values()) if counts else 0,
                    "source_posts_analyzed": counts.get(SourcePostStatus.ANALYZED, 0),
                    "source_posts_skipped": counts.get(SourcePostStatus.SKIPPED, 0),
                    "source_posts_failed": counts.get(SourcePostStatus.FAILED, 0),
                    "incidents_generated": pipeline_metrics.get("incidents_generated", 0),
                    "analysis_errors": pipeline_metrics.get("analysis_errors", 0),
                    "pipeline_metrics": pipeline_metrics,
                    "connector_states": conn_states,
                    "recent_events": broker.get_recent_events(limit=25),
                }
                yield broker.format_sse_message("initial_state", initial_data)

                # Stream live published events
                while True:
                    try:
                        event_type, payload = q.get(timeout=broker.keepalive_interval)
                        yield broker.format_sse_message(event_type, payload)
                    except queue.Empty:
                        # Yield keepalive heartbeat comment
                        yield broker.format_keepalive()
            except (GeneratorExit, BrokenPipeError, ConnectionResetError):
                logger.debug("SSE client disconnected from stream.")
            finally:
                broker.unregister_listener(q)

        response = Response(stream_generator(), mimetype="text/event-stream")
        response.headers["Cache-Control"] = "no-cache, no-transform"
        response.headers["X-Accel-Buffering"] = "no"
        response.headers["Connection"] = "keep-alive"
        return response

    @app.route("/api/live/feed", methods=["GET"])
    def live_feed():
        """Retrieve bounded recent events with optional source filtering."""
        try:
            broker = getattr(current_app, "live_broker", app.live_broker)
            source_filter = request.args.get("source")
            limit_param = request.args.get("limit", 50)
            try:
                limit = max(1, min(100, int(limit_param)))
            except ValueError:
                limit = 50

            events = broker.get_recent_events(limit=limit, source_filter=source_filter) if broker else []

            # If in-memory broker is empty (e.g. freshly started server), fall back to recent analyzed posts from DB
            if not events:
                try:
                    from database.db import db_session
                    forensic_srv = getattr(current_app, "forensic_service", getattr(app, "forensic_service", None))
                    db_path = forensic_srv.db_path if forensic_srv else None
                    with db_session(db_path) as conn:
                        query = """
                            SELECT sp.id AS source_post_id, sp.source, sp.source_id, sp.source_url,
                                   sp.author_id, sp.author_name, sp.content, sp.status,
                                   sp.processed_at, sp.ingested_at, sp.incident_id,
                                   COALESCE(inc.threat_score, 0.0) AS threat_score,
                                   COALESCE(inc.ai_probability, 0.0) AS ai_probability,
                                   COALESCE(inc.risk_level, 'LOW') AS risk_level,
                                   COALESCE(inc.category, 'Normal') AS category
                            FROM source_posts sp
                            LEFT JOIN incidents inc ON sp.incident_id = inc.incident_id
                            WHERE sp.status = 'ANALYZED'
                        """
                        params = []
                        if source_filter and source_filter.lower() != "all":
                            query += " AND LOWER(sp.source) = ?"
                            params.append(source_filter.lower())
                        query += " ORDER BY sp.id DESC LIMIT ?"
                        params.append(limit)

                        rows = conn.execute(query, params).fetchall()
                        events = [
                            {
                                "type": "source_post",
                                "data": dict(r),
                                "timestamp": r["processed_at"] or r["ingested_at"],
                            }
                            for r in rows
                        ]
                except Exception as db_fallback_err:
                    logger.debug("Database fallback for live feed failed: %s", db_fallback_err)

            return jsonify({
                "success": True,
                "events": events,
                "count": len(events),
            }), 200
        except Exception as exc:
            logger.exception("Error retrieving live feed: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving live feed.",
            }), 500

    @app.route("/api/live/status", methods=["GET"])
    def live_status():
        """Retrieve live broker subscriber metrics, connector states, and pipeline counters."""
        try:
            broker = getattr(current_app, "live_broker", app.live_broker)
            registry_srv = getattr(current_app, "connector_registry", app.connector_registry)
            pipeline_srv = getattr(current_app, "analysis_pipeline", app.analysis_pipeline)
            source_srv = getattr(current_app, "source_post_service", app.source_post_service)
            queue_srv = getattr(current_app, "processing_queue", app.processing_queue)
            worker_srv = getattr(current_app, "processing_worker", app.processing_worker)

            counts = source_srv.count_by_status() if source_srv else {}
            pipeline_metrics = pipeline_srv.get_metrics() if pipeline_srv else {}

            conn_states = registry_srv.get_connector_states() if registry_srv else {}
            conn_states["worker"] = {
                "state": "CONNECTED" if (worker_srv and worker_srv.is_alive()) else "PROCESSING",
                "active_workers": 1 if (worker_srv and worker_srv.is_alive()) else 0,
            }

            return jsonify({
                "success": True,
                "live_status": {
                    "active_subscribers": broker.get_subscriber_count() if broker else 0,
                    "max_subscribers": broker.max_subscribers if broker else 0,
                    "queue_size": queue_srv.qsize() if queue_srv else 0,
                    "active_workers": 1 if (worker_srv and worker_srv.is_alive()) else 0,
                    "source_posts_received": sum(counts.values()) if counts else 0,
                    "source_posts_analyzed": counts.get(SourcePostStatus.ANALYZED, 0),
                    "source_posts_skipped": counts.get(SourcePostStatus.SKIPPED, 0),
                    "source_posts_failed": counts.get(SourcePostStatus.FAILED, 0),
                    "incidents_generated": pipeline_metrics.get("incidents_generated", 0),
                    "analysis_errors": pipeline_metrics.get("analysis_errors", 0),
                    "pipeline_metrics": pipeline_metrics,
                    "connector_states": conn_states,
                }
            }), 200
        except Exception as exc:
            logger.exception("Error retrieving live status: %s", exc)
            return jsonify({
                "success": False,
                "error": "An internal error occurred while retrieving live status.",
            }), 500

    # =========================================================================
    # System Health & Operational Probes (Stage 6H)
    # =========================================================================

    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Evaluate and report operational health of core platform components."""
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {},
            "metrics": {},
        }

        status_code = 200
        is_down = False
        is_degraded = False

        # 1. Application Component
        start_time = getattr(app, "start_time", None)
        uptime = (time.time() - start_time) if start_time else 0.0
        health_data["components"]["application"] = {
            "status": "healthy",
            "uptime_seconds": round(uptime, 2),
            "version": "1.0.0",
            "environment": "testing" if app.config.get("TESTING") else "production",
        }

        # 2. Database Component Probe
        db_status = "healthy"
        db_writable = False
        forensic_srv = getattr(current_app, "forensic_service", getattr(app, "forensic_service", None))
        db_path = forensic_srv.db_path if forensic_srv else None
        try:
            from database.db import db_session
            with db_session(db_path) as conn:
                cursor = conn.execute("SELECT 1;")
                row = cursor.fetchone()
                if row and row[0] == 1:
                    db_writable = True
        except Exception as db_err:
            logger.error("Health probe database check failed: %s", db_err)
            db_status = "down"
            is_down = True

        health_data["components"]["database"] = {
            "status": db_status,
            "writable": db_writable,
            "path": str(db_path) if db_path else "unknown",
        }

        # 3. Workers Component Probe
        worker_srv = getattr(current_app, "processing_worker", getattr(app, "processing_worker", None))
        queue_srv = getattr(current_app, "processing_queue", getattr(app, "processing_queue", None))
        worker_status = "healthy"
        active_workers = 1 if (worker_srv and worker_srv.is_alive()) else 0
        q_size = queue_srv.qsize() if queue_srv else 0
        q_capacity = queue_srv.maxsize if queue_srv else 0

        if queue_srv and q_capacity > 0 and q_size >= q_capacity:
            worker_status = "degraded"
            is_degraded = True

        health_data["components"]["workers"] = {
            "status": worker_status,
            "active_workers": active_workers,
            "queue_size": q_size,
            "queue_capacity": q_capacity,
        }

        # 4. Connectors Component Probe
        registry_srv = getattr(current_app, "connector_registry", getattr(app, "connector_registry", None))
        conn_states = registry_srv.get_connector_states() if registry_srv else {}
        connector_health = "healthy"

        connectors_detail = {}
        for name, st in conn_states.items():
            state_str = str(st.get("status") or st.get("state") or "DISABLED").upper()
            if state_str in ("ERROR", "QUOTA_LIMIT_REACHED"):
                connector_health = "degraded"
                is_degraded = True

            connectors_detail[name] = {
                "state": state_str,
                "enabled": bool(st.get("enabled", False)),
                "connection_errors": int(st.get("connection_errors", 0)),
            }

        health_data["components"]["connectors"] = {
            "status": connector_health,
            "sources": connectors_detail,
        }

        # 5. Operational Metrics
        pipeline_srv = getattr(current_app, "analysis_pipeline", getattr(app, "analysis_pipeline", None))
        source_srv = getattr(current_app, "source_post_service", getattr(app, "source_post_service", None))
        counts = source_srv.count_by_status() if source_srv else {}
        pipeline_metrics = pipeline_srv.get_metrics() if pipeline_srv else {}

        health_data["metrics"] = {
            "source_posts_received": sum(counts.values()) if counts else 0,
            "source_posts_analyzed": counts.get(SourcePostStatus.ANALYZED, 0),
            "source_posts_failed": counts.get(SourcePostStatus.FAILED, 0),
            "incidents_generated": pipeline_metrics.get("incidents_generated", 0),
        }

        # Overall Status Determination
        if is_down:
            health_data["status"] = "down"
            status_code = 503
        elif is_degraded:
            health_data["status"] = "degraded"
            status_code = 200
        else:
            health_data["status"] = "healthy"
            status_code = 200

        return jsonify(health_data), status_code

    # =========================================================================
    # Error Handlers
    # =========================================================================

    @app.errorhandler(404)
    def handle_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Endpoint not found."}), 404
        return render_template("index.html"), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(e):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Method not allowed for this endpoint."}), 405
        return "Method Not Allowed", 405

    return app


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    try:
        application = create_app()
        port = int(os.environ.get("PORT", 5000))
        debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")

        # Graceful Shutdown Signal Handlers
        def shutdown_handler(signum, frame):
            print("\n[SHUTDOWN] Shutting down AIShield gracefully...")
            if hasattr(application, "connector_registry"):
                application.connector_registry.disconnect_all()
            if hasattr(application, "processing_worker"):
                application.processing_worker.stop(timeout=2.0)
            if hasattr(application, "live_broker"):
                application.live_broker.clear()
            print("[SHUTDOWN] All background workers and streams closed.")
            sys.exit(0)

        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)

        print("=" * 64)
        print(" AIShield - AI Detection & Digital Forensics Platform")
        print(f" Server running at: http://127.0.0.1:{port}")
        print("=" * 64)

        application.run(host="127.0.0.1", port=port, debug=debug_mode)
    except Exception as e:
        logger.critical("Fatal startup failure: %s", e)
        sys.exit(1)

