# AIShield — AI Detection, Threat Analysis, Digital Forensics, Threat Intelligence & Relationship Graph Platform

**AIShield** is an educational machine learning, threat analysis, digital forensics, threat intelligence, and relationship graph platform. This repository contains the complete, self-contained implementation of:
- **Module 1: AI-Generated Content Detection**
- **Module 2: Threat Analysis & Risk Scoring**
- **Module 3: Digital Forensics & Incident Records**
- **Module 4: Threat Intelligence & Investigation Dashboard**
- **Module 5: Threat Relationship Graph & Campaign Detection**

---

## Overview & Architecture

```
AIShield/
├── app.py                      # Flask web application & REST API routes (Modules 1–5)
├── requirements.txt            # Dependencies (Flask, pandas, scikit-learn, joblib, networkx, pytest)
├── README.md                   # Complete architectural and API documentation
├── .gitignore                  # Git ignore rules for caches, artifacts, and SQLite database
├── data/
│   └── dataset.csv             # Module 1 demonstration dataset (0=Human, 1=AI)
├── database/
│   ├── __init__.py             # Database package exports
│   ├── db.py                   # SQLite connection manager & auto-migration
│   └── ai_shield.db            # SQLite database file (auto-generated on startup)
├── models/
│   ├── __init__.py             # Exports AIDetector
│   ├── detector.py             # AIDetector: TF-IDF + Logistic Regression ML Pipeline
│   ├── detector_model.joblib   # Trained pipeline artifact (auto-generated on startup)
│   └── evaluation_report.json  # Held-out evaluation report & confusion matrix
├── services/
│   ├── __init__.py             # Exports ForensicService, IntelligenceService, TextAnalyzer, ThreatAnalyzer, ThreatGraphService
│   ├── forensic_service.py     # ForensicService: SQLite persistence, SHA-256 fingerprinting & integrity
│   ├── intelligence_service.py # IntelligenceService: Read-only analytics, distributions & multi-filter search
│   ├── text_analyzer.py        # TextAnalyzer: 10 structural & linguistic metrics
│   ├── threat_analyzer.py      # ThreatAnalyzer: Heuristic threat analysis & risk scoring
│   └── graph_service.py        # ThreatGraphService: Text similarity matrix, NetworkX graph & campaigns
├── templates/
│   ├── index.html              # Primary analysis interface with Save Incident action
│   ├── incidents.html          # Incident history table view
│   ├── incident_detail.html    # Detailed immutable forensic snapshot inspection page
│   ├── dashboard.html          # Threat intelligence analytics & investigation dashboard
│   └── graph.html              # Threat relationship graph & campaign detection workspace
├── static/
│   ├── css/
│   │   ├── style.css           # Modern theme styling & dynamic meters
│   │   ├── incidents.css       # Incident history, snapshot cards & verification badges
│   │   ├── dashboard.css       # Dashboard analytics grid, cards & search layout
│   │   └── graph.css           # Relationship graph canvas, toolbar & campaign cards
│   └── js/
│       ├── app.js              # Real-time counter, async fetch, XSS-safe DOM rendering
│       ├── incidents.js        # History table loader & cryptographic verification controller
│       ├── dashboard.js        # Chart.js analytics visualizations & search pagination controller
│       └── graph.js            # vis-network graph visualization & threshold controller
└── tests/
    ├── __init__.py             # Test package
    ├── test_detector.py        # Unit tests for ML detector pipeline & evaluation
    ├── test_text_analyzer.py   # Unit tests for text analyzer service
    ├── test_threat_analyzer.py # Unit tests for ThreatAnalyzer & risk scoring
    ├── test_forensics.py       # Unit tests for ForensicService, SQLite, & SHA-256 integrity
    ├── test_intelligence.py    # Unit tests for IntelligenceService analytics & search
    ├── test_graph.py           # Unit tests for ThreatGraphService & campaigns
    └── test_api.py             # Integration tests for Flask endpoints & error contracts
```

---

## Module 1 — AI-Generated Content Detection

### Architecture & Approach
Module 1 employs a classical, explainable machine learning approach for text classification:
- **Feature Extraction**: `TfidfVectorizer(max_features=5000, ngram_range=(1, 2), sublinear_tf=True)`
- **Classifier**: `LogisticRegression(C=1.0, max_iter=1000, random_state=42)`
- **Text Preprocessing**: Normalizes unicode whitespace while preserving structural characteristics.
- **Structural Text Statistics**: Computes 10 linguistic metrics:
  - Character count, word count, sentence count
  - Average word length, average sentence length
  - Vocabulary richness (Type-Token Ratio)
  - Punctuation count and exclamation count
  - Repeated word patterns and capital word frequency

---

## Module 2 — Threat Analysis & Risk Scoring

### Threat Indicators & Categories
Module 2 analyzes submitted text and integrates Module 1's detection probability:
- **Heuristic Indicators**: Identifies urgency phrases, manipulation cues, call-to-action prompts, unverified claim markers, and authority impersonation patterns with sentence-level negation suppression.
- **Content Categories**: Maps text to 7 distinct threat categories: `Normal`, `Phishing`, `Disinformation`, `Manipulation`, `Propaganda`, `Spam`, or `Other`.
- **Deterministic Threat Score Formula**:
  $$\text{Threat Score} = (0.35 \times \text{AI Likelihood}) + (0.20 \times \text{Urgency}) + (0.15 \times \text{Manipulation}) + (0.10 \times \text{CTA}) + (0.10 \times \text{Unverified Claims}) + (0.05 \times \text{Authority}) + (0.05 \times \text{Category Severity})$$
- **Risk Levels**:
  - `0–29.99`: **LOW**
  - `30–59.99`: **MEDIUM**
  - `60–79.99`: **HIGH**
  - `80–100.0`: **CRITICAL**

---

## Module 3 — Digital Forensics & Incident Records

### Forensic Architecture
- **Cryptographic Fingerprinting**: Computes exact SHA-256 hashes over unaltered raw UTF-8 input bytes.
- **Immutable Snapshots**: Stores complete snapshots of predictions, text metrics, and threat scores in SQLite (`database/ai_shield.db`).
- **Integrity Verification**: `POST /api/incidents/<id>/verify` dynamically verifies stored content against the recorded SHA-256 fingerprint.

---

## Module 4 — Threat Intelligence & Investigation Dashboard

### Analytics Engine
- **Read-Only Summaries**: Calculates total incidents, high-risk counts, critical-risk counts, AI vs. Human breakdown, and average threat score using SQLite aggregations (`COUNT`, `AVG`, `SUM(CASE...)`).
- **Visual Distributions**: Chart.js visualizations for risk tiers, threat categories, AI origin ratios, and daily UTC trends.
- **Investigation Workspace**: Multi-filter search supporting `q`, `risk_level`, `category`, `ai_label`, `min_score`, `max_score`, `from_date`, `to_date`, allowlisted sorting (`SORT_ALLOWLIST`), and bounded pagination (1 to 100).

---

## Module 5 — Threat Relationship Graph & Campaign Detection

### Architecture & Approach
Module 5 provides practical, explainable, and deterministic threat graph analytics over the existing stored SQLite incidents (bounded to the most recent 500 incidents).
- **Text Similarity Engine**: Preprocesses text (whitespace and case normalization) and uses scikit-learn's `TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)` and `cosine_similarity`.
- **Relationship Graph**: Builds an undirected `NetworkX` graph with incidents as nodes and pairwise similarity edges whenever `similarity >= threshold` (default `0.65`, configurable between `0.50` and `0.95`).
- **Cluster & Campaign Detection**: Uses NetworkX connected components to detect clusters (>= 2 incidents) and potential coordinated campaigns (>= 3 incidents).
- **Campaign Metrics & Risk Formula**: Calculates cluster cohesion (0–100%), average similarity, duration in hours, primary category, and campaign risk score:
  $$\text{Campaign Risk} = (0.50 \times \text{Avg Threat Score}) + (0.30 \times (\text{Avg AI Prob} \times 100)) + (0.20 \times \text{Cluster Cohesion})$$

### Important Limitations
> [!IMPORTANT]
> A relationship or text similarity does **NOT** prove:
> - Common authorship
> - Malicious coordination
> - Real-world threat actor attribution
> - Social-media propagation or bot activity
> 
> This is an educational analytic prototype. The system detects text content similarity and derived graph clusters, not confirmed coordinated operations.

---

## Installation & Setup

### 1. Prerequisites
- **Python 3.9+** (Tested on Python 3.12)
- **pip** package manager

### 2. Setup Virtual Environment
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1   # On Windows
# or: source venv/bin/activate # On Linux/macOS
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Running the Application

```bash
python app.py
```

- **Analyzer Interface**: `http://127.0.0.1:5000/`
- **Incident History**: `http://127.0.0.1:5000/incidents`
- **Incident Detail**: `http://127.0.0.1:5000/incidents/<incident_id>`
- **Threat Dashboard**: `http://127.0.0.1:5000/dashboard`
- **Relationship Graph**: `http://127.0.0.1:5000/graph`

---

## Running the Test Suite

Execute the complete automated test suite:
```bash
pytest -q
```

Or for verbose test logging:
```bash
pytest -v
```

---

---

## Stage 6A — Real-Time Ingestion Foundation

### Architecture & Separation of Concerns

Stage 6A introduces a clean, normalized representation for externally sourced content:

```
External Source (Bluesky, Mastodon, YouTube, Manual)
    ↓
IngestionService (Validate, Normalize HTML/Text, Check Supported Source)
    ↓
Deduplication Engine (Level 1: source + source_id, Level 2: content_hash)
    ↓
SourcePostService (SQLite Persistence: source_posts table)
    ↓
Status Lifecycle (RECEIVED → QUEUED → PROCESSING → ANALYZED / SKIPPED / FAILED)
    ↓
[Future Stage: Threat Analysis Pipeline] → Incident Created (Only if appropriate)
```

> [!IMPORTANT]
> **Source Post vs. Incident**:
> - A **Source Post** is raw incoming external content from platforms (Bluesky, Mastodon, YouTube, Manual).
> - An **Incident** is a permanent, analyzed forensic record created by AIShield's threat analysis pipeline.
> - **Not every source post is an incident**: Raw incoming data is ingested, normalized, and deduplicated. It only becomes an incident if subsequent analysis determines that it poses a threat or warrants forensic recording.

### Core Design & Capabilities

1. **Source Provenance & Two-Level Deduplication**:
   - **Level 1 (`source + source_id`)**: Strictly enforced uniqueness via unique SQLite index. Submitting the identical item from the same source returns the existing record (`duplicate: true`) without creating duplicate rows.
   - **Level 2 (`content_hash`)**: Cross-source duplicates (identical text published across different platforms or accounts) are indexed via SHA-256 content hashes, enabling multi-platform tracking while preserving source provenance.
2. **Forensic Content Hashing**:
   - Computes deterministic SHA-256 over exact UTF-8 content bytes prior to any destructive transformations.
3. **HTML-to-Text Normalization**:
   - Converts rich HTML content (e.g. Mastodon status updates) into clean plain text for downstream analysis while retaining the unaltered raw payload inside `metadata_json`.
4. **Explicit Status Lifecycle**:
   - `RECEIVED` $\rightarrow$ `QUEUED` $\rightarrow$ `PROCESSING` $\rightarrow$ `ANALYZED` / `SKIPPED` / `FAILED`
   - Tracks `analysis_attempts`, `last_error`, and `processed_at` timestamp.
5. **No External Network Connectors Yet**:
   - This stage establishes the foundation and data model. Direct live streaming connectors will be implemented in subsequent stages.

---

## REST API Specification

### 1. Text Analysis (`POST /api/analyze`)
Analyzes text for AI probability, structural statistics, and threat indicators.

### 2. Create Incident Record (`POST /api/incidents`)
Persists an analysis result as an immutable forensic record (`HTTP 201 Created`).

### 3. List Incidents (`GET /api/incidents`)
Retrieves summary records ordered newest first (supports `?limit=50&offset=0`).

### 4. Get Single Incident Snapshot (`GET /api/incidents/<incident_id>`)
Retrieves the complete stored forensic snapshot without recalculating any values.

### 5. Verify Cryptographic Integrity (`POST /api/incidents/<incident_id>/verify`)
Recalculates the SHA-256 fingerprint from stored content and compares it against `content_hash`.

### 6. Dashboard Summary (`GET /api/dashboard/summary`)
Returns aggregated incident statistics (`total_incidents`, `high_risk`, `critical_risk`, `ai_generated`, `human`, `average_threat_score`).

### 7. Dashboard Distributions (`GET /api/dashboard/distribution`)
Returns risk level, category, and AI classification breakdowns.

### 8. Threat Activity Trend (`GET /api/dashboard/trend`)
Returns daily UTC time-series trend of incident count and average threat score.

### 9. Multi-Filter Incident Search (`GET /api/dashboard/incidents`)
Search, filter, sort, and paginate stored incident records (`q`, `risk_level`, `category`, `ai_label`, `min_score`, `max_score`, `from_date`, `to_date`, `sort`, `order`, `page`, `page_size`).

### 10. Threat Relationship Graph (`GET /api/graph`)
Returns undirected graph nodes, similarity edges, connected clusters, and campaigns (supports `?threshold=0.65`).

### 11. List Potential Campaigns (`GET /api/campaigns`)
Returns detected potential campaigns with campaign metrics and incident lists.

### 12. Single Campaign Detail (`GET /api/campaigns/<campaign_id>`)
Returns detailed summary for a specific deterministic campaign ID (`CAMP-001`).

### 13. Ingest Source Post (`POST /api/source-posts`)
Ingests a normalized external source post (`HTTP 201 Created` for new posts, `HTTP 200 OK` with `duplicate: true` for existing posts).

### 14. Get Source Post by Key (`GET /api/source-posts/<source>/<source_id>`)
Retrieves a specific source post by its compound natural key.

### 15. List Source Posts (`GET /api/source-posts`)
Retrieves bounded list of source posts (supports `?limit=50&offset=0&source=bluesky&status=RECEIVED`).

### 16. Ingestion Status & Observability (`GET /api/ingestion/status`)
Retrieves queue depth, active worker counts, registered sources, and live connector observability states.

### 17. Manual Test Ingestion (`POST /api/ingestion/test`)
Testing endpoint that normalizes manual test payloads, creates source posts, transitions status to `QUEUED`, and enqueues to the processing queue.

---

## Stage 6B — Connector Framework & Processing Queue

### Operational Architecture
- **Base Connector**: Abstract interface (`BaseConnector`) standardizing connector lifecycle (`connect`, `disconnect`, `is_running`) and output structure (`NormalizedPost`).
- **Processing Queue**: Thread-safe bounded in-memory FIFO queue storing lightweight `source_post_id` references with in-flight duplicate enqueue suppression.
- **Worker & Safe Retries**: Background worker claims items (`PROCESSING`), increments `analysis_attempts`, re-enqueues on retryable failure (`attempts < 3`), and marks `FAILED` with sanitized error messages when attempts reach 3.

---

## Stage 6C — Real Bluesky Live Connector

### Overview & Architecture
Stage 6C integrates the official Bluesky-compatible Jetstream WebSocket public stream (`wantedCollections=app.bsky.feed.post`).

```
Bluesky Jetstream (wss://jetstream1.us-east.bsky.network/subscribe)
    ↓
BlueskyConnector (Background Daemon Thread, WebSocket Keepalive Ping/Pong)
    ↓
Filter & Normalize (kind=="commit", operation=="create", collection=="app.bsky.feed.post")
    ↓
IngestionService & SourcePostService (SQLite deduplication on source + source_id)
    ↓
ProcessingQueue (source_post_id) [Backpressure drop counters if queue full]
    ↓
ProcessingWorker (Executes lifecycle and retry handling)
```

### Enabling / Disabling Bluesky Ingestion

By default, Bluesky ingestion is disabled (`BLUESKY_ENABLED=false`) so the platform starts cleanly without network credentials or external connections.

To enable Bluesky live ingestion:
```bash
# Set environment variable
export BLUESKY_ENABLED=true
# Or on Windows PowerShell:
$env:BLUESKY_ENABLED="true"

# Optionally customize Jetstream WebSocket URL:
export BLUESKY_JETSTREAM_URL="wss://jetstream1.us-east.bsky.network/subscribe?wantedCollections=app.bsky.feed.post"

# Start AIShield
python app.py
```

To disable:
```bash
export BLUESKY_ENABLED=false
# Or on Windows PowerShell:
$env:BLUESKY_ENABLED="false"
```

### Configuration Parameters
- `BLUESKY_ENABLED`: `false` (default) or `true`
- `BLUESKY_JETSTREAM_URL`: `wss://jetstream1.us-east.bsky.network/subscribe?wantedCollections=app.bsky.feed.post`
- `BLUESKY_RECONNECT_INITIAL_BACKOFF`: `1.0` seconds
- `BLUESKY_RECONNECT_MAX_BACKOFF`: `30.0` seconds
- `BLUESKY_PING_INTERVAL`: `20.0` seconds
- `BLUESKY_PING_TIMEOUT`: `10.0` seconds

### Reconnect & Exponential Backoff Behavior
When a network glitch or remote server disconnection occurs:
1. Reconnect backoff begins at `1.0s` and doubles on consecutive errors (`1s`, `2s`, `4s`, `8s`, `16s`, capped at `30s`).
2. The connector uses an interruptible wait event allowing immediate clean shutdown without hanging.
3. Upon a successful, stable connection, the backoff automatically resets to `1.0s`.

### Backpressure & Queue Safety
To prevent unbounded memory accumulation:
- If `ProcessingQueue` reaches maximum capacity (`QUEUE_MAX_SIZE`), incoming events increment `events_dropped` without crashing or blocking.
- Metrics are tracked live in `/api/ingestion/status`:
  - `events_received`
  - `events_accepted`
  - `events_deduplicated`
  - `events_dropped`
  - `connection_errors`

### Data Stored, Privacy & Provenance Limitations
- **Stored Fields**: `source="bluesky"`, `source_id="did:plc:.../rkey"`, `source_url="https://bsky.app/profile/.../post/..."`, `author_id="did:plc:..."`, `content`, `published_at`, `language`, `metadata` (`cid`, `rev`, `langs`, `time_us`).
- **Privacy & Scope**:
  - Only public post creation commits published to public Jetstream relays are processed.
  - No private accounts, direct messages, or password-authenticated endpoints are accessed.
  - Deletes and non-post events (likes, follows, reposts) are ignored.

---

## Stage 6D — Real Mastodon Live Connector

### Overview & Architecture
Stage 6D integrates the official Mastodon Streaming API (Server-Sent Events / HTTP chunked stream) supporting hashtag and public streams.

```
Mastodon Streaming API (GET /api/v1/streaming/hashtag?tag=security)
    ↓
MastodonConnector (Background Daemon HTTP SSE Loop, Bearer Auth Header)
    ↓
Filter & Safety (Event=="update", Visibility=="public"|"unlisted", Ignore deletes/heartbeats)
    ↓
HTML Extraction (Safe plain text for AI, raw HTML preserved in metadata)
    ↓
NormalizedPost (source="mastodon", source_id, author_id, author_name, content, metadata)
    ↓
IngestionService & SourcePostService (Level 1 deduplication on source + source_id)
    ↓
ProcessingQueue (source_post_id) [Backpressure drop counters if queue full]
    ↓
ProcessingWorker (Executes lifecycle and retry handling)
```

### Enabling / Disabling Mastodon Ingestion

By default, Mastodon ingestion is disabled (`MASTODON_ENABLED=false`).

To enable Mastodon live ingestion:
```bash
# Enable connector
export MASTODON_ENABLED=true
# Or on Windows PowerShell:
$env:MASTODON_ENABLED="true"

# Configure instance and optional access token:
export MASTODON_BASE_URL="https://mastodon.social"
export MASTODON_ACCESS_TOKEN="your_mastodon_bearer_token"
export MASTODON_STREAM_MODE="hashtag"
export MASTODON_HASHTAGS="security,cybersecurity,infosec"

# Start AIShield
python app.py
```

To disable:
```bash
export MASTODON_ENABLED=false
# Or on Windows PowerShell:
$env:MASTODON_ENABLED="false"
```

### Obtaining & Configuring a Legitimate Mastodon Access Token
1. Log into your Mastodon account on your target instance (e.g. `mastodon.social`, `infosec.exchange`).
2. Navigate to **Preferences $\rightarrow$ Development $\rightarrow$ New Application**.
3. Grant `read:statuses` permission scope.
4. Copy the generated **Access Token** and set it to `MASTODON_ACCESS_TOKEN`.
5. Note: AIShield never logs or exposes access tokens through REST APIs or stdout.

### Configuration Parameters
- `MASTODON_ENABLED`: `false` (default) or `true`
- `MASTODON_BASE_URL`: `https://mastodon.social` (default instance URL)
- `MASTODON_ACCESS_TOKEN`: Bearer token for authenticated instance streaming
- `MASTODON_STREAM_MODE`: `"hashtag"` (default) or `"public"`
- `MASTODON_HASHTAGS`: Comma-separated list of monitored hashtags (e.g. `security,cybersecurity,infosec`)
- `MASTODON_RECONNECT_INITIAL_BACKOFF`: `1.0` seconds
- `MASTODON_RECONNECT_MAX_BACKOFF`: `30.0` seconds

### HTML Normalization & Forensic Integrity
- Mastodon status updates contain rich HTML tags (`<p>`, `<a>`, `<br>`).
- AIShield safely converts these tags into clean, human-readable plain text for AI threat detection.
- The original raw HTML is preserved untouched in `metadata_json["raw_html"]` and canonical forensic hashes are computed consistently with Stage 6A data model rules.

### Privacy & Access Controls
- Strictly processes `public` and `unlisted` status updates.
- Statuses marked `private` (followers-only) or `direct` (direct messages) are strictly ignored and discarded.
- Deletes, heartbeat `:thump` comments, and non-status events are ignored.

---

## Stage 6E — Real YouTube Keyword Polling Connector

### Overview & Architecture
Stage 6E integrates the official YouTube Data API v3 (`search.list` endpoint) to poll for newly published videos matching configured threat and disinformation search queries.

```
YouTube Data API v3 (GET https://www.googleapis.com/youtube/v3/search?part=snippet&q=...)
    ↓
YouTubeConnector (Background Thread, Polling Interval, Local Daily Quota Limit Counter)
    ↓
Filter & Normalize (Kind=="youtube#video", Extract Title + Description, Channel metadata)
    ↓
NormalizedPost (source="youtube", source_id=video_id, source_url, author_id, content, metadata)
    ↓
IngestionService & SourcePostService (Level 1 deduplication on source + video_id)
    ↓
ProcessingQueue (source_post_id) [Backpressure drop counters if queue full]
    ↓
ProcessingWorker (Executes lifecycle and retry handling)
```

### Enabling / Disabling YouTube Ingestion

By default, YouTube ingestion is disabled (`YOUTUBE_ENABLED=false`).

To enable YouTube live ingestion:
```bash
# Enable connector
export YOUTUBE_ENABLED=true
# Or on Windows PowerShell:
$env:YOUTUBE_ENABLED="true"

# Configure API Key and monitored search queries:
export YOUTUBE_API_KEY="your_google_cloud_youtube_api_key"
export YOUTUBE_QUERIES="cybersecurity threat,disinformation campaign,phishing attack"
export YOUTUBE_POLL_INTERVAL_SECONDS=300
export YOUTUBE_MAX_REQUESTS_PER_DAY=100

# Start AIShield
python app.py
```

To disable:
```bash
export YOUTUBE_ENABLED=false
# Or on Windows PowerShell:
$env:YOUTUBE_ENABLED="false"
```

### Google Cloud API Setup
1. Create a project in the [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the **YouTube Data API v3** in the API Library.
3. Generate an API Key under **Credentials**.
4. Set the key to environment variable `YOUTUBE_API_KEY`.
5. AIShield never prints or exposes API keys through REST APIs or stdout.

### Configuration Parameters
- `YOUTUBE_ENABLED`: `false` (default) or `true`
- `YOUTUBE_API_KEY`: API key for YouTube Data API v3
- `YOUTUBE_QUERIES`: Comma-separated search queries (e.g. `cybersecurity threat,disinformation campaign,phishing attack`)
- `YOUTUBE_REGION_CODE`: Optional 2-letter country code (default `US`)
- `YOUTUBE_LANGUAGE`: Optional ISO 639-1 language code (default `en`)
- `YOUTUBE_POLL_INTERVAL_SECONDS`: Periodic interval between search sweeps (default `300`s / 5 minutes)
- `YOUTUBE_MAX_RESULTS`: Search results requested per query (default `10`, max 50)
- `YOUTUBE_MAX_REQUESTS_PER_DAY`: Application-side daily request ceiling (default `100` requests/day)

### Quota Safety & Rate Limits
- To protect against unexpected API consumption or runaway costs, AIShield implements an internal daily request counter.
- When `requests_today >= YOUTUBE_MAX_REQUESTS_PER_DAY`:
  - Polling halts immediately.
  - Connector state transitions to `QUOTA_LIMIT_REACHED`.
  - The counter resets automatically at 00:00 UTC.
- When remote HTTP 403 quota errors occur, polling pauses gracefully without crashing.

### Data Normalization & Forensic Integrity
- `source = "youtube"`
- `source_id = videoId`
- `source_url = f"https://www.youtube.com/watch?v={videoId}"`
- `content = f"{title}\n\n{description}"` (HTML entities unescaped safely)
- `author_id = channelId`
- `author_name = channelTitle`
- `metadata = { "videoId", "channelId", "channelTitle", "title", "description", "thumbnail_url", "publishedAt" }`

---

## Stage 6F — Automatic Real-Time Analysis Pipeline

### Overview & Architecture
Stage 6F introduces the centralized orchestration pipeline that connects incoming ingested content (`source_posts`) with the analysis engines (Modules 1–2) and automated cryptographic incident creation (Module 3).

```
External / Live Ingestion (Bluesky, Mastodon, YouTube, Manual)
    ↓
source_posts Table (Level 1 deduplication, content_hash)
    ↓
ProcessingQueue (source_post_id)
    ↓
ProcessingWorker (Daemon Thread Pool, Max 3 attempts)
    ↓
AnalysisPipeline.process_source_post(source_post_id)
    ├── Step 1: Atomic claim -> Status PROCESSING
    ├── Step 2: Module 1 AI Detection (AIDetector.predict) & Linguistic Metrics (TextAnalyzer.analyze)
    ├── Step 3: Module 2 Threat Analysis & Risk Scoring (ThreatAnalyzer.analyze)
    ├── Step 4: Centralized IncidentPolicy.evaluate()
    └── Step 5: Decision Branch
          ├── IF INCIDENT REQUIRED:
          │     - Create immutable snapshot via ForensicService.create_incident()
          │     - Store source_post_id in incidents table
          │     - Store incident_id in source_posts table
          │     - Set status = ANALYZED, processed_at = UTC timestamp
          └── IF NO INCIDENT REQUIRED:
                - Set incident_id = NULL
                - Set status = ANALYZED, processed_at = UTC timestamp
```

### Centralized Incident Policy
To avoid flooding the forensic repository with benign conversational records, `IncidentPolicy` enforces deterministic decision criteria:
- **Rule 1 (High/Critical Risk)**: `risk_level in ("HIGH", "CRITICAL")`
- **Rule 2 (Primary Threat Score)**: `threat_score >= AISHIELD_INCIDENT_MIN_THREAT_SCORE` (default `60.0`)
- **Rule 3 (AI + Secondary Threat Score)**: `ai_probability >= AISHIELD_INCIDENT_MIN_AI_PROB` (default `0.85`) AND `threat_score >= AISHIELD_INCIDENT_SEC_THREAT_SCORE` (default `40.0`)

### Idempotency & Database Linking
- **Bidirectional Linking**:
  - `incidents.source_post_id` $\rightarrow$ Foreign key reference to `source_posts.id` (Nullable, NULL for manual direct incidents).
  - `source_posts.incident_id` $\rightarrow$ Reference to created `incidents.incident_id` (Nullable, NULL for low-risk analyzed posts).
- **Duplicate Protection**:
  - Re-evaluating an already `ANALYZED` post returns the existing incident ID without generating duplicate incident rows.
  - Workers verify database state before creation to avoid race conditions.

### REST API Endpoints

#### 1. Ingestion Status (`GET /api/ingestion/status`)
Returns real-time queue depth, active worker threads, and aggregate post lifecycle metrics:
```json
{
  "success": true,
  "status": {
    "queue_size": 0,
    "active_workers": 1,
    "source_posts_received": 145,
    "source_posts_analyzed": 140,
    "source_posts_skipped": 0,
    "source_posts_failed": 5,
    "incidents_generated": 32,
    "analysis_errors": 0,
    "pipeline_metrics": {
      "posts_analyzed": 140,
      "incidents_generated": 32,
      "posts_skipped_incident": 108,
      "analysis_errors": 0,
      "retries_attempted": 0
    },
    "registered_sources": ["bluesky", "manual", "mastodon", "youtube"],
    "connector_states": { ... }
  }
}
```

#### 2. Source Post Analysis Status (`GET /api/source-posts/<id>/analysis-status`)
Returns the processing lifecycle state for a specific source post:
```json
{
  "success": true,
  "source_post_id": 42,
  "status": "ANALYZED",
  "attempts": 1,
  "incident_id": "INC-a1b2c3d4-e5f6-7890",
  "processed_at": "2026-08-18T12:00:00Z",
  "last_error": null
}
```

---

## Stage 6G — Live Monitoring Dashboard

### Overview & Architecture
Stage 6G delivers a real-time operational dashboard (`/live`) providing live telemetry, connection cards for all ingestion adapters, a bounded real-time event feed, and instantaneous high-risk incident alerts powered by Server-Sent Events (SSE).

```
Pipeline / Ingestion Events
    ↓
LiveEventBroker (services/live_broker.py)
    ├── Thread-safe Subscriber Queue Management (max 25 subscribers)
    ├── Bounded Recent Cache (deque maxlen=100)
    └── Formats text/event-stream frames & keepalive comments
    ↓
GET /api/live/events (SSE Stream)  ←── Fallback ──→  GET /api/live/status & GET /api/live/feed
    ↓
Frontend Dashboard (templates/live.html, static/css/live.css, static/js/live.js)
    ├── Connection Status Cards (Bluesky, Mastodon, YouTube, Worker)
    ├── 10 Real-Time Metrics (Received, Deduplicated, Queued, Analyzed, Incidents...)
    ├── High-Risk Incident Alert Banner (HIGH/CRITICAL events with [View Incident])
    ├── Live Feed Table with Source Filters (All, Bluesky, Mastodon, YouTube, Manual)
    └── Strict DOM Safety (No innerHTML for untrusted source content)
```

### Endpoints
- `GET /live`: Renders the live monitoring single-page dashboard.
- `GET /api/live/events`: Streaming SSE endpoint (`text/event-stream`) broadcasting `initial_state`, `source_post`, `incident_alert`, and `: keepalive`.
- `GET /api/live/feed?source=<src>&limit=<50>`: Bounded recent event retrieval with source filtering.
- `GET /api/live/status`: Summary of active SSE subscribers, pipeline metrics, and connector states.

### Safe DOM & Security Standards
- Untrusted content (`post.content`, `author_name`, `source_id`) is strictly bound using `document.createElement()`, `element.textContent`, and safe DOM methods.
- Zero credential exposure: API tokens and private keys are never included in SSE events or REST endpoints.

---

## Stage 6H — Production Hardening & Reliability

### System Health Probe (`GET /api/health`)
AIShield provides a comprehensive operational probe verifying core subsystems:
```json
{
  "status": "healthy",
  "timestamp": "2026-08-18T12:00:00Z",
  "components": {
    "application": {
      "status": "healthy",
      "uptime_seconds": 3600.5,
      "version": "1.0.0",
      "environment": "production"
    },
    "database": {
      "status": "healthy",
      "writable": true,
      "path": "database/ai_shield.db"
    },
    "workers": {
      "status": "healthy",
      "active_workers": 1,
      "queue_size": 0,
      "queue_capacity": 1000
    },
    "connectors": {
      "status": "healthy",
      "sources": {
        "bluesky": { "state": "DISABLED", "enabled": false, "connection_errors": 0 },
        "mastodon": { "state": "DISABLED", "enabled": false, "connection_errors": 0 },
        "youtube": { "state": "DISABLED", "enabled": false, "connection_errors": 0 },
        "manual": { "state": "AVAILABLE", "enabled": true, "connection_errors": 0 }
      }
    }
  },
  "metrics": {
    "source_posts_received": 150,
    "source_posts_analyzed": 145,
    "source_posts_failed": 5,
    "incidents_generated": 35
  }
}
```

### Reliability & Resiliency Guarantees
1. **Zero Credential Exposure**: Automatic regex redaction (`sanitize_error_message`) scrubs bearer tokens, API keys, and passwords from logs and databases.
2. **Connector Failure Isolation**: Network or auth disconnects in one stream adapter (e.g. Bluesky) do not affect others (Mastodon, YouTube) or pipeline workers.
3. **Worker Crash Isolation**: Unhandled exceptions during single-post analysis increment retry counters, log sanitized errors, and permit uninterrupted execution of subsequent queue items.
4. **Bounded Queue & Backpressure**: Configurable queue capacities prevent memory leaks, with drop counters incremented on queue saturation.
5. **Clean Graceful Shutdown**: `SIGINT` (Ctrl+C) and `SIGTERM` signals trigger `disconnect_all()`, thread joins, and SSE subscriber cleanup with zero zombie threads.

---

---

## Stage 7 — Graph Neural Network (GNN) Threat Cluster Analysis

### Overview & Architecture
Stage 7 introduces learned graph representation learning operating on top of the deterministic Module 5 NetworkX relationship graph.

```
Deterministic Incident Graph (Module 5: TF-IDF + Cosine Similarity)
    ↓
30-Dimensional Feature Extraction (Forensic metrics, text stats, graph degree, one-hot encodings)
    ↓
Weak Supervision Engine (label_source: "module5_weak_supervision", N >= 3 cluster component)
    ↓
PyTorch Geometric GraphSAGE (2 SAGEConv layers + Dropout + Linear logits)
    ↓
Cluster Membership Likelihood Estimation (torch.sigmoid -> [0.0, 1.0])
    ↓
UI Graph Explorer & REST API (/api/gnn/predictions)
```

### Core Architecture & Technical Specifications

1. **GraphSAGE Architecture**:
   - Built using **PyTorch** (`torch>=2.0.0`) and **PyTorch Geometric** (`torch-geometric>=2.4.0`) running on CPU.
   - 2-layer GraphSAGE architecture: `SAGEConv(30, 32)` $\rightarrow$ ReLU $\rightarrow$ Dropout(0.2) $\rightarrow$ `SAGEConv(32, 32)` $\rightarrow$ ReLU $\rightarrow$ `Linear(32, 1)` returning raw logits.
   - Training loss: `torch.nn.BCEWithLogitsLoss()`.
   - Inference: `torch.sigmoid(logits)` producing cluster membership probabilities in $[0.0, 1.0]$.

2. **30-Dimensional Node Feature Schema**:
   - **Forensic & Base Probabilities (4)**: `ai_probability`, `human_probability`, `confidence`, `threat_score_scaled`.
   - **Text & Forensic Dimensions (10)**: `word_count_log`, `sentence_count_log`, `avg_word_length_scaled`, `avg_sentence_length_scaled`, `vocabulary_richness`, `urgency_score_scaled`, `manipulation_score_scaled`, `cta_score_scaled`, `unverified_claims_scaled`, `authority_pattern_scaled`.
   - **Graph Context (3)**: `node_degree_normalized`, `degree_centrality`, `avg_neighbor_similarity`.
   - **One-Hot Category (7)**: `Normal`, `Phishing`, `Disinformation`, `Manipulation`, `Propaganda`, `Spam`, `Other`.
   - **One-Hot Risk Level (4)**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
   - **One-Hot AI Label (2)**: `Human`, `AI-generated`.

3. **Strict Zero Target Leakage**:
   - Cluster IDs, campaign IDs, or weak labels are excluded from feature vectors to prevent trivial memorization.

4. **Weak Supervision & Analytical Framing**:
   - The GNN is trained using **weak labels** derived from Module 5 connected component heuristics ($N \ge 3$ incidents, mean similarity $\ge$ threshold).
   - Metadata explicitly records `label_source = "module5_weak_supervision"`.
   - > [!NOTE]
     > **Analytical Framing**: Weak labels represent heuristic similarity groupings, not ground truth. GNN output is an estimated likelihood of cluster membership ($[0.0, 0.39]$: `LOW_LIKELIHOOD`, $[0.40, 0.69]$: `POSSIBLE`, $[0.70, 1.00]$: `HIGH_LIKELIHOOD`), not proof of real-world coordination, campaign attribution, or actor identification.

5. **Small-Data Safety & Honest Evaluation**:
   - If dataset size $< 6$ nodes or lacks class diversity (all positive or all negative): Returns `INSUFFICIENT_DATA` without running training or fabricating evaluation metrics.
   - If validation set has $< 4$ nodes: Evaluation is marked `INSUFFICIENT_DATA`.

6. **Thread-Safe Offline Execution**:
   - Training runs on-demand via `POST /api/gnn/train` protected by `threading.Lock()` to prevent overlapping execution. GNN training is never triggered during real-time streaming ingestion.

### GNN REST API Specification

| Endpoint | Method | Description |
|---|---|---|
| `/api/gnn/status` | `GET` | Returns model training status, version, training node/edge counts, and metrics. |
| `/api/gnn/train` | `POST` | Triggers thread-safe on-demand training against stored incidents. |
| `/api/gnn/predictions` | `GET` | Retrieves GNN cluster membership probabilities and node explanations. |
| `/api/gnn/analyze` | `POST` | Runs on-demand inference across the incident graph. |

---

## Out-of-Scope Constraints

In accordance with project scope:
- No SIEM integrations, federated learning, or blockchain
- No user authentication or user account systems
- No multimedia (audio/video/image) analysis
- No automated enforcement or automatic takedowns
