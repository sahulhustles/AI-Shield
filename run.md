# AIShield — System Execution & Operational Guide (`run.md`)

This guide provides step-by-step instructions for installing dependencies, configuring environment settings, running the **AIShield** platform, accessing the interactive web interfaces, and executing the automated test suite.

---

## 1. System Prerequisites

- **Python**: Python 3.9, 3.10, 3.11, or 3.12 (64-bit)
- **Package Manager**: `pip` (up to date)
- **OS Support**: Windows (PowerShell/CMD), Linux, or macOS

---

## 2. Step-by-Step Setup Instructions

### Step 1: Navigate to the Project Root
Open your terminal/PowerShell and change directory to the platform root:

```bash
cd c:\Users\bsahu\Desktop\test111\new-gpt\platform
```

---

### Step 2: Create and Activate Virtual Environment

#### Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### Windows (Command Prompt):
```cmd
python -m venv venv
.\venv\Scripts\activate.bat
```

#### Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### Step 3: Install Required Dependencies

Install all core dependencies from `requirements.txt`:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **Note**: Key packages installed include:
> - `Flask` (Web framework & REST API)
> - `scikit-learn`, `pandas`, `numpy`, `joblib` (ML Detector & TF-IDF Vectorizer)
> - `networkx` (Graph relationship & cluster analysis)
> - `torch`, `torch-geometric` (Graph Neural Network module)
> - `pytest` (Test automation framework)

---

## 3. Environment Configuration (`.env`)

AIShield automatically loads environment variables from `.env` on startup via `config.py`.

If `.env` does not exist, copy `.env.example`:

```bash
copy .env.example .env    # On Windows
# or: cp .env.example .env # On Linux/macOS
```

### Key Configuration Variables (`.env`)

```env
# Application Server
PORT=5000
FLASK_DEBUG=0

# Ingestion Queue & Worker Pool
AISHIELD_QUEUE_MAX_SIZE=1000
AISHIELD_WORKER_COUNT=1
AISHIELD_MAX_ATTEMPTS=3

# Automated Incident Creation Policy Thresholds
AISHIELD_INCIDENT_MIN_THREAT_SCORE=60.0
AISHIELD_INCIDENT_MIN_AI_PROB=0.85
AISHIELD_INCIDENT_SEC_THREAT_SCORE=40.0

# Real-Time SSE Stream Settings
MAX_SSE_SUBSCRIBERS=25
SSE_KEEPALIVE_INTERVAL_SECONDS=15.0

# Social Stream Connectors
BLUESKY_ENABLED=true
MASTODON_ENABLED=true
YOUTUBE_ENABLED=true
YOUTUBE_API_KEY=your_youtube_api_key_here
```

---

## 4. Launching the Server

Run the main application script:

```bash
python app.py
```

### Server Startup Sequence:
When started, AIShield performs the following automated startup tasks:
1. Initializes the SQLite database (`database/ai_shield.db`) if not present.
2. Loads or trains the pre-trained Logistic Regression ML detector artifact (`models/detector_model.joblib`).
3. Starts the background asynchronous Ingestion Queue Worker.
4. Initializes enabled social stream connectors (Bluesky, Mastodon, YouTube).
5. Serves the Flask app at `http://127.0.0.1:5000/`.

---

## 5. Navigating the User Interfaces

Once the application is running, open your web browser to access the dashboards:

| Dashboard / Interface | URL | Description |
| :--- | :--- | :--- |
| **Analyzer** | `http://127.0.0.1:5000/` | Real-time AI detection, structural text statistics, and threat score breakdown. |
| **Incident History** | `http://127.0.0.1:5000/incidents` | Table of saved forensic incident records with SHA-256 integrity verification. |
| **Incident Detail** | `http://127.0.0.1:5000/incidents/<id>` | Full immutable snapshot inspection page for a single incident. |
| **Threat Dashboard** | `http://127.0.0.1:5000/dashboard` | Aggregated intelligence metrics, distribution charts, and multi-filter search. |
| **Relationship Graph** | `http://127.0.0.1:5000/graph` | Interactive `vis-network` TF-IDF text similarity graph and campaign detection. |
| **Live Monitoring** | `http://127.0.0.1:5000/live` | Real-time Server-Sent Events (SSE) stream of ingested social media posts. |
| **GNN Dashboard** | `http://127.0.0.1:5000/gnn` | Graph Neural Network embeddings, risk propagation, and structural analytics. |

---

## 6. Running the Automated Test Suite

To run all unit, integration, and service tests across all modules:

### Fast Quiet Mode:
```bash
pytest -q
```

### Verbose Mode with Test Names:
```bash
pytest -v
```

### Run Specific Test Modules:
```bash
pytest tests/test_detector.py     # Module 1 tests
pytest tests/test_threat_analyzer.py # Module 2 tests
pytest tests/test_forensics.py    # Module 3 tests
pytest tests/test_intelligence.py # Module 4 tests
pytest tests/test_graph.py        # Module 5 tests
pytest tests/test_api.py          # API & Integration tests
```

---

## 7. Useful REST API Commands

### Analyze Text Content (`POST /api/analyze`)
```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"URGENT SECURITY ALERT: Unauthorized login detected on your bank account! Click here immediately to verify credentials.\"}"
```

### Search Forensic Incidents (`GET /api/dashboard/incidents`)
```bash
curl "http://127.0.0.1:5000/api/dashboard/incidents?risk_level=HIGH&category=Phishing&page=1&page_size=10"
```

### Query Relationship Graph (`GET /api/graph`)
```bash
curl "http://127.0.0.1:5000/api/graph?threshold=0.65"
```

### Stream Live Ingestion Events (`GET /api/live/stream`)
```bash
curl -N http://127.0.0.1:5000/api/live/stream
```

---

## 8. Troubleshooting

- **Port in Use**: If port 5000 is occupied, set `PORT=5005` in `.env` or run:
  ```powershell
  $env:PORT="5005"; python app.py
  ```
- **Database Lock**: If SQLite reports locked state, ensure no other process is holding a transaction lock on `database/ai_shield.db`.
- **Model Re-training**: To force re-training of the ML detector, delete `models/detector_model.joblib` and restart `python app.py`.
