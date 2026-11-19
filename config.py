"""AIShield - System Configuration.

Centralizes operational parameters, limits, and runtime settings.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory
BASE_DIR: Path = Path(__file__).resolve().parent

# Automatically load environment variables from .env file if present
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path, override=True)

# Processing Queue Settings
MAX_PROCESSING_ATTEMPTS: int = int(os.environ.get("AISHIELD_MAX_ATTEMPTS", 3))
QUEUE_MAX_SIZE: int = int(os.environ.get("AISHIELD_QUEUE_MAX_SIZE", 1000))
WORKER_COUNT: int = int(os.environ.get("AISHIELD_WORKER_COUNT", 1))

# Text Limits
MAX_TEXT_LENGTH: int = int(os.environ.get("AISHIELD_MAX_TEXT_LENGTH", 50000))

# Graph Similarity Threshold Defaults
DEFAULT_SIMILARITY_THRESHOLD: float = float(os.environ.get("AISHIELD_SIMILARITY_THRESHOLD", 0.65))
MIN_SIMILARITY_THRESHOLD: float = 0.50
MAX_SIMILARITY_THRESHOLD: float = 0.95

# Bluesky Jetstream Live Connector Settings
BLUESKY_ENABLED: bool = os.environ.get("BLUESKY_ENABLED", "false").lower() in ("true", "1")
BLUESKY_JETSTREAM_URL: str = os.environ.get(
    "BLUESKY_JETSTREAM_URL",
    "wss://jetstream1.us-east.bsky.network/subscribe?wantedCollections=app.bsky.feed.post",
)
BLUESKY_RECONNECT_INITIAL_BACKOFF: float = 1.0
BLUESKY_RECONNECT_MAX_BACKOFF: float = 30.0
BLUESKY_PING_INTERVAL: float = 20.0
BLUESKY_PING_TIMEOUT: float = 10.0
BLUESKY_RELEVANCE_FILTER_ENABLED: bool = os.environ.get("BLUESKY_RELEVANCE_FILTER_ENABLED", "true").lower() in ("true", "1")
BLUESKY_MONITOR_TERMS: str = os.environ.get(
    "BLUESKY_MONITOR_TERMS",
    "cybersecurity,cyberattack,infosec,informationsecurity,malware,ransomware,phishing,databreach,socialengineering,misinformation,disinformation,propaganda,influenceoperation,informationwarfare,deepfake,aigenerated,misleading,factcheck,scam",
)

# Mastodon Live Streaming Connector Settings
MASTODON_ENABLED: bool = os.environ.get("MASTODON_ENABLED", "false").lower() in ("true", "1")
MASTODON_BASE_URL: str = os.environ.get("MASTODON_BASE_URL", "https://mastodon.social").rstrip("/")
MASTODON_ACCESS_TOKEN: str = os.environ.get("MASTODON_ACCESS_TOKEN", "").strip()
MASTODON_STREAM_MODE: str = os.environ.get("MASTODON_STREAM_MODE", "hashtag").lower()
MASTODON_HASHTAGS: str = os.environ.get(
    "MASTODON_HASHTAGS",
    "cybersecurity,cyberattack,infosec,informationsecurity,malware,ransomware,phishing,databreach,socialengineering,misinformation,disinformation,propaganda,influenceoperation,informationwarfare,deepfake,aigenerated,misleading,factcheck,scam",
)
MASTODON_RECONNECT_INITIAL_BACKOFF: float = 1.0
MASTODON_RECONNECT_MAX_BACKOFF: float = 30.0

# YouTube Keyword Polling Connector Settings
YOUTUBE_ENABLED: bool = os.environ.get("YOUTUBE_ENABLED", "false").lower() in ("true", "1")
YOUTUBE_API_KEY: str = os.environ.get("YOUTUBE_API_KEY", "").strip()
YOUTUBE_QUERIES: str = os.environ.get(
    "YOUTUBE_QUERIES",
    "cybersecurity threat,disinformation campaign,phishing attack",
)
YOUTUBE_REGION_CODE: str = os.environ.get("YOUTUBE_REGION_CODE", "US").strip()
YOUTUBE_LANGUAGE: str = os.environ.get("YOUTUBE_LANGUAGE", "en").strip()
YOUTUBE_POLL_INTERVAL_SECONDS: int = int(os.environ.get("YOUTUBE_POLL_INTERVAL_SECONDS", 300))
YOUTUBE_MAX_RESULTS: int = min(50, max(1, int(os.environ.get("YOUTUBE_MAX_RESULTS", 10))))
YOUTUBE_MAX_REQUESTS_PER_DAY: int = int(os.environ.get("YOUTUBE_MAX_REQUESTS_PER_DAY", 100))

# Incident Policy Decision Settings (Stage 6F)
INCIDENT_POLICY_MIN_THREAT_SCORE: float = float(os.environ.get("AISHIELD_INCIDENT_MIN_THREAT_SCORE", 60.0))
INCIDENT_POLICY_MIN_AI_PROBABILITY: float = float(os.environ.get("AISHIELD_INCIDENT_MIN_AI_PROB", 0.85))
INCIDENT_POLICY_SECONDARY_THREAT_SCORE: float = float(os.environ.get("AISHIELD_INCIDENT_SEC_THREAT_SCORE", 40.0))

# Live Monitoring & Server-Sent Events Settings (Stage 6G)
MAX_SSE_SUBSCRIBERS: int = int(os.environ.get("MAX_SSE_SUBSCRIBERS", 25))
SSE_KEEPALIVE_INTERVAL_SECONDS: float = float(os.environ.get("SSE_KEEPALIVE_INTERVAL_SECONDS", 15.0))

# Graph Neural Network (GNN) Settings
GNN_ENABLED: bool = os.environ.get("GNN_ENABLED", "true").lower() in ("true", "1")
GNN_MODEL_PATH: Path = BASE_DIR / "models" / "gnn_campaign_model.pt"
GNN_METADATA_PATH: Path = BASE_DIR / "models" / "gnn_metadata.json"
GNN_MIN_TRAIN_NODES: int = int(os.environ.get("GNN_MIN_TRAIN_NODES", 6))
GNN_HIDDEN_DIM: int = int(os.environ.get("GNN_HIDDEN_DIM", 32))
GNN_LEARNING_RATE: float = float(os.environ.get("GNN_LEARNING_RATE", 0.01))
GNN_EPOCHS: int = int(os.environ.get("GNN_EPOCHS", 80))
GNN_DROPOUT: float = float(os.environ.get("GNN_DROPOUT", 0.2))
GNN_RANDOM_SEED: int = int(os.environ.get("GNN_RANDOM_SEED", 42))

