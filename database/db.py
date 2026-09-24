"""SQLite Database Connection & Schema Management for AIShield."""

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Generator, Optional, Union

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "ai_shield.db"

TABLES_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    ai_label TEXT NOT NULL,
    ai_probability REAL NOT NULL,
    human_probability REAL NOT NULL,
    confidence REAL NOT NULL,
    threat_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    category TEXT NOT NULL,
    text_analysis_json TEXT NOT NULL,
    indicators_json TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    component_scores_json TEXT NOT NULL,
    source_post_id INTEGER
);

CREATE TABLE IF NOT EXISTS source_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_url TEXT,
    author_id TEXT,
    author_name TEXT,
    content TEXT NOT NULL,
    published_at TEXT,
    language TEXT,
    metadata_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    status TEXT NOT NULL,
    analysis_attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    processed_at TEXT,
    incident_id TEXT
);
"""

INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_content_hash ON incidents(content_hash);
CREATE INDEX IF NOT EXISTS idx_incidents_source_post_id ON incidents(source_post_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_source_posts_source_source_id ON source_posts(source, source_id);
CREATE INDEX IF NOT EXISTS idx_source_posts_content_hash ON source_posts(content_hash);
CREATE INDEX IF NOT EXISTS idx_source_posts_status ON source_posts(status);
CREATE INDEX IF NOT EXISTS idx_source_posts_ingested_at ON source_posts(ingested_at);
CREATE INDEX IF NOT EXISTS idx_source_posts_source ON source_posts(source);
CREATE INDEX IF NOT EXISTS idx_source_posts_incident_id ON source_posts(incident_id);
"""

# Backwards compatibility
SCHEMA_SQL = TABLES_SQL + "\n" + INDEXES_SQL


def get_db_path(custom_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve absolute database path using Pathlib."""
    if custom_path is not None:
        return Path(custom_path).resolve()
    return DEFAULT_DB_PATH


def get_db_connection(db_path: Optional[Union[str, Path]] = None) -> sqlite3.Connection:
    """Create and return a SQLite database connection with row factory enabled."""
    path = get_db_path(db_path)
    # Ensure directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrency and foreign keys
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def db_session(db_path: Optional[Union[str, Path]] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that yields a SQLite connection and guarantees clean closure."""
    conn = get_db_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: Optional[Union[str, Path]] = None) -> Path:
    """Initialize the SQLite database and create tables/indexes if absent."""
    path = get_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with db_session(path) as conn:
        with conn:
            # 1. Create tables first
            conn.executescript(TABLES_SQL)

            # 2. Safe schema migrations for existing databases
            inc_cols = [row[1] for row in conn.execute("PRAGMA table_info(incidents);").fetchall()]
            if "source_post_id" not in inc_cols:
                conn.execute("ALTER TABLE incidents ADD COLUMN source_post_id INTEGER;")

            sp_cols = [row[1] for row in conn.execute("PRAGMA table_info(source_posts);").fetchall()]
            if "incident_id" not in sp_cols:
                conn.execute("ALTER TABLE source_posts ADD COLUMN incident_id TEXT;")

            # 3. Create all indexes safely after columns are guaranteed to exist
            conn.executescript(INDEXES_SQL)

    return path
