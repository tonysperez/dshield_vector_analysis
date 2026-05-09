"""SQLite-backed state: dedup cache + watermark."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment_cache (
    command_hash    TEXT PRIMARY KEY,
    model           TEXT NOT NULL,
    prompt_version  TEXT NOT NULL,
    enriched_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watermark (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class StateDB:
    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, isolation_level=None)  # autocommit
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # --- cache --------------------------------------------------------------

    def is_cached(self, command_hash: str, model: str, prompt_version: str) -> bool:
        cur = self.conn.execute(
            "SELECT 1 FROM enrichment_cache WHERE command_hash=? AND model=? AND prompt_version=?",
            (command_hash, model, prompt_version),
        )
        return cur.fetchone() is not None

    def mark_cached(self, command_hash: str, model: str, prompt_version: str, enriched_at: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO enrichment_cache(command_hash, model, prompt_version, enriched_at) VALUES (?,?,?,?)",
            (command_hash, model, prompt_version, enriched_at),
        )

    # --- watermark ----------------------------------------------------------

    def get_watermark(self, key: str = "last_processed_at") -> Optional[str]:
        cur = self.conn.execute("SELECT value FROM watermark WHERE key=?", (key,))
        row = cur.fetchone()
        return row[0] if row else None

    def set_watermark(self, value: str, key: str = "last_processed_at") -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO watermark(key, value) VALUES (?, ?)",
            (key, value),
        )

    # --- maintenance --------------------------------------------------------

    def clear_cache(self) -> int:
        cur = self.conn.execute("DELETE FROM enrichment_cache")
        return cur.rowcount or 0

    def clear_watermark(self) -> int:
        cur = self.conn.execute("DELETE FROM watermark")
        return cur.rowcount or 0
