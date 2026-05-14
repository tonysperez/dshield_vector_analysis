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
    embed_version   TEXT NOT NULL DEFAULT 'v0',
    enriched_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watermark (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_spend (
    day            TEXT PRIMARY KEY,  -- ISO date YYYY-MM-DD UTC
    calls          INTEGER NOT NULL DEFAULT 0,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    cost_usd       REAL    NOT NULL DEFAULT 0.0
);
"""


class StateDB:
    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, isolation_level=None)  # autocommit
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        # Migration: add embed_version column to pre-Phase-3+ databases.
        try:
            self.conn.execute(
                "ALTER TABLE enrichment_cache ADD COLUMN embed_version TEXT NOT NULL DEFAULT 'v0'"
            )
        except sqlite3.OperationalError:
            pass  # column already exists

    def close(self) -> None:
        self.conn.close()

    # --- cache --------------------------------------------------------------

    def is_cached(self, command_hash: str, model: str, prompt_version: str, embed_version: str = "v0") -> bool:
        cur = self.conn.execute(
            "SELECT 1 FROM enrichment_cache"
            " WHERE command_hash=? AND model=? AND prompt_version=? AND embed_version=?",
            (command_hash, model, prompt_version, embed_version),
        )
        return cur.fetchone() is not None

    def mark_cached(self, command_hash: str, model: str, prompt_version: str, embed_version: str, enriched_at: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO enrichment_cache"
            "(command_hash, model, prompt_version, embed_version, enriched_at)"
            " VALUES (?,?,?,?,?)",
            (command_hash, model, prompt_version, embed_version, enriched_at),
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

    # --- cloud spend --------------------------------------------------------

    def get_spend(self, day: str) -> dict:
        cur = self.conn.execute(
            "SELECT calls, input_tokens, output_tokens, cost_usd FROM cloud_spend WHERE day=?",
            (day,),
        )
        row = cur.fetchone()
        if not row:
            return {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
        return {"calls": row[0], "input_tokens": row[1], "output_tokens": row[2], "cost_usd": row[3]}

    def add_spend(self, day: str, input_tokens: int, output_tokens: int, cost_usd: float) -> None:
        self.conn.execute(
            """INSERT INTO cloud_spend(day, calls, input_tokens, output_tokens, cost_usd)
               VALUES (?, 1, ?, ?, ?)
               ON CONFLICT(day) DO UPDATE SET
                 calls=calls+1,
                 input_tokens=input_tokens+excluded.input_tokens,
                 output_tokens=output_tokens+excluded.output_tokens,
                 cost_usd=cost_usd+excluded.cost_usd""",
            (day, input_tokens, output_tokens, cost_usd),
        )

    def clear_cache(self) -> int:
        cur = self.conn.execute("DELETE FROM enrichment_cache")
        return cur.rowcount or 0

    def clear_watermark(self) -> int:
        cur = self.conn.execute("DELETE FROM watermark")
        return cur.rowcount or 0
