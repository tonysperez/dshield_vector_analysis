"""SQLite-backed state: dedup cache + watermark.

Cache key components (ROADMAP #7 — two auto-derived hashes):
  - command_hash      identifier of the normalised command
  - model             cfg.llm.generation_model (which LLM produced enrichment)
  - llm_config_hash   compute_llm_config_hash(cfg) — prompt-file content +
                      LLM-affecting cooccurrence params. A change here means
                      the cached intent/tactics/etc are stale.
  - embed_config_hash compute_embed_config_hash(cfg) — embed_context list,
                      embedding_model, embed_cooccurrence toggle. A change
                      here means only the embedding is stale; `reembed`
                      refreshes it without an LLM call.

`mark_cached` writes both hashes (full enrich).
`mark_embed_cached` updates only `embed_config_hash` (embed-only refresh) —
preserves the cached llm_config_hash so a stale LLM output can't be
silently blessed by `reembed`.

Legacy columns `prompt_version`, `embed_version`, `config_hash` are kept
for backward-compat with older databases. They are filled with '' on every
new write and ignored by the lookup logic.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment_cache (
    command_hash       TEXT PRIMARY KEY,
    model              TEXT NOT NULL,
    prompt_version     TEXT NOT NULL DEFAULT '',
    embed_version      TEXT NOT NULL DEFAULT '',
    config_hash        TEXT NOT NULL DEFAULT '',
    llm_config_hash    TEXT NOT NULL DEFAULT '',
    embed_config_hash  TEXT NOT NULL DEFAULT '',
    enriched_at        TEXT NOT NULL
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

-- Intel subsystem (ROADMAP section A). The ES intel-* indices ARE the
-- result cache — these SQLite tables track only ephemeral worker state:
-- the priority queue, per-provider daily budget burn-down, and the
-- circuit-breaker state for failing providers.
CREATE TABLE IF NOT EXISTS intel_queue (
    artifact_kind  TEXT NOT NULL,
    artifact_value TEXT NOT NULL,
    priority       REAL NOT NULL,
    enqueued_at    TEXT NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (artifact_kind, artifact_value)
);
CREATE INDEX IF NOT EXISTS intel_queue_priority_idx
    ON intel_queue(priority DESC);

CREATE TABLE IF NOT EXISTS intel_provider_spend (
    provider TEXT NOT NULL,
    day      TEXT NOT NULL,            -- YYYY-MM-DD UTC
    calls    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, day)
);

CREATE TABLE IF NOT EXISTS intel_provider_state (
    provider             TEXT PRIMARY KEY,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    circuit_opened_at    TEXT NOT NULL DEFAULT '',
    last_success_at      TEXT NOT NULL DEFAULT '',
    last_error           TEXT NOT NULL DEFAULT ''
);
"""


# Idempotent migrations applied in order. Each tuple is (column, alter SQL).
# `ALTER TABLE ADD COLUMN` is idempotent in spirit only — SQLite errors if
# the column already exists. We catch the error per-column.
_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("embed_version",
     "ALTER TABLE enrichment_cache ADD COLUMN embed_version TEXT NOT NULL DEFAULT ''"),
    ("config_hash",
     "ALTER TABLE enrichment_cache ADD COLUMN config_hash TEXT NOT NULL DEFAULT ''"),
    ("llm_config_hash",
     "ALTER TABLE enrichment_cache ADD COLUMN llm_config_hash TEXT NOT NULL DEFAULT ''"),
    ("embed_config_hash",
     "ALTER TABLE enrichment_cache ADD COLUMN embed_config_hash TEXT NOT NULL DEFAULT ''"),
)


class StateDB:
    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, isolation_level=None)  # autocommit
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        for _name, ddl in _MIGRATIONS:
            try:
                self.conn.execute(ddl)
            except sqlite3.OperationalError:
                pass  # column already exists

    def close(self) -> None:
        self.conn.close()

    # --- cache --------------------------------------------------------------

    def is_cached(
        self,
        command_hash: str,
        model: str,
        llm_config_hash: str,
        embed_config_hash: str,
    ) -> bool:
        """Full cache hit — both LLM and embed sides are fresh."""
        cur = self.conn.execute(
            "SELECT 1 FROM enrichment_cache"
            " WHERE command_hash=? AND model=?"
            "   AND llm_config_hash=? AND embed_config_hash=?",
            (command_hash, model, llm_config_hash, embed_config_hash),
        )
        return cur.fetchone() is not None

    def mark_cached(
        self,
        command_hash: str,
        model: str,
        llm_config_hash: str,
        embed_config_hash: str,
        enriched_at: str,
    ) -> None:
        """Stamp a full enrichment (LLM + embed). Used by `enrich`."""
        self.conn.execute(
            "INSERT OR REPLACE INTO enrichment_cache"
            "(command_hash, model, prompt_version, embed_version, config_hash,"
            " llm_config_hash, embed_config_hash, enriched_at)"
            " VALUES (?,?, '', '', '', ?,?,?)",
            (command_hash, model, llm_config_hash, embed_config_hash, enriched_at),
        )

    def mark_embed_cached(
        self,
        command_hash: str,
        embed_config_hash: str,
        enriched_at: str,
    ) -> None:
        """Refresh only the embed side. Used by `reembed`.

        Updates `embed_config_hash` and `enriched_at` in place; does NOT
        touch `llm_config_hash` or `model`. If the row doesn't exist (a
        doc in ES with no cache row, e.g. legacy state), this is a no-op
        rather than an insert — we can't safely write a fresh
        `llm_config_hash` without proof the LLM output is current.
        """
        self.conn.execute(
            "UPDATE enrichment_cache"
            " SET embed_config_hash=?, enriched_at=?"
            " WHERE command_hash=?",
            (embed_config_hash, enriched_at, command_hash),
        )

    def get_cached_embed_hashes(self) -> dict[str, str]:
        """Bulk-load {command_hash: embed_config_hash} for every cache row.

        Used by `reembed` to skip docs whose embed-side cache is already
        current under the live config. Returns an empty dict for a fresh
        DB. Empty strings (legacy rows) are included; callers should
        treat them as 'not fresh' for any non-empty live hash.
        """
        cur = self.conn.execute(
            "SELECT command_hash, embed_config_hash FROM enrichment_cache"
        )
        return {row[0]: row[1] for row in cur.fetchall()}

    def get_cached_llm_hashes(self) -> dict[str, str]:
        """Bulk-load {command_hash: llm_config_hash} for every cache row.

        Mirror of `get_cached_embed_hashes` for the LLM side. Used by
        `re-enrich-stale` to find rows whose LLM hash drifted.
        """
        cur = self.conn.execute(
            "SELECT command_hash, llm_config_hash FROM enrichment_cache"
        )
        return {row[0]: row[1] for row in cur.fetchall()}

    def legacy_cache_row_count(self) -> int:
        """Rows missing one or both auto-hashes — i.e. pre-#7 or pre-split rows.

        Used at startup to decide whether to log the bless-cache hint.
        """
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM enrichment_cache"
            " WHERE llm_config_hash='' OR embed_config_hash=''"
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def bless_legacy_cache_rows(
        self, llm_config_hash: str, embed_config_hash: str,
    ) -> int:
        """Stamp every row with empty llm/embed hash with the current values.

        A one-time admin operation. Use after deploying a hash-affecting
        change when existing cached enrichments are known to be
        consistent with the current config — avoids a forced
        re-enrichment cycle. Returns the number of rows updated.
        """
        cur = self.conn.execute(
            "UPDATE enrichment_cache"
            " SET llm_config_hash = CASE WHEN llm_config_hash='' THEN ? ELSE llm_config_hash END,"
            "     embed_config_hash = CASE WHEN embed_config_hash='' THEN ? ELSE embed_config_hash END"
            " WHERE llm_config_hash='' OR embed_config_hash=''",
            (llm_config_hash, embed_config_hash),
        )
        return cur.rowcount or 0

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

    def clear_watermark(self, key: Optional[str] = None) -> int:
        """Delete one watermark row by key, or all rows when key is None."""
        if key is None:
            cur = self.conn.execute("DELETE FROM watermark")
        else:
            cur = self.conn.execute("DELETE FROM watermark WHERE key=?", (key,))
        return cur.rowcount or 0

    # --- intel subsystem ----------------------------------------------------

    def intel_queue_upsert(
        self,
        artifact_kind: str,
        artifact_value: str,
        priority: float,
        enqueued_at: str,
    ) -> None:
        """Insert a new artifact or refresh its priority if already queued.

        Re-enqueue with a higher priority lets a high-novelty discovery
        jump ahead of stale low-priority entries left over from a
        previous run. Attempt count + last error are preserved.
        """
        self.conn.execute(
            "INSERT INTO intel_queue(artifact_kind, artifact_value, priority, enqueued_at)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(artifact_kind, artifact_value) DO UPDATE SET"
            "   priority = excluded.priority,"
            "   enqueued_at = excluded.enqueued_at",
            (artifact_kind, artifact_value, priority, enqueued_at),
        )

    def intel_queue_pop_top(
        self, artifact_kind: str, limit: int,
    ) -> list[tuple[str, float]]:
        """Return up to `limit` queued artifacts of `kind`, highest-priority first.

        DOES NOT remove them from the queue — call `intel_queue_mark_done`
        after the lookup attempt. A worker that crashes mid-batch leaves
        the rows in place for the next run.
        """
        cur = self.conn.execute(
            "SELECT artifact_value, priority FROM intel_queue"
            " WHERE artifact_kind = ?"
            " ORDER BY priority DESC, enqueued_at ASC"
            " LIMIT ?",
            (artifact_kind, limit),
        )
        return [(row[0], row[1]) for row in cur.fetchall()]

    def intel_queue_mark_done(self, artifact_kind: str, artifact_value: str) -> None:
        """Remove an artifact from the queue (lookup successful for all providers)."""
        self.conn.execute(
            "DELETE FROM intel_queue WHERE artifact_kind=? AND artifact_value=?",
            (artifact_kind, artifact_value),
        )

    def intel_queue_mark_attempt(
        self, artifact_kind: str, artifact_value: str, last_error: str,
    ) -> None:
        """Increment the attempts counter and store the last error.

        Leaves the row in the queue so the next run retries. The worker
        decides when to give up via `attempts` threshold.
        """
        self.conn.execute(
            "UPDATE intel_queue"
            " SET attempts = attempts + 1, last_error = ?"
            " WHERE artifact_kind = ? AND artifact_value = ?",
            (last_error, artifact_kind, artifact_value),
        )

    def intel_queue_depth(self) -> dict[str, int]:
        """Return {kind: count} for the current queue. Used by /api/intel/health."""
        cur = self.conn.execute(
            "SELECT artifact_kind, COUNT(*) FROM intel_queue GROUP BY artifact_kind"
        )
        return {row[0]: row[1] for row in cur.fetchall()}

    def intel_provider_calls_today(self, provider: str, day: str) -> int:
        """Count of calls already made to `provider` today (UTC)."""
        cur = self.conn.execute(
            "SELECT calls FROM intel_provider_spend WHERE provider=? AND day=?",
            (provider, day),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def intel_provider_record_call(self, provider: str, day: str) -> None:
        """Increment the daily-call counter for `provider`."""
        self.conn.execute(
            "INSERT INTO intel_provider_spend(provider, day, calls)"
            " VALUES (?, ?, 1)"
            " ON CONFLICT(provider, day) DO UPDATE SET calls = calls + 1",
            (provider, day),
        )

    def intel_provider_get_state(self, provider: str) -> dict:
        """Return the current circuit-breaker / failure state for a provider.

        Empty result returns a default 'clean' state so callers don't
        need to handle the missing-row case.
        """
        cur = self.conn.execute(
            "SELECT consecutive_failures, circuit_opened_at, last_success_at, last_error"
            " FROM intel_provider_state WHERE provider = ?",
            (provider,),
        )
        row = cur.fetchone()
        if not row:
            return {
                "consecutive_failures": 0,
                "circuit_opened_at": "",
                "last_success_at": "",
                "last_error": "",
            }
        return {
            "consecutive_failures": int(row[0]),
            "circuit_opened_at": row[1],
            "last_success_at": row[2],
            "last_error": row[3],
        }

    def intel_provider_record_success(self, provider: str, when: str) -> None:
        """Mark a successful lookup. Resets consecutive_failures."""
        self.conn.execute(
            "INSERT INTO intel_provider_state(provider, consecutive_failures, last_success_at)"
            " VALUES (?, 0, ?)"
            " ON CONFLICT(provider) DO UPDATE SET"
            "   consecutive_failures = 0,"
            "   circuit_opened_at = '',"
            "   last_success_at = ?,"
            "   last_error = ''",
            (provider, when, when),
        )

    def intel_provider_record_failure(
        self, provider: str, error: str, when: str, open_circuit: bool,
    ) -> None:
        """Increment failure counter; mark circuit-open if requested."""
        self.conn.execute(
            "INSERT INTO intel_provider_state(provider, consecutive_failures, last_error, circuit_opened_at)"
            " VALUES (?, 1, ?, ?)"
            " ON CONFLICT(provider) DO UPDATE SET"
            "   consecutive_failures = consecutive_failures + 1,"
            "   last_error = ?,"
            "   circuit_opened_at = CASE WHEN ? THEN ? ELSE circuit_opened_at END",
            (provider, error, when if open_circuit else "", error, open_circuit, when),
        )
