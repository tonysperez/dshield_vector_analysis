"""Tor exit list provider.

Downloads the canonical Tor Project exit-list (one IP per line, no
authentication required) on a configurable cadence and answers
per-IP lookups from the in-memory snapshot. No per-lookup network
traffic; no API key; effectively unmetered.

A "tor_exit" verdict is not the same as "malicious." Tor exit traffic
is overwhelmingly benign on a research honeypot (and using this as
*detection* signal would be poor practice). We surface it as a
neutral label so the analyst can decide. The consensus rule
(any-positive flags malicious) intentionally treats `malicious=False`
on this provider as a no-op signal — it doesn't pull the artifact
toward "benign," it just adds a tag.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import Optional

import httpx

from ..artifact import Artifact
from .base import (
    DerivedSignals,
    HealthStatus,
    Provider,
    ProviderResult,
    ProviderUnavailable,
    RateLimit,
)

log = logging.getLogger(__name__)


class TorProvider(Provider):
    name = "tor"
    handles = frozenset({"ip"})
    ttl = timedelta(days=1)
    rate_limit = RateLimit(capacity=1000, refill_per_second=1000.0, daily_budget=None)

    def __init__(self, provider_cfg) -> None:
        super().__init__(provider_cfg)
        self._exits: set[str] = set()
        self._loaded_at: float = 0.0
        self._lock = threading.Lock()

    # --- list maintenance ---------------------------------------------------

    def _stale(self) -> bool:
        return (
            not self._exits
            or (time.time() - self._loaded_at) >= self.cfg.refresh_minutes * 60
        )

    def _load_from_cache_file(self) -> Optional[set[str]]:
        p = Path(self.cfg.cache_file)
        if not p.exists():
            return None
        try:
            stat = p.stat()
        except OSError:
            return None
        max_age = self.cfg.refresh_minutes * 60
        if (time.time() - stat.st_mtime) > max_age:
            return None
        try:
            return {
                line.strip()
                for line in p.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            }
        except OSError:
            return None

    def _save_cache_file(self, exits: set[str]) -> None:
        p = Path(self.cfg.cache_file)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("\n".join(sorted(exits)) + "\n")
        except OSError as exc:                     # pragma: no cover
            log.warning("tor: failed to persist cache file %s: %s", p, exc)

    def _fetch_remote(self) -> set[str]:
        try:
            r = httpx.get(self.cfg.exit_list_url, timeout=15.0)
            r.raise_for_status()
        except (httpx.HTTPError, httpx.RequestError) as exc:
            raise ProviderUnavailable(f"tor: fetch {self.cfg.exit_list_url}: {exc}") from exc
        return {
            line.strip()
            for line in r.text.splitlines()
            if line.strip() and not line.startswith("#")
        }

    def _ensure_loaded(self) -> None:
        if not self._stale():
            return
        with self._lock:
            if not self._stale():
                return
            cached = self._load_from_cache_file()
            if cached is not None:
                self._exits = cached
                self._loaded_at = time.time()
                return
            remote = self._fetch_remote()
            self._exits = remote
            self._loaded_at = time.time()
            self._save_cache_file(remote)

    # --- Provider contract --------------------------------------------------

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind != "ip":
            raise ValueError(f"tor: cannot handle kind {artifact.kind!r}")
        self._ensure_loaded()
        is_exit = artifact.value in self._exits
        derived = DerivedSignals(
            # Being a tor exit isn't itself a malicious verdict. We
            # expose the membership as a label + tag and leave the
            # consensus rule out of it. See module docstring.
            malicious=None,
            confidence=None,
            label="tor_exit" if is_exit else None,
            tags=("tor_exit",) if is_exit else (),
        )
        return ProviderResult.make(
            provider=self.name,
            artifact=artifact,
            structured={"is_exit": is_exit, "list_size": len(self._exits)},
            raw={"is_exit": is_exit},
            derived=derived,
            ttl=self.ttl,
        )

    def health(self) -> HealthStatus:
        try:
            self._ensure_loaded()
        except ProviderUnavailable as exc:
            return HealthStatus(ok=False, detail=str(exc))
        return HealthStatus(
            ok=True,
            detail=f"tor exit list loaded: {len(self._exits)} entries",
            extra={"list_size": len(self._exits)},
        )
