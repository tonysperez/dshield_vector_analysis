"""SANS Internet Storm Center / DShield top-attackers provider.

The ISC API publishes a list of source IPs reporting the highest
attack volumes across the DShield sensor network. We download the
list on a configurable cadence (default 6h) and answer per-IP
lookups from the in-memory snapshot.

The research signal: if our sensor sees an IP scoring high local
novelty AND ISC's global aggregation shows the same IP attacking
hundreds of other sensors, the local novelty was undercalibrated —
this is wide-scale, not a long-tail discovery. Conversely, an IP
attacking us heavily that ISC's network *isn't* seeing is a stronger
research lead.

Endpoint shape (subject to ISC's evolution; the parser is
defensive):

    [
      {"source": "1.2.3.4", "reports": 47000, "targets": 8123, ...},
      ...
    ]

A miss (artifact not in the top-N) is `malicious=None` — no opinion.
A hit is `malicious=True` with `label="isc_top_attacker"` and
confidence proportional to report volume.
"""
from __future__ import annotations

import json
import logging
import math
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

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


def parse_isc_response(payload: Any) -> dict[str, dict[str, Any]]:
    """Parse the ISC top-attackers response into `{ip: row}`.

    Defensive: accepts both list-of-objects and dict-with-data wrapping.
    Unknown shapes return an empty dict — better than crashing the
    provider on an upstream format change.
    """
    rows: list[dict[str, Any]] = []
    if isinstance(payload, list):
        rows = [r for r in payload if isinstance(r, dict)]
    elif isinstance(payload, dict):
        for key in ("data", "sources", "results"):
            v = payload.get(key)
            if isinstance(v, list):
                rows = [r for r in v if isinstance(r, dict)]
                break

    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        # Field name varies; try several.
        ip = r.get("source") or r.get("ip") or r.get("sourceip")
        if not isinstance(ip, str):
            continue
        ip = ip.strip()
        if ip:
            out[ip] = r
    return out


def confidence_from_reports(reports: int) -> int:
    """Map report count to a 1-10 confidence band.

    Log-scaled so a 10x change in volume bumps confidence by ~2. A
    single report is confidence 4 — barely notable; 100k+ reports is
    confidence 10.
    """
    if reports <= 0:
        return 1
    # log10(1) = 0 → ~4; log10(100000) = 5 → 9+. Clamped to [4, 10].
    raw = 4 + 1.2 * math.log10(max(1, reports))
    return max(4, min(10, int(round(raw))))


class ISCProvider(Provider):
    name = "isc"
    handles = frozenset({"ip"})
    ttl = timedelta(days=1)
    rate_limit = RateLimit(capacity=1000, refill_per_second=1000.0, daily_budget=None)

    def __init__(self, provider_cfg) -> None:
        super().__init__(provider_cfg)
        self._top: dict[str, dict[str, Any]] = {}
        self._loaded_at: float = 0.0
        self._lock = threading.Lock()

    def _stale(self) -> bool:
        return (
            not self._top
            or (time.time() - self._loaded_at) >= self.cfg.refresh_minutes * 60
        )

    def _load_from_cache_file(self) -> Optional[dict[str, dict[str, Any]]]:
        p = Path(self.cfg.cache_file)
        if not p.exists():
            return None
        try:
            stat = p.stat()
        except OSError:
            return None
        if (time.time() - stat.st_mtime) > self.cfg.refresh_minutes * 60:
            return None
        try:
            payload = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        return parse_isc_response(payload)

    def _save_cache_file(self, payload: Any) -> None:
        p = Path(self.cfg.cache_file)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(payload))
        except OSError as exc:                     # pragma: no cover
            log.warning("isc: failed to persist cache file %s: %s", p, exc)

    def _fetch_remote(self) -> tuple[dict[str, dict[str, Any]], Any]:
        try:
            r = httpx.get(self.cfg.sources_url, timeout=30.0)
            r.raise_for_status()
            payload = r.json()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as exc:
            raise ProviderUnavailable(f"isc: fetch {self.cfg.sources_url}: {exc}") from exc
        return parse_isc_response(payload), payload

    def _ensure_loaded(self) -> None:
        if not self._stale():
            return
        with self._lock:
            if not self._stale():
                return
            cached = self._load_from_cache_file()
            if cached is not None:
                self._top = cached
                self._loaded_at = time.time()
                return
            parsed, raw = self._fetch_remote()
            self._top = parsed
            self._loaded_at = time.time()
            self._save_cache_file(raw)

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind != "ip":
            raise ValueError(f"isc: cannot handle kind {artifact.kind!r}")
        self._ensure_loaded()
        row = self._top.get(artifact.value)
        if row is None:
            derived = DerivedSignals(malicious=None, confidence=None, label=None, tags=())
            structured: dict[str, Any] = {"in_top": False, "list_size": len(self._top)}
        else:
            reports = int(row.get("reports") or row.get("count") or row.get("attacks") or 0)
            targets = int(row.get("targets") or row.get("targetcount") or 0)
            confidence = confidence_from_reports(reports)
            derived = DerivedSignals(
                malicious=True,
                confidence=confidence,
                label="isc_top_attacker",
                tags=("isc_top_attacker",),
            )
            structured = {
                "in_top": True,
                "reports": reports,
                "targets": targets,
                "list_size": len(self._top),
            }
        return ProviderResult.make(
            provider=self.name,
            artifact=artifact,
            structured=structured,
            raw={"row": row} if row is not None else {"row": None},
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
            detail=f"isc top-attackers loaded: {len(self._top)} entries",
            extra={"list_size": len(self._top)},
        )
