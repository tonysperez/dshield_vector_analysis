"""abuse.ch FeodoTracker provider — active botnet C2 infrastructure.

FeodoTracker publishes a list of IPs currently hosting C2 servers
for the Feodo malware family (Emotet, Dridex, TrickBot, BazarLoader,
Heodo, Qakbot, IcedID and friends). The recommended block-list JSON
endpoint refreshes hourly and contains only IPs flagged `online` —
high-precision, low-volume (a few hundred to a few thousand entries
at any moment).

No API key, no per-IP rate limit, no DNS-blocklist-style query-source
restrictions. Bulk download, in-memory lookup. Sibling of the Tor
provider's mechanics.

We pull `ipblocklist_recommended.json` rather than the broader
`ipblocklist.json` because it pre-filters for currently-active C2;
that's the higher-signal product for honeypot-corpus annotation.

A hit means: "this IP is hosting active malware C2 right now." That's
strictly stronger than the SBL-style listings Spamhaus would have
provided for our use case. Confidence is set high (9/10) because the
upstream curation is excellent.

Endpoint shape (subject to abuse.ch evolution; the parser is
defensive):

    [
      {
        "ip_address": "1.2.3.4",
        "port": 443,
        "status": "online",
        "hostname": "...",
        "as_number": 12345,
        "as_name": "...",
        "country": "RU",
        "first_seen": "2026-04-12 14:23:01",
        "last_online": "2026-05-16 12:00:00",
        "malware": "Emotet"
      },
      ...
    ]

A miss is `malicious=None` (no opinion); a hit is `malicious=True`
with `label="feodo_c2"` and the malware family added as a tag.
"""
from __future__ import annotations

import json
import logging
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


def parse_feodo_response(payload: Any) -> dict[str, dict[str, Any]]:
    """Parse the FeodoTracker JSON into `{ip: row}`.

    Defensive: accepts both the canonical top-level list and a
    `{data: [...]}` wrapping that abuse.ch sometimes uses on
    sibling endpoints. Returns an empty dict on unknown shapes
    rather than raising.
    """
    rows: list[dict[str, Any]] = []
    if isinstance(payload, list):
        rows = [r for r in payload if isinstance(r, dict)]
    elif isinstance(payload, dict):
        for key in ("data", "ips", "results"):
            v = payload.get(key)
            if isinstance(v, list):
                rows = [r for r in v if isinstance(r, dict)]
                break

    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        ip = r.get("ip_address") or r.get("ip")
        if not isinstance(ip, str):
            continue
        ip = ip.strip()
        if ip:
            out[ip] = r
    return out


class FeodoTrackerProvider(Provider):
    name = "feodotracker"
    handles = frozenset({"ip"})
    ttl = timedelta(days=1)
    # Bulk download once per refresh window; per-IP lookup is in-memory.
    rate_limit = RateLimit(capacity=1000, refill_per_second=1000.0, daily_budget=None)

    def __init__(self, provider_cfg) -> None:
        super().__init__(provider_cfg)
        self._rows: dict[str, dict[str, Any]] = {}
        self._loaded_at: float = 0.0
        self._lock = threading.Lock()

    def _stale(self) -> bool:
        return (
            not self._rows
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
        return parse_feodo_response(payload)

    def _save_cache_file(self, payload: Any) -> None:
        p = Path(self.cfg.cache_file)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(payload))
        except OSError as exc:                       # pragma: no cover
            log.warning("feodotracker: persist cache failed %s: %s", p, exc)

    def _fetch_remote(self) -> tuple[dict[str, dict[str, Any]], Any]:
        try:
            r = httpx.get(self.cfg.feed_url, timeout=30.0)
            r.raise_for_status()
            payload = r.json()
        except (httpx.HTTPError, httpx.RequestError, ValueError) as exc:
            raise ProviderUnavailable(
                f"feodotracker: fetch {self.cfg.feed_url}: {exc}",
            ) from exc
        return parse_feodo_response(payload), payload

    def _ensure_loaded(self) -> None:
        if not self._stale():
            return
        with self._lock:
            if not self._stale():
                return
            cached = self._load_from_cache_file()
            if cached is not None:
                self._rows = cached
                self._loaded_at = time.time()
                return
            parsed, raw = self._fetch_remote()
            self._rows = parsed
            self._loaded_at = time.time()
            self._save_cache_file(raw)

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind != "ip":
            raise ValueError(f"feodotracker: cannot handle kind {artifact.kind!r}")
        self._ensure_loaded()
        row = self._rows.get(artifact.value)
        if row is None:
            derived = DerivedSignals(
                malicious=None, confidence=None, label=None, tags=(),
            )
            structured: dict[str, Any] = {
                "is_active_c2": False,
                "list_size": len(self._rows),
            }
            raw: dict[str, Any] = {"row": None}
        else:
            malware_family = (row.get("malware") or "").strip() or None
            port = row.get("port")
            first_seen = row.get("first_seen")
            tags: list[str] = ["feodo_c2"]
            if malware_family:
                tags.append(malware_family.lower())
            derived = DerivedSignals(
                malicious=True,
                confidence=9,                          # abuse.ch curation is high-precision
                label="feodo_c2",
                tags=tuple(tags),
            )
            structured = {
                "is_active_c2": True,
                "malware_family": malware_family,
                "port": int(port) if isinstance(port, (int, str)) and str(port).isdigit() else None,
                "first_seen": first_seen if isinstance(first_seen, str) else None,
                "list_size": len(self._rows),
            }
            raw = {"row": row}
        return ProviderResult.make(
            provider=self.name,
            artifact=artifact,
            structured=structured,
            raw=raw,
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
            detail=f"feodotracker loaded: {len(self._rows)} active C2 entries",
            extra={"list_size": len(self._rows)},
        )
