"""abuse.ch ThreatFox provider — per-IOC IOC database lookup.

ThreatFox is abuse.ch's general-purpose IOC database covering URLs,
IPs, domains, and hashes tied to known malware families. Unlike
URLhaus (a bulk-download list), ThreatFox is a per-IOC HTTP POST
API — small per-lookup cost but always-fresh data.

API:
    POST https://threatfox-api.abuse.ch/api/v1/
    Headers: Auth-Key: <optional; not required>
    Body:    {"query": "search_ioc", "search_term": "<ioc value>"}
    Returns: {"query_status": "ok", "data": [{...iocs...}]}

The data array can contain multiple entries (same IOC reported by
different sources). We pick the highest-confidence_level entry to
drive the label/tags; tags from all entries are unioned.

ThreatFox supports four IOC types in our pipeline today:
  - url            (M4)
  - ipv4 / ipv6    (cross-checks the existing IP store)
  - domain         (latent until M5+)
  - sha256_hash / md5_hash / sha1_hash (latent)

For M4 scope we wire up only `url`. The provider is structured so
adding `ip`/`domain`/`hash` later is a single-line `handles` change.

No API key needed for low-volume use. Free tier is generous (the
upstream docs say no enforced rate limit, but politeness applies).
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Any, Optional

import httpx

from ..artifact import Artifact
from .base import (
    DerivedSignals,
    HealthStatus,
    Provider,
    ProviderResult,
    ProviderRateLimited,
    ProviderUnavailable,
    RateLimit,
)

log = logging.getLogger(__name__)


def classify_threatfox(
    data: list[dict[str, Any]],
) -> tuple[Optional[bool], Optional[str], Optional[int], tuple[str, ...], bool, bool]:
    """Pure-function: ThreatFox `data` array → DerivedSignals fields.

    Returns `(malicious, label, confidence, tags, authoritative_clean,
    evidence_direct)`. Picks the entry with the highest
    `confidence_level` to drive the label.

    ThreatFox's `confidence_level` is 0-100; we map linearly into the
    1-10 range: 100 → 10, 75 → 8, 50 → 5, 25 → 3. Below 50 we
    don't flip malicious=True (the upstream curation considers <50
    low-quality). Above 50 → malicious=True with the mapped
    confidence.

    `evidence_direct=False`: ThreatFox aggregates community
    submissions, even if well-curated. Same semantics as URLhaus.
    """
    if not data:
        return None, None, None, (), False, False
    # Highest-confidence entry drives the verdict.
    best = max(
        data,
        key=lambda e: int(e.get("confidence_level") or 0),
    )
    confidence_level = int(best.get("confidence_level") or 0)
    threat_type = (best.get("threat_type") or "").strip().lower() or None
    malware = (best.get("malware") or "").strip().lower() or None
    malware_alias = (best.get("malware_alias") or "").strip().lower() or None

    if confidence_level < 50:
        # Informational: ThreatFox has data but the entries are
        # low-confidence (<50). Tag and label, but don't vote malicious.
        tags = ("threatfox_low_confidence",)
        if malware:
            tags = tags + (malware,)
        return None, "threatfox_low", None, tags, False, False

    # 50–100 → confidence 5–10 (linear)
    confidence = max(5, min(10, 5 + int(round((confidence_level - 50) / 10.0))))

    tags_list: list[str] = ["threatfox_match"]
    if threat_type:
        tags_list.append(f"threatfox_type_{threat_type.replace(' ', '_')}")
    if malware:
        tags_list.append(malware)
    if malware_alias and malware_alias != malware:
        tags_list.append(malware_alias)
    # De-dupe in case malware/alias collided after normalisation.
    seen: set[str] = set()
    tags = tuple(t for t in tags_list if not (t in seen or seen.add(t)))

    label = f"threatfox_{threat_type}" if threat_type else "threatfox_match"
    return True, label, confidence, tags, False, False


class ThreatFoxProvider(Provider):
    name = "threatfox"
    # M4 scope: URL only. Future M4+ can extend to ip / domain / hash.
    handles = frozenset({"url"})

    def __init__(self, provider_cfg, auth_key: Optional[str] = None) -> None:
        super().__init__(provider_cfg)
        self.ttl = timedelta(days=int(provider_cfg.ttl_days))
        self.rate_limit = RateLimit(
            capacity=10, refill_per_second=2.0, daily_budget=None,
        )
        # abuse.ch unified auth: when ABUSE_CH_AUTH_KEY is set in .env,
        # send as `Auth-Key`. Without it, the public endpoint still
        # accepts requests but with tighter rate limits.
        headers = {
            "Accept": "application/json",
            "User-Agent": "dshield_prism/intel (threatfox)",
        }
        if auth_key:
            headers["Auth-Key"] = auth_key
        self._client = httpx.Client(
            timeout=float(provider_cfg.request_timeout_seconds),
            headers=headers,
        )
        self._authenticated = bool(auth_key)
        self._last_call: float = 0.0

    def _throttle(self) -> None:
        gap = float(self.cfg.min_inter_call_seconds)
        if gap <= 0:
            return
        delta = time.monotonic() - self._last_call
        if delta < gap:
            time.sleep(gap - delta)

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind not in self.handles:
            raise ValueError(f"threatfox: cannot handle kind {artifact.kind!r}")
        self._throttle()
        body = {"query": "search_ioc", "search_term": artifact.value}
        try:
            r = self._client.post(self.cfg.base_url, json=body)
        except (httpx.HTTPError, httpx.RequestError) as exc:
            raise ProviderUnavailable(f"threatfox: HTTP {exc}") from exc
        finally:
            self._last_call = time.monotonic()

        if r.status_code == 429:
            raise ProviderRateLimited(
                f"threatfox: rate-limited (429): {r.text[:200]}"
            )
        if r.status_code != 200:
            raise ProviderUnavailable(
                f"threatfox: HTTP {r.status_code}: {r.text[:200]}"
            )

        try:
            payload = r.json()
        except ValueError as exc:
            raise ProviderUnavailable(f"threatfox: non-JSON body: {exc}") from exc

        status = (payload.get("query_status") or "").strip().lower()
        if status == "no_result":
            # ThreatFox explicitly says no match. Treat as no opinion.
            derived = DerivedSignals(
                malicious=None, confidence=None, label=None,
                tags=(), authoritative_clean=False, evidence_direct=False,
            )
            structured = {"in_threatfox": False}
            return ProviderResult.make(
                provider=self.name, artifact=artifact,
                structured=structured, raw=payload,
                derived=derived, ttl=self.ttl,
            )
        if status != "ok":
            raise ProviderUnavailable(
                f"threatfox: unexpected query_status={status!r}"
            )

        data = payload.get("data") or []
        if not isinstance(data, list):
            data = []

        (malicious, label, confidence, tags,
         ac, ed) = classify_threatfox(data)
        derived = DerivedSignals(
            malicious=malicious, confidence=confidence, label=label,
            tags=tags, authoritative_clean=ac, evidence_direct=ed,
        )
        # Pull the highest-confidence entry's fields for structured.
        best = max(data, key=lambda e: int(e.get("confidence_level") or 0)) if data else {}
        structured = {
            "in_threatfox": bool(data),
            "threat_type": best.get("threat_type"),
            "malware": best.get("malware"),
            "malware_alias": best.get("malware_alias"),
            "confidence_level": int(best.get("confidence_level") or 0) if data else None,
            "first_seen": best.get("first_seen"),
            "last_seen": best.get("last_seen"),
        }
        return ProviderResult.make(
            provider=self.name, artifact=artifact,
            structured=structured, raw=payload,
            derived=derived, ttl=self.ttl,
        )

    def health(self) -> HealthStatus:
        # Probe with a known-bad URL — abuse.ch's own test IOC.
        # If a probe fails on auth/connectivity, surface it; the
        # exact no-result vs match path doesn't matter for health.
        self._throttle()
        try:
            r = self._client.post(
                self.cfg.base_url,
                json={"query": "search_ioc",
                      "search_term": "http://threatfox-test.invalid/"},
            )
        except (httpx.HTTPError, httpx.RequestError) as exc:
            return HealthStatus(ok=False, detail=f"threatfox health HTTP: {exc}")
        finally:
            self._last_call = time.monotonic()
        if r.status_code == 200:
            return HealthStatus(
                ok=True,
                detail=f"threatfox reachable (probe status={r.status_code})",
            )
        return HealthStatus(
            ok=False,
            detail=f"threatfox probe HTTP {r.status_code}: {r.text[:120]}",
        )
