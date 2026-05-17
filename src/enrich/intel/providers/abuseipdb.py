"""AbuseIPDB provider — community abuse-confidence score per IP.

Endpoint:
    GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=<N>
    headers:
      Key: <your api key>
      Accept: application/json

Response shape:

    {
      "data": {
        "ipAddress": "1.2.3.4",
        "abuseConfidenceScore": 95,       # 0-100
        "totalReports": 412,
        "numDistinctUsers": 87,
        "lastReportedAt": "...",
        "countryCode": "RU",
        "isp": "...",
        "usageType": "Data Center/Web Hosting/Transit",
        "domain": "...",
        ...
      }
    }

Free tier: 1000 checks/day, ~10 req/sec. We treat
`abuseConfidenceScore >= 50` as `malicious=True`. The threshold is
conservative — AbuseIPDB's community reports aren't curated and a
score of 25 might be one revenge report. 50 is the canonical
"two or more independent reporters agree" line in their docs.
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


# Threshold for flipping malicious=True.
_MALICIOUS_SCORE_THRESHOLD = 50


def classify_abuseipdb(
    abuse_score: Optional[int],
    total_reports: Optional[int],
    usage_type: Optional[str],
    is_whitelisted: bool = False,
) -> tuple[Optional[bool], Optional[str], Optional[int], tuple[str, ...], bool, bool]:
    """Pure-function: AbuseIPDB response → derived signals.

    Returns `(malicious, label, confidence, tags, authoritative_clean,
    evidence_direct)`. Centralised so the smoke test can exercise the
    verdict logic without HTTP.

    Branch order (highest-priority first):

    - `is_whitelisted=True` → authoritative_clean=True. AbuseIPDB
      maintains its own curated whitelist (Cloudflare, Google, AWS,
      well-known scanners, etc.). Same character as GreyNoise RIOT —
      overrides aggregator-only malicious votes. Note: AbuseIPDB's
      whitelist is independent of their score; an IP can be both
      whitelisted AND have a moderate score (community submissions
      against a legitimate scanner). The whitelist flag wins.
    - `abuse_score >= 50` → malicious=True. NOT marked evidence_direct
      since the score is community-aggregated, not AbuseIPDB's own
      observation.
    - `abuse_score > 0` (but below threshold) → informational only.
      Tag carries the low score so analysts can sort the long tail.
    - score=None or 0 with no reports → no opinion.
    """
    if abuse_score is None:
        return None, None, None, (), False, False
    tags: list[str] = []
    if isinstance(usage_type, str) and usage_type.strip():
        # Useful research signal — "Data Center/Web Hosting/Transit"
        # vs "Fixed Line ISP" partitions actor populations cleanly.
        normalized = usage_type.replace(" ", "_").replace("/", "_").lower()
        tags.append(f"abuseipdb_usage:{normalized}")

    if is_whitelisted:
        # AbuseIPDB's own whitelist — curated, reliable. Overrides
        # aggregator votes the same way GN benign/RIOT does. We do
        # NOT consult the score here: a whitelisted IP with score 60
        # is the canonical case (community reports against a known-
        # good scanner) and we want the whitelist to win.
        tags.insert(0, "abuseipdb_whitelisted")
        return False, "abuseipdb_whitelisted", 8, tuple(tags), True, False

    if abuse_score >= _MALICIOUS_SCORE_THRESHOLD:
        # Map 50-100 score to 5-10 confidence band, monotonic.
        confidence = 5 + int(round((abuse_score - 50) / 10.0))
        confidence = max(5, min(10, confidence))
        tags.insert(0, f"abuseipdb_score_{abuse_score}")
        # NOT evidence_direct — community reports can be wrong (the
        # ShadowServer-class case). Aggregator-only vote.
        return True, "abuseipdb_high", confidence, tuple(tags), False, False

    # Below threshold — informational only. Score 0 vs score 25 isn't
    # a "benign vote", it's just "we have data but not enough to flag."
    # No malicious=False here — that would force a "benign" consensus
    # that's stronger than AbuseIPDB actually warrants.
    if total_reports and total_reports > 0:
        tags.insert(0, f"abuseipdb_low_score_{abuse_score}")
        return None, "abuseipdb_low", None, tuple(tags), False, False
    return None, None, None, tuple(tags), False, False


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    handles = frozenset({"ip"})

    def __init__(self, provider_cfg, api_key: str) -> None:
        super().__init__(provider_cfg)
        self.api_key = api_key
        self.ttl = timedelta(days=int(provider_cfg.ttl_days))
        self.rate_limit = RateLimit(
            capacity=10, refill_per_second=10.0,
            daily_budget=int(provider_cfg.daily_budget),
        )
        self._client = httpx.Client(
            timeout=float(provider_cfg.request_timeout_seconds),
            headers={
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "dshield_prism/intel (abuseipdb)",
            },
        )
        self._last_call: float = 0.0

    def _throttle(self) -> None:
        gap = self.cfg.min_inter_call_seconds
        if gap <= 0:
            return
        delta = time.monotonic() - self._last_call
        if delta < gap:
            time.sleep(gap - delta)

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind != "ip":
            raise ValueError(f"abuseipdb: cannot handle kind {artifact.kind!r}")
        self._throttle()
        url = f"{self.cfg.base_url}/api/v2/check"
        params = {
            "ipAddress": artifact.value,
            "maxAgeInDays": str(int(self.cfg.max_age_days)),
        }
        try:
            r = self._client.get(url, params=params)
        except (httpx.HTTPError, httpx.RequestError) as exc:
            raise ProviderUnavailable(f"abuseipdb: HTTP {exc}") from exc
        finally:
            self._last_call = time.monotonic()

        if r.status_code == 429:
            raise ProviderRateLimited(
                f"abuseipdb: rate-limited (429): {r.text[:200]}"
            )
        if r.status_code in (401, 403):
            raise ProviderUnavailable(
                f"abuseipdb: auth failed ({r.status_code}). Check ABUSEIPDB_API_KEY."
            )
        if r.status_code != 200:
            raise ProviderUnavailable(
                f"abuseipdb: HTTP {r.status_code}: {r.text[:200]}"
            )

        try:
            payload = r.json()
        except ValueError as exc:
            raise ProviderUnavailable(f"abuseipdb: non-JSON body: {exc}") from exc

        data = payload.get("data") or {}
        abuse_score = data.get("abuseConfidenceScore")
        total_reports = data.get("totalReports")
        usage_type = data.get("usageType")
        country = data.get("countryCode")
        isp = data.get("isp")
        last_reported = data.get("lastReportedAt")
        # 2026-05-17 expansion: AbuseIPDB has more useful fields than
        # we were capturing. `isWhitelisted` drives authoritative_clean
        # override (their own curated whitelist). `hostnames` + `domain`
        # are research-signal for the future Findings page / attribution.
        # `isTor` cross-checks our Tor provider — disagreement is signal.
        is_whitelisted = bool(data.get("isWhitelisted"))
        hostnames_raw = data.get("hostnames")
        hostnames = (
            [h for h in hostnames_raw if isinstance(h, str)]
            if isinstance(hostnames_raw, list) else []
        )
        domain = data.get("domain")
        is_tor = bool(data.get("isTor"))

        (malicious, label, confidence, tags,
         authoritative_clean, evidence_direct) = classify_abuseipdb(
            abuse_score=abuse_score,
            total_reports=total_reports,
            usage_type=usage_type,
            is_whitelisted=is_whitelisted,
        )
        derived = DerivedSignals(
            malicious=malicious,
            confidence=confidence,
            label=label,
            tags=tags,
            authoritative_clean=authoritative_clean,
            evidence_direct=evidence_direct,
        )
        structured = {
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "num_distinct_users": data.get("numDistinctUsers"),
            "country_code": country,
            "isp": isp,
            "usage_type": usage_type,
            "last_reported_at": last_reported,
            "is_whitelisted": is_whitelisted,
            "hostnames": hostnames,
            "domain": domain if isinstance(domain, str) else None,
            "is_tor": is_tor,
        }
        return ProviderResult.make(
            provider=self.name,
            artifact=artifact,
            structured=structured,
            raw=payload,
            derived=derived,
            ttl=self.ttl,
        )

    def health(self) -> HealthStatus:
        # Probe with 1.1.1.1 — known-clean infrastructure. Score should
        # be 0; any successful response confirms auth + connectivity.
        self._throttle()
        url = f"{self.cfg.base_url}/api/v2/check"
        try:
            r = self._client.get(url, params={"ipAddress": "1.1.1.1", "maxAgeInDays": "30"})
        except (httpx.HTTPError, httpx.RequestError) as exc:
            return HealthStatus(ok=False, detail=f"abuseipdb health HTTP: {exc}")
        finally:
            self._last_call = time.monotonic()
        if r.status_code == 200:
            try:
                d = r.json().get("data") or {}
            except ValueError:
                d = {}
            score = d.get("abuseConfidenceScore")
            return HealthStatus(
                ok=True,
                detail=f"abuseipdb reachable; 1.1.1.1 score={score}",
            )
        if r.status_code in (401, 403):
            return HealthStatus(
                ok=False,
                detail=f"abuseipdb auth failed ({r.status_code}) — check ABUSEIPDB_API_KEY",
            )
        return HealthStatus(
            ok=False,
            detail=f"abuseipdb probe HTTP {r.status_code}: {r.text[:120]}",
        )
