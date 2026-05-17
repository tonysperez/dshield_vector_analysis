"""GreyNoise Community provider — per-IP background-radiation classifier.

Why this is the highest-value M2 integration: GreyNoise scans the
internet continuously and labels IPs by what they appear to be doing
*everywhere* — mass scanners, benign researchers (Censys, Shodan,
Shadowserver), known-malicious actors, etc. That's exactly the
discrimination local novelty is reaching for from a single sensor.
An IP that scores high local novelty AND is unknown to GreyNoise is a
much stronger research lead than one GreyNoise tags as a noisy mass
scanner.

The Community endpoint:
    GET https://api.greynoise.io/v3/community/<ip>
    headers:
      key: <your api key>
      Accept: application/json

Response shape (current as of 2026; defensive parser handles unknowns):

    {
      "ip": "1.2.3.4",
      "noise": true,
      "riot": false,
      "classification": "malicious" | "benign" | "unknown",
      "name": "Mirai botnet",
      "link": "https://viz.greynoise.io/ip/1.2.3.4",
      "last_seen": "2026-05-15",
      "message": "...",
    }

    404 with body `{"message": "IP not observed scanning the internet"}`
    is GreyNoise's "no opinion" response — we surface as
    `malicious=None` (no opinion), `label=None`, no tags. Important:
    this is NOT the same as "benign" — most truly-novel IPs return
    404 because GreyNoise hasn't seen them.

Rate limits: free-tier Community plan is ~10,000 requests/month;
short-burst rate-limit kicks in around 1 req/sec. Provider sleeps
`min_inter_call_seconds` between calls to stay below. HTTP 429
maps to `ProviderRateLimited` so the worker stops dispatching to
GreyNoise for the rest of the run.
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


# GreyNoise classification → DerivedSignals fields.
def classify_greynoise(
    classification: Optional[str],
    is_noise: bool,
    is_riot: bool,
    name: Optional[str],
) -> tuple[Optional[bool], Optional[str], Optional[int], tuple[str, ...], bool, bool]:
    """Pure-function: map a GreyNoise Community response to derived signals.

    Returns `(malicious, label, confidence, tags, authoritative_clean,
    evidence_direct)`. Centralised so the smoke test can exercise the
    verdict logic without HTTP.

    Classification branches are checked in priority order:

    - `classification=malicious` → malicious=True, evidence_direct=True
      (GreyNoise has its own observation of bad behaviour). Survives
      authoritative-clean overrides.
    - `classification=benign` → authoritative_clean=True (overrides
      aggregator-based malicious votes from AbuseIPDB / FireHOL etc.)
    - `classification=suspicious` → informational. GreyNoise itself
      is expressing concern, so RIOT below cannot override it; let
      other providers' votes decide consensus. Real-world case
      (130.131.195.135): Microsoft Azure RIOT-listed IP that GN
      *also* classifies suspicious — almost certainly a compromised
      VM. Without this branch, RIOT would wrongly demote it to clean.
    - `riot=true` (with no classification or `unknown`) → same as
      benign (RIOT = GreyNoise's known-good infrastructure list).
    - `noise=true` (no classification / no riot) → informational tag,
      no vote either way. Mass-scanning ≠ malicious by itself.
    - Anything else → no opinion.
    """
    c = (classification or "").strip().lower()
    name_lower = (name or "").strip()
    tags: list[str] = []

    if c == "malicious":
        # GreyNoise rarely uses this; reserved for IPs they have
        # active evidence against. Marked as direct evidence so an
        # authoritative-clean vote elsewhere can't override.
        tags.append("greynoise_malicious")
        if name_lower:
            tags.append(name_lower)
        return True, "greynoise_malicious", 9, tuple(tags), False, True
    if c == "benign":
        # GreyNoise's "benign" = curated known-good infrastructure
        # (Cloudflare DNS, ShadowServer, legit search bots, etc.).
        # This is the override signal — flips an AbuseIPDB false-
        # positive when no direct-evidence malicious vote disputes.
        tags.append("greynoise_benign")
        if name_lower:
            tags.append(name_lower)
        return False, "greynoise_benign", 8, tuple(tags), True, False
    if c == "suspicious":
        # GN classifies suspicious when it's seen the IP doing things
        # it doesn't like, short of "malicious" — concrete enough that
        # RIOT-listed infrastructure shouldn't override. Informational
        # only: contributes a label + tags but doesn't vote either
        # way. Lets aggregator providers (AbuseIPDB, FireHOL) decide
        # consensus. Real case driving this: 130.131.195.135 (MS Azure
        # RIOT + GN suspicious — compromised cloud VM).
        tags.append("greynoise_suspicious")
        if name_lower:
            tags.append(name_lower)
        return None, "greynoise_suspicious", 5, tuple(tags), False, False
    if is_riot:
        # RIOT (Rule-It-Out) = GreyNoise's known-good infrastructure
        # list. Same override semantics as benign.
        tags.append("greynoise_riot")
        if name_lower:
            tags.append(name_lower)
        return False, "greynoise_riot", 8, tuple(tags), True, False
    if is_noise:
        # The default "yeah we've seen this scanner widely" bucket.
        # Informational only — mass-scanning isn't a malicious verdict
        # without a classification to back it. ShadowServer is `noise:
        # true` AND `classification: benign` — handled by the benign
        # branch above, this branch is for noise-without-classification.
        tags.append("greynoise_noise")
        if name_lower:
            tags.append(name_lower)
        return None, "greynoise_noise", 6, tuple(tags), False, False
    # classification=="unknown" AND noise=false AND riot=false →
    # GreyNoise has seen this IP but has nothing to say. Could be a
    # genuinely-quiet attacker; we say "no opinion."
    return None, None, None, (), False, False


class GreyNoiseProvider(Provider):
    name = "greynoise"
    handles = frozenset({"ip"})

    def __init__(self, provider_cfg, api_key: str) -> None:
        super().__init__(provider_cfg)
        self.api_key = api_key
        self.ttl = timedelta(days=int(provider_cfg.ttl_days))
        self.rate_limit = RateLimit(
            capacity=10, refill_per_second=1.0,
            daily_budget=int(provider_cfg.daily_budget),
        )
        self._client = httpx.Client(
            timeout=float(provider_cfg.request_timeout_seconds),
            headers={
                "key": api_key,
                "Accept": "application/json",
                "User-Agent": "dshield_prism/intel (greynoise community)",
            },
        )
        self._last_call: float = 0.0

    def _throttle(self) -> None:
        """Stay under the per-second cap. Cheap; the worker is single-threaded."""
        gap = self.cfg.min_inter_call_seconds
        if gap <= 0:
            return
        delta = time.monotonic() - self._last_call
        if delta < gap:
            time.sleep(gap - delta)

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind != "ip":
            raise ValueError(f"greynoise: cannot handle kind {artifact.kind!r}")
        self._throttle()
        url = f"{self.cfg.base_url}/v3/community/{artifact.value}"
        try:
            r = self._client.get(url)
        except (httpx.HTTPError, httpx.RequestError) as exc:
            raise ProviderUnavailable(f"greynoise: HTTP {exc}") from exc
        finally:
            self._last_call = time.monotonic()

        if r.status_code == 429:
            raise ProviderRateLimited(
                f"greynoise: rate-limited (429): {r.text[:200]}"
            )
        if r.status_code == 401 or r.status_code == 403:
            raise ProviderUnavailable(
                f"greynoise: auth failed ({r.status_code}). Check GREYNOISE_API_KEY."
            )
        if r.status_code == 404:
            # GreyNoise has no opinion on this IP.
            derived = DerivedSignals(
                malicious=None, confidence=None, label=None, tags=(),
            )
            return ProviderResult.make(
                provider=self.name,
                artifact=artifact,
                structured={"in_greynoise": False},
                raw={"status": 404},
                derived=derived,
                ttl=self.ttl,
            )
        if r.status_code != 200:
            raise ProviderUnavailable(
                f"greynoise: HTTP {r.status_code}: {r.text[:200]}"
            )

        try:
            payload = r.json()
        except ValueError as exc:
            raise ProviderUnavailable(f"greynoise: non-JSON body: {exc}") from exc

        classification = payload.get("classification")
        is_noise = bool(payload.get("noise"))
        is_riot = bool(payload.get("riot"))
        name = payload.get("name")
        last_seen = payload.get("last_seen")
        link = payload.get("link")

        (malicious, label, confidence, tags,
         authoritative_clean, evidence_direct) = classify_greynoise(
            classification, is_noise, is_riot, name,
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
            "in_greynoise": True,
            "classification": classification,
            "name": name,
            "noise": is_noise,
            "riot": is_riot,
            "last_seen": last_seen,
            "link": link,
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
        # A known-quiet IP (Cloudflare's 1.1.1.1) typically returns a
        # RIOT entry — a successful response that doesn't burn through
        # a meaningful query. Don't fail the box if GreyNoise just
        # doesn't know about 1.1.1.1 — any non-error response means
        # the auth + connectivity are good.
        self._throttle()
        try:
            r = self._client.get(f"{self.cfg.base_url}/v3/community/1.1.1.1")
        except (httpx.HTTPError, httpx.RequestError) as exc:
            return HealthStatus(ok=False, detail=f"greynoise health HTTP: {exc}")
        finally:
            self._last_call = time.monotonic()
        if r.status_code in (200, 404):
            return HealthStatus(
                ok=True,
                detail=f"greynoise reachable; probe status={r.status_code}",
            )
        if r.status_code in (401, 403):
            return HealthStatus(
                ok=False,
                detail=f"greynoise auth failed ({r.status_code}) — check GREYNOISE_API_KEY",
            )
        return HealthStatus(
            ok=False,
            detail=f"greynoise probe HTTP {r.status_code}: {r.text[:120]}",
        )
