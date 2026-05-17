"""Provider interface.

A Provider is a thin adapter around one external threat-intel feed.
Each provider:

- Declares which artifact kinds it can answer (`handles`).
- Declares its result TTL (how long an answer stays fresh before the
  refresh worker re-queries).
- Declares its daily budget and rate-limit characteristics, so the
  worker can avoid overdraft on free-tier APIs.
- Implements `lookup(artifact)` returning a `ProviderResult` (or
  raising `ProviderError` / `ProviderRateLimited` / `ProviderUnavailable`
  for the worker to handle).

`derived_signals` on the result is the *normalised* form the consensus
rule reads — providers translate their own semantics into the same
small vocabulary so the rest of the pipeline doesn't need to know
about per-provider quirks.

This module is pure-interface — no network, no provider implementations.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..artifact import Artifact


class ProviderError(Exception):
    """Generic provider failure. Worker logs + counts toward circuit-breaker."""


class ProviderRateLimited(ProviderError):
    """Provider returned a rate-limit response. Worker should back off."""


class ProviderUnavailable(ProviderError):
    """Provider is unreachable (network, DNS, 5xx). Transient."""


@dataclass(frozen=True)
class DerivedSignals:
    """Normalised provider verdict for the consensus rule.

    Every provider populates this from its own response. The consensus
    rule (see `writer.compute_derived`) reads only this; the raw
    provider payload is preserved for analyst inspection but isn't
    consulted by automated logic.

    The original (2026-05-16) consensus rule was pure any-positive.
    The 2026-05-17 refinement adds two boolean tags so authoritative
    benign verdicts (GreyNoise `benign` / RIOT for known-good
    infrastructure like ShadowServer) can override aggregator-based
    malicious votes (AbuseIPDB community reports, FireHOL aggregator)
    — but NOT direct-observation malicious votes (FeodoTracker active
    C2, GreyNoise's own malicious classification). See
    `writer.compute_derived` for the rule.
    """
    # Tri-state malicious flag. None means "provider has no opinion / no
    # data on this artifact." True/False are explicit verdicts.
    malicious: Optional[bool] = None
    # Provider's own confidence in its verdict, 0-10. None when not
    # provided. Used for tie-breaking and display weighting only.
    confidence: Optional[int] = None
    # Short categorical label: "scanner" | "botnet" | "tor_exit" |
    # "blocklisted" | "benign" | "research" | "unknown".
    # Free-form by convention; the consensus rule keys on `malicious`
    # not `label`.
    label: Optional[str] = None
    # Optional human-readable tags ("mirai", "ssh-bruteforce", etc.).
    tags: tuple[str, ...] = ()
    # Provider asserts this artifact is benign with high confidence.
    # Currently set by GreyNoise on `classification=benign` AND on
    # `riot=true` — both are well-curated GreyNoise-internal lists of
    # known-good infrastructure (ShadowServer, Cloudflare DNS, etc.).
    # The consensus rule uses this to override aggregator-only
    # malicious votes (AbuseIPDB false positives on legitimate
    # scanners are the canonical case).
    authoritative_clean: bool = False
    # Provider's `malicious=True` is from direct observation of bad
    # behaviour by this provider, not from aggregated community
    # reports. Set by FeodoTracker (sees IPs hosting C2 right now)
    # and GreyNoise (classification="malicious" is their own
    # observation). NOT set by AbuseIPDB / FireHOL / ISC which
    # aggregate community/feed reports. Authoritative-clean cannot
    # override a direct malicious vote.
    evidence_direct: bool = False


@dataclass(frozen=True)
class ProviderResult:
    """The outcome of one provider lookup against one artifact."""
    provider: str
    artifact: Artifact
    structured: dict[str, Any]   # provider-specific extracted fields
    raw: dict[str, Any]          # full upstream response (for analyst trust)
    derived: DerivedSignals      # normalised verdict for the consensus rule
    fetched_at: datetime
    ttl_expires_at: datetime

    @classmethod
    def make(
        cls,
        *,
        provider: str,
        artifact: Artifact,
        structured: dict[str, Any],
        raw: dict[str, Any],
        derived: DerivedSignals,
        ttl: timedelta,
        now: Optional[datetime] = None,
    ) -> "ProviderResult":
        """Convenience builder — fills in `fetched_at` + `ttl_expires_at`."""
        t = now or datetime.now(timezone.utc)
        return cls(
            provider=provider,
            artifact=artifact,
            structured=structured,
            raw=raw,
            derived=derived,
            fetched_at=t,
            ttl_expires_at=t + ttl,
        )


@dataclass
class RateLimit:
    """Token-bucket spec. Reified into runtime state by the queue worker.

    `capacity` tokens, refilling at `refill_per_second`. A `lookup` call
    consumes one token; the worker blocks (or skips, configurably) when
    the bucket is empty.

    `daily_budget` is a separate, harder ceiling — once exhausted for
    the UTC day, the worker stops dispatching to this provider until
    midnight UTC regardless of bucket state. Set to None to disable
    the daily ceiling (e.g. Tor / Spamhaus which are effectively
    unmetered).
    """
    capacity: int = 10
    refill_per_second: float = 1.0
    daily_budget: Optional[int] = None


@dataclass
class HealthStatus:
    """Returned by `Provider.health()`. Surfaced by `healthcheck --scope intel`."""
    ok: bool
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class Provider(ABC):
    """Base class for threat-intel providers.

    Subclasses set the class-level descriptors below and implement
    `lookup` + (optionally) `health`. Construction takes the provider's
    own config (a sub-block of `cfg.intel.providers.<name>`).

    `lookup` is sync — the refresh worker dispatches one provider per
    asyncio task and wraps sync calls in `asyncio.to_thread`. This keeps
    provider implementations simple (most are urllib / dnspython
    one-liners) while still parallelising across providers.
    """

    # Class-level descriptors — subclasses override.
    name: str = ""                       # e.g. "tor", "spamhaus", "isc"
    handles: frozenset[str] = frozenset()  # artifact kinds this provider answers
    ttl: timedelta = timedelta(days=1)
    rate_limit: RateLimit = field(default_factory=RateLimit)  # type: ignore[assignment]

    def __init__(self, provider_cfg: Any) -> None:
        """Override to consume provider-specific config (api key, base url, …)."""
        self.cfg = provider_cfg

    @abstractmethod
    def lookup(self, artifact: Artifact) -> ProviderResult:
        """Look the artifact up. Raises ProviderError on failure."""

    def health(self) -> HealthStatus:
        """Lightweight liveness check. Default: assume OK."""
        return HealthStatus(ok=True, detail=f"{self.name}: no health check implemented")

    def __repr__(self) -> str:  # pragma: no cover — debug only
        return f"<Provider {self.name} handles={sorted(self.handles)}>"
