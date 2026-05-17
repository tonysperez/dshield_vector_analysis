"""Intel refresh orchestrator.

One pass over the priority queue: for each enabled provider, pop the
top-N artifacts it can handle, call `provider.lookup`, group results
by artifact, and write through `writer.upsert_intel_doc`.

The worker is intentionally sync. Milestone-1 providers are either
local-in-memory (Tor, ISC after the periodic bulk fetch) or a single
DNS round-trip (Spamhaus), so async parallelism would not pay off
yet. When a paid HTTP-API provider lands (GreyNoise, AbuseIPDB) the
worker can be promoted to asyncio with no shape change to providers
themselves.

Circuit-breaker policy:

- After `_FAILURE_THRESHOLD` consecutive failures, the provider's
  circuit is opened and the rest of the run skips it.
- The breaker resets on the next successful call (any future run).
- Per-call failures don't poison other providers; each is isolated.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from ..cache import StateDB
from ..config import AppConfig, Secrets
from ..es_client import make_client
from .artifact import Artifact
from .providers.base import (
    Provider,
    ProviderError,
    ProviderRateLimited,
    ProviderResult,
    ProviderUnavailable,
)
from .providers.abuseipdb import AbuseIPDBProvider
from .providers.feodotracker import FeodoTrackerProvider
from .providers.firehol import FireholProvider
from .providers.greynoise import GreyNoiseProvider
from .providers.isc import ISCProvider
from .providers.threatfox import ThreatFoxProvider
from .providers.tor import TorProvider
from .providers.urlhaus import URLhausProvider
from .queue import discover_and_enqueue
from .writer import upsert_intel_doc

log = logging.getLogger(__name__)


# After this many consecutive failures, open the provider's circuit
# and skip it for the rest of the run. Low number — the worker is
# called frequently from the backward systemd pass, so a transient
# provider outage gets retried on the next pass without piling more
# damage in this one.
_FAILURE_THRESHOLD = 5

# Defensive ceiling on `intel_queue_pop_top` per kind per run. There
# is intentionally NO artifact-dispatch cap (a runaway queue is
# better discovered than silently truncated), but a buggy producer
# enqueuing billions of rows shouldn't OOM the worker. Million-row
# horizon is well above any realistic honeypot corpus.
_QUEUE_FETCH_HARD_LIMIT = 1_000_000


def _build_providers(cfg: AppConfig, secrets: Optional[Secrets] = None) -> list[Provider]:
    """Construct the enabled providers from config.

    New providers are added here. Order is the dispatch order per
    artifact — cheap/local first so a single artifact's enrichment
    has its in-memory hits computed before any network calls.

    M1 providers (`tor`, `isc`, `feodotracker`, `firehol`) are bulk-
    download style: one fetch per refresh window, then in-memory
    lookup. M2 providers (`greynoise`, `abuseipdb`) are per-IP HTTP
    calls with daily-budget gates enforced by the worker via the
    SQLite spend tracker.

    `secrets` carries the M2 API keys. When unset, or when the
    relevant `*_api_key` field is None, the corresponding M2 provider
    silently skips construction — runtime degrades to "we run the
    M1 providers and skip the others." That keeps a missing key from
    being a fatal config error.
    """
    out: list[Provider] = []
    pc = cfg.intel.providers
    # abuse.ch unified auth key shared across URLhaus / ThreatFox /
    # FeodoTracker. Optional — providers accept None and fall back to
    # unauthenticated endpoints with tighter rate limits.
    abusech_key = (secrets.abuse_ch_auth_key if secrets else None)
    if pc.tor.enabled:
        out.append(TorProvider(pc.tor))
    if pc.isc.enabled:
        out.append(ISCProvider(pc.isc))
    if pc.feodotracker.enabled:
        out.append(FeodoTrackerProvider(pc.feodotracker, auth_key=abusech_key))
    if pc.firehol.enabled:
        out.append(FireholProvider(pc.firehol))
    gn_key = (secrets.greynoise_api_key if secrets else None)
    if pc.greynoise.enabled and gn_key:
        out.append(GreyNoiseProvider(pc.greynoise, gn_key))
    abuse_key = (secrets.abuseipdb_api_key if secrets else None)
    if pc.abuseipdb.enabled and abuse_key:
        out.append(AbuseIPDBProvider(pc.abuseipdb, abuse_key))
    # M4: URL-kind providers. abuse.ch family — accept optional
    # auth_key, work unauthenticated when None.
    if pc.urlhaus.enabled:
        out.append(URLhausProvider(pc.urlhaus, auth_key=abusech_key))
    if pc.threatfox.enabled:
        out.append(ThreatFoxProvider(pc.threatfox, auth_key=abusech_key))
    return out


def _utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_refresh(
    cfg: AppConfig, secrets: Secrets, *, dry_run: bool = False,
) -> dict[str, Any]:
    """Single refresh pass. Returns a stats dict suitable for `print(json.dumps(…))`.

    Steps:
      1. Build the provider set from config.
      2. Run discovery to repopulate the SQLite priority queue from
         the current IP rollup state.
      3. For each artifact kind, pop top-N from the queue and
         dispatch each artifact through every applicable provider.
      4. Group ProviderResults per artifact, write the merged doc to
         the intel-* index.
      5. Mark the artifact done in the queue when at least one
         provider returned data (others can retry next pass).
    """
    if not cfg.intel.enabled:
        return {"enabled": False, "skipped": True}

    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    providers = _build_providers(cfg, secrets)
    by_kind: dict[str, list[Provider]] = defaultdict(list)
    for p in providers:
        for kind in p.handles:
            by_kind[kind].append(p)

    stats: dict[str, Any] = {
        "enabled": True,
        "dry_run": dry_run,
        "providers": [p.name for p in providers],
        "discovered": {},
        "processed": {},
        "writes": 0,
        "errors": [],
        "provider_calls": {p.name: 0 for p in providers},
        "provider_failures": {p.name: 0 for p in providers},
        # Providers with a daily_budget that's already at-or-past its
        # limit when this run starts. Surfaced explicitly so a 0 in
        # `provider_calls` doesn't look mysterious — these are
        # waiting for the UTC midnight reset.
        "provider_budget_exhausted": [],
        "provider_circuits_open": [],
    }

    # Pre-flight: identify providers whose daily budget is already
    # exhausted (GreyNoise / AbuseIPDB after a few runs in one day).
    # Surfaced in stats; the per-call gate inside the dispatch loop
    # still enforces, but reporting upfront is clearer.
    today = _utc_today()
    budget_exhausted: set[str] = set()
    for prov in providers:
        budget = prov.rate_limit.daily_budget
        if budget is None:
            continue
        spent = db.intel_provider_calls_today(prov.name, today)
        if spent >= budget:
            budget_exhausted.add(prov.name)
            log.info(
                "intel: %s daily budget already exhausted "
                "(%d/%d); will skip this run, resets at UTC midnight",
                prov.name, spent, budget,
            )
    stats["provider_budget_exhausted"] = sorted(budget_exhausted)

    # Step 1: discovery (queue upsert).
    discovered = discover_and_enqueue(es, db, cfg)
    stats["discovered"] = discovered

    if dry_run:
        stats["queue_depth"] = db.intel_queue_depth()
        db.close()
        return stats

    # Step 2: per-kind processing. No artifact-dispatch cap — the
    # whole queue gets a chance per run. Per-provider daily budgets
    # (above) and circuit breakers (below) are the real safety
    # gates; unmetered bulk providers don't have or need a cap.
    circuits_open: set[str] = set()

    for kind, kind_providers in by_kind.items():
        # Pop the entire queue slice for this kind. `intel_queue_pop_top`
        # only RETURNS; it doesn't remove. Rows stay until
        # `intel_queue_mark_done` after a successful dispatch.
        kind_queue = db.intel_queue_pop_top(kind, _QUEUE_FETCH_HARD_LIMIT)
        artifacts: list[Artifact] = []
        for value, _prio in kind_queue:
            try:
                artifacts.append(Artifact(kind, value))
            except ValueError:
                continue

        for artifact in artifacts:
            results: list[ProviderResult] = []
            any_success = False
            for prov in kind_providers:
                if prov.name in circuits_open:
                    continue
                # Per-provider daily-budget gate. None means unmetered.
                budget = prov.rate_limit.daily_budget
                if budget is not None:
                    spent = db.intel_provider_calls_today(prov.name, today)
                    if spent >= budget:
                        continue
                try:
                    result = prov.lookup(artifact)
                except ProviderRateLimited as exc:
                    # Don't open circuit — just stop dispatching this
                    # provider for the rest of the run. It'll come back
                    # next pass.
                    circuits_open.add(prov.name)
                    stats["provider_failures"][prov.name] += 1
                    stats["errors"].append({
                        "provider": prov.name, "kind": artifact.kind,
                        "value": artifact.value, "error": f"rate_limited: {exc}",
                    })
                    continue
                except (ProviderUnavailable, ProviderError) as exc:
                    stats["provider_failures"][prov.name] += 1
                    db.intel_provider_record_failure(
                        prov.name, str(exc), _utc_now_iso(),
                        open_circuit=False,
                    )
                    state = db.intel_provider_get_state(prov.name)
                    if state["consecutive_failures"] >= _FAILURE_THRESHOLD:
                        circuits_open.add(prov.name)
                        db.intel_provider_record_failure(
                            prov.name, str(exc), _utc_now_iso(),
                            open_circuit=True,
                        )
                    stats["errors"].append({
                        "provider": prov.name, "kind": artifact.kind,
                        "value": artifact.value, "error": str(exc),
                    })
                    continue
                except Exception as exc:                # pragma: no cover
                    # Unknown failure mode — log loudly but don't crash the run.
                    log.exception("intel: unexpected error in %s.lookup", prov.name)
                    stats["provider_failures"][prov.name] += 1
                    stats["errors"].append({
                        "provider": prov.name, "kind": artifact.kind,
                        "value": artifact.value, "error": f"unexpected: {exc}",
                    })
                    continue
                results.append(result)
                any_success = True
                stats["provider_calls"][prov.name] += 1
                db.intel_provider_record_call(prov.name, today)
                db.intel_provider_record_success(prov.name, _utc_now_iso())

            if results:
                try:
                    upsert_intel_doc(es, cfg, artifact, results)
                    stats["writes"] += 1
                except Exception as exc:                # pragma: no cover
                    stats["errors"].append({
                        "kind": artifact.kind, "value": artifact.value,
                        "error": f"upsert: {exc}",
                    })
                    any_success = False

            if any_success:
                db.intel_queue_mark_done(artifact.kind, artifact.value)
            else:
                db.intel_queue_mark_attempt(
                    artifact.kind, artifact.value, "all providers failed or skipped",
                )

        stats["processed"][kind] = stats["processed"].get(kind, 0) + len(artifacts)

    stats["provider_circuits_open"] = sorted(circuits_open)
    stats["queue_depth_after"] = db.intel_queue_depth()
    db.close()
    return stats


def run_backfill(
    cfg: AppConfig, secrets: Secrets, *, dry_run: bool = False,
) -> dict[str, Any]:
    """Force discovery to re-queue every artifact, then refresh.

    Same as `run_refresh` but bypasses the priority filter — useful
    after wiring up a new provider so existing artifacts get the new
    provider's coverage. Currently identical to `run_refresh` because
    discovery already upserts everything in the rollup unconditionally;
    kept as a separate verb so future scoping (e.g. age-based) has a
    home that won't break call sites.
    """
    return run_refresh(cfg, secrets, dry_run=dry_run)
