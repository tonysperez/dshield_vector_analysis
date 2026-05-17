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
from typing import Any

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
from .providers.feodotracker import FeodoTrackerProvider
from .providers.firehol import FireholProvider
from .providers.isc import ISCProvider
from .providers.tor import TorProvider
from .queue import discover_and_enqueue
from .writer import upsert_intel_doc

log = logging.getLogger(__name__)


# After this many consecutive failures, open the provider's circuit
# and skip it for the rest of the run. Low number — the worker is
# called frequently from the backward systemd pass, so a transient
# provider outage gets retried on the next pass without piling more
# damage in this one.
_FAILURE_THRESHOLD = 5


def _build_providers(cfg: AppConfig) -> list[Provider]:
    """Construct the enabled providers from config.

    New providers are added here. The order is the order of attempts —
    cheap/local providers first so a single artifact's enrichment has
    its in-memory hits computed before any network calls.

    All milestone-1 providers are bulk-download (one fetch per refresh
    window, then in-memory lookup) so per-artifact cost is the same
    across the set — order matters mostly for trace readability.
    """
    out: list[Provider] = []
    pc = cfg.intel.providers
    if pc.tor.enabled:
        out.append(TorProvider(pc.tor))
    if pc.isc.enabled:
        out.append(ISCProvider(pc.isc))
    if pc.feodotracker.enabled:
        out.append(FeodoTrackerProvider(pc.feodotracker))
    if pc.firehol.enabled:
        out.append(FireholProvider(pc.firehol))
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
    providers = _build_providers(cfg)
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
        "provider_circuits_open": [],
    }

    # Step 1: discovery (queue upsert).
    discovered = discover_and_enqueue(es, db, cfg)
    stats["discovered"] = discovered

    if dry_run:
        stats["queue_depth"] = db.intel_queue_depth()
        db.close()
        return stats

    # Step 2: per-kind processing.
    today = _utc_today()
    max_total = cfg.intel.max_per_run
    processed = 0
    circuits_open: set[str] = set()

    for kind, kind_providers in by_kind.items():
        if processed >= max_total:
            break
        # Pop a chunk of artifacts for this kind. Same cap so a high-
        # volume kind doesn't starve other kinds.
        remaining_budget = max_total - processed
        artifacts: list[Artifact] = []
        for value, _prio in db.intel_queue_pop_top(kind, remaining_budget):
            try:
                artifacts.append(Artifact(kind, value))
            except ValueError:
                continue

        for artifact in artifacts:
            if processed >= max_total:
                break
            processed += 1
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
