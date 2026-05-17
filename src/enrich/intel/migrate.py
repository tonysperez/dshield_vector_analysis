"""In-place migration helpers for the intel subsystem.

The intel index docs are expensive: free-tier provider budgets (50
GreyNoise lookups per week, 1000 AbuseIPDB checks per day) make it
operationally unacceptable to wipe and re-fetch on every consensus-
rule change. `reapply_rules` recomputes verdicts from each doc's
already-persisted `providers.<name>.structured` data without touching
any upstream — same artifact data, fresh derived signals.

Today's scope is the 2026-05-17 consensus refinement (`authoritative_clean`
+ `evidence_direct` fields on `DerivedSignals`). Future rule changes
that need backfill should add their reclassifier to `_RECLASSIFIERS`
below and bump the smoke test.

The reclassifiers are pure functions — they don't depend on any
provider runtime state (no API keys needed, no network). Smoke-test
them at `scripts/smoke_test_intel_migrate.py`.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from ..cache import StateDB
from ..config import AppConfig, Secrets
from ..es_client import make_client
from .providers.abuseipdb import classify_abuseipdb
from .providers.base import DerivedSignals
from .providers.greynoise import classify_greynoise
from .writer import compute_derived, index_for_kind

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-provider reclassifiers — pure functions over a persisted provider block.
# ---------------------------------------------------------------------------


def reclassify_greynoise(block: dict[str, Any]) -> dict[str, Any]:
    """Recompute the GreyNoise provider block from its persisted structured data.

    The persisted `structured` carries `classification`, `noise`,
    `riot`, `name` — everything the classifier needs. We run the
    current `classify_greynoise` over it and overwrite the derived
    fields. `structured` and `raw` are unchanged; `fetched_at` and
    `ttl_expires_at` are preserved so the worker's freshness logic
    still treats the doc correctly.

    Idempotent — running reclassify twice gives the same result.
    Returns the updated block (does not mutate the input).
    """
    structured = block.get("structured") or {}
    classification = structured.get("classification")
    is_noise = bool(structured.get("noise"))
    is_riot = bool(structured.get("riot"))
    name = structured.get("name")
    (malicious, label, confidence, tags,
     authoritative_clean, evidence_direct) = classify_greynoise(
        classification, is_noise, is_riot, name,
    )
    out = dict(block)
    out["malicious"] = malicious
    out["confidence"] = confidence
    out["label"] = label
    out["tags"] = list(tags)
    out["authoritative_clean"] = authoritative_clean
    out["evidence_direct"] = evidence_direct
    return out


def reclassify_feodotracker(block: dict[str, Any]) -> dict[str, Any]:
    """Recompute FeodoTracker derived fields from its persisted structured data.

    The persisted `structured.is_active_c2` flag captures the only
    runtime decision the classifier makes; everything else is
    derived from it. Sets `evidence_direct=True` on hits (the
    2026-05-17 refinement).
    """
    structured = block.get("structured") or {}
    is_active = bool(structured.get("is_active_c2"))
    out = dict(block)
    if is_active:
        family = (structured.get("malware_family") or "").strip()
        tags = ["feodo_c2"]
        if family:
            tags.append(family.lower())
        out["malicious"] = True
        out["confidence"] = 9
        out["label"] = "feodo_c2"
        out["tags"] = tags
        out["authoritative_clean"] = False
        out["evidence_direct"] = True
    else:
        out["malicious"] = None
        out["confidence"] = None
        out["label"] = None
        out["tags"] = []
        out["authoritative_clean"] = False
        out["evidence_direct"] = False
    return out


def reclassify_passthrough(block: dict[str, Any]) -> dict[str, Any]:
    """No-op reclassifier — preserves the block but ensures the new fields
    exist on it (default False for both)."""
    out = dict(block)
    out.setdefault("authoritative_clean", False)
    out.setdefault("evidence_direct", False)
    return out


def reclassify_abuseipdb(block: dict[str, Any]) -> dict[str, Any]:
    """Recompute AbuseIPDB derived fields from persisted structured data.

    Picks up the 2026-05-17 `isWhitelisted` precedence branch on docs
    where that field was captured. For pre-fix docs (`is_whitelisted`
    absent from `structured`), it gracefully defaults to False and
    the verdict matches the original score-based logic — idempotent
    on docs that hadn't yet captured the field.

    Forward-fill: as natural TTL re-fetch populates `is_whitelisted`
    on existing IPs over the next few weeks, subsequent
    `reapply-rules` runs will pick up the newly-captured signal
    without re-fetching anything.
    """
    structured = block.get("structured") or {}
    abuse_score = structured.get("abuse_confidence_score")
    total_reports = structured.get("total_reports")
    usage_type = structured.get("usage_type")
    # The new field; absent on pre-fix docs (defaults False).
    is_whitelisted = bool(structured.get("is_whitelisted", False))
    (malicious, label, confidence, tags,
     authoritative_clean, evidence_direct) = classify_abuseipdb(
        abuse_score=abuse_score,
        total_reports=total_reports,
        usage_type=usage_type,
        is_whitelisted=is_whitelisted,
    )
    out = dict(block)
    out["malicious"] = malicious
    out["confidence"] = confidence
    out["label"] = label
    out["tags"] = list(tags)
    out["authoritative_clean"] = authoritative_clean
    out["evidence_direct"] = evidence_direct
    return out


_RECLASSIFIERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "greynoise":    reclassify_greynoise,
    "feodotracker": reclassify_feodotracker,
    "abuseipdb":    reclassify_abuseipdb,
    # Aggregator-only providers without per-field precedence — ensure
    # the new boolean fields exist at their default values.
    "tor":          reclassify_passthrough,
    "isc":          reclassify_passthrough,
    "firehol":      reclassify_passthrough,
}


# ---------------------------------------------------------------------------
# Per-doc rebuild — also a pure function over the doc body.
# ---------------------------------------------------------------------------


def rebuild_doc(source: dict[str, Any]) -> dict[str, Any]:
    """Take an intel doc body, return the updated body with rules reapplied.

    Iterates providers, runs the appropriate reclassifier on each,
    then recomputes the `derived` block. Pure function — no network,
    no state. Idempotent.
    """
    out = dict(source)
    providers = dict(source.get("providers") or {})
    new_providers: dict[str, dict[str, Any]] = {}
    for name, block in providers.items():
        reclassifier = _RECLASSIFIERS.get(name, reclassify_passthrough)
        new_providers[name] = reclassifier(block)
    out["providers"] = new_providers
    signals = [
        DerivedSignals(
            malicious=b.get("malicious"),
            confidence=b.get("confidence"),
            label=b.get("label"),
            tags=tuple(b.get("tags") or ()),
            authoritative_clean=bool(b.get("authoritative_clean", False)),
            evidence_direct=bool(b.get("evidence_direct", False)),
        )
        for b in new_providers.values()
    ]
    out["derived"] = compute_derived(signals)
    return out


# ---------------------------------------------------------------------------
# Orchestrator — iterates the intel index, writes updates in place.
# ---------------------------------------------------------------------------


def run_reapply_rules(
    cfg: AppConfig, secrets: Secrets, *, dry_run: bool = False,
) -> dict[str, Any]:
    """Walk intel-*-default and rewrite each doc with current rules.

    Returns a stats dict suitable for `json.dumps`. Doesn't touch any
    upstream provider — purely re-derives from persisted data.

    Today only `intel-dshield-ip-default` is in scope; URL / domain
    / hash indices will be added with M3.
    """
    if not cfg.intel.enabled:
        return {"enabled": False, "skipped": True}

    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)  # opened only to surface queue depth
    db.close()

    stats: dict[str, Any] = {
        "dry_run": dry_run,
        "processed": 0,
        "consensus_changes": 0,
        "override_distribution": {},
        "by_kind": {},
        "errors": [],
    }

    idx = index_for_kind(cfg, "ip")
    if not es.indices.exists(index=idx):
        stats["errors"].append({"index": idx, "error": "not found"})
        return stats

    # Use sliced scroll-equivalent: scroll API in one go is fine for
    # tens of thousands of docs. Bulk-write in batches of 500.
    page_size = 500
    body = {
        "size": page_size,
        "query": {"match_all": {}},
        "sort": [{"_doc": "asc"}],
    }
    bulk_actions: list[dict[str, Any]] = []
    search_after: list | None = None
    by_kind_count = 0

    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=idx, **body)
        except Exception as exc:                       # pragma: no cover
            stats["errors"].append({"index": idx, "error": f"search: {exc}"})
            break
        hits = resp.get("hits", {}).get("hits") or []
        if not hits:
            break
        for hit in hits:
            doc_id = hit["_id"]
            src = hit.get("_source") or {}
            before_mal = (src.get("derived") or {}).get("consensus_malicious")
            rebuilt = rebuild_doc(src)
            after_mal = rebuilt["derived"]["consensus_malicious"]
            after_override = rebuilt["derived"].get("override_applied", "")
            if before_mal != after_mal:
                stats["consensus_changes"] += 1
            stats["override_distribution"][after_override] = (
                stats["override_distribution"].get(after_override, 0) + 1
            )
            stats["processed"] += 1
            by_kind_count += 1
            if not dry_run:
                bulk_actions.append({"_op_type": "index", "_id": doc_id, "_source": rebuilt})
        if not dry_run and len(bulk_actions) >= page_size:
            _flush_bulk(es, idx, bulk_actions, stats)
        search_after = hits[-1]["sort"]

    if not dry_run and bulk_actions:
        _flush_bulk(es, idx, bulk_actions, stats)
        try:
            es.indices.refresh(index=idx)
        except Exception as exc:                       # pragma: no cover
            stats["errors"].append({"index": idx, "error": f"refresh: {exc}"})

    stats["by_kind"]["ip"] = by_kind_count
    return stats


def _flush_bulk(es, idx: str, actions: list[dict[str, Any]], stats: dict[str, Any]) -> None:
    """Submit pending bulk actions; record per-action errors into stats."""
    from elasticsearch import helpers
    if not actions:
        return
    try:
        success, errors = helpers.bulk(
            es, actions, index=idx,
            raise_on_error=False, raise_on_exception=False,
            stats_only=False,
        )
    except Exception as exc:                           # pragma: no cover
        stats["errors"].append({"index": idx, "error": f"bulk: {exc}"})
        actions.clear()
        return
    for e in errors or []:
        stats["errors"].append({"index": idx, "error": str(e)[:300]})
    actions.clear()
