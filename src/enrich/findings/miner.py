"""Findings miner — produces one finding per playbook and one per campaign.

The earlier design (likely_discovery / axis_disagreement at IP+URL level)
gave a SOC-style triage inbox that didn't fit research-mode analysis.
Researchers think in playbooks (named behavior clusters) and campaigns
(multi-session patterns), and confirmed instances of those become the
accumulating knowledge base — the M6 attribution input and the eventual
sharing-back artifacts.

This miner emits one finding per playbook and per campaign every run.
The writer is responsible for preserving analyst-managed status across
re-mines, so the inbox naturally drains as the analyst ack/confirm/
rejects each card.

Runs hourly via systemd; ad-hoc via `dshield_prism mine findings`.
"""
from __future__ import annotations

import logging
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from elasticsearch import Elasticsearch

from ..config import AppConfig, Secrets
from ..es_client import init_index, make_client
from .writer import bulk_upsert_findings

log = logging.getLogger(__name__)

_FINDINGS_MAPPING = "setup/es-mappings/findings/default.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Playbook findings
# ---------------------------------------------------------------------------

def _latest_run_id(es: Elasticsearch, index: str) -> Optional[str]:
    """Return the most-recent run_id from the session_clusters index, or
    None if no run summary exists yet.

    Mirrors the console's RunCache logic — see `console.queries.RunCache`.
    """
    if not es.indices.exists(index=index):
        return None
    try:
        resp = es.search(
            index=index, size=1,
            query={"term": {"doc_type": "run_summary"}},
            sort=[{"@timestamp": {"order": "desc"}}],
            _source=["run_id"],
        )
        hits = resp.get("hits", {}).get("hits") or []
        if not hits:
            return None
        return (hits[0].get("_source") or {}).get("run_id")
    except Exception as exc:
        log.warning("findings: latest run lookup failed for %s: %s", index, exc)
        return None


def _cluster_to_playbook_map(
    es: Elasticsearch, clusters_idx: str, run_id: str, cluster_ids: list[str],
) -> dict[str, tuple[str, str]]:
    """Look up the centroid for each `(latest_run, cluster_id)` and return
    `{cluster_id: (playbook_id, playbook_name)}`. Either value can be empty
    when naming hasn't run for the latest clustering pass.
    """
    if not cluster_ids or not run_id:
        return {}
    out: dict[str, tuple[str, str]] = {}
    try:
        resp = es.search(
            index=clusters_idx,
            size=min(10000, max(len(cluster_ids) * 4, 100)),
            _source=["cluster_id", "playbook_id", "playbook_name"],
            query={"bool": {"must": [
                {"term": {"doc_type": "cluster"}},
                {"term": {"run_id": run_id}},
                {"terms": {"cluster_id": cluster_ids}},
            ]}},
        )
        for h in resp.get("hits", {}).get("hits") or []:
            src = h.get("_source") or {}
            cid = src.get("cluster_id")
            if cid and cid not in out:
                out[cid] = (
                    src.get("playbook_id") or "",
                    src.get("playbook_name") or "",
                )
    except Exception as exc:
        log.warning("findings: cluster-to-playbook lookup failed: %s", exc)
    return out


def _mine_playbooks(
    es: Elasticsearch, cfg: AppConfig, run_id: str,
) -> list[dict[str, Any]]:
    """Emit one finding per playbook (or per cluster when naming hasn't
    yet stamped the latest run).

    Why both: the session rollup carries
    `dshield.cowrie.enrichment.session.cluster.id` always (filled by the
    clustering pass), and `playbook_id` only after the naming pass has
    run AND the rollup hasn't been rebuilt since. The clean signal is
    `playbook_id` (content-addressed, stable across runs). The fallback
    is `cluster.id` (run-scoped, label-only) so the page still surfaces
    behavior groups in deployments where naming is out of sync.

    When a cluster centroid for the latest run carries a `playbook_id`,
    we use that as the artifact value — triage state persists across
    re-mines + re-clusters. When it doesn't, we use `cluster:<run_id>:<cluster_id>`,
    which is unique per cluster pass; the analyst's triage on those
    findings becomes stale on the next clustering run.
    """
    sess_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    if not es.indices.exists(index=sess_idx):
        log.info("findings: session rollup index %s missing — skipping playbooks", sess_idx)
        return []

    cluster_field = "dshield.cowrie.enrichment.session.cluster.id"
    try:
        resp = es.search(
            index=sess_idx, size=0,
            query={"bool": {"must": [
                {"exists": {"field": cluster_field}},
            ], "must_not": [
                # Outliers are HDBSCAN's "didn't fit anywhere" bucket;
                # surfacing every outlier session as one giant finding
                # is noise, not signal.
                {"term": {cluster_field: "outlier"}},
            ]}},
            aggs={"by_cluster": {
                "terms": {"field": cluster_field, "size": 2000, "min_doc_count": 1},
                "aggs": {
                    "unique_ips":    {"cardinality": {"field": "source.ip"}},
                    "first_seen":    {"min": {"field": "event.start"}},
                    "last_seen":     {"max": {"field": "event.start"}},
                    "mean_novelty":  {"avg": {"field":
                        "dshield.cowrie.enrichment.session.mean_novelty_score"}},
                    "dominant_intent": {"terms": {
                        "field": "dshield.cowrie.enrichment.session.dominant_intent",
                        "size": 1, "min_doc_count": 1,
                    }},
                },
            }},
        )
    except Exception as exc:
        log.warning("findings: cluster aggregation failed: %s", exc)
        return []

    buckets = (
        resp.get("aggregations", {}).get("by_cluster", {}).get("buckets") or []
    )
    if not buckets:
        return []

    cluster_ids = [b["key"] for b in buckets if b.get("key")]
    latest_run = _latest_run_id(es, clusters_idx) or ""
    cmap = _cluster_to_playbook_map(es, clusters_idx, latest_run, cluster_ids)

    out: list[dict[str, Any]] = []
    for b in buckets:
        cid = b.get("key")
        if not cid:
            continue
        session_count = int(b.get("doc_count") or 0)
        ip_count = int((b.get("unique_ips") or {}).get("value") or 0)
        first_seen = (b.get("first_seen") or {}).get("value_as_string") or ""
        last_seen = (b.get("last_seen") or {}).get("value_as_string") or ""
        mean_novelty = float((b.get("mean_novelty") or {}).get("value") or 0.0)
        intent_buckets = (b.get("dominant_intent") or {}).get("buckets") or []
        dominant_intent = intent_buckets[0]["key"] if intent_buckets else ""

        pid, name = cmap.get(cid, ("", ""))
        if pid:
            # Naming has stamped this cluster — stable artifact id.
            artifact_value = pid
            display = name or "(unnamed playbook)"
        else:
            # Fallback: cluster-scoped id. Unique per cluster run, so the
            # finding's triage state ages out on the next clustering pass.
            artifact_value = f"cluster:{latest_run}:{cid}"
            display = f"(unnamed cluster {cid})"

        # Score: log(1+sessions) * mean_novelty. Prevalence and novelty
        # both matter; the log compresses the long tail so an HDBSCAN
        # megacluster doesn't crowd out a tight, novel one. `+ 0.01`
        # floor keeps zero-novelty playbooks rankable.
        score = math.log1p(session_count) * (mean_novelty + 0.01)

        narrative = (
            f"{display} — {session_count} sessions across {ip_count} IPs; "
            f"mean novelty {mean_novelty:.2f}; "
            f"intent={dominant_intent or '?'}."
        )

        out.append({
            "kind": "playbook",
            "run_id": run_id,
            "artifact": {"kind": "playbook", "value": artifact_value},
            "score": score,
            "narrative": narrative,
            "evidence": {
                "playbook_id":      pid,
                "playbook_name":    name,
                "cluster_id":       cid,
                "cluster_run_id":   latest_run,
                "member_sessions":  session_count,
                "member_ips":       ip_count,
                "mean_novelty":     mean_novelty,
                "dominant_intent":  dominant_intent,
                "first_seen":       first_seen,
                "last_seen":        last_seen,
            },
        })

    out.sort(key=lambda f: f["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Campaign findings
# ---------------------------------------------------------------------------


def _mine_campaigns(
    es: Elasticsearch, cfg: AppConfig, run_id: str,
) -> list[dict[str, Any]]:
    """Emit one finding per campaign. The campaigns index already carries
    the headline fields (ip_count, session_count, first_seen, name,
    kind), so this is a straight scroll-and-shape pass."""
    idx = cfg.elasticsearch.indexes.cowrie.campaigns
    if not es.indices.exists(index=idx):
        log.info("findings: campaigns index %s missing — skipping campaigns", idx)
        return []

    out: list[dict[str, Any]] = []
    page_size = 500
    body: dict[str, Any] = {
        "size": page_size,
        "query": {"term": {"doc_type": "campaign"}},
        "_source": [
            "campaign_id", "name", "kind", "ip_count", "session_count",
            "first_seen", "last_seen", "support",
        ],
        "sort": [{"_doc": "asc"}],
    }
    search_after: Optional[list] = None
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=idx, **body)
        except Exception as exc:
            log.warning("findings: campaign scroll failed: %s", exc)
            break
        hits = resp.get("hits", {}).get("hits") or []
        if not hits:
            break
        for h in hits:
            src = h.get("_source") or {}
            cid = src.get("campaign_id") or h.get("_id")
            if not cid:
                continue
            name = src.get("name") or "(unnamed)"
            ip_count = int(src.get("ip_count") or 0)
            session_count = int(src.get("session_count") or 0)
            kind_sub = src.get("kind") or ""
            score = math.log1p(ip_count) * math.log1p(session_count)
            narrative = (
                f"{name} — {kind_sub or 'campaign'} • "
                f"{session_count} sessions across {ip_count} IPs."
            )
            out.append({
                "kind": "campaign",
                "run_id": run_id,
                "artifact": {"kind": "campaign", "value": cid},
                "score": score,
                "narrative": narrative,
                "evidence": {
                    "campaign_id":    cid,
                    "campaign_name":  name,
                    "campaign_kind":  kind_sub,
                    "member_ips":     ip_count,
                    "member_sessions": session_count,
                    "support":        int(src.get("support") or 0),
                    "first_seen":     src.get("first_seen") or "",
                    "last_seen":      src.get("last_seen") or "",
                },
            })
        search_after = hits[-1].get("sort")
        if not search_after:
            break

    out.sort(key=lambda f: f["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_mine(cfg: AppConfig, secrets: Secrets, dry_run: bool = False) -> dict[str, Any]:
    """Mine + write findings. Returns a stats dict.

    Reads from session rollup + session_clusters + campaigns. No threshold
    filter: every playbook + every campaign gets a finding doc. The
    inbox concept (status workflow) is what bounds the analyst's
    reading list, not a miner-side cutoff.
    """
    if not cfg.findings.enabled:
        return {"enabled": False, "skipped": True}

    es = make_client(cfg.elasticsearch, secrets)
    findings_idx = cfg.findings.indexes.default
    init_index(es, _FINDINGS_MAPPING, findings_idx)

    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)

    playbooks = _mine_playbooks(es, cfg, run_id)
    campaigns = _mine_campaigns(es, cfg, run_id)

    written_pb = 0
    written_cmp = 0
    if not dry_run:
        written_pb = bulk_upsert_findings(es, findings_idx, playbooks)
        written_cmp = bulk_upsert_findings(es, findings_idx, campaigns)
        try:
            es.indices.refresh(index=findings_idx)
        except Exception:
            pass

    elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
    stats = {
        "run_id": run_id,
        "dry_run": dry_run,
        "playbooks_mined":   len(playbooks),
        "playbooks_written": written_pb,
        "campaigns_mined":   len(campaigns),
        "campaigns_written": written_cmp,
        "elapsed_seconds":   round(elapsed, 2),
    }
    log.info("mine findings: %s", stats)
    return stats
