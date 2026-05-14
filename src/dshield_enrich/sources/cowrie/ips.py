"""Cowrie source-IP layer: rollup and clustering.

rollup-ips:  aggregate sessions per source IP. Incremental — only recomputes IPs
             whose sessions changed since the last run.
cluster-ips: HDBSCAN over IP embeddings (delegates to clustering core).

IP clusters are unnamed "actor profile" buckets. An IP's playbook membership
is derived from its sessions at query time, and campaigns (the multi-session
concept) are mined into a separate index by `dshield-enrich mine campaigns`.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterator, Optional

from elasticsearch import Elasticsearch

from ...cache import StateDB
from ...config import AppConfig, IPConfig, Secrets
from ...es_client import bulk_write, init_index, make_client
from .sessions import _mean_pool

log = logging.getLogger(__name__)

_IP_WATERMARK_KEY = "ip_rollup_last_processed_at"
_IPS_MAPPING = "es-mappings/cowrie/ips.json"
_IP_CLUSTERS_MAPPING = "es-mappings/cowrie/ip_clusters.json"

_IP_CLUSTER_UPDATE_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment.ip == null) { ctx._source.dshield.cowrie.enrichment.ip = [:]; }"
    "def ip = ctx._source.dshield.cowrie.enrichment.ip;"
    "if (ip.cluster == null) { ip.cluster = [:]; }"
    "ip.cluster.id = params.cluster_id;"
    "ip.cluster.novelty_score = params.novelty_score;"
    "ip.cluster.is_outlier = params.is_outlier;"
    "ip.cluster.scored_at = params.scored_at;"
)

_IP_CLUSTER_SAMPLE_SIZE = 5


# ---------------------------------------------------------------------------
# ES queries
# ---------------------------------------------------------------------------

def _iter_updated_session_ips(
    es: Elasticsearch,
    sessions_index: str,
    since: Optional[str],
    page_size: int = 1000,
) -> Iterator[str]:
    """Yield distinct source.ip values from session docs updated after `since`."""
    must: list[dict] = [{"exists": {"field": "source.ip"}}]
    if since:
        must.append({"range": {"@timestamp": {"gt": since}}})

    body: dict = {
        "size": page_size,
        "_source": ["source.ip"],
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    seen: set[str] = set()
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=sessions_index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            ip = (h["_source"].get("source") or {}).get("ip")
            if ip and ip not in seen:
                seen.add(ip)
                yield ip
        search_after = hits[-1]["sort"]


def _fetch_ip_session_docs(
    es: Elasticsearch,
    sessions_index: str,
    ip: str,
    page_size: int = 1000,
) -> list[dict]:
    """Fetch all session docs for a given source IP."""
    body: dict = {
        "size": page_size,
        "_source": [
            "source.geo", "source.as",
            "event.start", "event.end", "event.duration",
            "dshield.cowrie.enrichment.session.command_count",
            "dshield.cowrie.enrichment.session.login_success_count",
            "dshield.cowrie.enrichment.session.file_download_count",
            "dshield.cowrie.enrichment.session.dominant_intent",
            "dshield.cowrie.enrichment.session.mean_novelty_score",
            "dshield.cowrie.enrichment.session.max_novelty_score",
            "dshield.cowrie.enrichment.session.embedding",
            "cowrie.session_id",
        ],
        "query": {"term": {"source.ip": ip}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    results: list[dict] = []
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=sessions_index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        results.extend(h["_source"] for h in hits)
        search_after = hits[-1]["sort"]
    return results


# ---------------------------------------------------------------------------
# Rollup
# ---------------------------------------------------------------------------

def _build_ip_doc(
    ip: str,
    sessions: list[dict],
    cfg: AppConfig,
) -> dict:
    """Build an IP rollup doc from its session docs."""
    total_sessions = len(sessions)
    successful_sessions = 0
    command_sessions = 0
    total_commands = 0
    file_downloads = 0
    embeddings: list[list[float]] = []
    intents: list[str] = []
    novelty_scores: list[float] = []
    durations_s: list[float] = []
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    geo_info: dict = {}
    as_info: dict = {}

    for s in sessions:
        en = ((s.get("dshield") or {}).get("cowrie") or {}).get("enrichment", {}).get("session", {})
        ev = s.get("event") or {}

        if en.get("login_success_count", 0) >= 1:
            successful_sessions += 1
        if en.get("command_count", 0) >= 1:
            command_sessions += 1
        total_commands += en.get("command_count") or 0
        file_downloads += en.get("file_download_count") or 0

        emb = en.get("embedding")
        if emb:
            embeddings.append(emb)

        if en.get("dominant_intent"):
            intents.append(en["dominant_intent"])

        ns = en.get("mean_novelty_score")
        if ns is not None:
            novelty_scores.append(float(ns))

        dur = ev.get("duration")
        if dur is not None:
            durations_s.append(float(dur) / 1e9)

        start = ev.get("start")
        end = ev.get("end") or start
        if start:
            if not first_seen or start < first_seen:
                first_seen = start
        if end:
            if not last_seen or end > last_seen:
                last_seen = end

        if not geo_info and (s.get("source") or {}).get("geo"):
            geo_info = s["source"]["geo"]
        if not as_info and (s.get("source") or {}).get("as"):
            as_info = s["source"]["as"]

    embedding = _mean_pool(embeddings) if embeddings else None
    dominant_intent = Counter(intents).most_common(1)[0][0] if intents else None
    mean_novelty = round(sum(novelty_scores) / len(novelty_scores), 4) if novelty_scores else None
    max_novelty = round(max(novelty_scores), 4) if novelty_scores else None
    mean_duration_s = round(sum(durations_s) / len(durations_s), 2) if durations_s else None

    now = datetime.now(timezone.utc).isoformat()

    ip_block: dict = {
        "total_sessions": total_sessions,
        "successful_sessions": successful_sessions,
        "command_sessions": command_sessions,
        "total_commands": total_commands,
        "file_download_count": file_downloads,
        "embed_version": cfg.ip.embed_version,
    }
    if dominant_intent:
        ip_block["dominant_intent"] = dominant_intent
    if mean_novelty is not None:
        ip_block["mean_novelty_score"] = mean_novelty
    if max_novelty is not None:
        ip_block["max_novelty_score"] = max_novelty
    if mean_duration_s is not None:
        ip_block["mean_session_duration_s"] = mean_duration_s
    if first_seen:
        ip_block["first_seen"] = first_seen
    if last_seen:
        ip_block["last_seen"] = last_seen
    if embedding:
        ip_block["embedding"] = embedding

    source_block: dict = {"ip": ip}
    if geo_info:
        source_block["geo"] = geo_info
    if as_info:
        source_block["as"] = as_info

    return {
        "@timestamp": now,
        "source": source_block,
        "dshield": {
            "cowrie": {
                "enrichment": {
                    "ip": ip_block,
                }
            }
        },
    }


def run_rollup(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """Build/update IP rollup docs from the sessions index."""
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)

    ips_idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup

    since = db.get_watermark(_IP_WATERMARK_KEY)
    log.info("IP rollup watermark: %s", since or "(none, full backfill)")

    if not es.indices.exists(index=sessions_idx):
        db.close()
        raise RuntimeError(
            f"Sessions index '{sessions_idx}' not found. "
            "Run 'rollup sessions' first."
        )

    affected_ips = list(_iter_updated_session_ips(es, sessions_idx, since, cfg.ip.page_size))
    log.info("Found %d IPs with updated sessions", len(affected_ips))

    now = datetime.now(timezone.utc).isoformat()

    if not affected_ips:
        db.close()
        return {"affected_ips": 0, "dry_run": dry_run}

    if dry_run:
        db.close()
        return {"affected_ips": len(affected_ips), "dry_run": True}

    init_index(es, _IPS_MAPPING, ips_idx)

    stats: dict = defaultdict(int)
    actions: list[dict] = []

    for ip in affected_ips:
        sessions = _fetch_ip_session_docs(es, sessions_idx, ip, cfg.ip.page_size)
        if not sessions:
            stats["ips_no_sessions"] += 1
            continue

        doc = _build_ip_doc(ip, sessions, cfg)
        ip_block = doc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip", {})
        if ip_block.get("embedding"):
            stats["ips_with_embedding"] += 1

        actions.append({"_op_type": "index", "_id": ip, "_source": doc})
        stats["ips_built"] += 1

        if len(actions) >= cfg.ip.batch_size:
            ok, errs = bulk_write(es, ips_idx, actions)
            stats["bulk_ok"] += ok
            stats["bulk_errors"] += len(errs)
            if errs:
                log.warning("rollup-ips bulk errors (%d): %s", len(errs), errs[:2])
            actions = []

    if actions:
        ok, errs = bulk_write(es, ips_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("rollup-ips bulk errors (%d): %s", len(errs), errs[:2])

    # Explicit refresh so the next pipeline step (`cluster ips`) sees every
    # doc we just wrote. The ES mapping uses refresh_interval=30s, which
    # otherwise leaves a race window where cluster ips iterates a partial
    # snapshot of the rollup and silently leaves the trailing IPs unclustered.
    try:
        es.indices.refresh(index=ips_idx)
    except Exception as exc:
        log.warning("rollup-ips refresh failed (continuing): %s", exc)

    db.set_watermark(now, _IP_WATERMARK_KEY)
    log.info("IP rollup watermark advanced to %s", now)
    db.close()

    return dict(stats, affected_ips=len(affected_ips), ips_index=ips_idx, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Cluster IPs
# ---------------------------------------------------------------------------

def iter_ip_docs(
    es: Elasticsearch,
    index: str,
    page_size: int = 1000,
) -> Iterator[tuple[str, list[float], str, dict]]:
    """Yield (doc_id, embedding, source_ip, scalars)."""
    body: dict = {
        "size": page_size,
        "_source": [
            "source.ip",
            "dshield.cowrie.enrichment.ip.embedding",
            "dshield.cowrie.enrichment.ip.total_sessions",
            "dshield.cowrie.enrichment.ip.successful_sessions",
            "dshield.cowrie.enrichment.ip.mean_novelty_score",
            "dshield.cowrie.enrichment.ip.mean_session_duration_s",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.ip.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            ip_en = (
                ((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {}).get("ip", {})
            )
            emb = ip_en.get("embedding")
            if not emb:
                continue
            source_ip = (src.get("source") or {}).get("ip", h["_id"])
            total = ip_en.get("total_sessions") or 1
            success = ip_en.get("successful_sessions") or 0
            scalars = {
                "total_sessions": total,
                "login_success_rate": success / total,
                "mean_novelty_score": ip_en.get("mean_novelty_score") or 0.0,
                "mean_session_duration_s": ip_en.get("mean_session_duration_s") or 0.0,
            }
            yield h["_id"], emb, source_ip, scalars
        search_after = hits[-1]["sort"]


def build_ip_scalar_block(scalars_list: list[dict], weight: float) -> "np.ndarray":
    """(n, 4) weighted scalar matrix for IP-level HDBSCAN."""
    import numpy as np
    total = np.array([s.get("total_sessions") or 1 for s in scalars_list], dtype=np.float32)
    success_rate = np.array([s.get("login_success_rate", 0.0) for s in scalars_list], dtype=np.float32)
    novelty = np.array([s.get("mean_novelty_score", 0.0) for s in scalars_list], dtype=np.float32)
    duration = np.array([s.get("mean_session_duration_s", 0.0) for s in scalars_list], dtype=np.float32)

    max_total = float(np.max(total)) if total.max() > 0 else 1.0
    max_duration = float(np.max(duration)) if duration.max() > 0 else 1.0

    block = np.zeros((len(scalars_list), 4), dtype=np.float32)
    block[:, 0] = (np.log1p(total) / np.log1p(max_total)) * weight
    block[:, 1] = np.clip(success_rate, 0.0, 1.0) * weight
    block[:, 2] = np.clip(novelty, 0.0, 1.0) * weight
    block[:, 3] = (np.log1p(duration) / np.log1p(max_duration)) * weight
    return block


def run_cluster(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """HDBSCAN over IP embeddings. Delegates to clustering core."""
    from ...clustering import run_layer_clustering
    es = make_client(cfg.elasticsearch, secrets)
    ips_idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    clusters_idx = cfg.elasticsearch.indexes.cowrie.ip_clusters
    ipcfg: IPConfig = cfg.ip

    if not es.indices.exists(index=ips_idx):
        raise RuntimeError(
            f"IPs index '{ips_idx}' not found. "
            "Run 'rollup ips' first, or check elasticsearch.indexes.cowrie.ips_rollup in config."
        )

    return run_layer_clustering(
        es=es,
        docs_iter=iter_ip_docs(es, ips_idx, ipcfg.page_size),
        docs_index=ips_idx,
        clusters_index=clusters_idx,
        mapping_path=_IP_CLUSTERS_MAPPING,
        update_script=_IP_CLUSTER_UPDATE_SCRIPT,
        scalar_block_builder=build_ip_scalar_block,
        min_cluster_size=ipcfg.cluster_min_cluster_size,
        min_samples=ipcfg.cluster_min_samples,
        scalar_weight=ipcfg.cluster_scalar_weight,
        batch_size=ipcfg.batch_size,
        sample_size=_IP_CLUSTER_SAMPLE_SIZE,
        centroid_sample_field="sample_ips",
        dry_run=dry_run,
        layer_label="cowrie.ips",
    )
