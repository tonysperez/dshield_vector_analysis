"""Cowrie session layer: rollup, clustering, and playbook naming.

rollup-sessions: aggregate events per cowrie.session.closed into one session doc.
cluster-sessions: HDBSCAN over session embeddings (delegates to clustering core).
name-playbooks:   local LLM names each session cluster (a "playbook").
"""
from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterator, Optional

from elasticsearch import Elasticsearch

from ...cache import StateDB
from ...config import AppConfig, Secrets, SessionConfig
from ...es_client import bulk_write, make_client
from ...llm.schemas import PLAYBOOK_NAME_JSON_SCHEMA, PlaybookName
from .commands import hash_command, normalize

log = logging.getLogger(__name__)

_SESSION_WATERMARK_KEY = "session_last_processed_at"
_SESSIONS_MAPPING = "es-mappings/cowrie/sessions.json"
_SESSION_CLUSTERS_MAPPING = "es-mappings/cowrie/session_clusters.json"

_SESSION_CLUSTER_UPDATE_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment.session == null) { ctx._source.dshield.cowrie.enrichment.session = [:]; }"
    "def s = ctx._source.dshield.cowrie.enrichment.session;"
    "if (s.cluster == null) { s.cluster = [:]; }"
    "s.cluster.id = params.cluster_id;"
    "s.cluster.novelty_score = params.novelty_score;"
    "s.cluster.is_outlier = params.is_outlier;"
    "s.cluster.scored_at = params.scored_at;"
    # Re-clustering invalidates any playbook label on this session — the old
    # name was attached to a different clustering run. Clear so downstream
    # readers see "no playbook" until `name playbooks` reruns and refills
    # both fields from the new centroid. Otherwise session.playbook_id
    # would point at a stale playbook whose membership no longer matches
    # the new session.cluster.id.
    "s.remove('playbook_id');"
    "s.remove('playbook_name');"
)

_SESSION_PLAYBOOK_NAME_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment.session == null) { ctx._source.dshield.cowrie.enrichment.session = [:]; }"
    "ctx._source.dshield.cowrie.enrichment.session.playbook_id = params.playbook_id;"
    "ctx._source.dshield.cowrie.enrichment.session.playbook_name = params.playbook_name;"
)


def _make_playbook_id(run_id: str, group_id: str) -> str:
    """The canonical playbook primary key. Format: `sescl-<run_id>-<group_id>`.

    `group_id` is `pg<N>` where N is the merge-group index assigned by
    `merge_clusters_into_playbooks`. A playbook may map to one or more
    HDBSCAN clusters depending on `session.playbook_merge_threshold`. The
    id is the identity; the LLM `playbook_name` is a display label only and
    may legitimately duplicate across playbooks. Outlier clusters do not
    get a playbook_id — they're noise, not a behaviour group.
    """
    return f"sescl-{run_id}-{group_id}"


def merge_clusters_into_playbooks(
    centroids: dict[str, list[float]],
    threshold: float,
) -> dict[str, str]:
    """Group HDBSCAN cluster centroids into playbooks by cosine similarity.

    Two clusters whose L2-normalised centroids have cosine similarity ≥
    `threshold` are placed in the same playbook (single-linkage union-find
    over edges that clear the threshold). Returns `{cluster_id → group_id}`
    where group_id is `pg<N>` numbered deterministically: groups are
    sorted by their lex-smallest member cluster_id, then cluster_ids within
    each group are sorted lexicographically.

    `threshold = 1.0` only merges clusters with identical centroids
    (degenerate case from L2-normalisation rounding). For practical purposes
    it preserves 1-cluster-per-playbook unless duplicate centroids exist.

    Outliers should be filtered out *before* calling this — they have no
    centroid and shouldn't be grouped. Empty input → empty dict.
    """
    import numpy as np

    if not centroids:
        return {}

    cluster_ids = sorted(centroids.keys())
    n = len(cluster_ids)

    if n == 1:
        return {cluster_ids[0]: "pg0"}

    M = np.array([centroids[cid] for cid in cluster_ids], dtype=np.float32)
    norms = np.linalg.norm(M, axis=1, keepdims=True)
    norms = np.where(norms == 0.0, 1.0, norms)
    Mn = M / norms
    sim = Mn @ Mn.T  # (n, n) cosine since rows are unit vectors

    parent = list(range(n))
    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for i in range(n):
        for j in range(i + 1, n):
            if float(sim[i, j]) >= threshold:
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[ri] = rj

    # Collect groups, key them by lex-smallest member for deterministic numbering.
    by_root: dict[int, list[str]] = {}
    for idx, cid in enumerate(cluster_ids):
        by_root.setdefault(find(idx), []).append(cid)
    groups = sorted(by_root.values(), key=lambda members: members[0])

    out: dict[str, str] = {}
    for gidx, members in enumerate(groups):
        gid = f"pg{gidx}"
        for cid in members:
            out[cid] = gid
    return out


_SESSION_CLUSTER_SAMPLE_SIZE = 5


# ---------------------------------------------------------------------------
# Rollup: collect events + build session doc
# ---------------------------------------------------------------------------

def _iter_closed_sessions(
    es: Elasticsearch,
    index: str,
    since: Optional[str],
    page_size: int = 1000,
) -> Iterator[tuple[str, str]]:
    """Yield (session_id, closed_at) for cowrie.session.closed events after `since`."""
    must: list[dict] = [{"term": {"event.action": "cowrie.session.closed"}}]
    if since:
        must.append({"range": {"@timestamp": {"gt": since}}})

    body: dict = {
        "size": page_size,
        "_source": ["cowrie.session_id", "@timestamp"],
        "query": {"bool": {"must": must}},
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
            session_id = (src.get("cowrie") or {}).get("session_id")
            ts = src.get("@timestamp")
            if session_id and ts:
                yield session_id, ts
        search_after = hits[-1]["sort"]


def _fetch_session_events(
    es: Elasticsearch,
    index: str,
    session_ids: list[str],
    page_size: int = 1000,
) -> dict[str, list[dict]]:
    """Fetch all events for the given session_ids. Returns {session_id: [event_sources]}."""
    result: dict[str, list[dict]] = {sid: [] for sid in session_ids}

    body: dict = {
        "size": page_size,
        "_source": [
            "@timestamp", "event.action", "event.duration", "event.outcome",
            "source.ip", "source.port", "source.geo", "source.as",
            "destination.ip", "destination.port",
            "network.protocol", "network.type",
            "user.name", "user_agent.original",
            "cowrie.session_id", "cowrie.password", "cowrie.hassh_algorithms",
            "process.command_line",
        ],
        "query": {"terms": {"cowrie.session_id": session_ids}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }

    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            src = h["_source"]
            sid = (src.get("cowrie") or {}).get("session_id")
            if sid and sid in result:
                result[sid].append(src)
        search_after = hits[-1]["sort"]

    return result


def _mget_enrichment(
    es: Elasticsearch,
    index: str,
    hashes: list[str],
) -> dict[str, dict]:
    """Batch-fetch enrichment docs by command hash. Returns {hash: source}."""
    if not hashes:
        return {}
    resp = es.mget(index=index, ids=hashes)
    return {doc["_id"]: doc["_source"] for doc in resp["docs"] if doc.get("found")}


def _command_entropy(counts: dict[str, int]) -> float:
    """Shannon entropy (bits) of the command frequency distribution."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _mean_pool(embeddings: list[list[float]]) -> list[float]:
    """Mean-pool equal-length float vectors. Pure Python — no numpy required."""
    if not embeddings:
        return []
    dims = len(embeddings[0])
    result = [0.0] * dims
    n = len(embeddings)
    for emb in embeddings:
        for i, v in enumerate(emb):
            result[i] += v
    return [v / n for v in result]


def _build_session_doc(
    session_id: str,
    events: list[dict],
    enrichment_by_hash: dict[str, dict],
    cfg: AppConfig,
) -> dict:
    """Build a session rollup doc from raw events + pre-fetched enrichment data."""
    connect_event: Optional[dict] = None
    closed_event: Optional[dict] = None
    login_success_count = 0
    login_fail_count = 0
    file_download_count = 0
    file_upload_count = 0
    command_hashes: list[str] = []
    unique_hashes: set[str] = set()

    for ev in events:
        action = (ev.get("event") or {}).get("action", "")
        if action == "cowrie.session.connect":
            connect_event = ev
        elif action == "cowrie.session.closed":
            closed_event = ev
        elif action == "cowrie.login.success":
            login_success_count += 1
        elif action == "cowrie.login.failed":
            login_fail_count += 1
        elif action == "cowrie.session.file_download":
            file_download_count += 1
        elif action == "cowrie.session.file_upload":
            file_upload_count += 1
        elif action == "cowrie.command.input":
            cmd = (ev.get("process") or {}).get("command_line")
            if cmd:
                norm, _ = normalize(cmd, cfg.worker.command_max_chars)
                if norm:
                    h = hash_command(norm)
                    command_hashes.append(h)
                    unique_hashes.add(h)

    start_ts = (connect_event or {}).get("@timestamp") or (events[0].get("@timestamp") if events else None)
    end_ts = (closed_event or {}).get("@timestamp")
    anchor_ts = end_ts or start_ts
    duration_ns = ((closed_event.get("event") or {}).get("duration") if closed_event else None)

    source_info: dict = {}
    dest_info: dict = {}
    network_info: dict = {}
    user_info: dict = {}
    ua_info: dict = {}
    cowrie_extra: dict = {}

    for ev in events:
        if not source_info.get("ip") and (ev.get("source") or {}).get("ip"):
            source_info = ev["source"]
        if not dest_info.get("ip") and (ev.get("destination") or {}).get("ip"):
            dest_info = ev["destination"]
        if not network_info.get("protocol") and (ev.get("network") or {}).get("protocol"):
            network_info = ev["network"]
        if not user_info.get("name") and (ev.get("user") or {}).get("name"):
            user_info = ev["user"]
        if not ua_info.get("original") and (ev.get("user_agent") or {}).get("original"):
            ua_info = ev["user_agent"]
        cowrie = ev.get("cowrie") or {}
        if not cowrie_extra.get("password") and cowrie.get("password"):
            cowrie_extra["password"] = cowrie["password"]
        if not cowrie_extra.get("hassh_algorithms") and cowrie.get("hassh_algorithms"):
            cowrie_extra["hassh_algorithms"] = cowrie["hassh_algorithms"]

    embeddings: list[list[float]] = []
    intents: list[str] = []
    novelty_scores: list[float] = []
    confidences: list[float] = []

    for h in unique_hashes:
        enrich_doc = enrichment_by_hash.get(h)
        if not enrich_doc:
            continue
        en = ((enrich_doc.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
        emb = en.get("embedding")
        if emb:
            embeddings.append(emb)
        if en.get("intent"):
            intents.append(en["intent"])
        cluster = en.get("cluster") or {}
        ns = cluster.get("novelty_score")
        if ns is not None:
            novelty_scores.append(float(ns))
        c = en.get("confidence")
        if c is not None:
            confidences.append(float(c))

    embedding = _mean_pool(embeddings) if embeddings else None

    dominant_intent: Optional[str] = None
    if intents:
        dominant_intent = Counter(intents).most_common(1)[0][0]

    hash_counts = Counter(command_hashes)
    entropy = _command_entropy(dict(hash_counts))

    session_block: dict = {
        "command_count": len(command_hashes),
        "unique_commands": len(unique_hashes),
        "login_success_count": login_success_count,
        "login_fail_count": login_fail_count,
        "file_download_count": file_download_count,
        "file_upload_count": file_upload_count,
        "command_entropy": round(entropy, 4),
        "embed_version": cfg.session.embed_version,
    }
    if dominant_intent:
        session_block["dominant_intent"] = dominant_intent
    if novelty_scores:
        session_block["mean_novelty_score"] = round(sum(novelty_scores) / len(novelty_scores), 4)
        session_block["max_novelty_score"] = round(max(novelty_scores), 4)
    if confidences:
        session_block["mean_confidence"] = round(sum(confidences) / len(confidences), 2)
    if embedding:
        session_block["embedding"] = embedding

    doc: dict = {
        "@timestamp": anchor_ts,
        "event": {
            "kind": "enrichment",
            "category": ["network"],
            "dataset": "dshield.cowrie.enrichment.session",
        },
        "cowrie": {"session_id": session_id, **cowrie_extra},
        "dshield": {
            "cowrie": {
                "enrichment": {
                    "session": session_block,
                }
            }
        },
    }
    if start_ts:
        doc["event"]["start"] = start_ts
    if end_ts:
        doc["event"]["end"] = end_ts
    if duration_ns is not None:
        doc["event"]["duration"] = duration_ns
    if source_info:
        doc["source"] = source_info
    if dest_info:
        doc["destination"] = dest_info
    if network_info:
        doc["network"] = network_info
    if user_info:
        doc["user"] = user_info
    if ua_info:
        doc["user_agent"] = ua_info

    return doc


def run_rollup(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """Build/update session rollup docs from the events index."""
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)

    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands

    since = db.get_watermark(_SESSION_WATERMARK_KEY)
    log.info("Session watermark: %s", since or "(none, full backfill)")

    closed: list[tuple[str, str]] = list(
        _iter_closed_sessions(es, events_idx, since, cfg.session.page_size)
    )
    log.info("Found %d closed sessions since watermark", len(closed))

    if not closed:
        db.close()
        return {"closed_sessions_found": 0, "dry_run": dry_run}

    max_ts = max(ts for _, ts in closed)

    if dry_run:
        db.close()
        return {"closed_sessions_found": len(closed), "max_ts": max_ts, "dry_run": True}

    stats: dict = defaultdict(int)

    from ...es_client import init_index
    init_index(es, _SESSIONS_MAPPING, sessions_idx)

    session_ids_all = [sid for sid, _ in closed]
    page = cfg.session.page_size

    for batch_start in range(0, len(session_ids_all), page):
        batch_ids = session_ids_all[batch_start: batch_start + page]

        events_by_session = _fetch_session_events(es, events_idx, batch_ids)

        all_hashes: set[str] = set()
        for sid in batch_ids:
            for ev in events_by_session.get(sid, []):
                if (ev.get("event") or {}).get("action") == "cowrie.command.input":
                    cmd = (ev.get("process") or {}).get("command_line")
                    if cmd:
                        norm, _ = normalize(cmd, cfg.worker.command_max_chars)
                        if norm:
                            all_hashes.add(hash_command(norm))

        enrichment_by_hash = _mget_enrichment(es, commands_idx, list(all_hashes))
        stats["command_hashes_fetched"] += len(enrichment_by_hash)

        actions: list[dict] = []
        for sid in batch_ids:
            events = events_by_session.get(sid, [])
            if not events:
                stats["sessions_no_events"] += 1
                continue
            doc = _build_session_doc(sid, events, enrichment_by_hash, cfg)
            session_block = (
                doc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session", {})
            )
            if session_block.get("embedding"):
                stats["sessions_with_embedding"] += 1
            actions.append({"_op_type": "index", "_id": sid, "_source": doc})
            stats["sessions_built"] += 1

        if actions:
            ok, errs = bulk_write(es, sessions_idx, actions)
            stats["bulk_ok"] += ok
            stats["bulk_errors"] += len(errs)
            if errs:
                log.warning("rollup-sessions bulk errors (%d): %s", len(errs), errs[:2])

        log.info(
            "Processed batch %d/%d (%d sessions)",
            batch_start + len(batch_ids), len(session_ids_all), len(batch_ids),
        )

    # Explicit refresh so the next pipeline step (`cluster sessions`) and the
    # later `rollup ips` see every session doc we just wrote. The mapping
    # uses refresh_interval=30s, which otherwise leaves a race where the
    # downstream iterator misses the trailing batches.
    try:
        es.indices.refresh(index=sessions_idx)
    except Exception as exc:
        log.warning("rollup-sessions refresh failed (continuing): %s", exc)

    db.set_watermark(max_ts, _SESSION_WATERMARK_KEY)
    log.info("Session watermark advanced to %s", max_ts)
    db.close()

    return dict(
        stats,
        closed_sessions_found=len(closed),
        max_ts=max_ts,
        sessions_index=sessions_idx,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Cluster sessions
# ---------------------------------------------------------------------------

def iter_session_docs(
    es: Elasticsearch,
    index: str,
    page_size: int = 1000,
) -> Iterator[tuple[str, list[float], str, dict]]:
    """Yield (doc_id, embedding, session_id, scalars)."""
    body: dict = {
        "size": page_size,
        "_source": [
            "dshield.cowrie.enrichment.session.embedding",
            "dshield.cowrie.enrichment.session.command_count",
            "dshield.cowrie.enrichment.session.unique_commands",
            "dshield.cowrie.enrichment.session.login_success_count",
            "dshield.cowrie.enrichment.session.login_fail_count",
            "dshield.cowrie.enrichment.session.mean_novelty_score",
            "cowrie.session_id",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}},
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
            s = (
                ((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {})
                .get("session", {})
            )
            emb = s.get("embedding")
            if not emb:
                continue
            session_id = (src.get("cowrie") or {}).get("session_id", h["_id"])
            success = s.get("login_success_count") or 0
            fail = s.get("login_fail_count") or 0
            total_logins = success + fail
            scalars = {
                "command_count": s.get("command_count") or 1,
                "unique_commands": s.get("unique_commands") or 1,
                "login_success_rate": success / total_logins if total_logins > 0 else 0.0,
                "mean_novelty_score": s.get("mean_novelty_score") or 0.0,
            }
            yield h["_id"], emb, session_id, scalars
        search_after = hits[-1]["sort"]


def build_session_scalar_block(scalars_list: list[dict], weight: float) -> "np.ndarray":
    """(n, 4) weighted scalar matrix for session-level HDBSCAN."""
    import numpy as np
    counts = np.array([s.get("command_count") or 1 for s in scalars_list], dtype=np.float32)
    unique = np.array([s.get("unique_commands") or 1 for s in scalars_list], dtype=np.float32)
    success_rate = np.array([s.get("login_success_rate", 0.0) for s in scalars_list], dtype=np.float32)
    novelty = np.array([s.get("mean_novelty_score", 0.0) for s in scalars_list], dtype=np.float32)

    max_count = float(np.max(counts)) if counts.max() > 0 else 1.0
    max_unique = float(np.max(unique)) if unique.max() > 0 else 1.0

    block = np.zeros((len(scalars_list), 4), dtype=np.float32)
    block[:, 0] = (np.log1p(counts) / np.log1p(max_count)) * weight
    block[:, 1] = (np.log1p(unique) / np.log1p(max_unique)) * weight
    block[:, 2] = np.clip(success_rate, 0.0, 1.0) * weight
    block[:, 3] = np.clip(novelty, 0.0, 1.0) * weight
    return block


def run_cluster(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """HDBSCAN over session embeddings. Delegates to clustering core."""
    from ...clustering import run_layer_clustering
    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    scfg: SessionConfig = cfg.session

    if not es.indices.exists(index=sessions_idx):
        raise RuntimeError(
            f"Sessions index '{sessions_idx}' not found. "
            "Run 'rollup sessions' first, or check elasticsearch.indexes.cowrie.sessions_rollup in config."
        )

    return run_layer_clustering(
        es=es,
        docs_iter=iter_session_docs(es, sessions_idx, scfg.page_size),
        docs_index=sessions_idx,
        clusters_index=clusters_idx,
        mapping_path=_SESSION_CLUSTERS_MAPPING,
        update_script=_SESSION_CLUSTER_UPDATE_SCRIPT,
        scalar_block_builder=build_session_scalar_block,
        min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
        scalar_weight=scfg.cluster_scalar_weight,
        batch_size=scfg.batch_size,
        sample_size=_SESSION_CLUSTER_SAMPLE_SIZE,
        centroid_sample_field="sample_session_ids",
        dry_run=dry_run,
        layer_label="cowrie.sessions",
    )


# ---------------------------------------------------------------------------
# Name playbooks (each session cluster gets a short LLM-generated label).
# ---------------------------------------------------------------------------

def _fetch_session_sample_commands(
    es: Elasticsearch,
    events_index: str,
    session_ids: list[str],
    max_commands: int = 15,
) -> list[str]:
    """Top unique commands from given session IDs via events index aggregation."""
    try:
        resp = es.search(
            index=events_index,
            size=0,
            query={"bool": {"must": [
                {"terms": {"cowrie.session_id": session_ids}},
                {"term": {"event.action": "cowrie.command.input"}},
            ]}},
            aggs={"top_commands": {"terms": {"field": "process.command_line", "size": max_commands}}},
        )
        buckets = resp.get("aggregations", {}).get("top_commands", {}).get("buckets", [])
        return [b["key"] for b in buckets if b.get("key")]
    except Exception as exc:
        log.warning("Could not fetch session commands: %s", exc)
        return []


def run_name_playbooks(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
    force: bool = False,
) -> dict:
    """Generate playbook names for each non-outlier session cluster (local LLM, never cloud)."""
    if not cfg.prompts.playbook_name:
        raise RuntimeError("prompts.playbook_name is unset in config.")

    from pathlib import Path
    prompt_template = Path(cfg.prompts.playbook_name).read_text()

    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    session_clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    clusters: list[dict] = []
    try:
        if not es.indices.exists(index=session_clusters_idx):
            raise RuntimeError(
                f"Session clusters index '{session_clusters_idx}' not found. "
                "Run 'cluster sessions' first."
            )
        resp = es.search(
            index=session_clusters_idx,
            size=1,
            query={"term": {"doc_type": "cluster"}},
            sort=[{"@timestamp": "desc"}],
            _source=["run_id"],
        )
        hits = resp["hits"]["hits"]
        if not hits:
            raise RuntimeError("No cluster docs found. Run 'cluster sessions' first.")
        run_id = hits[0]["_source"]["run_id"]
        resp2 = es.search(
            index=session_clusters_idx,
            size=1000,
            query={"bool": {"must": [
                {"term": {"doc_type": "cluster"}},
                {"term": {"run_id": run_id}},
            ]}},
            _source=["cluster_id", "size", "sample_session_ids", "playbook_name",
                     "run_id", "centroid"],
        )
        clusters = [h["_source"] for h in resp2["hits"]["hits"]]
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Could not load session clusters: {exc}") from exc

    log.info("Loaded %d session cluster centroid docs", len(clusters))

    # Filter outliers out before merging — they have no centroid and aren't
    # a behaviour group. Then collapse near-duplicate clusters into playbook
    # groups via cosine-similarity union-find. Threshold of 1.0 effectively
    # disables merging (1 cluster = 1 playbook). See
    # `merge_clusters_into_playbooks` and config.SessionConfig.playbook_merge_threshold.
    nameable = [
        c for c in clusters
        if c.get("cluster_id") and c.get("cluster_id") != "outlier" and c.get("centroid")
    ]
    centroids_by_cid = {c["cluster_id"]: c["centroid"] for c in nameable}
    cluster_to_group = merge_clusters_into_playbooks(
        centroids_by_cid, cfg.session.playbook_merge_threshold,
    )

    # Bucket cluster docs by their assigned playbook group.
    docs_by_group: dict[str, list[dict]] = defaultdict(list)
    for c in nameable:
        docs_by_group[cluster_to_group[c["cluster_id"]]].append(c)

    n_groups = len(docs_by_group)
    n_merged_groups = sum(1 for members in docs_by_group.values() if len(members) > 1)
    log.info(
        "Playbook merge: %d nameable clusters → %d playbook groups (%d merged) "
        "at threshold %.3f",
        len(nameable), n_groups, n_merged_groups,
        cfg.session.playbook_merge_threshold,
    )

    from ...llm import make_llm_client
    llm = make_llm_client(cfg.llm).__enter__()
    log.info("Playbook naming: using local LLM (%s)", cfg.llm.generation_model)

    stats: dict = defaultdict(int)
    # Outliers don't appear in `nameable` — record them here for parity with
    # the old per-cluster stats.
    stats["skipped_outlier"] = sum(1 for c in clusters if c.get("cluster_id") == "outlier")

    try:
        for group_id in sorted(docs_by_group.keys()):
            members = docs_by_group[group_id]
            member_cids = sorted(c["cluster_id"] for c in members)
            total_size = sum(int(c.get("size") or 0) for c in members)

            # Skip if every member is already named and not forcing. Mixed
            # state (some named, some not) → re-process so the whole group
            # ends up consistent.
            if not force and members and all(c.get("playbook_name") for c in members):
                stats["skipped_already_named"] += 1
                continue

            # Pool sample session ids across all member clusters, preserving
            # order and de-duplicating. Cap at 5 for LLM context.
            sample_sids: list[str] = []
            seen_sids: set[str] = set()
            for c in members:
                for sid in (c.get("sample_session_ids") or []):
                    if sid and sid not in seen_sids:
                        seen_sids.add(sid)
                        sample_sids.append(sid)
            if not sample_sids:
                stats["skipped_no_sample_sessions"] += 1
                continue

            sample_sids = sample_sids[:5]
            unique_commands = _fetch_session_sample_commands(
                es, events_idx, sample_sids, cfg.session.playbook_sample_commands,
            )

            if not unique_commands:
                stats["skipped_no_commands"] += 1
                log.debug("No commands found for playbook group %s (clusters %s)",
                          group_id, member_cids)
                continue

            stats["clusters_processed"] += len(members)
            stats["groups_processed"] += 1

            if dry_run:
                log.info(
                    "[dry-run] playbook %s (clusters=%s, %d sessions): would name from %d commands",
                    group_id, member_cids, total_size, len(unique_commands),
                )
                continue

            # The prompt's CLUSTER_ID slot now identifies the playbook group;
            # if it merged multiple HDBSCAN clusters we hand the LLM the
            # group's playbook_id plus the constituent cluster ids so any
            # explanation it produces matches reality.
            playbook_id = _make_playbook_id(run_id, group_id)
            cluster_id_for_prompt = (
                member_cids[0] if len(member_cids) == 1
                else f"{playbook_id} (clusters: {', '.join(member_cids)})"
            )
            prompt = (
                prompt_template
                .replace("<<<CLUSTER_ID>>>", cluster_id_for_prompt)
                .replace("<<<SIZE>>>", str(total_size))
                .replace("<<<SAMPLE_IDS>>>", ", ".join(sample_sids))
                .replace("<<<COMMANDS>>>", "\n".join(f"  {c}" for c in unique_commands))
            )

            try:
                raw = llm.generate_json(
                    prompt,
                    schema=PLAYBOOK_NAME_JSON_SCHEMA,
                    schema_name="playbook_name",
                    options={"max_tokens": 512},
                )
                parsed = PlaybookName.model_validate_json(raw)
                name = parsed.playbook_name
                if not name:
                    raise ValueError("empty playbook_name")
            except Exception as exc:
                log.warning("LLM failed for playbook group %s (clusters %s): %s",
                            group_id, member_cids, exc)
                stats["llm_failed"] += 1
                continue

            log.info(
                "Playbook %s (clusters=%s, %d sessions) → '%s' (%s)",
                group_id, member_cids, total_size, name, parsed.rationale or "no rationale",
            )
            stats["named"] += 1

            try:
                es.update_by_query(
                    index=session_clusters_idx,
                    body={
                        "query": {"bool": {"must": [
                            {"term": {"run_id": run_id}},
                            {"term": {"doc_type": "cluster"}},
                            {"terms": {"cluster_id": member_cids}},
                        ]}},
                        "script": {
                            "source": (
                                "ctx._source.playbook_id = params.playbook_id;"
                                "ctx._source.playbook_name = params.name;"
                            ),
                            "params": {
                                "playbook_id": playbook_id,
                                "name": name,
                            },
                        },
                    },
                )
            except Exception as exc:
                log.warning("Failed to update centroids for playbook %s: %s", group_id, exc)
                stats["centroid_update_errors"] += 1

            try:
                es.update_by_query(
                    index=sessions_idx,
                    body={
                        "query": {"terms": {
                            "dshield.cowrie.enrichment.session.cluster.id": member_cids,
                        }},
                        "script": {
                            "source": _SESSION_PLAYBOOK_NAME_SCRIPT,
                            "params": {
                                "playbook_id":   playbook_id,
                                "playbook_name": name,
                            },
                        },
                    },
                )
            except Exception as exc:
                log.warning("Failed to update session docs for playbook %s: %s", group_id, exc)
                stats["session_update_errors"] += 1

    finally:
        llm.__exit__(None, None, None)

    # Refresh both indexes so `mine campaigns` (next pipeline step) sees the
    # playbook_id values we just wrote onto every member session. Without
    # this the miner reads a partial snapshot and the behaviour itemsets
    # come up empty even when the data supports them.
    try:
        es.indices.refresh(index=f"{session_clusters_idx},{sessions_idx}")
    except Exception as exc:
        log.warning("name-playbooks refresh failed (continuing): %s", exc)

    return dict(
        stats,
        total_clusters=len(clusters),
        total_groups=n_groups,
        merged_groups=n_merged_groups,
        merge_threshold=cfg.session.playbook_merge_threshold,
        dry_run=dry_run,
        force=force,
    )
