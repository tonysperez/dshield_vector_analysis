"""Cowrie session layer: rollup, clustering, and playbook naming.

rollup-sessions: aggregate events per cowrie.session.closed into one session doc.
cluster-sessions: HDBSCAN over session embeddings (delegates to clustering core).
name-playbooks:   local LLM names each session cluster (a "playbook").
"""
from __future__ import annotations

import hashlib
import logging
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

from elasticsearch import Elasticsearch

from ...cache import StateDB
from ...config import AppConfig, Secrets, SessionConfig
from ...es_client import bulk_write, make_client
from ...llm.schemas import (
    PLAYBOOK_DISAMBIGUATE_JSON_SCHEMA,
    PLAYBOOK_NAME_JSON_SCHEMA,
    PlaybookDisambiguation,
    PlaybookName,
)
from .commands import hash_command, normalize

log = logging.getLogger(__name__)

_SESSION_WATERMARK_KEY = "session_last_processed_at"
_SESSIONS_MAPPING = "es-mappings/cowrie/sessions.json"
_SESSION_CLUSTERS_MAPPING = "es-mappings/cowrie/session_clusters.json"

# Fixed corpus-scale denominators for the log1p-normalized scalar block,
# replacing the previous per-batch `np.max(...)` (ROADMAP #14). Per-batch
# normalization meant the same session yielded different scalar contributions
# across re-runs purely because a bigger neighbour appeared. These constants
# are chosen well above the long-term P99.9 observed in production
# (command_count P99.9 ≈ 10 today, max ≈ 20 — 1000 leaves headroom for
# unusually-long future sessions). The block output is clipped to [0, 1]
# so a future outlier above the denominator doesn't blow the normalization.
_SCALAR_DENOM_COMMAND_COUNT = 1000.0
_SCALAR_DENOM_UNIQUE_COMMANDS = 1000.0

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


_PLAYBOOK_ID_HASH_LEN = 16


def _make_playbook_id(member_session_ids: Iterable[str]) -> str:
    """The canonical playbook primary key. Format: `sescl-<16-hex>`.

    The hex is the first `_PLAYBOOK_ID_HASH_LEN` chars of the SHA-256 of
    the playbook's member session ids, sorted and joined with newline.
    Two `cluster sessions` runs that produce the same membership for a
    playbook yield byte-identical ids — so downstream pivots (campaign
    miner especially, since campaign ids hash a sorted playbook-id set)
    don't churn across re-clusterings.

    A playbook may map to one or more HDBSCAN clusters depending on
    `session.playbook_merge_threshold`. Membership here is the *union of
    session ids across every constituent cluster*, not a per-cluster value.
    Empty membership raises — outlier clusters carry no playbook_id and
    are filtered out by the caller before we reach this point.

    The LLM `playbook_name` is a display label only and may legitimately
    duplicate across playbooks.
    """
    sids = sorted(set(s for s in member_session_ids if s))
    if not sids:
        raise ValueError("_make_playbook_id requires at least one session id")
    digest = hashlib.sha256("\n".join(sids).encode("utf-8")).hexdigest()
    return f"sescl-{digest[:_PLAYBOOK_ID_HASH_LEN]}"


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


def _summarize_intents(
    intents: list[str], top_n: int = 3
) -> tuple[Optional[str], list[dict]]:
    """Return `(dominant_intent, intent_distribution)` from a list of intent
    labels. The distribution is the top-N `(intent, count)` pairs sorted by
    `(-count, intent)` so ties resolve lexically — deterministic across runs.

    The previous code used `Counter(intents).most_common(1)[0][0]`, which
    relies on Counter insertion order to break ties. A 2-command session with
    one `reconnaissance` and one `execution` produced a different
    `dominant_intent` depending on whichever order the unique-hash iteration
    happened to surface them in — ROADMAP #15.

    Empty input → `(None, [])`. Used by both session and IP rollups; the IP
    layer composes per-IP intents from per-session `dominant_intent` values
    so this helper fixes both layers in one place.
    """
    if not intents:
        return None, []
    counter = Counter(intents)
    # Lexical tie-break: sort by (-count, name). Counter.most_common is
    # stable but ordering depends on insertion — explicit sort makes ties
    # deterministic regardless of how the input was enumerated.
    pairs = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    distribution = [{"intent": name, "count": count} for name, count in pairs[:top_n]]
    return pairs[0][0], distribution


def _command_entropy(counts: dict[str, int]) -> float:
    """Shannon entropy (bits) of the command frequency distribution."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _mean_pool(embeddings: list[list[float]]) -> list[float]:
    """Mean-pool equal-length float vectors, then L2-normalize the result.

    Each input is L2-normalized before summing so commands with slightly
    larger embedding norms don't dominate the pooled vector (the embedding
    model returns approximately-but-not-exactly unit-norm vectors, and the
    norm bias is not uniform across command types). The pooled output is
    also L2-normalized so direct cosine comparisons downstream (kNN, cluster
    diagnostics, explain page) don't need a "did this caller remember to
    normalize?" footgun. ROADMAP #13. Pure Python — no numpy required.
    """
    if not embeddings:
        return []
    dims = len(embeddings[0])
    result = [0.0] * dims
    n = 0
    for emb in embeddings:
        norm = math.sqrt(sum(v * v for v in emb))
        if norm == 0.0:
            continue
        inv = 1.0 / norm
        for i, v in enumerate(emb):
            result[i] += v * inv
        n += 1
    if n == 0:
        # Every input had zero norm — pathological but possible. Return a
        # zero vector of correct dim rather than an empty list so downstream
        # callers (which already gate `if embeddings else None`) don't have
        # to special-case a sudden change in shape.
        return [0.0] * dims
    out_norm = math.sqrt(sum(v * v for v in result))
    if out_norm == 0.0:
        # Antipodal vectors summed to zero. Vanishingly unlikely on a 768-d
        # embedding model; return a zero vector rather than NaN-ing the doc.
        return [0.0] * dims
    inv_out = 1.0 / out_norm
    return [v * inv_out for v in result]


_MAX_CREDENTIALS_PER_SESSION = 200


def _record_credential(credentials_set: set[str], ev: dict) -> None:
    """Add the `(user.name, cowrie.password)` tuple from a login event to the
    session's credential set. Either part may be empty — empty user OR
    empty password both still contribute a tuple, since credential-spray
    scanners frequently use one of the two and the empty-string position
    is itself a fingerprint (matches the IP-layer convention at #8).
    """
    user = ((ev.get("user") or {}).get("name") or "")
    password = ((ev.get("cowrie") or {}).get("password") or "")
    if user or password:
        credentials_set.add(f"{user}:{password}")


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
    # Every (user, password) pair attempted in this session, deduped. The
    # legacy top-level cowrie.password / user.name fields keep first-seen
    # for compatibility, but credential-spray bots can fire 50+ unique
    # pairs in one session and the IP-layer attribution feature (ROADMAP
    # #8) needs all of them — ROADMAP #16.
    credentials_set: set[str] = set()

    for ev in events:
        action = (ev.get("event") or {}).get("action", "")
        if action == "cowrie.session.connect":
            connect_event = ev
        elif action == "cowrie.session.closed":
            closed_event = ev
        elif action == "cowrie.login.success":
            login_success_count += 1
            _record_credential(credentials_set, ev)
        elif action == "cowrie.login.failed":
            login_fail_count += 1
            _record_credential(credentials_set, ev)
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

    dominant_intent, intent_distribution = _summarize_intents(intents)

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
    if intent_distribution:
        session_block["intent_distribution"] = intent_distribution
    if credentials_set:
        # Sorted + capped so the doc is bounded and idempotent across runs.
        # Cap matches the IP-layer cap pattern from issue #8.
        session_block["credentials"] = sorted(credentials_set)[:_MAX_CREDENTIALS_PER_SESSION]
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
    """(n, 4) weighted scalar matrix for session-level HDBSCAN.

    log1p-normalized fields use fixed corpus-scale denominators (ROADMAP #14)
    so the same session yields identical scalar contributions across re-runs,
    regardless of who else is in the batch. Output clipped to [0, 1].
    """
    import numpy as np
    counts = np.array([s.get("command_count") or 1 for s in scalars_list], dtype=np.float32)
    unique = np.array([s.get("unique_commands") or 1 for s in scalars_list], dtype=np.float32)
    success_rate = np.array([s.get("login_success_rate", 0.0) for s in scalars_list], dtype=np.float32)
    novelty = np.array([s.get("mean_novelty_score", 0.0) for s in scalars_list], dtype=np.float32)

    denom_count = float(np.log1p(_SCALAR_DENOM_COMMAND_COUNT))
    denom_unique = float(np.log1p(_SCALAR_DENOM_UNIQUE_COMMANDS))

    block = np.zeros((len(scalars_list), 4), dtype=np.float32)
    block[:, 0] = np.clip(np.log1p(counts) / denom_count, 0.0, 1.0) * weight
    block[:, 1] = np.clip(np.log1p(unique) / denom_unique, 0.0, 1.0) * weight
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

def _fetch_member_session_ids(
    es: Elasticsearch,
    sessions_idx: str,
    cluster_ids: list[str],
    page_size: int = 1000,
) -> dict[str, set[str]]:
    """Pull `{cluster_id → set[session_id]}` for the named cluster ids.

    Reads the session rollup index, scoped to docs whose
    `dshield.cowrie.enrichment.session.cluster.id` matches one of the
    requested cluster_ids (i.e. members of the current run — `cluster
    sessions` overwrites this field for every session, so by the time
    `name playbooks` calls us the field reflects the latest run only).

    Returns an empty map if `cluster_ids` is empty. Missing cluster ids
    return as keys with empty sets (caller chooses how to react).
    """
    out: dict[str, set[str]] = {cid: set() for cid in cluster_ids}
    if not cluster_ids:
        return out

    cluster_field = "dshield.cowrie.enrichment.session.cluster.id"
    body: dict = {
        "size": page_size,
        "_source": ["cowrie.session_id", cluster_field],
        "query": {"terms": {cluster_field: cluster_ids}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=sessions_idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return out
        for h in hits:
            src = h["_source"]
            sid = (src.get("cowrie") or {}).get("session_id") or h["_id"]
            cid = (
                ((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {}).get("session", {}).get("cluster", {}).get("id")
            )
            if cid and cid in out and sid:
                out[cid].add(sid)
        search_after = hits[-1]["sort"]


def _load_other_playbook_names(
    es: Elasticsearch,
    session_clusters_idx: str,
    exclude_run_id: str,
) -> dict[str, dict]:
    """Load already-named playbooks from `session_clusters`, *excluding*
    centroids written in the current run.

    Returns `{playbook_id: {"name": str, "sample_session_ids": list[str],
    "cluster_ids": list[str]}}`. A single playbook can span multiple
    centroid docs (HDBSCAN clusters merged at name time share one
    `playbook_id`); we collapse those into one entry per playbook.

    Used by pass-2 disambiguation (ROADMAP #10) to find collisions
    against playbooks named in any prior run.
    """
    by_pid: dict[str, dict] = {}
    try:
        body: dict = {
            "size": 1000,
            "_source": ["playbook_id", "playbook_name", "sample_session_ids",
                        "cluster_id", "run_id"],
            "query": {"bool": {"must": [
                {"term": {"doc_type": "cluster"}},
                {"exists": {"field": "playbook_id"}},
                {"exists": {"field": "playbook_name"}},
            ]}},
            "sort": [{"@timestamp": "desc"}, {"_doc": "asc"}],
        }
        search_after = None
        while True:
            if search_after:
                body["search_after"] = search_after
            resp = es.search(index=session_clusters_idx, **body)
            hits = resp["hits"]["hits"]
            if not hits:
                break
            for h in hits:
                src = h["_source"]
                if src.get("run_id") == exclude_run_id:
                    continue
                pid = src.get("playbook_id")
                if not pid:
                    continue
                entry = by_pid.setdefault(pid, {
                    "playbook_id": pid,
                    "name": src.get("playbook_name") or "",
                    "sample_session_ids": [],
                    "cluster_ids": [],
                })
                # Newest doc wins for name (centroid rewrites land first).
                if not entry["name"] and src.get("playbook_name"):
                    entry["name"] = src["playbook_name"]
                for sid in (src.get("sample_session_ids") or []):
                    if sid not in entry["sample_session_ids"]:
                        entry["sample_session_ids"].append(sid)
                cid = src.get("cluster_id")
                if cid and cid not in entry["cluster_ids"]:
                    entry["cluster_ids"].append(cid)
            search_after = hits[-1]["sort"]
    except Exception as exc:
        log.warning("could not load existing playbook names (continuing): %s", exc)
    return by_pid


def _detect_name_collisions(
    pass1_named: list[dict],
    existing_playbooks: dict[str, dict],
) -> list[dict]:
    """Pure function — group playbooks by case-insensitive trimmed name.

    `pass1_named` is the list of playbooks named in the current run (each
    dict has `playbook_id`, `name`, plus pass-2 context fields). Entries
    with empty names are silently skipped.

    `existing_playbooks` is the output of `_load_other_playbook_names` —
    playbooks named in any prior run. Entries are folded into a
    collision group only if their name matches a name produced this run.
    We never disturb an existing playbook's name in pass 2; existing
    colliders are listed as "frozen" so the LLM can differentiate the
    new ones from them.

    Returns one entry per collision group with at least one renamable
    member AND at least 2 total members (renamable + frozen). Groups
    with a single playbook (no collision) are omitted.
    """
    by_name: dict[str, dict] = {}
    def _key(n: str) -> str:
        return (n or "").strip().lower()
    for pb in pass1_named:
        k = _key(pb.get("name"))
        if not k:
            continue
        g = by_name.setdefault(k, {"name": pb["name"], "renamable": [], "frozen": []})
        g["renamable"].append(pb)
    for pb in existing_playbooks.values():
        k = _key(pb.get("name"))
        if not k:
            continue
        if k in by_name:
            by_name[k]["frozen"].append(pb)
    return [
        g for g in by_name.values()
        if g["renamable"] and (len(g["renamable"]) + len(g["frozen"])) > 1
    ]


def _format_cluster_block(pb: dict, commands: list[str]) -> str:
    """Render one cluster's context (playbook id, sample sids, sample commands)
    as a textual block for inclusion in the pass-2 disambiguation prompt."""
    sids = pb.get("sample_session_ids") or []
    cids = pb.get("cluster_ids") or []
    lines = [
        f"  Playbook id: {pb.get('playbook_id', '?')}",
        f"  Cluster ids: {', '.join(cids) if cids else '(unknown)'}",
        f"  Sample session ids: {', '.join(sids[:5]) if sids else '(none)'}",
        "  Commands executed (sampled, deduplicated):",
    ]
    if commands:
        lines.extend(f"    - {c}" for c in commands[:15])
    else:
        lines.append("    (no commands available)")
    return "\n".join(lines)


def _apply_playbook_name(
    es: Elasticsearch,
    session_clusters_idx: str,
    sessions_idx: str,
    run_id: str,
    member_cids: list[str],
    playbook_id: str,
    name: str,
    stats: dict,
    *,
    log_prefix: str = "playbook",
) -> None:
    """Write playbook_id + playbook_name onto the centroid docs and onto
    every member session via update_by_query. Shared by pass-1 initial
    naming and pass-2 disambiguation rename.
    """
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
                    "params": {"playbook_id": playbook_id, "name": name},
                },
            },
        )
    except Exception as exc:
        log.warning("Failed to update centroids for %s %s: %s", log_prefix, playbook_id, exc)
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
                    "params": {"playbook_id": playbook_id, "playbook_name": name},
                },
            },
        )
    except Exception as exc:
        log.warning("Failed to update session docs for %s %s: %s", log_prefix, playbook_id, exc)
        stats["session_update_errors"] += 1


def _run_disambiguation_pass(
    *,
    es: Elasticsearch,
    llm,                                            # open llm client
    prompt_template: str,
    group: dict,                                    # output of _detect_name_collisions
    run_id: str,
    session_clusters_idx: str,
    sessions_idx: str,
    events_idx: str,
    cfg: AppConfig,
    stats: dict,
) -> None:
    """Resolve one name-collision group via a single LLM call.

    Builds the pass-2 prompt with each renamable cluster's rich context
    plus any frozen colliders (already-named playbooks from prior runs
    that share the name — for context only, never renamed). Calls the
    LLM, validates the response, and applies the renames via
    `_apply_playbook_name`.

    Soft-fails on any LLM error / invalid JSON / collision in the
    response — original pass-1 names stay. ROADMAP issue #10.
    """
    name = group["name"]
    renamable = group["renamable"]
    frozen = group["frozen"]

    # Build context blocks. For frozen colliders we fetch sample commands
    # from the events index using their stored sample_session_ids.
    renamable_blocks: list[str] = []
    for pb in renamable:
        renamable_blocks.append(_format_cluster_block(pb, pb.get("unique_commands") or []))

    frozen_blocks: list[str] = []
    for pb in frozen:
        sids = pb.get("sample_session_ids") or []
        cmds = _fetch_session_sample_commands(
            es, events_idx, sids[:5],
            max_commands=cfg.session.playbook_sample_commands,
        ) if sids else []
        frozen_blocks.append(
            f"  Name: \"{pb.get('name', '?')}\"\n" + _format_cluster_block(pb, cmds)
        )

    frozen_section = (
        "FROZEN (already-named in a prior run; do NOT rename, listed for differentiation):\n"
        + "\n\n".join(frozen_blocks)
    ) if frozen_blocks else (
        "FROZEN (already-named in a prior run; do NOT rename, listed for differentiation):\n"
        "  (none — this is a within-run collision only)"
    )

    prompt = (
        prompt_template
        .replace("<<<NAME>>>", name)
        .replace("<<<RENAMABLE_BLOCK>>>", "\n\n".join(renamable_blocks))
        .replace("<<<FROZEN_BLOCK>>>", frozen_section)
    )

    try:
        raw = llm.generate_json(
            prompt,
            schema=PLAYBOOK_DISAMBIGUATE_JSON_SCHEMA,
            schema_name="playbook_disambiguate",
            options={"max_tokens": 1024},
        )
        parsed = PlaybookDisambiguation.model_validate_json(raw)
    except Exception as exc:
        log.warning(
            "Pass-2 LLM call failed for name '%s' (%d renamable, %d frozen): %s",
            name, len(renamable), len(frozen), exc,
        )
        stats["disambiguate_failed"] += 1
        return

    # Build a {playbook_id: PlaybookRename} map. The LLM is told to use
    # cluster ids; we tolerate either playbook_id or any of the member
    # cluster ids as the key (LLMs occasionally confuse them).
    by_pid: dict[str, str] = {pb["playbook_id"]: pb["playbook_id"] for pb in renamable}
    by_cid: dict[str, str] = {}
    for pb in renamable:
        for cid in pb["member_cids"]:
            by_cid[cid] = pb["playbook_id"]
    resolved: dict[str, str] = {}
    for r in parsed.renames:
        if r.cluster_id in by_pid:
            resolved[r.cluster_id] = r.new_name
        elif r.cluster_id in by_cid:
            resolved[by_cid[r.cluster_id]] = r.new_name

    if len(resolved) < len(renamable):
        log.warning(
            "Pass-2 LLM omitted renames for %d cluster(s) under '%s'; "
            "keeping pass-1 names for those",
            len(renamable) - len(resolved), name,
        )

    # Final-distinctness gate: every new name must be distinct from the
    # others in this group AND from all frozen names. Otherwise drop the
    # offending one — pass-1 name stays.
    frozen_names_lc = {(pb.get("name") or "").strip().lower() for pb in frozen}
    seen_new_lc: set[str] = set()
    final_renames: dict[str, str] = {}
    for pid, new_name in resolved.items():
        nlc = new_name.strip().lower()
        if not nlc or nlc in frozen_names_lc or nlc in seen_new_lc:
            log.warning(
                "Pass-2 rename rejected (collides with frozen or another new name): "
                "pid=%s new_name=%r", pid, new_name,
            )
            continue
        seen_new_lc.add(nlc)
        final_renames[pid] = new_name

    # Apply.
    for pb in renamable:
        new_name = final_renames.get(pb["playbook_id"])
        if not new_name:
            continue
        log.info(
            "Pass-2 rename: %s '%s' → '%s'",
            pb["playbook_id"], pb["name"], new_name,
        )
        _apply_playbook_name(
            es, session_clusters_idx, sessions_idx,
            run_id, pb["member_cids"], pb["playbook_id"], new_name, stats,
            log_prefix="disambig",
        )
        stats["clusters_renamed"] += 1


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

    # Pull the *full* member session-id set per cluster from the rollup
    # index — the centroid doc only carries 5 samples, but the playbook id
    # is content-hashed over the entire membership so identical runs yield
    # identical ids (see `_make_playbook_id`).
    members_by_cid = _fetch_member_session_ids(
        es, sessions_idx, list(centroids_by_cid.keys()), cfg.session.page_size,
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
    # Pass-1 named playbooks (carries pass-2 disambiguation context).
    # ROADMAP issue #10.
    named_in_run: list[dict] = []

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
            #
            # Playbook id = SHA-256 over the union of member session ids
            # across every constituent cluster. Stable across cluster runs
            # when membership doesn't change. Empty membership is
            # impossible here: `nameable` filtered outliers, and clusters
            # with zero member docs would have nothing to anchor the
            # centroid on — but be defensive anyway.
            member_sids_union: set[str] = set()
            for cid in member_cids:
                member_sids_union.update(members_by_cid.get(cid, set()))
            if not member_sids_union:
                stats["skipped_no_members"] += 1
                log.warning(
                    "Playbook group %s (clusters %s) has zero member sessions"
                    " in the rollup index — skipping naming",
                    group_id, member_cids,
                )
                continue
            playbook_id = _make_playbook_id(member_sids_union)
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
            named_in_run.append({
                "playbook_id": playbook_id,
                "name": name,
                "member_cids": member_cids,
                "sample_session_ids": sample_sids,
                "unique_commands": unique_commands,
                "group_id": group_id,
                "size": total_size,
            })

            _apply_playbook_name(
                es, session_clusters_idx, sessions_idx,
                run_id, member_cids, playbook_id, name, stats,
                log_prefix="playbook",
            )

        # -------------------------------------------------------------------
        # Pass 2 — disambiguate any naming collisions (ROADMAP issue #10).
        # -------------------------------------------------------------------
        if cfg.prompts.playbook_disambiguate and named_in_run:
            existing = _load_other_playbook_names(
                es, session_clusters_idx, exclude_run_id=run_id,
            )
            collisions = _detect_name_collisions(named_in_run, existing)
            stats["collisions_detected"] = len(collisions)
            if collisions:
                disamb_prompt_template = Path(cfg.prompts.playbook_disambiguate).read_text()
                log.info(
                    "Pass-2 disambiguation: %d name collision group(s) "
                    "(in-run renamables: %d; frozen colliders: %d)",
                    len(collisions),
                    sum(len(g["renamable"]) for g in collisions),
                    sum(len(g["frozen"]) for g in collisions),
                )
                for group in collisions:
                    _run_disambiguation_pass(
                        es=es,
                        llm=llm,
                        prompt_template=disamb_prompt_template,
                        group=group,
                        run_id=run_id,
                        session_clusters_idx=session_clusters_idx,
                        sessions_idx=sessions_idx,
                        events_idx=events_idx,
                        cfg=cfg,
                        stats=stats,
                    )

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
