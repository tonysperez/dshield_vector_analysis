"""Cowrie source-IP layer: rollup and clustering.

rollup-ips:  aggregate sessions per source IP. Incremental — only recomputes IPs
             whose sessions changed since the last run.
cluster-ips: HDBSCAN over IP embeddings (delegates to clustering core).

IP clusters are unnamed "actor profile" buckets. An IP's playbook membership
is derived from its sessions at query time, and campaigns (the multi-session
concept) are mined into a separate index by `dshield_prism mine campaigns`.
"""
from __future__ import annotations

import hashlib
import logging
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterator, Optional

from elasticsearch import Elasticsearch

from ...cache import StateDB
from ...config import AppConfig, IPConfig, Secrets
from ...es_client import bulk_write, init_index, make_client
from .sessions import _mean_pool, _summarize_intents

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

# Fixed corpus-scale denominators for the log1p-normalized scalar block
# (ROADMAP #14). See sessions.py for the rationale; here total_sessions
# P99.9 ≈ 1400 today, max ≈ 14000, so 100000 leaves substantial headroom.
# mean_session_duration_s P99.9 is ~135s today — 3600s (1h) covers long
# interactive-shell sessions a real attacker might run.
_SCALAR_DENOM_TOTAL_SESSIONS = 100000.0
_SCALAR_DENOM_SESSION_DURATION_S = 3600.0

# Per-IP credential set cap. Keeps the rollup doc bounded while preserving
# the long tail of credential-spray attackers; collisions in the hash
# feature are already the dominant noise source, so capping at 200 is
# fine for the salient signal.
_MAX_CREDENTIALS_PER_IP = 200


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
            "user.name", "cowrie.password",
            "dshield.cowrie.enrichment.session.command_count",
            "dshield.cowrie.enrichment.session.login_success_count",
            "dshield.cowrie.enrichment.session.file_download_count",
            "dshield.cowrie.enrichment.session.dominant_intent",
            "dshield.cowrie.enrichment.session.mean_novelty_score",
            "dshield.cowrie.enrichment.session.max_novelty_score",
            "dshield.cowrie.enrichment.session.embedding",
            "dshield.cowrie.enrichment.session.credentials",
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
    credentials_set: set[str] = set()

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

        # Credential fingerprint accumulator. Prefer the per-session
        # `credentials` list (ROADMAP #16 — every (user, password) pair
        # attempted, not just the first-seen) when present; fall back to
        # the legacy first-seen top-level pair for pre-#16 session docs
        # whose backward pass hasn't recomputed them yet. Empty user OR
        # empty password both still contribute a tuple — credential-spray
        # scanners frequently use one of the two and the empty-string
        # position is itself a fingerprint. The IP-layer attribution
        # scalar block (issue #8) reads this set.
        session_creds = en.get("credentials") or []
        if session_creds:
            credentials_set.update(session_creds)
        else:
            username = ((s.get("user") or {}).get("name") or "")
            password = ((s.get("cowrie") or {}).get("password") or "")
            if username or password:
                credentials_set.add(f"{username}:{password}")

    embedding = _mean_pool(embeddings) if embeddings else None
    dominant_intent, intent_distribution = _summarize_intents(intents)
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
    if intent_distribution:
        ip_block["intent_distribution"] = intent_distribution
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
    if credentials_set:
        # Sorted + capped so the doc is bounded and idempotent across runs.
        ip_block["credentials"] = sorted(credentials_set)[:_MAX_CREDENTIALS_PER_IP]

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
    *,
    intel_lookup=None,
) -> Iterator[tuple[str, list[float], str, dict]]:
    """Yield (doc_id, embedding, source_ip, scalars).

    `scalars` carries the behavior signals (`total_sessions`,
    `login_success_rate`, `mean_novelty_score`, `mean_session_duration_s`)
    *and* the attribution signals (`country_iso_code`, `as_number`,
    `credentials`) used by the attribution scalar block. ROADMAP issue #8.

    When `intel_lookup` (an `enrich.intel.lookup.IntelLookup`) is
    supplied, each page of IPs is bulk-mget'd against
    `intel-dshield-ip-default` before yielding, and `scalars` gets two
    extra keys consumed by the intel sub-block (`_build_intel_block`):

      - `external_rarity_score`: float 0–1 (defaults 0 if no intel)
      - `consensus_malicious`:   bool      (defaults False if no intel)

    ROADMAP M3.B.
    """
    body: dict = {
        "size": page_size,
        "_source": [
            "source.ip",
            "source.geo.country_iso_code",
            "source.as.number",
            "dshield.cowrie.enrichment.ip.embedding",
            "dshield.cowrie.enrichment.ip.total_sessions",
            "dshield.cowrie.enrichment.ip.successful_sessions",
            "dshield.cowrie.enrichment.ip.mean_novelty_score",
            "dshield.cowrie.enrichment.ip.mean_session_duration_s",
            "dshield.cowrie.enrichment.ip.credentials",
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
        # M3.B: warm the intel cache for this page so the per-hit
        # `get_one` calls below are O(1) lookups in memory rather than
        # individual ES `get` requests.
        if intel_lookup is not None:
            page_ips = [
                ((h.get("_source") or {}).get("source") or {}).get("ip") or h["_id"]
                for h in hits
            ]
            intel_lookup.get_many("ip", page_ips)
        for h in hits:
            src = h["_source"]
            ip_en = (
                ((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {}).get("ip", {})
            )
            emb = ip_en.get("embedding")
            if not emb:
                continue
            source = src.get("source") or {}
            source_ip = source.get("ip", h["_id"])
            country = ((source.get("geo") or {}).get("country_iso_code")) or ""
            as_number = ((source.get("as") or {}).get("number"))
            total = ip_en.get("total_sessions") or 1
            success = ip_en.get("successful_sessions") or 0
            scalars = {
                "total_sessions": total,
                "login_success_rate": success / total,
                "mean_novelty_score": ip_en.get("mean_novelty_score") or 0.0,
                "mean_session_duration_s": ip_en.get("mean_session_duration_s") or 0.0,
                # Attribution inputs:
                "country_iso_code": country,
                "as_number": int(as_number) if as_number is not None else None,
                "credentials": list(ip_en.get("credentials") or []),
                # M3.B intel sub-block inputs. Defaults preserve cluster
                # behaviour when intel is disabled / not yet populated.
                "external_rarity_score": 0.0,
                "consensus_malicious": False,
            }
            if intel_lookup is not None:
                summary = intel_lookup.get_one("ip", source_ip)
                if summary is not None:
                    scalars["external_rarity_score"] = summary.external_rarity_score
                    scalars["consensus_malicious"] = bool(summary.consensus_malicious)
            yield h["_id"], emb, source_ip, scalars
        search_after = hits[-1]["sort"]


def _compute_top_asns(es: Elasticsearch, ips_index: str, top_n: int) -> list[int]:
    """Return the top-N most-frequent ASN numbers across the IP rollup.

    Used by the attribution-block builder to bucket every other ASN into
    a pooled "other" column. ROADMAP issue #8.

    Returns an empty list when the index is empty or the agg fails — the
    caller falls back to assigning every IP to the "other" bucket, which
    just means ASN doesn't differentiate IPs in this run.
    """
    if top_n <= 0:
        return []
    try:
        resp = es.search(
            index=ips_index, size=0,
            query={"exists": {"field": "source.as.number"}},
            aggs={"by_asn": {"terms": {"field": "source.as.number", "size": top_n}}},
        )
        return [int(b["key"]) for b in resp["aggregations"]["by_asn"]["buckets"]]
    except Exception as exc:
        log.warning("could not compute top-ASN list: %s", exc)
        return []


def _hash_credential_bin(cred: str, k: int) -> int:
    """Stable SHA-256-based hash of a credential string into [0, k).

    Stable across processes (Python's built-in `hash` is randomised).
    """
    if k <= 0:
        return 0
    digest = hashlib.sha256(cred.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:8], "big") % k


def _build_attribution_block(
    scalars_list: list[dict],
    *,
    top_asns: list[int],
    weight: float,
    cred_hash_dim: int,
) -> "np.ndarray":
    """Attribution scalar sub-block: country one-hot + ASN bucket + cred hash.

    Each of the three feature groups is pre-normalised to L2 ≤ 1, then
    scaled by `weight`. Stacked horizontally so the resulting matrix has
    shape `(n, k_country + k_asn + cred_hash_dim)` where:

      - `k_country` = number of distinct country ISO codes observed
        (empty-string IPs contribute to a single "unknown" column).
      - `k_asn`     = `len(top_asns) + 1` (top-N + one "other" pool).
      - `cred_hash_dim` is the fixed feature-hash width.

    L2 contribution per row is at most ~`weight * sqrt(3)` (one active
    column in each of country + ASN, and a unit-norm cred distribution).
    With `weight=0.10` that's ~0.17, slightly above the behavior block's
    max ~0.10 — matches the roadmap's "slightly hotter" target.

    ROADMAP issue #8.
    """
    import numpy as np

    n = len(scalars_list)
    if n == 0:
        return np.zeros((0, 0), dtype=np.float32)

    # --- country one-hot ---------------------------------------------------
    countries = [s.get("country_iso_code") or "" for s in scalars_list]
    country_vocab = sorted(set(countries))
    country_index = {c: i for i, c in enumerate(country_vocab)}
    country_block = np.zeros((n, len(country_vocab)), dtype=np.float32)
    for i, c in enumerate(countries):
        country_block[i, country_index[c]] = 1.0

    # --- ASN bucket: top-N one-hot + pooled "other" ------------------------
    asn_index: dict[int, int] = {asn: i for i, asn in enumerate(top_asns)}
    asn_block = np.zeros((n, len(top_asns) + 1), dtype=np.float32)
    other_col = len(top_asns)
    for i, s in enumerate(scalars_list):
        asn = s.get("as_number")
        col = asn_index.get(asn, other_col) if asn is not None else other_col
        asn_block[i, col] = 1.0

    # --- credential feature hash ------------------------------------------
    cred_block = np.zeros((n, cred_hash_dim), dtype=np.float32)
    if cred_hash_dim > 0:
        for i, s in enumerate(scalars_list):
            creds = s.get("credentials") or []
            if not creds:
                continue
            counts = np.zeros(cred_hash_dim, dtype=np.float32)
            for c in creds:
                counts[_hash_credential_bin(c, cred_hash_dim)] += 1.0
            total = counts.sum()
            if total > 0:
                cred_block[i] = counts / total  # normalised distribution

    block = np.hstack([country_block, asn_block, cred_block]).astype(np.float32)
    return block * weight


def _build_intel_block(
    scalars_list: list[dict], weight: float,
) -> "np.ndarray":
    """External-intel scalar sub-block: `external_rarity_score` + `consensus_malicious`.

    Two-column block, each scaled by `weight`. Pulls from the per-IP
    `scalars` dict that `iter_ip_docs` populates from the IntelLookup
    cache. Defaults are 0 for both columns when an IP has no intel
    data — same effect as "known-clean, no exotic rarity," which is
    geometrically a no-op against IPs that DO carry intel data.

    Two dimensions added to the matrix; L2 contribution per row is at
    most `weight * sqrt(2)`. At `attribution_weight=0.10` that's
    ~0.14 — same order of magnitude as the existing attribution
    block. ROADMAP M3.B.

    The point of this block: prevent ShadowServer-class IPs from
    clustering with same-behavior-but-actually-malicious IPs. External
    reputation is the discriminator the behavior+attribution-only
    matrix can't see.
    """
    import numpy as np

    n = len(scalars_list)
    if n == 0:
        return np.zeros((0, 2), dtype=np.float32)
    rarity = np.array(
        [float(s.get("external_rarity_score") or 0.0) for s in scalars_list],
        dtype=np.float32,
    )
    consensus = np.array(
        [1.0 if s.get("consensus_malicious") else 0.0 for s in scalars_list],
        dtype=np.float32,
    )
    block = np.zeros((n, 2), dtype=np.float32)
    block[:, 0] = np.clip(rarity, 0.0, 1.0) * weight
    block[:, 1] = consensus * weight
    return block


def _build_behavior_block(
    scalars_list: list[dict], weight: float,
) -> "np.ndarray":
    """Behavior scalar sub-block: total_sessions, login_success_rate,
    mean_novelty_score, mean_session_duration_s.

    Unchanged from the pre-#8 layout — split out from the combined
    builder so the attribution block can be hstack'd separately at its
    own (hotter) weight.
    """
    import numpy as np
    total = np.array([s.get("total_sessions") or 1 for s in scalars_list], dtype=np.float32)
    success_rate = np.array([s.get("login_success_rate", 0.0) for s in scalars_list], dtype=np.float32)
    novelty = np.array([s.get("mean_novelty_score", 0.0) for s in scalars_list], dtype=np.float32)
    duration = np.array([s.get("mean_session_duration_s", 0.0) for s in scalars_list], dtype=np.float32)

    denom_total = float(np.log1p(_SCALAR_DENOM_TOTAL_SESSIONS))
    denom_duration = float(np.log1p(_SCALAR_DENOM_SESSION_DURATION_S))

    block = np.zeros((len(scalars_list), 4), dtype=np.float32)
    block[:, 0] = np.clip(np.log1p(total) / denom_total, 0.0, 1.0) * weight
    block[:, 1] = np.clip(success_rate, 0.0, 1.0) * weight
    block[:, 2] = np.clip(novelty, 0.0, 1.0) * weight
    block[:, 3] = np.clip(np.log1p(duration) / denom_duration, 0.0, 1.0) * weight
    return block


def build_ip_scalar_block(scalars_list: list[dict], weight: float) -> "np.ndarray":
    """Backward-compat shim: behavior-only block at the given weight.

    The full IP scalar block (behavior + attribution) is built by
    `make_full_scalar_builder` and wired into `run_cluster` directly.
    This shim is preserved for any external caller (smoke tests, etc.)
    that still expects the simple `(scalars_list, weight) -> matrix`
    signature.
    """
    return _build_behavior_block(scalars_list, weight)


def make_full_scalar_builder(
    *,
    top_asns: list[int],
    attribution_weight: float,
    cred_hash_dim: int,
):
    """Return a builder closure that produces the combined IP scalar
    matrix (behavior + attribution) given the per-run attribution params.

    The clustering core (`run_layer_clustering`) accepts a single
    `(scalars_list, weight)` callable for `scalar_block_builder`. The
    weight argument it passes is the *behavior* weight; the attribution
    weight is captured in the closure. ROADMAP issue #8.
    """
    import numpy as np

    def _builder(scalars_list: list[dict], behavior_weight: float) -> "np.ndarray":
        behavior = _build_behavior_block(scalars_list, behavior_weight)
        attribution = _build_attribution_block(
            scalars_list,
            top_asns=top_asns,
            weight=attribution_weight,
            cred_hash_dim=cred_hash_dim,
        )
        # M3.B: external-intel block — same weight as attribution since
        # external reputation is attribution-type signal (who is this
        # IP) rather than behavior-type signal (what did this IP do).
        intel = _build_intel_block(scalars_list, attribution_weight)
        blocks = [behavior]
        if attribution.shape[1] > 0:
            blocks.append(attribution)
        blocks.append(intel)
        return np.hstack(blocks).astype(np.float32)

    return _builder


def annotate_ip_clusters_with_dominant_playbook(
    es: Elasticsearch,
    *,
    ips_rollup_index: str,
    ip_clusters_index: str,
    sessions_rollup_index: str,
    top_n: int = 3,
    page_size: int = 1000,
) -> dict:
    """Post-pass after IP clustering: stamp each IP-cluster centroid doc
    with the modal `playbook_id` / `playbook_name` across its member IPs'
    sessions, plus a top-N `playbook_distribution` array. ROADMAP #24.

    Why: IP clusters are unnamed actor-profile buckets. Until now the
    centroid doc didn't carry any human-readable label answering "what
    does cluster_9 *do*?" — a console query had to multi-hop join
    `ip.cluster.id → IP → session → playbook_id`. This post-pass does the
    join once at cluster-time and persists the answer.

    Deterministic: ties on count resolve lexically by `playbook_id` (same
    pattern as #15 / #17). Re-runs over unchanged data produce the same
    annotation.

    Stats returned: `{clusters_seen, clusters_annotated, runtime_seconds}`.
    Annotation is skipped (no field written) for clusters whose member IPs
    have no playbook-bearing sessions.
    """
    t0 = time.time()
    stats: dict = {
        "clusters_seen":     0,
        "clusters_annotated": 0,
    }

    # Step 1: find the latest cluster run on the IP clusters index.
    try:
        resp = es.search(
            index=ip_clusters_index,
            size=1,
            query={"term": {"doc_type": "cluster"}},
            sort=[{"@timestamp": "desc"}, {"_doc": "asc"}],
            _source=["run_id"],
        )
    except Exception as exc:
        log.warning("[ip-playbook-annot] could not locate latest run (%s); skipping", exc)
        stats["runtime_seconds"] = round(time.time() - t0, 2)
        return stats
    hits = resp["hits"]["hits"]
    if not hits:
        stats["runtime_seconds"] = round(time.time() - t0, 2)
        return stats
    run_id = hits[0]["_source"].get("run_id")
    if not run_id:
        stats["runtime_seconds"] = round(time.time() - t0, 2)
        return stats

    # Step 2: walk the IP rollup index for cluster.id → set of member IPs.
    cluster_to_ips: dict[str, set[str]] = defaultdict(set)
    body = {
        "size": page_size,
        "query": {"exists": {"field": "dshield.cowrie.enrichment.ip.cluster.id"}},
        "_source": ["source.ip", "dshield.cowrie.enrichment.ip.cluster.id"],
        "sort": [{"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=ips_rollup_index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            src = h["_source"]
            ip = (src.get("source") or {}).get("ip")
            cid = (((src.get("dshield") or {}).get("cowrie") or {})
                   .get("enrichment", {}).get("ip", {}).get("cluster", {}).get("id"))
            if ip and cid and cid != "outlier":
                cluster_to_ips[cid].add(ip)
        search_after = hits[-1]["sort"]

    stats["clusters_seen"] = len(cluster_to_ips)

    # Step 3: for each cluster's IPs, fetch playbook_id/name across their
    # sessions and compute the mode + top-N distribution.
    update_actions: list[dict] = []
    PB_FIELD = "dshield.cowrie.enrichment.session.playbook_id"
    PB_NAME_FIELD = "dshield.cowrie.enrichment.session.playbook_name"

    for cid, ips in cluster_to_ips.items():
        if not ips:
            continue
        # Counter keyed by playbook_id; remember the most recent name per id
        # (names are eventually-stable per #2's content-addressed scheme).
        pb_counts: Counter = Counter()
        pb_names: dict[str, str] = {}
        ip_list = list(ips)
        # Chunk to avoid hitting ES terms-query limits (default 65536).
        CHUNK = 1000
        for start in range(0, len(ip_list), CHUNK):
            chunk = ip_list[start: start + CHUNK]
            sbody = {
                "size": page_size,
                "query": {"bool": {"must": [
                    {"terms": {"source.ip": chunk}},
                    {"exists": {"field": PB_FIELD}},
                ]}},
                "_source": [PB_FIELD, PB_NAME_FIELD],
                "sort": [{"_doc": "asc"}],
            }
            sa = None
            while True:
                if sa:
                    sbody["search_after"] = sa
                sresp = es.search(index=sessions_rollup_index, **sbody)
                shits = sresp["hits"]["hits"]
                if not shits:
                    break
                for sh in shits:
                    en = (((sh["_source"].get("dshield") or {}).get("cowrie") or {})
                          .get("enrichment", {}).get("session", {}))
                    pid = en.get("playbook_id")
                    if not pid:
                        continue
                    pb_counts[pid] += 1
                    name = en.get("playbook_name")
                    if name:
                        pb_names[pid] = name
                sa = shits[-1]["sort"]

        if not pb_counts:
            continue

        # Sort by (-count, playbook_id) — deterministic lex tie-break.
        ranked = sorted(pb_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        dominant_id = ranked[0][0]
        dominant_name = pb_names.get(dominant_id)
        distribution = [
            {
                "playbook_id":   pid,
                "playbook_name": pb_names.get(pid),
                "count":         cnt,
            }
            for pid, cnt in ranked[:top_n]
        ]

        # Find the centroid doc for this cluster_id in the latest run.
        # Update it in-place via update-by-query on (run_id, cluster_id).
        params: dict = {
            "dominant_playbook_id":   dominant_id,
            "playbook_distribution":  distribution,
        }
        if dominant_name:
            params["dominant_playbook_name"] = dominant_name
        update_actions.append({
            "_op_type": "update_by_query",
            "_index":   ip_clusters_index,
            "query":    {"bool": {"must": [
                {"term": {"doc_type": "cluster"}},
                {"term": {"run_id": run_id}},
                {"term": {"cluster_id": cid}},
            ]}},
            "params":   params,
        })
        stats["clusters_annotated"] += 1

    # update_by_query isn't a `_bulk` op — apply each individually. There's
    # one per cluster, k = O(n_clusters) which is small (~tens), so this is
    # fine even without batching.
    script_source = (
        "ctx._source.dominant_playbook_id = params.dominant_playbook_id;"
        "ctx._source.playbook_distribution = params.playbook_distribution;"
        "if (params.containsKey('dominant_playbook_name')) {"
        "  ctx._source.dominant_playbook_name = params.dominant_playbook_name;"
        "} else {"
        "  ctx._source.remove('dominant_playbook_name');"
        "}"
    )
    for action in update_actions:
        try:
            es.update_by_query(
                index=action["_index"],
                query=action["query"],
                script={"source": script_source, "params": action["params"]},
                refresh=False,
                conflicts="proceed",
            )
        except Exception as exc:
            log.warning("[ip-playbook-annot] update failed for cluster %s: %s",
                        action["params"]["dominant_playbook_id"], exc)

    try:
        es.indices.refresh(index=ip_clusters_index)
    except Exception as exc:
        log.warning("[ip-playbook-annot] post-write refresh failed (continuing): %s", exc)

    stats["runtime_seconds"] = round(time.time() - t0, 2)
    log.info("[ip-playbook-annot] annotated %d/%d clusters in %ss",
             stats["clusters_annotated"], stats["clusters_seen"], stats["runtime_seconds"])
    return stats


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

    # Compute the top-N ASN bucket once per run; share across all rows.
    top_asns = _compute_top_asns(es, ips_idx, ipcfg.attribution_top_asns)
    log.info(
        "[cowrie.ips] attribution: top_asns=%d (configured=%d) cred_hash_dim=%d "
        "behavior_weight=%.3f attribution_weight=%.3f",
        len(top_asns), ipcfg.attribution_top_asns,
        ipcfg.attribution_cred_hash_dim,
        ipcfg.cluster_scalar_weight, ipcfg.cluster_attribution_weight,
    )

    scalar_builder = make_full_scalar_builder(
        top_asns=top_asns,
        attribution_weight=ipcfg.cluster_attribution_weight,
        cred_hash_dim=ipcfg.attribution_cred_hash_dim,
    )

    # M3.B: external-intel sub-block. Always-on when intel data is
    # present in the index; when intel is disabled / index missing,
    # the IntelLookup defensively returns None for every IP and the
    # block contributes 0s (no effect on clustering).
    intel_lookup = None
    if cfg.intel.enabled:
        from ...intel.lookup import IntelLookup
        intel_lookup = IntelLookup(es, cfg)
        log.info("[cowrie.ips] intel sub-block enabled (cfg.intel.enabled=true)")

    # NOTE: the `dominant_playbook` annotation post-pass (ROADMAP #24) is
    # NOT called here. It depends on `session.playbook_id` being populated,
    # which only happens after `name playbooks` runs — and the backward
    # task runs `cluster ips` *before* `name playbooks`. Calling it here
    # would always produce zeros. The annotation is invoked via the
    # separate `name ip-clusters` CLI verb, which the backward task runs
    # *after* `name playbooks`.

    return run_layer_clustering(
        es=es,
        docs_iter=iter_ip_docs(
            es, ips_idx, ipcfg.page_size, intel_lookup=intel_lookup,
        ),
        docs_index=ips_idx,
        clusters_index=clusters_idx,
        mapping_path=_IP_CLUSTERS_MAPPING,
        update_script=_IP_CLUSTER_UPDATE_SCRIPT,
        scalar_block_builder=scalar_builder,
        min_cluster_size=ipcfg.cluster_min_cluster_size,
        min_samples=ipcfg.cluster_min_samples,
        scalar_weight=ipcfg.cluster_scalar_weight,
        batch_size=ipcfg.batch_size,
        sample_size=_IP_CLUSTER_SAMPLE_SIZE,
        centroid_sample_field="sample_ips",
        dry_run=dry_run,
        layer_label="cowrie.ips",
    )


def run_name_ip_clusters(
    cfg: AppConfig,
    secrets: Secrets,
    *,
    dry_run: bool = False,
) -> dict:
    """Annotate every IP-cluster centroid in the latest run with its
    `dominant_playbook_id` / `dominant_playbook_name` / `playbook_distribution`.

    Standalone CLI verb (ROADMAP #24). Must run AFTER `name playbooks` —
    it reads `session.playbook_id` from the session rollup index, which
    only gets filled in by `name playbooks`. Running this from within
    `cluster ips` (which is the more obvious place) would always produce
    zero annotations because of backward-task step ordering. Cheap (~few
    hundred ms on a few-hundred-IP cluster set); safe to re-run.

    `dry_run=True` is a no-op stub for symmetry with other verbs — the
    annotation is read-only-then-write and there's no cheap "would
    change" path that's also cheap on ES. Returns the same stats dict
    shape either way.
    """
    if dry_run:
        log.info("[name ip-clusters] dry-run: no-op")
        return {"status": "dry_run"}
    es = make_client(cfg.elasticsearch, secrets)
    return annotate_ip_clusters_with_dominant_playbook(
        es,
        ips_rollup_index=cfg.elasticsearch.indexes.cowrie.ips_rollup,
        ip_clusters_index=cfg.elasticsearch.indexes.cowrie.ip_clusters,
        sessions_rollup_index=cfg.elasticsearch.indexes.cowrie.sessions_rollup,
    )
