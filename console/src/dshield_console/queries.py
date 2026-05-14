"""Elasticsearch queries used by the console API.

Design notes:
* Field paths follow the mappings in `es-mappings/cowrie/*.json`. Anything that
  changes there must be reflected here.
* Every query strips `dshield.*.embedding` from `_source` so 768-dim vectors
  never leave the server.
* Latest-cluster-run resolution: clusters indices store a `run_summary` doc
  per run. We look up the most recent run_id and filter cluster lookups by it.
* All sizes are bounded; callers pick `size` within [1, 500].
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from typing import Any

from elasticsearch import Elasticsearch, NotFoundError

from ._config import AppConfig

log = logging.getLogger(__name__)


# Mirror of `dshield_enrich.sources.cowrie.commands.normalize` + `hash_command_full`.
# Duplicated so the console package stays standalone. If the worker's
# normalization ever changes, mirror the edit here — otherwise we'd silently
# fail to join raw command-input events to their enrichment docs.
_WS_RE = re.compile(r"\s+")


def _hash_command(cmd: str, max_chars: int = 4000) -> str:
    s = _WS_RE.sub(" ", (cmd or "").strip())[:max_chars]
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------
# Aggregation-safe field resolver.
#
# When a field was first written via Painless before its mapping declared it,
# ES dynamic-maps strings as `text` with a `.keyword` sub-field. `_source`
# reads still work, but aggregations and term queries on the bare path silently
# fail (the agg `try/except` returns empty results; the term query matches the
# analyzed tokens, not the original string). For new indexes built from the
# updated mapping the field is `keyword` directly with no sub-field.
#
# `_resolve_agg_field` inspects the live mapping and returns whichever path
# actually works for aggregations on this index. Results are cached per
# (index, dotted_path) so we only hit the mapping API once per pair.
# ----------------------------------------------------------------------------

_AGG_FIELD_CACHE: dict[tuple[str, str], str] = {}


def _resolve_agg_field(es: Elasticsearch, index: str, dotted_path: str) -> str:
    cache_key = (index, dotted_path)
    if cache_key in _AGG_FIELD_CACHE:
        return _AGG_FIELD_CACHE[cache_key]
    resolved: str | None = None
    try:
        full = es.indices.get_mapping(index=index)
        if full:
            # `full` is { <resolved_index_name>: { mappings: { ... } } }.
            first_key = next(iter(full.keys()))
            mappings = full[first_key].get("mappings", {})
            node: Any = mappings
            for seg in dotted_path.split("."):
                props = (node or {}).get("properties") or {}
                node = props.get(seg)
                if node is None:
                    break
            if node:
                ftype = node.get("type")
                if ftype == "keyword":
                    resolved = dotted_path
                elif ftype == "text":
                    sub = (node.get("fields") or {}).get("keyword") or {}
                    if sub.get("type") == "keyword":
                        resolved = f"{dotted_path}.keyword"
                    else:
                        resolved = dotted_path
                else:
                    resolved = dotted_path
            else:
                # Field truly absent from the mapping — bare path is the
                # safest fallback. It's worth caching: if the field is added
                # later we'll pick it up on the next process restart.
                resolved = dotted_path
    except Exception as exc:
        log.debug("_resolve_agg_field(%s, %s) failed: %s", index, dotted_path, exc)
        # Do NOT cache on transient errors (ES timeout, etc.); next call
        # gets a fresh attempt. Falling back to the bare path is a
        # best-effort guess for the current call only.
        return dotted_path
    _AGG_FIELD_CACHE[cache_key] = resolved or dotted_path
    return resolved or dotted_path


# ----------------------------------------------------------------------------
# Session quality filter
# ----------------------------------------------------------------------------
#
# Most useful threat-hunting views want sessions that actually did something
# (logged in successfully AND ran a command). The login-only scanners blast
# every IP with credentials and never get in; the dropped-but-no-commands
# sessions are noise. The defaults reflect that.

class SessionFilter:
    """Quality filter applied to session rollup queries. Each flag is
    independent; both default ON so callers get the threat-hunter-useful
    view unless they explicitly opt out."""

    __slots__ = ("require_login", "require_commands")

    def __init__(self, require_login: bool = True, require_commands: bool = True) -> None:
        self.require_login = bool(require_login)
        self.require_commands = bool(require_commands)

    @property
    def active(self) -> bool:
        return self.require_login or self.require_commands

    def es_filters(self) -> list[dict]:
        """ES range clauses to AND into a bool/filter or bool/must. Returns []
        when nothing is active so callers can splice unconditionally."""
        out: list[dict] = []
        if self.require_login:
            out.append({"range": {"dshield.cowrie.enrichment.session.login_success_count": {"gte": 1}}})
        if self.require_commands:
            out.append({"range": {"dshield.cowrie.enrichment.session.command_count": {"gte": 1}}})
        return out


_NO_FILTER = SessionFilter(require_login=False, require_commands=False)


def _empty_search_result() -> dict:
    """Shape that mimics an ES search response with zero hits, so callers
    that index into `result['hits']['hits']` keep working when an index is
    missing."""
    return {"hits": {"total": {"value": 0}, "hits": []}}


# Fields excluded from every response — embeddings are too big to ship and
# never useful to the GUI.
_EXCLUDE = [
    "dshield.cowrie.enrichment.embedding",
    "dshield.cowrie.enrichment.session.embedding",
    "dshield.cowrie.enrichment.ip.embedding",
    "centroid",
]


def _src(*extra: str) -> dict:
    """Build a `_source` filter that includes everything except embeddings."""
    return {"excludes": _EXCLUDE}


# ----------------------------------------------------------------------------
# Latest-cluster-run resolution
# ----------------------------------------------------------------------------

class RunCache:
    """Caches the most recent run_id per cluster index for a short TTL."""

    def __init__(self, ttl_seconds: float = 60.0) -> None:
        self.ttl = ttl_seconds
        self._cache: dict[str, tuple[float, str | None]] = {}

    def latest(self, es: Elasticsearch, index: str) -> str | None:
        now = time.monotonic()
        hit = self._cache.get(index)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        try:
            r = es.search(
                index=index,
                size=1,
                _source=["run_id", "@timestamp"],
                query={"term": {"doc_type": "run_summary"}},
                sort=[{"@timestamp": {"order": "desc"}}],
            )
            hits = r["hits"]["hits"]
            run_id = hits[0]["_source"].get("run_id") if hits else None
        except Exception as e:  # pragma: no cover -- network paths
            log.warning("run-id lookup failed for %s: %s", index, e)
            run_id = None
        self._cache[index] = (now, run_id)
        return run_id


# ----------------------------------------------------------------------------
# Lookups (single-doc fetches keyed by IOC)
# ----------------------------------------------------------------------------

def lookup_ip(es: Elasticsearch, cfg: AppConfig, ip: str) -> dict | None:
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    try:
        r = es.get(index=idx, id=ip, source_excludes=_EXCLUDE)
        return {"_id": r["_id"], "_source": r["_source"]}
    except Exception:
        # Fall back to search by source.ip just in case _id != ip on some doc.
        r = es.search(index=idx, size=1, _source=_src(),
                      query={"term": {"source.ip": ip}})
        hits = r["hits"]["hits"]
        return {"_id": hits[0]["_id"], "_source": hits[0]["_source"]} if hits else None


def lookup_session(es: Elasticsearch, cfg: AppConfig, session_id: str) -> dict | None:
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        r = es.get(index=idx, id=session_id, source_excludes=_EXCLUDE)
        return {"_id": r["_id"], "_source": r["_source"]}
    except Exception:
        r = es.search(index=idx, size=1, _source=_src(),
                      query={"term": {"cowrie.session_id": session_id}})
        hits = r["hits"]["hits"]
        return {"_id": hits[0]["_id"], "_source": hits[0]["_source"]} if hits else None


def lookup_command(es: Elasticsearch, cfg: AppConfig, sha256: str) -> dict | None:
    idx = cfg.elasticsearch.indexes.cowrie.commands
    # First try _id == sha256 (the worker upserts with the hash as _id).
    try:
        r = es.get(index=idx, id=sha256, source_excludes=_EXCLUDE)
        return {"_id": r["_id"], "_source": r["_source"]}
    except Exception:
        r = es.search(index=idx, size=1, _source=_src(),
                      query={"term": {"process.hash.sha256": sha256}})
        hits = r["hits"]["hits"]
        return {"_id": hits[0]["_id"], "_source": hits[0]["_source"]} if hits else None


def lookup_cluster(
    es: Elasticsearch, cfg: AppConfig, kind: str, cluster_id: str,
    run_cache: RunCache,
) -> dict | None:
    """`kind` ∈ {'command', 'session', 'ip'}."""
    idx_map = {
        "command": cfg.elasticsearch.indexes.cowrie.command_clusters,
        "session": cfg.elasticsearch.indexes.cowrie.session_clusters,
        "ip":      cfg.elasticsearch.indexes.cowrie.ip_clusters,
    }
    idx = idx_map[kind]
    run_id = run_cache.latest(es, idx)
    must: list[dict] = [
        {"term": {"cluster_id": cluster_id}},
        {"term": {"doc_type": "cluster"}},
    ]
    if run_id:
        must.append({"term": {"run_id": run_id}})
    r = es.search(index=idx, size=1, _source=_src(),
                  query={"bool": {"must": must}})
    hits = r["hits"]["hits"]
    return {"_id": hits[0]["_id"], "_source": hits[0]["_source"]} if hits else None


def bulk_session_enrichment(
    es: Elasticsearch, cfg: AppConfig, session_ids: list[str],
) -> dict[str, dict]:
    """Resolve {session_id -> dshield.cowrie.enrichment.session} for many ids
    in one search. Used by graph builders that emit session nodes coming
    from non-session anchors (e.g. sessions_for_command rows) so the
    session's cluster_id / playbook_id / etc. land on the node even though
    the front-end's pipeline traversal won't re-fetch them as a real
    session anchor."""
    if not session_ids:
        return {}
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        r = es.search(
            index=idx, size=len(session_ids),
            _source=["cowrie.session_id", "source.ip",
                     "dshield.cowrie.enrichment.session"],
            query={"terms": {"cowrie.session_id": list(set(session_ids))}},
        )
    except Exception as e:
        log.warning("bulk_session_enrichment failed: %s", e)
        return {}
    out: dict[str, dict] = {}
    for h in r["hits"]["hits"]:
        src = h["_source"]
        sid = (src.get("cowrie") or {}).get("session_id")
        if not sid:
            continue
        senr = (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}).get("session") or {}
        out[sid] = {
            "enrichment": senr,
            "src_ip": (src.get("source") or {}).get("ip"),
        }
    return out


def bulk_ip_enrichment(
    es: Elasticsearch, cfg: AppConfig, ips: list[str],
) -> dict[str, dict]:
    """Resolve {ip -> {enrichment, asn, country}} for many ips in one search.
    Same motivation as bulk_session_enrichment: anchor functions need
    cluster / asn / country for source IPs they emit so the front-end's
    cluster bubbles include them, even though the IP node arrives as a
    'leaf' in pipeline-traversal terms."""
    if not ips:
        return {}
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    try:
        r = es.search(
            index=idx, size=len(ips),
            _source=["source.ip", "source.as", "source.geo",
                     "dshield.cowrie.enrichment.ip"],
            query={"terms": {"source.ip": list(set(ips))}},
        )
    except Exception as e:
        log.warning("bulk_ip_enrichment failed: %s", e)
        return {}
    out: dict[str, dict] = {}
    for h in r["hits"]["hits"]:
        src = h["_source"]
        ip = (src.get("source") or {}).get("ip")
        if not ip:
            continue
        ienr = (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}).get("ip") or {}
        out[ip] = {
            "enrichment": ienr,
            "asn": ((src.get("source") or {}).get("as") or {}).get("number"),
            "asn_org": (((src.get("source") or {}).get("as") or {}).get("organization") or {}).get("name"),
            "country": ((src.get("source") or {}).get("geo") or {}).get("country_iso_code"),
        }
    return out


def lookup_campaign(es: Elasticsearch, cfg: AppConfig, campaign_id: str) -> dict | None:
    """Read one campaign doc from the campaigns index (the multi-session
    concept mined by `dshield-enrich mine campaigns`). Returns None if no
    matching doc exists.

    Distinct from `lookup_playbook`, which operates on the session-cluster
    centroid index — a playbook is one named session cluster.
    """
    idx = cfg.elasticsearch.indexes.cowrie.campaigns
    cid_field = _resolve_agg_field(es, idx, "campaign_id")
    try:
        r = es.search(
            index=idx, size=1,
            query={"bool": {"must": [
                {"term": {"doc_type": "campaign"}},
                {"term": {cid_field: campaign_id}},
            ]}},
        )
        hits = r["hits"]["hits"]
    except Exception as exc:
        log.warning("lookup_campaign failed for %s: %s", campaign_id, exc)
        return None
    if not hits:
        return None
    return hits[0]["_source"]


def list_campaigns(
    es: Elasticsearch, cfg: AppConfig, *,
    kind: str | None = None, size: int = 25,
) -> list[dict]:
    """Top campaigns by session_count, optionally filtered by kind
    (`behaviour` | `infrastructure`). Used by the insights page."""
    idx = cfg.elasticsearch.indexes.cowrie.campaigns
    must: list[dict] = [{"term": {"doc_type": "campaign"}}]
    if kind:
        must.append({"term": {"kind": kind}})
    try:
        r = es.search(
            index=idx, size=size,
            _source=[
                "campaign_id", "kind", "name", "rationale",
                "ip_count", "session_count", "first_seen", "last_seen",
                "support", "member_playbook_ids",
            ],
            query={"bool": {"must": must}},
            sort=[{"session_count": {"order": "desc"}}],
        )
        return [h["_source"] for h in r["hits"]["hits"]]
    except Exception as exc:
        log.warning("list_campaigns failed: %s", exc)
        return []


def lookup_playbook(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str,
) -> dict:
    """Look up a playbook by its stable id (`sescl-<run_id>-pg<N>`).

    A playbook may be backed by one or more session-cluster centroid docs
    (HDBSCAN clusters merged by `session.playbook_merge_threshold` at name
    time share a `playbook_id`). Anchoring on the playbook returns the
    session members plus the source IPs that produced those sessions. IPs
    don't carry a playbook field; their playbook membership is derived
    from the sessions they ran.

    The return shape is rich on purpose — the playbook detail panel reads
    timespan / top-countries / top-ASNs / dominant intent / 24h delta /
    sample commands directly from it.
    """
    sess_idx     = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters

    # Centroid docs hold the display name + per-cluster sizes. With merge
    # enabled, a playbook can span >1 centroid doc, so we sum sizes across
    # every centroid that carries this playbook_id. The name is identical
    # across constituent docs (write-time invariant in run_name_playbooks).
    name = None
    size = None
    centroid_field = _resolve_agg_field(es, clusters_idx, "playbook_id")
    try:
        cresp = es.search(
            index=clusters_idx, size=100,
            _source=["playbook_name", "size", "cluster_id", "run_id"],
            query={"term": {centroid_field: playbook_id}},
        )
        chits = cresp["hits"]["hits"]
        if chits:
            name = chits[0]["_source"].get("playbook_name")
            size = sum(int(h["_source"].get("size") or 0) for h in chits)
    except Exception:
        pass

    pb_field = _resolve_agg_field(
        es, sess_idx, "dshield.cowrie.enrichment.session.playbook_id",
    )
    base_q = {"term": {pb_field: playbook_id}}

    # Sample sessions (for the "Sample IPs" / "Sample Sessions" rows).
    sess_hits = es.search(
        index=sess_idx, size=10, _source=_src(),
        query=base_q,
    )
    sample_sessions = []
    sample_ips_in_sample: list[str] = []
    seen_ips_in_sample: set[str] = set()
    for h in sess_hits["hits"]["hits"]:
        src = h["_source"]
        sid = (src.get("cowrie") or {}).get("session_id")
        if sid:
            sample_sessions.append(sid)
        ip = (src.get("source") or {}).get("ip")
        if ip and ip not in seen_ips_in_sample:
            seen_ips_in_sample.add(ip)
            sample_ips_in_sample.append(ip)

    # Rich aggregations: one round-trip pulls every field the playbook
    # detail panel reads, so the page renders in one ES hit + the centroid
    # lookup above. `now-24h` and `now-48h..now-24h` give the recent-delta.
    aggs_body = {
        "first_seen":     {"min": {"field": "event.start"}},
        "last_seen":      {"max": {"field": "event.start"}},
        "distinct_ips":   {"cardinality": {"field": "source.ip"}},
        "top_countries":  {"terms": {"field": "source.geo.country_iso_code", "size": 5}},
        "top_asns":       {"terms": {"field": "source.as.number", "size": 5}},
        "top_intents":    {"terms": {
            "field": "dshield.cowrie.enrichment.session.dominant_intent",
            "size": 3,
            "missing": "unknown",
        }},
        "last_24h":       {"filter": {"range": {"event.start": {"gte": "now-24h"}}}},
        "prior_24h":      {"filter": {"range": {"event.start": {"gte": "now-48h", "lt": "now-24h"}}}},
    }
    first_seen = last_seen = None
    distinct_ips = 0
    top_countries: list[dict] = []
    top_asns:      list[dict] = []
    top_intents:   list[dict] = []
    last_24h = prior_24h = 0
    try:
        agg_resp = es.search(index=sess_idx, size=0, query=base_q, aggs=aggs_body)
        a = agg_resp.get("aggregations", {})
        first_seen   = (a.get("first_seen") or {}).get("value_as_string")
        last_seen    = (a.get("last_seen")  or {}).get("value_as_string")
        distinct_ips = int((a.get("distinct_ips") or {}).get("value") or 0)
        top_countries = [
            {"cc": b["key"], "count": b["doc_count"]}
            for b in (a.get("top_countries") or {}).get("buckets", [])
        ]
        top_asns = [
            {"asn": b["key"], "count": b["doc_count"]}
            for b in (a.get("top_asns") or {}).get("buckets", [])
        ]
        top_intents = [
            {"intent": b["key"], "count": b["doc_count"]}
            for b in (a.get("top_intents") or {}).get("buckets", [])
        ]
        last_24h  = int((a.get("last_24h")  or {}).get("doc_count") or 0)
        prior_24h = int((a.get("prior_24h") or {}).get("doc_count") or 0)
    except Exception as exc:
        log.warning("lookup_playbook rich aggs failed for %s: %s", playbook_id, exc)

    # Sample commands the playbook's sessions are running. The session
    # rollup doesn't store full command lines, so we cross-join via the
    # commands index, looking up command_lines that appear most often in
    # this playbook's sessions. Three samples is enough to convey flavour.
    sample_commands: list[str] = []
    try:
        # First, get the session ids in this playbook (top N by command_count).
        sids_resp = es.search(
            index=sess_idx, size=20,
            _source=["cowrie.session_id"],
            query=base_q,
            sort=[{"dshield.cowrie.enrichment.session.command_count": {"order": "desc"}}],
        )
        sids = [
            (h["_source"].get("cowrie") or {}).get("session_id")
            for h in sids_resp["hits"]["hits"]
        ]
        sids = [s for s in sids if s]
        if sids:
            raw_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
            # `process.command_line` is the canonical raw-command field
            # (matches the rest of this module's command-input queries).
            # We resolve the agg-safe variant so a legacy index with a
            # `.keyword` sub-field still works.
            cmd_field = _resolve_agg_field(es, raw_idx, "process.command_line")
            cmd_resp = es.search(
                index=raw_idx, size=0,
                query={"bool": {"filter": [
                    {"term": {"event.action": "cowrie.command.input"}},
                    {"terms": {"cowrie.session_id": sids}},
                ]}},
                aggs={"by_cmd": {"terms": {"field": cmd_field, "size": 5}}},
            )
            for b in (cmd_resp.get("aggregations", {}).get("by_cmd") or {}).get("buckets", []):
                cl = (b.get("key") or "")[:120]
                if cl:
                    sample_commands.append(cl)
    except Exception as exc:
        log.debug("lookup_playbook sample_commands failed for %s: %s", playbook_id, exc)

    return {
        "id":              playbook_id,
        "name":            name,
        "cluster_size":    size,
        "session_count":   sess_hits["hits"]["total"]["value"],
        "ip_count":        distinct_ips,
        "first_seen":      first_seen,
        "last_seen":       last_seen,
        "last_24h":        last_24h,
        "prior_24h":       prior_24h,
        "top_countries":   top_countries,
        "top_asns":        top_asns,
        "top_intents":     top_intents,
        "sample_commands": sample_commands,
        "sample_ips":      sample_ips_in_sample,
        "sample_sessions": sample_sessions,
    }


# ----------------------------------------------------------------------------
# Related-rows queries (paginated tables for the detail panel)
# ----------------------------------------------------------------------------

def sessions_for_ip(
    es: Elasticsearch, cfg: AppConfig, ip: str, *,
    size: int = 50, frm: int = 0,
    sf: SessionFilter | None = None,
) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    must: list[dict] = [{"term": {"source.ip": ip}}]
    if sf:
        must.extend(sf.es_filters())
    return es.search(
        index=idx, from_=frm, size=size, _source=_src(),
        query={"bool": {"must": must}},
        sort=[{"event.start": {"order": "desc"}}],
    )


def commands_for_session(
    es: Elasticsearch, cfg: AppConfig, session_id: str, *, size: int = 50,
) -> dict:
    """Pull command-input events for the session from sessions_raw, then look
    up enrichment for each unique hash. Returns rows: [{command_line, hash,
    enrichment?}, ...]."""
    raw_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
    enr_idx = cfg.elasticsearch.indexes.cowrie.commands

    try:
        raw = es.search(
            index=raw_idx, size=min(size * 4, 500), _source=["process.command_line", "process.hash.sha256", "@timestamp", "event.action"],
            query={"bool": {"must": [
                {"term": {"cowrie.session_id": session_id}},
                {"term": {"event.action": "cowrie.command.input"}},
            ]}},
            sort=[{"@timestamp": {"order": "asc"}}],
        )
    except NotFoundError:
        log.warning("sessions_raw index %s missing; returning empty commands_for_session", raw_idx)
        return {"rows": [], "total": 0}
    rows: list[dict] = []
    hashes: list[str] = []
    for h in raw["hits"]["hits"]:
        src = h["_source"]
        cmd = (src.get("process") or {}).get("command_line")
        sha = ((src.get("process") or {}).get("hash") or {}).get("sha256")
        if not cmd:
            continue
        # Raw SO docs typically don't carry the sha; the worker computes it
        # during enrichment. Mirror that hash so we can join to enrichment.
        if not sha:
            sha = _hash_command(cmd)
        rows.append({
            "ts": src.get("@timestamp"),
            "command_line": cmd,
            "sha256": sha,
        })
        if sha:
            hashes.append(sha)

    enrichment: dict[str, dict] = {}
    if hashes:
        e = es.search(
            index=enr_idx, size=min(len(hashes), 500), _source=_src(),
            query={"terms": {"process.hash.sha256": list(set(hashes))}},
        )
        for h in e["hits"]["hits"]:
            sha = ((h["_source"].get("process") or {}).get("hash") or {}).get("sha256")
            if sha:
                enrichment[sha] = h["_source"]

    for row in rows:
        if row.get("sha256") and row["sha256"] in enrichment:
            full = enrichment[row["sha256"]]
            row["enrichment"] = full.get("dshield", {}).get("cowrie", {}).get("enrichment")
            # graph.py wants threat info too (for MITRE badges); pass the
            # narrow slice rather than the whole doc to stay lean.
            row["threat"] = full.get("threat")
    return {"rows": rows[:size], "total": raw["hits"]["total"]["value"]}


def sessions_for_command(
    es: Elasticsearch, cfg: AppConfig, sha256: str, *,
    size: int = 50,
    sf: SessionFilter | None = None,
) -> dict:
    """Sessions that ran a given command (by hash).

    Raw cowrie events don't carry `process.hash.sha256` — the enricher
    computes it. The enricher also NORMALIZES the command_line before
    hashing (whitespace strip + collapse). So a term-match against raw
    `process.command_line` using the enriched (normalized) value fails for
    every command whose raw form has a trailing newline, double space, or
    other whitespace that normalisation collapsed. Cowrie's `command.input`
    events very commonly include a trailing space, so this hit ~every
    multi-line command in practice (and was the root cause of the
    "commands not linked to sessions" symptom in Prism).

    Strategy: use a prefix query on the normalised line as a cheap filter
    in ES, then re-hash each candidate raw command_line client-side and
    keep the ones whose hash actually matches. The prefix is bounded so
    keyword-field prefix queries stay fast; the in-Python hash uses the
    SAME `_hash_command` the session anchor already uses for the inverse
    direction, so both joins are now symmetric.
    """
    raw_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
    enr_idx = cfg.elasticsearch.indexes.cowrie.commands

    # Step 1: resolve sha -> normalized command_line via the enriched doc.
    try:
        e = es.search(
            index=enr_idx, size=1, _source=["process.command_line"],
            query={"term": {"process.hash.sha256": sha256}},
        )
        hits = e["hits"]["hits"]
        norm_cmd = ((hits[0]["_source"].get("process") or {}).get("command_line")) if hits else None
    except Exception:
        norm_cmd = None
    if not norm_cmd:
        return {"rows": [], "total": 0}

    # Step 2: prefix-narrow on raw events. The prefix is the first 120 chars
    # of the normalised line; ES keyword prefix queries are O(log n) on the
    # term dictionary so this stays fast. We over-fetch (size * 20, capped)
    # so the Python-side hash filter has enough candidates to find `size`
    # distinct sessions even when the prefix is shared by other commands.
    prefix = norm_cmd[:120]
    fetch = max(size * 20, 500)
    try:
        r = es.search(
            index=raw_idx, size=fetch,
            _source=["process.command_line", "cowrie.session_id"],
            query={"bool": {"must": [
                {"prefix": {"process.command_line": prefix}},
                {"term": {"event.action": "cowrie.command.input"}},
            ]}},
        )
    except NotFoundError:
        log.warning("sessions_raw index %s missing; returning empty sessions_for_command", raw_idx)
        return {"rows": [], "total": 0}

    # Step 3: hash each candidate raw command_line and keep the matches.
    by_session: dict[str, int] = {}
    for h in r["hits"]["hits"]:
        src = h["_source"]
        cmd = (src.get("process") or {}).get("command_line")
        sid = (src.get("cowrie") or {}).get("session_id")
        if not cmd or not sid:
            continue
        if _hash_command(cmd) != sha256:
            continue
        by_session[sid] = by_session.get(sid, 0) + 1
    rows = [{"session_id": sid, "command_count": cnt} for sid, cnt in by_session.items()]
    rows.sort(key=lambda x: -x["command_count"])
    rows = rows[:size]

    # Step 4: optional session-quality filter. Cross-reference against
    # sessions_rollup with the filter clauses, then keep only rows whose
    # session_id is in the filtered set.
    if sf and sf.active and rows:
        sids = [x["session_id"] for x in rows]
        rollup_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
        try:
            r2 = es.search(
                index=rollup_idx, size=len(sids),
                _source=["cowrie.session_id"],
                query={"bool": {"must": [
                    {"terms": {"cowrie.session_id": sids}},
                    *sf.es_filters(),
                ]}},
            )
            keep = {h["_source"].get("cowrie", {}).get("session_id") for h in r2["hits"]["hits"]}
            rows = [x for x in rows if x["session_id"] in keep]
        except Exception as e:
            log.warning("session quality filter join failed: %s", e)

    return {"rows": rows, "total": len(rows)}


def members_of_cluster(
    es: Elasticsearch, cfg: AppConfig, kind: str, cluster_id: str, *,
    size: int = 50,
    sf: SessionFilter | None = None,
) -> dict:
    field_map = {
        "command": ("commands", "dshield.cowrie.enrichment.cluster.id"),
        "session": ("sessions_rollup", "dshield.cowrie.enrichment.session.cluster.id"),
        "ip":      ("ips_rollup", "dshield.cowrie.enrichment.ip.cluster.id"),
    }
    attr, field = field_map[kind]
    idx = getattr(cfg.elasticsearch.indexes.cowrie, attr)
    sort_field = {
        "command": "dshield.cowrie.enrichment.occurrence_count",
        "session": "dshield.cowrie.enrichment.session.command_count",
        "ip":      "dshield.cowrie.enrichment.ip.total_sessions",
    }[kind]
    must: list[dict] = [{"term": {field: cluster_id}}]
    if kind == "session" and sf:
        must.extend(sf.es_filters())
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"bool": {"must": must}},
        sort=[{sort_field: {"order": "desc", "missing": "_last"}}],
    )


def playbooks_for_ip(
    es: Elasticsearch, cfg: AppConfig, ip: str, *, size: int = 50,
) -> list[dict]:
    """All playbooks this IP ran, derived from its sessions.

    Aggregates over the sessions rollup filtered by source.ip, buckets on
    `playbook_id`, then decorates each bucket with the LLM display name from
    the session-cluster centroid. Returns `[{id, name, session_count,
    first_seen, last_seen}, ...]` sorted by session_count desc.

    Playbook membership isn't stored on the IP doc — the answer is derived
    through the sessions the IP produced.
    """
    sess_idx     = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    centroid_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    pb_field     = _resolve_agg_field(
        es, sess_idx, "dshield.cowrie.enrichment.session.playbook_id",
    )
    try:
        r = es.search(
            index=sess_idx, size=0,
            query={"term": {"source.ip": ip}},
            aggs={"by_playbook": {
                "terms": {"field": pb_field, "size": size, "min_doc_count": 1},
                "aggs": {
                    "first_seen": {"min": {"field": "event.start"}},
                    "last_seen":  {"max": {"field": "event.start"}},
                },
            }},
        )
        buckets = r["aggregations"]["by_playbook"]["buckets"]
    except Exception as exc:
        log.warning("playbooks_for_ip agg failed for %s: %s", ip, exc)
        return []
    if not buckets:
        return []
    pb_ids = [b["key"] for b in buckets if b.get("key")]
    name_map: dict[str, str] = {}
    if pb_ids:
        centroid_field = _resolve_agg_field(es, centroid_idx, "playbook_id")
        # A merged playbook can be backed by multiple centroid docs (one per
        # constituent HDBSCAN cluster); we'd need every match to be returned
        # so the name lookup doesn't miss a playbook by chance. The cap is
        # ES's default index.max_result_window — well above any realistic
        # cluster-to-playbook fanout. Names are identical across constituents.
        try:
            nresp = es.search(
                index=centroid_idx, size=min(10000, max(len(pb_ids) * 20, 100)),
                _source=["playbook_id", "playbook_name"],
                query={"terms": {centroid_field: pb_ids}},
            )
            for h in nresp["hits"]["hits"]:
                s = h["_source"]
                pid = s.get("playbook_id")
                if pid:
                    name_map[pid] = s.get("playbook_name") or ""
        except Exception:
            pass
    rows: list[dict] = []
    for b in buckets:
        pid = b.get("key")
        if not pid:
            continue
        fs = (b.get("first_seen") or {}).get("value_as_string")
        ls = (b.get("last_seen")  or {}).get("value_as_string")
        rows.append({
            "id":            pid,
            "name":          name_map.get(pid, ""),
            "session_count": b["doc_count"],
            "first_seen":    fs,
            "last_seen":     ls,
        })
    return rows


def ips_for_playbook(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str, *, size: int = 50,
) -> dict:
    """Return the IPs that contributed sessions to this playbook.

    Because playbooks live at the session-cluster layer, the IPs for a
    playbook are *derived*: collect the source IPs of every session in the
    playbook, then look those IPs up in the rollup so we get their full
    enrichment. Implemented as a terms agg over sessions then a `terms`
    lookup against the IP rollup.
    """
    sess_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    ips_idx  = cfg.elasticsearch.indexes.cowrie.ips_rollup
    pb_field = _resolve_agg_field(
        es, sess_idx, "dshield.cowrie.enrichment.session.playbook_id",
    )
    try:
        r = es.search(
            index=sess_idx, size=0,
            query={"term": {pb_field: playbook_id}},
            aggs={"src_ips": {"terms": {"field": "source.ip", "size": size}}},
        )
        ip_list = [b["key"] for b in r["aggregations"]["src_ips"]["buckets"]]
    except Exception:
        ip_list = []
    if not ip_list:
        return {"hits": {"hits": [], "total": {"value": 0}}}
    return es.search(
        index=ips_idx, size=len(ip_list), _source=_src(),
        query={"terms": {"source.ip": ip_list}},
        sort=[{"dshield.cowrie.enrichment.ip.total_sessions": {"order": "desc"}}],
    )


def sessions_for_playbook(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str, *,
    size: int = 50,
    sf: SessionFilter | None = None,
) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    pb_field = _resolve_agg_field(
        es, idx, "dshield.cowrie.enrichment.session.playbook_id",
    )
    must: list[dict] = [{"term": {pb_field: playbook_id}}]
    if sf:
        must.extend(sf.es_filters())
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"bool": {"must": must}},
        sort=[{"event.start": {"order": "desc"}}],
    )


def ips_for_asn(es: Elasticsearch, cfg: AppConfig, asn: str, *, size: int = 50) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"term": {"source.as.number": int(asn)}},
        sort=[{"dshield.cowrie.enrichment.ip.total_sessions": {"order": "desc"}}],
    )


def ips_for_country(es: Elasticsearch, cfg: AppConfig, cc: str, *, size: int = 50) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"term": {"source.geo.country_iso_code": cc}},
        sort=[{"dshield.cowrie.enrichment.ip.total_sessions": {"order": "desc"}}],
    )


def commands_for_mitre(
    es: Elasticsearch, cfg: AppConfig, mitre_id: str, *, kind: str = "technique", size: int = 50,
) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.commands
    field = "threat.technique.id" if kind == "technique" else "threat.tactic.id"
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"term": {field: mitre_id}},
        sort=[{"dshield.cowrie.enrichment.occurrence_count": {"order": "desc", "missing": "_last"}}],
    )


# ----------------------------------------------------------------------------
# Free-text search (fallback when query isn't a typed pattern)
# ----------------------------------------------------------------------------

def freetext_search(es: Elasticsearch, cfg: AppConfig, q: str, *, size: int = 25) -> list[dict]:
    """Multi-index search across command_line + playbook names + campaign names.

    Returns shallow candidate IOCRef-like dicts the API forwards to the client
    for disambiguation.
    """
    idx = cfg.elasticsearch.indexes
    candidates: list[dict] = []

    # 1. command lines (most useful free-text target).
    # Use a bool/should so:
    #   a) match — fast full-text token match (works for whole words / multiple tokens)
    #   b) wildcard on .keyword — substring match for partial words that the standard
    #      tokenizer keeps intact (e.g. "lsb" matching "lsb_release", "_release"
    #      matching any command containing that substring).
    # Escape wildcard special chars in user input so `?` / `*` aren't interpreted.
    q_esc = q.replace("\\", "\\\\").replace("?", "\\?").replace("*", "\\*")
    r = es.search(
        index=idx.cowrie.commands, size=size, _source=["process.command_line", "process.hash.sha256"],
        query={"bool": {"should": [
            {"match": {"process.command_line": {"query": q, "boost": 2}}},
            {"wildcard": {"process.command_line.keyword": {
                "value": f"*{q_esc}*",
                "case_insensitive": True,
            }}},
        ], "minimum_should_match": 1}},
    )
    for h in r["hits"]["hits"]:
        src = h["_source"]
        cmd = (src.get("process") or {}).get("command_line", "")
        sha = ((src.get("process") or {}).get("hash") or {}).get("sha256")
        if not sha:
            continue
        candidates.append({
            "type": "command_hash",
            "id": sha,
            "label": (cmd[:80] + ("…" if len(cmd) > 80 else "")) or sha[:12],
            "score": h.get("_score", 0),
        })

    # 2. Playbook names live on session-cluster centroid docs. Each centroid
    # carries a `playbook_id` (the canonical primary key) plus a display
    # `playbook_name` from the LLM. With cluster merging enabled multiple
    # centroid docs can share one playbook_id (and identical name) — we
    # collapse those to a single dropdown candidate keyed on playbook_id.
    # Distinct playbooks with identical display names still surface as
    # separate candidates and get a disambiguating suffix.
    cluster_idx = idx.cowrie.session_clusters
    must_clauses: list[dict] = [{"term": {"doc_type": "cluster"}}]
    # Scope to the latest run so stale centroids from previous runs don't
    # crowd the dropdown.
    run_cache_local = RunCache(ttl_seconds=60)
    latest_run = run_cache_local.latest(es, cluster_idx)
    if latest_run:
        must_clauses.append({"term": {"run_id": latest_run}})
    must_clauses.append({"bool": {"should": [
        {"term":     {"playbook_name": q}},
        {"wildcard": {"playbook_name": {"value": f"*{q_esc}*", "case_insensitive": True}}},
    ], "minimum_should_match": 1}})
    try:
        r = es.search(
            index=cluster_idx, size=20,
            _source=["playbook_id", "playbook_name", "cluster_id", "size"],
            query={"bool": {"must": must_clauses}},
        )
        hits = r["hits"]["hits"]
    except Exception:
        hits = []
    # Collapse hits by playbook_id (merged playbooks have >1 centroid doc).
    # Keep the highest-scoring hit per playbook_id; preserve order of first
    # appearance for stable dropdown ranking.
    by_pid: dict[str, dict] = {}
    for h in hits:
        pid = (h.get("_source") or {}).get("playbook_id")
        if not pid:
            continue
        prev = by_pid.get(pid)
        if prev is None or h.get("_score", 0) > prev.get("_score", 0):
            by_pid[pid] = h
    # Detect display-name collisions across DIFFERENT playbooks so the label
    # can disambiguate. Same playbook_id sharing a name is not a collision.
    name_to_pids: dict[str, set[str]] = {}
    for pid, h in by_pid.items():
        nm = h["_source"].get("playbook_name") or ""
        if nm:
            name_to_pids.setdefault(nm, set()).add(pid)
    for pid, h in by_pid.items():
        src = h["_source"]
        nm     = src.get("playbook_name") or "(unnamed)"
        sescid = src.get("cluster_id")
        suffix = f" · sescl {sescid}" if len(name_to_pids.get(nm, ())) > 1 and sescid else ""
        candidates.append({
            "type":  "playbook",
            "id":    pid,
            "label": f"playbook: {nm}{suffix}",
            "score": h.get("_score", 0),
        })

    # 2b. Multi-session campaigns mined by `mine campaigns`. Has its own
    # index with its own `campaign_id` keyword. Same wildcard/exact pattern
    # as playbook search.
    camp_idx = idx.cowrie.campaigns
    try:
        r = es.search(
            index=camp_idx, size=10,
            _source=["campaign_id", "name", "kind", "ip_count", "session_count"],
            query={"bool": {"must": [
                {"term": {"doc_type": "campaign"}},
                {"bool": {"should": [
                    {"term":     {"name": q}},
                    {"wildcard": {"name": {"value": f"*{q_esc}*", "case_insensitive": True}}},
                ], "minimum_should_match": 1}},
            ]}},
        )
        cam_hits = r["hits"]["hits"]
    except Exception:
        cam_hits = []
    for h in cam_hits:
        src = h["_source"]
        cid  = src.get("campaign_id")
        nm   = src.get("name") or "(unnamed)"
        kind = src.get("kind") or "?"
        if not cid:
            continue
        candidates.append({
            "type":  "campaign",
            "id":    cid,
            "label": f"campaign [{kind}]: {nm}",
            "score": h.get("_score", 0),
        })

    # 3. Cluster IDs (name-style: "cluster_11", "outlier") across all three
    # cluster indices.  Uses prefix + term so partial names work too.
    for cl_idx, cl_kind, cl_type in [
        (idx.cowrie.session_clusters, "session", "session_cluster"),
        (idx.cowrie.ip_clusters,      "ip",      "ip_cluster"),
        (idx.cowrie.command_clusters, "command",  "command_cluster"),
    ]:
        run_cache_obj = RunCache(ttl_seconds=60)
        run_id = run_cache_obj.latest(es, cl_idx)
        must_clauses: list[dict] = [{"term": {"doc_type": "cluster"}}]
        if run_id:
            must_clauses.append({"term": {"run_id": run_id}})
        must_clauses.append({"bool": {"should": [
            {"term":   {"cluster_id": q.lower()}},
            {"prefix": {"cluster_id": q.lower()}},
        ], "minimum_should_match": 1}})
        # `playbook_name` only exists on session_clusters; other cluster
        # indexes ignore the field gracefully.
        try:
            r = es.search(index=cl_idx, size=5,
                          _source=["cluster_id", "playbook_name"],
                          query={"bool": {"must": must_clauses}})
        except Exception:
            continue
        for h in r["hits"]["hits"]:
            cid = h["_source"].get("cluster_id")
            if not cid:
                continue
            pb_name = h["_source"].get("playbook_name")
            label = f"{cl_kind} cluster {cid}" + (f" · {pb_name}" if pb_name else "")
            candidates.append({
                "type": cl_type,
                "id":    cid,
                "label": label,
                "score": 0.5,
            })

    candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
    return candidates[:size]


# ----------------------------------------------------------------------------
# Health
# ----------------------------------------------------------------------------

def health(es: Elasticsearch, cfg: AppConfig) -> dict:
    info = es.info()
    indexes = cfg.elasticsearch.indexes.cowrie.model_dump()
    counts: dict[str, Any] = {}
    for name, idx in indexes.items():
        try:
            counts[name] = es.count(index=idx).get("count", 0)
        except Exception as e:
            counts[name] = f"error: {e.__class__.__name__}"
    return {
        "elasticsearch_version": info.get("version", {}).get("number"),
        "cluster_name": info.get("cluster_name"),
        "indexes": indexes,
        "doc_counts": counts,
    }


# ---------------------------------------------------------------------------
# Insights: pre-aggregated data for the /insights dashboard page.
# ---------------------------------------------------------------------------

def insights_summary(
    es: Elasticsearch, cfg: AppConfig, run_cache: RunCache,
) -> dict:
    idxs = cfg.elasticsearch.indexes.cowrie

    # --- Overview counts ---------------------------------------------------
    def _count(idx: str) -> int:
        try:
            return es.count(index=idx).get("count", 0)
        except Exception:
            return 0

    total_ips = _count(idxs.ips_rollup)
    total_sessions = _count(idxs.sessions_rollup)
    total_commands = _count(idxs.commands)

    pb_field = _resolve_agg_field(
        es, idxs.sessions_rollup, "dshield.cowrie.enrichment.session.playbook_id",
    )
    try:
        r = es.search(index=idxs.sessions_rollup, size=0, aggs={
            "playbooks": {"cardinality": {"field": pb_field}}
        })
        active_playbooks = r["aggregations"]["playbooks"]["value"]
    except Exception:
        active_playbooks = 0

    # --- Cluster run summaries --------------------------------------------
    def _run_summary(idx: str, kind: str) -> dict:
        run_id = run_cache.latest(es, idx)
        must: list[dict] = [{"term": {"doc_type": "run_summary"}}]
        if run_id:
            must.append({"term": {"run_id": run_id}})
        try:
            r = es.search(index=idx, size=1,
                          _source=["total_docs", "n_clusters", "n_outliers",
                                   "run_id", "@timestamp"],
                          query={"bool": {"must": must}},
                          sort=[{"@timestamp": {"order": "desc"}}])
            hits = r["hits"]["hits"]
            src = hits[0]["_source"] if hits else {}
        except Exception:
            src = {}
        return {
            "total_docs": src.get("total_docs"),
            "n_clusters": src.get("n_clusters"),
            "n_outliers": src.get("n_outliers"),
            "run_id": src.get("run_id"),
            "timestamp": src.get("@timestamp"),
        }

    cluster_runs = {
        "command": _run_summary(idxs.command_clusters, "command"),
        "session": _run_summary(idxs.session_clusters, "session"),
        "ip":      _run_summary(idxs.ip_clusters, "ip"),
    }

    # --- Playbooks --------------------------------------------------------
    # Aggregate over the session rollup (the canonical playbook membership
    # source). For each playbook_id bucket we count sessions directly and
    # use a cardinality sub-agg on source.ip for the distinct-IP count, then
    # look up the centroid doc to get the LLM display name.
    playbooks: list[dict] = []
    # `pb_field` is reused from the active_playbooks block above.
    # Sparkline: 14-day daily session-count per playbook, baked into the
    # same agg so the Insights endpoint is still one round-trip.
    try:
        r = es.search(
            index=idxs.sessions_rollup, size=0,
            query={"range": {"event.start": {"gte": "now-14d"}}},
            aggs={
                "by_playbook": {
                    "terms": {
                        "field": pb_field,
                        "size": 30,
                        "order": {"_count": "desc"},
                        "min_doc_count": 1,
                    },
                    "aggs": {
                        "distinct_ips": {"cardinality": {"field": "source.ip"}},
                        "daily": {
                            "date_histogram": {
                                "field": "event.start",
                                "fixed_interval": "1d",
                                "min_doc_count": 0,
                                "extended_bounds": {"min": "now-14d", "max": "now"},
                            },
                        },
                    },
                },
            },
        )
        buckets = r["aggregations"]["by_playbook"]["buckets"]
        pb_ids = [b["key"] for b in buckets if b.get("key")]
        name_map: dict[str, str] = {}
        if pb_ids:
            centroid_field = _resolve_agg_field(
                es, idxs.session_clusters, "playbook_id",
            )
            try:
                # A merged playbook can have multiple centroid docs; bump size
                # so every constituent comes back even when fanout > 1.
                nresp = es.search(
                    index=idxs.session_clusters,
                    size=min(10000, max(len(pb_ids) * 20, 100)),
                    _source=["playbook_id", "playbook_name"],
                    query={"terms": {centroid_field: pb_ids}},
                )
                for h in nresp["hits"]["hits"]:
                    s = h["_source"]
                    pid = s.get("playbook_id")
                    nm  = s.get("playbook_name")
                    if pid:
                        name_map[pid] = nm or ""
            except Exception:
                pass
        for b in buckets:
            pid = b.get("key")
            if not pid:
                continue
            # 14-day daily counts as a plain int array, oldest → newest. The
            # frontend renders it as an inline SVG sparkline; the dates are
            # implied by position (today is the last bucket).
            daily_counts = [
                int(db.get("doc_count") or 0)
                for db in (b.get("daily") or {}).get("buckets", [])
            ]
            playbooks.append({
                "id":            pid,
                "name":          name_map.get(pid, ""),
                "session_count": b["doc_count"],
                "ip_count":      int(b["distinct_ips"]["value"]),
                "daily_14d":     daily_counts,
            })
    except Exception as e:
        log.warning("insights playbooks failed: %s", e)

    # --- Top command clusters ---------------------------------------------
    command_clusters: list[dict] = []
    try:
        run_id = run_cache.latest(es, idxs.command_clusters)
        must: list[dict] = [{"term": {"doc_type": "cluster"}}]
        if run_id:
            must.append({"term": {"run_id": run_id}})
        r = es.search(
            index=idxs.command_clusters, size=10,
            _source=["cluster_id", "size", "sample_commands"],
            query={"bool": {"must": must}},
            sort=[{"size": {"order": "desc"}}],
        )
        cluster_ids = []
        raw_clusters: list[dict] = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            cid = s.get("cluster_id")
            if not cid:
                continue
            cluster_ids.append(cid)
            samples = s.get("sample_commands") or []
            if isinstance(samples, str):
                samples = [samples]
            raw_clusters.append({
                "cluster_id": cid,
                "size": s.get("size", 0),
                "sample_commands": [c[:100] for c in samples[:3]],
                "dominant_intent": None,
            })
        # Enrich with dominant intent per cluster
        if cluster_ids:
            r2 = es.search(
                index=idxs.commands, size=0,
                query={"bool": {"filter": [
                    {"terms": {"dshield.cowrie.enrichment.cluster.id": cluster_ids}},
                    {"term": {"dshield.cowrie.enrichment.cluster.is_outlier": False}},
                ]}},
                aggs={"by_cluster": {
                    "terms": {"field": "dshield.cowrie.enrichment.cluster.id", "size": 20},
                    "aggs": {"dominant_intent": {
                        "terms": {"field": "dshield.cowrie.enrichment.intent", "size": 1}
                    }}
                }},
            )
            intent_map: dict[str, str | None] = {}
            for b in r2["aggregations"]["by_cluster"]["buckets"]:
                ib = b["dominant_intent"]["buckets"]
                intent_map[b["key"]] = ib[0]["key"] if ib else None
            for cl in raw_clusters:
                cl["dominant_intent"] = intent_map.get(cl["cluster_id"])
        command_clusters = raw_clusters
    except Exception as e:
        log.warning("insights command_clusters failed: %s", e)

    # --- Top session clusters ---------------------------------------------
    session_clusters: list[dict] = []
    try:
        run_id = run_cache.latest(es, idxs.session_clusters)
        must = [{"term": {"doc_type": "cluster"}}]
        if run_id:
            must.append({"term": {"run_id": run_id}})
        r = es.search(
            index=idxs.session_clusters, size=10,
            _source=["cluster_id", "size", "playbook_id", "playbook_name", "sample_session_ids"],
            query={"bool": {"must": must}},
            sort=[{"size": {"order": "desc"}}],
        )
        for h in r["hits"]["hits"]:
            s = h["_source"]
            cid = s.get("cluster_id")
            if not cid:
                continue
            samples = s.get("sample_session_ids") or []
            if isinstance(samples, str):
                samples = [samples]
            session_clusters.append({
                "cluster_id":          cid,
                "size":                s.get("size", 0),
                "playbook_id":         s.get("playbook_id"),
                "playbook_name":       s.get("playbook_name"),
                "sample_session_ids":  [str(x)[:16] for x in samples[:3]],
            })
    except Exception as e:
        log.warning("insights session_clusters failed: %s", e)

    # --- Top IP clusters --------------------------------------------------
    ip_clusters: list[dict] = []
    try:
        run_id = run_cache.latest(es, idxs.ip_clusters)
        must = [{"term": {"doc_type": "cluster"}}]
        if run_id:
            must.append({"term": {"run_id": run_id}})
        r = es.search(
            index=idxs.ip_clusters, size=10,
            _source=["cluster_id", "size", "sample_ips"],
            query={"bool": {"must": must}},
            sort=[{"size": {"order": "desc"}}],
        )
        cluster_ids = []
        raw_ip_clusters: list[dict] = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            cid = s.get("cluster_id")
            if not cid:
                continue
            cluster_ids.append(cid)
            samples = s.get("sample_ips") or []
            if isinstance(samples, str):
                samples = [samples]
            # IP clusters are unnamed actor profiles; an IP's playbook
            # membership is derived from the sessions it produced. The
            # `playbook_count` here is the breadth of playbooks spanned by
            # this IP cluster's IPs.
            raw_ip_clusters.append({
                "cluster_id":     cid,
                "size":           s.get("size", 0),
                "sample_ips":     list(samples[:4]),
                "top_countries":  [],
                "playbook_count": None,
            })
        # Enrich with top countries per cluster
        if cluster_ids:
            r2 = es.search(
                index=idxs.ips_rollup, size=0,
                query={"terms": {"dshield.cowrie.enrichment.ip.cluster.id": cluster_ids}},
                aggs={"by_cluster": {
                    "terms": {"field": "dshield.cowrie.enrichment.ip.cluster.id", "size": 20},
                    "aggs": {"countries": {
                        "terms": {"field": "source.geo.country_iso_code", "size": 5}
                    }}
                }},
            )
            cc_map: dict[str, list[dict]] = {}
            for b in r2["aggregations"]["by_cluster"]["buckets"]:
                cc_map[b["key"]] = [
                    {"cc": cb["key"], "count": cb["doc_count"]}
                    for cb in b["countries"]["buckets"]
                ]
            for cl in raw_ip_clusters:
                cl["top_countries"] = cc_map.get(cl["cluster_id"], [])

            # Per-cluster distinct playbook count: for each IP cluster, count
            # the distinct playbook_ids spanned by sessions of IPs in that
            # cluster. Two-hop join (ipcluster -> ips -> sessions -> playbooks).
            try:
                cluster_to_ips: dict[str, list[str]] = {cid: [] for cid in cluster_ids}
                r3 = es.search(
                    index=idxs.ips_rollup, size=0,
                    query={"terms": {"dshield.cowrie.enrichment.ip.cluster.id": cluster_ids}},
                    aggs={"by_cluster": {
                        "terms": {"field": "dshield.cowrie.enrichment.ip.cluster.id", "size": len(cluster_ids)},
                        "aggs": {"ips": {"terms": {"field": "source.ip", "size": 500}}},
                    }},
                )
                for b in r3["aggregations"]["by_cluster"]["buckets"]:
                    cluster_to_ips[b["key"]] = [ib["key"] for ib in b["ips"]["buckets"]]

                pb_field2 = _resolve_agg_field(
                    es, idxs.sessions_rollup,
                    "dshield.cowrie.enrichment.session.playbook_id",
                )
                pb_count_map: dict[str, int] = {}
                for cid, ip_list in cluster_to_ips.items():
                    if not ip_list:
                        pb_count_map[cid] = 0
                        continue
                    try:
                        rc = es.search(
                            index=idxs.sessions_rollup, size=0,
                            query={"terms": {"source.ip": ip_list}},
                            aggs={"distinct_playbooks": {"cardinality": {"field": pb_field2}}},
                        )
                        pb_count_map[cid] = int(rc["aggregations"]["distinct_playbooks"]["value"])
                    except Exception:
                        pb_count_map[cid] = 0
                for cl in raw_ip_clusters:
                    cl["playbook_count"] = pb_count_map.get(cl["cluster_id"], 0)
            except Exception as e:
                log.warning("insights ip_clusters playbook_count failed: %s", e)
        ip_clusters = raw_ip_clusters
    except Exception as e:
        log.warning("insights ip_clusters failed: %s", e)

    # --- Novel-but-recurring commands -------------------------------------
    novel_commands: list[dict] = []
    try:
        # Use is_outlier=True since truly novel commands are outliers.
        # Filter occurrence_count >= 3 to exclude one-off typos.
        r = es.search(
            index=idxs.commands, size=20,
            _source=[
                "process.command_line", "process.hash.sha256",
                "dshield.cowrie.enrichment.intent",
                "dshield.cowrie.enrichment.cluster.novelty_score",
                "dshield.cowrie.enrichment.cluster.is_outlier",
                "dshield.cowrie.enrichment.unique_sessions",
                "dshield.cowrie.enrichment.unique_source_ips",
                "dshield.cowrie.enrichment.occurrence_count",
                "threat.tactic", "threat.technique",
            ],
            query={"bool": {"filter": [
                {"range": {"dshield.cowrie.enrichment.unique_sessions": {"gte": 3}}},
            ]}},
            sort=[{
                "dshield.cowrie.enrichment.cluster.novelty_score": {"order": "desc"}
            }],
        )
        import math as _math
        for h in r["hits"]["hits"]:
            s = h["_source"]
            enr = (s.get("dshield") or {}).get("cowrie", {}).get("enrichment", {}) or {}
            cluster = enr.get("cluster") or {}
            novelty = cluster.get("novelty_score") or 0.0
            sess = enr.get("unique_sessions") or 0
            # Compute a combined "interesting" score weighting novelty × spread
            score = novelty * _math.log(sess + 1)
            sha = ((s.get("process") or {}).get("hash") or {}).get("sha256") or ""
            cmd_line = (s.get("process") or {}).get("command_line") or sha
            threat = s.get("threat") or {}
            from . import graph as _graph
            tactics = _graph._mitre_ids(threat.get("tactic"))
            techniques = _graph._mitre_ids(threat.get("technique"))
            novel_commands.append({
                "sha256": sha,
                "command_line": cmd_line,
                "intent": enr.get("intent"),
                "novelty_score": novelty,
                "is_outlier": cluster.get("is_outlier", False),
                "unique_sessions": sess,
                "unique_source_ips": enr.get("unique_source_ips") or 0,
                "occurrence_count": enr.get("occurrence_count") or 0,
                "score": score,
                "tactics": tactics,
                "techniques": techniques,
            })
        # Re-sort by combined score (not just raw novelty)
        novel_commands.sort(key=lambda x: x["score"], reverse=True)
    except Exception as e:
        log.warning("insights novel_commands failed: %s", e)

    # Multi-session campaigns from the campaigns index — best-effort; an
    # empty list is fine if the miner hasn't run yet.
    mined_campaigns = list_campaigns(es, cfg, size=20)

    return {
        "overview": {
            "total_ips":        total_ips,
            "total_sessions":   total_sessions,
            "total_commands":   total_commands,
            "active_playbooks": active_playbooks,
            "cluster_runs":     cluster_runs,
        },
        # Playbooks (named session clusters) and mined campaigns (multi-
        # session patterns) are distinct surfaces.
        "playbooks":         playbooks,
        "mined_campaigns":   mined_campaigns,
        "command_clusters":  command_clusters,
        "session_clusters":  session_clusters,
        "ip_clusters":       ip_clusters,
        "novel_commands":    novel_commands,
    }


# ---------------------------------------------------------------------------
# Timeline: session data for the Timeline view.
# ---------------------------------------------------------------------------

_TL_SOURCE = [
    "cowrie.session_id",
    "source.ip",
    "@timestamp",
    "event.start",
    "event.end",
    "dshield.cowrie.enrichment.session.command_count",
    "dshield.cowrie.enrichment.session.dominant_intent",
    "dshield.cowrie.enrichment.session.playbook_id",
    "dshield.cowrie.enrichment.session.playbook_name",
    "dshield.cowrie.enrichment.session.cluster.id",
    "dshield.cowrie.enrichment.session.cluster.is_outlier",
    "dshield.cowrie.enrichment.session.login_success_count",
    "dshield.cowrie.enrichment.session.mean_novelty_score",
]


def timeline_sessions(
    es: Elasticsearch, cfg: AppConfig,
    *,
    kind: str,       # "ip" | "session_cluster" | "playbook"
    id_: str,
    limit: int = 500,
    sf: SessionFilter | None = None,
) -> dict:
    """Fetch sessions for the Timeline view, scoped to a specific IOC.

    Returns sessions sorted ascending by event.start together with metadata
    needed to lay out the swimlane canvas: unique cluster ids, time bounds,
    total count (pre-truncation).
    """
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup

    field_map = {
        "ip":              "source.ip",
        "session_cluster": "dshield.cowrie.enrichment.session.cluster.id",
    }
    if kind not in field_map and kind != "playbook":
        return {"sessions": [], "clusters": [], "time_range": None, "total": 0, "shown": 0}

    if kind == "playbook":
        # Playbooks live at the session-cluster layer — filter sessions
        # directly by `playbook_id`.
        pb_field = _resolve_agg_field(
            es, idx, "dshield.cowrie.enrichment.session.playbook_id",
        )
        must: list[dict] = [{"term": {pb_field: id_}}]
    else:
        must = [{"term": {field_map[kind]: id_}}]

    if sf and sf.active:
        must.extend(sf.es_filters())

    try:
        r = es.search(
            index=idx, size=limit,
            _source=_TL_SOURCE,
            query={"bool": {"must": must}},
            sort=[{"event.start": {"order": "asc", "unmapped_type": "date"}}],
        )
    except Exception as e:
        log.warning("timeline_sessions failed: %s", e)
        return {"sessions": [], "clusters": [], "time_range": None, "total": 0, "shown": 0}

    total = r["hits"]["total"]["value"]
    hits = r["hits"]["hits"]
    sessions: list[dict] = []
    cluster_set: dict[str, dict] = {}   # cluster_id -> {id, playbook_id, playbook_name, is_outlier}
    t_min: str | None = None
    t_max: str | None = None

    for h in hits:
        s = h["_source"]
        enr = ((s.get("dshield") or {}).get("cowrie") or {}).get("enrichment", {}).get("session") or {}
        cl = enr.get("cluster") or {}
        start = (s.get("event") or {}).get("start") or s.get("@timestamp")
        end = (s.get("event") or {}).get("end") or start
        cluster_id = cl.get("id") or "none"

        sessions.append({
            "id":              (s.get("cowrie") or {}).get("session_id") or h["_id"],
            "src_ip":          (s.get("source") or {}).get("ip") or "",
            "start":           start,
            "end":             end,
            "command_count":   enr.get("command_count") or 0,
            "intent":          enr.get("dominant_intent"),
            # `playbook_id` is the stable grouping key; `playbook_name` is the
            # display label. Two playbooks can share a name but never an id.
            "playbook_id":     enr.get("playbook_id"),
            "playbook_name":   enr.get("playbook_name"),
            "cluster_id":      cluster_id,
            "is_outlier":      cl.get("is_outlier", False),
            "novelty":         enr.get("mean_novelty_score"),
            "login_success":   enr.get("login_success_count") or 0,
        })

        if cluster_id not in cluster_set:
            cluster_set[cluster_id] = {
                "id":            cluster_id,
                "playbook_id":   enr.get("playbook_id"),
                "playbook_name": enr.get("playbook_name"),
                "is_outlier":    cl.get("is_outlier", False),
            }

        if start:
            if t_min is None or start < t_min:
                t_min = start
            if t_max is None or end > t_max:
                t_max = end

    # Sort clusters so named ones come first, then outliers last.
    clusters = sorted(cluster_set.values(), key=lambda c: (
        c["is_outlier"], c["id"] == "none", c["id"]
    ))

    return {
        "sessions":   sessions,
        "clusters":   clusters,
        "time_range": {"start": t_min, "end": t_max} if t_min else None,
        "total":      total,
        "shown":      len(sessions),
    }
