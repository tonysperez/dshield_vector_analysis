"""Multi-session campaign mining.

A "campaign" under the new model is a *multi-session* behavioral or
infrastructural pattern, distinct from a session cluster (now called a
"playbook"). Two independent miners produce campaign docs:

  behaviour   — frequent-itemset mining over per-IP playbook bags.
                Catches kill-chain combinations: "IPs that ran playbook A
                AND playbook B AND playbook C are doing the same operation."

  infrastructure — connected-component mining over a session-session graph
                where edges are shared artifacts (URLs, file hashes, SSH
                keys). Catches operations tied by shared toolchain even when
                the commands themselves differ.

Output schema is shared: one doc per campaign in `cfg.elasticsearch.indexes.
cowrie.campaigns`. See es-mappings/cowrie/campaigns.json. The console reads
this index to render the `campaign` IOC type.

Why the two flavours coexist
----------------------------
They answer different threat-hunting questions (combo vs shared-infra) and
are structurally orthogonal — behaviour mining can miss a campaign that
rotates playbooks but stays on one CDN; infrastructure mining can miss a
campaign where IPs share a playbook but rotate URLs every hour. Running
both and intersecting (or unioning) gives the hunter two lenses on the
same dataset.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

from ...config import AppConfig, Secrets
from ...es_client import init_index, make_client

log = logging.getLogger(__name__)

# Used by both miners to ensure the campaigns index exists with the right
# explicit mapping before we bulk-write into it. Without this, a fresh
# deployment that runs `mine campaigns` before `init-indexes` would let ES
# auto-create the index with dynamic mapping — silently mis-typing fields
# like `member_playbook_ids` (would become `text` instead of `keyword`).
_CAMPAIGNS_MAPPING = "es-mappings/cowrie/campaigns.json"


_BEHAVIOUR_MIN_SUPPORT_IPS = 5     # itemset must hold for >=N IPs to be a campaign
_BEHAVIOUR_MIN_ITEMSET_SIZE = 2    # singletons aren't campaigns — they're playbooks
_BEHAVIOUR_MAX_ITEMSET_SIZE = 6    # combinatorial guard; very few real ops chain >6 playbooks

_INFRA_MIN_SESSIONS = 3            # connected component must have >=N sessions
_INFRA_MIN_DISTINCT_IPS = 2        # ...and >=N distinct source IPs (a single IP is not a campaign)
_INFRA_MAX_ARTIFACT_FREQ = 0.50    # ignore artifacts present in >50% of all sessions (too generic)
_INFRA_MAX_COMPONENT_SIZE = 5000   # sanity cap on members per component to keep ES docs sane

_SAMPLE_IPS_PER_CAMPAIGN      = 50
_SAMPLE_SESSIONS_PER_CAMPAIGN = 100
_TOP_ARTIFACTS_PER_CAMPAIGN   = 30


# Regexes for D-side artifact extraction. Conservative on purpose: each
# pattern aims for "high precision, low recall" — false positives in the
# artifact set will glue unrelated sessions together via spurious edges.
_URL_RE = re.compile(
    r"https?://[A-Za-z0-9._\-]+(?:\:\d+)?(?:/[A-Za-z0-9._\-/?=&%+~:]*)?",
    re.IGNORECASE,
)
_SSH_KEY_RE = re.compile(
    r"ssh-(?:rsa|dss|ed25519|ecdsa-[A-Za-z0-9-]+)\s+[A-Za-z0-9+/=]{40,}",
)
# Stand-alone SHA-256 / SHA-1 / MD5 hex strings appearing in command text.
_HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")


# ===========================================================================
# Shared helpers
# ===========================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _campaign_id(kind: str, fingerprint: str) -> str:
    """Stable campaign id.

    Format: `cmp-<kind3>-<short_hash>`. The hash is computed from the
    fingerprint string (sorted itemset for behaviour; sorted artifact list
    for infra) so two mining runs that find the same campaign produce the
    same id.
    """
    h = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16]
    return f"cmp-{kind[:3]}-{h}"


def _iter_session_rollups(
    es: Elasticsearch, idx: str, page_size: int = 1000,
) -> Iterable[dict]:
    """Yield every session rollup doc's _source. Uses search_after pagination
    for stable iteration over potentially millions of docs."""
    body = {
        "size": page_size,
        "_source": [
            "cowrie.session_id", "source.ip", "event.start", "event.end",
            "dshield.cowrie.enrichment.session.playbook_id",
            "dshield.cowrie.enrichment.session.playbook_name",
            "dshield.cowrie.enrichment.session.command_count",
        ],
        "query": {"match_all": {}},
        "sort": [{"event.start": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h["_source"]
        search_after = hits[-1]["sort"]


# ===========================================================================
# A: behaviour (itemset) mining
# ===========================================================================

def _frequent_itemsets(
    transactions: list[frozenset[str]], *,
    min_support: int, min_size: int, max_size: int,
) -> list[tuple[frozenset[str], int]]:
    """Apriori-style frequent-itemset miner. Returns
    `[(itemset, support_count), ...]` for every itemset whose support is
    >= min_support and size is within [min_size, max_size].

    Suitable for the small candidate space we operate on (≤ a few hundred
    distinct playbook ids; thousands of IPs). For larger candidate sets
    swap in `mlxtend.fpgrowth`.
    """
    if not transactions:
        return []
    # Level 1: singletons.
    counts: dict[str, int] = defaultdict(int)
    for tx in transactions:
        for item in tx:
            counts[item] += 1
    L: list[frozenset[str]] = [frozenset([i]) for i, c in counts.items() if c >= min_support]
    all_frequent: list[tuple[frozenset[str], int]] = []
    if min_size <= 1:
        for s in L:
            all_frequent.append((s, counts[next(iter(s))]))

    k = 2
    while L and k <= max_size:
        # Generate candidates by joining size-(k-1) frequent itemsets.
        candidates: set[frozenset[str]] = set()
        L_list = sorted(L, key=lambda s: sorted(s))
        for i in range(len(L_list)):
            for j in range(i + 1, len(L_list)):
                u = L_list[i] | L_list[j]
                if len(u) == k:
                    candidates.add(u)
        # Count support for each candidate.
        sup: dict[frozenset[str], int] = defaultdict(int)
        for tx in transactions:
            for c in candidates:
                if c.issubset(tx):
                    sup[c] += 1
        # Filter by min_support.
        L = [c for c in candidates if sup[c] >= min_support]
        if k >= min_size:
            for c in L:
                all_frequent.append((c, sup[c]))
        k += 1
    return all_frequent


def _build_ip_to_playbooks(es: Elasticsearch, sessions_idx: str) -> dict[str, dict]:
    """Group session-rollup docs by source.ip; for each IP collect the
    *set* of canonical playbook ids it visited, plus the session ids and a
    time bound.

    Filters: sessions without a `playbook_id` are skipped (this naturally
    excludes outliers and any session whose playbook hasn't been named yet —
    `name playbooks` writes `playbook_id` only for non-outlier clusters).

    Returns `{ip: {"playbooks": set[str], "sessions": list[str],
                   "first_seen": iso, "last_seen": iso}}`.
    """
    out: dict[str, dict] = {}
    for src in _iter_session_rollups(es, sessions_idx):
        ip  = (src.get("source") or {}).get("ip")
        sid = (src.get("cowrie") or {}).get("session_id")
        senr = (src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
        # The canonical playbook id (`sescl-<16hex>`, a SHA-256 over the
        # sorted member session ids — see _make_playbook_id). Multiple
        # HDBSCAN clusters can map to one playbook (cluster merge at name
        # time), and `cluster.id` alone is run-scoped, so anchoring on
        # playbook_id is the only correct cross-IP identity. The
        # content-hashed form means re-clustering preserves the id when
        # membership is unchanged — so campaign ids (which fingerprint
        # sorted playbook-id sets, below) survive across runs too.
        pid  = senr.get("playbook_id")
        if not ip or not pid:
            continue
        ev = src.get("event") or {}
        start = ev.get("start")
        rec = out.get(ip)
        if rec is None:
            rec = {"playbooks": set(), "sessions": [], "first_seen": start, "last_seen": start}
            out[ip] = rec
        rec["playbooks"].add(str(pid))
        if sid:
            rec["sessions"].append(sid)
        if start:
            if rec["first_seen"] is None or start < rec["first_seen"]:
                rec["first_seen"] = start
            if rec["last_seen"] is None or start > rec["last_seen"]:
                rec["last_seen"] = start
    return out


def run_mine_behaviour(
    cfg: AppConfig, secrets: Secrets, *,
    dry_run: bool = False,
    min_support: int = _BEHAVIOUR_MIN_SUPPORT_IPS,
    min_size: int   = _BEHAVIOUR_MIN_ITEMSET_SIZE,
    max_size: int   = _BEHAVIOUR_MAX_ITEMSET_SIZE,
) -> dict:
    """Itemset-mining campaign discovery (the "A" approach).

    Each frequent itemset of playbook ids becomes a campaign whose member
    IPs are those that visited every playbook in the itemset and whose
    member sessions are those IPs' sessions in any of the itemset's
    playbooks. Closed itemsets only — if an itemset is a strict subset of
    another with the same support, only the larger is kept.
    """
    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    out_idx      = cfg.elasticsearch.indexes.cowrie.campaigns

    t0 = time.time()
    log.info("[mine behaviour] reading session rollup %s", sessions_idx)
    ip_to_pb = _build_ip_to_playbooks(es, sessions_idx)
    log.info("[mine behaviour] %d IPs with >=1 non-outlier playbook session", len(ip_to_pb))

    transactions = [frozenset(rec["playbooks"]) for rec in ip_to_pb.values()]
    itemsets = _frequent_itemsets(
        transactions,
        min_support=min_support, min_size=min_size, max_size=max_size,
    )
    log.info("[mine behaviour] %d frequent itemsets (min_support=%d, sizes %d..%d)",
             len(itemsets), min_support, min_size, max_size)

    # Closed itemsets: drop any itemset that's a strict subset of a larger
    # itemset with the same support count.
    by_support: dict[int, list[frozenset[str]]] = defaultdict(list)
    for s, cnt in itemsets:
        by_support[cnt].append(s)
    closed: list[tuple[frozenset[str], int]] = []
    for cnt, sets in by_support.items():
        # Sort largest first; a set is closed if it isn't a strict subset
        # of any earlier (larger) set with the same support.
        sets.sort(key=lambda s: -len(s))
        kept: list[frozenset[str]] = []
        for s in sets:
            if any(s < bigger for bigger in kept):
                continue
            kept.append(s)
        for s in kept:
            closed.append((s, cnt))
    log.info("[mine behaviour] %d closed itemsets after pruning", len(closed))

    docs: list[dict] = []
    run_id = str(uuid.uuid4())
    for itemset, support in closed:
        ips = [ip for ip, rec in ip_to_pb.items() if itemset.issubset(rec["playbooks"])]
        if len(ips) < min_support:
            continue  # belt-and-suspenders
        sessions: list[str] = []
        first_seen = None
        last_seen  = None
        for ip in ips:
            rec = ip_to_pb[ip]
            for sid in rec["sessions"]:
                sessions.append(sid)
            fs = rec.get("first_seen"); ls = rec.get("last_seen")
            if fs and (first_seen is None or fs < first_seen): first_seen = fs
            if ls and (last_seen  is None or ls > last_seen):  last_seen  = ls
        sorted_pb = sorted(itemset)
        fingerprint = "|".join(sorted_pb)
        cid = _campaign_id("behaviour", fingerprint)
        name = "Playbook combo: " + " + ".join(sorted_pb)
        docs.append({
            "_index": out_idx,
            "_id":    cid,
            "_source": {
                "@timestamp":           _now_iso(),
                "run_id":               run_id,
                "doc_type":             "campaign",
                "campaign_id":          cid,
                "kind":                 "behaviour",
                "name":                 name,
                "rationale":            (
                    f"{len(ips)} IPs ran every playbook in {sorted_pb} — itemset "
                    f"closed under support {support}."
                ),
                "ip_count":             len(ips),
                "session_count":        len(sessions),
                "first_seen":           first_seen,
                "last_seen":            last_seen,
                "support":              support,
                "member_playbook_ids":  sorted_pb,
                "member_session_ids":   sessions[:_SAMPLE_SESSIONS_PER_CAMPAIGN],
                "member_source_ips":    ips[:_SAMPLE_IPS_PER_CAMPAIGN],
                "shared_artifacts":     [],
            },
        })

    stats = {
        "ips_seen":         len(ip_to_pb),
        "frequent_itemsets": len(itemsets),
        "closed_itemsets":   len(closed),
        "campaigns_written": len(docs),
        "run_id":            run_id,
        "min_support":       min_support,
        "dry_run":           dry_run,
        "runtime_seconds":   round(time.time() - t0, 2),
    }
    if dry_run or not docs:
        log.info("[mine behaviour] dry-run or no docs; stats: %s", stats)
        return stats

    # Ensure the campaigns index exists with the explicit mapping before
    # the first write. Idempotent — no-op if already created.
    init_index(es, _CAMPAIGNS_MAPPING, out_idx)

    # Clear previous behaviour-kind docs (this mining run supersedes them
    # entirely — campaign ids are content-derived, so re-runs over the
    # same data write the same docs, but data churn can produce orphans).
    try:
        es.delete_by_query(
            index=out_idx,
            body={"query": {"bool": {"must": [
                {"term": {"doc_type": "campaign"}},
                {"term": {"kind": "behaviour"}},
            ]}}},
            refresh=False, conflicts="proceed",
        )
    except Exception as exc:
        log.warning("[mine behaviour] delete-previous failed (continuing): %s", exc)

    bulk(es, docs, refresh=True)
    log.info("[mine behaviour] wrote %d campaign docs in %ss", len(docs), stats["runtime_seconds"])
    return stats


# ===========================================================================
# D: infrastructure (shared-artifact) mining
# ===========================================================================

def _extract_artifacts(text: str) -> list[tuple[str, str]]:
    """Pull (kind, value) artifact tuples from a piece of command text.

    Kinds: `url`, `ssh_key`, `hash`. Conservative on purpose — every false
    positive becomes a spurious cross-session edge.
    """
    if not text:
        return []
    out: list[tuple[str, str]] = []
    for m in _URL_RE.finditer(text):
        out.append(("url", m.group(0)))
    for m in _SSH_KEY_RE.finditer(text):
        # Normalize: keep only the key-type and the first 32 chars of the
        # base64 body so trailing comments / labels don't fragment matches.
        key = m.group(0).split()
        if len(key) >= 2:
            out.append(("ssh_key", f"{key[0]} {key[1][:32]}"))
    for m in _HASH_RE.finditer(text):
        out.append(("hash", m.group(0).lower()))
    return out


def _iter_command_input_events(
    es: Elasticsearch, idx: str, page_size: int = 1000,
) -> Iterable[dict]:
    """Yield raw cowrie command-input event _sources."""
    body = {
        "size": page_size,
        "_source": [
            "cowrie.session_id", "process.command_line", "source.ip",
            "@timestamp", "event.start",
        ],
        "query": {"term": {"event.action": "cowrie.command.input"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h["_source"]
        search_after = hits[-1]["sort"]


def _connected_components(
    edges: list[tuple[str, str]], nodes: set[str],
) -> list[set[str]]:
    """Union-find over the given edges, returning the connected components
    (each as a set of node ids). Components of size 1 are excluded —
    isolated sessions aren't a campaign."""
    parent: dict[str, str] = {n: n for n in nodes}
    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    for a, b in edges:
        if a in parent and b in parent:
            union(a, b)
    groups: dict[str, set[str]] = defaultdict(set)
    for n in nodes:
        groups[find(n)].add(n)
    return [g for g in groups.values() if len(g) >= 2]


def run_mine_infrastructure(
    cfg: AppConfig, secrets: Secrets, *,
    dry_run: bool = False,
    min_sessions:    int = _INFRA_MIN_SESSIONS,
    min_distinct_ips: int = _INFRA_MIN_DISTINCT_IPS,
) -> dict:
    """Shared-artifact campaign discovery (the "D" approach).

    Pulls every cowrie.command.input event, extracts URL / SSH-key / hash
    artifacts from the command line, and joins sessions through shared
    artifacts. Each connected component of >=`min_sessions` becomes a
    campaign. Very-common artifacts (>50% of all sessions) are dropped as
    too generic — they'd glue everything together.
    """
    es = make_client(cfg.elasticsearch, secrets)
    raw_idx       = cfg.elasticsearch.indexes.cowrie.sessions_raw
    sessions_idx  = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    out_idx       = cfg.elasticsearch.indexes.cowrie.campaigns

    t0 = time.time()
    log.info("[mine infra] reading %s for command-input events", raw_idx)

    # session -> set of (kind, value); session -> source.ip; session -> earliest_ts
    sess_arts: dict[str, set[tuple[str, str]]] = defaultdict(set)
    sess_ip:   dict[str, str] = {}
    sess_ts:   dict[str, str] = {}
    art_to_sessions: dict[tuple[str, str], set[str]] = defaultdict(set)
    n_events = 0
    for src in _iter_command_input_events(es, raw_idx):
        sid = (src.get("cowrie") or {}).get("session_id")
        if not sid:
            continue
        n_events += 1
        cmd = (src.get("process") or {}).get("command_line") or ""
        ip  = (src.get("source") or {}).get("ip")
        ts  = src.get("@timestamp") or (src.get("event") or {}).get("start")
        if ip and sid not in sess_ip:
            sess_ip[sid] = ip
        if ts and (sid not in sess_ts or ts < sess_ts[sid]):
            sess_ts[sid] = ts
        for art in _extract_artifacts(cmd):
            sess_arts[sid].add(art)
            art_to_sessions[art].add(sid)
    n_sessions = len(sess_arts)
    log.info("[mine infra] scanned %d command-input events across %d sessions; "
             "extracted %d distinct artifacts",
             n_events, n_sessions, len(art_to_sessions))

    # Drop artifacts that appear in too many sessions (generic) or only one
    # (no joining power).
    max_freq_count = max(1, int(n_sessions * _INFRA_MAX_ARTIFACT_FREQ))
    useful_arts = {
        a: sids for a, sids in art_to_sessions.items()
        if 2 <= len(sids) <= max_freq_count
    }
    log.info("[mine infra] %d/%d artifacts retained after frequency filter "
             "(>=2 and <=%d sessions)", len(useful_arts), len(art_to_sessions), max_freq_count)

    # Build session-session edge list via star expansion: each artifact
    # connects all its sessions to a synthetic "artifact-node" so we get
    # one connected component instead of O(n²) pairwise edges.
    nodes: set[str] = set(sess_arts.keys())
    edges: list[tuple[str, str]] = []
    art_node_prefix = "__art__:"
    for art, sids in useful_arts.items():
        anode = art_node_prefix + f"{art[0]}|{art[1]}"
        nodes.add(anode)
        for sid in sids:
            edges.append((anode, sid))
    components = _connected_components(edges, nodes)
    # Filter out artifact-nodes from each component; keep only session ids.
    real_components: list[set[str]] = []
    for comp in components:
        sessions_only = {n for n in comp if not n.startswith(art_node_prefix)}
        if len(sessions_only) >= min_sessions:
            real_components.append(sessions_only)
    log.info("[mine infra] %d connected components with >=%d sessions",
             len(real_components), min_sessions)

    docs: list[dict] = []
    run_id = str(uuid.uuid4())
    for comp in real_components:
        sids = sorted(comp)[:_INFRA_MAX_COMPONENT_SIZE]
        ips = sorted({sess_ip[s] for s in sids if s in sess_ip})
        if len(ips) < min_distinct_ips:
            continue
        # Tally the artifacts present in this component for the doc body.
        art_counts: dict[tuple[str, str], int] = defaultdict(int)
        for s in sids:
            for a in sess_arts.get(s, ()):
                if a in useful_arts:
                    art_counts[a] += 1
        top_arts = sorted(art_counts.items(), key=lambda kv: -kv[1])[:_TOP_ARTIFACTS_PER_CAMPAIGN]

        ts_list = [sess_ts[s] for s in sids if s in sess_ts]
        first_seen = min(ts_list) if ts_list else None
        last_seen  = max(ts_list) if ts_list else None

        # Stable fingerprint: sorted top artifacts. Same component -> same id
        # across re-runs (when the artifact set is stable enough).
        fingerprint = "|".join(f"{k}={v}" for (k, v), _ in top_arts[:10])
        cid = _campaign_id("infrastructure", fingerprint or ",".join(sids[:5]))

        # Lead artifact for the name: prefer URL > ssh_key > hash, most frequent.
        lead = None
        for (k, v), _ in top_arts:
            if k == "url":  lead = ("url", v); break
        if lead is None and top_arts:
            (lk, lv), _ = top_arts[0]; lead = (lk, lv)
        name_hint = lead[1][:80] if lead else "shared infra"
        name = f"Shared infrastructure: {name_hint}"

        docs.append({
            "_index": out_idx,
            "_id":    cid,
            "_source": {
                "@timestamp":           _now_iso(),
                "run_id":               run_id,
                "doc_type":             "campaign",
                "campaign_id":          cid,
                "kind":                 "infrastructure",
                "name":                 name,
                "rationale":            (
                    f"{len(sids)} sessions across {len(ips)} IPs share "
                    f"{len(top_arts)} artifact(s); top: {lead[0] + '=' + lead[1] if lead else 'n/a'}"
                ),
                "ip_count":             len(ips),
                "session_count":        len(sids),
                "first_seen":           first_seen,
                "last_seen":            last_seen,
                "support":              len(ips),
                "member_playbook_ids":  [],
                "member_session_ids":   sids[:_SAMPLE_SESSIONS_PER_CAMPAIGN],
                "member_source_ips":    ips[:_SAMPLE_IPS_PER_CAMPAIGN],
                "shared_artifacts": [
                    {"kind": k, "value": v, "count": c}
                    for (k, v), c in top_arts
                ],
            },
        })

    stats = {
        "events_scanned":      n_events,
        "sessions_with_artifacts": n_sessions,
        "distinct_artifacts":  len(art_to_sessions),
        "useful_artifacts":    len(useful_arts),
        "components_found":    len(real_components),
        "campaigns_written":   len(docs),
        "run_id":              run_id,
        "dry_run":             dry_run,
        "runtime_seconds":     round(time.time() - t0, 2),
    }
    if dry_run or not docs:
        log.info("[mine infra] dry-run or no docs; stats: %s", stats)
        return stats

    # Ensure the campaigns index exists with the explicit mapping. Idempotent.
    init_index(es, _CAMPAIGNS_MAPPING, out_idx)

    try:
        es.delete_by_query(
            index=out_idx,
            body={"query": {"bool": {"must": [
                {"term": {"doc_type": "campaign"}},
                {"term": {"kind": "infrastructure"}},
            ]}}},
            refresh=False, conflicts="proceed",
        )
    except Exception as exc:
        log.warning("[mine infra] delete-previous failed (continuing): %s", exc)

    bulk(es, docs, refresh=True)
    log.info("[mine infra] wrote %d campaign docs in %ss",
             len(docs), stats["runtime_seconds"])
    return stats


# ===========================================================================
# Unified entry point for the CLI verb
# ===========================================================================

def run_mine(
    cfg: AppConfig, secrets: Secrets, *,
    kind: str = "all", dry_run: bool = False,
) -> dict:
    """Dispatch to the requested miner(s)."""
    kind = kind.lower().strip()
    if kind not in ("behaviour", "infrastructure", "all"):
        raise ValueError(f"unknown campaign mining kind: {kind}")
    out: dict = {}
    if kind in ("behaviour", "all"):
        out["behaviour"] = run_mine_behaviour(cfg, secrets, dry_run=dry_run)
    if kind in ("infrastructure", "all"):
        out["infrastructure"] = run_mine_infrastructure(cfg, secrets, dry_run=dry_run)
    return out
