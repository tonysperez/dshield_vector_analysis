"""Cowrie command layer: enrichment, escalation, re-embed, and clustering.

Phase 1: read raw cowrie command events -> dedup -> enrich (local LLM, optional
cloud escalation) -> embed -> write to the commands index.
Phase 2: escalate locally-enriched docs whose novelty rose above threshold.
Phase 3: HDBSCAN over command embeddings (delegated to clustering.run_layer_clustering).
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterator, Optional

from pydantic import ValidationError
from elasticsearch import Elasticsearch

from ...cache import StateDB
from ...config import AppConfig, Secrets, load_prompt, CommandClusterConfig
from ...es_client import bulk_write, init_index, make_client
from ...llm import make_llm_client
from ...llm.schemas import CommandEnrichment, CloudCommandEnrichment
from ... import triage as triage_mod

log = logging.getLogger(__name__)

_COMMANDS_MAPPING = "es-mappings/cowrie/commands.json"
_COMMAND_CLUSTERS_MAPPING = "es-mappings/cowrie/command_clusters.json"

# Painless: patch only the embedding vector.
_REEMBED_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "ctx._source.dshield.cowrie.enrichment.embedding = params.embedding;"
)

_WS_RE = re.compile(r"\s+")

# Painless: patch only cloud-overwritten fields (embedding, cluster.*, etc. untouched).
_ESCALATE_SCRIPT = (
    "ctx._source.event.provider = params.provider;"
    "ctx._source.event.reason = params.description;"
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "en.intent = params.intent;"
    "en.confidence = params.confidence;"
    "en.model = params.model;"
    "en.triage_reasons = params.triage_reasons;"
    "en.notes = params.notes;"
    "en.local_fallback = params.local_fallback;"
    "if (ctx._source.threat == null) { ctx._source.threat = [:]; }"
    "if (ctx._source.threat.tactic == null) { ctx._source.threat.tactic = [:]; }"
    "if (ctx._source.threat.technique == null) { ctx._source.threat.technique = [:]; }"
    "ctx._source.threat.tactic.id = params.tactics;"
    "ctx._source.threat.technique.id = params.techniques;"
    "ctx._source.threat.indicator = params.indicators;"
)

_CLUSTER_UPDATE_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "if (en.cluster == null) { en.cluster = [:]; }"
    "en.cluster.id = params.cluster_id;"
    "en.cluster.novelty_score = params.novelty_score;"
    "en.cluster.is_outlier = params.is_outlier;"
    "en.cluster.scored_at = params.scored_at;"
)

_CLUSTER_SAMPLE_SIZE = 5


# ---------------------------------------------------------------------------
# Source-event iteration (cowrie-specific event shape)
# ---------------------------------------------------------------------------

def iter_command_events(
    es: Elasticsearch,
    index: str,
    since: Optional[str],
    page_size: int = 1000,
) -> Iterator[dict]:
    """Yield Cowrie command.input events ordered by @timestamp asc.

    Uses search_after for stable deep pagination.
    """
    must = [{"term": {"event.action": "cowrie.command.input"}}]
    if since:
        must.append({"range": {"@timestamp": {"gt": since}}})

    body = {
        "size": page_size,
        "_source": [
            "@timestamp",
            "process.command_line",
            "cowrie.session_id",
            "source.ip",
        ],
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
            yield h
        search_after = hits[-1]["sort"]


# ---------------------------------------------------------------------------
# Normalization + hashing
# ---------------------------------------------------------------------------

def normalize(cmd: str, max_chars: int) -> tuple[str, bool]:
    """Strip + collapse whitespace, truncate. Returns (normalized, was_truncated)."""
    s = _WS_RE.sub(" ", cmd.strip())
    truncated = len(s) > max_chars
    if truncated:
        s = s[:max_chars]
    return s, truncated


def hash_command_full(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def hash_command(normalized: str) -> str:
    """Short hash used as ES _id and event.id."""
    return hash_command_full(normalized)[:16]


def _extract_command(src: dict) -> Optional[str]:
    p = src.get("process") or {}
    cmd = p.get("command_line")
    return cmd if isinstance(cmd, str) and cmd else None


def _extract_session(src: dict) -> Optional[str]:
    c = src.get("cowrie") or {}
    return c.get("session_id")


def _extract_ip(src: dict) -> Optional[str]:
    s = src.get("source") or {}
    return s.get("ip")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_indicators(iocs: dict) -> list[dict]:
    """Convert flat IOC arrays into ECS threat.indicator nested-object array."""
    out: list[dict] = []
    for ip in iocs.get("ips") or []:
        if not ip:
            continue
        kind = "ipv6-addr" if ":" in ip else "ipv4-addr"
        out.append({"type": kind, "ip": ip})
    for d in iocs.get("domains") or []:
        if d:
            out.append({"type": "domain-name", "domain": d})
    for u in iocs.get("urls") or []:
        if u:
            out.append({"type": "url", "url": {"full": u}})
    for f in iocs.get("files") or []:
        if f:
            out.append({"type": "file", "file": {"name": f}})
    for hh in iocs.get("hashes") or []:
        if hh:
            out.append({"type": "file", "file": {"hash": {"sha256": hh}}})
    return out


def _build_ecs_doc(
    *,
    now: str,
    short_hash: str,
    full_hash: str,
    command: str,
    truncated: bool,
    first_seen: Optional[str],
    last_seen: Optional[str],
    occurrence_count: int,
    unique_sessions: int,
    unique_source_ips: int,
    description: str,
    provider: str,
    model: str,
    prompt_version: str,
    intent: str,
    confidence: int,
    tactics: list[str],
    techniques: list[str],
    indicators: list[dict],
    embedding: list[float],
    triage_reasons: Optional[list[str]] = None,
    notes: str = "",
    local_fallback: Optional[dict] = None,
) -> dict:
    enrichment_block = {
        "intent": intent,
        "confidence": confidence,
        "model": model,
        "prompt_version": prompt_version,
        "occurrence_count": occurrence_count,
        "unique_sessions": unique_sessions,
        "unique_source_ips": unique_source_ips,
        "command_truncated": truncated,
        "embedding": embedding,
    }
    if triage_reasons:
        enrichment_block["triage_reasons"] = triage_reasons
    if notes:
        enrichment_block["notes"] = notes
    if local_fallback:
        enrichment_block["local_fallback"] = local_fallback
    return {
        "@timestamp": now,
        "event": {
            "kind": "enrichment",
            "category": ["process"],
            "type": ["info"],
            "module": "cowrie",
            "dataset": "dshield.cowrie.enrichment.command",
            "provider": provider,
            "ingested": now,
            "start": first_seen,
            "end": last_seen,
            "id": short_hash,
            "reason": description,
        },
        "process": {
            "command_line": command,
            "hash": {"sha256": full_hash},
        },
        "observer": {
            "type": "honeypot",
            "vendor": "Cowrie",
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": tactics} if tactics else {},
            "technique": {"id": techniques} if techniques else {},
            "indicator": indicators,
        },
        "dshield": {
            "cowrie": {
                "enrichment": enrichment_block,
            },
        },
    }


def _try_parse(raw: str) -> Optional[CommandEnrichment]:
    try:
        return CommandEnrichment(**json.loads(raw))
    except (json.JSONDecodeError, ValidationError) as e:
        log.debug("LLM JSON parse failed: %s; raw=%r", e, raw[:300])
        return None


_ENRICHMENT_SCHEMA = CommandEnrichment.model_json_schema()


def _fetch_total_session_count(es: Elasticsearch, events_index: str) -> int:
    """Total distinct cowrie.session_id over all command.input events.

    Used as `N` in the TF-IDF salience weight for cooccurring siblings
    (see `score_cooccurring_siblings`). Replaces the old boilerplate-cutoff
    denominator; the change to continuous IDF weighting is ROADMAP #6.
    """
    try:
        resp = es.search(
            index=events_index,
            size=0,
            query={"term": {"event.action": "cowrie.command.input"}},
            aggs={"sessions": {"cardinality": {"field": "cowrie.session_id", "precision_threshold": 40000}}},
        )
        return int(resp["aggregations"]["sessions"]["value"])
    except Exception as e:
        log.warning("could not compute total session count: %s", e)
        return 0


def score_cooccurring_siblings(
    tf_by_sib: dict[str, int],
    df_by_sib: dict[str, int],
    total_sessions: int,
    top_k: int,
) -> list[tuple[str, int]]:
    """Rank candidate siblings by TF-IDF salience; return top-k.

    Pure function — no ES, easy to unit-test. ROADMAP issue #6.

    `tf` = window session count (how many of the anchor's window sessions
    ran the sibling). `df` = corpus session count (how many sessions
    corpus-wide ran the sibling). `N` = total_sessions.

    Salience = tf * ln((N + 1) / (df + 1)). Log-smoothed, parameter-free.
    Corpus-common siblings (high df) get small idf and drop in ranking
    without being categorically rejected; specifically-correlated siblings
    (high tf, low df) rise.

    Falls back to ranking by raw tf when `total_sessions <= 0` or when
    `df_by_sib` is empty — the idf term is undefined in those cases and
    raw-count order is the most we can do.

    Returned tuples carry the *original window tf*, not the score, so
    downstream prompt-display continues to show concrete session counts.
    """
    if not tf_by_sib:
        return []

    use_idf = total_sessions > 0 and bool(df_by_sib)
    log_n = math.log(total_sessions + 1) if use_idf else 0.0

    scored: list[tuple[float, int, str]] = []
    for sib, tf in tf_by_sib.items():
        if use_idf:
            df = df_by_sib.get(sib, 1)
            idf = log_n - math.log(df + 1)
            score = tf * idf
        else:
            score = float(tf)
        scored.append((score, tf, sib))

    scored.sort(key=lambda x: (-x[0], -x[1], x[2]))
    return [(sib, tf) for _, tf, sib in scored[:top_k]]


def fetch_cooccurring_commands(
    es: Elasticsearch,
    events_index: str,
    command: str,
    *,
    session_sample_size: int,
    top_k: int,
    min_sessions: int,
    total_sessions: int,
) -> list[tuple[str, int]]:
    """Return [(sibling_command, window_session_count), ...] ordered by
    TF-IDF salience (most informative siblings first).

    Strategy (see also `score_cooccurring_siblings`):
      1. Find up to `session_sample_size` sessions that ran this command.
      2. In those sessions, aggregate other command_line values, counting
         distinct sessions per sibling (sessions, not raw events — a
         session that runs `wget X` 5 times still counts once).
      3. One corpus-wide query fetches `df` (session cardinality) for all
         candidate siblings at once.
      4. Rank each surviving sibling by `tf * ln((N+1)/(df+1))` — the
         tf-idf weight inside the cooccurrence window — and return top-k.

    Continuous IDF weighting replaces the prior binary
    `max_corpus_session_ratio` boilerplate cutoff: corpus-common siblings
    are *demoted*, not rejected. Net cost is lower than the old code,
    which ran one cardinality query per candidate above the cutoff.
    ROADMAP issue #6.
    """
    if not command:
        return []
    try:
        resp = es.search(
            index=events_index,
            size=0,
            query={"bool": {"must": [
                {"term": {"event.action": "cowrie.command.input"}},
                {"term": {"process.command_line": command}},
            ]}},
            aggs={"sessions": {"terms": {"field": "cowrie.session_id", "size": session_sample_size}}},
        )
        sids = [b["key"] for b in resp["aggregations"]["sessions"]["buckets"] if b.get("key")]
    except Exception as e:
        log.warning("co-occurrence: session lookup failed for %r: %s", command[:80], e)
        return []

    if len(sids) < min_sessions:
        return []

    # Pull a generous candidate bucket so corpus-common siblings still
    # appear and can be ranked against specific ones — they'll demote
    # themselves via the IDF weight in score_cooccurring_siblings.
    bucket_size = max(top_k * 5, 20)
    try:
        resp2 = es.search(
            index=events_index,
            size=0,
            query={"bool": {"must": [
                {"term": {"event.action": "cowrie.command.input"}},
                {"terms": {"cowrie.session_id": sids}},
            ]}},
            aggs={
                "siblings": {
                    "terms": {"field": "process.command_line", "size": bucket_size},
                    "aggs": {"sessions": {"cardinality": {"field": "cowrie.session_id"}}},
                }
            },
        )
        buckets = resp2["aggregations"]["siblings"]["buckets"]
    except Exception as e:
        log.warning("co-occurrence: sibling agg failed for %r: %s", command[:80], e)
        return []

    tf_by_sib: dict[str, int] = {}
    for b in buckets:
        sib = b.get("key") or ""
        if not sib or sib == command:
            continue
        tf = int(b.get("sessions", {}).get("value", 0))
        if tf > 0:
            tf_by_sib[sib] = tf
    if not tf_by_sib:
        return []

    # One corpus-wide query for df (session cardinality) per candidate. When
    # total_sessions is unknown the IDF term is undefined and we fall back
    # to raw-tf ordering inside score_cooccurring_siblings.
    df_by_sib: dict[str, int] = {}
    if total_sessions > 0:
        try:
            resp3 = es.search(
                index=events_index,
                size=0,
                query={"bool": {"must": [
                    {"term": {"event.action": "cowrie.command.input"}},
                    {"terms": {"process.command_line": list(tf_by_sib.keys())}},
                ]}},
                aggs={
                    "by_cmd": {
                        "terms": {"field": "process.command_line", "size": len(tf_by_sib)},
                        "aggs": {"sessions": {"cardinality": {"field": "cowrie.session_id"}}},
                    }
                },
            )
            df_by_sib = {
                b["key"]: int(b["sessions"]["value"])
                for b in resp3["aggregations"]["by_cmd"]["buckets"]
            }
        except Exception as e:
            log.warning("co-occurrence: corpus df agg failed for %r: %s", command[:80], e)

    return score_cooccurring_siblings(tf_by_sib, df_by_sib, total_sessions, top_k)


def _format_cooccurring_block(siblings: list[tuple[str, int]]) -> str:
    """Render the co-occurrence list for prompt injection.

    Returns "(none)" when empty so the placeholder is never blank — keeps the
    surrounding prompt structure stable for the LLM.
    """
    if not siblings:
        return "(none)"
    lines = [f"  - {cmd}  (sessions: {n})" for cmd, n in siblings]
    return "\n".join(lines)


def _build_embed_text(
    command: str,
    parsed: Optional[CommandEnrichment],
    context_fields: list[str],
    cooccurring: Optional[list[tuple[str, int]]] = None,
    embed_cooccurrence: bool = False,
) -> str:
    """Build the text string to embed. Prepends enrichment fields when context_fields is set.

    When `embed_cooccurrence` is True and `cooccurring` is non-empty, appends a
    "co-occurs with: cmd1; cmd2; ..." line so the embedding picks up the
    behavioral neighborhood of the command, not just its surface form.
    """
    parts: list[str] = []
    if context_fields and parsed is not None:
        if "intent" in context_fields and parsed.intent:
            parts.append(f"intent: {parsed.intent}.")
        if "tactics" in context_fields and parsed.tactics:
            parts.append(f"tactics: {', '.join(parsed.tactics)}.")
        if "techniques" in context_fields and parsed.techniques:
            parts.append(f"techniques: {', '.join(parsed.techniques)}.")
        if "description" in context_fields and parsed.description:
            parts.append(parsed.description)

    cooc_line = ""
    if embed_cooccurrence and cooccurring:
        joined = "; ".join(c for c, _ in cooccurring)
        cooc_line = f"co-occurs with: {joined}."

    if not parts and not cooc_line:
        return command

    head = " ".join(parts)
    if cooc_line:
        head = f"{head} {cooc_line}".strip()
    return f"{head}\nCommand: {command}"


def _build_local_fallback(parsed: Optional[CommandEnrichment], model: str) -> Optional[dict]:
    if parsed is None:
        return {"model": model, "intent": "unknown", "confidence": 1, "description": "",
                "tactics": [], "techniques": []}
    return {
        "model": model,
        "intent": parsed.intent,
        "confidence": parsed.confidence,
        "description": parsed.description,
        "tactics": parsed.tactics,
        "techniques": parsed.techniques,
    }


def cloud_enrich_one(
    cloud_client,
    prompt_template: str,
    command: str,
    triage_reasons: list[str],
    cooccurring_block: str = "(none)",
) -> tuple[Optional[CloudCommandEnrichment], int, int]:
    """Returns (parsed_or_None, input_tokens, output_tokens)."""
    from ...llm.anthropic import parse_cloud_json, _strip_code_fences
    prompt = (
        prompt_template
        .replace("<<<COMMAND>>>", command)
        .replace("<<<TRIAGE_REASONS>>>", ", ".join(triage_reasons) if triage_reasons else "(none)")
        .replace("<<<COOCCURRING_COMMANDS>>>", cooccurring_block)
    )
    try:
        text, in_tok, out_tok = cloud_client.generate_with_usage(prompt)
    except Exception as e:
        log.warning("cloud generate failed: %s", e)
        return None, 0, 0
    parsed = parse_cloud_json(_strip_code_fences(text))
    return parsed, in_tok, out_tok


def enrich_one(
    llm,
    prompt_template: str,
    command: str,
    max_retries: int,
    cooccurring_block: str = "(none)",
) -> tuple[Optional[CommandEnrichment], str, str]:
    """Returns (enrichment_or_None, source, model)."""
    base_prompt = (
        prompt_template
        .replace("<<<COMMAND>>>", command)
        .replace("<<<COOCCURRING_COMMANDS>>>", cooccurring_block)
    )
    prompt = base_prompt
    last_raw = ""
    for attempt in range(max_retries + 1):
        try:
            raw = llm.generate_json(
                prompt,
                schema=_ENRICHMENT_SCHEMA,
                schema_name="command_enrichment",
            )
        except Exception as e:
            log.warning("llm generate failed (attempt %d): %s", attempt, e)
            continue
        last_raw = raw
        parsed = _try_parse(raw)
        if parsed is not None:
            return parsed, "local", llm.gen_model
        prompt = (
            base_prompt
            + "\n\nYour previous response was invalid JSON. It was:\n"
            + raw[:500]
            + "\nReturn ONLY valid JSON."
        )
    log.warning("local enrichment failed after retries; last_raw=%r", last_raw[:200])
    return None, "local_failed", llm.gen_model


# ---------------------------------------------------------------------------
# Enrich entry point
# ---------------------------------------------------------------------------

def run_enrich(cfg: AppConfig, secrets: Secrets, dry_run: bool = False, no_cloud: bool = False) -> dict:
    """Main worker entry. Returns stats dict."""
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    prompt = load_prompt(cfg, "command_enrichment")
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    cloud_enabled = bool(cfg.cloud.enabled and not no_cloud and secrets.anthropic_api_key)
    cloud_prompt: Optional[str] = None
    cloud_client = None
    if cloud_enabled:
        if cfg.prompts.command_deep_dive is None:
            log.warning("cloud enabled but prompts.command_deep_dive is unset; skipping cloud")
            cloud_enabled = False
        else:
            cloud_prompt = load_prompt(cfg, "command_deep_dive")
            from ...llm.anthropic import AnthropicClient
            cloud_client = AnthropicClient(
                api_key=secrets.anthropic_api_key,
                model=cfg.cloud.model,
                max_tokens=cfg.cloud.max_tokens,
                timeout=cfg.cloud.request_timeout,
                base_url=cfg.cloud.base_url,
            )
            try:
                cloud_client.ping()
                log.info("cloud escalation enabled: model=%s daily_budget=$%.2f remaining=$%.2f",
                         cfg.cloud.model, cfg.cloud.daily_budget_usd,
                         triage_mod.budget_remaining_usd(db, cfg.cloud))
            except Exception as e:
                log.warning("cloud preflight failed (%s); continuing local-only", e)
                try:
                    cloud_client.close()
                except Exception:
                    pass
                cloud_client = None
                cloud_enabled = False

    cooc_cfg = cfg.cooccurrence
    total_sessions = (
        _fetch_total_session_count(es, events_idx) if cooc_cfg.enabled else 0
    )
    if cooc_cfg.enabled:
        log.info(
            "co-occurrence enabled: top_k=%d sample=%d sessions, "
            "tf-idf weighted against %d total corpus sessions",
            cooc_cfg.top_k, cooc_cfg.session_sample_size, total_sessions,
        )

    since = db.get_watermark()
    if since is None and cfg.worker.initial_lookback_days is not None:
        from datetime import timedelta
        since_dt = datetime.now(timezone.utc) - timedelta(days=cfg.worker.initial_lookback_days)
        since = since_dt.isoformat()
    log.info("Watermark: %s", since or "(none, full backfill)")

    stats = defaultdict(int)
    groups: dict[str, dict] = {}
    last_ts = since

    # Reset the MITRE-validation drop counter so the value reported at the end
    # of this run reflects only this run's hallucinations.
    from enrich.llm.schemas import reset_mitre_drop_counts
    reset_mitre_drop_counts()

    for hit in iter_command_events(es, events_idx, since, cfg.worker.page_size):
        stats["events_seen"] += 1
        src = hit["_source"]
        ts = src.get("@timestamp")
        if ts:
            last_ts = ts

        cmd = _extract_command(src)
        if not cmd:
            stats["events_no_command"] += 1
            continue

        norm, truncated = normalize(cmd, cfg.worker.command_max_chars)
        if not norm:
            continue
        h = hash_command(norm)

        g = groups.get(h)
        if g is None:
            g = {
                "command": norm,
                "truncated": truncated,
                "sessions": set(),
                "ips": set(),
                "first_seen": ts,
                "last_seen": ts,
                "count": 0,
            }
            groups[h] = g
        g["count"] += 1
        sid = _extract_session(src)
        if sid:
            g["sessions"].add(sid)
        ip = _extract_ip(src)
        if ip:
            g["ips"].add(ip)
        if ts:
            if not g["first_seen"] or ts < g["first_seen"]:
                g["first_seen"] = ts
            if not g["last_seen"] or ts > g["last_seen"]:
                g["last_seen"] = ts

    log.info("Collected %d events into %d unique commands", stats["events_seen"], len(groups))

    if dry_run:
        log.info("dry-run: skipping LLM + writes")
        return dict(stats, unique_commands=len(groups))

    actions: list[dict] = []

    with make_llm_client(cfg.llm) as llm:
        for h, g in groups.items():
            cached = db.is_cached(h, cfg.llm.generation_model, cfg.worker.prompt_version, cfg.llm.embed_version)
            if cached:
                stats["cache_hits"] += 1
                actions.append({
                    "_op_type": "update",
                    "_id": h,
                    "script": {
                        "source": (
                            "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
                            "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
                            "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
                            "def en = ctx._source.dshield.cowrie.enrichment;"
                            "en.occurrence_count = (en.occurrence_count ?: 0) + params.add_count;"
                            "if (ctx._source.event == null) { ctx._source.event = [:]; }"
                            "if (ctx._source.event.end == null || params.last_seen.compareTo(ctx._source.event.end) > 0) { ctx._source.event.end = params.last_seen; }"
                            "if (ctx._source.event.start == null || params.first_seen.compareTo(ctx._source.event.start) < 0) { ctx._source.event.start = params.first_seen; }"
                        ),
                        "params": {
                            "add_count": g["count"],
                            "last_seen": g["last_seen"],
                            "first_seen": g["first_seen"],
                        },
                    },
                })
                continue

            stats["cache_miss"] += 1

            cooccurring: list[tuple[str, int]] = []
            if cooc_cfg.enabled:
                cooccurring = fetch_cooccurring_commands(
                    es, events_idx, g["command"],
                    session_sample_size=cooc_cfg.session_sample_size,
                    top_k=cooc_cfg.top_k,
                    min_sessions=cooc_cfg.min_sessions,
                    total_sessions=total_sessions,
                )
                if cooccurring:
                    stats["cooccurrence_hits"] += 1
                else:
                    stats["cooccurrence_empty"] += 1
            cooc_block = _format_cooccurring_block(cooccurring)

            parsed, source, model = enrich_one(
                llm, prompt, g["command"], cfg.llm.max_retries,
                cooccurring_block=cooc_block,
            )
            now = _now()
            full_hash = hash_command_full(g["command"])
            if parsed is not None:
                description = parsed.description
                intent = parsed.intent
                confidence = parsed.confidence
                tactics = parsed.tactics
                techniques = parsed.techniques
                indicators = _build_indicators(parsed.iocs.model_dump())
                stats["enriched_ok"] += 1
            else:
                description = ""
                intent = "unknown"
                confidence = 1
                tactics, techniques = [], []
                indicators = []
                stats["enriched_failed"] += 1

            triage_reasons: list[str] = []
            notes = ""
            local_fallback_doc: Optional[dict] = None
            doc_provider = source
            doc_model = model
            final_parsed = parsed

            if cloud_enabled:
                triage_reasons = triage_mod.reasons_to_escalate(
                    command=g["command"],
                    parsed=parsed,
                    local_failed=(source == "local_failed"),
                    cfg=cfg.cloud,
                    embedding=None,
                    centroids=None,
                )
                if triage_reasons:
                    stats["triaged"] += 1
                    if not triage_mod.can_spend(db, cfg.cloud):
                        stats["cloud_skipped_budget"] += 1
                        triage_reasons.append("budget_exhausted")
                    else:
                        cloud_parsed, in_tok, out_tok = cloud_enrich_one(
                            cloud_client, cloud_prompt, g["command"], triage_reasons,
                            cooccurring_block=cooc_block,
                        )
                        from ...llm.anthropic import cost_usd as _cost_usd
                        spend = _cost_usd(
                            in_tok, out_tok,
                            cfg.cloud.pricing.input_per_mtok,
                            cfg.cloud.pricing.output_per_mtok,
                        )
                        if in_tok or out_tok:
                            db.add_spend(triage_mod.utc_today(), in_tok, out_tok, spend)
                            stats["cloud_calls"] += 1
                            stats["cloud_input_tokens"] += in_tok
                            stats["cloud_output_tokens"] += out_tok
                            stats["cloud_cost_usd_x10000"] += int(round(spend * 10000))
                        if cloud_parsed is not None:
                            local_fallback_doc = _build_local_fallback(parsed, model)
                            description = cloud_parsed.description
                            intent = cloud_parsed.intent
                            confidence = cloud_parsed.confidence
                            tactics = cloud_parsed.tactics
                            techniques = cloud_parsed.techniques
                            indicators = _build_indicators(cloud_parsed.iocs.model_dump())
                            notes = cloud_parsed.notes
                            doc_provider = "claude"
                            doc_model = cfg.cloud.model
                            final_parsed = cloud_parsed
                            stats["cloud_enriched_ok"] += 1
                        else:
                            stats["cloud_enriched_failed"] += 1
                            triage_reasons.append("cloud_parse_failed")

            embed_text = _build_embed_text(
                g["command"], final_parsed, cfg.llm.embed_context,
                cooccurring=cooccurring,
                embed_cooccurrence=cooc_cfg.enabled and cooc_cfg.embed_cooccurrence,
            )
            try:
                embedding = llm.embed(embed_text)
            except Exception as e:
                log.error("embed failed for %s: %s", h, e)
                stats["embed_failed"] += 1
                continue

            doc = _build_ecs_doc(
                now=now,
                short_hash=h,
                full_hash=full_hash,
                command=g["command"],
                truncated=g["truncated"],
                first_seen=g["first_seen"],
                last_seen=g["last_seen"],
                occurrence_count=g["count"],
                unique_sessions=len(g["sessions"]),
                unique_source_ips=len(g["ips"]),
                description=description,
                provider=doc_provider,
                model=doc_model,
                prompt_version=cfg.worker.prompt_version,
                intent=intent,
                confidence=confidence,
                tactics=tactics,
                techniques=techniques,
                indicators=indicators,
                embedding=embedding,
                triage_reasons=triage_reasons,
                notes=notes,
                local_fallback=local_fallback_doc,
            )
            actions.append({"_op_type": "index", "_id": h, "_source": doc})
            if doc_provider in ("local", "claude"):
                db.mark_cached(h, cfg.llm.generation_model, cfg.worker.prompt_version, cfg.llm.embed_version, now)

            if len(actions) >= 50:
                ok, errs = bulk_write(es, commands_idx, actions)
                stats["bulk_ok"] += ok
                stats["bulk_errors"] += len(errs)
                if errs:
                    log.warning("bulk errors (%d): %s", len(errs), errs[:2])
                actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("bulk errors (%d): %s", len(errs), errs[:2])

    # Refresh so the next pipeline step (`rollup sessions`, then `cluster
    # commands`) sees every enriched command. The mapping uses default 1s
    # refresh but the index can lag under load; explicit refresh removes the
    # race entirely.
    try:
        es.indices.refresh(index=commands_idx)
    except Exception as exc:
        log.warning("enrich refresh failed (continuing): %s", exc)

    if last_ts and last_ts != since:
        db.set_watermark(last_ts)
        log.info("Watermark advanced to %s", last_ts)

    if cloud_client is not None:
        cloud_client.close()

    out = dict(stats, unique_commands=len(groups))
    if "cloud_cost_usd_x10000" in out:
        out["cloud_cost_usd"] = out.pop("cloud_cost_usd_x10000") / 10000.0
    # Surface MITRE ID hallucination rate from this run.
    from enrich.llm.schemas import mitre_drop_counts
    mitre_drops = mitre_drop_counts()
    if mitre_drops["tactics"] or mitre_drops["techniques"]:
        log.info(
            "MITRE ATT&CK invalid IDs dropped this run: tactics=%d techniques=%d",
            mitre_drops["tactics"], mitre_drops["techniques"],
        )
    out["mitre_invalid_tactics"] = mitre_drops["tactics"]
    out["mitre_invalid_techniques"] = mitre_drops["techniques"]
    db.close()
    return out


# ---------------------------------------------------------------------------
# Escalate
# ---------------------------------------------------------------------------

def iter_novel_local_docs(
    es: Elasticsearch,
    index: str,
    novelty_threshold: float,
    confidence_max: int,
    confidence_min: int,
    page_size: int = 50,
) -> Iterator[dict]:
    """Yield enrichment docs with event.provider='local', novelty_score >= novelty_threshold,
    and confidence in [confidence_min, confidence_max]. Sorted novelty_score desc.

    The lower bound on confidence is the novelty-noise floor — see
    ROADMAP issue #3. Local-LLM confidence below this is almost always an
    encoding artifact whose novelty score is meaningless; gating those out
    here stops them from burning cloud budget.
    """
    body: dict = {
        "size": page_size,
        "_source": [
            "process.command_line",
            "event.reason",
            "dshield.cowrie.enrichment.intent",
            "dshield.cowrie.enrichment.confidence",
            "dshield.cowrie.enrichment.model",
            "threat.tactic.id",
            "threat.technique.id",
        ],
        "query": {
            "bool": {
                "must": [
                    {"term": {"event.provider": "local"}},
                    {"range": {
                        "dshield.cowrie.enrichment.cluster.novelty_score": {"gte": novelty_threshold}
                    }},
                    {"range": {
                        "dshield.cowrie.enrichment.confidence": {
                            "gte": confidence_min,
                            "lte": confidence_max,
                        }
                    }},
                ]
            }
        },
        "sort": [
            {"dshield.cowrie.enrichment.cluster.novelty_score": "desc"},
            {"_doc": "asc"},
        ],
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
            yield h
        search_after = hits[-1]["sort"]


def run_escalate(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """Cloud-escalate locally-enriched docs whose novelty_score >= threshold."""
    if not cfg.cloud.enabled:
        raise RuntimeError(
            "cloud.enabled is false. Set it in config/local.yaml to use escalate."
        )
    if not secrets.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set in .env.")
    if not cfg.prompts.command_deep_dive:
        raise RuntimeError("prompts.command_deep_dive is unset in config.")

    threshold = cfg.cloud.triage.novel_embedding_threshold
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    cloud_prompt = load_prompt(cfg, "command_deep_dive")
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    cooc_cfg = cfg.cooccurrence
    total_sessions = (
        _fetch_total_session_count(es, events_idx) if cooc_cfg.enabled else 0
    )

    from ...llm.anthropic import AnthropicClient, cost_usd as _cost_usd
    cloud_client = AnthropicClient(
        api_key=secrets.anthropic_api_key,
        model=cfg.cloud.model,
        max_tokens=cfg.cloud.max_tokens,
        timeout=cfg.cloud.request_timeout,
        base_url=cfg.cloud.base_url,
    )
    try:
        cloud_client.ping()
    except Exception as exc:
        cloud_client.close()
        db.close()
        raise RuntimeError(f"Cloud preflight failed: {exc}") from exc

    confidence_max = cfg.cloud.triage.escalate_confidence_max
    confidence_min = cfg.cloud.triage.novel_confidence_min
    log.info(
        "escalate: novelty_threshold=%.2f confidence=[%d,%d] model=%s budget_remaining=$%.4f",
        threshold, confidence_min, confidence_max, cfg.cloud.model,
        triage_mod.budget_remaining_usd(db, cfg.cloud),
    )

    stats: dict = defaultdict(int)
    actions: list[dict] = []

    for hit in iter_novel_local_docs(
        es, commands_idx, threshold, confidence_max, confidence_min,
    ):
        stats["candidates"] += 1

        if not dry_run and not triage_mod.can_spend(db, cfg.cloud):
            stats["skipped_budget"] += 1
            log.warning("Budget exhausted; stopping escalate run")
            break

        if dry_run:
            continue

        src = hit["_source"]
        doc_id = hit["_id"]
        command = (src.get("process") or {}).get("command_line", "")
        if not command:
            stats["skipped_no_command"] += 1
            continue

        en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
        local_fallback = {
            "model": en.get("model", ""),
            "intent": en.get("intent", "unknown"),
            "confidence": en.get("confidence", 1),
            "description": (src.get("event") or {}).get("reason", ""),
            "tactics": ((src.get("threat") or {}).get("tactic") or {}).get("id") or [],
            "techniques": ((src.get("threat") or {}).get("technique") or {}).get("id") or [],
        }

        triage_reasons = ["novel_embedding"]
        cooccurring: list[tuple[str, int]] = []
        if cooc_cfg.enabled:
            cooccurring = fetch_cooccurring_commands(
                es, events_idx, command,
                session_sample_size=cooc_cfg.session_sample_size,
                top_k=cooc_cfg.top_k,
                min_sessions=cooc_cfg.min_sessions,
                total_sessions=total_sessions,
            )
        cloud_parsed, in_tok, out_tok = cloud_enrich_one(
            cloud_client, cloud_prompt, command, triage_reasons,
            cooccurring_block=_format_cooccurring_block(cooccurring),
        )
        spend = _cost_usd(
            in_tok, out_tok,
            cfg.cloud.pricing.input_per_mtok,
            cfg.cloud.pricing.output_per_mtok,
        )
        if in_tok or out_tok:
            db.add_spend(triage_mod.utc_today(), in_tok, out_tok, spend)
            stats["cloud_calls"] += 1
            stats["cloud_input_tokens"] += in_tok
            stats["cloud_output_tokens"] += out_tok
            stats["cloud_cost_usd_x10000"] += int(round(spend * 10000))

        if cloud_parsed is None:
            stats["cloud_failed"] += 1
            log.warning("cloud parse failed for doc %s", doc_id)
            continue

        stats["cloud_ok"] += 1
        actions.append({
            "_op_type": "update",
            "_id": doc_id,
            "script": {
                "source": _ESCALATE_SCRIPT,
                "params": {
                    "provider": "claude",
                    "description": cloud_parsed.description,
                    "intent": cloud_parsed.intent,
                    "confidence": cloud_parsed.confidence,
                    "model": cfg.cloud.model,
                    "triage_reasons": triage_reasons,
                    "notes": cloud_parsed.notes,
                    "local_fallback": local_fallback,
                    "tactics": cloud_parsed.tactics,
                    "techniques": cloud_parsed.techniques,
                    "indicators": _build_indicators(cloud_parsed.iocs.model_dump()),
                },
            },
        })

        if len(actions) >= 20:
            ok, errs = bulk_write(es, commands_idx, actions)
            stats["bulk_ok"] += ok
            stats["bulk_errors"] += len(errs)
            if errs:
                log.warning("escalate bulk errors (%d): %s", len(errs), errs[:2])
            actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("escalate bulk errors (%d): %s", len(errs), errs[:2])

    # Refresh so downstream `cluster sessions` / `rollup ips` see the
    # cloud-rewritten enrichment immediately.
    try:
        es.indices.refresh(index=commands_idx)
    except Exception as exc:
        log.warning("escalate refresh failed (continuing): %s", exc)

    cloud_client.close()
    db.close()

    out = dict(
        stats, dry_run=dry_run,
        novelty_threshold=threshold,
        confidence_min=confidence_min,
        confidence_max=confidence_max,
    )
    if "cloud_cost_usd_x10000" in out:
        out["cloud_cost_usd"] = out.pop("cloud_cost_usd_x10000") / 10000.0
    return out


# ---------------------------------------------------------------------------
# Re-embed
# ---------------------------------------------------------------------------

def iter_docs_for_reembed(
    es: Elasticsearch,
    index: str,
    page_size: int = 200,
) -> Iterator[dict]:
    """Yield dicts with the enrichment fields needed to rebuild an embedding."""
    body: dict = {
        "size": page_size,
        "_source": [
            "process.command_line",
            "event.reason",
            "dshield.cowrie.enrichment.intent",
            "threat.tactic.id",
            "threat.technique.id",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.embedding"}},
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
            en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
            yield {
                "doc_id": h["_id"],
                "command": (src.get("process") or {}).get("command_line", ""),
                "intent": en.get("intent", ""),
                "tactics": ((src.get("threat") or {}).get("tactic") or {}).get("id") or [],
                "techniques": ((src.get("threat") or {}).get("technique") or {}).get("id") or [],
                "description": (src.get("event") or {}).get("reason", ""),
            }
        search_after = hits[-1]["sort"]


def run_reembed(cfg: AppConfig, secrets: Secrets, dry_run: bool = False) -> dict:
    """Re-embed all enrichment docs using stored fields — no LLM generation calls."""
    from types import SimpleNamespace

    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    cooc_cfg = cfg.cooccurrence
    use_cooc = cooc_cfg.enabled and cooc_cfg.embed_cooccurrence
    total_sessions = (
        _fetch_total_session_count(es, events_idx) if use_cooc else 0
    )

    log.info(
        "re-embed: embed_context=%s embed_version=%s embed_cooccurrence=%s index=%s dry_run=%s",
        cfg.llm.embed_context, cfg.llm.embed_version, use_cooc, commands_idx, dry_run,
    )

    stats: dict = defaultdict(int)
    actions: list[dict] = []
    now = _now()

    with make_llm_client(cfg.llm) as llm:
        for doc in iter_docs_for_reembed(es, commands_idx):
            stats["docs_seen"] += 1
            if not doc["command"]:
                stats["skipped_no_command"] += 1
                continue

            parsed_stub = SimpleNamespace(
                intent=doc["intent"],
                tactics=doc["tactics"],
                techniques=doc["techniques"],
                description=doc["description"],
            )
            cooccurring: list[tuple[str, int]] = []
            if use_cooc:
                cooccurring = fetch_cooccurring_commands(
                    es, events_idx, doc["command"],
                    session_sample_size=cooc_cfg.session_sample_size,
                    top_k=cooc_cfg.top_k,
                    min_sessions=cooc_cfg.min_sessions,
                    total_sessions=total_sessions,
                )
            embed_text = _build_embed_text(
                doc["command"], parsed_stub, cfg.llm.embed_context,
                cooccurring=cooccurring,
                embed_cooccurrence=use_cooc,
            )

            if dry_run:
                stats["would_embed"] += 1
                continue

            try:
                embedding = llm.embed(embed_text)
            except Exception as e:
                log.error("embed failed for doc %s: %s", doc["doc_id"], e)
                stats["embed_failed"] += 1
                continue

            stats["embedded_ok"] += 1
            actions.append({
                "_op_type": "update",
                "_id": doc["doc_id"],
                "script": {
                    "source": _REEMBED_SCRIPT,
                    "params": {"embedding": embedding},
                },
            })

            db.mark_cached(
                doc["doc_id"],
                cfg.llm.generation_model,
                cfg.worker.prompt_version,
                cfg.llm.embed_version,
                now,
            )

            if len(actions) >= 50:
                ok, errs = bulk_write(es, commands_idx, actions)
                stats["bulk_ok"] += ok
                stats["bulk_errors"] += len(errs)
                if errs:
                    log.warning("re-embed bulk errors (%d): %s", len(errs), errs[:2])
                actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("re-embed bulk errors (%d): %s", len(errs), errs[:2])

    db.close()
    return dict(stats, dry_run=dry_run, embed_version=cfg.llm.embed_version)


# ---------------------------------------------------------------------------
# Cluster commands
# ---------------------------------------------------------------------------

def iter_enriched_docs(
    es: Elasticsearch,
    index: str,
    page_size: int = 1000,
) -> Iterator[tuple[str, list[float], str, dict]]:
    """Yield (doc_id, embedding, command, scalars) for docs that have an embedding.

    scalars keys: occurrence_count, unique_source_ips, confidence, session_reuse_rate.
    """
    body: dict = {
        "size": page_size,
        "_source": [
            "dshield.cowrie.enrichment.embedding",
            "dshield.cowrie.enrichment.occurrence_count",
            "dshield.cowrie.enrichment.unique_sessions",
            "dshield.cowrie.enrichment.unique_source_ips",
            "dshield.cowrie.enrichment.confidence",
            "process.command_line",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.embedding"}},
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
            en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment", {})
            emb = en.get("embedding")
            if not emb:
                continue
            cmd = (src.get("process") or {}).get("command_line", "")
            occ = en.get("occurrence_count") or 1
            scalars = {
                "occurrence_count": occ,
                "unique_sessions": en.get("unique_sessions") or 1,
                "unique_source_ips": en.get("unique_source_ips") or 1,
                "confidence": en.get("confidence") or 5,
                "session_reuse_rate": min((en.get("unique_sessions") or 1) / occ, 1.0),
            }
            yield h["_id"], emb, cmd, scalars
        search_after = hits[-1]["sort"]


def build_command_scalar_block(scalars_list: list[dict], weight: float) -> "np.ndarray":
    """(n, 4) weighted scalar matrix appended to L2-normalized embeddings."""
    import numpy as np
    counts = np.array([s.get("occurrence_count") or 1 for s in scalars_list], dtype=np.float32)
    ips = np.array([s.get("unique_source_ips") or 1 for s in scalars_list], dtype=np.float32)
    conf = np.array([s.get("confidence") or 5 for s in scalars_list], dtype=np.float32)
    reuse = np.array([s.get("session_reuse_rate", 1.0) for s in scalars_list], dtype=np.float32)

    max_count = float(np.max(counts)) if counts.max() > 0 else 1.0
    max_ips = float(np.max(ips)) if ips.max() > 0 else 1.0

    block = np.zeros((len(scalars_list), 4), dtype=np.float32)
    block[:, 0] = (np.log1p(counts) / np.log1p(max_count)) * weight
    block[:, 1] = (np.log1p(ips) / np.log1p(max_ips)) * weight
    block[:, 2] = (conf / 10.0) * weight
    block[:, 3] = np.clip(reuse, 0.0, 1.0) * weight
    return block


def run_cluster(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """Cluster command embeddings + write novelty scores back. Delegates to clustering core."""
    from ...clustering import run_layer_clustering
    es = make_client(cfg.elasticsearch, secrets)
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    clusters_idx = cfg.elasticsearch.indexes.cowrie.command_clusters
    ccfg: CommandClusterConfig = cfg.command_cluster

    if not es.indices.exists(index=commands_idx):
        raise RuntimeError(
            f"Commands index '{commands_idx}' not found. "
            "Run 'enrich' first, or check elasticsearch.indexes.cowrie.commands in config."
        )

    return run_layer_clustering(
        es=es,
        docs_iter=iter_enriched_docs(es, commands_idx, ccfg.page_size),
        docs_index=commands_idx,
        clusters_index=clusters_idx,
        mapping_path=_COMMAND_CLUSTERS_MAPPING,
        update_script=_CLUSTER_UPDATE_SCRIPT,
        scalar_block_builder=build_command_scalar_block,
        min_cluster_size=ccfg.min_cluster_size,
        min_samples=ccfg.min_samples,
        scalar_weight=ccfg.scalar_weight,
        batch_size=ccfg.batch_size,
        sample_size=_CLUSTER_SAMPLE_SIZE,
        centroid_sample_field="sample_commands",
        dry_run=dry_run,
        layer_label="cowrie.commands",
    )
