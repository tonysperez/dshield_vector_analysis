"""Phase 1 orchestration: read events -> dedup -> enrich -> write."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from pydantic import ValidationError

from .cache import StateDB
from .config import AppConfig, Secrets, load_prompt
from .es_client import bulk_write, iter_command_events, make_client
from .llm import make_llm_client
from .llm.schemas import CommandEnrichment, CloudCommandEnrichment
from . import triage as triage_mod

log = logging.getLogger(__name__)

_WS_RE = re.compile(r"\s+")


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
    """Short hash used as ES _id and event.id. Full sha256 is stored in process.hash.sha256."""
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
    """Convert flat IOC arrays into ECS threat.indicator nested-object array.

    ECS types: ipv4-addr, ipv6-addr, domain-name, url, file.
    See https://www.elastic.co/guide/en/ecs/current/ecs-threat.html
    """
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
) -> tuple[Optional[CloudCommandEnrichment], int, int]:
    """Returns (parsed_or_None, input_tokens, output_tokens). Tokens are 0 on hard failure."""
    from .llm.anthropic import parse_cloud_json, _strip_code_fences
    prompt = (
        prompt_template
        .replace("<<<COMMAND>>>", command)
        .replace("<<<TRIAGE_REASONS>>>", ", ".join(triage_reasons) if triage_reasons else "(none)")
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
) -> tuple[Optional[CommandEnrichment], str, str]:
    """Returns (enrichment_or_None, source, model). source: 'local' | 'local_failed'."""
    prompt = prompt_template.replace("<<<COMMAND>>>", command)
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
            prompt_template.replace("<<<COMMAND>>>", command)
            + "\n\nYour previous response was invalid JSON. It was:\n"
            + raw[:500]
            + "\nReturn ONLY valid JSON."
        )
    log.warning("local enrichment failed after retries; last_raw=%r", last_raw[:200])
    return None, "local_failed", llm.gen_model


def run(cfg: AppConfig, secrets: Secrets, dry_run: bool = False, no_cloud: bool = False) -> dict:
    """Main worker entry. Returns stats dict."""
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    prompt = load_prompt(cfg, "command_enrichment")

    cloud_enabled = bool(cfg.cloud.enabled and not no_cloud and secrets.anthropic_api_key)
    cloud_prompt: Optional[str] = None
    cloud_client = None
    if cloud_enabled:
        if cfg.prompts.command_deep_dive is None:
            log.warning("cloud enabled but prompts.command_deep_dive is unset; skipping cloud")
            cloud_enabled = False
        else:
            cloud_prompt = load_prompt(cfg, "command_deep_dive")
            from .llm.anthropic import AnthropicClient
            cloud_client = AnthropicClient(
                api_key=secrets.anthropic_api_key,
                model=cfg.cloud.model,
                max_tokens=cfg.cloud.max_tokens,
                timeout=cfg.cloud.request_timeout,
                base_url=cfg.cloud.base_url,
            )
            # Preflight ping — connectivity + auth only, no generation tokens.
            # Failure here means rotated key, network glitch, or Anthropic
            # outage; degrade to local-only instead of failing the whole run.
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

    since = db.get_watermark()
    if since is None and cfg.worker.initial_lookback_days is not None:
        from datetime import timedelta
        since_dt = datetime.now(timezone.utc) - timedelta(days=cfg.worker.initial_lookback_days)
        since = since_dt.isoformat()
    log.info("Watermark: %s", since or "(none, full backfill)")

    stats = defaultdict(int)
    # group_by_hash[h] = {command, normalized, truncated, sessions:set, ips:set, first, last, count}
    groups: dict[str, dict] = {}
    last_ts = since

    for hit in iter_command_events(es, cfg.elasticsearch.events_index, since, cfg.worker.page_size):
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
            cached = db.is_cached(h, cfg.llm.generation_model, cfg.worker.prompt_version)
            if cached:
                # Bulk-update aggregate stats only via scripted update.
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
            # 1) embedding
            try:
                embedding = llm.embed(g["command"])
            except Exception as e:
                log.error("embed failed for %s: %s", h, e)
                stats["embed_failed"] += 1
                continue

            # 2) enrichment
            parsed, source, model = enrich_one(
                llm, prompt, g["command"], cfg.llm.max_retries
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
                confidence = 1  # minimum on the 1-10 scale
                tactics, techniques = [], []
                indicators = []
                stats["enriched_failed"] += 1

            # --- Phase 2 triage + cloud escalation ---------------------------
            triage_reasons: list[str] = []
            notes = ""
            local_fallback_doc: Optional[dict] = None
            doc_provider = source
            doc_model = model

            if cloud_enabled:
                triage_reasons = triage_mod.reasons_to_escalate(
                    command=g["command"],
                    parsed=parsed,
                    local_failed=(source == "local_failed"),
                    cfg=cfg.cloud,
                )
                if triage_reasons:
                    stats["triaged"] += 1
                    if not triage_mod.can_spend(db, cfg.cloud):
                        stats["cloud_skipped_budget"] += 1
                        triage_reasons.append("budget_exhausted")
                    else:
                        cloud_parsed, in_tok, out_tok = cloud_enrich_one(
                            cloud_client, cloud_prompt, g["command"], triage_reasons,
                        )
                        from .llm.anthropic import cost_usd as _cost_usd
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
                            stats["cloud_enriched_ok"] += 1
                        else:
                            stats["cloud_enriched_failed"] += 1
                            triage_reasons.append("cloud_parse_failed")

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
            # Cache on successful enrichment (local or cloud). local_failed without
            # successful cloud rescue stays uncached so a retry happens next run.
            if doc_provider in ("local", "claude"):
                db.mark_cached(h, cfg.llm.generation_model, cfg.worker.prompt_version, now)

            # Flush periodically
            if len(actions) >= 50:
                ok, errs = bulk_write(es, cfg.elasticsearch.enrichment_index, actions)
                stats["bulk_ok"] += ok
                stats["bulk_errors"] += len(errs)
                if errs:
                    log.warning("bulk errors (%d): %s", len(errs), errs[:2])
                actions = []

    if actions:
        ok, errs = bulk_write(es, cfg.elasticsearch.enrichment_index, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("bulk errors (%d): %s", len(errs), errs[:2])

    if last_ts and last_ts != since:
        db.set_watermark(last_ts)
        log.info("Watermark advanced to %s", last_ts)

    if cloud_client is not None:
        cloud_client.close()

    out = dict(stats, unique_commands=len(groups))
    # Convert the integerized cost back to USD for human-readable output.
    if "cloud_cost_usd_x10000" in out:
        out["cloud_cost_usd"] = out.pop("cloud_cost_usd_x10000") / 10000.0
    db.close()
    return out
