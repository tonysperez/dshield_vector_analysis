"""CLI entry points.

Verb shape: ``<verb> [<layer>] --source <source>``

Multi-source-ready: every layer-bearing verb accepts ``--source`` (default
``cowrie``). New sources slot in as ``sources/<source>/<layer>.py`` modules
with the same ``run_*`` callables; this dispatcher routes by name.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from .__about__ import CLI_NAME
from .config import load_config, load_secrets
from . import healthcheck as hc_mod


def _setup_log(level: str, log_dir: str | None = None) -> None:
    """Configure root logging.

    Always installs a stderr handler so systemd's journal capture and
    interactive shell sessions both see live output. When `log_dir` is
    non-empty AND writable, additionally installs a RotatingFileHandler
    on `<log_dir>/cli.log` (10 MB × 5 backups) so historical CLI runs
    are durable independent of journald rotation.

    File-handler failures (missing directory, no write permission, etc.)
    fall back to stderr-only with a single warning printed; never raise,
    so the CLI works on dev workstations where /var/log/dshield_prism
    doesn't exist.
    """
    import os
    fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
    lvl = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    # PRISM_LOG_DIR env var wins over config so operators can redirect
    # ad-hoc without editing config.
    env_dir = os.environ.get("PRISM_LOG_DIR")
    resolved = env_dir if env_dir is not None else (log_dir or "")
    if resolved:
        try:
            os.makedirs(resolved, exist_ok=True)
            from logging.handlers import RotatingFileHandler
            log_path = os.path.join(resolved, "cli.log")
            handlers.append(
                RotatingFileHandler(
                    log_path, maxBytes=10 * 1024 * 1024, backupCount=5,
                    encoding="utf-8",
                )
            )
        except Exception as exc:
            # Single stderr line, no traceback — file logging is a nicety.
            print(
                f"[warn] file logging disabled: {resolved}/cli.log unwritable ({exc})",
                file=__import__("sys").stderr, flush=True,
            )
    logging.basicConfig(level=lvl, format=fmt, handlers=handlers, force=True)


# --- per-source dispatch ----------------------------------------------------
# Each (source, layer) -> module that exposes the named run_* entry points.

def _load_source_layer(source: str, layer: str):
    """Return the module that owns this (source, layer) pair."""
    if source == "cowrie":
        from .sources.cowrie import commands, sessions, ips, campaigns
        return {
            "commands":  commands,
            "sessions":  sessions,
            "ips":       ips,
            "campaigns": campaigns,
        }.get(layer)
    return None


def _commands_layer(source: str):
    """Commands-layer module for a source (used by enrich/escalate/reembed)."""
    return _load_source_layer(source, "commands")


# --- mapping files for init-indexes ----------------------------------------

_LAYER_MAPPINGS = {
    "cowrie": {
        "commands":         "setup/es-mappings/cowrie/commands.json",
        "command_clusters": "setup/es-mappings/cowrie/command_clusters.json",
        "sessions":         "setup/es-mappings/cowrie/sessions.json",
        "session_clusters": "setup/es-mappings/cowrie/session_clusters.json",
        "ips":              "setup/es-mappings/cowrie/ips.json",
        "ip_clusters":      "setup/es-mappings/cowrie/ip_clusters.json",
        "campaigns":        "setup/es-mappings/cowrie/campaigns.json",
    },
    # External threat-intel — cross-source per-artifact indices.
    # `init-indexes --source intel` creates these. M1 shipped `ip`,
    # M4 added `url`; `domain` / `hash` land when corpus produces
    # extractable values.
    "intel": {
        "ip":     "setup/es-mappings/intel/ip.json",
        "url":    "setup/es-mappings/intel/url.json",
    },
    # Persisted findings index — M5. Cross-source: the miner reads
    # IP rollups + intel-{ip,url}, writes one findings index.
    "findings": {
        "default": "setup/es-mappings/findings/default.json",
    },
}


def _wipe_processed(cfg, secrets, source: str) -> dict:
    """Destroy every processed ES index for this source and recreate them
    from their mapping files; clear the SQLite cache + watermark. The raw
    `sessions_raw` (cowrie source-of-truth) index is intentionally not
    touched — this only wipes derived/computed data so the pipeline can be
    rebuilt from scratch.

    Returns a dict of per-index actions and per-state-table row counts.
    """
    from .es_client import init_index, make_client
    from .cache import StateDB

    es = make_client(cfg.elasticsearch, secrets)
    mappings = _LAYER_MAPPINGS.get(source) or {}
    # All layers except `sessions` (which is sessions_raw alias-bearing for
    # other sources; for cowrie source it maps to sessions_rollup which IS
    # processed) — and we explicitly EXCLUDE the raw source-of-truth.
    #
    # For cowrie: processed layers are everything in the mapping table.
    # `sessions_raw` is NOT in the mapping table (it's an external index
    # produced by Filebeat/Elastic agent) — so iterating mappings.keys() is
    # already the right set.
    out: dict = {"deleted": [], "created": [], "errors": []}
    for layer in mappings.keys():
        idx = _resolve_index_for_layer(cfg, source, layer)
        # Delete (idempotent).
        try:
            if es.indices.exists(index=idx):
                es.indices.delete(index=idx)
                out["deleted"].append(idx)
        except Exception as exc:
            out["errors"].append({"layer": layer, "action": "delete", "error": str(exc)})
            continue
        # Recreate from mapping file.
        try:
            r = init_index(es, mappings[layer], idx)
            out["created"].append(r)
        except Exception as exc:
            out["errors"].append({"layer": layer, "action": "init", "error": str(exc)})

    # SQLite state.
    try:
        db = StateDB(cfg.worker.state_db)
        out["sqlite_cache_rows_deleted"]     = db.clear_cache()
        out["sqlite_watermark_rows_deleted"] = db.clear_watermark()
        db.close()
    except Exception as exc:
        out["errors"].append({"action": "sqlite_clear", "error": str(exc)})
    return out


def _acquire_pipeline_lock(cfg, *, no_lock: bool, print_args):
    """Acquire the same flock the systemd units use, so manual `pipeline`
    invocations serialise with the forward / backward / mine-findings
    timers. Returns the open file descriptor (caller keeps it alive for
    the duration of the run; closing releases the lock).

    Lock path mirrors the systemd units: `<state_db parent>/.lock`. With
    the default config that's `/var/lib/dshield_prism/.lock`.

    --no-lock skips acquisition entirely. Pre-emptive escape hatch for
    test environments or ad-hoc runs where you've already stopped the
    systemd timers and don't want the lock dance.
    """
    if no_lock:
        print_args("[pipeline] --no-lock: skipping flock acquisition (caller responsible for serialisation)")
        return None
    import fcntl
    from pathlib import Path
    lock_path = Path(cfg.worker.state_db).parent / ".lock"
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    # Open for append (creates if missing). The file's content is
    # irrelevant — the OS-level advisory lock is what serialises us.
    lock_fd = open(lock_path, "a")
    try:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        print_args(f"[pipeline] acquired lock {lock_path}")
    except BlockingIOError:
        print_args(f"[pipeline] waiting for lock {lock_path} (held by another process — likely forward/backward/mine-findings)")
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
        print_args(f"[pipeline] acquired lock {lock_path}")
    return lock_fd


def _run_pipeline(cfg, secrets, args) -> int:
    """End-to-end runner: each verb is invoked in dependency order via the
    same `run_*` entry points the individual CLI verbs call. Steps marked
    `optional=True` won't halt the chain on failure (mirrors the analytics
    systemd unit's leading `-` semantics). `--continue-on-error` extends
    that tolerance to every step.

    The whole run is serialised with the systemd timers via an exclusive
    flock on `<state_db_parent>/.lock`. Use `--no-lock` to skip if the
    timers are already stopped and you want a fast manual iteration.
    """
    print_args = lambda *a, **kw: print(*a, **{**kw, "flush": True})

    # Hold the flock for the entire run. `_pipeline_lock_fd` stays alive
    # in this scope; closing on function exit releases the lock.
    _pipeline_lock_fd = _acquire_pipeline_lock(
        cfg, no_lock=getattr(args, "no_lock", False), print_args=print_args,
    )

    # ---- Optional fresh-start wipe ---------------------------------------
    # `--force` wipes every processed index across ALL sources (cowrie +
    # intel + findings) plus the SQLite cache + watermark. The only thing
    # preserved is the raw `sessions_raw` index — that's the source of
    # truth ingested by Filebeat/Elastic-agent and is intentionally not
    # touched. Re-running the pipeline rebuilds everything else from raw.
    wipe_sources = ["cowrie", "intel", "findings"]
    if args.force:
        if not args.yes:
            try:
                resp = input(
                    "[pipeline] --force will DELETE every processed ES index "
                    f"across all sources ({', '.join(wipe_sources)}):\n"
                    "  cowrie:   commands, command_clusters, sessions_rollup, "
                    "session_clusters, ips_rollup, ip_clusters, campaigns\n"
                    "  intel:    prism.intel.ip, prism.intel.url\n"
                    "  findings: prism.finding\n"
                    "and clear the SQLite cache + watermark. The raw "
                    "sessions_raw index is NOT touched.\n"
                    "Proceed? [y/N] "
                ).strip().lower()
            except EOFError:
                resp = ""
            if resp not in ("y", "yes"):
                print_args("Aborted.")
                return 1
        if args.dry_run:
            print_args(
                "[pipeline] DRY-RUN: would wipe every processed index across "
                f"{wipe_sources}, clear SQLite, then run every step."
            )
        else:
            wipe_summary: dict = {}
            for src in wipe_sources:
                wipe_summary[src] = _wipe_processed(cfg, secrets, src)
            print_args("[pipeline] wipe:")
            print_args(json.dumps(wipe_summary, indent=2, default=str))

    # ---- Step plan -------------------------------------------------------
    # Each step is (name, callable, optional). `optional=True` mirrors the
    # systemd unit's leading-dash semantics: a failure logs but doesn't
    # break the chain. Order is the same as the systemd ingest + analytics
    # services chained together.
    cmds_mod      = _commands_layer(args.source)
    sessions_mod  = _load_source_layer(args.source, "sessions")
    ips_mod       = _load_source_layer(args.source, "ips")
    campaigns_mod = _load_source_layer(args.source, "campaigns")
    if cmds_mod is None or sessions_mod is None or ips_mod is None or campaigns_mod is None:
        print_args(f"[ERROR] Source {args.source!r} is missing one or more pipeline layers.")
        return 1

    dry = args.dry_run
    if getattr(args, "ignore_config_hash", False):
        cfg.worker.cache_auto_invalidate = False

    # Lazy imports so a missing optional dep (e.g. intel disabled in
    # local.yaml) doesn't break the dispatcher import path.
    def _run_intel_refresh():
        from .intel.refresh import run_refresh
        return run_refresh(cfg, secrets, dry_run=dry)

    def _run_mine_findings():
        from .findings.miner import run_mine as _rm
        return _rm(cfg, secrets, dry_run=dry)

    def _reset_rollup_watermarks():
        """Clear the session + IP rollup watermarks so the next rollup
        re-pools from every session/IP. Mirrors `reset --session-watermark
        --ip-watermark --yes`. No-op when the watermarks were never set
        (fresh deploys, --force runs that wiped SQLite). Returns a dict
        for the step summary."""
        from .cache import StateDB
        db = StateDB(cfg.worker.state_db)
        try:
            sess = db.clear_watermark("session_rollup_last_processed_at")
            ipw = db.clear_watermark("ip_rollup_last_processed_at")
        finally:
            db.close()
        return {"session_watermark_rows_deleted": sess, "ip_watermark_rows_deleted": ipw}

    steps: list[tuple[str, callable, bool]] = [
        # ---- pre-enrich catch-up: re-LLM and re-embed any rows whose
        # cache hashes drifted since the last run. Both are no-ops in
        # steady state and on fresh deploys; they only do work when a
        # prompt edit, embed_context change, or model swap has happened.
        # Optional: shouldn't halt the chain if the LLM is down.
        ("re-enrich-stale",            lambda: cmds_mod.run_reenrich_stale(cfg, secrets, dry_run=dry),                    True),
        ("reembed",                    lambda: cmds_mod.run_reembed(cfg, secrets, dry_run=dry),                           True),

        # ---- ingest: raw events → enriched commands
        ("enrich",                     lambda: cmds_mod.run_enrich(cfg, secrets, dry_run=dry, no_cloud=args.no_cloud), False),

        # ---- force a full rollup re-pool. The rollup verbs are
        # watermark-driven; after re-enrich-stale or reembed may have
        # rewritten command-level data, we want the session/IP rollups
        # to incorporate those changes rather than only processing rows
        # whose source ts is newer than the watermark. SQLite-only;
        # cheap and idempotent. Mirrors backward systemd step 3.
        ("reset rollup watermarks",    _reset_rollup_watermarks,                                                          True),

        # ---- session rollup + command clustering + cloud escalation
        ("rollup sessions",            lambda: sessions_mod.run_rollup(cfg, secrets, dry_run=dry),                       False),
        ("cluster commands",           lambda: cmds_mod.run_cluster(cfg, secrets, dry_run=dry),                           False),
        ("escalate",                   lambda: cmds_mod.run_escalate(cfg, secrets, dry_run=dry),                          True),

        # ---- session clustering + LLM naming (playbooks = named session clusters)
        ("cluster sessions",           lambda: sessions_mod.run_cluster(cfg, secrets, dry_run=dry),                       False),
        ("name playbooks",             lambda: sessions_mod.run_name_playbooks(cfg, secrets, dry_run=dry, force=False),   True),

        # ---- IP rollup + clustering. `rollup ips` MUST come after
        # `name playbooks` because session rollups carry playbook_id
        # only after naming runs, and `name ip-clusters` reads those
        # session rollups to derive dominant_playbook per IP cluster.
        # ROADMAP #24.
        ("rollup ips",                 lambda: ips_mod.run_rollup(cfg, secrets, dry_run=dry),                             False),
        ("cluster ips",                lambda: ips_mod.run_cluster(cfg, secrets, dry_run=dry),                            False),
        ("name ip-clusters",           lambda: ips_mod.run_name_ip_clusters(cfg, secrets, dry_run=dry),                   True),

        # ---- multi-session campaign mining (frequent-itemset + shared-artifact)
        ("mine campaigns",             lambda: campaigns_mod.run_mine(cfg, secrets, kind="all", dry_run=dry),             True),

        # ---- external threat-intel refresh — must run AFTER `rollup ips`
        # (uses IP rollup for discovery) and AFTER `enrich` (uses
        # LLM-extracted URL indicators in the commands index). No-op
        # when intel is disabled in config; the run_refresh entry
        # point gates on cfg.intel.enabled.
        ("intel refresh",              _run_intel_refresh,                                                                True),

        # ---- findings miner — populates prism.finding with one card
        # per playbook + per campaign. Reads everything above;
        # intentionally last in the chain so the inbox reflects this
        # pipeline's output.
        ("mine findings",              _run_mine_findings,                                                                True),
    ]

    if dry:
        print_args("[pipeline] DRY-RUN — step plan:")
        for i, (name, _fn, optional) in enumerate(steps, 1):
            tag = " (optional)" if optional else ""
            print_args(f"  {i:2}. {name}{tag}")
        # Still call each so dry-run telemetry from the steps that support it
        # is exposed (most do).
    print_args(f"[pipeline] running {len(steps)} step(s){' (dry-run)' if dry else ''}")

    summary: dict = {"force_wipe": bool(args.force), "dry_run": dry, "steps": []}
    failed_hard = False
    for i, (name, fn, optional) in enumerate(steps, 1):
        print_args(f"\n=== [{i}/{len(steps)}] {name}" + (" (optional)" if optional else "") + " ===")
        try:
            stats = fn()
            summary["steps"].append({"name": name, "ok": True, "stats": stats})
            print_args(json.dumps(stats, indent=2, default=str))
        except Exception as exc:
            summary["steps"].append({"name": name, "ok": False, "error": str(exc)})
            print_args(f"[FAIL] {name}: {exc}")
            if optional or args.continue_on_error:
                continue
            failed_hard = True
            break

    print_args("\n[pipeline] summary:")
    print_args(json.dumps(
        {"force_wipe": summary["force_wipe"],
         "dry_run":    summary["dry_run"],
         "steps":      [{"name": s["name"], "ok": s["ok"]} for s in summary["steps"]]},
        indent=2,
    ))
    return 1 if failed_hard else 0


def _resolve_index_for_layer(cfg, source: str, layer: str) -> str:
    """Map (source, layer) -> the configured index name on cfg."""
    if source == "cowrie":
        c = cfg.elasticsearch.indexes.cowrie
        return {
            "commands":         c.commands,
            "command_clusters": c.command_clusters,
            "sessions":         c.sessions_rollup,
            "session_clusters": c.session_clusters,
            "ips":              c.ips_rollup,
            "ip_clusters":      c.ip_clusters,
            "campaigns":        c.campaigns,
        }[layer]
    if source == "intel":
        i = cfg.intel.indexes
        return {
            "ip":     i.ip,
            "url":    i.url,
            "domain": i.domain,
            "hash":   i.hash,
        }[layer]
    if source == "findings":
        return {"default": cfg.findings.indexes.default}[layer]
    raise ValueError(f"Unknown source: {source}")


# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=CLI_NAME)
    p.add_argument("--config", default=None, help="Path to YAML config")
    sub = p.add_subparsers(dest="verb", required=True)

    # healthcheck
    p_hc = sub.add_parser("healthcheck", help="Verify ES/LLM/SQLite/cloud connectivity")
    p_hc.add_argument(
        "--scope",
        default="all",
        help=(
            "Comma-separated subset of scopes: "
            f"{','.join(hc_mod.VALID_SCOPES)} (or 'all'). "
            "Example: --scope llm,cloud."
        ),
    )

    # enrich (commands-layer only for now; multi-layer future opens this up)
    p_enrich = sub.add_parser("enrich", help="Enrich command events from a source")
    p_enrich.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_enrich.add_argument("--dry-run", action="store_true", help="Read events but skip LLM + writes")
    p_enrich.add_argument("--no-cloud", action="store_true", help="Force-disable cloud escalation for this run")
    p_enrich.add_argument(
        "--ignore-config-hash", action="store_true",
        help=(
            "Override worker.cache_auto_invalidate=true for this run only — "
            "treat the cache as if prompt/cooccurrence config didn't change. "
            "Use when LLM budget is tight and you'd rather keep current "
            "enrichments through a config drift."
        ),
    )

    # budget
    sub.add_parser("budget", help="Show today's cloud-LLM spend vs daily cap")

    # reset
    p_reset = sub.add_parser(
        "reset",
        help="Clear local SQLite state (cache and/or watermarks). Does NOT touch ES.",
    )
    p_reset.add_argument("--cache", action="store_true",
                         help="Clear the enrichment cache")
    p_reset.add_argument("--watermark", action="store_true",
                         help="Clear ALL watermarks (command + session + IP)")
    p_reset.add_argument("--all", action="store_true",
                         help="Clear cache and all watermarks (default when no flag given)")
    p_reset.add_argument("--session-watermark", action="store_true",
                         help=(
                             "Clear only the session-rollup watermark "
                             "(forces a full re-rollup of sessions). "
                             "Combinable with other flags."
                         ))
    p_reset.add_argument("--ip-watermark", action="store_true",
                         help=(
                             "Clear only the IP-rollup watermark "
                             "(forces a full re-rollup of IPs). "
                             "Combinable with other flags."
                         ))
    p_reset.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    # init-indexes
    p_init = sub.add_parser(
        "init-indexes",
        help="Create ES indexes from mapping JSON. Defaults to all layers for the source.",
    )
    p_init.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_init.add_argument(
        "--layer",
        default=None,
        help=(
            "Specific layer to init (e.g. commands, sessions, ips, command_clusters, "
            "session_clusters, ip_clusters). Omit to init all layers."
        ),
    )
    p_init.add_argument(
        "--update-mapping",
        action="store_true",
        help="If an index exists, push additive mapping changes instead of noop",
    )

    # bootstrap-es — apply project-owned ES templates + ingest pipelines from
    # the setup/ tree. Idempotent. Runs from the install dir; reuses the
    # same ES client (TLS + auth) as everything else. Setup script calls
    # this after healthcheck and before init-indexes so the data-stream
    # template exists when the cowrie ingest pipeline first reroutes into
    # `prism.raw.cowrie.session`.
    p_boot = sub.add_parser(
        "bootstrap-es",
        help="Apply setup/*.yaml + setup/es-pipelines/*.yml to ES (templates + ingest pipelines)",
    )
    p_boot.add_argument(
        "--dry-run", action="store_true",
        help="Parse + list what would be applied without contacting ES",
    )

    # escalate
    p_escalate = sub.add_parser(
        "escalate",
        help="Re-triage novel locally-enriched docs via cloud LLM. Run after cluster.",
    )
    p_escalate.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_escalate.add_argument("--dry-run", action="store_true", help="Count candidates without making cloud calls")

    # reembed
    p_reembed = sub.add_parser(
        "reembed",
        help="Re-embed enrichment docs using stored fields. No LLM generation calls.",
    )
    p_reembed.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_reembed.add_argument(
        "--dry-run", action="store_true",
        help="Count docs that would be re-embedded without calling the embed model or writing to ES",
    )
    p_reembed.add_argument(
        "--ignore-config-hash", action="store_true",
        help="See `enrich --ignore-config-hash`.",
    )

    # re-enrich-stale — LLM-side mirror of `reembed`. Walks the commands
    # index, finds cache rows whose llm_config_hash is stale (e.g. after
    # a prompt edit), re-calls the local LLM, and patches the doc.
    p_reenrich = sub.add_parser(
        "re-enrich-stale",
        help=(
            "Re-run the local LLM on every doc whose cached llm_config_hash "
            "is stale. The LLM-side counterpart of `reembed`. Skips rows "
            "whose hash already matches live (cheap no-op when nothing has "
            "changed). Burns LLM time per stale doc when prompts or "
            "LLM-side cooccurrence config have drifted. ROADMAP issue #7.5."
        ),
    )
    p_reenrich.add_argument("--source", default="cowrie",
                            help="Source name (default: cowrie)")
    p_reenrich.add_argument("--dry-run", action="store_true",
                            help="Count stale rows without calling LLM or writing.")

    # re-triage — re-evaluate stored `triage_reasons` against current rules.
    # No LLM/cloud calls. Closes the gap that `re-enrich-stale` doesn't cover:
    # triage.py changes (e.g. ROADMAP #23) don't affect llm_config_hash, so
    # stored triage_reasons on already-enriched docs go stale silently.
    p_retriage = sub.add_parser(
        "re-triage",
        help=(
            "Re-evaluate stored `triage_reasons` on every enriched command "
            "using the current triage rules. No LLM or cloud calls. Useful "
            "after a triage-rule change (e.g. #23) that re-enrich-stale "
            "won't pick up. Preserves runtime-only reasons "
            "(budget_exhausted/cloud_failed/sample). ROADMAP #23 follow-on."
        ),
    )
    p_retriage.add_argument("--source", default="cowrie",
                            help="Source name (default: cowrie)")
    p_retriage.add_argument(
        "--backward", action="store_true",
        help="Required. Scan every already-enriched doc and rewrite "
             "triage_reasons. Required flag so the verb has room for a "
             "future --forward mode without breaking call sites.",
    )
    p_retriage.add_argument(
        "--window-days", type=int, default=None,
        help="Only re-evaluate docs whose @timestamp is within the last N "
             "days. Default: all docs. Matches the #21 pattern.",
    )
    p_retriage.add_argument("--dry-run", action="store_true",
                            help="Report what would change without writing.")

    # bless-cache — stamp existing cache rows with the current config hash so
    # they're treated as fresh after a #7-style auto-invalidating config change.
    # The user opts into this when they know existing enrichments are
    # consistent with the current cooccurrence config + prompts.
    p_bless = sub.add_parser(
        "bless-cache",
        help=(
            "Stamp all legacy cache rows (config_hash='') with the current "
            "config hash so they're treated as fresh. Use after deploying a "
            "config-affecting change when you know the cached enrichments are "
            "still correct under the new config. ROADMAP issue #7."
        ),
    )
    p_bless.add_argument(
        "--dry-run", action="store_true",
        help="Report how many rows would be stamped without writing to the cache.",
    )

    # cluster <layer>
    p_cluster = sub.add_parser("cluster", help="Run HDBSCAN over a layer's embeddings")
    cluster_sub = p_cluster.add_subparsers(dest="layer", required=True)
    for layer_name in ("commands", "sessions", "ips"):
        cl = cluster_sub.add_parser(layer_name, help=f"Cluster {layer_name}")
        cl.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
        cl.add_argument("--dry-run", action="store_true", help="Fetch + cluster but skip all ES writes")

    # rollup <layer>
    p_rollup = sub.add_parser("rollup", help="Aggregate one layer up from raw events")
    rollup_sub = p_rollup.add_subparsers(dest="layer", required=True)
    for layer_name in ("sessions", "ips"):
        rl = rollup_sub.add_parser(layer_name, help=f"Rollup to {layer_name}")
        rl.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
        rl.add_argument("--dry-run", action="store_true", help="Count without writing docs")

    # name playbooks — LLM-name each non-outlier session cluster. The cluster
    # is the "playbook" (a recurring routine); the LLM picks a short label.
    p_name = sub.add_parser("name", help="LLM-name clusters")
    name_sub = p_name.add_subparsers(dest="subject", required=True)
    p_pb = name_sub.add_parser("playbooks", help="Name session-cluster playbooks")
    p_pb.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_pb.add_argument("--dry-run", action="store_true", help="Show candidates without calling LLM")
    p_pb.add_argument("--force", action="store_true", help="Rename clusters that already have a name")

    # name ip-clusters — annotate each IP-cluster centroid with its modal
    # playbook across member IPs' sessions. Must run AFTER `name playbooks`
    # (depends on session.playbook_id being populated). ROADMAP #24.
    p_ipc = name_sub.add_parser(
        "ip-clusters",
        help="Annotate IP-cluster centroids with dominant_playbook (#24)",
    )
    p_ipc.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_ipc.add_argument("--dry-run", action="store_true", help="No-op")

    # mine campaigns — multi-session campaign discovery. Runs frequent-itemset
    # mining over per-IP playbook bags (kind=behaviour) and/or shared-artifact
    # graph mining over raw events (kind=infrastructure). Distinct from
    # playbooks (which are per-session-cluster). See docs/PLAYBOOKS_AND_CAMPAIGNS.md.
    p_mine = sub.add_parser("mine", help="Discover multi-session campaigns")
    mine_sub = p_mine.add_subparsers(dest="subject", required=True)
    p_mc = mine_sub.add_parser("campaigns", help="Mine multi-session campaigns")
    p_mc.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_mc.add_argument(
        "--kind",
        choices=["behaviour", "infrastructure", "all"],
        default="all",
        help="Which miner(s) to run (default: all)",
    )
    p_mc.add_argument("--dry-run", action="store_true",
                      help="Mine without writing campaign docs")
    p_mc.add_argument(
        "--window-days",
        type=int,
        default=None,
        help="Only consider sessions/events from the last N days. "
             "Default (None) uses the miner's built-in default (currently 30); "
             "pass 0 to disable windowing and scan the entire corpus (legacy "
             "unbounded behaviour — slower and memory-hungrier on large "
             "corpora). ROADMAP #21.",
    )

    # mine findings — M5 persisted findings index. Cross-source: reads IP
    # rollup + intel-{ip,url}, writes prism.finding. Status
    # workflow on each doc is preserved across re-mines (writer merges
    # analyst-owned fields back in). Hourly via systemd timer.
    p_mf = mine_sub.add_parser("findings", help="Mine likely_discovery + axis_disagreement findings (M5)")
    p_mf.add_argument("--dry-run", action="store_true",
                      help="Score + rank without writing finding docs")

    # intel — external threat-intel subsystem. `refresh` runs one pass:
    # discovers artifacts, priority-queues them, dispatches to every
    # enabled provider, writes intel-*-default docs. `backfill` forces a
    # full re-scan (currently identical to refresh; reserved for future
    # scoping). See docs/ROADMAP.md "Research-mode strategic gaps" A.
    p_intel = sub.add_parser("intel", help="External threat-intel subsystem (ROADMAP A)")
    intel_sub = p_intel.add_subparsers(dest="subject", required=True)
    p_intel_refresh = intel_sub.add_parser(
        "refresh",
        help="One refresh pass — discover, queue, lookup, write",
    )
    p_intel_refresh.add_argument(
        "--dry-run", action="store_true",
        help="Discover + queue without calling providers or writing intel docs",
    )
    p_intel_backfill = intel_sub.add_parser(
        "backfill",
        help="Force a full re-scan over the corpus (same as refresh for milestone 1)",
    )
    p_intel_backfill.add_argument("--dry-run", action="store_true")
    # intel reapply-rules — re-derive each intel doc's verdicts from its
    # already-persisted per-provider structured data. No upstream calls,
    # so no budget burn. Use after deploying a consensus-rule change
    # (e.g. the 2026-05-17 authoritative_clean refinement).
    p_intel_reapply = intel_sub.add_parser(
        "reapply-rules",
        help="Recompute verdicts on existing intel docs without re-fetching",
    )
    p_intel_reapply.add_argument(
        "--dry-run", action="store_true",
        help="Walk every doc + report would-be changes without writing",
    )

    # pipeline — run every processing stage in order, raw → fully processed.
    # Mirrors the analytics + ingest systemd units but in one verb so a
    # human can rebuild from scratch (with --force) or top up incrementally
    # (without --force). Order matters: each step's inputs come from the
    # previous step's outputs.
    p_pipe = sub.add_parser(
        "pipeline",
        help=(
            "Run every processing step end-to-end: re-enrich-stale → reembed → "
            "enrich → reset rollup watermarks → rollup sessions → cluster commands → "
            "escalate → cluster sessions → name playbooks → rollup ips → cluster ips → "
            "name ip-clusters → mine campaigns → intel refresh → mine findings. "
            "Serialised with the systemd timers via an exclusive flock; pass "
            "--no-lock to skip when the timers are already stopped."
        ),
    )
    p_pipe.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_pipe.add_argument(
        "--force", action="store_true",
        help=(
            "Wipe ALL processed data first, across every source, then "
            "recreate each index from its mapping and clear the SQLite "
            "cache + watermark. Targets: cowrie (commands, command_clusters, "
            "sessions_rollup, session_clusters, ips_rollup, ip_clusters, "
            "campaigns), intel (prism.intel.{ip,url}), findings "
            "(prism.finding). The raw `sessions_raw` index is "
            "NOT touched. Requires --yes to skip the confirmation prompt."
        ),
    )
    p_pipe.add_argument(
        "--yes", action="store_true",
        help="Skip the confirmation prompt for --force",
    )
    p_pipe.add_argument(
        "--dry-run", action="store_true",
        help="Print the step list (and pass --dry-run to each step) without writing data",
    )
    p_pipe.add_argument(
        "--continue-on-error", action="store_true",
        help=(
            "Don't halt if a step fails. By default the LLM-dependent steps "
            "(escalate, name playbooks, mine campaigns) already tolerate "
            "failure; this flag extends that to every step."
        ),
    )
    p_pipe.add_argument(
        "--ignore-config-hash", action="store_true",
        help="See `enrich --ignore-config-hash`. Applies to enrich/reembed steps.",
    )
    p_pipe.add_argument(
        "--no-cloud", action="store_true",
        help="Pass --no-cloud through to `enrich` (skip cloud escalation paths)",
    )
    p_pipe.add_argument(
        "--no-lock", action="store_true",
        help=(
            "Skip the flock acquisition that serialises with the forward / "
            "backward / mine-findings systemd timers. Default behaviour is "
            "to wait for the lock; pass --no-lock when you've already "
            "stopped the timers and want to iterate without the wait."
        ),
    )

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    secrets = load_secrets(args.config)
    _setup_log(cfg.worker.log_level, log_dir=cfg.worker.log_dir)

    if args.verb == "healthcheck":
        raw_scope = (args.scope or "all").strip().lower()
        scopes = None if raw_scope == "all" else [s.strip() for s in raw_scope.split(",") if s.strip()]
        return hc_mod.check(cfg, secrets, scopes=scopes)

    if args.verb == "budget":
        from .cache import StateDB
        from . import triage as triage_mod
        db = StateDB(cfg.worker.state_db)
        today = triage_mod.utc_today()
        spent = db.get_spend(today)
        remaining = max(0.0, cfg.cloud.daily_budget_usd - spent["cost_usd"])
        out = {
            "date": today,
            "daily_budget_usd": cfg.cloud.daily_budget_usd,
            "spent_usd": round(spent["cost_usd"], 4),
            "remaining_usd": round(remaining, 4),
            "calls": spent["calls"],
            "input_tokens": spent["input_tokens"],
            "output_tokens": spent["output_tokens"],
            "cloud_enabled": cfg.cloud.enabled,
            "model": cfg.cloud.model,
        }
        db.close()
        print(json.dumps(out, indent=2))
        return 0

    if args.verb == "reset":
        from .cache import StateDB
        # Explicit selectors. Specific-watermark flags don't imply --all.
        explicit_specific = args.session_watermark or args.ip_watermark
        explicit_broad    = args.cache or args.watermark or args.all
        # No flag at all = clear everything (legacy default behaviour).
        default_all = not (explicit_specific or explicit_broad)

        do_cache       = args.cache or args.all or default_all
        do_all_wm      = args.watermark or args.all or default_all
        do_session_wm  = args.session_watermark and not do_all_wm
        do_ip_wm       = args.ip_watermark and not do_all_wm

        targets: list[str] = []
        if do_cache:      targets.append("cache")
        if do_all_wm:     targets.append("watermarks (all)")
        if do_session_wm: targets.append("session watermark only")
        if do_ip_wm:      targets.append("IP watermark only")
        msg = f"About to clear: {', '.join(targets)} from {cfg.worker.state_db}"
        print(msg)
        if not args.yes:
            try:
                resp = input("Proceed? [y/N] ").strip().lower()
            except EOFError:
                resp = ""
            if resp not in ("y", "yes"):
                print("Aborted.")
                return 1
        db = StateDB(cfg.worker.state_db)
        result: dict = {}
        if do_cache:
            result["cache_rows_deleted"] = db.clear_cache()
        if do_all_wm:
            result["watermark_rows_deleted"] = db.clear_watermark()
        else:
            if do_session_wm:
                # Key matches sessions._SESSION_WATERMARK_KEY — duplicated
                # rather than imported to avoid pulling in the LLM-dep
                # sessions module just for a string constant.
                result["session_watermark_deleted"] = db.clear_watermark(
                    "session_last_processed_at"
                )
            if do_ip_wm:
                result["ip_watermark_deleted"] = db.clear_watermark(
                    "ip_rollup_last_processed_at"
                )
        db.close()
        print(json.dumps(result, indent=2))
        return 0

    if args.verb == "bootstrap-es":
        from .bootstrap import run_bootstrap
        stats = run_bootstrap(cfg, secrets, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, default=str))
        return 0 if not stats.get("errors") else 1

    if args.verb == "init-indexes":
        from .es_client import init_index, make_client, update_mapping
        es = make_client(cfg.elasticsearch, secrets)
        mappings = _LAYER_MAPPINGS.get(args.source)
        if mappings is None:
            print(f"[ERROR] Unknown source: {args.source}", flush=True)
            return 1
        layers = [args.layer] if args.layer else list(mappings.keys())
        unknown = [l for l in layers if l not in mappings]
        if unknown:
            print(f"[ERROR] Unknown layer(s) for source {args.source}: {unknown}", flush=True)
            return 1
        results: list[dict] = []
        for layer in layers:
            mapping_path = mappings[layer]
            idx = _resolve_index_for_layer(cfg, args.source, layer)
            r = init_index(es, mapping_path, idx)
            if args.update_mapping and r.get("action") == "noop":
                r = update_mapping(es, mapping_path, idx)
            r["layer"] = layer
            results.append(r)
        print(json.dumps(results, indent=2))
        return 0

    if args.verb == "enrich":
        mod = _commands_layer(args.source)
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no commands layer", flush=True)
            return 1
        if getattr(args, "ignore_config_hash", False):
            cfg.worker.cache_auto_invalidate = False
        stats = mod.run_enrich(cfg, secrets, dry_run=args.dry_run, no_cloud=args.no_cloud)
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "escalate":
        mod = _commands_layer(args.source)
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no commands layer", flush=True)
            return 1
        try:
            stats = mod.run_escalate(cfg, secrets, dry_run=args.dry_run)
        except RuntimeError as exc:
            print(f"[ERROR] {exc}", flush=True)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "reembed":
        mod = _commands_layer(args.source)
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no commands layer", flush=True)
            return 1
        if getattr(args, "ignore_config_hash", False):
            cfg.worker.cache_auto_invalidate = False
        stats = mod.run_reembed(cfg, secrets, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "re-enrich-stale":
        mod = _commands_layer(args.source)
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no commands layer", flush=True)
            return 1
        stats = mod.run_reenrich_stale(cfg, secrets, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "re-triage":
        if not args.backward:
            print(
                "[ERROR] re-triage requires --backward. Forward mode isn't "
                "implemented yet; --backward signals 'rewrite triage_reasons "
                "on every already-enriched doc using current rules.'",
                flush=True,
            )
            return 1
        mod = _commands_layer(args.source)
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no commands layer", flush=True)
            return 1
        stats = mod.run_retriage(
            cfg, secrets,
            dry_run=args.dry_run,
            window_days=args.window_days,
        )
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "bless-cache":
        from .cache import StateDB
        from .config import compute_embed_config_hash, compute_llm_config_hash
        db = StateDB(cfg.worker.state_db)
        try:
            legacy = db.legacy_cache_row_count()
            llm_hash = compute_llm_config_hash(cfg)
            embed_hash = compute_embed_config_hash(cfg)
            if args.dry_run:
                print(json.dumps({
                    "dry_run": True,
                    "legacy_rows": legacy,
                    "would_stamp_llm_hash": llm_hash,
                    "would_stamp_embed_hash": embed_hash,
                }, indent=2))
            else:
                stamped = db.bless_legacy_cache_rows(llm_hash, embed_hash)
                print(json.dumps({
                    "stamped_rows": stamped,
                    "llm_config_hash": llm_hash,
                    "embed_config_hash": embed_hash,
                }, indent=2))
        finally:
            db.close()
        return 0

    if args.verb == "cluster":
        mod = _load_source_layer(args.source, args.layer)
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no {args.layer!r} layer", flush=True)
            return 1
        try:
            stats = mod.run_cluster(cfg, secrets, dry_run=args.dry_run)
        except (ImportError, RuntimeError) as exc:
            print(f"[ERROR] {exc}", flush=True)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "rollup":
        mod = _load_source_layer(args.source, args.layer)
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no {args.layer!r} layer", flush=True)
            return 1
        try:
            stats = mod.run_rollup(cfg, secrets, dry_run=args.dry_run)
        except RuntimeError as exc:
            print(f"[ERROR] {exc}", flush=True)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "name":
        if args.subject == "playbooks":
            mod = _load_source_layer(args.source, "sessions")
            if mod is None:
                print(f"[ERROR] Source {args.source!r} has no `sessions` layer", flush=True)
                return 1
            try:
                stats = mod.run_name_playbooks(
                    cfg, secrets, dry_run=args.dry_run, force=args.force,
                )
            except RuntimeError as exc:
                print(f"[ERROR] {exc}", flush=True)
                return 1
            print(json.dumps(stats, indent=2, default=str))
            return 0
        if args.subject == "ip-clusters":
            mod = _load_source_layer(args.source, "ips")
            if mod is None:
                print(f"[ERROR] Source {args.source!r} has no `ips` layer", flush=True)
                return 1
            try:
                stats = mod.run_name_ip_clusters(cfg, secrets, dry_run=args.dry_run)
            except RuntimeError as exc:
                print(f"[ERROR] {exc}", flush=True)
                return 1
            print(json.dumps(stats, indent=2, default=str))
            return 0
        print(f"[ERROR] Unknown `name` subject: {args.subject!r}", flush=True)
        return 1

    if args.verb == "mine":
        if args.subject == "findings":
            # Cross-source: reads IP rollup + intel-{ip,url}, writes findings-*.
            from .findings.miner import run_mine as run_mine_findings
            stats = run_mine_findings(cfg, secrets, dry_run=args.dry_run)
            print(json.dumps(stats, indent=2, default=str))
            return 0
        mod = _load_source_layer(args.source, "campaigns")
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no `campaigns` miner", flush=True)
            return 1
        try:
            stats = mod.run_mine(
                cfg, secrets,
                kind=args.kind, dry_run=args.dry_run,
                window_days=args.window_days,
            )
        except RuntimeError as exc:
            print(f"[ERROR] {exc}", flush=True)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "intel":
        from .intel.refresh import run_backfill, run_refresh
        if args.subject == "refresh":
            stats = run_refresh(cfg, secrets, dry_run=args.dry_run)
        elif args.subject == "backfill":
            stats = run_backfill(cfg, secrets, dry_run=args.dry_run)
        elif args.subject == "reapply-rules":
            from .intel.migrate import run_reapply_rules
            stats = run_reapply_rules(cfg, secrets, dry_run=args.dry_run)
        else:
            print(f"[ERROR] Unknown `intel` subject: {args.subject!r}", flush=True)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "pipeline":
        return _run_pipeline(cfg, secrets, args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
