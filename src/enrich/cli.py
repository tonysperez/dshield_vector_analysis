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


def _setup_log(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


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
        "commands":         "es-mappings/cowrie/commands.json",
        "command_clusters": "es-mappings/cowrie/command_clusters.json",
        "sessions":         "es-mappings/cowrie/sessions.json",
        "session_clusters": "es-mappings/cowrie/session_clusters.json",
        "ips":              "es-mappings/cowrie/ips.json",
        "ip_clusters":      "es-mappings/cowrie/ip_clusters.json",
        "campaigns":        "es-mappings/cowrie/campaigns.json",
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


def _run_pipeline(cfg, secrets, args) -> int:
    """End-to-end runner: each verb is invoked in dependency order via the
    same `run_*` entry points the individual CLI verbs call. Steps marked
    `optional=True` won't halt the chain on failure (mirrors the analytics
    systemd unit's leading `-` semantics). `--continue-on-error` extends
    that tolerance to every step.
    """
    print_args = lambda *a, **kw: print(*a, **{**kw, "flush": True})

    # ---- Optional fresh-start wipe ---------------------------------------
    if args.force:
        if not args.yes:
            try:
                resp = input(
                    "[pipeline] --force will DELETE every processed ES index "
                    f"for source {args.source!r} (commands, command_clusters, "
                    "sessions_rollup, session_clusters, ips_rollup, ip_clusters, "
                    "campaigns) and clear the SQLite cache + watermark. The raw "
                    "sessions_raw index is NOT touched.\n"
                    "Proceed? [y/N] "
                ).strip().lower()
            except EOFError:
                resp = ""
            if resp not in ("y", "yes"):
                print_args("Aborted.")
                return 1
        if args.dry_run:
            print_args("[pipeline] DRY-RUN: would wipe all processed data + SQLite state, then run every step.")
        else:
            wipe = _wipe_processed(cfg, secrets, args.source)
            print_args("[pipeline] wipe:")
            print_args(json.dumps(wipe, indent=2, default=str))

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

    steps: list[tuple[str, callable, bool]] = [
        # ingest half: raw events → enriched commands → session rollup
        ("enrich",                     lambda: cmds_mod.run_enrich(cfg, secrets, dry_run=dry, no_cloud=args.no_cloud), False),
        ("rollup sessions",            lambda: sessions_mod.run_rollup(cfg, secrets, dry_run=dry),                       False),
        # analytics half: command clustering → optional cloud escalation
        ("cluster commands",           lambda: cmds_mod.run_cluster(cfg, secrets, dry_run=dry),                           False),
        ("escalate",                   lambda: cmds_mod.run_escalate(cfg, secrets, dry_run=dry),                          True),
        # session clustering + LLM naming (playbooks = named session clusters)
        ("cluster sessions",           lambda: sessions_mod.run_cluster(cfg, secrets, dry_run=dry),                       False),
        ("name playbooks",             lambda: sessions_mod.run_name_playbooks(cfg, secrets, dry_run=dry, force=False),   True),
        # IP rollup + clustering (IP clusters are unnamed actor profiles)
        ("rollup ips",                 lambda: ips_mod.run_rollup(cfg, secrets, dry_run=dry),                             False),
        ("cluster ips",                lambda: ips_mod.run_cluster(cfg, secrets, dry_run=dry),                            False),
        # multi-session campaign mining (separate concept; programmatic names)
        ("mine campaigns",             lambda: campaigns_mod.run_mine(cfg, secrets, kind="all", dry_run=dry),             True),
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

    # budget
    sub.add_parser("budget", help="Show today's cloud-LLM spend vs daily cap")

    # reset
    p_reset = sub.add_parser(
        "reset",
        help="Clear local SQLite state (cache and/or watermark). Does NOT touch ES.",
    )
    g = p_reset.add_mutually_exclusive_group()
    g.add_argument("--cache", action="store_true", help="Clear only the enrichment cache")
    g.add_argument("--watermark", action="store_true", help="Clear only the watermark")
    g.add_argument("--all", action="store_true", help="Clear both (default)")
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

    # pipeline — run every processing stage in order, raw → fully processed.
    # Mirrors the analytics + ingest systemd units but in one verb so a
    # human can rebuild from scratch (with --force) or top up incrementally
    # (without --force). Order matters: each step's inputs come from the
    # previous step's outputs.
    p_pipe = sub.add_parser(
        "pipeline",
        help="Run the full enrichment pipeline end-to-end (enrich → rollup → cluster → name → mine)",
    )
    p_pipe.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_pipe.add_argument(
        "--force", action="store_true",
        help=(
            "Wipe all processed data first: delete every processed ES index "
            "(commands, command_clusters, sessions_rollup, session_clusters, "
            "ips_rollup, ip_clusters, campaigns), recreate them from their "
            "mappings, and clear the SQLite cache + watermark. The raw "
            "sessions_raw index is NOT touched. Requires --yes to skip the "
            "confirmation prompt."
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
        "--no-cloud", action="store_true",
        help="Pass --no-cloud through to `enrich` (skip cloud escalation paths)",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    secrets = load_secrets(args.config)
    _setup_log(cfg.worker.log_level)

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
        do_cache = args.cache or args.all or (not args.cache and not args.watermark)
        do_watermark = args.watermark or args.all or (not args.cache and not args.watermark)
        targets = []
        if do_cache:
            targets.append("cache")
        if do_watermark:
            targets.append("watermark")
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
        if do_watermark:
            result["watermark_rows_deleted"] = db.clear_watermark()
        db.close()
        print(json.dumps(result, indent=2))
        return 0

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
        stats = mod.run_reembed(cfg, secrets, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, default=str))
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
        if args.subject != "playbooks":
            print(f"[ERROR] Unknown `name` subject: {args.subject!r}", flush=True)
            return 1
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

    if args.verb == "mine":
        # `mine campaigns` is the only subject so far.
        mod = _load_source_layer(args.source, "campaigns")
        if mod is None:
            print(f"[ERROR] Source {args.source!r} has no `campaigns` miner", flush=True)
            return 1
        try:
            stats = mod.run_mine(cfg, secrets, kind=args.kind, dry_run=args.dry_run)
        except RuntimeError as exc:
            print(f"[ERROR] {exc}", flush=True)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "pipeline":
        return _run_pipeline(cfg, secrets, args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
