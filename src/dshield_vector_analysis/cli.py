"""CLI entry points."""
from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import load_config, load_secrets
from . import enrich as enrich_mod
from . import healthcheck as hc_mod


def _setup_log(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dshield_vector_analysis")
    p.add_argument("--config", default=None, help="Path to YAML config")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_hc = sub.add_parser("healthcheck", help="Verify ES/LLM/SQLite/cloud connectivity")
    p_hc.add_argument(
        "--scope",
        default="all",
        help=(
            "Comma-separated subset of scopes to run: "
            f"{','.join(hc_mod.VALID_SCOPES)} (or 'all'). "
            "Example: --scope llm,cloud (used by systemd ExecStartPre to gate enrich)."
        ),
    )

    p_enrich = sub.add_parser("enrich", help="Run a single enrichment pass")
    p_enrich.add_argument("--dry-run", action="store_true", help="Read events but skip LLM + writes")
    p_enrich.add_argument("--no-cloud", action="store_true", help="Force-disable Phase 2 cloud escalation for this run")

    sub.add_parser("budget", help="Show today's cloud-LLM spend vs daily cap")

    p_reset = sub.add_parser(
        "reset",
        help="Clear local SQLite state (enrichment cache and/or watermark). Does NOT touch ES.",
    )
    g = p_reset.add_mutually_exclusive_group()
    g.add_argument("--cache", action="store_true", help="Clear only the enrichment cache")
    g.add_argument("--watermark", action="store_true", help="Clear only the watermark")
    g.add_argument("--all", action="store_true", help="Clear both cache and watermark (default)")
    p_reset.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    p_init = sub.add_parser(
        "init-index",
        help="Create the enrichment index using the configured name + mapping JSON",
    )
    p_init.add_argument(
        "--mapping",
        default="es-mappings/dshield-cowrie-enrichment-mapping.json",
        help="Path to mapping JSON",
    )
    p_init.add_argument(
        "--update-mapping",
        action="store_true",
        help="If index exists, push additive mapping changes instead of noop",
    )

    args = p.parse_args(argv)

    cfg = load_config(args.config)
    secrets = load_secrets(args.config)
    _setup_log(cfg.worker.log_level)

    if args.cmd == "healthcheck":
        raw = (args.scope or "all").strip().lower()
        scopes = None if raw == "all" else [s.strip() for s in raw.split(",") if s.strip()]
        return hc_mod.check(cfg, secrets, scopes=scopes)
    if args.cmd == "enrich":
        stats = enrich_mod.run(cfg, secrets, dry_run=args.dry_run, no_cloud=args.no_cloud)
        print(json.dumps(stats, indent=2, default=str))
        return 0
    if args.cmd == "budget":
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
    if args.cmd == "reset":
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

    if args.cmd == "init-index":
        from .es_client import init_index, make_client, update_mapping
        es = make_client(cfg.elasticsearch, secrets)
        idx = cfg.elasticsearch.enrichment_index
        result = init_index(es, args.mapping, idx)
        if args.update_mapping and result.get("action") == "noop":
            result = update_mapping(es, args.mapping, idx)
        print(json.dumps(result, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
