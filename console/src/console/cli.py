"""CLI entrypoint: `<CLI_NAME> serve` (CLI_NAME from __about__.py)."""
from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from .__about__ import CLI_NAME


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .server import build_app

    app = build_app(config_path=args.config)
    url = f"http://{args.host}:{args.port}/"
    if args.open:
        webbrowser.open(url)
    print(f"DShield console listening on {url}", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def _healthcheck(args: argparse.Namespace) -> int:
    import json

    from ._config import load_config, load_secrets
    from ._es import make_client
    from . import queries

    cfg = load_config(args.config)
    secrets = load_secrets(args.config)
    es = make_client(cfg.elasticsearch, secrets)
    try:
        h = queries.health(es, cfg)
        print(json.dumps({"ok": True, **h}, indent=2, default=str))
        return 0
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"{e.__class__.__name__}: {e}"}, indent=2))
        return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog=CLI_NAME)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="Run the web UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--config", default=None,
                   help="Path to base YAML config (default: config/default.yaml).")
    s.add_argument("--open", action="store_true",
                   help="Open the system browser at the server URL.")
    s.set_defaults(func=_serve)

    h = sub.add_parser("healthcheck", help="Ping ES through the API and exit")
    h.add_argument("--config", default=None)
    h.set_defaults(func=_healthcheck)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
