# dshield_prism_console

Browser-based, read-only investigation console for the enriched DShield/Cowrie
indices produced by the `enrich` pipeline in the parent repository.

Search any IOC — IP, session id, command sha256, raw command text, campaign
name, cluster id, MITRE id, ASN, country code — and see it plus its first-
degree neighborhood as an interactive node-link graph. Click a node to fill the
detail panel. Double-click to expand its neighbors into the existing graph
without losing position. Click links inside the detail panel to pivot to that
IOC.

## Install

Self-contained — no dependency on the parent `enrich` package.

```bash
cd console
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

By default the console reads the parent repo's `config/default.yaml` (+
`local.yaml` override) and `.env` so it Just Works in-repo. To point it at
configs elsewhere, set `PRISM_CONFIG=/path/to/default.yaml` (or pass
`--config`) and optionally `PRISM_ENV=/path/to/.env`. The
`PRISM_*` env vars are honored as fallbacks.

Only the `elasticsearch.*` block of the YAML is required; all other keys
(llm, worker, cloud, …) are ignored. ES credentials come from `.env`
(`ES_USERNAME`/`ES_PASSWORD` or `ES_API_KEY`).

## Run

```bash
dshield_prism_console serve --open
```

Defaults to `127.0.0.1:8765`. Pass `--config config/local.yaml` if you want a
non-default config path. `--open` launches the system browser.

Healthcheck (no server needed):
```bash
dshield_prism_console healthcheck
```

## What you can search

The single search box accepts any of:

| Pattern | Resolved as |
|---|---|
| `1.2.3.4` / `2001:db8::1` | IP |
| 64 hex chars | command (by sha256) |
| 12 lowercase alnum | session id |
| integer (e.g. `42`) | cluster id (you pick command / session / ip from suggestions) |
| `T1059.003` / `TA0002` | MITRE technique / tactic |
| `AS12345` | ASN |
| 2-letter ISO country code | country |
| anything else | free-text — searches `process.command_line`, `playbook_name`, and the multi-session campaigns index |

## Architecture

* **Backend**: FastAPI + the `elasticsearch` Python client. Self-contained
  YAML + .env loader (reads the parent repo's `config/default.yaml` by
  default, but has no Python dependency on `enrich`). Strips 768-dim
  embeddings server-side; they never reach the browser.
* **Frontend**: vanilla JS + Cytoscape.js (vendored) with the fcose layout. No
  build step, no framework. Loads from `web/`.
* **State**: read-only. The console never writes to ES.

Pages:

| Path | Page |
|---|---|
| `/` | Search → graph investigation view (the default landing page) |
| `/insights` | Read-only summary dashboard: top novel commands, active campaigns, recent activity. Click any row to pivot into the graph view |

API endpoints:

```
GET  /api/health
GET  /api/search?q=...
GET  /api/ioc/{type}/{id}
GET  /api/ioc/{type}/{id}/neighbors?limit=50&require_login=&require_commands=
GET  /api/ioc/ip/{ip}/sessions
GET  /api/ioc/session/{sid}/commands
GET  /api/ioc/command/{sha}/sessions
GET  /api/cluster/{kind}/{cid}/members
GET  /api/timeline?kind=ip|session_cluster|playbook&id=...
GET  /api/insights                 # 60s server-side cache
POST /api/ask                      # natural-language Q&A backed by the parent project's LLM config
```

Where `type` ∈ `ip session command command_hash playbook campaign
command_cluster session_cluster ip_cluster asn country mitre_technique
mitre_tactic`. `playbook` is the LLM-named session cluster (anchored by
`playbook_id` = `sescl-<16hex>`, content-hashed over the member-session-id set); `campaign` is the multi-session
pattern mined by `mine campaigns` (anchored by `campaign_id` =
`cmp-bhv-…` / `cmp-inf-…`).

The `require_login` / `require_commands` filters on the neighbors and sessions tables default to `true`, so the default view only shows sessions where the attacker actually logged in **and** ran at least one command. Toggle them off in the UI (or pass `?require_login=false&require_commands=false`) to see credential-spray-only sessions.

## Files

```
console/
  pyproject.toml
  src/console/
    cli.py                  -- `dshield_prism_console serve|healthcheck`
    server.py               -- FastAPI app, routes, detail builders
    ioc.py                  -- IOC type detection from query string
    queries.py              -- ES query functions
    graph.py                -- ES rows -> Cytoscape nodes/edges
    models.py               -- pydantic response shapes
    _config.py              -- self-contained YAML + .env loader
    _es.py                  -- Elasticsearch client factory
    web/
      index.html            -- search + graph investigation view
      insights.html         -- dashboard-style overview page
      css/                  -- vanilla CSS, no framework
      js/{app.js,graph.js,insights.js,timeline.js}
      js/vendor/{cytoscape,layout-base,cose-base,cytoscape-fcose}.js
```

## Duplicated code

To keep this package free of cross-package imports, two small pieces are
deliberately duplicated from the parent `enrich` package:

| Console file | Duplicates |
|---|---|
| [`_config.py`](src/console/_config.py) | `CowrieIndexes` / `SourceIndexes` / `ESConfig` / `Secrets` models + YAML+`.env` loader from `src/enrich/config.py` |
| [`_es.py`](src/console/_es.py) | `make_client` from `src/enrich/es_client.py` |

**Drift risk**: the two copies must agree on the
`elasticsearch.indexes.cowrie.*` field shape. If a new cowrie index is added
(or one is renamed) on the parent side, mirror the change in
`console/src/console/_config.py`. Everything else (LLM config, worker
config, cloud config, …) is intentionally absent from the console copy and
can drift safely.

## Security notes

* Default bind is `127.0.0.1` — single-user workstation use.
* No auth on the local HTTP server. If exposing on a LAN, add a reverse proxy
  with auth (or extend the FastAPI app with token middleware).
* Read-only: the only ES operations are search / get / count / info.

## Known limitations

* Cluster ids are run-scoped. The console resolves the most-recent
  `run_summary` doc and filters cluster lookups by that `run_id`. If you want
  to investigate a historical run, that's a v1.x feature.
* ASN / country anchors can fan out to thousands of IPs. They're capped at
  `limit=50` in the graph by default; the related-rows table can paginate the
  rest in v1.x (current build shows the first 50 only).
* Free-text command search returns the top-25 hits by score. For more
  specific lookups, search by sha256 directly.
