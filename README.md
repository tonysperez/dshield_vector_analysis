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
5. **Writes** the result to separate, project-owned, ECS-compliant indices that can be queried, joined back to their associated log events, and pivoted on in Kibana without risking the SO-managed pipelines.

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
| **4 - Session + IP rollups** | planned | Aggregate command embeddings into per-session and per-IP vectors; cluster IPs into "campaigns"; surface IPs that don't fit any cluster (lone-wolf or new-campaign signal) |
| **5 - Eval + monitoring** | planned | Hand-labeled regression set; weekly F1 against ground truth; structured worker logs to ES; alerts on budget / drift / failure rate |

---

## Quickstart

**First-time install** on a SecurityOnion box (after filling `.env` + `config/local.yaml`, and after standing up your LLM server per [step 1](#1-gpu-box--install-your-llm-server)):

```bash
sudo bash scripts/setup-so-node.sh
```

The script handles user creation, deploy to `/opt/dshield_vector_analysis`, venv + install, healthcheck, index creation, and systemd enablement. It's fully idempotent — safe to re-run after fixing anything. See [Automated setup](#automated-setup-script) for flags. For the manual step-by-step (or to understand what the script does), see the [Setup guide](#setup-guide--step-by-step).

**Daily / recurring use:**

```bash
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli healthcheck
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli enrich --dry-run
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli enrich
```

**Recovery / re-scan everything:**
```bash
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli reset --yes
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli enrich
```

---

## Architecture

```
+-------------------------+        +---------------------------------+
|   GPU box               |        |   SecurityOnion box             |
|   Ollama OR LM Studio   | <----- |   dshield_vector_analysis       |
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
                                   |   write: <enrichment_index>     |
                                   +---------------------------------+
```

The worker only **reads** from the SO-managed Cowrie events index. All enriched data is written to a separate, project-owned index.

---

## Repository contents

| Path | Purpose |
|---|---|
| `pyproject.toml` | Python package + dependencies (`[cluster]` extra for Phase 3) |
| `config/default.yaml` | Default worker config (committed) |
| `config/local.yaml.example` | Template for per-deploy overrides — copy to `local.yaml` (gitignored) |
| `config/prompts/command_enrichment.txt` | LLM prompt template |
| `src/dshield_vector_analysis/` | Python package: `cli`, `config`, `cache`, `es_client`, `enrich`, `cluster`, `healthcheck`, `triage`, `llm/{ollama,openai_compat,anthropic,schemas}` |
| `es-mappings/dshield-cowrie-enrichment-mapping.json` | Settings + ECS-compliant mappings for the enrichment index |
| `es-mappings/dshield-cowrie-clusters-mapping.json` | Settings + mappings for the cluster centroids index (Phase 3) |
| `systemd/dshield_vector_analysis.service` + `.timer` | Hourly oneshot service + timer |
| `scripts/setup-so-node.sh` | One-shot, idempotent SO-box installer |
| `.env.example` | Secrets template (copy to `.env`) |
| `.gitignore` | Excludes `.env`, `config/local.yaml`, `config/local.yml`, `*.sqlite`, `__pycache__` |

---

## CLI commands

All run as the service user from the install dir:

```bash
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli <subcommand>
```

| Subcommand | What it does |
|---|---|
| `healthcheck` | Verify ES + LLM server + models + SQLite + cloud. Exits non-zero on failure. |
| `healthcheck --scope <s>` | Run a subset. Comma-separated; valid: `es`, `llm`, `sqlite`, `cloud-conn`, `cloud`, or `all` (default). **Default / `all` runs the *cheap* cloud check (`cloud-conn`)** — `GET /v1/models` against Anthropic, zero generation tokens — so scripts, timers, and the setup runner can call `healthcheck` without burning budget. The full `cloud` scope (~16-token round-trip + budget readout) is **opt-in for user troubleshooting only**: `healthcheck --scope cloud`. Output is `[ok]` / `[warn]` / `[FAIL]` lines plus a summary, suitable for `ExecStartPre` gating — the systemd unit uses `--scope llm` so only a local-LLM outage blocks `enrich`. Cloud reachability is preflighted inside `enrich` itself (Anthropic `ping`); on failure the run degrades to local-only and logs a warning rather than failing. |
| `init-index` | `PUT <enrichment_index>` with explicit ECS settings + mappings. Idempotent (no-op if index exists). |
| `init-index --mapping <path>` | Use a different mapping file (e.g. the clusters mapping). Combine with `--index` to target a different index. |
| `init-index --index <name>` | Override the target index name. Used to create the clusters index: `--mapping es-mappings/dshield-cowrie-clusters-mapping.json --index enriched-dshield_cowrie_sessions-clusters-default`. |
| `init-index --update-mapping` | If index exists, push **additive** mapping changes (new fields). Cannot change existing field types. |
| `enrich` | One enrichment pass: read new events, dedup, embed, LLM-classify, bulk-write, advance watermark. |
| `enrich --dry-run` | Read + group events, print stats; skip LLM and writes. |
| `enrich --no-cloud` | Force-disable Phase 2 cloud escalation for this run, even if `cloud.enabled=true` in config. |
| `cluster` | Phase 3: pull all embeddings, run HDBSCAN, compute novelty scores, bulk-update cluster fields on every enrichment doc, write centroid docs to the clusters index. |
| `cluster --dry-run` | Fetch + cluster without writing anything to ES. Prints stats (n_clusters, n_outliers, runtime). |
| `cluster --clusters-index <name>` | Override the clusters index name (default: derived from `enrichment_index`). |
| `escalate` | Phase 3: cloud-escalate locally-enriched docs where novelty_score ≥ `novel_embedding_threshold` AND confidence ≤ `escalate_confidence_max`. Queries ES directly — no watermark, no cache — so it catches docs enriched in any previous run. Already cloud-enriched docs are never re-escalated. Run after each `cluster` pass. |
| `escalate --dry-run` | Count candidates matching both filters (novelty ≥ `novel_embedding_threshold` AND confidence ≤ `escalate_confidence_max`) without making cloud calls or writes. |
| `budget` | Print today's cloud-LLM spend, daily cap, calls, token totals (Phase 2). |
| `reset` | Clear local SQLite state. Default: cache + watermark. Flags: `--cache`, `--watermark`, `--all`, `--yes` (skip confirmation). Does NOT touch ES. |

---

## Automated setup script

`scripts/setup-so-node.sh` performs steps 2-9 of the manual guide below.

**Prerequisites** before running:
- Source folder is on the SO box (any path).
- `config/local.yaml` (or `local.yml`) is filled in.
- `.env` is filled in.
- The GPU-side LLM server (step 1) is reachable from this box.

**Run:**
```bash
sudo bash scripts/setup-so-node.sh
```

**Flags:**
| Flag | Effect |
|---|---|
| `--no-systemd` | Skip installing/enabling the timer |
| `--skip-healthcheck` | Continue past a failed healthcheck (NOT recommended) |
| `--skip-init-index` | Don't run `init-index` |
| `-h` / `--help` | Print the embedded usage block |

**Environment overrides:**
| Var | Default |
|---|---|
| `SERVICE_USER` | `dshield_vector_analysis` |
| `INSTALL_DIR` | `/opt/dshield_vector_analysis` |
| `STATE_DIR` | `/var/lib/dshield_vector_analysis` |
| `SYSTEMD_DIR` | `/etc/systemd/system` |
| `PYTHON_BIN` | `python3` |

The script is idempotent — re-run it after editing config or fixing healthcheck failures.

The first enrichment run is **not** triggered by the script (it can take hours on a backlog). Run it manually:
```bash
sudo -u dshield_vector_analysis /opt/dshield_vector_analysis/.venv/bin/python \
    -m dshield_vector_analysis.cli enrich --dry-run
sudo -u dshield_vector_analysis /opt/dshield_vector_analysis/.venv/bin/python \
    -m dshield_vector_analysis.cli enrich
```

---

## Setup guide — step by step

### 0. Prerequisites

- A GPU box reachable from the SecurityOnion (SO) box on the LLM server's port.
- SecurityOnion 2.x box with shell access.
- Python 3.11+ on the SO box.
- An Elasticsearch user with `read` on the Cowrie events index pattern, and `manage` / `read` / `write` on `<enrichment_index>*`.
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
sudo useradd --system --home /opt/dshield_vector_analysis --shell /usr/sbin/nologin dshield_vector_analysis
sudo mkdir -p /opt/dshield_vector_analysis /var/lib/dshield_vector_analysis
sudo chown -R dshield_vector_analysis:dshield_vector_analysis /opt/dshield_vector_analysis /var/lib/dshield_vector_analysis
```

### 3. SO box — deploy this folder

Clone this repo to your SecurityOnion node, to /opt/dshield_vector_analysis

### 4. SO box — Python venv + install

```bash
cd /opt/dshield_vector_analysis
sudo -u dshield_vector_analysis python3 -m venv .venv
sudo -u dshield_vector_analysis .venv/bin/pip install --upgrade pip
sudo -u dshield_vector_analysis .venv/bin/pip install -e .
```

### 5. SO box — configure

All per-deploy values (LLM URL, ES hosts, index names, paths) live in `config/local.yaml` (gitignored). `config/default.yaml` ships safe defaults; `local.yaml` overrides on top via deep-merge. The loader also accepts `local.yml`. Secrets live in `.env`.

```bash
cd /opt/dshield_vector_analysis
sudo -u dshield_vector_analysis cp config/local.yaml.example config/local.yaml
sudo -u dshield_vector_analysis cp .env.example              .env

# At minimum set: llm.{provider,base_url}, elasticsearch.events_index
sudo -u dshield_vector_analysis $EDITOR config/local.yaml

# Set ES credentials (ES_USERNAME/ES_PASSWORD or ES_API_KEY)
sudo -u dshield_vector_analysis $EDITOR .env
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
> Use the pattern that returns `count > 0`. Common values: `logs-dshield_cowrie_sessions-default` or `logs-dshield.cowrie.session-*`.

### 6. SO box — create the enrichment index

The CLI does a plain `PUT <index>` with explicit ECS settings + mappings from `es-mappings/dshield-cowrie-enrichment-mapping.json`. The index name comes from `elasticsearch.enrichment_index` in your config.

```bash
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli init-index
# -> {"index_created": "<name>", "action": "created"}
# Re-running is idempotent: -> {"index_exists": "<name>", "action": "noop"}
```

For destructive mapping changes (changing field types — e.g. `confidence` float→byte), delete and recreate:
```bash
curl -k -u admin:PWD -X DELETE 'https://localhost:9200/<INDEX_NAME>'
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli init-index
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli reset --yes
```

Manual / curl alternative for `init-index`:
```bash
curl -k -u admin:PWD \
  -X PUT 'https://localhost:9200/<INDEX_NAME>' \
  -H 'Content-Type: application/json' \
  --data-binary @es-mappings/dshield-cowrie-enrichment-mapping.json
```

### 7. SO box — healthcheck

```bash
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli healthcheck
```

Expected (all `[ok]`):
```
[ok] ES 8.x.y at https://localhost:9200
[ok] enrichment index exists: <your enrichment_index>
[ok] events index '<your events_index pattern>' has N docs
[ok] LLM (openai_compat) at http://GPU_IP:PORT
[ok] model present: <generation_model>
[ok] model present: <embedding_model>
[ok] embedding works (dim=768)
[ok] SQLite writable at /var/lib/dshield_vector_analysis/state.sqlite, watermark=None
All checks OK
```

If `[FAIL] embedding dim X != 768`: pick a 768-dim embedding model OR change `dense_vector.dims` in `es-mappings/dshield-cowrie-enrichment-mapping.json` and recreate the index. Fix all failures before continuing.

### 8. First manual run (dry-run + real)

```bash
# Dry-run: read events, compute hashes, but skip LLM + writes
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli enrich --dry-run

# Real run — backfills all historical command events
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli enrich
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
sudo cp /opt/dshield_vector_analysis/systemd/dshield_vector_analysis.service /etc/systemd/system/
sudo cp /opt/dshield_vector_analysis/systemd/dshield_vector_analysis.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dshield_vector_analysis.timer

# Verify
systemctl list-timers dshield_vector_analysis.timer
journalctl -u dshield_vector_analysis.service -n 200 --no-pager
```

### 10. Quick Kibana sanity

In Kibana, add an index pattern matching your `enrichment_index` (default `enriched-dshield_cowrie_sessions-default*`, time field `@timestamp`).

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
3. **Push the additive mapping** so `triage_reasons`, `notes`, and `local_fallback.*` exist on the index:
   ```bash
   sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli init-index --update-mapping
   ```
4. **Bump `prompt_version`** (default already `v3`) and `reset --cache --yes` if you want previously-cached commands re-evaluated through the new triage path.
5. **Healthcheck** — confirms Anthropic reachability + budget:
   ```bash
   sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli healthcheck
   ```
6. **Run** as normal. After a pass, `enrich` returns extra stats: `triaged`, `cloud_calls`, `cloud_input_tokens`, `cloud_output_tokens`, `cloud_cost_usd`, `cloud_skipped_budget`. Daily spend is also queryable via:
   ```bash
   sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli budget
   ```

**Triage rules** (any rule fires → escalate; recorded in `dshield.cowrie.enrichment.triage_reasons`):

| Rule code | When it fires |
|---|---|
| `low_confidence<=N` | Local model's `confidence` is at or below `cloud.triage.confidence_max` |
| `local_failed` | Local LLM returned invalid JSON twice |
| `base64_blob` | Command contains a base64-ish run ≥ `cloud.triage.base64_min_run` chars |
| `ip_literal` | An IPv4 literal appears in the command |
| `rare_tld` | A domain in the command uses a TLD listed in `cloud.triage.suspicious_tlds` |
| `novel_embedding` | Phase 3: command's novelty score (distance to nearest cluster centroid) is ≥ `cloud.triage.novel_embedding_threshold` (default `0.5`). Only fires after Phase 3 has written centroids to the clusters index |
| `sample` | Random `cloud.triage.sample_rate` fraction (default 1%) — quality monitoring |
| `budget_exhausted` | Triage wanted to escalate but daily cap was already hit; no cloud call made |
| `cloud_parse_failed` | Cloud was called but returned unparseable JSON; doc keeps local fields |

**Cost control:** every cloud call's input + output tokens are converted to USD via `cloud.pricing.{input,output}_per_mtok` and tallied per UTC day in SQLite. Once the day's spend ≥ `cloud.daily_budget_usd`, further escalations are skipped (the doc still gets the local-only enrichment, with `triage_reasons: ["…", "budget_exhausted"]`). Update `pricing` if you change models — the defaults track Claude Sonnet 4.6 and may not match your model.

**Cache semantics:** a successful local-only enrichment is cached with key `(short_hash, generation_model, prompt_version)`. A cloud rewrite of that same hash is also cached (under the same key — `prompt_version` covers both prompts together; bump it when either prompt changes). `local_failed` results without a cloud rescue stay uncached so they retry next run.

---

## Phase 3 — clustering and novelty scoring

Phase 1 and 2 must already be running and producing docs with embeddings. Phase 3 is a separate, stateless job — it reads the enrichment index, clusters all embeddings with HDBSCAN, then writes novelty scores back. Run it periodically (every 6 hours is plenty at this volume).

### 1. Install cluster deps

```bash
sudo -u dshield_vector_analysis .venv/bin/pip install -e ".[cluster]"
```

This installs `numpy` and `scikit-learn` (which bundles HDBSCAN since 1.3). No Cython or compiler needed — both ship as pre-built wheels. No other changes required — the cluster deps are isolated to the `[cluster]` extra.

### 2. Create the clusters index

```bash
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli \
    init-index \
    --mapping es-mappings/dshield-cowrie-clusters-mapping.json \
    --index enriched-dshield_cowrie_sessions-clusters-default
```

Idempotent — safe to re-run. The clusters index stores one centroid doc per cluster per run plus a run-summary doc. Multiple runs accumulate; the `cluster` worker always queries the latest run's centroids.

### 3. Dry-run to verify

```bash
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli cluster --dry-run
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

If `docs_fetched` is 0, Phase 1 hasn't written any docs yet or `enrichment_index` is misconfigured.

### 4. Run for real

```bash
sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli cluster
```

Stats include `docs_updated`, `cluster_docs_written`, and `runtime_seconds`. After a successful run, every enrichment doc has its `dshield.cowrie.enrichment.cluster.*` fields populated.

### 5. Schedule it

Add a cron job (or systemd timer) to run `cluster` followed by `escalate` every 6 hours. The two commands are intentionally separate: `cluster` updates novelty scores for all docs; `escalate` then re-triages any locally-enriched doc whose score now exceeds the threshold.

Example cron (as root, after deploying):
```
0 */6 * * * dshield_vector_analysis /opt/dshield_vector_analysis/.venv/bin/python -m dshield_vector_analysis.cli cluster >> /var/log/dshield_cluster.log 2>&1
5 */6 * * * dshield_vector_analysis /opt/dshield_vector_analysis/.venv/bin/python -m dshield_vector_analysis.cli escalate >> /var/log/dshield_cluster.log 2>&1
```

`escalate` is safe to re-run: it only queries for `event.provider: "local"` docs, so already cloud-escalated docs are never re-processed. If the daily budget is exhausted mid-run, it stops cleanly and picks up from the most novel remaining candidates next time.

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

Once Phase 3 has written centroids, the `novel_embedding` triage rule activates automatically in subsequent `enrich` runs (Phase 2 must be enabled). The `enrich` worker loads the latest centroid set from the clusters index at startup and computes each command's cosine distance to its nearest centroid. Commands whose novelty score is ≥ `cloud.triage.novel_embedding_threshold` (default `0.5`) are escalated to Claude.

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

### Pivoting between events and enrichment

Both indices share `process.command_line`. To find an enrichment for a given event:
- Hash the normalized command (sha256, first 16 hex chars) and `GET <enrichment_index>/_doc/<short-hash>`, or
- Filter on `process.command_line.keyword` in either index.

Note: Kibana's `_score` field is the ES query relevance score (only meaningful for `match`/`multi_match` queries). It is NOT a stored severity score. Use `dshield.cowrie.enrichment.confidence` for quick confidence filtering and `dshield.cowrie.enrichment.cluster.novelty_score` for novelty (after Phase 3 has run).

---

## Operational notes

- **Cache key** = `(short_command_hash, generation_model, prompt_version)`. Bump `worker.prompt_version` in `config/local.yaml` to force re-enrichment after prompt edits.
- **Watermark** lives in SQLite (`/var/lib/dshield_vector_analysis/state.sqlite`). Loss of cache only costs LLM time, not data.
- **Failure handling**: failed enrichments (`event.provider: "local_failed"`) are written to ES with empty fields but are **not cached**, so they will be retried whenever the same command appears again.
- **Long commands** are truncated to 4000 chars before hashing; `dshield.cowrie.enrichment.command_truncated: true` is set on the doc.
- **GPU OOM**: the worker calls one generation + one embedding sequentially. If you stack other workloads on the same GPU, expect failures. Cap generation context with the `options` dict in `llm/ollama.py` or `llm/openai_compat.py` if needed.
- **Phase 3 cluster deps** (`numpy`, `scikit-learn`) are an optional extra — `pip install -e ".[cluster]"`. Both ship as pre-built wheels; no Cython or compiler needed. The base package (`pip install -e .`) does not pull them in, so Phase 1/2 work on any SO box without the heavy ML deps.
- **Re-enrich / re-scan from scratch**:
  ```bash
  sudo -u dshield_vector_analysis .venv/bin/python -m dshield_vector_analysis.cli reset --yes
  ```
- **Index management**: SO 2.x manages its own indices but does NOT touch the enrichment index. Add an ILM policy if you want rollover/retention; not required for Phase 1 volumes (likely <1GB/year).
- **Provider switch**: changing `llm.provider` mid-stream is fine — but bump `prompt_version` so cached results from the old provider get re-run if you want consistency.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `[FAIL] elasticsearch: AuthenticationException` | Wrong creds in `.env`, or user lacks index permissions |
| `[FAIL] llm: ConnectError` / timeout | Firewall on GPU box, server not bound on `0.0.0.0`, wrong port |
| `[FAIL] model missing on server` | Pull/load the model on the LLM server (Ollama: `ollama pull <name>`; LM Studio: load it in the UI) |
| `[FAIL] embedding dim X != 768` | Embed model is not 768-dim. Pick `nomic-embed-text` (768) or change `dense_vector.dims` in `es-mappings/...json` and recreate the index |
| `events_index ... has 0 docs` | Wrong index pattern; find it via Kibana Dev Tools `GET _cat/indices/*cowrie*?v&s=index` |
| `enriched_failed` high | LLM returning malformed JSON. Check raw output in journal logs; tune the prompt or move to a stronger model |
| `chat 400: 'response_format.type' must be 'json_schema' or 'text'` | LM Studio rejects `json_object`. Already handled by passing the Pydantic schema as `json_schema` — make sure you are on the latest code |
| `dense_vector` mapping conflict on first write | Index was auto-created by a write before `init-index` ran. Delete the index and re-run `init-index` |
| Worker hangs on first run | Generation slow on cold model. Check `journalctl -fu dshield_vector_analysis.service`; service has `TimeoutStartSec=2h` |

---
