"""Config loading. YAML file + .env overrides for secrets."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .__about__ import ENV_PREFIX

_CONFIG_ENV = f"{ENV_PREFIX}CONFIG"
_LOCAL_CONFIG_ENV = f"{ENV_PREFIX}LOCAL_CONFIG"
_ENV_FILE_ENV = f"{ENV_PREFIX}ENV"


class CowrieIndexes(BaseModel):
    """All index names for the cowrie source. One layer per field.

    Naming convention (post-2026-05-17 rename): `prism.<function>.<source>.<layer>`.
    The `prism.*` prefix isn't claimed by any Fleet integration template,
    so these indices are wholly project-owned and survive integration
    upgrades. See docs/reference.md for the full layout.
    """
    sessions_raw: str       # raw cowrie session-log events
    commands: str           # per-command enrichment docs
    command_clusters: str   # HDBSCAN centroids over commands
    sessions_rollup: str    # session-level rollup docs
    session_clusters: str   # HDBSCAN centroids over sessions ("playbooks")
    ips_rollup: str         # source-IP rollup docs
    ip_clusters: str        # HDBSCAN centroids over IPs
    # Multi-session campaign docs. Holds the output of `mine campaigns`
    # — frequent-itemset (behaviour) and connected-component (infrastructure)
    # groupings of sessions that span multiple connections. Distinct from
    # session_clusters (those are playbooks). See docs/PLAYBOOKS_AND_CAMPAIGNS.md.
    campaigns: str = "prism.campaign.cowrie"


class SourceIndexes(BaseModel):
    """Top-level container. Add a sibling model + field per new source."""
    cowrie: CowrieIndexes


class ESConfig(BaseModel):
    hosts: list[str]
    verify_certs: bool = False
    ca_certs: Optional[str] = None
    request_timeout: int = 60
    indexes: SourceIndexes


class LLMConfig(BaseModel):
    provider: str = "ollama"  # "ollama" | "openai_compat"
    base_url: str
    generation_model: str
    embedding_model: str
    request_timeout: int = 120
    max_retries: int = 2
    api_key: Optional[str] = None  # for openai_compat servers that require it
    embed_context: list[str] = Field(
        default_factory=lambda: ["intent", "tactics", "description"]
    )


class CooccurrenceConfig(BaseModel):
    """Per-command session-co-occurrence context.

    For each cache-miss command, queries ES for the sessions that ran the
    command, then aggregates the other commands run in those sessions. Top-K
    co-occurring commands are passed to the LLM (and optionally appended to
    the embed text) as context, so enrichment sees the command in the
    company it usually keeps.
    """
    enabled: bool = True
    # Sample at most this many sessions per command when computing co-occurrence.
    # Lower = faster ES query, less stable. 50 is plenty for tail commands;
    # head commands cap out anyway.
    session_sample_size: int = 50
    # Number of co-occurring commands surfaced to the LLM and embed text.
    top_k: int = 8
    # Skip co-occurrence when the command appears in fewer than this many
    # sessions — too little signal to be meaningful.
    min_sessions: int = 3
    # NOTE: `max_corpus_session_ratio` (the old binary boilerplate cutoff)
    # was removed in ROADMAP #6. The ranker now uses TF-IDF weighting —
    # corpus-common siblings demote themselves continuously. Stray YAML
    # entries are silently ignored by pydantic.
    # If true, append "co-occurs with: ..." to the embed text alongside
    # other enrichment context. Goes into embed_config_hash automatically;
    # no manual version bump required.
    embed_cooccurrence: bool = True


class CloudTriageConfig(BaseModel):
    # Anchor of "actually low confidence" — model's modal/default rating
    # was 6 on this corpus, escalating below that burnt budget on docs the
    # model was sure about. ROADMAP issue #4.
    confidence_max: int = 4
    escalate_confidence_max: int = 7
    sample_rate: float = 0.01
    base64_min_run: int = 200
    # File extensions removed (`zip`, `exe`): more often filename suffixes
    # than TLDs; the host-context anchor on _TLD_RE in triage.py rejects
    # bare-filename matches anyway. ROADMAP issue #4.
    suspicious_tlds: list[str] = Field(default_factory=lambda: [
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "club", "icu", "buzz",
        "monster", "rest", "bar", "fit", "online", "site", "stream", "cam",
    ])
    novel_embedding_threshold: float = 0.5
    # Suppress novelty-based escalation/surfacing when the local model's
    # self-rated confidence is below this floor. Confidence-1 enrichments
    # are typically encoding artifacts (raw ELF bytes, mojibake) where
    # novelty=1.0 is meaningless — see docs/ROADMAP.md issue #3.
    novel_confidence_min: int = 4
    # M3.A: intel-aware escalation gate. When True (default), the triage
    # consults each command's source-IP intel summaries before
    # dispatching to the cloud LLM. Two skip rules fire:
    #   - all source IPs have `override_applied=authoritative_clean`
    #     (e.g. all are GreyNoise-RIOT or AbuseIPDB-whitelisted) →
    #     "intel_skip_authoritative_clean"
    #   - all source IPs have malicious_provider_count >= 2 AND all
    #     existing triage_reasons are gateable (low_confidence /
    #     novel_embedding / sample, NOT base64_blob / ip_literal /
    #     rare_tld) → "intel_skip_commodity_consensus"
    # Disable to revert to the M2-and-earlier behaviour where intel
    # doesn't gate escalation. See src/enrich/triage.py
    # `intel_skip_reason` for the canonical rule. ROADMAP M3.A.
    intel_aware: bool = True


class CloudPricingConfig(BaseModel):
    input_per_mtok: float = 3.0
    output_per_mtok: float = 15.0


class CloudConfig(BaseModel):
    enabled: bool = False
    provider: str = "anthropic"
    base_url: Optional[str] = None
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 1024
    request_timeout: int = 120
    daily_budget_usd: float = 5.0
    rpm_limit: int = 10
    triage: CloudTriageConfig = Field(default_factory=CloudTriageConfig)
    pricing: CloudPricingConfig = Field(default_factory=CloudPricingConfig)


class CommandClusterConfig(BaseModel):
    min_cluster_size: int = 5
    min_samples: int = 2
    page_size: int = 1000
    batch_size: int = 200
    scalar_weight: float = 0.05


class SessionConfig(BaseModel):
    embed_version: str = "v1"
    cluster_min_cluster_size: int = 3
    # min_samples=2 avoids collapsing HDBSCAN's mutual-reachability distance
    # to raw distance (single-linkage), which can let one mega-cluster
    # swallow the bulk on a duplicate-heavy corpus. ROADMAP issue #5.
    cluster_min_samples: int = 2
    cluster_scalar_weight: float = 0.05
    page_size: int = 1000
    batch_size: int = 200
    # Max unique commands sampled per playbook (session cluster) for LLM
    # name generation.
    playbook_sample_commands: int = 15
    # Cosine-similarity threshold for merging HDBSCAN clusters into a single
    # playbook. A playbook is a *group* of one or more clusters whose
    # centroids are pairwise (single-linkage) at least this similar. 1.0
    # disables merging (1 cluster = 1 playbook, legacy behaviour). 0.96 is
    # the empirically-tuned default — see scripts/diagnose_centroid_similarity.py.
    playbook_merge_threshold: float = 0.96


class IPConfig(BaseModel):
    embed_version: str = "v1"
    cluster_min_cluster_size: int = 3
    # See SessionConfig.cluster_min_samples for rationale. ROADMAP issue #5.
    cluster_min_samples: int = 2
    # Weight on the behavior-scalar sub-block (total_sessions,
    # login_success_rate, mean_novelty, mean_session_duration_s). These
    # break ties on the embedding axis and should stay subdued — 0.05 is
    # the empirically-tuned default.
    cluster_scalar_weight: float = 0.05
    # Weight on the attribution-scalar sub-block (country one-hot, ASN
    # bucket, credential hash). Slightly hotter than behavior because
    # these are attribution signals, not noise. ROADMAP issue #8.
    cluster_attribution_weight: float = 0.10
    # ASN bucketing: top-N ASNs each get a dedicated one-hot column; all
    # other ASNs share a single pooled "other" column. Computed via a
    # corpus-wide ES terms agg at cluster time.
    attribution_top_asns: int = 50
    # Credential feature-hash dimension. Each unique (user:pass) the IP
    # tried is hashed into one of K bins (stable SHA-256-based hash); the
    # column value is that bin's share of the IP's credential set, so the
    # block sums to 1 per row. K=16 trades collisions for compactness.
    attribution_cred_hash_dim: int = 16
    page_size: int = 1000
    batch_size: int = 200


class IntelProviderConfig(BaseModel):
    """Generic per-provider toggle + key holder.

    Each provider's own config (api key, refresh cadence, etc.) lives
    in a typed sub-model below. This base just carries `enabled` so
    operators can flip a provider off without removing the block.
    """
    enabled: bool = True


class TorProviderConfig(IntelProviderConfig):
    """Tor exit-list provider — bulk file download, no API key."""
    # URL of the public exit-list file. Default is the canonical Tor
    # Project endpoint; override only when mirroring locally.
    exit_list_url: str = "https://check.torproject.org/torbulkexitlist"
    # How often to re-download the full list. The file updates hourly
    # upstream; refreshing more often wastes bandwidth.
    refresh_minutes: int = 60
    # On-disk cache path. Survives process restarts so a worker reboot
    # doesn't re-download. Stored alongside other state.
    cache_file: str = "/var/lib/dshield_prism/intel_tor_exits.txt"


class FeodoTrackerProviderConfig(IntelProviderConfig):
    """abuse.ch FeodoTracker — active malware C2 IP list. No API key.

    Replaces the previous Spamhaus DNS provider after the public-
    resolver block proved an architectural mismatch for the
    transportable / research-honeypot use case. FeodoTracker is
    HTTP-based bulk download, high-precision (active C2 only),
    sibling format to URLhaus / ThreatFox / MalwareBazaar from the
    same operator.
    """
    # Recommended endpoint — pre-filtered to currently-active C2 only.
    # `ipblocklist.json` exists too but includes historical entries.
    feed_url: str = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    refresh_minutes: int = 60
    cache_file: str = "/var/lib/dshield_prism/intel_feodotracker.json"


class FireholProviderConfig(IntelProviderConfig):
    """FireHOL Level 1 IP reputation aggregator. No API key, no auth.

    Aggregates hundreds of upstream feeds (CINS Army, DROP/EDROP,
    BinaryDefense, AlienVault, EmergingThreats compromised hosts,
    …) into a single very-low-FP block list. Level 1 is the
    strictest tier — entries the maintainers consider safe for null-
    routing at a network edge.
    """
    feed_url: str = "https://iplists.firehol.org/files/firehol_level1.netset"
    refresh_minutes: int = 360
    cache_file: str = "/var/lib/dshield_prism/intel_firehol_level1.netset"


class GreyNoiseProviderConfig(IntelProviderConfig):
    """GreyNoise Community provider — per-IP HTTP lookup.

    Free-tier limits (verified 2026-05-17): **50 lookups per week**
    on the Community plan — much tighter than the marketing
    "10k/month" suggests. Daily ceiling of 6 here gives ~42/week,
    leaving headroom for healthcheck probes plus any retries.

    The 7-day cache TTL is the other half of the throughput model:
    every artifact resolved by GreyNoise stays resolved for a week,
    so we can keep growing the corpus and the budget covers it as
    long as we resolve the 6 highest-novelty new artifacts each day.

    A separate constraint: GreyNoise rate-limits short bursts. The
    provider sleeps `min_inter_call_seconds` between calls to stay
    below the per-second cap.
    """
    base_url: str = "https://api.greynoise.io"
    # Community endpoint: GET /v3/community/<ip> → {classification, name, last_seen, ...}
    request_timeout_seconds: float = 8.0
    daily_budget: int = 6
    min_inter_call_seconds: float = 1.0
    # Cache TTL — Community endpoint data changes slowly; 7d matches
    # the weekly budget cycle. Adjust if you have a paid plan with a
    # different cadence.
    ttl_days: int = 7


class URLhausProviderConfig(IntelProviderConfig):
    """abuse.ch URLhaus — known-malicious URL list. HTTP bulk-download CSV.

    No API key; unmetered. Sibling family to FeodoTracker / ThreatFox /
    MalwareBazaar. M4 first URL-kind provider.
    """
    # `csv_online` is the actively-malicious subset; the broader
    # `csv` endpoint includes offline entries too.
    feed_url: str = "https://urlhaus.abuse.ch/downloads/csv_online/"
    refresh_minutes: int = 60
    cache_file: str = "/var/lib/dshield_prism/intel_urlhaus.csv"


class ThreatFoxProviderConfig(IntelProviderConfig):
    """abuse.ch ThreatFox — per-IOC HTTP POST API.

    Free, no API key required for low-volume usage. POSTs a search
    body per artifact; returns rich IOC metadata (malware family,
    threat type, confidence). M4 ships URL-kind handling; IP /
    domain / hash extensions are a single-line change to
    `ThreatFoxProvider.handles`.
    """
    base_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    request_timeout_seconds: float = 8.0
    # Gentle throttle — abuse.ch politely accepts steady traffic.
    min_inter_call_seconds: float = 0.5
    ttl_days: int = 3


class AbuseIPDBProviderConfig(IntelProviderConfig):
    """AbuseIPDB provider — per-IP HTTP lookup. Free tier: 1000/day."""
    base_url: str = "https://api.abuseipdb.com"
    request_timeout_seconds: float = 8.0
    daily_budget: int = 900
    min_inter_call_seconds: float = 0.0
    # AbuseIPDB lets you ask "how far back in reports to look" — 90
    # days is their max for the free tier and matches the default UI.
    max_age_days: int = 90
    ttl_days: int = 3


class ISCProviderConfig(IntelProviderConfig):
    """SANS Internet Storm Center / DShield top-attackers daily feed.

    The ISC API publishes a top-N list of attacking IPs daily. We
    download once per `refresh_minutes` and answer per-IP lookups
    from the in-memory snapshot.
    """
    # ISC API. Adjust if/when ISC publishes a research-friendly mirror.
    sources_url: str = "https://isc.sans.edu/api/sources/attacks/2000?json"
    refresh_minutes: int = 360
    cache_file: str = "/var/lib/dshield_prism/intel_isc_top.json"


class IntelProvidersConfig(BaseModel):
    """Per-provider sub-blocks. Add one field per new provider."""
    tor: TorProviderConfig = Field(default_factory=TorProviderConfig)
    feodotracker: FeodoTrackerProviderConfig = Field(default_factory=FeodoTrackerProviderConfig)
    firehol: FireholProviderConfig = Field(default_factory=FireholProviderConfig)
    isc: ISCProviderConfig = Field(default_factory=ISCProviderConfig)
    greynoise: GreyNoiseProviderConfig = Field(default_factory=GreyNoiseProviderConfig)
    abuseipdb: AbuseIPDBProviderConfig = Field(default_factory=AbuseIPDBProviderConfig)
    # M4: URL-kind providers.
    urlhaus: URLhausProviderConfig = Field(default_factory=URLhausProviderConfig)
    threatfox: ThreatFoxProviderConfig = Field(default_factory=ThreatFoxProviderConfig)


class IntelPriorityConfig(BaseModel):
    """Weights on the priority-queue scoring function.

    `priority = novelty_w * novelty + low_conf_w * (1 - conf/10)
              + centrality_w * centrality_norm
              + recency_w * recency_decay`

    Defaults follow the design decision (2026-05-16) that local
    novelty dominates — scarce free-tier budget goes to artifacts most
    likely to be discoveries. Weights need not sum to 1; the queue
    sorts on the raw score.
    """
    novelty_w: float = 0.50
    low_conf_w: float = 0.20
    centrality_w: float = 0.15
    recency_w: float = 0.15
    # Half-life of the recency term, in hours. Recent artifacts get
    # close to 1.0; week-old gets ~0.5; month-old gets ~0.07.
    recency_half_life_hours: float = 168.0


class IntelIndexes(BaseModel):
    """Project-owned intel indices. One per artifact kind.

    Only `ip` is end-to-end in milestone 1. The other names are
    pre-allocated so adding a kind later doesn't require config
    migration on existing deploys.
    """
    ip:     str = "prism.intel.ip"
    url:    str = "prism.intel.url"
    domain: str = "prism.intel.domain"
    hash:   str = "prism.intel.hash"


class IntelConfig(BaseModel):
    """External threat-intel subsystem.

    Disabled by default. Per-deploy enable + provider keys go in
    `config/local.yaml`. See ROADMAP "Research-mode strategic gaps"
    section A for the design.
    """
    enabled: bool = False
    indexes: IntelIndexes = Field(default_factory=IntelIndexes)
    providers: IntelProvidersConfig = Field(default_factory=IntelProvidersConfig)
    priority: IntelPriorityConfig = Field(default_factory=IntelPriorityConfig)
    # CIDRs the worker MUST NOT look up against external feeds. RFC1918
    # is already filtered at canonicalisation time (artifact.py); list
    # the operator's egress + research peer CIDRs here.
    never_query_cidrs: list[str] = Field(default_factory=list)
    # ES `size:` parameter for the discovery scans (IP rollup search,
    # threat.indicator nested terms agg). NOT an artifact-dispatch
    # cap — the prior global-cap semantics starved URL artifacts and
    # were removed. Provider rate enforcement belongs at the
    # *integration* level: providers with API limits (GreyNoise,
    # AbuseIPDB) set `RateLimit.daily_budget` and the worker gates on
    # `intel_provider_calls_today` per call. Unmetered bulk providers
    # (Tor / ISC / FireHOL / FeodoTracker / URLhaus) have effectively
    # zero per-artifact cost after their once-per-window bulk
    # download, so they shouldn't be capped.
    max_per_run: int = 5000


class FindingsIndexes(BaseModel):
    """Persisted findings index. M5."""
    default: str = "prism.finding"


class FindingsConfig(BaseModel):
    """Findings-mining subsystem (M5).

    The miner walks IP rollups (for `likely_discovery`) and joins
    URL ↔ host-IP intel (for `axis_disagreement`), upserting one
    finding doc per (kind, artifact_kind, artifact_value). Status
    workflow lives on each doc; the miner is careful to overwrite
    only the evidence/score/last_seen_at fields so the analyst's
    triage state survives re-mines.
    """
    enabled: bool = True
    indexes: FindingsIndexes = Field(default_factory=FindingsIndexes)
    # Likely-discovery thresholds. Both halves must clear: high local
    # novelty AND high external rarity. Defaults err on the side of a
    # short ranked list — easier to lower than to wade through noise.
    likely_discovery_novelty_min: float = 0.70
    likely_discovery_rarity_min: float = 0.50
    # Floor on local activity to avoid surfacing IPs we barely saw
    # — single-session IPs aren't candidate discoveries even when
    # both scores spike.
    likely_discovery_min_sessions: int = 3
    # Cap on how many findings of each kind the miner persists per
    # run. The console paginates; a 5000-finding backlog is rarely
    # useful and bloats the index.
    max_findings_per_kind: int = 500
    # Look-back window (days) for "recent activity" — IPs/URLs whose
    # `last_seen` is older than this are ineligible for new findings.
    # Existing finding docs keep their status; the miner just stops
    # emitting fresh ones for stale artifacts.
    window_days: int = 30


class WorkerConfig(BaseModel):
    state_db: str
    page_size: int = 1000
    command_max_chars: int = 4000
    initial_lookback_days: Optional[int] = None
    log_level: str = "INFO"
    # Directory for project-owned log files. The CLI installs a rotating
    # file handler at `<log_dir>/cli.log` when this path is writable;
    # setup.sh and destroy.sh write `<log_dir>/setup.log` and
    # `<log_dir>/destroy.log`. Set to "" or an unwritable path to disable
    # file logging entirely (the CLI keeps its stderr handler either
    # way, so systemd's journal capture is unaffected). Override per
    # run via the PRISM_LOG_DIR env var.
    log_dir: str = "/var/log/dshield_prism"
    # When True (default), the cache key includes two SHA-256 hashes over
    # the inputs that affect enrichment output (see
    # `compute_llm_config_hash` and `compute_embed_config_hash`). Edits to
    # prompts, cooccurrence config, embed_context, or embedding_model then
    # auto-invalidate stale cache rows on the appropriate side. Set to
    # False to bypass the auto-invalidation when LLM budget is tight and
    # you'd rather keep current enrichments through a config drift — you
    # can still wipe or bless the cache manually. ROADMAP issue #7.
    cache_auto_invalidate: bool = True


class PromptsConfig(BaseModel):
    command_enrichment: str
    command_deep_dive: Optional[str] = None
    playbook_name: Optional[str] = None
    # Pass-2 of `name playbooks`: re-prompts the LLM when multiple clusters
    # end up with the same pass-1 name, asking it to produce distinct
    # names that capture what makes each cluster substantively different.
    # Optional — when unset, pass 2 is skipped (collisions keep their
    # pass-1 names). ROADMAP issue #10.
    playbook_disambiguate: Optional[str] = None
    # Console-facing: plain-language explanation of why two session clusters
    # weren't merged into the same playbook. Used by the /compare endpoint
    # and the explain_cluster_pair.py CLI's --explain flag.
    cluster_pair_explanation: Optional[str] = None


class AppConfig(BaseModel):
    elasticsearch: ESConfig
    llm: LLMConfig
    worker: WorkerConfig
    prompts: PromptsConfig
    cloud: CloudConfig = Field(default_factory=CloudConfig)
    command_cluster: CommandClusterConfig = Field(default_factory=CommandClusterConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    ip: IPConfig = Field(default_factory=IPConfig)
    cooccurrence: CooccurrenceConfig = Field(default_factory=CooccurrenceConfig)
    intel: IntelConfig = Field(default_factory=IntelConfig)
    findings: FindingsConfig = Field(default_factory=FindingsConfig)


class Secrets(BaseSettings):
    """Secrets pulled from environment / .env."""
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    es_username: Optional[str] = None
    es_password: Optional[str] = None
    es_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    # Intel-subsystem provider keys (M2). Both free-tier:
    # GreyNoise Community (~10k req/month), AbuseIPDB (1000 checks/day).
    # When unset, the corresponding provider is silently skipped at
    # `intel.refresh._build_providers` construction time — no error,
    # the rest of the providers run normally.
    greynoise_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    # M4: abuse.ch unified auth key. ONE key covers URLhaus,
    # ThreatFox, FeodoTracker, and the future MalwareBazaar provider.
    # Register at https://auth.abuse.ch/. Optional: the abuse.ch
    # endpoints we use also serve unauthenticated callers at lower
    # rate limits — when this is set, the providers send the key
    # as the `Auth-Key` request header; when unset, they fall back
    # to unauthenticated requests and just hope the rate limit
    # holds.
    abuse_ch_auth_key: Optional[str] = None


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str] = None) -> AppConfig:
    """Load default.yaml, then deep-merge local.yaml override if it exists.

    Path resolution:
      1. --config / <ENV_PREFIX>CONFIG -> base file
      2. else: config/default.yaml
      3. local override: sibling file 'local.yaml' next to base
      4. or <ENV_PREFIX>LOCAL_CONFIG (absolute override path)
      (ENV_PREFIX is defined in __about__.py; currently "PRISM_")
    """
    cfg_path = path or os.environ.get(_CONFIG_ENV, "config/default.yaml")
    p = Path(cfg_path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    data = yaml.safe_load(p.read_text()) or {}

    local_env = os.environ.get(_LOCAL_CONFIG_ENV)
    if local_env:
        candidates = [Path(local_env)]
    else:
        candidates = [p.parent / "local.yaml", p.parent / "local.yml"]
    for local_path in candidates:
        if local_path.exists():
            local_data = yaml.safe_load(local_path.read_text()) or {}
            data = _deep_merge(data, local_data)
            break

    return AppConfig(**data)


def _resolve_env_file(config_path: Optional[str]) -> Optional[Path]:
    """Find the .env file. Search order:
      1. <ENV_PREFIX>ENV (explicit absolute path)
      2. Sibling of the resolved config file
      3. Parent of the config file
      4. Current working directory
    """
    explicit = os.environ.get(_ENV_FILE_ENV)
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None

    if config_path:
        cfg = Path(config_path).resolve()
        for candidate in (cfg.parent.parent / ".env", cfg.parent / ".env"):
            if candidate.exists():
                return candidate

    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        return cwd_env
    return None


def load_secrets(config_path: Optional[str] = None) -> Secrets:
    """Load ES credentials. Reads OS env first; if a .env file is locatable,
    it is layered in too (OS env wins on conflict, per pydantic-settings).
    """
    env_path = _resolve_env_file(config_path)
    if env_path is not None:
        return Secrets(_env_file=str(env_path))  # type: ignore[call-arg]
    return Secrets()


def load_prompt(cfg: AppConfig, name: str = "command_enrichment") -> str:
    path = getattr(cfg.prompts, name)
    return Path(path).read_text()


# CooccurrenceConfig fields that change the LLM prompt (affect the
# sibling block injected into the prompt). Pinned so the hash doesn't
# churn when unrelated fields are added later.
_LLM_COOC_FIELDS = ("enabled", "top_k", "session_sample_size", "min_sessions")
# CooccurrenceConfig fields that only affect the embed text, not the LLM
# prompt. `embed_cooccurrence` toggles whether siblings appear in the
# embedded representation; it doesn't change anything the LLM sees.
_EMBED_COOC_FIELDS = ("embed_cooccurrence",)
_CONFIG_HASH_LEN = 16


def _hash_prompt_files(cfg: AppConfig) -> str:
    """SHA-256 each configured prompt file's content; combine deterministically."""
    parts: list[str] = []
    prompts_dict = cfg.prompts.model_dump()
    for name in sorted(prompts_dict):
        path = prompts_dict[name]
        if not path:
            continue
        try:
            content = Path(path).read_bytes()
        except OSError:
            # Missing prompt file: fold the path into the digest so a typo
            # doesn't silently produce the same hash as a correct config.
            digest = hashlib.sha256(f"missing:{path}".encode("utf-8")).hexdigest()
        else:
            digest = hashlib.sha256(content).hexdigest()
        parts.append(f"{name}={digest}")
    return "\n".join(parts)


# Path to the command-grounding data directory (ROADMAP #11). Hashed into
# `compute_llm_config_hash` so that edits to curated descriptions or a
# refreshed tldr.json bundle automatically invalidate cached enrichments.
# Resolved relative to this module so it works regardless of cwd.
_COMMANDS_DATA_DIR = Path(__file__).parent / "data" / "commands"


def _hash_command_grounding() -> str:
    """SHA-256 over the command-grounding data directory's content.

    Walks `src/enrich/data/commands/` recursively, hashing every regular
    file's content alongside its relative path. Missing directory returns
    a fixed sentinel rather than a random digest so an unconfigured
    install doesn't churn the cache.
    """
    if not _COMMANDS_DATA_DIR.exists():
        return "missing"
    parts: list[str] = []
    for path in sorted(_COMMANDS_DATA_DIR.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(_COMMANDS_DATA_DIR).as_posix()
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = hashlib.sha256(f"unreadable:{rel}".encode("utf-8")).hexdigest()
        parts.append(f"{rel}={digest}")
    return "\n".join(parts)


def compute_llm_config_hash(cfg: AppConfig) -> str:
    """Fingerprint of the inputs that affect *LLM* enrichment output.

    Returns a 16-hex prefix of SHA-256 over:
      - LLM-affecting cooccurrence fields (sibling-context inputs).
      - SHA-256 of each configured prompt file's content.
      - SHA-256 of the command-grounding data directory's content
        (ROADMAP #11) — edits to curated descriptions or a refreshed
        tldr.json bundle change the ground-truth block injected into
        the prompt and therefore should invalidate cached enrichments.

    Used as one half of the auto-invalidating cache key (ROADMAP #7). A
    change here means the cached intent/tactics/techniques/description
    are no longer trustworthy — the next `enrich` will re-run the LLM.
    Embed-only changes (see `compute_embed_config_hash`) do NOT flip
    this; they're handled separately so `reembed` doesn't waste an LLM
    call.
    """
    cooc = cfg.cooccurrence.model_dump()
    cooc_subset = {k: cooc[k] for k in _LLM_COOC_FIELDS if k in cooc}
    cooc_payload = json.dumps(cooc_subset, sort_keys=True, separators=(",", ":"))
    prompt_payload = _hash_prompt_files(cfg)
    grounding_payload = _hash_command_grounding()
    combined = (
        f"cooc:{cooc_payload}\n"
        f"prompts:{prompt_payload}\n"
        f"grounding:{grounding_payload}"
    )
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:_CONFIG_HASH_LEN]


def compute_embed_config_hash(cfg: AppConfig) -> str:
    """Fingerprint of the inputs that affect *embedding* output.

    Returns a 16-hex prefix of SHA-256 over:
      - `llm.embed_context` (which stored fields get prepended to the
        embed text — sorted JSON so list ordering is stable).
      - `llm.embedding_model` (changing models obviously changes vectors).
      - `cooccurrence.embed_cooccurrence` (whether siblings get appended
        to the embed text — independent of whether they were fetched for
        the LLM prompt).

    Used as the other half of the auto-invalidating cache key (ROADMAP
    #7). A change here means only the embedding is stale — `reembed`
    can refresh it without re-running the LLM. `mark_embed_cached`
    updates only this hash, preserving `llm_config_hash`, so a stale
    LLM output can't be silently blessed by an embed-only refresh.
    """
    cooc = cfg.cooccurrence.model_dump()
    cooc_subset = {k: cooc[k] for k in _EMBED_COOC_FIELDS if k in cooc}
    embed_payload = json.dumps({
        "embed_context": sorted(cfg.llm.embed_context or []),
        "embedding_model": cfg.llm.embedding_model,
        "cooc": cooc_subset,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(embed_payload.encode("utf-8")).hexdigest()[:_CONFIG_HASH_LEN]
