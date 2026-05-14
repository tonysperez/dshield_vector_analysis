"""Config loading. YAML file + .env overrides for secrets."""
from __future__ import annotations

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
    """All index names for the cowrie source. One layer per field."""
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
    campaigns: str = "campaigns-dshield.cowrie-default"


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
    embed_version: str = "v1"  # bump when embed_context changes to force re-embed


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
    # Drop sibling commands whose corpus-wide session frequency exceeds this
    # ratio (0.0-1.0). Filters boilerplate like `cd /tmp`, `whoami` that
    # appear with everything.
    max_corpus_session_ratio: float = 0.40
    # If true, append "co-occurs with: ..." to the embed text alongside
    # other enrichment context. Bumps embed_version when toggled.
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
    cluster_scalar_weight: float = 0.05
    page_size: int = 1000
    batch_size: int = 200


class WorkerConfig(BaseModel):
    state_db: str
    page_size: int = 1000
    command_max_chars: int = 4000
    prompt_version: str = "v1"
    initial_lookback_days: Optional[int] = None
    log_level: str = "INFO"


class PromptsConfig(BaseModel):
    command_enrichment: str
    command_deep_dive: Optional[str] = None
    playbook_name: Optional[str] = None
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


class Secrets(BaseSettings):
    """Secrets pulled from environment / .env."""
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    es_username: Optional[str] = None
    es_password: Optional[str] = None
    es_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None


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
