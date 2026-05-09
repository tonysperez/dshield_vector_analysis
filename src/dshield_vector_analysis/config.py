"""Config loading. YAML file + .env overrides for secrets."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ESConfig(BaseModel):
    hosts: list[str]
    verify_certs: bool = False
    ca_certs: Optional[str] = None
    events_index: str
    enrichment_index: str
    request_timeout: int = 60


class LLMConfig(BaseModel):
    provider: str = "ollama"  # "ollama" | "openai_compat"
    base_url: str
    generation_model: str
    embedding_model: str
    request_timeout: int = 120
    max_retries: int = 2
    api_key: Optional[str] = None  # for openai_compat servers that require it


class CloudTriageConfig(BaseModel):
    confidence_max: int = 5  # escalate (during enrich) if local confidence <= this (1-10)
    escalate_confidence_max: int = 7  # escalate (via `escalate` cmd) if novelty high AND confidence <= this
    sample_rate: float = 0.01  # random sample fraction for monitoring
    base64_min_run: int = 200  # length threshold for suspicious base64 blob
    suspicious_tlds: list[str] = Field(default_factory=lambda: [
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "club", "icu", "buzz",
        "monster", "rest", "bar", "fit", "online", "site", "stream", "cam",
    ])
    novel_embedding_threshold: float = 0.5  # fire novel_embedding if novelty_score >= this


class CloudPricingConfig(BaseModel):
    """USD per 1M tokens. Override in local.yaml to match the model picked."""
    input_per_mtok: float = 3.0
    output_per_mtok: float = 15.0


class CloudConfig(BaseModel):
    enabled: bool = False
    provider: str = "anthropic"
    base_url: Optional[str] = None  # default Anthropic API
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 1024
    request_timeout: int = 120
    daily_budget_usd: float = 5.0
    rpm_limit: int = 10
    triage: CloudTriageConfig = Field(default_factory=CloudTriageConfig)
    pricing: CloudPricingConfig = Field(default_factory=CloudPricingConfig)


class ClusterConfig(BaseModel):
    min_cluster_size: int = 5
    min_samples: int = 2
    page_size: int = 1000
    batch_size: int = 200  # docs per bulk-update flush
    clusters_index: Optional[str] = None  # null = derive from enrichment_index


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


class AppConfig(BaseModel):
    elasticsearch: ESConfig
    llm: LLMConfig
    worker: WorkerConfig
    prompts: PromptsConfig
    cloud: CloudConfig = Field(default_factory=CloudConfig)
    cluster: ClusterConfig = Field(default_factory=ClusterConfig)


class Secrets(BaseSettings):
    """Secrets pulled from environment / .env.

    Use `load_secrets()` to construct — it resolves the .env path explicitly
    instead of relying on the process CWD.
    """
    # env_file=None here; load_secrets() injects the resolved path at instantiation.
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
      1. --config / DSHIELD_VECTOR_ANALYSIS_CONFIG -> base file
      2. else: config/default.yaml
      3. local override: sibling file 'local.yaml' next to base
      4. or DSHIELD_VECTOR_ANALYSIS_LOCAL_CONFIG (absolute override path)
    """
    cfg_path = path or os.environ.get("DSHIELD_VECTOR_ANALYSIS_CONFIG", "config/default.yaml")
    p = Path(cfg_path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    data = yaml.safe_load(p.read_text()) or {}

    local_env = os.environ.get("DSHIELD_VECTOR_ANALYSIS_LOCAL_CONFIG")
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
      1. DSHIELD_VECTOR_ANALYSIS_ENV (explicit absolute path)
      2. Sibling of the resolved config file (e.g. <repo>/.env when config is <repo>/config/default.yaml)
      3. Parent of the config file (covers the same case as above)
      4. Current working directory
    """
    explicit = os.environ.get("DSHIELD_VECTOR_ANALYSIS_ENV")
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None

    if config_path:
        cfg = Path(config_path).resolve()
        # config/default.yaml -> ../  (project root)
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
