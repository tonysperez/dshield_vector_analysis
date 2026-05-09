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


class WorkerConfig(BaseModel):
    state_db: str
    page_size: int = 1000
    command_max_chars: int = 4000
    prompt_version: str = "v1"
    initial_lookback_days: Optional[int] = None
    log_level: str = "INFO"


class PromptsConfig(BaseModel):
    command_enrichment: str


class AppConfig(BaseModel):
    elasticsearch: ESConfig
    llm: LLMConfig
    worker: WorkerConfig
    prompts: PromptsConfig


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
