"""Self-contained config loader for the console.

Reads the same `config/default.yaml` (+ `local.yaml` override) and `.env` files
that the parent `enrich` pipeline uses, but only requires the
`elasticsearch.*` block. All other top-level keys (llm, worker, cloud, …) are
ignored, so the console can be installed and run independently of the
pipeline.

DUPLICATION NOTICE
==================
The following are deliberately duplicated from `src/enrich/config.py`
to keep this package free of cross-package imports:

    - CowrieIndexes, SourceIndexes, ESConfig pydantic models
    - Secrets (subset — only the ES credential fields)
    - _deep_merge()
    - YAML + local-override load logic
    - .env file resolution logic

If you rename a field on `CowrieIndexes` in the parent package (e.g. add a new
index), mirror the change here. The two copies must agree on the
`elasticsearch.indexes.cowrie.*` shape; everything else can drift safely.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from .__about__ import ENV_PREFIX


class CowrieIndexes(BaseModel):
    sessions_raw: str
    commands: str
    command_clusters: str
    sessions_rollup: str
    session_clusters: str       # playbook centroids (named session clusters)
    ips_rollup: str
    ip_clusters: str
    # Multi-session campaigns mined by `dshield_prism mine campaigns`.
    # Default value here means the console will fall back to a sensible
    # name if the user's local.yaml hasn't been re-merged from default.yaml.
    campaigns: str = "prism.campaign.cowrie"


class SourceIndexes(BaseModel):
    cowrie: CowrieIndexes


class ESConfig(BaseModel):
    hosts: list[str]
    verify_certs: bool = False
    ca_certs: Optional[str] = None
    request_timeout: int = 60
    indexes: SourceIndexes


class LLMConfig(BaseModel):
    provider: str = "openai_compat"
    base_url: str
    generation_model: str
    api_key: Optional[str] = None
    request_timeout: int = 600


class IntelIndexes(BaseModel):
    """Mirror of the parent IntelIndexes. Drift-tolerant: any of these
    is optional, so older deploys without an `intel:` block in their
    config still load. The console treats missing indices as "intel
    not deployed yet" and degrades gracefully on the artifact pane.
    """
    ip:     str = "prism.intel.ip"
    url:    str = "prism.intel.url"
    domain: str = "prism.intel.domain"
    hash:   str = "prism.intel.hash"


class IntelConfig(BaseModel):
    enabled: bool = False
    indexes: IntelIndexes = IntelIndexes()


class FindingsIndexes(BaseModel):
    """Mirror of the parent FindingsIndexes (M5)."""
    default: str = "prism.finding"


class FindingsConfig(BaseModel):
    """Minimal mirror — the console only needs to know the index name
    and whether the feature is enabled. Thresholds live on the miner."""
    enabled: bool = True
    indexes: FindingsIndexes = FindingsIndexes()


class AppConfig(BaseModel):
    """Slimmed-down config — only what the console needs."""
    elasticsearch: ESConfig
    llm: Optional[LLMConfig] = None
    intel: IntelConfig = IntelConfig()
    findings: FindingsConfig = FindingsConfig()


class Secrets(BaseSettings):
    """ES credentials from environment / .env."""
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


def _default_config_path() -> str:
    """Default search:
      $<ENV_PREFIX>CONFIG, ./config/default.yaml,
      ../config/default.yaml (when the console is run from inside console/).
    """
    v = os.environ.get(f"{ENV_PREFIX}CONFIG")
    if v:
        return v
    for cand in ("config/default.yaml", "../config/default.yaml"):
        if Path(cand).exists():
            return cand
    return "config/default.yaml"


def load_config(path: Optional[str] = None) -> AppConfig:
    cfg_path = path or _default_config_path()
    p = Path(cfg_path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    data = yaml.safe_load(p.read_text()) or {}

    local_env = os.environ.get(f"{ENV_PREFIX}LOCAL_CONFIG")
    if local_env:
        candidates = [Path(local_env)]
    else:
        candidates = [p.parent / "local.yaml", p.parent / "local.yml"]
    for local_path in candidates:
        if local_path.exists():
            local_data = yaml.safe_load(local_path.read_text()) or {}
            data = _deep_merge(data, local_data)
            break

    raw_llm = data.get("llm")
    raw_intel = data.get("intel") or {}
    raw_findings = data.get("findings") or {}
    return AppConfig(
        elasticsearch=data["elasticsearch"],
        llm=LLMConfig(**raw_llm) if raw_llm else None,
        intel=IntelConfig(**raw_intel),
        findings=FindingsConfig(**raw_findings),
    )


def _resolve_env_file(config_path: Optional[str]) -> Optional[Path]:
    explicit = os.environ.get(f"{ENV_PREFIX}ENV")
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
    env_path = _resolve_env_file(config_path or _default_config_path())
    if env_path is not None:
        return Secrets(_env_file=str(env_path))  # type: ignore[call-arg]
    return Secrets()
