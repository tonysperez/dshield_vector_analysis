"""LLM client factory."""
from __future__ import annotations

from typing import Protocol


class LLMClient(Protocol):
    gen_model: str
    embed_model: str

    def generate_json(
        self,
        prompt: str,
        *,
        options: dict | None = None,
        schema: dict | None = None,
        schema_name: str | None = None,
    ) -> str: ...
    def generate_text(self, prompt: str, *, max_tokens: int = 16) -> str: ...
    def embed(self, text: str) -> list[float]: ...
    def health(self) -> dict: ...
    def close(self) -> None: ...
    def __enter__(self) -> "LLMClient": ...
    def __exit__(self, *exc) -> None: ...


def make_llm_client(cfg) -> LLMClient:
    """cfg is an LLMConfig. Returns the concrete client per cfg.provider."""
    provider = (cfg.provider or "ollama").lower()
    if provider == "ollama":
        from .ollama import OllamaClient
        return OllamaClient(
            base_url=cfg.base_url,
            generation_model=cfg.generation_model,
            embedding_model=cfg.embedding_model,
            timeout=cfg.request_timeout,
        )
    if provider in ("openai_compat", "openai-compat", "lmstudio", "lm_studio"):
        from .openai_compat import OpenAICompatClient
        return OpenAICompatClient(
            base_url=cfg.base_url,
            generation_model=cfg.generation_model,
            embedding_model=cfg.embedding_model,
            timeout=cfg.request_timeout,
            api_key=cfg.api_key,
        )
    raise ValueError(f"Unknown llm.provider: {provider!r}")
