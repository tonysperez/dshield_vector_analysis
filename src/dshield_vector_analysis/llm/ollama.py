"""Ollama HTTP client. Generation (JSON-mode) + embeddings."""
from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

log = logging.getLogger(__name__)


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(
        self,
        base_url: str,
        generation_model: str,
        embedding_model: str,
        timeout: int = 120,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.gen_model = generation_model
        self.embed_model = embedding_model
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def health(self) -> dict:
        """Return list of locally available models."""
        r = self._client.get(f"{self.base_url}/api/tags")
        r.raise_for_status()
        return r.json()

    def generate_json(
        self,
        prompt: str,
        *,
        options: Optional[dict] = None,
        schema: Optional[dict] = None,
        schema_name: Optional[str] = None,  # accepted for interface parity; unused
    ) -> str:
        """Call /api/generate with format=json (or schema if provided).

        Ollama supports format='json' (loose) or format=<JSON Schema dict> (strict, v0.5+).
        """
        payload = {
            "model": self.gen_model,
            "prompt": prompt,
            "format": schema if schema is not None else "json",
            "stream": False,
            "options": options or {"temperature": 0.1, "num_ctx": 4096},
        }
        r = self._client.post(f"{self.base_url}/api/generate", json=payload)
        if r.status_code != 200:
            raise OllamaError(f"generate {r.status_code}: {r.text[:300]}")
        data = r.json()
        return data.get("response", "")

    def embed(self, text: str) -> list[float]:
        """Call /api/embeddings. Returns vector."""
        payload = {"model": self.embed_model, "prompt": text}
        r = self._client.post(f"{self.base_url}/api/embeddings", json=payload)
        if r.status_code != 200:
            raise OllamaError(f"embed {r.status_code}: {r.text[:300]}")
        data = r.json()
        emb = data.get("embedding")
        if not emb or not isinstance(emb, list):
            raise OllamaError(f"embed: empty/invalid embedding in response")
        return emb
