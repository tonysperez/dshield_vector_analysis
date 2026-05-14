"""Anthropic Claude client for Phase 2 cloud escalation.

Implements only the generation half of the LLMClient surface — embeddings stay
local. Returns the raw model text plus token usage so the caller can compute
USD cost against the configured pricing table.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

log = logging.getLogger(__name__)


class CloudLLMError(RuntimeError):
    pass


class AnthropicClient:
    """Minimal Anthropic Messages API client.

    Uses raw httpx to avoid pinning the anthropic SDK version. Endpoint:
    POST {base_url}/v1/messages with x-api-key header.
    """

    DEFAULT_BASE_URL = "https://api.anthropic.com"
    API_VERSION = "2023-06-01"

    def __init__(
        self,
        api_key: str,
        model: str,
        max_tokens: int = 1024,
        timeout: int = 120,
        base_url: Optional[str] = None,
    ) -> None:
        if not api_key:
            raise CloudLLMError("anthropic_api_key not set")
        self.gen_model = model
        self.embed_model = ""  # not supported here
        self.max_tokens = max_tokens
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._client = httpx.Client(
            timeout=timeout,
            headers={
                "x-api-key": api_key,
                "anthropic-version": self.API_VERSION,
                "Content-Type": "application/json",
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def health(self) -> dict:
        # Cheapest possible smoke test: a 1-token completion.
        r = self._client.post(
            f"{self.base_url}/v1/messages",
            json={
                "model": self.gen_model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
        if r.status_code != 200:
            raise CloudLLMError(f"anthropic health {r.status_code}: {r.text[:300]}")
        return r.json()

    def ping(self) -> dict:
        """Connectivity + auth check without invoking a model.

        GET /v1/models validates DNS, TLS, TCP, and x-api-key in one call —
        zero generation tokens. Used by the systemd ExecStartPre gate so the
        hourly enrich doesn't try to start when the key is rotated/expired.
        """
        r = self._client.get(f"{self.base_url}/v1/models")
        if r.status_code == 401:
            raise CloudLLMError(f"anthropic ping 401: bad/expired x-api-key ({r.text[:200]})")
        if r.status_code != 200:
            raise CloudLLMError(f"anthropic ping {r.status_code}: {r.text[:300]}")
        return r.json()

    def generate_with_usage(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> tuple[str, int, int]:
        """Returns (text, input_tokens, output_tokens)."""
        payload: dict = {
            "model": self.gen_model,
            "max_tokens": max_tokens or self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        r = self._client.post(f"{self.base_url}/v1/messages", json=payload)
        if r.status_code != 200:
            raise CloudLLMError(f"anthropic {r.status_code}: {r.text[:300]}")
        data = r.json()
        try:
            blocks = data["content"]
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            usage = data.get("usage") or {}
            in_tok = int(usage.get("input_tokens", 0))
            out_tok = int(usage.get("output_tokens", 0))
        except (KeyError, TypeError) as e:
            raise CloudLLMError(f"anthropic: malformed response: {e}; body={str(data)[:300]}")
        return text, in_tok, out_tok

    def generate_json(
        self,
        prompt: str,
        *,
        options: Optional[dict] = None,
        schema: Optional[dict] = None,
        schema_name: str = "structured_output",
    ) -> str:
        """LLMClient-compatible signature. Schema is advisory — Claude follows
        the prompt's JSON instructions reliably without needing tool-use.
        """
        text, _, _ = self.generate_with_usage(prompt)
        return _strip_code_fences(text)

    def generate_text(self, prompt: str, *, max_tokens: int = 16) -> str:
        text, _, _ = self.generate_with_usage(prompt, max_tokens=max_tokens)
        return text

    def embed(self, text: str) -> list[float]:
        raise CloudLLMError("anthropic client does not support embeddings; use the local LLM")


def _strip_code_fences(s: str) -> str:
    """Claude sometimes wraps JSON in ```json ... ``` despite instructions. Strip it."""
    s = s.strip()
    if s.startswith("```"):
        # drop opening fence (and optional language tag)
        nl = s.find("\n")
        if nl != -1:
            s = s[nl + 1 :]
        if s.endswith("```"):
            s = s[:-3]
    return s.strip()


def cost_usd(input_tokens: int, output_tokens: int, in_per_mtok: float, out_per_mtok: float) -> float:
    return (input_tokens / 1_000_000.0) * in_per_mtok + (output_tokens / 1_000_000.0) * out_per_mtok


def parse_cloud_json(raw: str):
    """Parse + validate a CloudCommandEnrichment from raw text. Returns model or None."""
    from .schemas import CloudCommandEnrichment
    from pydantic import ValidationError
    try:
        return CloudCommandEnrichment(**json.loads(raw))
    except (json.JSONDecodeError, ValidationError) as e:
        log.debug("cloud JSON parse failed: %s; raw=%r", e, raw[:300])
        return None
