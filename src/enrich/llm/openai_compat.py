"""OpenAI-compatible LLM client. Works with LM Studio, vLLM, llama.cpp server, etc."""
from __future__ import annotations

import logging
import re
from typing import Optional

import httpx

log = logging.getLogger(__name__)

# Matches <think>...</think> blocks emitted by reasoning models (e.g. DeepSeek-R1,
# Qwen QwQ). Some servers stream the closing tag late or drop it on truncation,
# so we also strip a trailing unmatched opener.
_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL | re.IGNORECASE)
_THINK_OPEN_RE = re.compile(r"<think>.*\Z", re.DOTALL | re.IGNORECASE)


def _strip_think(text: str) -> str:
    if not text:
        return text
    text = _THINK_BLOCK_RE.sub("", text)
    text = _THINK_OPEN_RE.sub("", text)
    return text.strip()


class LLMError(RuntimeError):
    pass


class OpenAICompatClient:
    """Talks /v1/chat/completions + /v1/embeddings.

    For LM Studio: base_url is the server root (e.g. http://host:1234).
    Internally we hit base_url + '/v1/...'.
    """

    def __init__(
        self,
        base_url: str,
        generation_model: str,
        embedding_model: str,
        timeout: int = 120,
        api_key: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/").removesuffix("/v1")
        self.gen_model = generation_model
        self.embed_model = embedding_model
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.Client(timeout=timeout, headers=headers)

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def health(self) -> dict:
        r = self._client.get(f"{self.base_url}/v1/models")
        r.raise_for_status()
        return r.json()

    def generate_json(
        self,
        prompt: str,
        *,
        options: Optional[dict] = None,
        schema: Optional[dict] = None,
        schema_name: str = "structured_output",
    ) -> str:
        """Send chat completion. If `schema` provided, uses response_format=json_schema
        (LM Studio / OpenAI structured outputs); otherwise falls back to free-text mode
        and relies on the prompt to coax JSON.
        """
        opts = options or {}
        payload: dict = {
            "model": self.gen_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": opts.get("temperature", 0.1),
            "max_tokens": opts.get("max_tokens", 1024),
            "stream": False,
        }
        if schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "strict": False,
                    "schema": schema,
                },
            }
        else:
            payload["response_format"] = {"type": "text"}

        r = self._client.post(f"{self.base_url}/v1/chat/completions", json=payload)
        if r.status_code != 200:
            raise LLMError(f"chat {r.status_code}: {r.text[:300]}")
        data = r.json()
        try:
            return _strip_think(data["choices"][0]["message"]["content"] or "")
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"chat: malformed response: {e}; body={str(data)[:300]}")

    def generate_text(self, prompt: str, *, max_tokens: int = 512) -> str:
        """Plain text completion with no response_format constraint. Used by
        healthcheck. LM Studio is picky about response_format — omitting it
        entirely (rather than sending {"type":"text"}) avoids edge-case
        rejections on some loaded models.

        Default budget is generous enough for reasoning models (qwen3, R1, QwQ)
        to finish their <think> block; otherwise the entire budget is consumed
        inside <think>, _strip_think drops the unclosed opener, and the caller
        sees an empty reply.
        """
        payload = {
            "model": self.gen_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "stream": False,
        }
        r = self._client.post(f"{self.base_url}/v1/chat/completions", json=payload)
        if r.status_code != 200:
            raise LLMError(f"chat {r.status_code}: {r.text[:300]}")
        data = r.json()
        try:
            choice = data["choices"][0]
            raw = choice["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"chat: malformed response: {e}; body={str(data)[:300]}")
        stripped = _strip_think(raw)
        if not stripped and "<think>" in raw.lower() and choice.get("finish_reason") == "length":
            raise LLMError(
                "reasoning model truncated mid-<think> (finish_reason=length); "
                "increase max_tokens or load a non-reasoning model"
            )
        return stripped

    def embed(self, text: str) -> list[float]:
        payload = {"model": self.embed_model, "input": text}
        r = self._client.post(f"{self.base_url}/v1/embeddings", json=payload)
        if r.status_code != 200:
            raise LLMError(f"embed {r.status_code}: {r.text[:300]}")
        data = r.json()
        try:
            emb = data["data"][0]["embedding"]
        except (KeyError, IndexError, TypeError):
            raise LLMError(f"embed: malformed response: {str(data)[:300]}")
        if not isinstance(emb, list) or not emb:
            raise LLMError("embed: empty embedding")
        return emb
