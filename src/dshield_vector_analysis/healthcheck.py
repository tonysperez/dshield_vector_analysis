"""Connectivity + sanity tests. Exits 0 OK, nonzero fail."""
from __future__ import annotations

import logging
import socket
import ssl
from urllib.parse import urlparse

import httpx

from .cache import StateDB
from .config import AppConfig, Secrets
from .es_client import make_client
from .llm import make_llm_client

log = logging.getLogger(__name__)


def _diagnose_llm_failure(base_url: str, exc: Exception) -> list[str]:
    """Build a list of human-readable diagnostic lines for a local-LLM failure.

    Splits the failure into "what kind of network error" + "what to try next".
    Order of checks matters — DNS first, then TCP, then TLS, then HTTP.
    """
    out: list[str] = [f"        URL configured: {base_url!r}", f"        error type:    {type(exc).__name__}: {exc}"]

    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    out.append(f"        parsed:        scheme={parsed.scheme!r} host={host!r} port={port}")

    if not host:
        out.append("        hint:          base_url has no hostname — check llm.base_url in config/local.yaml")
        return out

    # 1) DNS
    try:
        addrs = sorted({str(ai[4][0]) for ai in socket.getaddrinfo(host, None)})
        out.append(f"        dns:           {host} -> {', '.join(addrs)}")
    except socket.gaierror as e:
        out.append(f"        dns:           [FAIL] could not resolve {host!r}: {e}")
        out.append("        hint:          fix DNS or use the GPU box's IP literal in llm.base_url")
        return out

    # 2) TCP connect
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            out.append(f"        tcp:           connect {host}:{port} OK (local={sock.getsockname()})")
    except socket.timeout:
        out.append(f"        tcp:           [FAIL] connect {host}:{port} timed out")
        out.append("        hint:          firewall on the GPU box, server not bound on 0.0.0.0, or wrong port")
        return out
    except OSError as e:
        out.append(f"        tcp:           [FAIL] connect {host}:{port}: {e}")
        out.append("        hint:          server not running, wrong port, or routing issue")
        return out

    # 3) TLS handshake (only if scheme is https)
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    out.append(f"        tls:           handshake OK (peer={cert.get('subject', '?')})")
        except ssl.SSLError as e:
            out.append(f"        tls:           [FAIL] {e}")
            out.append("        hint:          self-signed cert? Either install the CA or switch to http:// if local")
            return out
        except Exception as e:
            out.append(f"        tls:           [warn] {type(e).__name__}: {e}")

    # 4) HTTP probe — the most common providers expose either /api/tags (Ollama)
    #    or /v1/models (OpenAI-compatible). Try the right one based on URL hint
    #    but fall back to the other if it 404s, since users mix them up.
    candidates = ["/api/tags", "/v1/models"]
    if "11434" in str(port) or "ollama" in host.lower():
        candidates = ["/api/tags", "/v1/models"]
    else:
        candidates = ["/v1/models", "/api/tags"]
    base = base_url.rstrip("/")
    for path in candidates:
        url = f"{base}{path}"
        try:
            r = httpx.get(url, timeout=5, verify=False)
        except httpx.RequestError as e:
            out.append(f"        http {path}:   [FAIL] {type(e).__name__}: {e}")
            continue
        out.append(f"        http {path}:   {r.status_code} ({len(r.content)} bytes)")
        if r.status_code == 200:
            break
    out.append(
        "        hints:         "
        "(a) is the LLM server actually running on the GPU box? "
        "(b) is llm.provider matched to it (ollama vs openai_compat)? "
        "(c) try `curl -v <base_url>/v1/models` from the SO box to confirm reachability"
    )
    return out


def _model_present(tags: dict, needed: str) -> bool:
    """Check both Ollama (.models[].name) and OpenAI-compat (.data[].id) shapes."""
    candidates: list[str] = []
    for m in tags.get("models", []) or []:
        if isinstance(m, dict) and m.get("name"):
            candidates.append(m["name"])
    for m in tags.get("data", []) or []:
        if isinstance(m, dict) and m.get("id"):
            candidates.append(m["id"])
    return any(c == needed or c.startswith(needed) for c in candidates)


VALID_SCOPES = ("es", "llm", "sqlite", "cloud-conn", "cloud")


def _check_es(cfg: AppConfig, secrets: Secrets) -> int:
    failures = 0
    try:
        es = make_client(cfg.elasticsearch, secrets)
        info = es.info()
        print(f"[ok] ES {info['version']['number']} at {cfg.elasticsearch.hosts[0]}")
        if es.indices.exists(index=cfg.elasticsearch.enrichment_index):
            print(f"[ok] enrichment index exists: {cfg.elasticsearch.enrichment_index}")
        else:
            print(f"[warn] enrichment index missing: {cfg.elasticsearch.enrichment_index} (run init-index)")
        # Source events index: pattern may be alias/wildcard, so resolve via
        # indices.exists (treats wildcards as "any match"). Warn if pattern
        # resolves but holds zero docs — symptom of wrong index name or stale
        # pipeline.
        if es.indices.exists(index=cfg.elasticsearch.events_index, allow_no_indices=False):
            cnt = es.count(index=cfg.elasticsearch.events_index, ignore_unavailable=True)
            n = cnt["count"]
            if n == 0:
                print(f"[warn] events index '{cfg.elasticsearch.events_index}' exists but has 0 docs")
            else:
                print(f"[ok] events index '{cfg.elasticsearch.events_index}' has {n} docs")
        else:
            print(f"[FAIL] events index missing: {cfg.elasticsearch.events_index}")
            failures += 1
    except Exception as e:
        print(f"[FAIL] elasticsearch: {e}")
        failures += 1
    return failures


def _check_llm(cfg: AppConfig, secrets: Secrets) -> int:
    failures = 0
    print(f"[..] checking LLM provider={cfg.llm.provider!r} base_url={cfg.llm.base_url!r}")
    try:
        with make_llm_client(cfg.llm) as llm:
            try:
                tags = llm.health()
            except Exception as e:
                print(f"[FAIL] LLM /models listing failed: {type(e).__name__}: {e}")
                for line in _diagnose_llm_failure(cfg.llm.base_url, e):
                    print(line)
                raise
            print(f"[ok] LLM ({cfg.llm.provider}) at {cfg.llm.base_url}")
            for needed in (cfg.llm.generation_model, cfg.llm.embedding_model):
                if _model_present(tags, needed):
                    print(f"[ok] model present: {needed}")
                else:
                    print(f"[FAIL] model missing on server: {needed}")
                    failures += 1
            v = llm.embed("hello")
            print(f"[ok] embedding works (dim={len(v)})")
            if len(v) != 768:
                print(f"[FAIL] embedding dim {len(v)} != 768 — index mapping requires 768. Pick a 768-dim model or update es-mappings/.")
                failures += 1
            # Generation round-trip — short prompt, no schema, just confirm the
            # model returns *something*. Catches model-not-loaded / bad URL /
            # auth issues that the /v1/models listing alone misses.
            try:
                # Plain-text smoke test: no JSON-mode coercion, tight token cap.
                # JSON mode + a non-JSON prompt makes the model run to max_tokens
                # and times out (esp. on cold-loaded models).
                reply = llm.generate_text("Reply with the single word: pong", max_tokens=16)
                snippet = (reply or "").strip().replace("\n", " ")[:60]
                if snippet:
                    print(f"[ok] local LLM generation works (reply={snippet!r})")
                else:
                    print("[FAIL] local LLM generation returned empty string")
                    failures += 1
            except Exception as e:
                print(f"[FAIL] local LLM generation: {e}")
                failures += 1
    except Exception as e:
        # Avoid printing the diagnostic twice if llm.health() already did.
        msg = str(e)
        already_diagnosed = "URL configured" in msg or "[FAIL] LLM /models" in msg
        if not already_diagnosed:
            print(f"[FAIL] llm: {type(e).__name__}: {e}")
            for line in _diagnose_llm_failure(cfg.llm.base_url, e):
                print(line)
        failures += 1
    return failures


def _check_sqlite(cfg: AppConfig, secrets: Secrets) -> int:
    failures = 0
    try:
        db = StateDB(cfg.worker.state_db)
        wm = db.get_watermark()
        print(f"[ok] SQLite writable at {cfg.worker.state_db}, watermark={wm}")
        db.close()
    except Exception as e:
        print(f"[FAIL] sqlite: {e}")
        failures += 1
    return failures


def _cloud_preflight(cfg: AppConfig, secrets: Secrets) -> tuple[int, bool]:
    """Shared gate for both cloud scopes. Returns (failures, should_continue)."""
    if not cfg.cloud.enabled:
        print("[ok] cloud escalation disabled (cfg.cloud.enabled=false)")
        return 0, False
    if not secrets.anthropic_api_key:
        print("[FAIL] cloud: cfg.cloud.enabled=true but ANTHROPIC_API_KEY is unset")
        return 1, False
    return 0, True


def _check_cloud_conn(cfg: AppConfig, secrets: Secrets) -> int:
    """Connectivity + auth only. No model invocation, zero generation tokens.

    Used as the systemd ExecStartPre gate so a rotated/expired key fails fast
    without spending budget on a smoke-test message every hour.
    """
    failures, go = _cloud_preflight(cfg, secrets)
    if not go:
        return failures
    try:
        from .llm.anthropic import AnthropicClient
        with AnthropicClient(
            api_key=secrets.anthropic_api_key,
            model=cfg.cloud.model,
            max_tokens=1,
            timeout=cfg.cloud.request_timeout,
            base_url=cfg.cloud.base_url,
        ) as cc:
            data = cc.ping()
        n = len((data or {}).get("data") or [])
        print(f"[ok] cloud (anthropic) connectivity + auth OK ({n} models visible)")
    except Exception as e:
        print(f"[FAIL] cloud connectivity: {e}")
        failures += 1
    return failures


def _check_cloud(cfg: AppConfig, secrets: Secrets) -> int:
    """Full round-trip: connectivity + auth + configured model + parsing.

    Burns ~16 output tokens. Run by the interactive `healthcheck` command,
    not by the systemd pre-gate.
    """
    failures, go = _cloud_preflight(cfg, secrets)
    if not go:
        return failures
    try:
        from .llm.anthropic import AnthropicClient
        with AnthropicClient(
            api_key=secrets.anthropic_api_key,
            model=cfg.cloud.model,
            max_tokens=16,
            timeout=cfg.cloud.request_timeout,
            base_url=cfg.cloud.base_url,
        ) as cc:
            text, in_tok, out_tok = cc.generate_with_usage(
                "Reply with the single word: pong"
            )
        snippet = (text or "").strip().replace("\n", " ")[:60]
        if not snippet:
            print(f"[FAIL] cloud (anthropic) returned empty content (model={cfg.cloud.model})")
            failures += 1
        else:
            print(
                f"[ok] cloud (anthropic) generation works, model={cfg.cloud.model} "
                f"reply={snippet!r} tokens=in:{in_tok}/out:{out_tok}"
            )
    except Exception as e:
        print(f"[FAIL] cloud: {e}")
        failures += 1
    try:
        from . import triage as triage_mod
        db = StateDB(cfg.worker.state_db)
        spent = db.get_spend(triage_mod.utc_today())["cost_usd"]
        remaining = max(0.0, cfg.cloud.daily_budget_usd - spent)
        print(f"[ok] cloud budget today: spent=${spent:.4f} / cap=${cfg.cloud.daily_budget_usd:.2f} remaining=${remaining:.4f}")
        db.close()
    except Exception as e:
        print(f"[warn] cloud budget read failed: {e}")
    return failures


_SCOPE_FNS = {
    "es": _check_es,
    "llm": _check_llm,
    "sqlite": _check_sqlite,
    "cloud-conn": _check_cloud_conn,
    "cloud": _check_cloud,
}


def check(cfg: AppConfig, secrets: Secrets, scopes: list[str] | None = None) -> int:
    """Run selected scope checks. ``scopes=None`` runs all.

    Output is a stream of ``[ok]`` / ``[warn]`` / ``[FAIL]`` prefixed lines plus
    a trailing ``All checks OK`` or ``N check(s) FAILED`` summary. Exit code is
    1 if any scope reports a failure, else 0.
    """
    # Default is the cheap path: run cloud-conn (ping only, zero generation
    # tokens) so scripts/timers/setup runners don't burn budget on every call.
    # The full ``cloud`` round-trip is opt-in (--scope cloud or --scope all)
    # for interactive troubleshooting.
    default_scopes = [s for s in VALID_SCOPES if s != "cloud"]
    selected = scopes or default_scopes
    unknown = [s for s in selected if s not in _SCOPE_FNS]
    if unknown:
        print(f"[FAIL] unknown scope(s): {', '.join(unknown)} (valid: {', '.join(VALID_SCOPES)})")
        return 2

    failures = 0
    for s in selected:
        failures += _SCOPE_FNS[s](cfg, secrets)

    if failures:
        print(f"\n{failures} check(s) FAILED (scopes={','.join(selected)})")
        return 1
    print(f"\nAll checks OK (scopes={','.join(selected)})")
    return 0
