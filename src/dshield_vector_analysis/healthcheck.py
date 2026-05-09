"""Connectivity + sanity tests. Exits 0 OK, nonzero fail."""
from __future__ import annotations

import logging

from .cache import StateDB
from .config import AppConfig, Secrets
from .es_client import make_client
from .llm import make_llm_client

log = logging.getLogger(__name__)


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


def check(cfg: AppConfig, secrets: Secrets) -> int:
    failures = 0

    # ES
    try:
        es = make_client(cfg.elasticsearch, secrets)
        info = es.info()
        print(f"[ok] ES {info['version']['number']} at {cfg.elasticsearch.hosts[0]}")
        if es.indices.exists(index=cfg.elasticsearch.enrichment_index):
            print(f"[ok] enrichment index exists: {cfg.elasticsearch.enrichment_index}")
        else:
            print(f"[warn] enrichment index missing: {cfg.elasticsearch.enrichment_index} (run init-index)")
        cnt = es.count(index=cfg.elasticsearch.events_index, ignore_unavailable=True)
        print(f"[ok] events index '{cfg.elasticsearch.events_index}' has {cnt['count']} docs")
    except Exception as e:
        print(f"[FAIL] elasticsearch: {e}")
        failures += 1

    # LLM
    try:
        with make_llm_client(cfg.llm) as llm:
            tags = llm.health()
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
    except Exception as e:
        print(f"[FAIL] llm: {e}")
        failures += 1

    # SQLite
    try:
        db = StateDB(cfg.worker.state_db)
        wm = db.get_watermark()
        print(f"[ok] SQLite writable at {cfg.worker.state_db}, watermark={wm}")
        db.close()
    except Exception as e:
        print(f"[FAIL] sqlite: {e}")
        failures += 1

    if failures:
        print(f"\n{failures} check(s) FAILED")
        return 1
    print("\nAll checks OK")
    return 0
