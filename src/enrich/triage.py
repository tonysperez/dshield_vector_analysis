"""Phase 2 triage: decide which Phase 1 enrichments deserve a cloud second opinion.

Decisions consume the already-emitted Phase 1 doc (or its in-memory equivalent),
not the raw event. Each rule that fires is recorded in the returned reason list
so downstream queries can see *why* something was escalated.
"""
from __future__ import annotations

import logging
import random
import re
from datetime import datetime, timezone
from typing import Optional

from .cache import StateDB
from .config import CloudConfig
from .llm.schemas import CommandEnrichment

log = logging.getLogger(__name__)

# A run of base64-ish chars. The threshold is configurable.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")
_IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_TLD_RE = re.compile(r"\b[a-z0-9-]+\.([a-z]{2,24})\b", re.IGNORECASE)


def reasons_to_escalate(
    *,
    command: str,
    parsed: Optional[CommandEnrichment],
    local_failed: bool,
    cfg: CloudConfig,
    embedding: Optional[list[float]] = None,
    centroids: Optional[list[list[float]]] = None,
    rng: Optional[random.Random] = None,
) -> list[str]:
    """Return list of reason codes that fire for this command. Empty = stay local.

    embedding + centroids are optional Phase 3 inputs. When both are provided
    and the command's novelty_score >= cfg.triage.novel_embedding_threshold,
    the "novel_embedding" reason code fires.
    """
    rng = rng or random
    reasons: list[str] = []

    if local_failed:
        reasons.append("local_failed")

    if parsed is not None and parsed.confidence <= cfg.triage.confidence_max:
        reasons.append(f"low_confidence<={cfg.triage.confidence_max}")

    # Suspicious IOC patterns — independent of what the local model extracted,
    # since we may be escalating *because* the local model missed them.
    longest_b64 = 0
    for m in _BASE64_RE.finditer(command):
        longest_b64 = max(longest_b64, len(m.group(0)))
    if longest_b64 >= cfg.triage.base64_min_run:
        reasons.append("base64_blob")

    if _IPV4_RE.search(command):
        reasons.append("ip_literal")

    sus_tlds = {t.lower().lstrip(".") for t in cfg.triage.suspicious_tlds}
    for m in _TLD_RE.finditer(command):
        if m.group(1).lower() in sus_tlds:
            reasons.append("rare_tld")
            break

    # Phase 3 novel_embedding rule — requires cluster centroids loaded from ES.
    #
    # Gate by confidence floor: novelty-as-signal only makes sense when the
    # local model said something coherent about the command. A
    # confidence-1 enrichment with novelty=1.0 is almost always raw bytes
    # / encoding artifacts (see ROADMAP issue #3), and the `low_confidence`
    # rule above already routes those to the cloud — no need to also fire
    # `novel_embedding` and double-count them in escalate budget. When
    # `parsed is None` (local LLM never produced a doc to rate), defer to
    # `local_failed` for escalation instead.
    if (
        embedding is not None and centroids
        and parsed is not None
        and parsed.confidence >= cfg.triage.novel_confidence_min
    ):
        from .clustering import novelty_score_from_lists
        score = novelty_score_from_lists(embedding, centroids)
        if score >= cfg.triage.novel_embedding_threshold:
            reasons.append("novel_embedding")

    # Random sampling for quality monitoring.
    if cfg.triage.sample_rate > 0 and rng.random() < cfg.triage.sample_rate:
        reasons.append("sample")

    # de-dup while preserving order
    seen = set()
    out = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def budget_remaining_usd(db: StateDB, cfg: CloudConfig) -> float:
    spent = db.get_spend(utc_today())["cost_usd"]
    return max(0.0, cfg.daily_budget_usd - spent)


def can_spend(db: StateDB, cfg: CloudConfig) -> bool:
    return budget_remaining_usd(db, cfg) > 0.0
