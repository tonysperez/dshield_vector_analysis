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
    rng: Optional[random.Random] = None,
) -> list[str]:
    """Return list of reason codes that fire for this command. Empty = stay local."""
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
