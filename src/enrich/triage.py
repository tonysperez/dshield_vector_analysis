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
from .intel.lookup import IntelSummary
from .llm.schemas import CommandEnrichment

log = logging.getLogger(__name__)

# A run of base64-ish chars. The threshold is configurable.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")


def _has_mixed_classes(s: str) -> bool:
    """True iff `s` contains at least one ASCII upper, one ASCII lower,
    and one digit.

    Used to gate `base64_blob` triage so a long hex digest (only lower-or-
    upper + digits) or a bare uppercase id (no lowercase, no digits) stops
    triggering the rule. ROADMAP #23 — character-class entropy guard.

    Base64 padding (`=`) and the URL-safe extras (`+`, `/`) don't count
    toward any class — only ASCII alnum does.
    """
    has_upper = has_lower = has_digit = False
    for c in s:
        if "A" <= c <= "Z":
            has_upper = True
        elif "a" <= c <= "z":
            has_lower = True
        elif "0" <= c <= "9":
            has_digit = True
        if has_upper and has_lower and has_digit:
            return True
    return False
_IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")

# Host-context anchor: only fire `rare_tld` when the hostname.tld pattern
# appears in a network-fetch context — either after a URL scheme (`://`)
# or after a known network-tool keyword. Bare-filename matches like
# `update.exe` or `./script.run` were previously dragging in `.zip` /
# `.exe` (now removed from suspicious_tlds) and any future entry that
# happens to overlap a filename suffix would have re-introduced the same
# bug. ROADMAP issue #4.
_NETWORK_TOOLS = (
    "wget|curl|nslookup|dig|host|ping|nc|ncat|ssh|scp|sftp|tftp|telnet|ftp"
)
# Two host-context anchors:
#   - `://`            : URL scheme (catches any URL regardless of caller).
#   - `<tool>...`      : a network-tool keyword followed by any non-shell-
#                        separator chars up to the hostname. The `[^|;&\n]*?`
#                        is lazy so it doesn't bleed past a pipe/semicolon
#                        into an unrelated command in the same line.
_TLD_RE = re.compile(
    rf"(?:://|\b(?:{_NETWORK_TOOLS})\b[^|;&\n]*?\b)"
    r"[a-z0-9-]+\.([a-z]{2,24})\b",
    re.IGNORECASE,
)


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
    # `base64_blob` requires the matched run to mix upper, lower, AND digit
    # (ROADMAP #23) so a long hex digest or a bare uppercase id doesn't trip
    # the rule — both legitimately match `[A-Za-z0-9+/=]{40,}` but are not
    # base64 in shape.
    longest_b64 = 0
    for m in _BASE64_RE.finditer(command):
        run = m.group(0)
        if not _has_mixed_classes(run):
            continue
        if len(run) > longest_b64:
            longest_b64 = len(run)
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


# Triage reasons that originate from the COMMAND SHAPE itself (base64,
# IP literal, suspicious TLD). Independent of the attacker's identity —
# even a known commodity scanner running a base64-evasion command is
# still doing something interesting. The intel gate REFUSES to suppress
# escalation when any of these reasons fire.
_COMMAND_SHAPE_REASONS: frozenset[str] = frozenset(
    {"base64_blob", "ip_literal", "rare_tld"}
)

# Triage reasons we WILL suppress when intel says the source IPs are
# all-commodity or all-clean. These are "the LLM was uncertain" reasons,
# not "the command itself looks evasive" reasons.
_GATEABLE_REASONS_PREFIXES: tuple[str, ...] = (
    "low_confidence",       # parsed.confidence <= threshold
    "novel_embedding",      # cluster-distance novelty
    "sample",               # random quality-monitoring sample
)


def _reasons_are_gateable(reasons: list[str]) -> bool:
    """True iff every reason in the list is a gateable (LLM-uncertainty) reason.

    Command-shape reasons (base64_blob / ip_literal / rare_tld) make a
    list non-gateable — those signals are independent of attacker
    identity and the cloud's deeper analysis is still warranted.
    """
    if not reasons:
        return False
    for r in reasons:
        # Match by prefix because some reasons carry a suffix like
        # "low_confidence<=4". Exact match handles the rest.
        if any(r == p or r.startswith(p) for p in _GATEABLE_REASONS_PREFIXES):
            continue
        return False
    return True


def intel_skip_reason(
    *,
    triage_reasons: list[str],
    ip_summaries: list[IntelSummary],
    cfg: CloudConfig,
) -> Optional[str]:
    """Decide whether external intel grounds suppression of cloud escalation.

    Returns a reason code (string) when escalation should be skipped —
    appended to the command's `triage_reasons` so the doc records WHY
    we didn't escalate — or None when intel has no grounds to override.

    Rules (all conservative; require intel data to be unambiguous):

    1. **All source IPs are authoritative-clean** → return
       `"intel_skip_authoritative_clean"`. ShadowServer-class researchers
       running enumeration commands don't deserve cloud-LLM budget.

    2. **All source IPs have ≥2-provider malicious consensus** AND every
       triage reason is gateable (no `base64_blob` / `ip_literal` /
       `rare_tld`) → return `"intel_skip_commodity_consensus"`. The
       command + attacker combination is well-known commodity activity;
       the local LLM's enrichment is sufficient.

    3. Otherwise → None. Let the existing escalation rules decide.

    Disabled when `cfg.triage.intel_aware=False`. No-op when
    `ip_summaries` is empty (e.g. intel disabled, or no IPs had data).
    """
    if not cfg.triage.intel_aware:
        return None
    if not ip_summaries:
        return None
    # Rule 1: every IP carries an authoritative_clean override.
    if all(s.override_applied == "authoritative_clean" for s in ip_summaries):
        return "intel_skip_authoritative_clean"
    # Rule 2: every IP has strong-consensus malicious AND the only
    # escalation reasons are gateable.
    all_strong_commodity = all(
        s.consensus_malicious and s.malicious_provider_count >= 2
        for s in ip_summaries
    )
    if all_strong_commodity and _reasons_are_gateable(triage_reasons):
        return "intel_skip_commodity_consensus"
    return None


def utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def budget_remaining_usd(db: StateDB, cfg: CloudConfig) -> float:
    spent = db.get_spend(utc_today())["cost_usd"]
    return max(0.0, cfg.daily_budget_usd - spent)


def can_spend(db: StateDB, cfg: CloudConfig) -> bool:
    return budget_remaining_usd(db, cfg) > 0.0
