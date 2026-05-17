"""Intel priority queue.

Owns the priority formula + the artifact-discovery scan that feeds the
queue. Pure functions where possible — the priority math has its own
smoke test at `scripts/smoke_test_intel_priority.py`.

Design (ROADMAP "Research-mode strategic gaps" section A):

  priority = novelty_w * novelty
           + low_conf_w * (1 - confidence/10)
           + centrality_w * centrality_norm
           + recency_w * recency_decay

Local novelty dominates by design — the scarce free-tier budgets go
first to artifacts most likely to be discoveries. Weights are
configurable in `cfg.intel.priority`.

The discovery scan walks the per-source enrichment indices, extracts
artifacts (currently only source IPs in milestone 1), canonicalises
them, filters never-query CIDRs, and upserts them into the SQLite
`intel_queue` table with the computed priority.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from ..cache import StateDB
from ..config import AppConfig, IntelPriorityConfig
from .artifact import Artifact, canonical_ip, is_in_cidrs, make_artifact

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Priority computation — pure function.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PriorityInputs:
    """All signals the priority formula consumes. None = signal unavailable."""
    novelty_score: Optional[float] = None       # 0.0–1.0 (or None)
    confidence: Optional[int] = None            # 1–10 LLM self-rating
    centrality_norm: Optional[float] = None     # 0.0–1.0, log-normalised occurrence
    age_hours: Optional[float] = None           # hours since first-observed locally


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def compute_priority(
    inputs: PriorityInputs, weights: IntelPriorityConfig,
) -> float:
    """Compute the priority score for a queue entry.

    Each term is in [0, 1] before weighting; missing signals contribute
    0 (their weight is effectively skipped). The result is the weighted
    sum — not normalised to [0, 1] since only relative ordering matters
    when popping from the queue.
    """
    novelty_term = _clamp(inputs.novelty_score) if inputs.novelty_score is not None else 0.0
    if inputs.confidence is not None:
        low_conf_term = _clamp(1.0 - inputs.confidence / 10.0)
    else:
        low_conf_term = 0.0
    centrality_term = _clamp(inputs.centrality_norm) if inputs.centrality_norm is not None else 0.0
    if inputs.age_hours is not None and weights.recency_half_life_hours > 0:
        # Half-life decay: 1 at age=0, 0.5 at age=half_life.
        recency_term = math.exp(
            -math.log(2.0) * max(0.0, inputs.age_hours) / weights.recency_half_life_hours
        )
    else:
        recency_term = 0.0
    return (
        weights.novelty_w * novelty_term
        + weights.low_conf_w * low_conf_term
        + weights.centrality_w * centrality_term
        + weights.recency_w * recency_term
    )


# ---------------------------------------------------------------------------
# Artifact discovery from project-owned indices.
# ---------------------------------------------------------------------------


def _iter_ip_artifacts_from_rollup(es, cfg: AppConfig) -> Iterator[tuple[Artifact, PriorityInputs]]:
    """Scan the IP rollup index and yield (artifact, priority inputs).

    The IP rollup is the canonical place — every source IP we've ever
    observed locally appears here, with the behavioural stats (mean
    novelty, total sessions, first/last seen) needed to compute
    priority. Encoding artifacts and other one-off oddities don't show
    up in the IP rollup, so the queue stays clean.
    """
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    if not es.indices.exists(index=idx):
        return
    body = {
        "size": cfg.intel.max_per_run,
        "_source": [
            "source.ip",
            "dshield.cowrie.enrichment.ip.mean_novelty_score",
            "dshield.cowrie.enrichment.ip.max_novelty_score",
            "dshield.cowrie.enrichment.ip.total_sessions",
            "dshield.cowrie.enrichment.ip.first_seen",
        ],
        "query": {"exists": {"field": "source.ip"}},
        "sort": [{"_doc": "asc"}],
    }
    now = datetime.now(timezone.utc)
    # Corpus-scale denominator for centrality. Bounded so a single
    # very-active IP doesn't pin every other IP at centrality≈0. Same
    # rationale as ROADMAP #14 (fixed-denominator scalar normalisation).
    _TOTAL_SESSIONS_DENOM = 1000.0
    try:
        resp = es.search(index=idx, **body)
    except Exception as exc:                       # pragma: no cover
        log.warning("intel: IP rollup scan failed: %s", exc)
        return
    for hit in resp.get("hits", {}).get("hits", []) or []:
        src = hit.get("_source") or {}
        ip_raw = (src.get("source") or {}).get("ip")
        canon = canonical_ip(ip_raw) if ip_raw else None
        if canon is None:
            continue
        if is_in_cidrs(canon, cfg.intel.never_query_cidrs):
            continue
        enrich = (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}).get("ip") or {}
        # Use max_novelty so a single high-novelty session dominates a
        # bag of boilerplate ones (mean would dilute the signal we
        # most want to act on).
        novelty = enrich.get("max_novelty_score")
        if novelty is None:
            novelty = enrich.get("mean_novelty_score")
        total_sessions = enrich.get("total_sessions") or 0
        centrality_norm = (
            math.log1p(total_sessions) / math.log1p(_TOTAL_SESSIONS_DENOM)
            if total_sessions > 0 else 0.0
        )
        first_seen_str = enrich.get("first_seen")
        age_hours: Optional[float]
        if first_seen_str:
            try:
                fs = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
                age_hours = max(0.0, (now - fs).total_seconds() / 3600.0)
            except (ValueError, TypeError):
                age_hours = None
        else:
            age_hours = None
        yield (
            Artifact("ip", canon),
            PriorityInputs(
                novelty_score=float(novelty) if novelty is not None else None,
                confidence=None,  # IP-level rollup doesn't carry a confidence
                centrality_norm=centrality_norm,
                age_hours=age_hours,
            ),
        )


def discover_and_enqueue(
    es, db: StateDB, cfg: AppConfig,
) -> dict[str, int]:
    """Walk the per-source indices, compute priorities, upsert into the queue.

    Returns a stats dict (`{kind: count_enqueued}`) for the CLI to print.
    Idempotent and cheap-when-no-change: existing rows get their
    priority refreshed but the row stays in place.
    """
    weights = cfg.intel.priority
    now_iso = datetime.now(timezone.utc).isoformat()
    counts: dict[str, int] = {}
    for artifact, inputs in _iter_ip_artifacts_from_rollup(es, cfg):
        prio = compute_priority(inputs, weights)
        db.intel_queue_upsert(artifact.kind, artifact.value, prio, now_iso)
        counts[artifact.kind] = counts.get(artifact.kind, 0) + 1
    return counts


def select_for_provider(
    db: StateDB, provider_handles: Iterable[str], limit: int,
) -> list[Artifact]:
    """Pop top-N queued artifacts the provider can answer.

    Doesn't actually remove rows — the refresh worker calls
    `intel_queue_mark_done` only after the lookup succeeds across
    every applicable provider. A row stays in the queue until every
    provider that handles its kind has had a successful pass.
    """
    out: list[Artifact] = []
    remaining = limit
    for kind in provider_handles:
        if remaining <= 0:
            break
        rows = db.intel_queue_pop_top(kind, remaining)
        for value, _prio in rows:
            try:
                out.append(Artifact(kind, value))
            except ValueError:
                # Skip rows that fail re-validation (kind was renamed,
                # canonicaliser was tightened, …) so they don't poison
                # the worker. The row stays in the queue until manually
                # cleared.
                continue
        remaining -= len(rows)
    return out
