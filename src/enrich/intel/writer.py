"""Intel doc writer + consensus rule.

The intel-*-default ES indices hold one doc per artifact. Each doc has
a `providers.<name>` sub-object for each provider that ever returned
data, plus a `derived` block recomputed every refresh.

This module:

  - `build_intel_doc` — pure function. Given an artifact + list of
    ProviderResults + the prior doc (if any), returns the new ES
    source body. Merges per-provider entries (later results overwrite
    earlier ones for the same provider).
  - `compute_derived` — pure function. Applies the consensus rule
    (any-positive flags malicious, per 2026-05-16 design decision)
    over the merged providers block and emits `derived.*`.
  - `upsert_intel_doc` — actually writes the doc to ES via the existing
    es_client.

Pure-function cores have their own smoke test at
`scripts/smoke_test_intel_writer.py`.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from ..config import AppConfig
from .artifact import Artifact
from .providers.base import DerivedSignals, ProviderResult

log = logging.getLogger(__name__)


# Index lookup per artifact kind.
def index_for_kind(cfg: AppConfig, kind: str) -> str:
    """Resolve the configured intel index for an artifact kind."""
    indexes = cfg.intel.indexes
    return {
        "ip": indexes.ip,
        "url": indexes.url,
        "domain": indexes.domain,
        "hash": indexes.hash,
    }[kind]


# ---------------------------------------------------------------------------
# Consensus rule — pure function.
# ---------------------------------------------------------------------------


def compute_derived(provider_signals: Iterable[DerivedSignals]) -> dict[str, Any]:
    """Apply the refined consensus rule across provider signals.

    The rule (2026-05-17, supersedes the simple any-positive of
    2026-05-16):

    1. Direct-evidence malicious wins absolutely. If any provider has
       `malicious=True AND evidence_direct=True` (FeodoTracker active
       C2, GreyNoise's own malicious classification), consensus is
       malicious regardless of any clean signals.
    2. Authoritative clean overrides aggregator-only malicious votes.
       If any provider has `authoritative_clean=True` (GreyNoise
       benign or RIOT — its curated known-good infrastructure lists)
       AND no direct-evidence malicious exists, consensus is clean
       (`consensus_malicious=False`) regardless of how many aggregator
       providers flagged the artifact. The canonical case: AbuseIPDB
       false-positive on a legitimate scanner like ShadowServer; GN
       benign rescues it.
    3. Otherwise: any-positive (the original rule). Any provider
       flagging `malicious=True` flips consensus.

    Returns a dict with:
      - `consensus_malicious`: bool
      - `consensus_label`: str — preferentially from the authoritative
        signal when override applies; else from malicious providers;
        else any provider; else "unknown".
      - `override_applied`: str — "direct_malicious", "authoritative_clean",
        or "" — surfaces the rule that produced the verdict.
      - `tags`: list[str] — deduplicated union of all provider tags.
      - `providers_with_data`: int — count of signals with non-None
        `malicious`.
      - `providers_total`: int — total signals seen.
      - `external_rarity_score`: float — 0.0 (everyone knows) to 1.0
        (nobody knows). Linear in the no-opinion fraction.
      - `malicious_provider_count`: int — count of providers that
        voted `malicious=True`. Direct input for M3.A triage gate
        ("skip cloud if ≥2 providers agree malicious"). Precomputed
        so the gate doesn't have to iterate per-provider blocks.
      - `clean_provider_count`: int — count of providers that voted
        `malicious=False`. M5 calibration display.
      - `confidence_max`: int|None — highest confidence among the
        malicious-voting providers, else None. Direct triage-gate
        tuning input ("skip cloud only if confidence_max ≥ 8").

    The rationale for `external_rarity_score`: research mode wants
    candidates where local novelty is high AND external feeds are
    silent. This number is the "external feeds are silent" half.
    """
    sig_list = list(provider_signals)
    total = len(sig_list)
    with_data = sum(1 for s in sig_list if s.malicious is not None)

    direct_malicious_signals = [
        s for s in sig_list if s.malicious is True and s.evidence_direct
    ]
    any_malicious_signals = [s for s in sig_list if s.malicious is True]
    authoritative_clean_signals = [
        s for s in sig_list if s.authoritative_clean
    ]

    consensus_malicious: bool
    override_applied: str
    label: Optional[str] = None

    if direct_malicious_signals:
        # Rule 1: direct evidence wins.
        consensus_malicious = True
        override_applied = "direct_malicious"
        for s in direct_malicious_signals:
            if s.label:
                label = s.label
                break
    elif authoritative_clean_signals:
        # Rule 2: authoritative clean overrides aggregator-only malicious.
        consensus_malicious = False
        override_applied = "authoritative_clean"
        for s in authoritative_clean_signals:
            if s.label:
                label = s.label
                break
    else:
        # Rule 3: any-positive.
        consensus_malicious = bool(any_malicious_signals)
        override_applied = ""
        for s in any_malicious_signals:
            if s.label:
                label = s.label
                break

    if label is None:
        for s in sig_list:
            if s.label:
                label = s.label
                break
    if label is None:
        label = "unknown"

    tags: list[str] = []
    seen: set[str] = set()
    for s in sig_list:
        for tag in s.tags:
            if tag and tag not in seen:
                seen.add(tag)
                tags.append(tag)

    if total == 0:
        external_rarity_score = 1.0
    else:
        external_rarity_score = (total - with_data) / total

    # Rollups precomputed for downstream consumers (M3 triage gate,
    # M5 findings page). Cheap to compute here; expensive for callers
    # to recompute by walking per-provider blocks every time.
    malicious_provider_count = sum(1 for s in sig_list if s.malicious is True)
    clean_provider_count = sum(1 for s in sig_list if s.malicious is False)
    malicious_confidences = [
        s.confidence for s in sig_list
        if s.malicious is True and s.confidence is not None
    ]
    confidence_max = max(malicious_confidences) if malicious_confidences else None

    return {
        "consensus_malicious": consensus_malicious,
        "consensus_label": label,
        "override_applied": override_applied,
        "tags": tags,
        "providers_with_data": with_data,
        "providers_total": total,
        "external_rarity_score": round(external_rarity_score, 4),
        "malicious_provider_count": malicious_provider_count,
        "clean_provider_count": clean_provider_count,
        "confidence_max": confidence_max,
    }


# ---------------------------------------------------------------------------
# Doc builder — pure function.
# ---------------------------------------------------------------------------


def _provider_block(r: ProviderResult) -> dict[str, Any]:
    """Per-provider sub-object stored at `providers.<name>`."""
    return {
        "fetched_at": r.fetched_at.isoformat(),
        "ttl_expires_at": r.ttl_expires_at.isoformat(),
        "structured": r.structured,
        "raw": r.raw,
        # Persist the derived block flat for in-ES filtering. Provider
        # results can be queried directly by malicious flag without
        # joining the `derived` aggregate.
        "malicious": r.derived.malicious,
        "confidence": r.derived.confidence,
        "label": r.derived.label,
        "tags": list(r.derived.tags),
        "authoritative_clean": r.derived.authoritative_clean,
        "evidence_direct": r.derived.evidence_direct,
    }


def build_intel_doc(
    artifact: Artifact,
    new_results: Iterable[ProviderResult],
    prior_doc: Optional[dict[str, Any]] = None,
    *,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Construct the full ES doc body for the artifact's intel index.

    Merges `new_results` into `prior_doc.providers` (later overwrites
    earlier per-provider). Recomputes the `derived` block over the
    merged provider set. Stamps `last_refreshed` from `now` (UTC).

    The prior-doc merge is what makes the writer idempotent across
    refresh runs: a worker that only re-queried two of five providers
    keeps the other three's data intact.
    """
    t = (now or datetime.now(timezone.utc)).isoformat()
    providers: dict[str, dict[str, Any]] = {}
    first_observed_locally: Optional[str] = None
    if prior_doc:
        prior_providers = (prior_doc.get("providers") or {})
        if isinstance(prior_providers, dict):
            providers.update(prior_providers)
        prior_artifact = prior_doc.get("artifact") or {}
        first_observed_locally = prior_artifact.get("first_observed_locally")

    for r in new_results:
        providers[r.provider] = _provider_block(r)

    # Reconstruct the per-provider DerivedSignals from whatever's in
    # the merged providers map. We can do this from the persisted
    # fields without re-running providers — the block carries
    # everything `compute_derived` needs.
    signals = [
        DerivedSignals(
            malicious=p.get("malicious"),
            confidence=p.get("confidence"),
            label=p.get("label"),
            tags=tuple(p.get("tags") or ()),
            authoritative_clean=bool(p.get("authoritative_clean", False)),
            evidence_direct=bool(p.get("evidence_direct", False)),
        )
        for p in providers.values()
    ]
    derived = compute_derived(signals)

    return {
        "artifact": {
            "kind": artifact.kind,
            "value": artifact.value,
            "first_observed_locally": first_observed_locally or t,
        },
        "providers": providers,
        "derived": derived,
        "last_refreshed": t,
    }


# ---------------------------------------------------------------------------
# ES writer.
# ---------------------------------------------------------------------------


def upsert_intel_doc(
    es, cfg: AppConfig, artifact: Artifact,
    new_results: list[ProviderResult],
) -> dict[str, Any]:
    """Read the prior doc (if any), merge results, write back. Returns the new body."""
    idx = index_for_kind(cfg, artifact.kind)
    doc_id = artifact.value
    prior: Optional[dict[str, Any]] = None
    try:
        resp = es.get(index=idx, id=doc_id, ignore=[404])
        if resp.get("found"):
            prior = resp.get("_source")
    except Exception as exc:                       # pragma: no cover
        log.warning("intel.writer: GET %s/%s failed: %s", idx, doc_id, exc)

    body = build_intel_doc(artifact, new_results, prior)
    try:
        es.index(index=idx, id=doc_id, body=body)
    except Exception as exc:                       # pragma: no cover
        log.error("intel.writer: index %s/%s failed: %s", idx, doc_id, exc)
        raise
    return body
