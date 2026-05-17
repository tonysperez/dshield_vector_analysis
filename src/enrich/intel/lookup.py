"""Read-side helper for intel-*-default indices.

The intel store is written by `intel.refresh.run_refresh`; this module
is how the *rest* of the pipeline consumes it. Three planned M3
consumers:

- `triage.intel_skip_reason` — gate cloud escalation when intel says
  the source IPs are commodity-known or curated-clean.
- `sources/cowrie/ips.py` IP cluster matrix — fold
  `external_rarity_score` + `consensus_malicious` into the
  attribution sub-block.
- `sources/cowrie/sessions.py` session rollup — persist the source
  IP's intel verdict on each session doc for fast pivot.

`IntelSummary` is the compact view downstream consumers use; the
full `derived.*` block in ES is rich but most callers want a small
hashable struct. `IntelLookup` does in-memory caching so repeated
queries within a single enrichment run don't hit ES multiple times
for the same IP.

Pure-function classifier helpers live alongside so smoke tests can
exercise the lookup-result shape without an ES connection.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from ..config import AppConfig

log = logging.getLogger(__name__)


# Hard ceiling on per-mget IP count — ES default is 1000. We chunk to
# stay under that comfortably; downstream callers can pass thousands
# of IPs and the helper transparently batches.
_MGET_CHUNK = 500


@dataclass(frozen=True)
class IntelSummary:
    """Compact downstream view of an intel doc's derived signals.

    Tracks only the fields M3 consumers actually need. The full
    per-provider data still lives in ES for analyst inspection;
    `IntelSummary` is the cheap-to-pass-around in-pipeline view.
    """
    consensus_malicious: bool
    consensus_label: str
    override_applied: str          # "" | "direct_malicious" | "authoritative_clean"
    external_rarity_score: float
    malicious_provider_count: int
    clean_provider_count: int
    confidence_max: Optional[int]
    tags: tuple[str, ...]

    @classmethod
    def from_doc(cls, source: dict) -> Optional["IntelSummary"]:
        """Build an IntelSummary from an intel ES doc body, or None on missing/malformed input."""
        if not isinstance(source, dict):
            return None
        derived = source.get("derived")
        if not isinstance(derived, dict):
            return None
        cm = derived.get("consensus_malicious")
        if cm is None:
            return None
        # Defensive defaults for every field — old intel docs that
        # haven't been touched by `reapply-rules` yet may be missing
        # the M2 rollup additions.
        return cls(
            consensus_malicious=bool(cm),
            consensus_label=str(derived.get("consensus_label") or "unknown"),
            override_applied=str(derived.get("override_applied") or ""),
            external_rarity_score=float(derived.get("external_rarity_score") or 0.0),
            malicious_provider_count=int(derived.get("malicious_provider_count") or 0),
            clean_provider_count=int(derived.get("clean_provider_count") or 0),
            confidence_max=(int(derived["confidence_max"])
                            if derived.get("confidence_max") is not None else None),
            tags=tuple(derived.get("tags") or ()),
        )


class IntelLookup:
    """Multi-kind in-memory-cached reader for the `intel-*-default` indices.

    Instantiate once per enrichment run / cluster pass and reuse —
    repeated lookups for the same artifact across many commands or
    sessions hit the cache rather than ES.

    `None` is a valid cache entry meaning "no intel data exists for
    this artifact" — distinguishes from "haven't queried yet".

    Generalised in M4: keyed by `(kind, value)` so URL / domain /
    hash / IP lookups all flow through the same helper. The IP-only
    convenience methods `get_one_ip` / `get_many_ip` remain for
    callers that don't care about the kind dispatch.
    """

    def __init__(self, es, cfg: AppConfig) -> None:
        self.es = es
        self.cfg = cfg
        self._cache: dict[tuple[str, str], Optional[IntelSummary]] = {}
        self._index_exists: dict[str, Optional[bool]] = {}

    # --- helpers ------------------------------------------------------------

    def _index_for_kind(self, kind: str) -> Optional[str]:
        """Resolve the configured ES index name for an artifact kind, or None when unsupported."""
        indexes = self.cfg.intel.indexes
        mapping = {
            "ip":     indexes.ip,
            "url":    indexes.url,
            "domain": indexes.domain,
            "hash":   indexes.hash,
        }
        return mapping.get(kind)

    def _ensure_index(self, index: str) -> bool:
        cached = self._index_exists.get(index)
        if cached is None:
            try:
                cached = bool(self.es.indices.exists(index=index))
            except Exception as exc:                   # pragma: no cover
                log.warning("intel.lookup: index existence check failed: %s", exc)
                cached = False
            self._index_exists[index] = cached
        return cached

    # --- multi-kind API -----------------------------------------------------

    def get_one(self, kind: str, value: str) -> Optional[IntelSummary]:
        """Fetch intel for a single (kind, value). Cached. Returns None when absent."""
        if not value:
            return None
        key = (kind, value)
        if key in self._cache:
            return self._cache[key]
        idx = self._index_for_kind(kind)
        if not idx or not self._ensure_index(idx):
            self._cache[key] = None
            return None
        try:
            resp = self.es.get(index=idx, id=value, ignore=[404])
        except Exception as exc:                       # pragma: no cover
            log.warning("intel.lookup: get %s/%s failed: %s", kind, value, exc)
            self._cache[key] = None
            return None
        if not resp.get("found"):
            self._cache[key] = None
            return None
        summary = IntelSummary.from_doc(resp.get("_source") or {})
        self._cache[key] = summary
        return summary

    def get_many(self, kind: str, values: list[str]) -> dict[str, Optional[IntelSummary]]:
        """Bulk-fetch intel for many values of one kind. Caches everything.

        Uses ES mget in chunks of `_MGET_CHUNK`. Return dict maps
        `value -> Optional[IntelSummary]`. Duplicates dedupe
        transparently.
        """
        out: dict[str, Optional[IntelSummary]] = {}
        to_fetch: list[str] = []
        for v in values:
            if not v:
                continue
            key = (kind, v)
            if key in self._cache:
                out[v] = self._cache[key]
            elif v not in out and v not in to_fetch:
                to_fetch.append(v)
        if not to_fetch:
            return out
        idx = self._index_for_kind(kind)
        if not idx or not self._ensure_index(idx):
            for v in to_fetch:
                self._cache[(kind, v)] = None
                out[v] = None
            return out
        for start in range(0, len(to_fetch), _MGET_CHUNK):
            chunk = to_fetch[start:start + _MGET_CHUNK]
            try:
                resp = self.es.mget(index=idx, body={"ids": chunk})
            except Exception as exc:                   # pragma: no cover
                log.warning(
                    "intel.lookup: mget chunk of %d failed: %s", len(chunk), exc,
                )
                for v in chunk:
                    self._cache[(kind, v)] = None
                    out[v] = None
                continue
            for doc in resp.get("docs") or []:
                v = doc.get("_id")
                if not v:
                    continue
                if doc.get("found"):
                    summary = IntelSummary.from_doc(doc.get("_source") or {})
                else:
                    summary = None
                self._cache[(kind, v)] = summary
                out[v] = summary
        return out

    # --- IP-only convenience (existing callers) -----------------------------

    def get_one_ip(self, ip: str) -> Optional[IntelSummary]:
        """Backward-compat shortcut for the IP path. Equivalent to `get_one('ip', ip)`."""
        return self.get_one("ip", ip)

    def get_many_ip(self, ips: list[str]) -> dict[str, Optional[IntelSummary]]:
        """Backward-compat shortcut for bulk IP fetches."""
        return self.get_many("ip", ips)

    # --- housekeeping -------------------------------------------------------

    def clear(self) -> None:
        """Drop cached state. Useful for long-running processes that
        want fresh data after an `intel refresh` pass elsewhere."""
        self._cache.clear()
        self._index_exists.clear()

    @property
    def cache_size(self) -> int:
        """Number of cached `(kind, value) -> summary` entries (including None misses)."""
        return len(self._cache)
