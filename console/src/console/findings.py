"""Console-side queries for the M5 findings page.

Read-only against `prism.finding` (list, filter, sort) and
the IP rollup + intel-ip indices (calibration scatter). Status
mutations are handled inline by the `/api/finding/{id}/status` route
in `server.py`, which calls into the parent package's writer to keep
the upsert + history-append logic in one place.

The miner writes; the console reads. The only mutation the console
performs is the analyst's status change, and that's surfaced via a
single explicit endpoint.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


_VALID_STATUSES: frozenset[str] = frozenset({"new", "ack", "confirmed", "rejected"})
_VALID_KINDS: frozenset[str] = frozenset({"playbook", "campaign"})


def list_findings(
    es, cfg, *,
    status: Optional[list[str]] = None,
    kind: Optional[str] = None,
    size: int = 100,
    frm: int = 0,
    sort: str = "score",
) -> dict[str, Any]:
    """Paginated findings list.

    Filters:
      - `status`: list of valid statuses (default: ["new"] — the
        analyst's inbox; explicit `[]` returns everything).
      - `kind`: optional single kind.

    Sort:
      - `score` (desc) — default; ranks the most interesting first.
      - `last_seen` (desc) — recency.
      - `first_seen` (desc) — discovery age.

    Returns `{total, rows, page: {from, size}}` where each row is the
    finding's _source augmented with `_id` for client convenience.
    """
    idx = cfg.findings.indexes.default
    if not es.indices.exists(index=idx):
        return {"total": 0, "rows": [], "page": {"from": frm, "size": size},
                "index_missing": True}

    must: list[dict] = []
    if status is None:
        status = ["new"]
    if status:
        must.append({"terms": {"status": status}})
    if kind:
        if kind not in _VALID_KINDS:
            raise ValueError(f"invalid kind: {kind!r}")
        must.append({"term": {"kind": kind}})

    sort_clause: list[dict]
    if sort == "last_seen":
        sort_clause = [{"last_seen_at": {"order": "desc"}}]
    elif sort == "first_seen":
        sort_clause = [{"first_seen_at": {"order": "desc"}}]
    else:
        sort_clause = [{"score": {"order": "desc"}}, {"last_seen_at": {"order": "desc"}}]

    body = {
        "size": size, "from": frm,
        "query": {"bool": {"must": must or [{"match_all": {}}]}},
        "sort": sort_clause,
    }
    try:
        resp = es.search(index=idx, **body)
    except Exception as exc:
        log.warning("findings: list query failed: %s", exc)
        return {"total": 0, "rows": [], "page": {"from": frm, "size": size},
                "error": str(exc)}

    hits = resp.get("hits", {})
    rows = []
    for h in hits.get("hits", []):
        src = h.get("_source") or {}
        src["_id"] = h.get("_id")
        rows.append(src)
    total = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else 0
    return {"total": total, "rows": rows, "page": {"from": frm, "size": size}}


def status_counts(es, cfg) -> dict[str, int]:
    """Counts per status across all findings. Cheap aggregation —
    drives the page's status filter chips."""
    idx = cfg.findings.indexes.default
    if not es.indices.exists(index=idx):
        return {}
    try:
        resp = es.search(
            index=idx, size=0,
            aggs={"by_status": {"terms": {"field": "status", "size": 10}}},
        )
    except Exception as exc:
        log.warning("findings: status_counts failed: %s", exc)
        return {}
    buckets = resp.get("aggregations", {}).get("by_status", {}).get("buckets", []) or []
    return {b["key"]: int(b["doc_count"]) for b in buckets}


def kind_counts(es, cfg, *, status: Optional[list[str]] = None) -> dict[str, int]:
    """Per-kind counts, optionally constrained by status. Drives the
    kind filter."""
    idx = cfg.findings.indexes.default
    if not es.indices.exists(index=idx):
        return {}
    must: list[dict] = []
    if status:
        must.append({"terms": {"status": status}})
    try:
        resp = es.search(
            index=idx, size=0,
            query={"bool": {"must": must or [{"match_all": {}}]}},
            aggs={"by_kind": {"terms": {"field": "kind", "size": 10}}},
        )
    except Exception as exc:
        log.warning("findings: kind_counts failed: %s", exc)
        return {}
    buckets = resp.get("aggregations", {}).get("by_kind", {}).get("buckets", []) or []
    return {b["key"]: int(b["doc_count"]) for b in buckets}


def get_finding(es, cfg, finding_id: str) -> Optional[dict[str, Any]]:
    """Single-finding detail. Returns None if missing."""
    idx = cfg.findings.indexes.default
    try:
        resp = es.get(index=idx, id=finding_id)
    except Exception:
        return None
    src = resp.get("_source") or {}
    src["_id"] = resp.get("_id")
    return src


def valid_statuses() -> frozenset[str]:
    return _VALID_STATUSES


def valid_kinds() -> frozenset[str]:
    return _VALID_KINDS
