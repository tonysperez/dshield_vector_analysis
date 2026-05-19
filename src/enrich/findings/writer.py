"""Upsert findings docs while preserving analyst status.

The miner produces a fresh `evidence` block + score for each finding on
every run; the analyst's `status` / `status_history` / `first_seen_at`
must outlive the re-mine. This module enforces that contract: see
`upsert_finding`.

`finding_id` is content-addressed on `(kind, artifact_kind, artifact_value)`
so the same discovery across runs collapses onto one doc.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

log = logging.getLogger(__name__)


_VALID_STATUSES: frozenset[str] = frozenset({"new", "ack", "confirmed", "rejected"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_id(kind: str, artifact_kind: str, artifact_value: str) -> str:
    """Deterministic id: `find-<kind3>-<sha16(akind:avalue)>`.

    Two re-mines that produce the same finding pin to the same doc id,
    so the GET-then-upsert flow naturally preserves the analyst's
    triage state across runs.
    """
    h = hashlib.sha256(f"{artifact_kind}:{artifact_value}".encode("utf-8")).hexdigest()[:16]
    return f"find-{kind[:3]}-{h}"


def upsert_finding(
    es: Elasticsearch,
    index: str,
    *,
    finding: dict[str, Any],
) -> str:
    """Upsert a single finding, preserving analyst-managed fields.

    `finding` must contain at minimum: kind, artifact{kind,value},
    score, evidence, narrative, run_id. The writer:

    - Computes `finding_id` deterministically and uses it as the doc id.
    - Reads any existing doc to capture `status`, `status_history`,
      and `first_seen_at`. If absent, status defaults to `"new"`,
      history to `[]`, `first_seen_at` to now.
    - Writes the union: miner-owned fields from `finding`,
      analyst-owned fields carried forward from the existing doc.

    Returns the finding_id written.
    """
    kind = finding["kind"]
    artifact = finding["artifact"]
    fid = finding_id(kind, artifact["kind"], artifact["value"])

    try:
        existing = es.get(index=index, id=fid)
        src = existing.get("_source") or {}
    except Exception:
        src = {}

    status = src.get("status") or "new"
    status_history = src.get("status_history") or []
    first_seen_at = src.get("first_seen_at") or _now_iso()

    doc = {
        "finding_id":      fid,
        "kind":            kind,
        "run_id":          finding.get("run_id"),
        "artifact":        artifact,
        "score":           float(finding.get("score") or 0.0),
        "narrative":       finding.get("narrative") or "",
        "status":          status,
        "status_history":  status_history,
        "first_seen_at":   first_seen_at,
        "last_seen_at":    _now_iso(),
        "evidence":        finding.get("evidence") or {},
        "linked_artifacts": finding.get("linked_artifacts") or [],
    }
    es.index(index=index, id=fid, document=doc, refresh=False)
    return fid


def bulk_upsert_findings(
    es: Elasticsearch,
    index: str,
    findings: Iterable[dict[str, Any]],
    *,
    batch_size: int = 100,
) -> int:
    """Faster path for the miner — bulk-index after a single mget for
    existing analyst state. Returns the count successfully indexed.

    Order:
      1. compute every finding_id
      2. mget the existing docs in one round-trip
      3. merge analyst fields into the new docs
      4. bulk-index in batches

    The per-finding `upsert_finding` is kept for the status-mutation
    code path (the console PATCH endpoint) where bulk isn't needed.
    """
    findings = list(findings)
    if not findings:
        return 0

    ids: list[str] = []
    keyed: list[tuple[str, dict[str, Any]]] = []
    for f in findings:
        kind = f["kind"]
        a = f["artifact"]
        fid = finding_id(kind, a["kind"], a["value"])
        ids.append(fid)
        keyed.append((fid, f))

    existing_by_id: dict[str, dict[str, Any]] = {}
    try:
        resp = es.mget(index=index, ids=ids)
        for d in resp.get("docs") or []:
            if d.get("found"):
                existing_by_id[d["_id"]] = d.get("_source") or {}
    except Exception as exc:
        log.warning("findings: mget for analyst-state preservation failed: %s", exc)

    now = _now_iso()
    actions: list[dict[str, Any]] = []
    for fid, f in keyed:
        src = existing_by_id.get(fid) or {}
        doc = {
            "finding_id":      fid,
            "kind":            f["kind"],
            "run_id":          f.get("run_id"),
            "artifact":        f["artifact"],
            "score":           float(f.get("score") or 0.0),
            "narrative":       f.get("narrative") or "",
            "status":          src.get("status") or "new",
            "status_history":  src.get("status_history") or [],
            "first_seen_at":   src.get("first_seen_at") or now,
            "last_seen_at":    now,
            "evidence":        f.get("evidence") or {},
            "linked_artifacts": f.get("linked_artifacts") or [],
        }
        actions.append({"_op_type": "index", "_index": index, "_id": fid, "_source": doc})

    success = 0
    for i in range(0, len(actions), batch_size):
        chunk = actions[i:i + batch_size]
        try:
            ok, _ = bulk(es, chunk, raise_on_error=False, request_timeout=60)
            success += ok
        except Exception as exc:
            log.warning("findings bulk-index batch failed: %s", exc)
    return success


def mutate_status(
    es: Elasticsearch,
    index: str,
    finding_id_: str,
    *,
    new_status: str,
    note: str = "",
) -> dict[str, Any]:
    """Transition a finding's status. Appends a history entry; rejects
    unknown statuses. Returns the updated doc body.

    Called from the console's POST endpoint, not the miner.
    """
    if new_status not in _VALID_STATUSES:
        raise ValueError(f"invalid status: {new_status!r} (valid: {sorted(_VALID_STATUSES)})")
    try:
        resp = es.get(index=index, id=finding_id_)
    except Exception as exc:
        raise LookupError(f"finding not found: {finding_id_}") from exc
    src = resp.get("_source") or {}
    prev = src.get("status") or "new"
    if prev == new_status:
        return src
    history = src.get("status_history") or []
    history.append({
        "ts": _now_iso(),
        "from": prev,
        "to":   new_status,
        "note": note or "",
    })
    src["status"] = new_status
    src["status_history"] = history
    es.index(index=index, id=finding_id_, document=src, refresh="wait_for")
    return src


def valid_statuses() -> frozenset[str]:
    return _VALID_STATUSES
