"""Console-side intel pane backend.

Reads from the project-owned `intel-*-default` indices written by
`enrich.cli intel refresh`. Joins the per-artifact intel doc with the
corresponding rollup record so the artifact pane can show local
observations + external opinions side-by-side.

Soft-degrades when intel hasn't been deployed yet — the page renders
the local-observations half and a "no intel data" placeholder for
the providers panel.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


def _canonical_ip(raw: str) -> Optional[str]:
    """Local copy of `enrich.intel.artifact.canonical_ip`.

    Console must not depend on the enrich package — `_config.py`
    already documents that. Mirrors the parent's never-query filter
    so the artifact pane refuses to render anything we'd never look
    up.
    """
    s = (raw or "").strip()
    if not s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except (ValueError, TypeError):
        return None
    if (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    ):
        return None
    return str(ip)


def fetch_intel_ip(es, cfg, value: str) -> dict[str, Any]:
    """Return the joined view for an IP artifact.

    Shape:
    {
      "artifact": {"kind": "ip", "value": "<ip>"},
      "intel":       <intel doc body or None>,
      "rollup":      <IP rollup doc body or None>,
      "intel_index_exists": bool,
      "rollup_index_exists": bool,
    }
    """
    canon = _canonical_ip(value)
    if canon is None:
        return {
            "artifact": {"kind": "ip", "value": value},
            "intel": None,
            "rollup": None,
            "intel_index_exists": False,
            "rollup_index_exists": False,
            "rejected_reason": "value not a public IP (canonicaliser refused)",
        }

    out: dict[str, Any] = {
        "artifact": {"kind": "ip", "value": canon},
        "intel": None,
        "rollup": None,
        "intel_index_exists": False,
        "rollup_index_exists": False,
    }

    intel_idx = cfg.intel.indexes.ip
    try:
        if es.indices.exists(index=intel_idx):
            out["intel_index_exists"] = True
            resp = es.get(index=intel_idx, id=canon, ignore=[404])
            if resp.get("found"):
                out["intel"] = resp.get("_source")
    except Exception as exc:                           # pragma: no cover
        log.warning("console.intel: intel GET failed for %s: %s", canon, exc)

    rollup_idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    try:
        if es.indices.exists(index=rollup_idx):
            out["rollup_index_exists"] = True
            # IP rollup docs are keyed by source.ip via _id (see
            # ips.py:_build_ip_doc); fall back to a search if direct
            # get misses (some older docs may not be _id-keyed).
            resp = es.get(index=rollup_idx, id=canon, ignore=[404])
            if resp.get("found"):
                out["rollup"] = resp.get("_source")
            else:
                search = es.search(
                    index=rollup_idx,
                    size=1,
                    query={"term": {"source.ip": canon}},
                )
                hits = (search.get("hits") or {}).get("hits") or []
                if hits:
                    out["rollup"] = hits[0].get("_source")
    except Exception as exc:                           # pragma: no cover
        log.warning("console.intel: rollup GET failed for %s: %s", canon, exc)

    return out
