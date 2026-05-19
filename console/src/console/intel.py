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
from urllib.parse import urlsplit

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


# ---------------------------------------------------------------------------
# M4: URL artifact pane backend.
# ---------------------------------------------------------------------------


def _canonical_url(raw: str) -> Optional[str]:
    """Local copy of `enrich.intel.artifact.canonical_url` — keeps the
    console package free of cross-package imports.

    Strips query + fragment, lowercases host, drops default ports.
    Returns None on unrecognised scheme / missing host / parse error.
    """
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    try:
        parts = urlsplit(s)
    except (ValueError, TypeError):
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https", "ftp", "tftp"):
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    port = parts.port
    if port in (None, 80, 443):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return f"{scheme}://{netloc}{path}"


def _extract_host_ip(url: str) -> Optional[str]:
    """If the URL's host is an IP literal (not a domain), return its
    canonical form for cross-reference against the IP intel store.

    Returns None when the host is a domain (requires passive DNS to
    resolve to an IP — out of scope for M4). Most observed Cowrie C2
    URLs in this corpus use IP-literal hosts (Mirai-style hardcoded
    droppers), which is what makes the cross-reference cheap.
    """
    try:
        parts = urlsplit(url)
    except (ValueError, TypeError):
        return None
    host = parts.hostname
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except (ValueError, TypeError):
        return None


def _enrichment_docs_for_url(es, cfg, canon_url: str) -> list[dict]:
    """Return enrichment-command docs that reference `canon_url` as a
    `threat.indicator.type=url`. URLhaus may keep query strings; the
    enriched index strips them via canonicalisation, so we match the
    canonical form first and fall back to a wildcard URL match.

    Used by the artifact pane to surface "which commands actually
    ran this URL" — the local-observations equivalent of source IPs
    on the IP artifact pane.
    """
    cmds_idx = cfg.elasticsearch.indexes.cowrie.commands
    if not es.indices.exists(index=cmds_idx):
        return []
    try:
        resp = es.search(
            index=cmds_idx, size=20,
            query={"nested": {
                "path": "threat.indicator",
                "query": {"term": {"threat.indicator.url.full": canon_url}},
            }},
            _source=["process.command_line", "@timestamp",
                     "dshield.cowrie.enrichment.occurrence_count",
                     "dshield.cowrie.enrichment.unique_source_ips",
                     "dshield.cowrie.enrichment.intent"],
            sort=[{"@timestamp": "desc"}],
        )
    except Exception as exc:                           # pragma: no cover
        log.warning("console.intel: URL→commands lookup failed: %s", exc)
        return []
    return [h.get("_source") or {} for h in resp.get("hits", {}).get("hits", [])]


def fetch_intel_url(es, cfg, value: str) -> dict[str, Any]:
    """Return the joined view for a URL artifact.

    Shape:
    {
      "artifact": {"kind": "url", "value": "<canon url>"},
      "intel":              <intel-url doc body or None>,
      "intel_index_exists": bool,
      "host_ip":            <ip literal, or None when host is a domain>,
      "host_ip_intel":      <intel-ip doc body for the host, or None>,
      "host_ip_index_exists": bool,
      "command_docs":       [<recent enriched commands that ran this URL>],
    }

    The host-IP cross-reference is the M4 design point — most C2
    dropper URLs in the corpus use IP-literal hosts, and those IPs
    already have intel data from M1/M2. The pane shows the URL's
    own verdict alongside its host's verdict so the analyst doesn't
    have to multi-hop.
    """
    canon = _canonical_url(value)
    if canon is None:
        return {
            "artifact": {"kind": "url", "value": value},
            "intel": None, "host_ip": None, "host_ip_intel": None,
            "intel_index_exists": False, "host_ip_index_exists": False,
            "command_docs": [],
            "rejected_reason": "value not a recognised URL (canonicaliser refused)",
        }

    out: dict[str, Any] = {
        "artifact": {"kind": "url", "value": canon},
        "intel": None,
        "host_ip": None,
        "host_ip_intel": None,
        "intel_index_exists": False,
        "host_ip_index_exists": False,
        "command_docs": [],
    }

    intel_idx = cfg.intel.indexes.url
    try:
        if es.indices.exists(index=intel_idx):
            out["intel_index_exists"] = True
            resp = es.get(index=intel_idx, id=canon, ignore=[404])
            if resp.get("found"):
                out["intel"] = resp.get("_source")
    except Exception as exc:                           # pragma: no cover
        log.warning("console.intel: URL intel GET %s failed: %s", canon, exc)

    # M4: cross-reference the host IP against prism.intel.ip.
    host_ip = _extract_host_ip(canon)
    if host_ip:
        out["host_ip"] = host_ip
        ip_idx = cfg.intel.indexes.ip
        try:
            if es.indices.exists(index=ip_idx):
                out["host_ip_index_exists"] = True
                resp = es.get(index=ip_idx, id=host_ip, ignore=[404])
                if resp.get("found"):
                    out["host_ip_intel"] = resp.get("_source")
        except Exception as exc:                       # pragma: no cover
            log.warning("console.intel: host-IP intel GET %s failed: %s", host_ip, exc)

    # Local observations: which enrichment-command docs reference this URL.
    out["command_docs"] = _enrichment_docs_for_url(es, cfg, canon)
    return out
