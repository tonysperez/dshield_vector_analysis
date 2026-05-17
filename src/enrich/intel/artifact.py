"""Artifact abstraction.

An *artifact* is something we want to look up against external threat
intelligence feeds. Every artifact has a `kind` (ip / url / domain /
hash / asn / ssh_key / cred_tuple) and a canonical `value`. Providers
declare which kinds they handle; the queue dispatches accordingly.

This module is pure-function. No network, no state, no LLM. Smoke
tests live at `scripts/smoke_test_intel_artifact.py`.

Milestone 1 ships only `ip` end-to-end; the other kinds are parsed +
canonicalised but writers / providers come later.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urlsplit, urlunsplit


# Order matters for stable serialisation in derived signals.
ARTIFACT_KINDS: tuple[str, ...] = (
    "ip",
    "url",
    "domain",
    "hash",
    "asn",
    "ssh_key",
    "cred_tuple",
)


@dataclass(frozen=True)
class Artifact:
    """Canonical (kind, value) pair. Hashable, equality by both fields."""
    kind: str
    value: str

    def __post_init__(self) -> None:
        if self.kind not in ARTIFACT_KINDS:
            raise ValueError(f"unknown artifact kind: {self.kind!r}")
        if not self.value:
            raise ValueError("artifact value is empty")

    @property
    def id(self) -> str:
        """Stable id for the artifact across indices. `<kind>:<value>`."""
        return f"{self.kind}:{self.value}"


# ---------------------------------------------------------------------------
# Canonicalisers — input -> canonical Artifact, or None when the input is
# unparseable / non-IOC. These are the gatekeepers that prevent garbage
# from reaching the queue or the intel indices.
# ---------------------------------------------------------------------------


def canonical_ip(raw: str) -> Optional[str]:
    """Validate + canonicalise an IP literal. Returns None on failure.

    Accepts IPv4 and IPv6. Strips surrounding whitespace, lowercases
    (matters for IPv6). Rejects private / loopback / link-local /
    multicast / reserved per `ipaddress.IPv*Address.is_*` predicates
    — never query these against external TI feeds.
    """
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except (ValueError, TypeError):
        return None
    # Filter never-query categories. We do not look up RFC1918, loopback,
    # link-local, multicast, reserved, or unspecified addresses against
    # external services. Operator's own egress also needs to be filtered
    # but that's runtime config, not address-class.
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return None
    return str(ip)


def canonical_domain(raw: str) -> Optional[str]:
    """Validate + canonicalise a domain. Lowercased, trailing dot stripped.

    Rejects values containing slashes, scheme markers, or whitespace.
    Single-label inputs (no dot) are rejected — they're rarely a real
    domain in attacker context and almost always a tokenisation artifact.
    """
    if raw is None:
        return None
    s = raw.strip().lower().rstrip(".")
    if not s or "/" in s or "://" in s or " " in s or "\t" in s:
        return None
    if "." not in s:
        return None
    # Each label 1-63 chars, alnum + hyphen, no leading/trailing hyphen.
    # Total length <= 253.
    if len(s) > 253:
        return None
    label_re = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    for label in s.split("."):
        if not label_re.match(label):
            return None
    return s


def canonical_url(raw: str) -> Optional[str]:
    """Canonicalise a URL: scheme + host + path. Query and fragment dropped.

    Dropping the query string matches the existing campaign-miner URL
    normalisation goal (ROADMAP gap: `host/path?id=1` vs `?id=2`
    fragmenting a real campaign). Also strips defaults port 80/443 from
    the host, and lowercases the host. Path is preserved as-is.
    """
    if raw is None:
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
    return urlunsplit((scheme, netloc, path, "", ""))


_HASH_RE = re.compile(r"^[A-Fa-f0-9]+$")


def canonical_hash(raw: str) -> Optional[str]:
    """Canonicalise a file hash. Must be exactly 32 / 40 / 64 hex chars."""
    if raw is None:
        return None
    s = raw.strip().lower()
    if len(s) not in (32, 40, 64):
        return None
    if not _HASH_RE.match(s):
        return None
    return s


_CANONICALIZERS = {
    "ip": canonical_ip,
    "url": canonical_url,
    "domain": canonical_domain,
    "hash": canonical_hash,
}


def make_artifact(kind: str, raw: str) -> Optional[Artifact]:
    """Canonicalise + wrap, or None when canonicalisation rejects.

    Single entry point used by the artifact-discovery scan over the
    project-owned indices. New kinds slot in by adding a canonicaliser
    to `_CANONICALIZERS`.
    """
    fn = _CANONICALIZERS.get(kind)
    if fn is None:
        return None
    canon = fn(raw)
    if canon is None:
        return None
    return Artifact(kind=kind, value=canon)


def dedupe_artifacts(items: Iterable[Artifact]) -> list[Artifact]:
    """Order-preserving dedupe — yields in first-seen order."""
    seen: set[tuple[str, str]] = set()
    out: list[Artifact] = []
    for a in items:
        key = (a.kind, a.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


def is_in_cidrs(ip_value: str, cidrs: Iterable[str]) -> bool:
    """Membership test: is `ip_value` within any of the given CIDR ranges.

    Used to enforce `intel.never_query_cidrs` — operator's home network,
    egress IP, peer research sensors, etc. Silently returns False on
    parse errors (an invalid CIDR in config shouldn't break the gate
    on the well-formed entries).
    """
    try:
        addr = ipaddress.ip_address(ip_value)
    except (ValueError, TypeError):
        return False
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            continue
        if addr in net:
            return True
    return False
