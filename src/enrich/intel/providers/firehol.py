"""FireHOL Level 1 IP reputation aggregator.

FireHOL maintains a set of meta-blocklists that aggregate hundreds of
individual threat-intel feeds with quality tiers. Level 1 is the
strictest tier — entries that the maintainers consider safe to null-
route at a network edge, very low false-positive rate. Roughly a
few hundred to a few thousand entries (mix of single IPs and CIDR
ranges), refreshed continuously upstream and republished as a single
`firehol_level1.netset` file.

What it covers that overlaps Spamhaus's value for our use case:

  - Spamhaus DROP / EDROP equivalents (hijacked netblocks) are
    direct inputs to FireHOL Level 1.
  - CINS Army, BinaryDefense, AlienVault, EmergingThreats compromised
    hosts, etc. are also folded in.
  - Strictly broader coverage than Spamhaus zen.spamhaus.org for an
    SSH honeypot — Spamhaus weights mail-source listings heavily;
    FireHOL Level 1 weights generic attack sources.

No API key, no rate limit, no DNS-query-source restrictions. Single
plain-text netset, in-memory match.

File format:
  - Comments start with `#`.
  - Each non-blank, non-comment line is either a single IPv4 address
    or a CIDR (`a.b.c.d/N`).
  - IPv6 is not represented in Level 1 today; the parser handles it
    if it appears, but the lookup path for IPv4-only is the common
    case.

A hit returns `malicious=True`, `label="firehol_level1"`, confidence
8 (high — aggregator of consensus-grade feeds, but the level-1
threshold is curated, not LLM-bestowed). A miss returns no opinion.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import Optional

import httpx

from ..artifact import Artifact
from .base import (
    DerivedSignals,
    HealthStatus,
    Provider,
    ProviderResult,
    ProviderUnavailable,
    RateLimit,
)

log = logging.getLogger(__name__)


def parse_firehol_netset(text: str) -> tuple[set[str], list]:
    """Parse a FireHOL netset file into (exact-match IPs, CIDR networks).

    Pure function. Returns:
      - `exact_ips`: set of bare IP literals (string form). O(1) lookup.
      - `networks`: list of `ipaddress.IPv4Network|IPv6Network` for
        CIDR entries. Linear scan; fine for Level 1 (few hundred
        networks). If a future tier grows large enough to matter,
        swap for a radix trie or `netaddr.IPSet`.
    """
    exact_ips: set[str] = set()
    networks: list = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line:
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except (ValueError, TypeError):
                continue
        else:
            try:
                addr = ipaddress.ip_address(line)
            except (ValueError, TypeError):
                continue
            exact_ips.add(str(addr))
    return exact_ips, networks


def match_firehol(
    ip_value: str, exact_ips: set[str], networks: list,
) -> tuple[bool, Optional[str]]:
    """Look up `ip_value`. Returns `(matched, matched_network_or_None)`.

    Exact-IP hits return `(True, None)` since the match is the literal
    address. CIDR hits return `(True, "a.b.c.d/N")` so we can surface
    which network the IP fell into — useful when the analyst wants to
    audit why something was flagged.
    """
    if ip_value in exact_ips:
        return True, None
    try:
        addr = ipaddress.ip_address(ip_value)
    except (ValueError, TypeError):
        return False, None
    for net in networks:
        if addr.version != net.version:
            continue
        if addr in net:
            return True, str(net)
    return False, None


class FireholProvider(Provider):
    name = "firehol"
    handles = frozenset({"ip"})
    ttl = timedelta(days=1)
    rate_limit = RateLimit(capacity=1000, refill_per_second=1000.0, daily_budget=None)

    def __init__(self, provider_cfg) -> None:
        super().__init__(provider_cfg)
        self._exact_ips: set[str] = set()
        self._networks: list = []
        self._loaded_at: float = 0.0
        self._lock = threading.Lock()

    def _stale(self) -> bool:
        return (
            (not self._exact_ips and not self._networks)
            or (time.time() - self._loaded_at) >= self.cfg.refresh_minutes * 60
        )

    def _load_from_cache_file(self) -> Optional[str]:
        p = Path(self.cfg.cache_file)
        if not p.exists():
            return None
        try:
            stat = p.stat()
        except OSError:
            return None
        if (time.time() - stat.st_mtime) > self.cfg.refresh_minutes * 60:
            return None
        try:
            return p.read_text()
        except OSError:
            return None

    def _save_cache_file(self, text: str) -> None:
        p = Path(self.cfg.cache_file)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        except OSError as exc:                       # pragma: no cover
            log.warning("firehol: persist cache failed %s: %s", p, exc)

    def _fetch_remote(self) -> str:
        try:
            r = httpx.get(self.cfg.feed_url, timeout=30.0)
            r.raise_for_status()
        except (httpx.HTTPError, httpx.RequestError) as exc:
            raise ProviderUnavailable(
                f"firehol: fetch {self.cfg.feed_url}: {exc}",
            ) from exc
        return r.text

    def _ensure_loaded(self) -> None:
        if not self._stale():
            return
        with self._lock:
            if not self._stale():
                return
            cached_text = self._load_from_cache_file()
            if cached_text is not None:
                self._exact_ips, self._networks = parse_firehol_netset(cached_text)
                self._loaded_at = time.time()
                return
            text = self._fetch_remote()
            self._exact_ips, self._networks = parse_firehol_netset(text)
            self._loaded_at = time.time()
            self._save_cache_file(text)

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind != "ip":
            raise ValueError(f"firehol: cannot handle kind {artifact.kind!r}")
        self._ensure_loaded()
        matched, matched_net = match_firehol(
            artifact.value, self._exact_ips, self._networks,
        )
        if not matched:
            derived = DerivedSignals(
                malicious=None, confidence=None, label=None, tags=(),
            )
            structured = {
                "matched": False,
                "matched_net": None,
                "list_size_ips": len(self._exact_ips),
                "list_size_nets": len(self._networks),
            }
        else:
            derived = DerivedSignals(
                malicious=True,
                confidence=8,                          # aggregator-of-consensus, strict tier
                label="firehol_level1",
                tags=("firehol_level1",),
            )
            structured = {
                "matched": True,
                "matched_net": matched_net,           # CIDR string when CIDR match, else null
                "list_size_ips": len(self._exact_ips),
                "list_size_nets": len(self._networks),
            }
        return ProviderResult.make(
            provider=self.name,
            artifact=artifact,
            structured=structured,
            raw={"matched": matched, "matched_net": matched_net},
            derived=derived,
            ttl=self.ttl,
        )

    def health(self) -> HealthStatus:
        try:
            self._ensure_loaded()
        except ProviderUnavailable as exc:
            return HealthStatus(ok=False, detail=str(exc))
        return HealthStatus(
            ok=True,
            detail=(
                f"firehol level1 loaded: "
                f"{len(self._exact_ips)} exact + {len(self._networks)} CIDR"
            ),
            extra={
                "list_size_ips": len(self._exact_ips),
                "list_size_nets": len(self._networks),
            },
        )
