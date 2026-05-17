"""abuse.ch URLhaus provider — known-malicious URL block list.

URLhaus publishes a continuously-updated list of URLs hosting malware
payloads. Same operator family as FeodoTracker / ThreatFox /
MalwareBazaar — no API key, no per-IP rate limit, HTTP bulk download
once per refresh window. The `csv_online` endpoint pre-filters to
URLs whose status is "online" right now, which is the high-precision
slice for our use case (vs the broader historical list).

Per-row CSV columns (as of 2026):
    id, dateadded, url, url_status, last_online, threat, tags,
    urlhaus_link, reporter

For our purposes:
    - `url` (column 3) — the URL value
    - `url_status` ("online" / "offline")
    - `threat` ("malware_download" etc.)
    - `tags` (comma-separated tags like "elf,mirai")

A hit yields `malicious=True, label="urlhaus_<threat>"`, with tags
joined as DerivedSignals tags. Confidence 9 — URLhaus curation is
high-precision.

No `evidence_direct=True`: URLhaus aggregates community submissions
(though they're well-curated). Mirrors the FireHOL semantics on the
IP side — known-bad aggregator that participates in any-positive
consensus but doesn't override authoritative_clean.
"""
from __future__ import annotations

import csv
import io
import logging
import re
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


# Column names in a URLhaus CSV header must look like identifiers
# (lowercase + alphanumeric + underscore). Real header is
# `id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter`.
# This regex distinguishes a real header from a documentation line that
# happens to contain commas + the word "url" inside descriptive text
# like `# Format: id,dateadded,url,...`.
_HEADER_COL_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def parse_urlhaus_csv(text: str) -> dict[str, dict[str, str]]:
    """Parse the URLhaus `csv_online` body into `{url: row}`.

    URLhaus's CSV format prefixes EVERY documentation line with `#`,
    INCLUDING the column-header line (e.g.
    `# id,dateadded,url,url_status,...`). Naively dropping every
    `#`-prefixed line therefore drops the header along with the
    preamble. Defensive parser:

      1. Walk lines looking for one that — after stripping its
         leading `#` and spaces — looks like a CSV header
         (contains "url" as a column).
      2. Once found, parse all subsequent non-`#`-prefixed lines
         as data rows against that header.

    Handles both shapes: `#`-prefixed-header URLhaus (the canonical
    `csv_online` format) and a hypothetical no-`#` variant. Returns
    `{}` defensively on truly malformed input.
    """
    if not text:
        return {}
    lines = text.splitlines()

    def _looks_like_header(cols: list[str]) -> bool:
        # Strict: every column must be an identifier-shaped name
        # AND `url` must be one of them. Filters documentation
        # lines like `# Format: id,dateadded,url,...` where
        # `Format: id` would be the first "column" and fails the
        # regex.
        return bool(cols) and "url" in cols and all(
            _HEADER_COL_RE.match(c) for c in cols
        )

    # Step 1: locate the header — the LAST `#`-prefixed line whose
    # stripped form parses as a clean identifier-only CSV header.
    header: Optional[list[str]] = None
    data_start_idx = len(lines)
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            # First non-`#` line — header should already be set by a
            # prior iteration. If not, fall back to trying THIS line
            # as a header in case some upstream variant doesn't use
            # `#` (defensive; canonical URLhaus always does).
            if header is None:
                try:
                    row = next(csv.reader([stripped], quotechar='"',
                                          skipinitialspace=True))
                except (StopIteration, csv.Error):
                    row = []
                cols = [c.strip().lower() for c in row]
                if _looks_like_header(cols):
                    header = cols
                    data_start_idx = i + 1
                else:
                    data_start_idx = i
            else:
                data_start_idx = i
            break
        # `#`-prefixed candidate — try as header. Track the
        # most-recent match in case the file has multiple comment
        # blocks separated by an empty `#` line.
        candidate = stripped.lstrip("#").strip()
        if "," not in candidate:
            continue
        try:
            row = next(csv.reader([candidate], quotechar='"',
                                  skipinitialspace=True))
        except (StopIteration, csv.Error):
            continue
        cols = [c.strip().lower() for c in row]
        if _looks_like_header(cols):
            header = cols
            data_start_idx = i + 1

    if header is None:
        return {}

    # Step 2: parse data rows.
    data_lines = [
        raw.strip() for raw in lines[data_start_idx:]
        if raw.strip() and not raw.strip().startswith("#")
    ]
    out: dict[str, dict[str, str]] = {}
    reader = csv.reader(data_lines, quotechar='"', skipinitialspace=True)
    for row in reader:
        if not row or len(row) != len(header):
            continue
        entry = {header[i]: row[i] for i in range(len(header))}
        url = entry.get("url", "").strip()
        if not url:
            continue
        out[url] = entry
    return out


# URLhaus row values that mean "no tag set" rather than a real tag.
# Their CSV uses the literal string `None` for empty cells in tags-like
# columns; lowercasing it gives `none`, which would otherwise leak
# into DerivedSignals as a junk tag.
_URLHAUS_EMPTY_SENTINELS: frozenset[str] = frozenset({"", "none", "null"})


def classify_urlhaus(
    in_urlhaus: bool, threat: Optional[str], tags: tuple[str, ...],
) -> tuple[Optional[bool], Optional[str], Optional[int], tuple[str, ...], bool, bool]:
    """Pure-function: URLhaus per-URL hit data → DerivedSignals fields.

    Returns `(malicious, label, confidence, tags, authoritative_clean,
    evidence_direct)`.

    - Hit → `malicious=True`, `label="urlhaus_<threat>"`, confidence 9.
    - Miss → no opinion (None / False / empty).

    Filters URLhaus's `None`/`null`/empty sentinel values out of the
    tag list — they're the upstream "this column is empty" marker,
    not real tags.
    """
    if not in_urlhaus:
        return None, None, None, (), False, False
    threat_label = (threat or "").strip().lower()
    if threat_label in _URLHAUS_EMPTY_SENTINELS:
        threat_label = "unknown"
    label = f"urlhaus_{threat_label}"
    all_tags = ["urlhaus_match"]
    if threat_label != "unknown":
        all_tags.append(f"urlhaus_threat_{threat_label}")
    for t in tags:
        t_norm = (t or "").strip().lower()
        if t_norm and t_norm not in _URLHAUS_EMPTY_SENTINELS:
            all_tags.append(t_norm)
    return True, label, 9, tuple(all_tags), False, False


class URLhausProvider(Provider):
    name = "urlhaus"
    handles = frozenset({"url"})
    ttl = timedelta(days=1)
    rate_limit = RateLimit(capacity=1000, refill_per_second=1000.0, daily_budget=None)

    def __init__(self, provider_cfg, auth_key: Optional[str] = None) -> None:
        super().__init__(provider_cfg)
        self._rows: dict[str, dict[str, str]] = {}
        self._loaded_at: float = 0.0
        self._lock = threading.Lock()
        # abuse.ch unified auth — same key as ThreatFox / FeodoTracker.
        # Used as the `Auth-Key` header on the bulk-download fetch.
        # When None, falls back to unauthenticated download at lower
        # rate limits.
        self._auth_key = auth_key
        self._authenticated = bool(auth_key)

    def _stale(self) -> bool:
        return (
            not self._rows
            or (time.time() - self._loaded_at) >= self.cfg.refresh_minutes * 60
        )

    def _load_from_cache_file(self) -> Optional[dict[str, dict[str, str]]]:
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
            return parse_urlhaus_csv(p.read_text())
        except OSError:
            return None

    def _save_cache_file(self, text: str) -> None:
        p = Path(self.cfg.cache_file)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        except OSError as exc:                         # pragma: no cover
            log.warning("urlhaus: persist cache failed %s: %s", p, exc)

    def _fetch_remote(self) -> tuple[dict[str, dict[str, str]], str]:
        headers = {"User-Agent": "dshield_prism/intel (urlhaus)"}
        if self._auth_key:
            headers["Auth-Key"] = self._auth_key
        try:
            r = httpx.get(self.cfg.feed_url, headers=headers, timeout=30.0)
            r.raise_for_status()
        except (httpx.HTTPError, httpx.RequestError) as exc:
            raise ProviderUnavailable(
                f"urlhaus: fetch {self.cfg.feed_url}: {exc}",
            ) from exc
        return parse_urlhaus_csv(r.text), r.text

    def _ensure_loaded(self) -> None:
        if not self._stale():
            return
        with self._lock:
            if not self._stale():
                return
            cached = self._load_from_cache_file()
            if cached is not None:
                self._rows = cached
                self._loaded_at = time.time()
                return
            parsed, raw = self._fetch_remote()
            self._rows = parsed
            self._loaded_at = time.time()
            self._save_cache_file(raw)

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind != "url":
            raise ValueError(f"urlhaus: cannot handle kind {artifact.kind!r}")
        self._ensure_loaded()
        # URLhaus stores URLs in their canonical form too — typically
        # with query strings intact. We match against the value as-is;
        # the discovery side strips query strings (per canonical_url),
        # so a URLhaus entry like `host/path?q=1` may not match a
        # canonicalised `host/path`. Try both shapes.
        row = self._rows.get(artifact.value)
        if row is None:
            # Try with a trailing slash variant — URLhaus is inconsistent.
            alt = artifact.value + "/"
            row = self._rows.get(alt)
        if row is None:
            derived = DerivedSignals(
                malicious=None, confidence=None, label=None,
                tags=(), authoritative_clean=False, evidence_direct=False,
            )
            structured = {"in_urlhaus": False, "list_size": len(self._rows)}
            raw_payload = {"row": None}
        else:
            # URLhaus uses the literal `None` string when no tags
            # are set on a row. Treat that as no tags rather than
            # carrying a junk `'None'` entry into structured + tags.
            tags_raw = (row.get("tags") or "").split(",")
            tags = tuple(
                t.strip() for t in tags_raw
                if t.strip() and t.strip().lower() not in _URLHAUS_EMPTY_SENTINELS
            )
            threat = row.get("threat") or None
            if threat and threat.strip().lower() in _URLHAUS_EMPTY_SENTINELS:
                threat = None
            (malicious, label, confidence, derived_tags,
             ac, ed) = classify_urlhaus(in_urlhaus=True, threat=threat, tags=tags)
            derived = DerivedSignals(
                malicious=malicious, confidence=confidence, label=label,
                tags=derived_tags, authoritative_clean=ac, evidence_direct=ed,
            )
            structured = {
                "in_urlhaus": True,
                "threat": threat,
                "tags": list(tags),
                "url_status": row.get("url_status"),
                "first_seen": row.get("dateadded"),
                "list_size": len(self._rows),
            }
            raw_payload = {"row": row}
        return ProviderResult.make(
            provider=self.name,
            artifact=artifact,
            structured=structured,
            raw=raw_payload,
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
            detail=f"urlhaus loaded: {len(self._rows)} online malware URLs",
            extra={"list_size": len(self._rows)},
        )
