"""IOC type detection from a free-form search string.

Resolves a query into one or more candidate (type, id) tuples. The server's
/api/search uses this to short-circuit when the query unambiguously matches a
typed pattern (IP, sha256, MITRE id, ASN, country) and falls back to an ES
search across command_line / playbook_name / campaign `name` otherwise.
The campaigns index uses a bare `name` field (not `campaign_name`).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable


# Canonical type strings used everywhere in the API.
TYPES = (
    "ip",
    "session",
    "command",          # by hash (canonical command identifier)
    "command_hash",     # alias for command, kept for clarity in URLs
    "playbook",         # named group of 1+ session clusters — anchored by
                        # playbook_id (`sescl-<16hex>`, content-hashed over
                        # the sorted member-session-id set).
    "campaign",         # multi-session pattern mined by `mine campaigns`
                        # — anchored by campaign_id (`cmp-bhv-...` / `cmp-inf-...`).
    "command_cluster",
    "session_cluster",
    "ip_cluster",
    "mitre_tactic",
    "mitre_technique",
    "asn",
    "country",
    "freetext",         # fallback: server multi-field text search
)


@dataclass(frozen=True)
class IOCRef:
    type: str
    id: str
    label: str | None = None


_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_MITRE_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_MITRE_TACTIC = re.compile(r"^TA\d{4}$")
_ASN = re.compile(r"^AS(\d+)$", re.IGNORECASE)
# Cowrie session ids are typically 12 alphanumerics.
_SESSION_ID = re.compile(r"^[a-z0-9]{12}$")
# Cluster ids written by this pipeline are stringified ints. Disambiguated by
# context (which kind) via dropdown — see detect().
_CLUSTER_ID   = re.compile(r"^-?\d+$")
_CLUSTER_NAME = re.compile(r"^(cluster_\d+|outlier)$", re.IGNORECASE)
# ISO 3166 alpha-2 country codes (validated against the static set below).
_COUNTRY = re.compile(r"^[A-Za-z]{2}$")

_ISO3166_ALPHA2 = {
    # Truncated to the codes we're most likely to see; the regex still matches
    # any 2 letters and we let unknown codes through as 'country' with a hint.
    "US","CN","RU","DE","NL","FR","GB","BR","JP","KR","SG","HK","IN","CA",
    "AU","IT","ES","PL","UA","TR","IR","VN","TH","ID","MX","AR","ZA","NG",
    "EG","SA","AE","IL","CH","SE","NO","FI","DK","BE","IE","CZ","AT","PT",
    "RO","BG","HU","GR","TW","PH","MY","PK","BD","NZ","CL","CO","PE","KZ",
}


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def detect(query: str) -> list[IOCRef]:
    """Return candidate IOC refs from the query string.

    For unambiguous typed patterns (IP, sha256, MITRE, ASN), returns exactly
    one IOCRef. For ambiguous patterns (a bare integer that could be any
    cluster kind), returns one IOCRef per candidate kind. For everything else,
    returns a single 'freetext' IOCRef so the server falls back to a multi-
    field ES search.
    """
    q = (query or "").strip()
    if not q:
        return []

    if _is_ip(q):
        return [IOCRef(type="ip", id=q, label=q)]

    if _SHA256.match(q):
        return [IOCRef(type="command_hash", id=q.lower(), label=q[:12] + "…")]

    if _MITRE_TECHNIQUE.match(q):
        return [IOCRef(type="mitre_technique", id=q.upper(), label=q.upper())]
    if _MITRE_TACTIC.match(q):
        return [IOCRef(type="mitre_tactic", id=q.upper(), label=q.upper())]

    m = _ASN.match(q)
    if m:
        return [IOCRef(type="asn", id=m.group(1), label=f"AS{m.group(1)}")]

    if _COUNTRY.match(q) and q.upper() in _ISO3166_ALPHA2:
        return [IOCRef(type="country", id=q.upper(), label=q.upper())]

    if _SESSION_ID.match(q):
        # Could be a session_id; also could collide with a hash prefix. The
        # server will verify by attempting a lookup. We return both 'session'
        # and 'freetext' so the search endpoint can fall through if no doc
        # exists for the session id.
        return [
            IOCRef(type="session", id=q, label=q),
            IOCRef(type="freetext", id=q, label=q),
        ]

    if _CLUSTER_ID.match(q):
        return [
            IOCRef(type="command_cluster", id=q, label=f"cmd cluster {q}"),
            IOCRef(type="session_cluster", id=q, label=f"sess cluster {q}"),
            IOCRef(type="ip_cluster", id=q, label=f"ip cluster {q}"),
        ]

    # Named cluster pattern: "cluster_11", "outlier"
    if _CLUSTER_NAME.match(q):
        return [
            IOCRef(type="session_cluster", id=q.lower(), label=f"sess cluster {q.lower()}"),
            IOCRef(type="ip_cluster",      id=q.lower(), label=f"ip cluster {q.lower()}"),
            IOCRef(type="command_cluster", id=q.lower(), label=f"cmd cluster {q.lower()}"),
        ]

    return [IOCRef(type="freetext", id=q, label=q)]


def is_known_type(t: str) -> bool:
    return t in TYPES


if __name__ == "__main__":  # pragma: no cover  -- ad-hoc sanity check
    cases = [
        "1.2.3.4",
        "2001:db8::1",
        "a" * 64,
        "T1059.003",
        "TA0002",
        "AS12345",
        "us",
        "abcdef012345",
        "42",
        "free-form command text",
    ]
    for c in cases:
        print(c, "->", detect(c))
