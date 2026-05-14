"""Build Cytoscape-shaped {nodes, edges} JSON from ES result rows.

A node is `{data: {id, type, label, ...metadata}}`.
An edge is `{data: {id, source, target, label, kind}}`.

`id` for nodes uses a typed prefix so the frontend can disambiguate without
inspecting `type`: e.g. `ip:1.2.3.4`, `session:abc123`, `cmd:<sha256>`,
`cmdcl:42`, `sescl:7`, `ipcl:3`, `pb:<playbook_id>`, `camp:<campaign_id>`,
`asn:12345`, `cc:US`, `tt:T1059.003`, `ta:TA0002`.
"""
from __future__ import annotations

import math
from typing import Any

from elasticsearch import Elasticsearch

from ._config import AppConfig

from . import queries


def _nid(t: str, ident: str) -> str:
    return f"{t}:{ident}"


def _log_size(n: int | float | None, *, base: float = 24.0, scale: float = 8.0) -> float:
    n = n or 0
    if n <= 0:
        return base
    return base + scale * math.log10(1 + n)


def _flatten_mitre(obj: Any) -> list[dict]:
    """Normalize ES `threat.technique` / `threat.tactic` into a flat list of
    `{id, name}` dicts. Tolerates None, single dict, list of dicts, and the
    case where inner `id`/`name` fields are themselves lists (which ES does
    when the mapping is keyword multi-value)."""
    if obj is None:
        return []
    items = obj if isinstance(obj, list) else [obj]
    out: list[dict] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        ids = it.get("id")
        names = it.get("name")
        id_list = ids if isinstance(ids, list) else ([ids] if ids else [])
        name_list = names if isinstance(names, list) else ([names] if names else [])
        for i, tid in enumerate(id_list):
            if not tid:
                continue
            tname = name_list[i] if i < len(name_list) else (name_list[0] if name_list else None)
            out.append({"id": tid, "name": tname})
    return out


def _mitre_ids(obj: Any, *, kind: str = "id") -> list[str]:
    """Extract just the ids (or just the names) from a MITRE field. Convenient
    when populating badge arrays on command nodes."""
    return [m.get(kind) for m in _flatten_mitre(obj) if m.get(kind)]


# ----------------------------------------------------------------------------
# "Resolve a pipeline node's clusterings + playbook" helpers. Each anchor
# function returns pipeline nodes (ip / session / command) in directions
# the front-end won't follow up on via further fetches (the role-based
# pipeline traversal treats them as "leaf"). Without these helpers those
# nodes would arrive without their cluster_id / playbook_name fields and
# without their cluster / playbook pill nodes — meaning sibling-expanded
# IOCs never join the cluster bubbles or playbook bubbles the front-end
# draws from those fields. Emitting the pills + edges inline closes the
# gap so siblings get the same visual context the anchor's neighbors do.
# ----------------------------------------------------------------------------

def _emit_ip_cluster(nodes: list, edges: list, ip: str, ienr: dict) -> None:
    """Attach the IP's cluster pill. IPs don't carry a playbook or campaign
    field — those concepts are derived from the IP's sessions."""
    nid_ip = _nid("ip", ip)
    cid = (ienr.get("cluster") or {}).get("id")
    if cid:
        nodes.append({"data": {"id": _nid("ipcl", cid), "type": "ip_cluster",
                               "label": f"ip cluster {cid}"}})
        edges.append({"data": {"id": f"{nid_ip}->{_nid('ipcl', cid)}",
                               "source": nid_ip, "target": _nid("ipcl", cid),
                               "label": "member_of", "kind": "member_of"}})


def _emit_session_cluster_playbook(nodes: list, edges: list, sid: str, senr: dict) -> None:
    """Attach the session's cluster pill and (if named) its playbook node.

    A playbook is the LLM-named group of 1+ HDBSCAN session clusters. The
    playbook node id is the stable `playbook_id` value (`sescl-<16hex>`,
    content-hashed over the sorted member-session-id set). Sessions from a
    merged playbook still emit their own per-cluster pill, so the graph
    shows the playbook node wired to each constituent cluster. Two
    playbooks with the same display name are distinct because they have
    different ids.
    """
    nid_s = _nid("session", sid)
    scid = (senr.get("cluster") or {}).get("id")
    if scid:
        nodes.append({"data": {"id": _nid("sescl", scid), "type": "session_cluster",
                               "label": f"sess cluster {scid}"}})
        edges.append({"data": {"id": f"{nid_s}->{_nid('sescl', scid)}",
                               "source": nid_s, "target": _nid("sescl", scid),
                               "label": "member_of", "kind": "member_of"}})
    pb_id   = senr.get("playbook_id")
    pb_name = senr.get("playbook_name")
    if pb_id:
        nodes.append({"data": {"id": _nid("pb", pb_id), "type": "playbook",
                               "playbook_id": pb_id,
                               "label": pb_name or pb_id}})
        edges.append({"data": {"id": f"{nid_s}->{_nid('pb', pb_id)}",
                               "source": nid_s, "target": _nid("pb", pb_id),
                               "label": "playbook_of", "kind": "playbook_of"}})


def _emit_command_cluster_mitre(nodes: list, edges: list, sha: str, cenr: dict, threat: dict | None) -> None:
    nid_c = _nid("cmd", sha)
    ccid = (cenr.get("cluster") or {}).get("id")
    if ccid:
        nodes.append({"data": {"id": _nid("cmdcl", ccid), "type": "command_cluster",
                               "label": f"cmd cluster {ccid}"}})
        edges.append({"data": {"id": f"{nid_c}->{_nid('cmdcl', ccid)}",
                               "source": nid_c, "target": _nid("cmdcl", ccid),
                               "label": "member_of", "kind": "member_of"}})
    if not threat:
        return
    for tech in _flatten_mitre(threat.get("technique")):
        tid = tech.get("id")
        if not tid:
            continue
        tname = tech.get("name")
        nodes.append({"data": {"id": _nid("tt", tid), "type": "mitre_technique",
                               "label": tid + (f" {tname}" if tname else "")}})
        edges.append({"data": {"id": f"{nid_c}->{_nid('tt', tid)}",
                               "source": nid_c, "target": _nid("tt", tid),
                               "label": "ttp", "kind": "ttp"}})
    for tac in _flatten_mitre(threat.get("tactic")):
        tid = tac.get("id")
        if not tid:
            continue
        tname = tac.get("name")
        nodes.append({"data": {"id": _nid("ta", tid), "type": "mitre_tactic",
                               "label": tid + (f" {tname}" if tname else "")}})
        edges.append({"data": {"id": f"{nid_c}->{_nid('ta', tid)}",
                               "source": nid_c, "target": _nid("ta", tid),
                               "label": "ttp", "kind": "ttp"}})


# ----------------------------------------------------------------------------
# Per-anchor neighborhood builders
# ----------------------------------------------------------------------------

def _ip_anchor(es: Elasticsearch, cfg: AppConfig, ip: str, *, limit: int, sf: "queries.SessionFilter | None" = None) -> dict:
    ip_doc = queries.lookup_ip(es, cfg, ip)
    nodes: list[dict] = []
    edges: list[dict] = []
    if ip_doc:
        src = ip_doc["_source"]
        enr = (src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
        asn_obj = (src.get("source", {}).get("as") or {})
        geo_obj = (src.get("source", {}).get("geo") or {})
        nodes.append({"data": {
            "id": _nid("ip", ip),
            "type": "ip",
            "label": ip,
            "size": _log_size(enr.get("total_sessions")),
            "novelty": enr.get("mean_novelty_score"),
            "cluster_id": (enr.get("cluster") or {}).get("id"),
            "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
            "asn": asn_obj.get("number"),
            "country": geo_obj.get("country_iso_code"),
        }})

        # ASN
        asn = (src.get("source", {}).get("as") or {}).get("number")
        org = ((src.get("source", {}).get("as") or {}).get("organization") or {}).get("name")
        if asn:
            nodes.append({"data": {"id": _nid("asn", str(asn)), "type": "asn",
                                   "label": f"AS{asn}" + (f" {org}" if org else "")}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('asn',str(asn))}",
                                   "source": _nid("ip", ip), "target": _nid("asn", str(asn)),
                                   "label": "asn", "kind": "asn"}})
        # Country
        cc = (src.get("source", {}).get("geo") or {}).get("country_iso_code")
        if cc:
            nodes.append({"data": {"id": _nid("cc", cc), "type": "country", "label": cc}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('cc',cc)}",
                                   "source": _nid("ip", ip), "target": _nid("cc", cc),
                                   "label": "country", "kind": "country"}})
        # ip cluster (IP-layer "actor profile"; no playbook attachment at this layer)
        cluster_id = (enr.get("cluster") or {}).get("id")
        if cluster_id:
            nodes.append({"data": {"id": _nid("ipcl", cluster_id), "type": "ip_cluster",
                                   "label": f"ip cluster {cluster_id}"}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('ipcl',cluster_id)}",
                                   "source": _nid("ip", ip), "target": _nid("ipcl", cluster_id),
                                   "label": "member_of", "kind": "member_of"}})

    # sessions for this ip — the playbook-bearing layer. Each session
    # carries its own playbook_id / playbook_name; playbook nodes get
    # merged across sessions by `_emit_session_cluster_playbook`.
    sess = queries.sessions_for_ip(es, cfg, ip, size=limit, sf=sf)
    for h in sess["hits"]["hits"]:
        sid = (h["_source"].get("cowrie") or {}).get("session_id") or h["_id"]
        senr = (h["_source"].get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
        nodes.append({"data": {
            "id": _nid("session", sid), "type": "session", "label": sid,
            "size": _log_size(senr.get("command_count")),
            "novelty": senr.get("mean_novelty_score"),
            "playbook_id":   senr.get("playbook_id"),
            "playbook_name": senr.get("playbook_name"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',sid)}",
                               "source": _nid("ip", ip), "target": _nid("session", sid),
                               "label": "saw", "kind": "saw"}})
        _emit_session_cluster_playbook(nodes, edges, sid, senr)
    return _dedup({"nodes": nodes, "edges": edges})


def _session_anchor(es: Elasticsearch, cfg: AppConfig, session_id: str, *, limit: int, sf: "queries.SessionFilter | None" = None) -> dict:
    sdoc = queries.lookup_session(es, cfg, session_id)
    nodes: list[dict] = []
    edges: list[dict] = []
    if sdoc:
        src = sdoc["_source"]
        senr = (src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
        nodes.append({"data": {
            "id": _nid("session", session_id), "type": "session", "label": session_id,
            "size": _log_size(senr.get("command_count")),
            "playbook_id":   senr.get("playbook_id"),
            "playbook_name": senr.get("playbook_name"),
            "novelty": senr.get("mean_novelty_score"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        # source ip — look up its enrichment so the IP arrives with cluster_id /
        # asn / country fields. The IP doesn't carry a playbook attribute
        # of its own; playbooks are derived from the IP's sessions.
        ip = (src.get("source") or {}).get("ip")
        if ip:
            ip_doc = queries.lookup_ip(es, cfg, ip)
            ienr: dict = {}
            ip_asn = None
            ip_asn_org = None
            ip_cc = None
            if ip_doc:
                isrc = ip_doc["_source"]
                ienr = (isrc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
                ip_asn = ((isrc.get("source") or {}).get("as") or {}).get("number")
                ip_asn_org = (((isrc.get("source") or {}).get("as") or {}).get("organization") or {}).get("name")
                ip_cc = ((isrc.get("source") or {}).get("geo") or {}).get("country_iso_code")
            nodes.append({"data": {
                "id": _nid("ip", ip), "type": "ip", "label": ip,
                "cluster_id": (ienr.get("cluster") or {}).get("id"),
                "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
                "asn": ip_asn, "country": ip_cc,
            }})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',session_id)}",
                                   "source": _nid("ip", ip), "target": _nid("session", session_id),
                                   "label": "saw", "kind": "saw"}})
            _emit_ip_cluster(nodes, edges, ip, ienr)
            if ip_asn:
                nodes.append({"data": {"id": _nid("asn", str(ip_asn)), "type": "asn",
                                       "label": f"AS{ip_asn}" + (f" {ip_asn_org}" if ip_asn_org else "")}})
                edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('asn',str(ip_asn))}",
                                       "source": _nid("ip", ip), "target": _nid("asn", str(ip_asn)),
                                       "label": "asn", "kind": "asn"}})
            if ip_cc:
                nodes.append({"data": {"id": _nid("cc", ip_cc), "type": "country", "label": ip_cc}})
                edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('cc',ip_cc)}",
                                       "source": _nid("ip", ip), "target": _nid("cc", ip_cc),
                                       "label": "country", "kind": "country"}})
        # session cluster + playbook (playbook_id is the merge key)
        _emit_session_cluster_playbook(nodes, edges, session_id, senr)

    # commands in this session
    cmd_rows = queries.commands_for_session(es, cfg, session_id, size=limit)
    seen_hashes: set[str] = set()
    for row in cmd_rows["rows"]:
        sha = row.get("sha256")
        if not sha or sha in seen_hashes:
            continue
        seen_hashes.add(sha)
        enr = row.get("enrichment") or {}
        threat = row.get("threat") or {}
        label = (row.get("command_line") or sha)[:80]
        nodes.append({"data": {
            "id": _nid("cmd", sha), "type": "command", "label": label,
            "sha256": sha,
            "intent": enr.get("intent"),
            "novelty": (enr.get("cluster") or {}).get("novelty_score"),
            "size": _log_size(enr.get("occurrence_count")),
            "cluster_id": (enr.get("cluster") or {}).get("id"),
            "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
            "mitre_techniques": _mitre_ids(threat.get("technique")),
            "mitre_tactics": _mitre_ids(threat.get("tactic")),
        }})
        edges.append({"data": {"id": f"{_nid('session',session_id)}->{_nid('cmd',sha)}",
                               "source": _nid("session", session_id), "target": _nid("cmd", sha),
                               "label": "ran", "kind": "ran"}})
        _emit_command_cluster_mitre(nodes, edges, sha, enr, threat)
    return _dedup({"nodes": nodes, "edges": edges})


def _command_anchor(es: Elasticsearch, cfg: AppConfig, sha256: str, *, limit: int, sf: "queries.SessionFilter | None" = None) -> dict:
    cdoc = queries.lookup_command(es, cfg, sha256)
    nodes: list[dict] = []
    edges: list[dict] = []
    if cdoc:
        src = cdoc["_source"]
        cmd = ((src.get("process") or {}).get("command_line") or sha256)
        enr = (src.get("dshield", {}).get("cowrie", {}).get("enrichment") or {})
        nodes.append({"data": {
            "id": _nid("cmd", sha256), "type": "command", "label": cmd[:80],
            "sha256": sha256, "intent": enr.get("intent"),
            "size": _log_size(enr.get("occurrence_count")),
            "novelty": (enr.get("cluster") or {}).get("novelty_score"),
            "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
            "cluster_id": (enr.get("cluster") or {}).get("id"),
        }})
        ccid = (enr.get("cluster") or {}).get("id")
        if ccid:
            nodes.append({"data": {"id": _nid("cmdcl", ccid), "type": "command_cluster",
                                   "label": f"cmd cluster {ccid}"}})
            edges.append({"data": {"id": f"{_nid('cmd',sha256)}->{_nid('cmdcl',ccid)}",
                                   "source": _nid("cmd", sha256), "target": _nid("cmdcl", ccid),
                                   "label": "member_of", "kind": "member_of"}})
        # MITRE techniques/tactics. ES stores both `technique` and `tactic` as
        # either a single object or a list; within each object, `id` and
        # `name` can themselves be a list (ES collapses keyword multi-values).
        # Flatten everything into a list of plain {id, name} dicts.
        threat = src.get("threat") or {}
        for tech in _flatten_mitre(threat.get("technique")):
            tid = tech.get("id")
            if not tid:
                continue
            tname = tech.get("name")
            nodes.append({"data": {"id": _nid("tt", tid), "type": "mitre_technique",
                                   "label": tid + (f" {tname}" if tname else "")}})
            edges.append({"data": {"id": f"{_nid('cmd',sha256)}->{_nid('tt',tid)}",
                                   "source": _nid("cmd", sha256), "target": _nid("tt", tid),
                                   "label": "ttp", "kind": "ttp"}})
        for tac in _flatten_mitre(threat.get("tactic")):
            tid = tac.get("id")
            if not tid:
                continue
            tname = tac.get("name")
            nodes.append({"data": {"id": _nid("ta", tid), "type": "mitre_tactic",
                                   "label": tid + (f" {tname}" if tname else "")}})
            edges.append({"data": {"id": f"{_nid('cmd',sha256)}->{_nid('ta',tid)}",
                                   "source": _nid("cmd", sha256), "target": _nid("ta", tid),
                                   "label": "ttp", "kind": "ttp"}})

    # sessions that ran this command — bulk-enrich so each session arrives
    # with cluster_id / playbook and its source-IP context, both of which
    # the front-end needs to fold these nodes into the right cluster /
    # playbook bubbles. (sessions_for_command returns just session_id +
    # command_count, so we hydrate explicitly here.)
    sess = queries.sessions_for_command(es, cfg, sha256, size=limit, sf=sf)
    sids = [row["session_id"] for row in sess["rows"]]
    senr_map = queries.bulk_session_enrichment(es, cfg, sids)
    src_ips: list[str] = []
    for v in senr_map.values():
        if v.get("src_ip"):
            src_ips.append(v["src_ip"])
    ienr_map = queries.bulk_ip_enrichment(es, cfg, src_ips)
    for row in sess["rows"]:
        sid = row["session_id"]
        info = senr_map.get(sid, {})
        senr = info.get("enrichment", {}) if isinstance(info, dict) else {}
        nodes.append({"data": {
            "id": _nid("session", sid), "type": "session", "label": sid,
            "size": _log_size(senr.get("command_count")),
            "playbook_id":   senr.get("playbook_id"),
            "playbook_name": senr.get("playbook_name"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        edges.append({"data": {"id": f"{_nid('session',sid)}->{_nid('cmd',sha256)}",
                               "source": _nid("session", sid), "target": _nid("cmd", sha256),
                               "label": "ran", "kind": "ran"}})
        _emit_session_cluster_playbook(nodes, edges, sid, senr)
        # Pull the session's source IP into the graph too. Without this the
        # IP arrives later via a leaf-traversal fetch and never carries its
        # ip_cluster_id, so the ip_cluster bubble never groups it.
        ip = info.get("src_ip") if isinstance(info, dict) else None
        if not ip:
            continue
        ipinfo = ienr_map.get(ip) or {}
        ienr = ipinfo.get("enrichment") or {}
        ip_asn = ipinfo.get("asn")
        ip_cc = ipinfo.get("country")
        nodes.append({"data": {
            "id": _nid("ip", ip), "type": "ip", "label": ip,
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn": ip_asn, "country": ip_cc,
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',sid)}",
                               "source": _nid("ip", ip), "target": _nid("session", sid),
                               "label": "saw", "kind": "saw"}})
        _emit_ip_cluster(nodes, edges, ip, ienr)
        if ip_asn:
            nodes.append({"data": {"id": _nid("asn", str(ip_asn)), "type": "asn",
                                   "label": f"AS{ip_asn}"}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('asn',str(ip_asn))}",
                                   "source": _nid("ip", ip), "target": _nid("asn", str(ip_asn)),
                                   "label": "asn", "kind": "asn"}})
        if ip_cc:
            nodes.append({"data": {"id": _nid("cc", ip_cc), "type": "country", "label": ip_cc}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('cc',ip_cc)}",
                                   "source": _nid("ip", ip), "target": _nid("cc", ip_cc),
                                   "label": "country", "kind": "country"}})
    return _dedup({"nodes": nodes, "edges": edges})


def _cluster_anchor(
    es: Elasticsearch, cfg: AppConfig, kind: str, cluster_id: str, *, limit: int,
    run_cache: queries.RunCache,
    sf: "queries.SessionFilter | None" = None,
) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    cluster_node_type = {"command": "command_cluster", "session": "session_cluster", "ip": "ip_cluster"}[kind]
    cluster_node_prefix = {"command": "cmdcl", "session": "sescl", "ip": "ipcl"}[kind]
    cnid = _nid(cluster_node_prefix, cluster_id)
    cdoc = queries.lookup_cluster(es, cfg, kind, cluster_id, run_cache)
    if cdoc:
        src = cdoc["_source"]
        nodes.append({"data": {
            "id": cnid, "type": cluster_node_type,
            "label": f"{kind} cluster {cluster_id}",
            "size": _log_size(src.get("size"), base=32),
            "playbook_id":   src.get("playbook_id"),
            "playbook_name": src.get("playbook_name"),
            "member_count": src.get("size"),
        }})
        # Only session clusters carry a playbook label.
        if kind == "session":
            pb_id   = src.get("playbook_id")
            pb_name = src.get("playbook_name")
            if pb_id:
                nodes.append({"data": {"id": _nid("pb", pb_id), "type": "playbook",
                                       "playbook_id": pb_id,
                                       "label": pb_name or pb_id}})
                edges.append({"data": {"id": f"{cnid}->{_nid('pb', pb_id)}",
                                       "source": cnid, "target": _nid("pb", pb_id),
                                       "label": "named", "kind": "named"}})

    members = queries.members_of_cluster(es, cfg, kind, cluster_id, size=limit, sf=sf)
    for h in members["hits"]["hits"]:
        s = h["_source"]
        if kind == "command":
            sha = ((s.get("process") or {}).get("hash") or {}).get("sha256") or h["_id"]
            cmd = ((s.get("process") or {}).get("command_line") or sha)
            enr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment") or {})
            threat = s.get("threat") or {}
            nodes.append({"data": {
                "id": _nid("cmd", sha), "type": "command",
                "label": cmd[:80], "sha256": sha,
                "intent": enr.get("intent"),
                "novelty": (enr.get("cluster") or {}).get("novelty_score"),
                "size": _log_size(enr.get("occurrence_count")),
                "cluster_id": (enr.get("cluster") or {}).get("id"),
                "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
                "mitre_techniques": _mitre_ids(threat.get("technique")),
                "mitre_tactics": _mitre_ids(threat.get("tactic")),
            }})
            edges.append({"data": {"id": f"{_nid('cmd',sha)}->{cnid}",
                                   "source": _nid("cmd", sha), "target": cnid,
                                   "label": "member_of", "kind": "member_of"}})
            _emit_command_cluster_mitre(nodes, edges, sha, enr, threat)
        elif kind == "session":
            sid = (s.get("cowrie") or {}).get("session_id") or h["_id"]
            senr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
            nodes.append({"data": {
                "id": _nid("session", sid), "type": "session", "label": sid,
                "size": _log_size(senr.get("command_count")),
                "novelty": senr.get("mean_novelty_score"),
                "playbook_id":   senr.get("playbook_id"),
                "playbook_name": senr.get("playbook_name"),
                "cluster_id": (senr.get("cluster") or {}).get("id"),
                "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
            }})
            edges.append({"data": {"id": f"{_nid('session',sid)}->{cnid}",
                                   "source": _nid("session", sid), "target": cnid,
                                   "label": "member_of", "kind": "member_of"}})
            _emit_session_cluster_playbook(nodes, edges, sid, senr)
        else:  # ip
            ip = (s.get("source") or {}).get("ip") or h["_id"]
            ienr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
            asn_obj = (s.get("source", {}).get("as") or {})
            geo_obj = (s.get("source", {}).get("geo") or {})
            nodes.append({"data": {
                "id": _nid("ip", ip), "type": "ip", "label": ip,
                "size": _log_size(ienr.get("total_sessions")),
                "novelty": ienr.get("mean_novelty_score"),
                "cluster_id": (ienr.get("cluster") or {}).get("id"),
                "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
                "asn": asn_obj.get("number"),
                "country": geo_obj.get("country_iso_code"),
            }})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{cnid}",
                                   "source": _nid("ip", ip), "target": cnid,
                                   "label": "member_of", "kind": "member_of"}})
            _emit_ip_cluster(nodes, edges, ip, ienr)
    return _dedup({"nodes": nodes, "edges": edges})


def _campaign_anchor(
    es: Elasticsearch, cfg: AppConfig, campaign_id: str, *, limit: int,
    sf: "queries.SessionFilter | None" = None,
) -> dict:
    """Anchor on a multi-session campaign.

    Unlike a playbook (one session cluster), a campaign here is a derived
    multi-session grouping mined by `dshield_prism mine campaigns`. The
    doc in `campaigns-dshield.cowrie-default` carries explicit lists of
    member session ids and source ips, so the graph build is a direct
    `terms` fetch — no aggregation needed.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    camp = queries.lookup_campaign(es, cfg, campaign_id)
    if not camp:
        # Anchor on an unknown campaign id — return a sentinel node so the
        # UI can show "not found" instead of a blank canvas.
        nodes.append({"data": {
            "id":   _nid("camp", campaign_id),
            "type": "campaign",
            "campaign_id": campaign_id,
            "label": campaign_id,
            "kind": "unknown",
        }})
        return _dedup({"nodes": nodes, "edges": edges})

    cnode = {
        "id":            _nid("camp", campaign_id),
        "type":          "campaign",
        "campaign_id":   campaign_id,
        "campaign_kind": camp.get("kind") or "unknown",
        "label":         camp.get("name") or campaign_id,
        "ip_count":      camp.get("ip_count"),
        "session_count": camp.get("session_count"),
    }
    nodes.append({"data": cnode})

    # Pull a sample of member sessions and their source IPs into the graph.
    sids = (camp.get("member_session_ids") or [])[:limit]
    if sids:
        try:
            sresp = es.search(
                index=cfg.elasticsearch.indexes.cowrie.sessions_rollup,
                size=len(sids),
                _source=queries._src(),
                query={"terms": {"cowrie.session_id": sids}},
            )
        except Exception:
            sresp = {"hits": {"hits": []}}
        for h in sresp["hits"]["hits"]:
            s = h["_source"]
            sid = (s.get("cowrie") or {}).get("session_id") or h["_id"]
            senr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
            nodes.append({"data": {
                "id":           _nid("session", sid), "type": "session", "label": sid,
                "size":         _log_size(senr.get("command_count")),
                "playbook_id":   senr.get("playbook_id"),
                "playbook_name": senr.get("playbook_name"),
                "novelty":      senr.get("mean_novelty_score"),
                "cluster_id":   (senr.get("cluster") or {}).get("id"),
                "is_outlier":   (senr.get("cluster") or {}).get("is_outlier"),
            }})
            edges.append({"data": {
                "id":     f"{_nid('session', sid)}->{_nid('camp', campaign_id)}",
                "source": _nid("session", sid),
                "target": _nid("camp", campaign_id),
                "label":  "in_campaign", "kind": "in_campaign",
            }})
            _emit_session_cluster_playbook(nodes, edges, sid, senr)
            # Source IP into view.
            ip = (s.get("source") or {}).get("ip")
            if not ip:
                continue
            ip_doc = queries.lookup_ip(es, cfg, ip)
            ienr: dict = {}
            ip_asn = ip_cc = None
            if ip_doc:
                isrc = ip_doc["_source"]
                ienr = (isrc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
                ip_asn = ((isrc.get("source") or {}).get("as") or {}).get("number")
                ip_cc  = ((isrc.get("source") or {}).get("geo") or {}).get("country_iso_code")
            nodes.append({"data": {
                "id": _nid("ip", ip), "type": "ip", "label": ip,
                "cluster_id": (ienr.get("cluster") or {}).get("id"),
                "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
                "asn": ip_asn, "country": ip_cc,
            }})
            edges.append({"data": {
                "id":     f"{_nid('ip', ip)}->{_nid('session', sid)}",
                "source": _nid("ip", ip), "target": _nid("session", sid),
                "label":  "saw", "kind": "saw",
            }})
            _emit_ip_cluster(nodes, edges, ip, ienr)

    return _dedup({"nodes": nodes, "edges": edges})


def _playbook_anchor(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str, *, limit: int,
    sf: "queries.SessionFilter | None" = None,
) -> dict:
    """Anchor on a playbook by its stable primary key.

    Playbook = a named session cluster. Anchoring returns the playbook's
    session members, the source IPs that produced those sessions, and the
    relevant IP-cluster pills. IPs are derived via session ownership;
    there is no direct IP→playbook edge.
    """
    sess_clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    playbook_name = None
    centroid_field = queries._resolve_agg_field(es, sess_clusters_idx, "playbook_id")
    try:
        cresp = es.search(
            index=sess_clusters_idx, size=1,
            _source=["playbook_name"],
            query={"term": {centroid_field: playbook_id}},
        )
        chits = cresp["hits"]["hits"]
        if chits:
            playbook_name = chits[0]["_source"].get("playbook_name")
    except Exception:
        pass

    nodes: list[dict] = [{"data": {
        "id": _nid("pb", playbook_id),
        "type": "playbook",
        "playbook_id": playbook_id,
        "label": playbook_name or playbook_id,
    }}]
    edges: list[dict] = []

    # Sessions in this playbook (the authoritative membership).
    r = queries.sessions_for_playbook(es, cfg, playbook_id, size=limit, sf=sf)
    for h in r["hits"]["hits"]:
        s = h["_source"]
        sid = (s.get("cowrie") or {}).get("session_id") or h["_id"]
        senr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
        nodes.append({"data": {
            "id": _nid("session", sid), "type": "session", "label": sid,
            "size": _log_size(senr.get("command_count")),
            "playbook_id":   playbook_id,
            "playbook_name": playbook_name,
            "novelty": senr.get("mean_novelty_score"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        edges.append({"data": {"id": f"{_nid('session',sid)}->{_nid('pb',playbook_id)}",
                               "source": _nid("session", sid), "target": _nid("pb", playbook_id),
                               "label": "playbook_of", "kind": "playbook_of"}})
        _emit_session_cluster_playbook(nodes, edges, sid, senr)
        # Pull the source IP into view so the hunter can see who's running
        # this playbook. The IP doesn't get a direct edge to the playbook —
        # the session sits in between, which is the relationship that
        # actually exists in the data.
        ip = (s.get("source") or {}).get("ip")
        if not ip:
            continue
        ip_doc = queries.lookup_ip(es, cfg, ip)
        ienr: dict = {}
        ip_asn = None
        ip_cc = None
        if ip_doc:
            isrc = ip_doc["_source"]
            ienr = (isrc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
            ip_asn = ((isrc.get("source") or {}).get("as") or {}).get("number")
            ip_cc = ((isrc.get("source") or {}).get("geo") or {}).get("country_iso_code")
        nodes.append({"data": {
            "id": _nid("ip", ip), "type": "ip", "label": ip,
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn": ip_asn, "country": ip_cc,
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',sid)}",
                               "source": _nid("ip", ip), "target": _nid("session", sid),
                               "label": "saw", "kind": "saw"}})
        _emit_ip_cluster(nodes, edges, ip, ienr)
    return _dedup({"nodes": nodes, "edges": edges})


def _asn_anchor(es: Elasticsearch, cfg: AppConfig, asn: str, *, limit: int) -> dict:
    nodes: list[dict] = [{"data": {"id": _nid("asn", asn), "type": "asn", "label": f"AS{asn}"}}]
    edges: list[dict] = []
    r = queries.ips_for_asn(es, cfg, asn, size=limit)
    for h in r["hits"]["hits"]:
        s = h["_source"]
        ip = (s.get("source") or {}).get("ip") or h["_id"]
        ienr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
        geo_obj = (s.get("source", {}).get("geo") or {})
        nodes.append({"data": {
            "id": _nid("ip", ip), "type": "ip", "label": ip,
            "size": _log_size(ienr.get("total_sessions")),
            "novelty": ienr.get("mean_novelty_score"),
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn": asn,
            "country": geo_obj.get("country_iso_code"),
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('asn',asn)}",
                               "source": _nid("ip", ip), "target": _nid("asn", asn),
                               "label": "asn", "kind": "asn"}})
        _emit_ip_cluster(nodes, edges, ip, ienr)
    return _dedup({"nodes": nodes, "edges": edges})


def _country_anchor(es: Elasticsearch, cfg: AppConfig, cc: str, *, limit: int) -> dict:
    nodes: list[dict] = [{"data": {"id": _nid("cc", cc), "type": "country", "label": cc}}]
    edges: list[dict] = []
    r = queries.ips_for_country(es, cfg, cc, size=limit)
    for h in r["hits"]["hits"]:
        s = h["_source"]
        ip = (s.get("source") or {}).get("ip") or h["_id"]
        ienr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
        asn_obj = (s.get("source", {}).get("as") or {})
        nodes.append({"data": {
            "id": _nid("ip", ip), "type": "ip", "label": ip,
            "size": _log_size(ienr.get("total_sessions")),
            "novelty": ienr.get("mean_novelty_score"),
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn": asn_obj.get("number"),
            "country": cc,
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('cc',cc)}",
                               "source": _nid("ip", ip), "target": _nid("cc", cc),
                               "label": "country", "kind": "country"}})
        _emit_ip_cluster(nodes, edges, ip, ienr)
    return _dedup({"nodes": nodes, "edges": edges})


def _mitre_anchor(es: Elasticsearch, cfg: AppConfig, mitre_id: str, kind: str, *, limit: int) -> dict:
    node_prefix = "tt" if kind == "technique" else "ta"
    node_type = "mitre_technique" if kind == "technique" else "mitre_tactic"
    nid = _nid(node_prefix, mitre_id)
    nodes: list[dict] = [{"data": {"id": nid, "type": node_type, "label": mitre_id}}]
    edges: list[dict] = []
    r = queries.commands_for_mitre(es, cfg, mitre_id, kind=kind, size=limit)
    for h in r["hits"]["hits"]:
        s = h["_source"]
        sha = ((s.get("process") or {}).get("hash") or {}).get("sha256") or h["_id"]
        cmd = ((s.get("process") or {}).get("command_line") or sha)
        enr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment") or {})
        threat = s.get("threat") or {}
        nodes.append({"data": {
            "id": _nid("cmd", sha), "type": "command",
            "label": cmd[:80], "sha256": sha,
            "intent": enr.get("intent"),
            "novelty": (enr.get("cluster") or {}).get("novelty_score"),
            "size": _log_size(enr.get("occurrence_count")),
            "cluster_id": (enr.get("cluster") or {}).get("id"),
            "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
            "mitre_techniques": _mitre_ids(threat.get("technique")),
            "mitre_tactics": _mitre_ids(threat.get("tactic")),
        }})
        edges.append({"data": {"id": f"{_nid('cmd',sha)}->{nid}",
                               "source": _nid("cmd", sha), "target": nid,
                               "label": "ttp", "kind": "ttp"}})
        _emit_command_cluster_mitre(nodes, edges, sha, enr, threat)
    return _dedup({"nodes": nodes, "edges": edges})


# ----------------------------------------------------------------------------
# Public dispatch
# ----------------------------------------------------------------------------

def neighbors(
    es: Elasticsearch, cfg: AppConfig, ioc_type: str, ident: str, *,
    limit: int = 50, run_cache: queries.RunCache,
    sf: queries.SessionFilter | None = None,
) -> dict:
    if ioc_type == "ip":
        return _ip_anchor(es, cfg, ident, limit=limit, sf=sf)
    if ioc_type == "session":
        return _session_anchor(es, cfg, ident, limit=limit, sf=sf)
    if ioc_type in ("command", "command_hash"):
        return _command_anchor(es, cfg, ident.lower(), limit=limit, sf=sf)
    if ioc_type == "command_cluster":
        return _cluster_anchor(es, cfg, "command", ident, limit=limit, run_cache=run_cache, sf=sf)
    if ioc_type == "session_cluster":
        return _cluster_anchor(es, cfg, "session", ident, limit=limit, run_cache=run_cache, sf=sf)
    if ioc_type == "ip_cluster":
        return _cluster_anchor(es, cfg, "ip", ident, limit=limit, run_cache=run_cache, sf=sf)
    if ioc_type == "playbook":
        return _playbook_anchor(es, cfg, ident, limit=limit, sf=sf)
    if ioc_type == "campaign":
        return _campaign_anchor(es, cfg, ident, limit=limit, sf=sf)
    if ioc_type == "asn":
        return _asn_anchor(es, cfg, ident, limit=limit)
    if ioc_type == "country":
        return _country_anchor(es, cfg, ident.upper(), limit=limit)
    if ioc_type == "mitre_technique":
        return _mitre_anchor(es, cfg, ident.upper(), "technique", limit=limit)
    if ioc_type == "mitre_tactic":
        return _mitre_anchor(es, cfg, ident.upper(), "tactic", limit=limit)
    raise ValueError(f"unsupported ioc_type: {ioc_type}")


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _dedup(g: dict) -> dict:
    """Drop duplicate nodes (last write wins) and duplicate edges by id."""
    nodes: dict[str, dict] = {}
    for n in g["nodes"]:
        nid = n["data"]["id"]
        # Prefer the entry that has more keys (typically the fuller anchor doc).
        if nid not in nodes or len(n["data"]) > len(nodes[nid]["data"]):
            nodes[nid] = n
    edges: dict[str, dict] = {}
    for e in g["edges"]:
        edges[e["data"]["id"]] = e
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}
