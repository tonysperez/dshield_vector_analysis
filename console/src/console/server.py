"""FastAPI server.

Exposes the JSON API used by the browser UI and serves the static frontend
from `web/`.

The app is read-only against Elasticsearch.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ._config import load_config, load_secrets
from ._es import make_client
from . import graph, ioc, queries
# Imported as a renamed local to avoid shadowing the `health()` function
# below that's registered as the `/api/health` system-check route.
from . import health as health_mod
from .models import (
    GraphResponse, HealthResponse, IOCDetail, SearchCandidate,
    SearchResponse, TableResponse,
)

log = logging.getLogger(__name__)

WEB_DIR = Path(__file__).parent / "web"


class AskRequest(BaseModel):
    question: str
    context: dict = {}


class DenylistAddRequest(BaseModel):
    """POST body for /api/health/commands/denylist (ROADMAP #11.5)."""
    token: str
    rationale: str = ""


def build_app(config_path: str | None = None) -> FastAPI:
    cfg = load_config(config_path)
    secrets = load_secrets(config_path)
    es = make_client(cfg.elasticsearch, secrets)
    run_cache = queries.RunCache()

    app = FastAPI(title="DShield Console", version="0.1.0")

    # ------------------------------------------------------------------
    # Static frontend
    # ------------------------------------------------------------------
    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/")
    def root() -> FileResponse:
        index = WEB_DIR / "index.html"
        if not index.exists():
            raise HTTPException(500, "web/index.html missing")
        return FileResponse(index)

    @app.get("/insights")
    def insights_page() -> FileResponse:
        page = WEB_DIR / "insights.html"
        if not page.exists():
            raise HTTPException(500, "web/insights.html missing")
        return FileResponse(page)

    @app.get("/compare")
    def compare_page() -> FileResponse:
        page = WEB_DIR / "compare.html"
        if not page.exists():
            raise HTTPException(500, "web/compare.html missing")
        return FileResponse(page)

    @app.get("/health")
    def health_page() -> FileResponse:
        page = WEB_DIR / "health.html"
        if not page.exists():
            raise HTTPException(500, "web/health.html missing")
        return FileResponse(page)

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------
    _insights_cache: dict[str, Any] = {"ts": 0.0, "data": None}
    _INSIGHTS_TTL = 60.0  # seconds — data changes slowly

    @app.get("/api/timeline")
    def timeline_api(
        kind:             str  = Query(...),
        id:               str  = Query(...),
        limit:            int  = Query(500, ge=1, le=2000),
        require_login:    bool = Query(False),
        require_commands: bool = Query(False),
    ) -> JSONResponse:
        if kind not in ("ip", "session_cluster", "playbook"):
            raise HTTPException(400, f"unknown timeline kind: {kind}")
        sf = _session_filter(require_login, require_commands)
        data = queries.timeline_sessions(es, cfg, kind=kind, id_=id, limit=limit, sf=sf)
        return JSONResponse(data)

    @app.get("/api/insights")
    def insights_api() -> JSONResponse:
        now = time.monotonic()
        if _insights_cache["data"] and now - _insights_cache["ts"] < _INSIGHTS_TTL:
            return JSONResponse(_insights_cache["data"])
        try:
            data = queries.insights_summary(es, cfg, run_cache)
            _insights_cache["ts"] = now
            _insights_cache["data"] = data
            return JSONResponse(data)
        except Exception as e:
            log.exception("insights_summary failed")
            raise HTTPException(500, f"insights query failed: {e}")

    # Health page — command-grounding coverage report (ROADMAP #11.5).
    # Same 60s in-memory cache pattern as /api/insights; the underlying
    # data changes only when curated YAMLs / the tldr bundle / the
    # corpus drift, none of which happen sub-minute.
    _health_cmds_cache: dict[str, Any] = {"ts": 0.0, "data": None}
    _HEALTH_CMDS_TTL = 60.0

    @app.get("/api/health/commands")
    def health_commands_api() -> JSONResponse:
        now = time.monotonic()
        if _health_cmds_cache["data"] and now - _health_cmds_cache["ts"] < _HEALTH_CMDS_TTL:
            return JSONResponse(_health_cmds_cache["data"])
        try:
            data = health_mod.health_commands(es, cfg)
            _health_cmds_cache["ts"] = now
            _health_cmds_cache["data"] = data
            return JSONResponse(data)
        except Exception as e:
            log.exception("health_commands failed")
            raise HTTPException(500, f"health_commands query failed: {e}")

    def _invalidate_health_cache() -> None:
        _health_cmds_cache["data"] = None
        _health_cmds_cache["ts"] = 0.0

    @app.post("/api/health/commands/denylist")
    def denylist_add_api(body: DenylistAddRequest) -> JSONResponse:
        ok, msg = health_mod.add_token_to_denylist(body.token, body.rationale)
        if not ok:
            raise HTTPException(400, msg)
        _invalidate_health_cache()
        return JSONResponse({"ok": True, "message": msg})

    @app.delete("/api/health/commands/denylist/{token}")
    def denylist_remove_api(token: str) -> JSONResponse:
        ok, msg = health_mod.remove_token_from_denylist(token)
        if not ok:
            # "not present" is a benign no-op for idempotent UI clicks;
            # truly malformed input would have been rejected earlier.
            raise HTTPException(404, msg)
        _invalidate_health_cache()
        return JSONResponse({"ok": True, "message": msg})

    # ------------------------------------------------------------------
    # Compare clusters (interactive: "why didn't these two playbooks merge?")
    # ------------------------------------------------------------------
    #
    # These endpoints reach into the parent `enrich` package — the
    # only place in this console where we cross-package import. The pipeline
    # owns the analysis primitives (`analyze_cluster_pair`) and the LLM
    # client; duplicating either here would mean keeping two implementations
    # of cluster math + LLM transport in sync. The pipeline `AppConfig` is
    # loaded lazily on first call so vanilla pages don't pay the import
    # cost, and `analyze` works even when LLM/prompts aren't configured.
    _pipeline_cfg: dict[str, Any] = {"value": None}

    def _get_pipeline_cfg():
        if _pipeline_cfg["value"] is None:
            from enrich.config import load_config as _load_pipeline_cfg
            _pipeline_cfg["value"] = _load_pipeline_cfg(config_path)
        return _pipeline_cfg["value"]

    @app.get("/api/compare/clusters")
    def compare_list_clusters() -> JSONResponse:
        """Latest session-cluster centroids — populates the picker dropdowns."""
        idx = cfg.elasticsearch.indexes.cowrie.session_clusters
        try:
            run_id = run_cache.latest(es, idx)
            if not run_id:
                return JSONResponse({"run_id": None, "clusters": []})
            r = es.search(
                index=idx, size=1000,
                query={"bool": {"must": [
                    {"term": {"doc_type": "cluster"}},
                    {"term": {"run_id": run_id}},
                ]}},
                _source=["cluster_id", "size", "playbook_id", "playbook_name"],
                sort=[{"playbook_name": "asc"}, {"cluster_id": "asc"}],
            )
            clusters = [h["_source"] for h in r["hits"]["hits"]]
        except Exception as exc:
            raise HTTPException(500, f"list clusters failed: {exc}")
        return JSONResponse({"run_id": run_id, "clusters": clusters})

    @app.get("/api/compare")
    def compare_analyze(
        a: str = Query(..., description="cluster_id A"),
        b: str = Query(..., description="cluster_id B"),
    ) -> JSONResponse:
        """Structured analysis of why two HDBSCAN clusters didn't merge.
        Fast (ES-only); no LLM call."""
        if a == b:
            raise HTTPException(400, "a and b must be different cluster_ids")
        from enrich.sources.cowrie.explain import analyze_cluster_pair
        try:
            data = analyze_cluster_pair(es, _get_pipeline_cfg(), a, b)
        except RuntimeError as exc:
            raise HTTPException(404, str(exc))
        except Exception as exc:
            log.exception("compare_analyze failed for %s vs %s", a, b)
            raise HTTPException(500, f"analyze failed: {exc}")
        return JSONResponse(data)

    @app.post("/api/compare/explain")
    def compare_explain(payload: dict) -> JSONResponse:
        """Take a previously-computed analysis dict and ask the local LLM
        for a verdict + evidence + recommendation. Slow (10-30s); fires only
        when the user clicks 'Explain' on the compare page."""
        from enrich.sources.cowrie.explain import explain_cluster_pair_with_llm
        analysis = payload.get("analysis") if isinstance(payload, dict) else None
        if not analysis or not isinstance(analysis, dict):
            raise HTTPException(400, "request body must include {'analysis': <dict>}")
        try:
            narrative = explain_cluster_pair_with_llm(_get_pipeline_cfg(), analysis)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc))
        except Exception as exc:
            log.exception("compare_explain LLM call failed")
            raise HTTPException(502, f"LLM call failed: {exc}")
        return JSONResponse(narrative)

    @app.get("/api/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        try:
            h = queries.health(es, cfg)
            return HealthResponse(ok=True, **h)
        except Exception as e:  # pragma: no cover -- depends on ES state
            return HealthResponse(
                ok=False, indexes={}, doc_counts={},
                error=f"{e.__class__.__name__}: {e}",
            )

    @app.get("/api/search", response_model=SearchResponse)
    def search(q: str = Query(..., min_length=1)) -> SearchResponse:
        refs = ioc.detect(q)
        candidates: list[SearchCandidate] = []
        for ref in refs:
            if ref.type == "freetext":
                candidates.extend(SearchCandidate(**c) for c in queries.freetext_search(es, cfg, ref.id))
            else:
                candidates.append(SearchCandidate(
                    type=ref.type, id=ref.id, label=ref.label or ref.id,
                ))
        return SearchResponse(query=q, candidates=candidates)

    # Specific suffix routes are registered BEFORE the catch-all detail route
    # so FastAPI matches them first. None of our IOC ids legitimately contain
    # '/', so plain {ident} (no :path converter) is enough.

    def _session_filter(require_login: bool, require_commands: bool) -> queries.SessionFilter:
        return queries.SessionFilter(
            require_login=require_login,
            require_commands=require_commands,
        )

    @app.get("/api/ioc/{ioc_type}/{ident}/neighbors", response_model=GraphResponse)
    def ioc_neighbors(
        ioc_type: str, ident: str,
        limit: int = Query(50, ge=1, le=500),
        require_login: bool = Query(True),
        require_commands: bool = Query(True),
    ) -> GraphResponse:
        if not ioc.is_known_type(ioc_type):
            raise HTTPException(400, f"unknown ioc_type: {ioc_type}")
        sf = _session_filter(require_login, require_commands)
        g = graph.neighbors(es, cfg, ioc_type, ident, limit=limit,
                            run_cache=run_cache, sf=sf)
        return GraphResponse(nodes=g["nodes"], edges=g["edges"],
                             anchor={"type": ioc_type, "id": ident})

    @app.get("/api/ioc/ip/{ip}/sessions", response_model=TableResponse)
    def table_sessions_for_ip(
        ip: str, size: int = Query(50, ge=1, le=500),
        frm: int = Query(0, ge=0),
        require_login: bool = Query(True),
        require_commands: bool = Query(True),
    ) -> TableResponse:
        sf = _session_filter(require_login, require_commands)
        r = queries.sessions_for_ip(es, cfg, ip, size=size, frm=frm, sf=sf)
        return _table(r, frm, size)

    @app.get("/api/ioc/session/{sid}/commands", response_model=TableResponse)
    def table_commands_for_session(sid: str, size: int = Query(50, ge=1, le=500)) -> TableResponse:
        r = queries.commands_for_session(es, cfg, sid, size=size)
        return TableResponse(total=r["total"], rows=r["rows"],
                             page={"from": 0, "size": size})

    @app.get("/api/ioc/command/{sha}/sessions", response_model=TableResponse)
    def table_sessions_for_command(
        sha: str, size: int = Query(50, ge=1, le=500),
        require_login: bool = Query(True),
        require_commands: bool = Query(True),
    ) -> TableResponse:
        sf = _session_filter(require_login, require_commands)
        r = queries.sessions_for_command(es, cfg, sha.lower(), size=size, sf=sf)
        return TableResponse(total=r["total"], rows=r["rows"],
                             page={"from": 0, "size": size})

    @app.get("/api/cluster/{kind}/{cid}/members", response_model=TableResponse)
    def table_cluster_members(
        kind: str, cid: str, size: int = Query(50, ge=1, le=500),
        require_login: bool = Query(True),
        require_commands: bool = Query(True),
    ) -> TableResponse:
        if kind not in ("command", "session", "ip"):
            raise HTTPException(400, "kind must be one of command|session|ip")
        sf = _session_filter(require_login, require_commands) if kind == "session" else None
        r = queries.members_of_cluster(es, cfg, kind, cid, size=size, sf=sf)
        return _table(r, 0, size)

    @app.get("/api/ioc/{ioc_type}/{ident}", response_model=IOCDetail)
    def ioc_detail(ioc_type: str, ident: str) -> IOCDetail:
        if not ioc.is_known_type(ioc_type):
            raise HTTPException(400, f"unknown ioc_type: {ioc_type}")

        if ioc_type == "ip":
            doc = queries.lookup_ip(es, cfg, ident)
            if not doc:
                raise HTTPException(404, "ip not found")
            return _detail_ip_with_playbooks(es, cfg, ident, doc)
        if ioc_type == "session":
            doc = queries.lookup_session(es, cfg, ident)
            if not doc:
                raise HTTPException(404, "session not found")
            return _detail_session(ident, doc)
        if ioc_type in ("command", "command_hash"):
            doc = queries.lookup_command(es, cfg, ident.lower())
            if not doc:
                raise HTTPException(404, "command not found")
            return _detail_command(ident.lower(), doc)
        if ioc_type in ("command_cluster", "session_cluster", "ip_cluster"):
            kind = ioc_type.replace("_cluster", "")
            doc = queries.lookup_cluster(es, cfg, kind, ident, run_cache)
            return _detail_cluster(kind, ident, doc)
        if ioc_type == "playbook":
            data = queries.lookup_playbook(es, cfg, ident)
            title = (data.get("name") or ident) if isinstance(data, dict) else ident
            return IOCDetail(
                type="playbook", id=ident, title=f"playbook: {title}",
                summary=data, raw=None,
            )
        if ioc_type == "campaign":
            # Multi-session campaign — mined into its own index by
            # `dshield_prism mine campaigns`. Distinct from playbook (which
            # is a named session cluster).
            doc = queries.lookup_campaign(es, cfg, ident)
            if not doc:
                raise HTTPException(404, f"campaign not found: {ident}")
            title = doc.get("name") or ident
            return IOCDetail(
                type="campaign", id=ident, title=f"campaign: {title}",
                summary=doc, raw=None,
            )
        if ioc_type == "asn":
            return IOCDetail(type="asn", id=ident, title=f"AS{ident}",
                             summary={"asn": ident}, raw=None)
        if ioc_type == "country":
            return IOCDetail(type="country", id=ident.upper(),
                             title=f"country {ident.upper()}",
                             summary={"country_iso_code": ident.upper()}, raw=None)
        if ioc_type in ("mitre_technique", "mitre_tactic"):
            return IOCDetail(type=ioc_type, id=ident.upper(),
                             title=ident.upper(), summary={"id": ident.upper()}, raw=None)
        raise HTTPException(400, f"detail not implemented for {ioc_type}")

    # ------------------------------------------------------------------
    # Ask AI
    # ------------------------------------------------------------------
    llm_cfg = cfg.llm

    @app.post("/api/ask")
    def ask_llm(body: AskRequest) -> JSONResponse:
        if not llm_cfg:
            raise HTTPException(503, "LLM not configured — add an llm: block to local.yaml")
        if not body.question.strip():
            raise HTTPException(400, "question is required")
        prompt = _build_ask_prompt(body.question, body.context)
        try:
            headers = {"Content-Type": "application/json"}
            if llm_cfg.api_key:
                headers["Authorization"] = f"Bearer {llm_cfg.api_key}"
            base = llm_cfg.base_url.rstrip("/").removesuffix("/v1")
            payload = {
                "model": llm_cfg.generation_model,
                "messages": [
                    {"role": "system", "content": (
                        "You are a cybersecurity analyst assistant helping investigate "
                        "honeypot intrusion data from DShield sensors. "
                        "Be concise and actionable. Refer specifically to the data provided."
                    )},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 2048,
                "stream": False,
            }
            r = httpx.post(
                f"{base}/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=llm_cfg.request_timeout,
            )
            if r.status_code != 200:
                raise HTTPException(502, f"LLM returned {r.status_code}: {r.text[:300]}")
            data = r.json()
            answer = data["choices"][0]["message"]["content"] or ""
            return JSONResponse({"answer": answer, "model": llm_cfg.generation_model})
        except HTTPException:
            raise
        except Exception as e:
            log.exception("ask_llm failed")
            raise HTTPException(500, f"LLM request failed: {e}")

    return app


def _build_ask_prompt(question: str, context: dict) -> str:
    lines: list[str] = []

    anchor = context.get("anchor")
    if anchor:
        lines.append(f"Focus IOC: {anchor.get('type')} — {anchor.get('id')}")

    detail = context.get("detail")
    if detail and detail.get("summary"):
        lines.append("Selected node detail:")
        for k, v in detail["summary"].items():
            if v is not None and v != "" and v != []:
                lines.append(f"  {k}: {v}")

    playbooks = context.get("playbooks", [])
    if playbooks:
        lines.append(f"Playbooks in view: {', '.join(str(p) for p in playbooks)}")
    campaigns = context.get("campaigns", [])
    if campaigns:
        lines.append(f"Campaigns in view: {', '.join(str(c) for c in campaigns)}")

    nc = context.get("node_counts", {})
    lines.append(
        f"Graph contains {nc.get('ips', 0)} IPs, "
        f"{nc.get('sessions', 0)} sessions, "
        f"{nc.get('commands', 0)} commands."
    )

    nodes = context.get("nodes", [])
    ips      = [n for n in nodes if n.get("type") == "ip"]
    sessions = [n for n in nodes if n.get("type") == "session"]
    commands = [n for n in nodes if n.get("type") == "command"]

    if ips:
        lines.append(f"\nIPs ({len(ips)} shown):")
        for n in ips[:25]:
            parts = [n.get("label") or n.get("id", "?")]
            if n.get("country"):   parts.append(f"cc={n['country']}")
            if n.get("asn"):       parts.append(f"AS{n['asn']}")
            if n.get("playbook_name"):  parts.append(f"playbook={n['playbook_name']}")
            if n.get("novelty") is not None:
                parts.append(f"novelty={float(n['novelty']):.2f}")
            if n.get("is_outlier"): parts.append("OUTLIER")
            lines.append("  " + "  ".join(parts))

    if sessions:
        lines.append(f"\nSessions: {len(sessions)} total.")
        outliers = [n for n in sessions if n.get("is_outlier")]
        if outliers:
            lines.append(f"  {len(outliers)} outlier session(s).")
        intents: dict[str, int] = {}
        for n in sessions:
            intent = n.get("intent") or n.get("dominant_intent")
            if intent:
                intents[intent] = intents.get(intent, 0) + 1
        if intents:
            lines.append("  Intent breakdown: " +
                         ", ".join(f"{k}={v}" for k, v in sorted(intents.items(), key=lambda x: -x[1])))

    if commands:
        lines.append(f"\nCommands ({min(len(commands), 25)} of {len(commands)} shown):")
        for n in commands[:25]:
            parts = [n.get("label") or (n.get("id") or "?")[:40]]
            if n.get("intent"):  parts.append(f"intent={n['intent']}")
            if n.get("novelty") is not None:
                parts.append(f"novelty={float(n['novelty']):.2f}")
            if n.get("is_outlier"): parts.append("OUTLIER")
            lines.append("  " + "  ".join(parts))

    lines.append(f"\nQuestion: {question}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Detail builders (pull out the headline fields a human wants to see first)
# ---------------------------------------------------------------------------

def _detail_ip(ip: str, doc: dict) -> IOCDetail:
    src = doc["_source"]
    geo = (src.get("source") or {}).get("geo") or {}
    asn = (src.get("source") or {}).get("as") or {}
    enr = src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip", {})
    total_sessions = enr.get("total_sessions")
    successful_sessions = enr.get("successful_sessions")
    # Failed-login sessions: connections that didn't successfully authenticate.
    # Computed from the rollup's totals rather than counted separately so the
    # number reflects whatever the worker's most recent rollup produced.
    failed_login_sessions = None
    if isinstance(total_sessions, (int, float)) and isinstance(successful_sessions, (int, float)):
        failed_login_sessions = max(0, int(total_sessions) - int(successful_sessions))
    summary: dict[str, Any] = {
        "ip": ip,
        "country": geo.get("country_iso_code"),
        "region": geo.get("region_name"),
        "city": geo.get("city_name"),
        "asn": asn.get("number"),
        "asn_org": (asn.get("organization") or {}).get("name"),
        "total_sessions": total_sessions,
        "successful_sessions": successful_sessions,
        "failed_login_sessions": failed_login_sessions,
        "command_sessions": enr.get("command_sessions"),
        "total_commands": enr.get("total_commands"),
        "file_download_count": enr.get("file_download_count"),
        "dominant_intent": enr.get("dominant_intent"),
        "mean_novelty_score": enr.get("mean_novelty_score"),
        "first_seen": enr.get("first_seen"),
        "last_seen": enr.get("last_seen"),
        "cluster_id": (enr.get("cluster") or {}).get("id"),
        "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
        # An IP's playbook membership is derived from its sessions, not
        # stored on the IP doc — see `_detail_ip_with_playbooks` below.
    }
    return IOCDetail(type="ip", id=ip, title=ip, summary=summary, raw=src)


def _detail_ip_with_playbooks(es, cfg, ip: str, doc: dict) -> IOCDetail:
    """Wrap `_detail_ip` with a derived list of playbooks this IP ran.

    The list is derived through this IP's sessions, each tagged with its
    session-cluster's id+name.
    """
    detail = _detail_ip(ip, doc)
    try:
        pbs = queries.playbooks_for_ip(es, cfg, ip)
    except Exception:
        pbs = []
    detail.summary["playbooks"]      = pbs
    detail.summary["playbook_count"] = len(pbs)
    return detail


def _detail_session(sid: str, doc: dict) -> IOCDetail:
    src = doc["_source"]
    senr = src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session", {})
    ev = src.get("event") or {}
    summary: dict[str, Any] = {
        "session_id": sid,
        "src_ip": (src.get("source") or {}).get("ip"),
        "user": (src.get("user") or {}).get("name"),
        "password": (src.get("cowrie") or {}).get("password"),
        "start": ev.get("start"),
        "end": ev.get("end"),
        "duration_ms": ev.get("duration"),
        "command_count": senr.get("command_count"),
        "unique_commands": senr.get("unique_commands"),
        "login_success_count": senr.get("login_success_count"),
        "login_fail_count": senr.get("login_fail_count"),
        "file_download_count": senr.get("file_download_count"),
        "file_upload_count": senr.get("file_upload_count"),
        "dominant_intent": senr.get("dominant_intent"),
        "mean_novelty_score": senr.get("mean_novelty_score"),
        "max_novelty_score": senr.get("max_novelty_score"),
        "playbook_id":   senr.get("playbook_id"),
        "playbook_name": senr.get("playbook_name"),
        "cluster_id": (senr.get("cluster") or {}).get("id"),
        "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
    }
    return IOCDetail(type="session", id=sid, title=f"session {sid}", summary=summary, raw=src)


def _detail_command(sha: str, doc: dict) -> IOCDetail:
    src = doc["_source"]
    enr = src.get("dshield", {}).get("cowrie", {}).get("enrichment") or {}
    fb = enr.get("local_fallback") or {}
    threat = src.get("threat") or {}
    summary: dict[str, Any] = {
        "sha256": sha,
        "command_line": (src.get("process") or {}).get("command_line"),
        "intent": enr.get("intent") or fb.get("intent"),
        "confidence": enr.get("confidence") or fb.get("confidence"),
        "description": fb.get("description"),
        "tactics": fb.get("tactics") or [t.get("id") for t in (threat.get("tactic") if isinstance(threat.get("tactic"), list) else [threat.get("tactic")]) if t],
        "techniques": fb.get("techniques") or [t.get("id") for t in (threat.get("technique") if isinstance(threat.get("technique"), list) else [threat.get("technique")]) if t],
        "occurrence_count": enr.get("occurrence_count"),
        "unique_sessions": enr.get("unique_sessions"),
        "unique_source_ips": enr.get("unique_source_ips"),
        "triage_reasons": enr.get("triage_reasons"),
        "cluster_id": (enr.get("cluster") or {}).get("id"),
        "novelty_score": (enr.get("cluster") or {}).get("novelty_score"),
        "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
        "model": enr.get("model"),
    }
    return IOCDetail(type="command", id=sha, title=f"command {sha[:12]}…", summary=summary, raw=src)


def _detail_cluster(kind: str, cid: str, doc: dict | None) -> IOCDetail:
    if not doc:
        return IOCDetail(
            type=f"{kind}_cluster", id=cid, title=f"{kind} cluster {cid}",
            summary={"note": "centroid doc not found in latest run", "kind": kind, "id": cid},
            raw=None,
        )
    src = doc["_source"]
    summary: dict[str, Any] = {
        "kind": kind,
        "cluster_id": cid,
        "size": src.get("size"),
        "run_id": src.get("run_id"),
        # Session-cluster centroids carry playbook_id/playbook_name; other
        # centroid kinds simply have these as None.
        "playbook_id":   src.get("playbook_id"),
        "playbook_name": src.get("playbook_name"),
        "sample_commands": src.get("sample_commands"),
        "sample_session_ids": src.get("sample_session_ids"),
        "sample_ips": src.get("sample_ips"),
    }
    return IOCDetail(type=f"{kind}_cluster", id=cid,
                     title=f"{kind} cluster {cid}", summary=summary, raw=src)


def _table(r: dict, frm: int, size: int) -> TableResponse:
    rows = [{"_id": h["_id"], **h["_source"]} for h in r["hits"]["hits"]]
    return TableResponse(total=r["hits"]["total"]["value"], rows=rows,
                         page={"from": frm, "size": size})
