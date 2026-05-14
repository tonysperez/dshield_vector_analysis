/* Top-level glue: search, fetch, detail panel, breadcrumb, URL state. */

(function () {
  const $ = (sel) => document.querySelector(sel);

  // ---------------------------------------------------------------------
  // Mapping from API ioc types to graph node id prefixes (mirrors graph.py).
  // ---------------------------------------------------------------------
  // `playbook` = LLM-named session cluster (prefix `pb:`). `campaign` =
  // multi-session pattern mined by `mine campaigns` (prefix `camp:`). Both
  // are distinct IOC types that get rendered in their own columns.
  const TYPE_TO_PREFIX = {
    ip: "ip",
    session: "session",
    command: "cmd",
    command_hash: "cmd",
    command_cluster: "cmdcl",
    session_cluster: "sescl",
    ip_cluster: "ipcl",
    playbook: "pb",
    campaign: "camp",
    asn: "asn",
    country: "cc",
    mitre_technique: "tt",
    mitre_tactic: "ta",
  };
  const PREFIX_TO_TYPE = {
    ip: "ip",
    session: "session",
    cmd: "command",
    cmdcl: "command_cluster",
    sescl: "session_cluster",
    ipcl: "ip_cluster",
    pb: "playbook",
    camp: "campaign",
    asn: "asn",
    cc: "country",
    tt: "mitre_technique",
    ta: "mitre_tactic",
  };

  function nodeIdFor(type, id) {
    const p = TYPE_TO_PREFIX[type] || type;
    return `${p}:${id}`;
  }
  function parseNodeId(nid) {
    const idx = nid.indexOf(":");
    const prefix = nid.slice(0, idx);
    const id = nid.slice(idx + 1);
    return { type: PREFIX_TO_TYPE[prefix] || prefix, id };
  }

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------
  // Two-dimensional traversal:
  //   - Pipeline (horizontal) — IP → Session → Command → MITRE. Always
  //     auto-extended from the anchor as far as the data goes. Edges here
  //     are causal (this IP ran these sessions which ran these commands).
  //   - Siblings (vertical)  — cluster / playbook membership. These are
  //     similarity relationships; expanding them brings in "other things
  //     that look like this." Controlled by state.siblings (0-3).
  //
  // The user can also hide individual lanes via state.lanesVisible (any of
  // geo, ip, session, command, mitre). Hiding a lane removes its nodes
  // from the graph; re-enabling forces a pipeline re-fetch to backfill.
  const state = {
    anchor: null,           // {type, id}
    history: [],            // [{type, id, label}]
    currentDetail: null,    // last /api/ioc/... payload
    siblings: 0,            // cluster sibling expansion levels (0 = none)
    pipelineExpanded: new Set(),  // ids whose pipeline neighbors we've fetched
    siblingsExpanded: new Set(),  // cluster pill ids whose members we've fetched
    // Per-node directional role for pipeline auto-trace:
    //   "anchor"     = user's anchor node, fully traces in valid directions
    //   "miniAnchor" = a cluster/geo/mitre-sibling that should trace its own
    //                  full pipeline (mini-anchor)
    //   "trace"      = a session reached via the anchor's auto-trace; fetched
    //                  to extend the pipeline ONE more step
    //   "leaf"       = node added for context only; not re-fetched (this is
    //                  what prevents lateral fan-out through commands)
    pipelineRole: new Map(),
    depthOf: new Map(),     // node id -> siblings depth from anchor (0 = anchor's pipeline)
    expandToken: 0,         // cancels in-flight expansion when anchor / reset changes
    inflight: 0,            // # of /neighbors requests currently in-flight
    lanesVisible: new Set(["geo", "ip", "session", "command", "mitre"]),
    // Clusters added via the "+ Add cluster to view" button. Stored as
    //   clusterNodeId -> Set<node id> introduced by that click
    // so we can undo precisely what was added (clusters that arrived via
    // auto-trace or initial anchor aren't tracked here).
    addedClusters: new Map(),
  };

  // ---------------------------------------------------------------------
  // Settings (persisted to localStorage)
  // ---------------------------------------------------------------------
  // Threat-hunter defaults: only sessions that successfully logged in AND
  // ran a command. Users can flip either off via the settings modal.
  const SETTINGS_KEY = "dshield-console.settings.v1";
  const SETTINGS_DEFAULTS = { requireLogin: true, requireCommands: true };
  function loadSettings() {
    try {
      const raw = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "null");
      return Object.assign({}, SETTINGS_DEFAULTS, raw || {});
    } catch (e) {
      return { ...SETTINGS_DEFAULTS };
    }
  }
  function saveSettings(s) {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  }
  const settings = loadSettings();

  // ---------------------------------------------------------------------
  // API helpers
  // ---------------------------------------------------------------------
  // Every call appends the current session-quality filter as query params
  // so the server applies the same filter everywhere. Callers can still
  // pass `?foo=bar` in the path; we splice with the right separator.
  function _withFilterParams(path) {
    const sep = path.includes("?") ? "&" : "?";
    return `${path}${sep}require_login=${settings.requireLogin}&require_commands=${settings.requireCommands}`;
  }

  async function api(path) {
    const r = await fetch(_withFilterParams(path));
    if (!r.ok) {
      const text = await r.text().catch(() => "");
      throw new Error(`${r.status} ${r.statusText}: ${text.slice(0, 200)}`);
    }
    return r.json();
  }

  // ---------------------------------------------------------------------
  // Health badge
  // ---------------------------------------------------------------------
  async function refreshHealth() {
    const badge = $("#health");
    try {
      const h = await api("/api/health");
      if (h.ok) {
        const total = Object.values(h.doc_counts).filter((v) => typeof v === "number").reduce((a, b) => a + b, 0);
        badge.textContent = `ES ${h.elasticsearch_version} • ${total.toLocaleString()} docs`;
        badge.className = "health ok";
      } else {
        badge.textContent = `ES error: ${h.error || "unknown"}`;
        badge.className = "health err";
      }
    } catch (e) {
      badge.textContent = `ES error: ${e.message}`;
      badge.className = "health err";
    }
  }

  // ---------------------------------------------------------------------
  // Search
  // ---------------------------------------------------------------------
  async function doSearch(q) {
    const sugg = $("#search-suggestions");
    sugg.innerHTML = "";
    sugg.classList.add("hidden");

    let resp;
    try {
      resp = await api(`/api/search?q=${encodeURIComponent(q)}`);
    } catch (e) {
      alert(`Search failed: ${e.message}`);
      return;
    }
    const cands = resp.candidates.filter((c) => c.type !== "freetext");
    if (cands.length === 0) {
      alert("No matches.");
      return;
    }
    if (cands.length === 1) {
      _navigateTo(cands[0].type, cands[0].id);
      return;
    }
    cands.forEach((c) => {
      const div = document.createElement("div");
      div.className = "item";
      div.innerHTML = `<span class="ty">${c.type}</span><span class="id">${escapeHtml(c.label || c.id)}</span>`;
      div.addEventListener("click", () => {
        sugg.classList.add("hidden");
        _navigateTo(c.type, c.id);
      });
      sugg.appendChild(div);
    });
    sugg.classList.remove("hidden");
  }

  // ---------------------------------------------------------------------
  // Anchor / expand
  // ---------------------------------------------------------------------
  async function anchor(type, id, opts = {}) {
    state.anchor = { type, id };
    if (!opts.skipHistory) {
      const last = state.history[state.history.length - 1];
      if (!last || last.type !== type || last.id !== id) {
        state.history.push({ type, id, label: `${type}:${truncate(id, 24)}` });
      }
    }
    updateBreadcrumb();
    updateUrl();

    // Cancel any in-flight expansion for the previous anchor.
    state.expandToken += 1;
    state.depthOf = new Map();
    state.pipelineExpanded = new Set();
    state.siblingsExpanded = new Set();
    state.pipelineRole = new Map();
    state.addedClusters = new Map();
    // The previous anchor's sidecar filter doesn't make sense against a
    // fresh graph (set ids almost certainly differ); clear it so the new
    // view isn't silently filtered to nothing.
    setsState.active.clear();
    setsState.mode = "union";

    const [detail, graph] = await Promise.all([
      api(`/api/ioc/${encodeURIComponent(type)}/${encodeURIComponent(id)}`).catch((e) => ({ error: e.message })),
      api(`/api/ioc/${encodeURIComponent(type)}/${encodeURIComponent(id)}/neighbors?limit=50`).catch((e) => ({ error: e.message })),
    ]);
    const anchorNodeId = nodeIdFor(type, id);
    if (graph.error) {
      alert(`Neighbors failed: ${graph.error}`);
    } else {
      Graph.replace(graph, anchorNodeId);
      // Anchor sits at sibling-depth 0; everything reached via pipeline
      // auto-trace also stays at depth 0. Cluster pills sit at depth 0
      // too — only their *members* (when expanded) bump depth to 1+.
      state.depthOf.set(anchorNodeId, 0);
      state.pipelineRole.set(anchorNodeId, "anchor");
      state.pipelineExpanded.add(anchorNodeId);
      assignRolesFromFetch(anchorNodeId, type, graph);
      for (const n of (graph.nodes || [])) {
        const nid = n.data && n.data.id;
        if (nid && !state.depthOf.has(nid)) state.depthOf.set(nid, 0);
      }
      // Auto-trace the pipeline + apply siblings depth.
      refreshExpansion();
    }
    if (detail.error) {
      renderDetailError(type, id, detail.error);
    } else {
      renderDetail(detail);
    }
  }

  async function expand(node, originNodeId) {
    if (!node || !node.id) return;
    const { type, id } = parseNodeId(node.id);
    try {
      const g = await api(`/api/ioc/${encodeURIComponent(type)}/${encodeURIComponent(id)}/neighbors?limit=30`);
      const originId = originNodeId || node.id;
      const baseDepth = state.depthOf.has(originId)
        ? state.depthOf.get(originId)
        : 0;
      const isCluster = CLUSTER_KINDS.has(type);
      const childDepth = isCluster ? baseDepth + 1 : baseDepth;
      // Manual expand: the origin is acting as the user's chosen focus.
      // Promote it to mini-anchor so its pipeline auto-traces fully.
      state.pipelineRole.set(originId, "miniAnchor");
      if (isCluster) state.siblingsExpanded.add(originId);
      else state.pipelineExpanded.add(originId);
      assignRolesFromFetch(originId, type, g);
      for (const n of (g.nodes || [])) {
        const nid = n.data && n.data.id;
        if (!nid) continue;
        if (!state.depthOf.has(nid) || state.depthOf.get(nid) > childDepth) {
          state.depthOf.set(nid, childDepth);
        }
      }
      Graph.merge(g, originId);
      refreshExpansion();
    } catch (e) {
      alert(`Expand failed: ${e.message}`);
    }
  }

  async function selectNode(node) {
    if (!node || !node.id) return;
    // Campaign and cluster pill nodes also activate the sets filter so
    // clicking them instantly highlights every member without needing the
    // sidecar. Clicking the same node again clears the filter.
    _toggleNodeSetHighlight(node);
    const { type, id } = parseNodeId(node.id);
    try {
      const d = await api(`/api/ioc/${encodeURIComponent(type)}/${encodeURIComponent(id)}`);
      renderDetail(d);
    } catch (e) {
      renderDetailError(type, id, e.message);
    }
  }

  function _nodeSetId(node) {
    if (!node) return null;
    if (node.type === "playbook") {
      const cid = node.playbook_id || node.id.replace(/^pb:/, "");
      return "playbook:" + cid;
    }
    if (node.type === "campaign") {
      // node.id = "camp:<campaign_id>" (multi-session, from mine campaigns).
      const cid = node.campaign_id || node.id.replace(/^camp:/, "");
      return "campaign:" + cid;
    }
    if (node.type && node.type.endsWith("_cluster")) {
      // node.id = "ipcl:cluster_8"  →  set id = "ip_cluster:cluster_8"
      const cid = node.id.includes(":") ? node.id.split(":").slice(1).join(":") : node.id;
      return `${node.type}:${cid}`;
    }
    return null;
  }

  function _toggleNodeSetHighlight(node) {
    const setId = _nodeSetId(node);
    if (!setId) return;
    if (setsState.active.size === 1 && setsState.active.has(setId)) {
      // Second click on the same node → clear the highlight.
      clearSetsFilter();
    } else {
      setsState.active.clear();
      setsState.active.add(setId);
      setsState.mode = "union";
      applySetsFilter();
      renderSets();
    }
  }

  // ---------------------------------------------------------------------
  // Detail panel
  // ---------------------------------------------------------------------
  function renderDetail(d) {
    state.currentDetail = d;
    $("#detail-header").innerHTML =
      `<div class="type">${escapeHtml(d.type)}</div>` +
      `<h2>${escapeHtml(d.title)}</h2>`;

    const overview = $("#tab-overview");
    overview.innerHTML = "";
    renderActions(d, overview);
    // Structured sections are rendered with their own custom widgets; the
    // generic kv table below skips any key we've already consumed.
    const consumed = renderStructuredSections(d, overview);
    const kv = document.createElement("div");
    kv.className = "kv";
    for (const [k, v] of Object.entries(d.summary || {})) {
      if (consumed.has(k)) continue;
      if (v === null || v === undefined || v === "") continue;
      const kEl = document.createElement("div"); kEl.className = "k"; kEl.textContent = k;
      const vEl = document.createElement("div"); vEl.className = "v";
      const pivot = makePivot(k, v);
      if (pivot) {
        vEl.classList.add("pivot");
        vEl.textContent = fmtValue(v);
        vEl.addEventListener("click", () => anchor(pivot.type, pivot.id));
      } else {
        vEl.textContent = fmtValue(v);
      }
      kv.appendChild(kEl); kv.appendChild(vEl);
    }
    overview.appendChild(kv);

    $("#raw-json").textContent = JSON.stringify(d.raw || {}, null, 2);

    // Related tab: pull a few tables based on type.
    const rel = $("#tab-related");
    rel.innerHTML = "<em>loading…</em>";
    loadRelated(d, rel);
  }

  // Render rich/structured fields of `d.summary` as their own widgets and
  // return the set of summary keys we consumed (so the generic kv table
  // doesn't dump them as raw JSON). Each section is its own self-contained
  // chunk and is robust to missing data — if a key is absent we just don't
  // render that section.
  function renderStructuredSections(d, container) {
    const consumed = new Set();
    const s = d.summary || {};

    // -- Feature 1+2: list of playbooks this IP ran ------------------------
    if (Array.isArray(s.playbooks) && s.playbooks.length > 0) {
      consumed.add("playbooks");
      consumed.add("playbook_count");
      const section = document.createElement("div");
      section.className = "detail-section playbooks-section";
      const head = document.createElement("div");
      head.className = "section-head";
      head.textContent = `Playbooks (${s.playbooks.length})`;
      section.appendChild(head);

      const list = document.createElement("table");
      list.className = "section-table playbooks-table";
      const thead = document.createElement("thead");
      thead.innerHTML = "<tr><th>Name</th><th>Sessions</th><th>Last seen</th></tr>";
      list.appendChild(thead);
      const tbody = document.createElement("tbody");
      for (const c of s.playbooks) {
        const tr = document.createElement("tr");
        tr.className = "pivot-row";
        tr.title = c.id;
        tr.addEventListener("click", () => anchor("playbook", c.id));
        const tdName = document.createElement("td");
        tdName.textContent = c.name || c.id;
        tdName.className = "playbook-name";
        const tdSessions = document.createElement("td");
        tdSessions.textContent = String(c.session_count ?? 0);
        tdSessions.className = "num";
        const tdLast = document.createElement("td");
        tdLast.textContent = c.last_seen ? fmtShortDate(c.last_seen) : "—";
        tdLast.className = "ts";
        tr.appendChild(tdName); tr.appendChild(tdSessions); tr.appendChild(tdLast);
        tbody.appendChild(tr);
      }
      list.appendChild(tbody);
      section.appendChild(list);
      container.appendChild(section);
    } else if (s.playbook_count === 0) {
      consumed.add("playbook_count");
      consumed.add("playbooks");
    }

    // -- Feature 3: playbook detail panel rich sections ---------------------
    // The playbook IOC type returns timespan / activity-delta / top geo /
    // top intents / sample commands. Each is its own widget; the generic
    // kv loop continues to render the basic counts (session_count, ip_count,
    // cluster_size, etc.). The rich activity/geo/intent/sample-commands
    // section is the playbook detail panel; the new multi-session
    // campaign IOC has a different shape and is handled below.
    if (d.type === "playbook") {
      // Activity row: first_seen .. last_seen, with the 24h delta arrow.
      if (s.first_seen || s.last_seen || s.last_24h != null) {
        consumed.add("first_seen");
        consumed.add("last_seen");
        consumed.add("last_24h");
        consumed.add("prior_24h");
        const section = document.createElement("div");
        section.className = "detail-section";
        const head = document.createElement("div");
        head.className = "section-head";
        head.textContent = "Activity";
        section.appendChild(head);
        const kv = document.createElement("div");
        kv.className = "kv";
        if (s.first_seen) {
          kv.insertAdjacentHTML("beforeend",
            `<div class="k">first seen</div><div class="v">${escapeHtml(fmtShortDate(s.first_seen))}</div>`);
        }
        if (s.last_seen) {
          kv.insertAdjacentHTML("beforeend",
            `<div class="k">last seen</div><div class="v">${escapeHtml(fmtShortDate(s.last_seen))}</div>`);
        }
        if (s.last_24h != null || s.prior_24h != null) {
          const cur  = s.last_24h  ?? 0;
          const prev = s.prior_24h ?? 0;
          let arrow = "→";
          let cls = "delta-flat";
          if (cur > prev) { arrow = "↑"; cls = "delta-up"; }
          else if (cur < prev) { arrow = "↓"; cls = "delta-down"; }
          kv.insertAdjacentHTML("beforeend",
            `<div class="k">last 24h</div><div class="v ${cls}">${cur} sessions <span class="delta-arrow">${arrow}</span> (prior 24h: ${prev})</div>`);
        }
        section.appendChild(kv);
        container.appendChild(section);
      }

      // Top countries chips.
      if (Array.isArray(s.top_countries) && s.top_countries.length > 0) {
        consumed.add("top_countries");
        container.appendChild(_chipSection("Top countries", s.top_countries.map(c => ({
          label: c.cc, count: c.count,
          pivot: { type: "country", id: c.cc },
        }))));
      }

      // Top ASNs chips.
      if (Array.isArray(s.top_asns) && s.top_asns.length > 0) {
        consumed.add("top_asns");
        container.appendChild(_chipSection("Top ASNs", s.top_asns.map(a => ({
          label: `AS${a.asn}`, count: a.count,
          pivot: { type: "asn", id: String(a.asn) },
        }))));
      }

      // Top intents chips (no pivot — intent isn't a navigable IOC type).
      if (Array.isArray(s.top_intents) && s.top_intents.length > 0) {
        consumed.add("top_intents");
        container.appendChild(_chipSection("Top intents", s.top_intents.map(i => ({
          label: i.intent, count: i.count,
        }))));
      }

      // Sample commands — three short strings the playbook's sessions
      // were running. Read-only; the user can pivot from a session to a
      // specific command from the Related tab.
      if (Array.isArray(s.sample_commands) && s.sample_commands.length > 0) {
        consumed.add("sample_commands");
        const section = document.createElement("div");
        section.className = "detail-section";
        const head = document.createElement("div");
        head.className = "section-head";
        head.textContent = "Sample commands";
        section.appendChild(head);
        const ul = document.createElement("ul");
        ul.className = "sample-commands";
        for (const c of s.sample_commands) {
          const li = document.createElement("li");
          li.textContent = c;
          li.title = c;
          ul.appendChild(li);
        }
        section.appendChild(ul);
        container.appendChild(section);
      }
    }

    // -- Multi-session campaign IOC detail panel ----------------------------
    // Payload shape from `mine campaigns` (see queries.lookup_campaign):
    //   { kind, name, rationale, ip_count, session_count,
    //     first_seen, last_seen, support,
    //     member_playbook_ids[], member_session_ids[], member_source_ips[],
    //     shared_artifacts: [{kind, value, count}, ...] }
    if (d.type === "campaign") {
      consumed.add("rationale");
      consumed.add("member_playbook_ids");
      consumed.add("member_session_ids");
      consumed.add("member_source_ips");
      consumed.add("shared_artifacts");
      if (s.rationale) {
        const sec = document.createElement("div");
        sec.className = "detail-section";
        const head = document.createElement("div");
        head.className = "section-head";
        head.textContent = "Why this is a campaign";
        sec.appendChild(head);
        const p = document.createElement("div");
        p.style.fontSize = "12px";
        p.textContent = s.rationale;
        sec.appendChild(p);
        container.appendChild(sec);
      }
      if (Array.isArray(s.member_playbook_ids) && s.member_playbook_ids.length > 0) {
        container.appendChild(_chipSection(
          `Playbooks in this campaign (${s.member_playbook_ids.length})`,
          s.member_playbook_ids.map((pid) => ({
            label: pid, pivot: { type: "playbook", id: pid },
          })),
        ));
      }
      if (Array.isArray(s.shared_artifacts) && s.shared_artifacts.length > 0) {
        const sec = document.createElement("div");
        sec.className = "detail-section";
        const head = document.createElement("div");
        head.className = "section-head";
        head.textContent = `Shared artifacts (${s.shared_artifacts.length})`;
        sec.appendChild(head);
        const ul = document.createElement("ul");
        ul.className = "sample-commands";
        for (const art of s.shared_artifacts.slice(0, 25)) {
          const li = document.createElement("li");
          li.textContent = `[${art.kind}] ${art.value}  (×${art.count})`;
          li.title = art.value;
          ul.appendChild(li);
        }
        sec.appendChild(ul);
        container.appendChild(sec);
      }
      if (Array.isArray(s.member_source_ips) && s.member_source_ips.length > 0) {
        container.appendChild(_chipSection(
          `Source IPs in this campaign (${s.member_source_ips.length})`,
          s.member_source_ips.slice(0, 30).map((ip) => ({
            label: ip, pivot: { type: "ip", id: ip },
          })),
        ));
      }
    }

    return consumed;
  }

  function _chipSection(title, items) {
    const section = document.createElement("div");
    section.className = "detail-section";
    const head = document.createElement("div");
    head.className = "section-head";
    head.textContent = title;
    section.appendChild(head);
    const row = document.createElement("div");
    row.className = "chip-row";
    for (const it of items) {
      const chip = document.createElement("span");
      chip.className = "chip" + (it.pivot ? " chip-pivot" : "");
      chip.innerHTML = `${escapeHtml(String(it.label || ""))}<span class="count">${it.count ?? ""}</span>`;
      if (it.pivot) {
        chip.style.cursor = "pointer";
        chip.title = `Pivot to ${it.pivot.type} ${it.pivot.id}`;
        chip.addEventListener("click", () => anchor(it.pivot.type, it.pivot.id));
      }
      row.appendChild(chip);
    }
    section.appendChild(row);
    return section;
  }

  function fmtShortDate(s) {
    // ES returns ISO-8601 with millis. Drop seconds for the table view.
    if (!s) return "";
    return String(s).replace("T", " ").replace(/:\d{2}\.\d+Z?$/, "").replace(/Z$/, "");
  }

  function renderDetailError(type, id, msg) {
    $("#detail-header").innerHTML =
      `<div class="type">${escapeHtml(type)}</div><h2>${escapeHtml(id)}</h2>`;
    $("#tab-overview").innerHTML = `<div class="kv"><div class="k">error</div><div class="v">${escapeHtml(msg)}</div></div>`;
    $("#tab-related").innerHTML = "";
    $("#raw-json").textContent = "";
  }

  async function loadRelated(d, container) {
    container.innerHTML = "";
    const type = d.type;
    const id = d.id;
    try {
      if (type === "ip") {
        const t = await api(`/api/ioc/ip/${encodeURIComponent(id)}/sessions?size=25`);
        container.appendChild(buildRelatedTable("Sessions from this IP", t, [
          { key: "_id", label: "session_id", pivot: (v) => ({ type: "session", id: v }) },
          { key: "event.start", label: "start" },
          { key: "dshield.cowrie.enrichment.session.command_count", label: "cmds" },
          { key: "dshield.cowrie.enrichment.session.dominant_intent", label: "intent" },
        ]));
      } else if (type === "session") {
        const t = await api(`/api/ioc/session/${encodeURIComponent(id)}/commands?size=50`);
        container.appendChild(buildRelatedTable("Commands in this session", { rows: t.rows, total: t.total }, [
          { key: "ts", label: "ts" },
          { key: "command_line", label: "command" },
          { key: "sha256", label: "sha", pivot: (v) => v ? ({ type: "command", id: v }) : null },
        ]));
      } else if (type === "command" || type === "command_hash") {
        const t = await api(`/api/ioc/command/${encodeURIComponent(id)}/sessions?size=25`);
        container.appendChild(buildRelatedTable("Sessions that ran this command", { rows: t.rows, total: t.total }, [
          { key: "session_id", label: "session_id", pivot: (v) => ({ type: "session", id: v }) },
          { key: "command_count", label: "events" },
        ]));
      } else if (type === "command_cluster" || type === "session_cluster" || type === "ip_cluster") {
        const kind = type.replace("_cluster", "");
        const t = await api(`/api/cluster/${kind}/${encodeURIComponent(id)}/members?size=25`);
        const cols = kind === "command"
          ? [ { key: "_id", label: "sha", pivot: (v) => ({ type: "command", id: v }) },
              { key: "process.command_line", label: "command" } ]
          : kind === "session"
            ? [ { key: "_id", label: "session_id", pivot: (v) => ({ type: "session", id: v }) } ]
            : [ { key: "_id", label: "ip", pivot: (v) => ({ type: "ip", id: v }) },
                { key: "source.geo.country_iso_code", label: "cc" } ];
        container.appendChild(buildRelatedTable("Members", t, cols));
      } else {
        container.innerHTML = "<em>No related tables for this IOC type.</em>";
      }
    } catch (e) {
      container.innerHTML = `<em>related load failed: ${escapeHtml(e.message)}</em>`;
    }
  }

  function buildRelatedTable(title, t, cols) {
    const wrap = document.createElement("div");
    wrap.className = "related-section";
    const total = t.total != null ? ` (${t.total})` : "";
    wrap.innerHTML = `<h3>${escapeHtml(title)}${total}</h3>`;
    const table = document.createElement("table");
    const tr = document.createElement("tr");
    cols.forEach((c) => {
      const th = document.createElement("th");
      th.textContent = c.label;
      tr.appendChild(th);
    });
    table.appendChild(tr);
    (t.rows || []).forEach((row) => {
      const r = document.createElement("tr");
      cols.forEach((c) => {
        const td = document.createElement("td");
        const v = deepGet(row, c.key);
        if (v != null && c.pivot) {
          const piv = c.pivot(v);
          if (piv) {
            const a = document.createElement("a");
            a.textContent = String(v);
            a.addEventListener("click", () => anchor(piv.type, piv.id));
            td.appendChild(a);
          } else {
            td.textContent = String(v);
          }
        } else if (v != null) {
          td.textContent = typeof v === "string" ? truncate(v, 100) : String(v);
        }
        r.appendChild(td);
      });
      table.appendChild(r);
    });
    wrap.appendChild(table);
    return wrap;
  }

  // Threat-hunter action strip: contextual buttons based on the current IOC.
  // - "+ Add cluster to view" / "× Remove cluster from view": toggles the
  //   cluster's members in/out of the current graph (additive merge / scoped
  //   removal). Only tracks clusters introduced via this button — clusters
  //   that came in via the anchor's 1-hop or via BFS aren't managed here.
  // - "→ Pivot to cluster": re-anchors the view on the cluster.
  function renderActions(d, container) {
    const summary = d.summary || {};
    const cid = summary.cluster_id;
    const t = d.type;
    let clusterKind = null;
    let clusterPrefix = null;
    if (t === "ip") { clusterKind = "ip_cluster"; clusterPrefix = "ipcl"; }
    else if (t === "session") { clusterKind = "session_cluster"; clusterPrefix = "sescl"; }
    else if (t === "command" || t === "command_hash") { clusterKind = "command_cluster"; clusterPrefix = "cmdcl"; }

    if (!cid || !clusterKind) return;

    const clusterNodeId = `${clusterPrefix}:${cid}`;
    const isAdded = state.addedClusters.has(clusterNodeId);

    const bar = document.createElement("div");
    bar.className = "actions";

    const toggleBtn = document.createElement("button");
    toggleBtn.className = isAdded ? "action remove" : "action add";
    toggleBtn.textContent = isAdded ? "× Remove cluster from view" : "+ Add cluster to view";
    toggleBtn.title = isAdded
      ? "Remove this cluster's pill and the members it brought into the graph"
      : "Pull the rest of this cluster's members into the current graph (additive, keeps context)";
    toggleBtn.addEventListener("click", async () => {
      if (state.addedClusters.has(clusterNodeId)) {
        removeAddedCluster(clusterNodeId, d, toggleBtn);
      } else {
        await addClusterToView(clusterKind, cid, clusterNodeId, d, toggleBtn);
      }
    });

    const pivotBtn = document.createElement("button");
    pivotBtn.className = "action pivot";
    pivotBtn.textContent = `→ Pivot to ${clusterKind.replace("_", " ")} ${cid}`;
    pivotBtn.title = "Re-anchor the graph on the cluster (replaces current view)";
    pivotBtn.addEventListener("click", () => anchor(clusterKind, cid));

    bar.appendChild(toggleBtn);
    bar.appendChild(pivotBtn);
    container.appendChild(bar);
  }

  async function addClusterToView(clusterKind, cid, clusterNodeId, d, btn) {
    btn.disabled = true; btn.textContent = "loading…";
    try {
      const originId = nodeIdFor(d.type, d.id);
      const g = await api(`/api/ioc/${clusterKind}/${encodeURIComponent(cid)}/neighbors?limit=60`);
      // Capture the diff (nodes new to the graph because of this click) so
      // the Remove action can undo precisely what Add did. The cluster
      // members come in at the origin's depth + 1 (one sibling hop away).
      const introduced = new Set();
      const baseDepth = state.depthOf.has(originId)
        ? state.depthOf.get(originId)
        : 0;
      for (const n of (g.nodes || [])) {
        const nid = n.data && n.data.id;
        if (!nid) continue;
        if (!Graph.hasNode(nid)) introduced.add(nid);
        if (!state.depthOf.has(nid) || state.depthOf.get(nid) > baseDepth + 1) {
          state.depthOf.set(nid, baseDepth + 1);
        }
      }
      // Mark this cluster pill as "siblings-expanded" so the auto-loop
      // won't fetch it again redundantly. Cluster members become
      // mini-anchors so their pipelines fully auto-trace.
      state.siblingsExpanded.add(clusterNodeId);
      for (const n of (g.nodes || [])) {
        const nd = n.data || {};
        if (nd.id && PIPELINE_KINDS.has(nd.type) && !state.pipelineRole.has(nd.id)) {
          state.pipelineRole.set(nd.id, "miniAnchor");
        }
      }
      Graph.merge(g, originId);
      state.addedClusters.set(clusterNodeId, introduced);
      // Re-render the action strip with the flipped label.
      if (state.currentDetail) renderDetail(state.currentDetail);
      // Auto-trace the new members' pipelines and recurse on siblings.
      refreshExpansion();
    } catch (e) {
      btn.textContent = "failed";
      setTimeout(() => { btn.textContent = "+ Add cluster to view"; btn.disabled = false; }, 1500);
    }
  }

  function removeAddedCluster(clusterNodeId, d, btn) {
    const introduced = state.addedClusters.get(clusterNodeId) || new Set();
    // Always include the cluster pill itself so a one-member cluster (where
    // the pill was the only new thing) still toggles off cleanly.
    introduced.add(clusterNodeId);
    // Clean up our expansion bookkeeping for the removed ids so re-adding
    // works. (Re-adding fetches the cluster afresh.)
    for (const nid of introduced) {
      state.depthOf.delete(nid);
      state.pipelineExpanded.delete(nid);
      state.siblingsExpanded.delete(nid);
      state.pipelineRole.delete(nid);
    }
    state.addedClusters.delete(clusterNodeId);
    // If the corresponding sidecar set is currently filtering the view,
    // drop it BEFORE the removeNodes call — removeNodes triggers
    // dataChangeHandler -> renderSets, and we want the post-remove render
    // to reflect the cleared filter. (The anchor itself may still carry
    // this cluster_id, keeping the set alive in getSets() with count=1,
    // so the stale-prune logic in renderSets won't catch it.)
    const setId = _setIdForClusterNode(clusterNodeId);
    if (setId && setsState.active.has(setId)) {
      setsState.active.delete(setId);
      if (setsState.active.size <= 1) setsState.mode = "union";
      applySetsFilter();
    }
    Graph.removeNodes(introduced);
    if (state.currentDetail) renderDetail(state.currentDetail);
  }

  function _setIdForClusterNode(clusterNodeId) {
    const idx = clusterNodeId.indexOf(":");
    if (idx < 0) return null;
    const prefix = clusterNodeId.slice(0, idx);
    const rest = clusterNodeId.slice(idx + 1);
    const map = { ipcl: "ip_cluster", sescl: "session_cluster", cmdcl: "command_cluster" };
    return map[prefix] ? `${map[prefix]}:${rest}` : null;
  }

  function makePivot(key, value) {
    if (value == null) return null;
    switch (key) {
      case "src_ip": case "ip": return { type: "ip", id: String(value) };
      case "session_id": return { type: "session", id: String(value) };
      case "sha256": return { type: "command", id: String(value) };
      case "asn": return { type: "asn", id: String(value) };
      case "country": case "country_iso_code": return { type: "country", id: String(value) };
      // Playbook pivot uses the stable playbook_id.
      case "playbook_id":   return { type: "playbook", id: String(value) };
      case "playbook_name": return null;
      // Multi-session campaign pivots by campaign_id (cmp-bhv-... / cmp-inf-...).
      case "campaign_id":   return { type: "campaign", id: String(value) };
      case "campaign_name": return null;
      case "cluster_id":
        // Cluster pivot depends on the current detail's kind.
        if (state.currentDetail) {
          const t = state.currentDetail.type;
          if (t === "ip") return { type: "ip_cluster", id: String(value) };
          if (t === "session") return { type: "session_cluster", id: String(value) };
          if (t === "command" || t === "command_hash") return { type: "command_cluster", id: String(value) };
        }
        return null;
      default: return null;
    }
  }

  function fmtValue(v) {
    if (Array.isArray(v)) return v.join(", ");
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  function deepGet(obj, path) {
    return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
  }

  // ---------------------------------------------------------------------
  // Breadcrumb + URL state
  // ---------------------------------------------------------------------
  function updateBreadcrumb() {
    const bc = document.querySelector(".breadcrumb-bar");
    if (!bc) return;
    bc.innerHTML = "";
    state.history.slice(-6).forEach((h, i, arr) => {
      const span = document.createElement("span");
      span.className = "step";
      span.textContent = h.label;
      span.addEventListener("click", () => anchor(h.type, h.id, { skipHistory: true }));
      bc.appendChild(span);
      if (i < arr.length - 1) {
        const s = document.createElement("span");
        s.className = "sep"; s.textContent = "›";
        bc.appendChild(s);
      }
    });
  }

  function updateUrl() {
    if (!state.anchor) return;
    const p = new URLSearchParams();
    p.set("ioc", `${state.anchor.type}:${state.anchor.id}`);
    const next = `/?${p.toString()}`;
    if (location.pathname + location.search === next) return;
    // Push a new history entry so browser back/forward works for
    // anchor changes. updateUrl is suppressed when we're already
    // restoring from a popstate event.
    if (state.suppressUrlPush) {
      history.replaceState(null, "", next);
    } else {
      history.pushState({ ioc: `${state.anchor.type}:${state.anchor.id}` }, "", next);
    }
  }

  function readUrl() {
    const p = new URLSearchParams(location.search);
    const raw = p.get("ioc");
    if (!raw) return null;
    const idx = raw.indexOf(":");
    if (idx < 0) return null;
    return { type: raw.slice(0, idx), id: raw.slice(idx + 1) };
  }

  // ---------------------------------------------------------------------
  // Utils
  // ---------------------------------------------------------------------
  function truncate(s, n) {
    s = String(s);
    return s.length > n ? s.slice(0, n) + "…" : s;
  }
  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // ---------------------------------------------------------------------
  // Expansion: two parallel passes
  // ---------------------------------------------------------------------
  //
  //  expandPipeline():
  //    Walks every "pipeline-kind" node (IP / Session / Command) whose
  //    neighbors we haven't fetched yet, regardless of sibling depth.
  //    Each fetch's response goes through Graph.merge, which lets a
  //    newly-arrived session pull in its commands on the next pass.
  //    Pipeline traversal has zero sibling-cost: neighbors come in at the
  //    same depth as the source. This is the "always show the full
  //    attack story for what's in view" behavior.
  //
  //  expandSiblings(targetDepth):
  //    Walks every cluster pill (ip_cluster / session_cluster /
  //    command_cluster) whose depth is < targetDepth and whose members
  //    we haven't fetched yet. The members arrive at depth+1. After
  //    each siblings wave we run expandPipeline again so the new
  //    members get their own pipeline trace.
  //
  //  refreshExpansion():
  //    Glue: run pipeline first (cheap when nothing changed), then if
  //    siblings > 0 run sibling expansion. Called after every action
  //    that mutates the graph.
  //
  // Lane-hidden node types (state.lanesVisible) don't trigger fetches —
  // hiding a lane removes those nodes from the graph and skips fetching
  // them in future expansions.
  const PIPELINE_KINDS = new Set(["ip", "session", "command"]);
  const CLUSTER_KINDS = new Set(["ip_cluster", "session_cluster", "command_cluster"]);
  const PIPELINE_LIMIT = 50;
  const SIBLINGS_LIMIT = { 1: 50, 2: 30, 3: 20 };
  const MAX_INFLIGHT = 6;
  const TYPE_TO_LANE = {
    campaign: "campaign",   // lives in its own column; never filtered out via laneVisibility
    ip: "ip", session: "session", command: "command",
    ip_cluster: "ip", session_cluster: "session", command_cluster: "command",
    asn: "geo", country: "geo",
    mitre_technique: "mitre", mitre_tactic: "mitre",
  };

  function siblingsTarget(target) {
    const prev = state.siblings;
    state.siblings = Math.max(0, Math.min(3, Number(target) || 0));
    $("#siblings-value").textContent = String(state.siblings);
    if (!state.anchor) return;
    // Cancel any in-flight expansion so a wave fired at the old target
    // can't re-introduce nodes we're about to prune.
    state.expandToken += 1;
    if (state.siblings < prev) pruneToSiblings(state.siblings);
    refreshExpansion().then(() => Graph.fit()).catch(() => {});
  }

  // Drop nodes whose siblings-depth exceeds the new target. User-pinned
  // clusters (added via "Add cluster to view") are immune — they were
  // brought in manually, not by the slider.
  function pruneToSiblings(target) {
    const pinned = new Set();
    for (const [pillId, introduced] of state.addedClusters) {
      pinned.add(pillId);
      for (const nid of introduced) pinned.add(nid);
    }
    const toRemove = new Set();
    for (const [nid, depth] of state.depthOf) {
      if (depth > target && !pinned.has(nid)) toRemove.add(nid);
    }
    if (toRemove.size === 0) return;
    for (const nid of toRemove) {
      state.depthOf.delete(nid);
      state.pipelineExpanded.delete(nid);
      state.siblingsExpanded.delete(nid);
      state.pipelineRole.delete(nid);
    }
    // Remaining cluster pills may have lost their member set — clear
    // their "already expanded" mark so a future slide-up can re-fetch.
    // Pinned (user-added) clusters keep their mark.
    for (const nid of Array.from(state.siblingsExpanded)) {
      if (pinned.has(nid)) continue;
      const prefix = nid.split(":", 1)[0];
      if (prefix === "ipcl" || prefix === "sescl" || prefix === "cmdcl") {
        state.siblingsExpanded.delete(nid);
      }
    }
    Graph.removeNodes(toRemove);
  }

  async function refreshExpansion() {
    if (!state.anchor) return;
    await expandPipeline();
    if (state.siblings > 0) await expandSiblings(state.siblings);
    _updateLoading(0);
  }

  // Given a fetch (sourceId/sourceType + returned graph), classify every
  // new pipeline-kind node into one of four roles:
  //   anchor / miniAnchor — extend the pipeline like the anchor would
  //   trace               — a session whose neighbors must still be
  //                         fetched (one more step from a pipeline anchor)
  //   leaf                — node included for context but not re-fetched
  //
  // The role rules prevent the lateral "command -> other sessions ->
  // their IPs -> ..." fan-out that happens when every pipeline-kind
  // node is treated equally.
  function assignRolesFromFetch(sourceId, sourceType, graph) {
    const sourceRole = state.pipelineRole.get(sourceId) || "anchor";
    for (const n of (graph.nodes || [])) {
      const d = n.data || {};
      if (!d.id) continue;
      if (d.id === sourceId) continue;
      if (state.pipelineRole.has(d.id)) continue;
      const role = _decideRole(sourceType, sourceRole, d.type);
      state.pipelineRole.set(d.id, role);
    }
  }

  function _decideRole(sourceType, sourceRole, newType) {
    // Source acts as an anchor — extend its pipeline in valid directions.
    if (sourceRole === "anchor" || sourceRole === "miniAnchor") {
      if (sourceType === "ip" && newType === "session") return "trace";
      if (sourceType === "session") return "leaf";
      if (sourceType === "command" || sourceType === "command_hash") {
        if (newType === "session") return "trace";
        return "leaf";
      }
      if (CLUSTER_KINDS.has(sourceType) && PIPELINE_KINDS.has(newType)) return "miniAnchor";
      if ((sourceType === "asn" || sourceType === "country") && newType === "ip") return "miniAnchor";
      if ((sourceType === "mitre_technique" || sourceType === "mitre_tactic") && newType === "command") return "miniAnchor";
      // Both campaign-like sources expand to a full pipeline trace for each
      // session they bring in. Without the `playbook` branch, anchoring on a
      // playbook (e.g. from Insights or a search hit) leaves its sessions at
      // role "leaf" — so expandPipeline never fetches them and commands
      // never arrive. Same shape as the campaign branch.
      if ((sourceType === "campaign" || sourceType === "playbook") && PIPELINE_KINDS.has(newType)) return "miniAnchor";
      return "leaf";
    }
    // Source was a "trace" session — its neighbors fill in one more
    // pipeline step but are themselves leaves (no further fan-out).
    if (sourceRole === "trace") return "leaf";
    return "leaf";
  }

  function _shouldFetchPipeline(nid, type) {
    if (!PIPELINE_KINDS.has(type)) return false;
    if (!state.lanesVisible.has(TYPE_TO_LANE[type])) return false;
    if (state.pipelineExpanded.has(nid)) return false;
    const role = state.pipelineRole.get(nid);
    return role === "anchor" || role === "miniAnchor" || role === "trace";
  }

  async function expandPipeline() {
    const token = state.expandToken;
    let safety = 60;
    while (safety-- > 0) {
      if (token !== state.expandToken) return;
      const frontier = [];
      for (const [nid, d] of state.depthOf) {
        const { type, id } = parseNodeId(nid);
        if (!_shouldFetchPipeline(nid, type)) continue;
        frontier.push({ nid, type, id, depth: d });
      }
      if (frontier.length === 0) break;
      await _runPool(frontier, MAX_INFLIGHT, async (item) => {
        if (token !== state.expandToken) return;
        state.pipelineExpanded.add(item.nid);
        let g;
        try {
          g = await api(`/api/ioc/${encodeURIComponent(item.type)}/${encodeURIComponent(item.id)}/neighbors?limit=${PIPELINE_LIMIT}`);
        } catch (e) { return; }
        if (token !== state.expandToken) return;
        assignRolesFromFetch(item.nid, item.type, g);
        for (const n of (g.nodes || [])) {
          const id = n.data && n.data.id;
          if (!id) continue;
          if (!state.depthOf.has(id) || state.depthOf.get(id) > item.depth) {
            state.depthOf.set(id, item.depth);
          }
        }
        Graph.merge(g, item.nid);
      });
    }
  }

  // Walks cluster pills, fetching their members. Members come in at the
  // pill's depth + 1 and get role "miniAnchor" so their own pipelines
  // are auto-traced. The loop re-pipelines after each wave so new
  // members get their attack stories before the next siblings wave.
  async function expandSiblings(targetDepth) {
    const token = state.expandToken;
    let safety = 25;
    while (safety-- > 0) {
      if (token !== state.expandToken) return;
      const frontier = [];
      for (const [nid, d] of state.depthOf) {
        if (d >= targetDepth) continue;
        if (state.siblingsExpanded.has(nid)) continue;
        const { type, id } = parseNodeId(nid);
        if (!CLUSTER_KINDS.has(type)) continue;
        if (!state.lanesVisible.has(TYPE_TO_LANE[type])) continue;
        frontier.push({ nid, type, id, depth: d });
      }
      if (frontier.length === 0) break;
      frontier.sort((a, b) => a.depth - b.depth);
      const minDepth = frontier[0].depth;
      const wave = frontier.filter((f) => f.depth === minDepth);
      const limit = SIBLINGS_LIMIT[minDepth + 1] || 20;
      await _runPool(wave, MAX_INFLIGHT, async (item) => {
        if (token !== state.expandToken) return;
        state.siblingsExpanded.add(item.nid);
        let g;
        try {
          g = await api(`/api/ioc/${encodeURIComponent(item.type)}/${encodeURIComponent(item.id)}/neighbors?limit=${limit}`);
        } catch (e) { return; }
        if (token !== state.expandToken) return;
        // Cluster members are mini-anchors of their own pipelines.
        for (const n of (g.nodes || [])) {
          const d = n.data || {};
          if (!d.id) continue;
          if (PIPELINE_KINDS.has(d.type) && !state.pipelineRole.has(d.id)) {
            state.pipelineRole.set(d.id, "miniAnchor");
          }
        }
        const childDepth = item.depth + 1;
        for (const n of (g.nodes || [])) {
          const id = n.data && n.data.id;
          if (!id) continue;
          if (!state.depthOf.has(id) || state.depthOf.get(id) > childDepth) {
            state.depthOf.set(id, childDepth);
          }
        }
        Graph.merge(g, item.nid);
      });
      await expandPipeline();
    }
  }

  function setLaneVisible(lane, visible) {
    if (visible) state.lanesVisible.add(lane);
    else state.lanesVisible.delete(lane);
    Graph.setLaneVisibility(Array.from(state.lanesVisible));
    if (visible) {
      // Re-enabling a lane: invalidate pipeline cache so the auto-trace
      // can backfill the missing nodes on the next refresh, then re-fit
      // the view once those nodes have actually landed.
      state.pipelineExpanded.clear();
      refreshExpansion().then(() => Graph.fit()).catch(() => {});
    }
  }

  async function _runPool(items, concurrency, worker, onProgress) {
    let i = 0;
    state.inflight = 0;
    _updateLoading(items.length);
    async function runner() {
      while (i < items.length) {
        const idx = i++;
        state.inflight++;
        try { await worker(items[idx]); }
        finally {
          state.inflight--;
          if (onProgress) onProgress();
        }
      }
    }
    const workers = [];
    for (let k = 0; k < Math.min(concurrency, items.length); k++) workers.push(runner());
    await Promise.all(workers);
  }

  function _updateLoading(remaining) {
    const el = $("#loading");
    if (!el) return;
    if (remaining > 0 || state.inflight > 0) {
      el.classList.remove("hidden");
      el.textContent = `expanding · ${state.inflight} in flight`;
    } else {
      el.classList.add("hidden");
      el.textContent = "";
    }
  }

  // ---------------------------------------------------------------------
  // Sets sidecar (UpSet-style filter rail)
  // ---------------------------------------------------------------------
  // Click a row to keep only nodes belonging to that set. Shift-click a
  // second row to keep nodes that belong to BOTH (intersection). Click
  // an active row again, or hit "clear", to drop the filter.
  const setsState = { active: new Set(), mode: "union" };

  function renderSets() {
    const body = $("#sets-body");
    const { sets } = Graph.getSets();
    // Prune any active filter ids that no longer correspond to a set in
    // view (e.g. their members were removed via Remove cluster, or we
    // re-anchored). Without this, applySetsFilter would dim everything
    // because no node would match the dead set.
    const alive = new Set(sets.map((s) => s.id));
    let pruned = false;
    for (const sid of Array.from(setsState.active)) {
      if (!alive.has(sid)) { setsState.active.delete(sid); pruned = true; }
    }
    if (pruned) {
      if (setsState.active.size <= 1) setsState.mode = "union";
      applySetsFilter();
    }
    if (sets.length === 0) {
      body.innerHTML = '<em class="sets-empty">Sets appear here as nodes are loaded.</em>';
      $("#sets-clear").classList.remove("dirty");
      return;
    }

    // Group sets by kind for readability.
    const KIND_ORDER = [
      "ip_cluster", "session_cluster", "command_cluster",
      "campaign", "asn", "country",
      "mitre_technique", "mitre_tactic",
    ];
    const KIND_LABEL = {
      ip_cluster: "IP clusters",
      session_cluster: "Session clusters",
      command_cluster: "Command clusters",
      campaign: "Campaigns",
      asn: "ASNs",
      country: "Countries",
      mitre_technique: "MITRE techniques",
      mitre_tactic: "MITRE tactics",
    };
    const byKind = new Map();
    for (const s of sets) {
      if (!byKind.has(s.kind)) byKind.set(s.kind, []);
      byKind.get(s.kind).push(s);
    }
    for (const list of byKind.values()) {
      list.sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
    }

    body.innerHTML = "";
    for (const kind of KIND_ORDER) {
      if (!byKind.has(kind)) continue;
      const group = document.createElement("div");
      group.className = "sets-group";
      const title = document.createElement("div");
      title.className = "sets-group-title";
      title.textContent = KIND_LABEL[kind];
      group.appendChild(title);
      for (const s of byKind.get(kind)) {
        const row = document.createElement("div");
        row.className = `set-row kind-${kind}`;
        if (setsState.active.has(s.id)) {
          row.classList.add(setsState.mode === "intersect" && setsState.active.size > 1 ? "intersect" : "active");
        }
        row.innerHTML =
          '<span class="swatch"></span>' +
          `<span class="label">${escapeHtml(s.label)}</span>` +
          `<span class="count">${s.count}</span>`;
        row.title = `${s.label} — ${s.count} member${s.count === 1 ? "" : "s"} in view\nclick: filter • shift-click: intersect • click again to remove`;
        row.addEventListener("click", (e) => onSetRowClick(s.id, e));
        group.appendChild(row);
      }
      body.appendChild(group);
    }
    $("#sets-clear").classList.toggle("dirty", setsState.active.size > 0);
  }

  function onSetRowClick(setId, ev) {
    if (ev.shiftKey) {
      // Intersect mode: add to selection, ALL must match.
      if (setsState.active.has(setId)) {
        setsState.active.delete(setId);
      } else {
        setsState.active.add(setId);
      }
      setsState.mode = setsState.active.size > 1 ? "intersect" : "union";
    } else {
      // Plain click: toggle this row, single-set union mode.
      if (setsState.active.has(setId) && setsState.active.size === 1) {
        setsState.active.clear();
      } else {
        setsState.active = new Set([setId]);
      }
      setsState.mode = "union";
    }
    applySetsFilter();
    renderSets();
  }

  function applySetsFilter() {
    const ids = Array.from(setsState.active);
    if (ids.length === 0) {
      Graph.highlightSets(null);
      return;
    }
    if (setsState.mode === "intersect") Graph.highlightIntersection(ids);
    else Graph.highlightSets(ids);
  }

  function clearSetsFilter() {
    setsState.active.clear();
    setsState.mode = "union";
    Graph.highlightSets(null);
    renderSets();
  }

  // ---------------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------------
  // ── Mode + Timeline ──────────────────────────────────────────────────────
  // Timeline mode re-uses the main topbar search bar. `_navigateTo` routes
  // every search result to Prism *or* Timeline depending on the active mode.

  const tlState = {
    mode: "prism",   // "prism" | "timeline"
    kind: null,
    id:   null,
  };

  // Types that can be displayed in Timeline (mapped to timeline `kind`).
  // Backend timeline kind "playbook" filters sessions whose `playbook_id`
  // matches the anchor id. The multi-session campaign IOC has
  // no timeline visualisation (members come from a different index) so it
  // simply doesn't appear in this map and the mode toggle falls back to
  // Prism for it.
  const TL_KIND = {
    ip:              "ip",
    session_cluster: "session_cluster",
    playbook:        "playbook",
  };

  function setMode(mode) {
    if (mode === tlState.mode) return;
    tlState.mode = mode;
    document.querySelectorAll(".mode-btn").forEach(b => {
      b.classList.toggle("active", b.dataset.mode === mode);
    });
    const cyEl = $("#cy");
    const tlEl = $("#tl");
    if (mode === "timeline") {
      cyEl.style.visibility = "hidden";
      tlEl.classList.remove("hidden");
      // Auto-load timeline from current Prism anchor if it's a compatible type.
      if (state.anchor && TL_KIND[state.anchor.type]) {
        loadTimeline(TL_KIND[state.anchor.type], state.anchor.id);
      }
    } else {
      cyEl.style.visibility = "";
      tlEl.classList.add("hidden");
    }
  }

  async function loadTimeline(kind, id) {
    tlState.kind = kind;
    tlState.id   = id;
    const statusEl = $("#tl-status");
    if (statusEl) statusEl.textContent = "loading…";
    Timeline.clear();
    try {
      const r = await fetch(
        `/api/timeline?kind=${encodeURIComponent(kind)}&id=${encodeURIComponent(id)}&require_login=false&require_commands=false`
      );
      if (!r.ok) throw new Error(r.statusText);
      const data = await r.json();
      const total = data.total || 0;
      const shown = data.shown || 0;
      if (statusEl) statusEl.textContent = shown < total
        ? `${shown.toLocaleString()} of ${total.toLocaleString()} sessions shown`
        : `${shown.toLocaleString()} session${shown !== 1 ? "s" : ""}`;
      Timeline.load(data);
    } catch (e) {
      if (statusEl) statusEl.textContent = `error: ${e.message}`;
    }
  }

  // Route a search result to the right mode.
  function _navigateTo(type, id) {
    if (tlState.mode === "timeline" && TL_KIND[type]) {
      loadTimeline(TL_KIND[type], id);
    } else {
      if (tlState.mode === "timeline") setMode("prism"); // non-TL type → switch back
      anchor(type, id);
    }
  }

  // ── DOMContentLoaded ──────────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", () => {
    Graph.init("cy");
    Timeline.init(
      document.getElementById("tl-canvas"),
      document.getElementById("tl-minimap")
    );
    Timeline.onPivot((sessionId) => {
      setMode("prism");
      anchor("session", sessionId);
    });
    Graph.onSelect(selectNode);
    Graph.onExpand(expand);
    Graph.onPivot(({ type, id }) => anchor(type, id));
    Graph.onDataChange(renderSets);

    // Mode toggle — setMode handles auto-loading the timeline from the current anchor.
    document.querySelectorAll(".mode-btn").forEach(btn => {
      btn.addEventListener("click", () => setMode(btn.dataset.mode));
    });

    // Fit button — works for both modes.
    $("#fit-btn").addEventListener("click", () => {
      if (tlState.mode === "timeline") Timeline.fit();
      else Graph.fit();
    });

    // GroupBy checkboxes for Timeline Y-axis.
    function _syncGroupBy() {
      Timeline.setGroupBy({
        playbook: document.getElementById("tl-grp-playbook").checked,
        cluster:  document.getElementById("tl-grp-cluster").checked,
        ip:       document.getElementById("tl-grp-ip").checked,
      });
    }
    ["tl-grp-playbook", "tl-grp-cluster", "tl-grp-ip"].forEach(id => {
      document.getElementById(id).addEventListener("change", _syncGroupBy);
    });

    $("#search-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const q = $("#search-input").value.trim();
      if (q) doSearch(q);
    });

    $("#reset-btn").addEventListener("click", () => {
      state.history = [];
      state.anchor = null;
      state.expandToken += 1;
      state.depthOf = new Map();
      state.pipelineExpanded = new Set();
      state.siblingsExpanded = new Set();
      state.pipelineRole = new Map();
      state.addedClusters = new Map();
      _updateLoading(0);
      clearSetsFilter();
      Graph.replace({ nodes: [], edges: [] }, null);
      $("#detail-header").innerHTML = "<em>Search an IOC to begin.</em>";
      $("#tab-overview").innerHTML = "";
      $("#tab-related").innerHTML = "";
      $("#raw-json").textContent = "";
      history.replaceState(null, "", "/");
    });
    $("#sets-clear").addEventListener("click", clearSetsFilter);

    const sibSlider = $("#siblings-slider");
    sibSlider.addEventListener("input", (e) => {
      $("#siblings-value").textContent = e.target.value;
    });
    sibSlider.addEventListener("change", (e) => {
      siblingsTarget(e.target.value);
    });

    document.querySelectorAll(".lane-chk input").forEach((chk) => {
      chk.addEventListener("change", (e) => {
        setLaneVisible(e.target.dataset.lane, e.target.checked);
      });
    });

    // Settings modal
    const modal = $("#settings-modal");
    const cfgLogin = $("#cfg-require-login");
    const cfgCmd = $("#cfg-require-commands");
    function openSettings() {
      cfgLogin.checked = settings.requireLogin;
      cfgCmd.checked = settings.requireCommands;
      modal.classList.remove("hidden");
    }
    function closeSettings() { modal.classList.add("hidden"); }
    function applySettings() {
      const newReqLogin = !!cfgLogin.checked;
      const newReqCmd = !!cfgCmd.checked;
      const changed = newReqLogin !== settings.requireLogin || newReqCmd !== settings.requireCommands;
      settings.requireLogin = newReqLogin;
      settings.requireCommands = newReqCmd;
      saveSettings(settings);
      closeSettings();
      if (changed && state.anchor) {
        // Re-anchor to re-fetch with new filter applied to every cached call.
        anchor(state.anchor.type, state.anchor.id, { skipHistory: true });
      }
    }
    $("#settings-btn").addEventListener("click", openSettings);
    modal.querySelector(".modal-close").addEventListener("click", closeSettings);
    modal.querySelector(".modal-cancel").addEventListener("click", closeSettings);
    modal.querySelector(".modal-save").addEventListener("click", applySettings);
    modal.addEventListener("click", (e) => {
      // Clicking the backdrop (the modal itself, not the card) closes.
      if (e.target === modal) closeSettings();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !modal.classList.contains("hidden")) closeSettings();
    });

    document.querySelectorAll("#detail-tabs button").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#detail-tabs button").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
        btn.classList.add("active");
        $(`#tab-${btn.dataset.tab}`).classList.add("active");
      });
    });

    // ------------------------------------------------------------------
    // Ask AI
    // ------------------------------------------------------------------
    const ASK_PRESETS = [
      {
        label: "Attacker goal",
        query: "Based on the commands run, sessions observed, and any campaign or cluster data visible, what is this attacker most likely trying to accomplish? Be specific about the objective (e.g. initial access, persistence, data exfiltration, crypto mining) and cite the evidence.",
      },
      {
        label: "Attack summary",
        query: "Summarize the overall attack pattern visible in this graph. Cover: which IPs are involved, what commands were run, the session flow, and any campaign or cluster groupings that suggest coordinated behaviour.",
      },
      {
        label: "MITRE techniques",
        query: "Which MITRE ATT&CK techniques and tactics are most relevant to the activity in this graph? For each technique, briefly explain which specific commands or behaviours in the data support that classification.",
      },
      {
        label: "Coordination signs",
        query: "Are there signs that this activity is coordinated, automated, or part of a campaign? Look for shared tooling, timing patterns, overlapping cluster membership, similar command sequences, or other indicators of a single threat actor across multiple IPs.",
      },
      {
        label: "Notable anomalies",
        query: "What is most unusual or noteworthy about this activity compared to typical honeypot traffic? Pay particular attention to high novelty scores, outlier sessions or commands, rare techniques, or anything that deviates from common automated scanning behaviour.",
      },
      {
        label: "Next steps",
        query: "Given what is currently visible in this graph, what should I investigate next? Suggest specific IOC types to pivot on, clusters or campaigns worth expanding, and any threat intelligence queries that would add context.",
      },
      {
        label: "SANS Analysis",
        query: `Perform a structured SANS-style threat analysis of the activity visible in this graph. Address each section in order:

1. VULNERABILITY TARGETED
Identify what vulnerability, misconfiguration, or exposed service this attack appears to be targeting. Name the specific CVE, protocol weakness, or default credential issue if the commands or session data make it apparent. If multiple vulnerabilities are suggested by different commands, list each one.

2. ATTACK VIABILITY
Assess whether this attack would actually succeed against a vulnerable system. Consider: Are the commands syntactically correct and in the right order? Does the attacker appear to understand the target? Are there signs of copy-paste scripts being run blindly, incorrect assumptions about the environment (e.g. wrong OS, wrong path, wrong service), or missing prerequisites? Give a clear verdict — likely successful, partially effective, or unlikely to work — with reasoning.

3. ATTACKER OBJECTIVE
What is the end goal of this attack? Look at the full command sequence and infer the payload or outcome being sought. Examples: establishing a reverse shell or backdoor, deploying a crypto miner, staging ransomware, exfiltrating credentials or data, adding persistence via cron or systemd, lateral movement. Be specific about what the attacker would have if they succeeded.

4. ATTACK ORIGIN
Assess the nature of the source IP(s). Based on the data in the graph (ASN, country, novelty score, session count, campaign membership), determine: Is this likely an automated scanner or botnet node that indiscriminately probes the internet? Or are there signs of manual, targeted interaction — e.g. low session count, unusual timing, interactive command sequences, or responses to system output? Note any ASN or country context that is relevant (e.g. known hosting providers used for scanning infrastructure, Tor exit nodes, residential ISPs).

5. DEFENSIVE RECOMMENDATIONS
What specific steps should a defender take to prevent this attack from succeeding? Include: the patch level or software version required to close the vulnerability, any configuration hardening steps (disabling a service, changing a default, restricting network access), detection signatures or log patterns to alert on, and any compensating controls if patching is not immediately possible.`,
      },
    ];

    const askModal       = $("#ask-ai-modal");
    const askInputPanel  = $("#ask-ai-input-panel");
    const askLoadPanel   = $("#ask-ai-loading-panel");
    const askResultPanel = $("#ask-ai-result-panel");
    const askFooter      = $("#ask-ai-footer");
    const askTextarea    = $("#ask-ai-question");
    const askSubmitBtn   = $("#ask-ai-submit");
    const askCancelBtn   = $("#ask-ai-cancel");

    // Populate preset chips once.
    const presetsEl = $("#ask-ai-presets");
    ASK_PRESETS.forEach(({ label, query }) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "ask-ai-chip";
      chip.textContent = label;
      chip.title = query;
      chip.addEventListener("click", () => {
        presetsEl.querySelectorAll(".ask-ai-chip").forEach(c => c.classList.remove("selected"));
        chip.classList.add("selected");
        askTextarea.value = query;
      });
      presetsEl.appendChild(chip);
    });

    function _openAskModal() {
      _showAskPanel("input");
      askTextarea.value = "";
      presetsEl.querySelectorAll(".ask-ai-chip").forEach(c => c.classList.remove("selected"));
      askSubmitBtn.textContent = "Ask";
      askSubmitBtn.onclick = _submitAsk;
      askCancelBtn.textContent = "Cancel";
      askCancelBtn.onclick = _closeAskModal;
      askModal.classList.remove("hidden");
      askTextarea.focus();
    }

    function _closeAskModal() {
      askModal.classList.add("hidden");
    }

    function _showAskPanel(which) {
      askInputPanel.classList.toggle("hidden",  which !== "input");
      askLoadPanel.classList.toggle("hidden",   which !== "loading");
      askResultPanel.classList.toggle("hidden", which !== "result");
      askFooter.classList.toggle("hidden", which === "loading");
    }

    function _buildAskContext() {
      const nodes = Graph.allNodes();
      // De-dup by playbook_id. Two playbooks with the same display name
      // are still distinct — keep them separate in the LLM context.
      const seenPbIds = new Set();
      const playbooks = [];
      for (const n of nodes) {
        const cid = n.playbook_id;
        if (!cid || seenPbIds.has(cid)) continue;
        seenPbIds.add(cid);
        playbooks.push({ id: cid, name: n.playbook_name || null });
      }
      // Distinct (new) multi-session campaigns.
      const seenCampIds = new Set();
      const campaigns = [];
      for (const n of nodes) {
        if (n.type !== "campaign") continue;
        const cid = n.campaign_id;
        if (!cid || seenCampIds.has(cid)) continue;
        seenCampIds.add(cid);
        campaigns.push({ id: cid, name: n.label || null, kind: n.campaign_kind || null });
      }
      return {
        anchor: state.anchor || null,
        detail: state.currentDetail ? {
          type: state.currentDetail.type,
          id:   state.currentDetail.id,
          summary: state.currentDetail.summary || {},
        } : null,
        playbooks,
        campaigns,
        node_counts: {
          ips:      nodes.filter(n => n.type === "ip").length,
          sessions: nodes.filter(n => n.type === "session").length,
          commands: nodes.filter(n => n.type === "command").length,
        },
        nodes: nodes.slice(0, 120).map(n => ({
          id: n.id, type: n.type, label: n.label,
          playbook_id:   n.playbook_id   || null,
          playbook_name: n.playbook_name || null,
          cluster_id: n.cluster_id || null,
          novelty: n.novelty ?? null,
          is_outlier: n.is_outlier || false,
          intent: n.intent || n.dominant_intent || null,
          country: n.country || null,
          asn: n.asn || null,
        })),
      };
    }

    async function _submitAsk() {
      const question = askTextarea.value.trim();
      if (!question) { askTextarea.focus(); return; }

      _showAskPanel("loading");

      let result;
      try {
        result = await fetch("/api/ask", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question, context: _buildAskContext() }),
        });
      } catch (e) {
        _showAskPanel("input");
        alert(`Ask AI failed: ${e.message}`);
        return;
      }

      if (!result.ok) {
        const err = await result.text().catch(() => result.statusText);
        _showAskPanel("input");
        alert(`Ask AI error (${result.status}): ${err.slice(0, 200)}`);
        return;
      }

      const data = await result.json();
      const resultPanel = $("#ask-ai-result-panel");
      resultPanel.querySelector(".ask-ai-result-q").textContent = `Q: ${question}`;
      resultPanel.querySelector(".ask-ai-result-answer").textContent = data.answer || "(no response)";
      resultPanel.querySelector(".ask-ai-result-meta").textContent =
        data.model ? `via ${data.model}` : "";

      _showAskPanel("result");
      askSubmitBtn.textContent = "Ask Another";
      askSubmitBtn.onclick = _openAskModal;
      askCancelBtn.textContent = "Close";
      askCancelBtn.onclick = _closeAskModal;
    }

    $("#ask-ai-btn").addEventListener("click", _openAskModal);
    $("#ask-ai-close").addEventListener("click", _closeAskModal);
    askModal.addEventListener("click", (e) => { if (e.target === askModal) _closeAskModal(); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !askModal.classList.contains("hidden")) _closeAskModal();
      if (e.key === "Enter" && e.ctrlKey && !askModal.classList.contains("hidden") &&
          askLoadPanel.classList.contains("hidden") &&
          !askInputPanel.classList.contains("hidden")) {
        _submitAsk();
      }
    });

    refreshHealth();
    setInterval(refreshHealth, 30000);

    window.addEventListener("popstate", () => {
      const target = readUrl();
      if (!target) return;
      if (state.anchor && state.anchor.type === target.type && state.anchor.id === target.id) return;
      state.suppressUrlPush = true;
      anchor(target.type, target.id, { skipHistory: true }).finally(() => {
        state.suppressUrlPush = false;
      });
    });

    const initial = readUrl();
    if (initial) anchor(initial.type, initial.id);
  });
})();
