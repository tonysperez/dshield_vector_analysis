/* Insights dashboard — standalone page, no external dependencies. */
(function () {
  "use strict";

  // ─── utilities ───────────────────────────────────────────────────────────

  function esc(s) {
    return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function fmt(n) {
    return (n ?? 0).toLocaleString();
  }

  function el(tag, cls, ...children) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    for (const c of children) {
      if (c == null) continue;
      if (typeof c === "string") e.appendChild(document.createTextNode(c));
      else e.appendChild(c);
    }
    return e;
  }

  function td(cls, ...children) { return el("td", cls, ...children); }
  function th(text) { const e = document.createElement("th"); e.textContent = text; return e; }

  function truncate(s, n) {
    s = s ?? "";
    return s.length > n ? s.slice(0, n) + "…" : s;
  }

  // ─── navigation ──────────────────────────────────────────────────────────

  function pivot(type, id) {
    window.location.href = "/?ioc=" + encodeURIComponent(type + ":" + id);
  }

  function pivotBtn(type, id, label) {
    const b = document.createElement("button");
    b.className = "pivot-btn";
    b.textContent = label || "→ Explore";
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      pivot(type, id);
    });
    return b;
  }

  function iocLink(type, id, label) {
    const a = document.createElement("a");
    a.className = "ioc-link";
    a.textContent = label != null ? label : id;
    a.title = type + ":" + id;
    a.href = "/?ioc=" + encodeURIComponent(type + ":" + id);
    return a;
  }

  // ─── section renderers ───────────────────────────────────────────────────

  function renderOverview(overview) {
    const statsDiv = document.getElementById("overview-stats");
    const runsDiv = document.getElementById("cluster-runs");

    // `active_playbooks` is the count of distinct playbooks (named session
    // clusters). The multi-session campaign count lives in the "Campaigns
    // (multi-session)" section below.
    const stats = [
      ["Total IPs",       overview.total_ips],
      ["Sessions",        overview.total_sessions],
      ["Commands",        overview.total_commands],
      ["Playbooks",       overview.active_playbooks],
    ];
    const runs = overview.cluster_runs || {};
    // Derived totals from run summaries
    let totalClusters = 0, totalOutliers = 0;
    for (const v of Object.values(runs)) {
      totalClusters += v.n_clusters || 0;
      totalOutliers += v.n_outliers || 0;
    }
    stats.push(["Clusters", totalClusters], ["Outliers", totalOutliers]);

    for (const [label, value] of stats) {
      const card = el("div", "stat-card");
      card.appendChild(el("div", "s-label", label));
      card.appendChild(el("div", "s-value", fmt(value)));
      statsDiv.appendChild(card);
    }

    for (const [kind, info] of Object.entries(runs)) {
      if (!info || (!info.n_clusters && !info.n_outliers)) continue;
      const chip = el("div", "run-chip");
      chip.appendChild(el("span", "rc-kind", kind));
      chip.appendChild(el("span", "rc-num", fmt(info.n_clusters)));
      chip.appendChild(el("span", "rc-sep", "clusters"));
      chip.appendChild(el("span", "rc-num", fmt(info.n_outliers)));
      chip.appendChild(el("span", "rc-sep", "outliers"));
      if (info.total_docs) {
        chip.appendChild(el("span", "rc-sep", "·"));
        chip.appendChild(el("span", "rc-sep", fmt(info.total_docs) + " docs"));
      }
      runsDiv.appendChild(chip);
    }
  }

  function renderMinedCampaigns(rows) {
    // Multi-session campaigns mined by `dshield_prism mine campaigns`.
    // `rows` shape (from queries.list_campaigns):
    //   { campaign_id, kind, name, rationale, ip_count, session_count,
    //     first_seen, last_seen, support, member_playbook_ids }
    const wrap = document.getElementById("campaigns-body");
    if (!wrap) return;
    if (!rows || !rows.length) {
      wrap.innerHTML = "";
      const e = el("em", "ins-empty",
        "No mined campaigns yet — run `dshield_prism mine campaigns` to discover them.");
      wrap.appendChild(e);
      return;
    }
    const table = el("table", "ins-table");
    const thead = el("thead");
    const hrow = el("tr");
    for (const h of ["Campaign", "Kind", "IPs", "Sessions", "Members", ""]) hrow.appendChild(th(h));
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = el("tbody");
    for (const row of rows) {
      const cid   = row.campaign_id;
      const label = row.name || cid;
      const tr = el("tr", "clickable");
      tr.addEventListener("click", () => pivot("campaign", cid));
      tr.appendChild(td("", iocLink("campaign", cid, label)));
      tr.appendChild(td("size-badge", String(row.kind || "?")));
      tr.appendChild(td("size-badge", fmt(row.ip_count)));
      tr.appendChild(td("", fmt(row.session_count)));
      const mbrs = Array.isArray(row.member_playbook_ids) ? row.member_playbook_ids.length : 0;
      tr.appendChild(td("", row.kind === "behaviour" ? `${mbrs} playbooks` : `${row.support || 0} IPs`));
      tr.appendChild(td("", pivotBtn("campaign", cid)));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.innerHTML = "";
    wrap.appendChild(table);
  }

  function renderPlaybooks(rows) {
    // Renders the Playbooks table (named session clusters). Multi-session
    // campaigns have their own renderer (`renderMinedCampaigns`).
    const wrap = document.getElementById("playbooks-body");
    if (!rows || !rows.length) { wrap.innerHTML = ""; wrap.appendChild(el("em", "ins-empty", "No playbooks found.")); return; }
    const table = el("table", "ins-table");
    const thead = el("thead");
    const hrow = el("tr");
    for (const h of ["Playbook", "IPs", "Sessions", "14d", ""]) hrow.appendChild(th(h));
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = el("tbody");
    for (const row of rows) {
      const cid   = row.id;
      const label = row.name || cid;
      const tr = el("tr", "clickable");
      tr.addEventListener("click", () => pivot("playbook", cid));
      tr.appendChild(td("", iocLink("playbook", cid, label)));
      tr.appendChild(td("size-badge", fmt(row.ip_count)));
      tr.appendChild(td("", fmt(row.session_count)));
      const sparkCell = document.createElement("td");
      const sparkSvg = renderSparkline(row.daily_14d || []);
      if (sparkSvg) sparkCell.appendChild(sparkSvg);
      tr.appendChild(sparkCell);
      tr.appendChild(td("", pivotBtn("playbook", cid)));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.innerHTML = "";
    wrap.appendChild(table);
  }

  // 14-day sparkline. `counts` is oldest → newest (today is the last entry).
  // We use a simple SVG polyline scaled to a fixed 80×18 box. Zero-only
  // series render a flat line at the bottom; one-bar series render a dot.
  function renderSparkline(counts) {
    if (!counts || counts.length === 0) return null;
    const W = 80, H = 18, padY = 1;
    const max = Math.max(1, ...counts);
    const n   = counts.length;
    const stepX = n > 1 ? W / (n - 1) : 0;
    const points = counts.map((v, i) => {
      const x = i * stepX;
      const y = H - padY - ((H - 2 * padY) * (v / max));
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(" ");
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "sparkline");
    svg.setAttribute("width", String(W));
    svg.setAttribute("height", String(H));
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("class", "bg");
    bg.setAttribute("x", "0"); bg.setAttribute("y", "0");
    bg.setAttribute("width", String(W)); bg.setAttribute("height", String(H));
    svg.appendChild(bg);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    path.setAttribute("points", points);
    svg.appendChild(path);
    // Tooltip: total sessions + max-day so the hover gives a quick read.
    const total = counts.reduce((a, b) => a + b, 0);
    svg.setAttribute("title", `${total} sessions over 14d, peak ${max}/day`);
    return svg;
  }

  function badgeIntent(intent) {
    if (!intent) return null;
    const b = el("span", "badge-intent " + intent.toLowerCase().replace(/\s+/g, "_"), intent);
    return b;
  }

  function renderCommandClusters(rows) {
    const wrap = document.getElementById("cmd-clusters-body");
    if (!rows || !rows.length) { wrap.innerHTML = ""; wrap.appendChild(el("em", "ins-empty", "No command clusters found.")); return; }
    const table = el("table", "ins-table");
    const thead = el("thead");
    const hrow = el("tr");
    for (const h of ["Cluster", "Members", "Intent", "Sample Commands", ""]) hrow.appendChild(th(h));
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = el("tbody");
    for (const row of rows) {
      const tr = el("tr", "clickable");
      tr.addEventListener("click", () => pivot("command_cluster", row.cluster_id));
      tr.appendChild(td("", iocLink("command_cluster", row.cluster_id, row.cluster_id)));
      tr.appendChild(td("size-badge", String(row.size)));
      const intentCell = document.createElement("td");
      const badge = badgeIntent(row.dominant_intent);
      if (badge) intentCell.appendChild(badge);
      tr.appendChild(intentCell);
      const sampleCell = document.createElement("td");
      const sampleList = el("div", "sample-list");
      for (const cmd of (row.sample_commands || []).slice(0, 3)) {
        const tag = el("span", "sample-tag");
        tag.textContent = truncate(cmd, 70);
        tag.title = cmd;
        sampleList.appendChild(tag);
      }
      sampleCell.appendChild(sampleList);
      tr.appendChild(sampleCell);
      tr.appendChild(td("", pivotBtn("command_cluster", row.cluster_id)));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.innerHTML = "";
    wrap.appendChild(table);
  }

  function renderSessionClusters(rows) {
    const wrap = document.getElementById("sess-clusters-body");
    if (!rows || !rows.length) { wrap.innerHTML = ""; wrap.appendChild(el("em", "ins-empty", "No session clusters found.")); return; }
    const table = el("table", "ins-table");
    const thead = el("thead");
    const hrow = el("tr");
    for (const h of ["Cluster", "Members", "Playbook", "Sample Sessions", ""]) hrow.appendChild(th(h));
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = el("tbody");
    for (const row of rows) {
      const tr = el("tr", "clickable");
      tr.addEventListener("click", () => pivot("session_cluster", row.cluster_id));
      tr.appendChild(td("", iocLink("session_cluster", row.cluster_id, row.cluster_id)));
      tr.appendChild(td("size-badge", String(row.size)));
      const pbCell = document.createElement("td");
      if (row.playbook_id) {
        pbCell.appendChild(iocLink("playbook", row.playbook_id, row.playbook_name || row.playbook_id));
      }
      tr.appendChild(pbCell);
      const sampleCell = document.createElement("td");
      const sampleList = el("div", "sample-list");
      for (const sid of (row.sample_session_ids || []).slice(0, 3)) {
        const tag = el("span", "sample-tag");
        tag.textContent = sid;
        sampleList.appendChild(tag);
      }
      sampleCell.appendChild(sampleList);
      tr.appendChild(sampleCell);
      tr.appendChild(td("", pivotBtn("session_cluster", row.cluster_id)));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.innerHTML = "";
    wrap.appendChild(table);
  }

  function renderIPClusters(rows) {
    const wrap = document.getElementById("ip-clusters-body");
    if (!rows || !rows.length) { wrap.innerHTML = ""; wrap.appendChild(el("em", "ins-empty", "No IP clusters found.")); return; }
    const table = el("table", "ins-table");
    const thead = el("thead");
    const hrow = el("tr");
    // IP clusters are unnamed actor profiles. `Playbooks` here is the
    // distinct count of playbooks spanned by the sessions of every IP in
    // this cluster — a "behaviour breadth" number for the actor profile.
    for (const h of ["Cluster", "Members", "Playbooks", "Sample IPs", "Countries", ""]) hrow.appendChild(th(h));
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = el("tbody");
    for (const row of rows) {
      const tr = el("tr", "clickable");
      tr.addEventListener("click", () => pivot("ip_cluster", row.cluster_id));
      tr.appendChild(td("", iocLink("ip_cluster", row.cluster_id, row.cluster_id)));
      tr.appendChild(td("size-badge", String(row.size)));
      tr.appendChild(td(
        "size-badge playbook-count",
        row.playbook_count == null ? "—" : String(row.playbook_count),
      ));
      const ipCell = document.createElement("td");
      const ipList = el("div", "sample-list");
      for (const ip of (row.sample_ips || []).slice(0, 4)) {
        const tag = el("span", "sample-tag ip");
        tag.textContent = ip;
        tag.title = "Open IP in graph";
        tag.addEventListener("click", (e) => { e.stopPropagation(); pivot("ip", ip); });
        ipList.appendChild(tag);
      }
      ipCell.appendChild(ipList);
      tr.appendChild(ipCell);
      const ccCell = document.createElement("td");
      const ccChips = el("div", "cc-chips");
      for (const c of (row.top_countries || []).slice(0, 5)) {
        const chip = el("span", "cc-chip", c.cc + " " + c.count);
        ccChips.appendChild(chip);
      }
      ccCell.appendChild(ccChips);
      tr.appendChild(ccCell);
      tr.appendChild(td("", pivotBtn("ip_cluster", row.cluster_id)));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.innerHTML = "";
    wrap.appendChild(table);
  }

  function renderNovelCommands(rows) {
    const wrap = document.getElementById("novel-body");
    if (!rows || !rows.length) { wrap.innerHTML = ""; wrap.appendChild(el("em", "ins-empty", "No novel commands found.")); return; }
    const table = el("table", "ins-table");
    const thead = el("thead");
    const hrow = el("tr");
    for (const h of ["Command", "Intent", "Novelty", "Sessions", "Source IPs", "MITRE", ""]) hrow.appendChild(th(h));
    thead.appendChild(hrow);
    table.appendChild(thead);
    const tbody = el("tbody");
    for (const row of rows) {
      const tr = el("tr", "clickable");
      tr.addEventListener("click", () => row.sha256 && pivot("command", row.sha256));
      const cmdCell = document.createElement("td");
      const cmdSpan = document.createElement("span");
      cmdSpan.className = "cmd-cell";
      cmdSpan.textContent = truncate(row.command_line || row.sha256, 90);
      cmdSpan.title = row.command_line || "";
      cmdCell.appendChild(cmdSpan);
      tr.appendChild(cmdCell);
      const intentCell = document.createElement("td");
      const badge = badgeIntent(row.intent);
      if (badge) intentCell.appendChild(badge);
      tr.appendChild(intentCell);
      // Novelty bar
      const novCell = document.createElement("td");
      const bar = el("div", "novelty-bar");
      const track = el("div", "novelty-track");
      const fill = el("div", "novelty-fill");
      fill.style.width = Math.round((row.novelty_score || 0) * 100) + "%";
      track.appendChild(fill);
      bar.appendChild(track);
      bar.appendChild(el("span", "novelty-val", (row.novelty_score || 0).toFixed(2)));
      novCell.appendChild(bar);
      tr.appendChild(novCell);
      tr.appendChild(td("size-badge", fmt(row.unique_sessions)));
      tr.appendChild(td("", fmt(row.unique_source_ips)));
      // MITRE
      const mitreCell = document.createElement("td");
      const tags = [...(row.techniques || []), ...(row.tactics || [])];
      for (const t of tags.slice(0, 3)) {
        mitreCell.appendChild(el("span", "mitre-tag", t));
        mitreCell.appendChild(document.createTextNode(" "));
      }
      tr.appendChild(mitreCell);
      tr.appendChild(td("", row.sha256 ? pivotBtn("command", row.sha256) : null));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.innerHTML = "";
    wrap.appendChild(table);
  }

  // ─── health badge ────────────────────────────────────────────────────────

  async function pollHealth() {
    const el = document.getElementById("health");
    try {
      const r = await fetch("/api/health");
      const d = await r.json();
      el.textContent = "ES " + (d.elasticsearch_version || d.version || "?");
      el.className = "health " + (d.ok ? "ok" : "err");
    } catch (_) {
      el.textContent = "ES offline";
      el.className = "health err";
    }
  }

  // ─── init ────────────────────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", async () => {
    const loading = document.getElementById("loading");
    loading.classList.remove("hidden");
    loading.textContent = "loading insights…";
    pollHealth();
    setInterval(pollHealth, 30000);
    try {
      const resp = await fetch("/api/insights");
      if (!resp.ok) throw new Error(resp.status + " " + resp.statusText);
      const data = await resp.json();
      renderOverview(data.overview);
      renderPlaybooks(data.playbooks);
      renderMinedCampaigns(data.mined_campaigns || []);
      renderCommandClusters(data.command_clusters);
      renderSessionClusters(data.session_clusters);
      renderIPClusters(data.ip_clusters);
      renderNovelCommands(data.novel_commands);
    } catch (e) {
      const main = document.getElementById("insights-main");
      main.innerHTML = "";
      main.appendChild(el("div", "ins-error", "Failed to load insights: " + e.message));
    } finally {
      loading.classList.add("hidden");
    }
  });
})();
