"use strict";

/* M5 — findings page (playbook + campaign edition).
 *
 * The miner emits one finding per playbook and one per campaign. The
 * page is a triage view: status workflow drains the backlog. URL
 * query string (?status=new&kind=playbook&sort=score) survives
 * reloads and bookmarks.
 */

const STATUSES = ["new", "ack", "confirmed", "rejected"];
const KINDS = ["playbook", "campaign"];

const state = {
  status: "new",      // single status (chip click), or "all"
  kind: "",           // "" = any kind
  size: 200,
  frm: 0,
  sort: "score",
};

function parseQuery() {
  const q = new URLSearchParams(location.search);
  if (q.has("status")) state.status = q.get("status");
  if (q.has("kind"))   state.kind = q.get("kind");
  if (q.has("sort"))   state.sort = q.get("sort");
}

function pushQuery() {
  const q = new URLSearchParams();
  q.set("status", state.status);
  if (state.kind) q.set("kind", state.kind);
  if (state.sort !== "score") q.set("sort", state.sort);
  history.replaceState(null, "", "?" + q.toString());
}

function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === "class") e.className = attrs[k];
    else if (k === "html") e.innerHTML = attrs[k];
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), attrs[k]);
    else e.setAttribute(k, attrs[k]);
  }
  if (children) {
    for (const c of children) {
      if (c == null) continue;
      e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
  }
  return e;
}

function fmtScore(s) {
  if (s == null) return "—";
  const n = +s;
  if (Number.isNaN(n)) return "—";
  return n.toFixed(2);
}

function fmtTs(s) {
  if (!s) return "—";
  // YYYY-MM-DD only — the table needs date, not minute precision.
  return s.slice(0, 10);
}

function artifactLink(r) {
  const a = r.artifact || {};
  const ev = r.evidence || {};
  if (!a.value) return document.createTextNode("—");
  if (a.kind === "playbook") {
    const name = ev.playbook_name || "(unnamed)";
    return el("a", {
      href: `/graph?ioc=playbook:${encodeURIComponent(a.value)}`,
      title: a.value,
    }, [name]);
  }
  if (a.kind === "campaign") {
    const name = ev.campaign_name || "(unnamed)";
    return el("a", {
      href: `/graph?ioc=campaign:${encodeURIComponent(a.value)}`,
      title: a.value,
    }, [name]);
  }
  return document.createTextNode(`${a.kind}:${a.value}`);
}

function sizeCell(r) {
  const ev = r.evidence || {};
  const sessions = ev.member_sessions;
  const ips = ev.member_ips;
  const parts = [];
  if (sessions != null) parts.push(`${sessions} sess`);
  if (ips != null) parts.push(`${ips} IPs`);
  return parts.length ? parts.join(" · ") : "—";
}

// ---------------------------------------------------------------------------
// Filter chips
// ---------------------------------------------------------------------------

function renderStatusChips(counts) {
  const wrap = document.getElementById("status-chips");
  wrap.innerHTML = "";

  const all = ["all", ...STATUSES];
  for (const s of all) {
    const count = s === "all"
      ? Object.values(counts || {}).reduce((a, b) => a + b, 0)
      : (counts && counts[s]) || 0;
    const chip = el("span", {
      class: "fnd-chip" + (state.status === s ? " active" : ""),
      onclick: () => {
        state.status = s;
        state.frm = 0;
        pushQuery();
        refresh();
      },
    }, [s, el("span", {class: "count"}, [`${count}`])]);
    wrap.appendChild(chip);
  }
}

function renderKindChips(counts) {
  const wrap = document.getElementById("kind-chips");
  wrap.innerHTML = "";

  const all = ["", ...KINDS];
  for (const k of all) {
    const label = k === "" ? "all" : k;
    const count = k === ""
      ? Object.values(counts || {}).reduce((a, b) => a + b, 0)
      : (counts && counts[k]) || 0;
    const chip = el("span", {
      class: "fnd-chip" + (state.kind === k ? " active" : ""),
      onclick: () => {
        state.kind = k;
        state.frm = 0;
        pushQuery();
        refresh();
      },
    }, [label, el("span", {class: "count"}, [`${count}`])]);
    wrap.appendChild(chip);
  }
}

// ---------------------------------------------------------------------------
// Findings table
// ---------------------------------------------------------------------------

function renderTable(rows) {
  const wrap = document.getElementById("findings-table-wrap");
  wrap.innerHTML = "";
  if (!rows.length) {
    wrap.appendChild(el("p", {class: "fnd-empty"}, [
      "no findings match this filter — try a wider status, or run `dshield_prism mine findings`",
    ]));
    return;
  }

  const table = el("table", {class: "fnd-table"});
  const thead = el("thead", null, [el("tr", null, [
    el("th", null, ["Kind"]),
    el("th", null, ["Name"]),
    el("th", null, ["Size"]),
    el("th", null, ["Score"]),
    el("th", null, ["Narrative"]),
    el("th", null, ["First"]),
    el("th", null, ["Last"]),
    el("th", null, ["Status"]),
  ])]);
  table.appendChild(thead);

  const tbody = el("tbody");
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", null, [
      el("span", {class: `fnd-kind-badge fnd-kind-${r.kind}`}, [r.kind || "?"]),
    ]));
    tr.appendChild(el("td", {class: "artifact"}, [artifactLink(r)]));
    tr.appendChild(el("td", {class: "size"}, [sizeCell(r)]));
    tr.appendChild(el("td", {class: "score"}, [fmtScore(r.score)]));
    tr.appendChild(el("td", {class: "narrative"}, [r.narrative || ""]));
    const ev = r.evidence || {};
    tr.appendChild(el("td", null, [fmtTs(ev.first_seen || r.first_seen_at)]));
    tr.appendChild(el("td", null, [fmtTs(ev.last_seen || r.last_seen_at)]));

    const sel = el("select", {class: "fnd-status-select", "data-fid": r._id || r.finding_id});
    for (const s of STATUSES) {
      const opt = el("option", {value: s}, [s]);
      if (s === r.status) opt.setAttribute("selected", "selected");
      sel.appendChild(opt);
    }
    sel.addEventListener("change", (ev) => mutateStatus(ev.target.dataset.fid, ev.target.value, sel));
    tr.appendChild(el("td", null, [sel]));

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
}

async function mutateStatus(fid, newStatus, selEl) {
  if (!fid || !newStatus) return;
  selEl.disabled = true;
  try {
    const r = await fetch(`/api/finding/${encodeURIComponent(fid)}/status`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({status: newStatus}),
    });
    if (!r.ok) {
      const err = await r.text();
      alert(`status mutation failed: ${err}`);
    } else {
      await refresh();
    }
  } catch (exc) {
    alert(`status mutation failed: ${exc}`);
  } finally {
    selEl.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

async function refresh() {
  const params = new URLSearchParams();
  params.set("status", state.status);
  if (state.kind) params.set("kind", state.kind);
  params.set("size", state.size);
  params.set("from", state.frm);
  params.set("sort", state.sort);

  try {
    const r = await fetch("/api/findings?" + params.toString());
    if (!r.ok) {
      document.getElementById("findings-table-wrap").innerHTML =
        `<p class="fnd-empty">load failed: ${await r.text()}</p>`;
      return;
    }
    const data = await r.json();
    renderStatusChips(data.status_counts || {});
    renderKindChips(data.kind_counts || {});
    renderTable(data.rows || []);
  } catch (exc) {
    document.getElementById("findings-table-wrap").innerHTML =
      `<p class="fnd-empty">load failed: ${exc}</p>`;
  }
}

(function init() {
  parseQuery();

  const sortSel = document.getElementById("sort-select");
  sortSel.value = state.sort;
  sortSel.addEventListener("change", () => {
    state.sort = sortSel.value;
    pushQuery();
    refresh();
  });

  refresh();
})();
