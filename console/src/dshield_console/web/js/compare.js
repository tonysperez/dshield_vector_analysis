/* Compare two session clusters: structured analysis + on-demand LLM narrative.
 * Vanilla JS, no framework. State lives in three module-scope variables:
 *   - clusters[]: the dropdown source (loaded once on page open)
 *   - analysis:   the latest /api/compare response (used for /api/compare/explain POST)
 *   - llm:        the latest /api/compare/explain response
 */
(function () {
  "use strict";

  let clusters = [];     // [{cluster_id, size, playbook_id, playbook_name}, ...]
  let analysis = null;   // structured analysis dict
  let llm      = null;   // LLM narrative dict

  // ---- bootstrap ---------------------------------------------------------

  document.addEventListener("DOMContentLoaded", () => {
    initHealth();
    initTabs();
    initButtons();
    loadClusters().then(() => {
      // Deep-link support: /compare?a=cluster_9&b=cluster_12
      const qs = new URLSearchParams(window.location.search);
      const a = qs.get("a");
      const b = qs.get("b");
      if (a && b) {
        document.getElementById("picker-a").value = a;
        document.getElementById("picker-b").value = b;
        updateGoEnabled();
        runCompare();
      }
    });
  });

  async function initHealth() {
    try {
      const r = await fetch("/api/health");
      const d = await r.json();
      const el = document.getElementById("health");
      el.textContent = d.ok ? "● healthy" : "● error";
      el.className = "health " + (d.ok ? "ok" : "err");
    } catch (_) {
      document.getElementById("health").textContent = "● offline";
    }
  }

  function initTabs() {
    for (const tab of document.querySelectorAll(".cmp-tab")) {
      tab.addEventListener("click", () => switchTab(tab.dataset.tab));
    }
  }

  function switchTab(name) {
    for (const tab of document.querySelectorAll(".cmp-tab")) {
      tab.classList.toggle("active", tab.dataset.tab === name);
    }
    document.getElementById("tab-plain").classList.toggle("active", name === "plain");
    document.getElementById("tab-tech").classList.toggle("active", name === "tech");
  }

  function initButtons() {
    document.getElementById("picker-a").addEventListener("change", updateGoEnabled);
    document.getElementById("picker-b").addEventListener("change", updateGoEnabled);
    document.getElementById("cmp-go").addEventListener("click", runCompare);
  }

  function updateGoEnabled() {
    const a = document.getElementById("picker-a").value;
    const b = document.getElementById("picker-b").value;
    document.getElementById("cmp-go").disabled = !a || !b || a === b;
  }

  // ---- dropdown population ----------------------------------------------

  async function loadClusters() {
    try {
      const r = await fetch("/api/compare/clusters");
      if (!r.ok) throw new Error(`status ${r.status}`);
      const d = await r.json();
      clusters = d.clusters || [];
    } catch (e) {
      showError(`Could not load cluster list: ${e.message}`);
      return;
    }
    const a = document.getElementById("picker-a");
    const b = document.getElementById("picker-b");
    for (const sel of [a, b]) {
      while (sel.options.length > 1) sel.remove(1);
      for (const c of clusters) {
        const opt = document.createElement("option");
        opt.value = c.cluster_id;
        const name = c.playbook_name ? ` — ${c.playbook_name}` : " — (unnamed)";
        opt.textContent = `${c.cluster_id} (size ${c.size})${name}`;
        sel.appendChild(opt);
      }
    }
  }

  // ---- run the analysis -------------------------------------------------

  async function runCompare() {
    const a = document.getElementById("picker-a").value;
    const b = document.getElementById("picker-b").value;
    if (!a || !b || a === b) return;
    hideError();
    setLoading(true);
    analysis = null;
    llm = null;

    try {
      const r = await fetch(`/api/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
      if (!r.ok) {
        const txt = await r.text();
        throw new Error(`HTTP ${r.status}: ${txt}`);
      }
      analysis = await r.json();
    } catch (e) {
      showError(`compare failed: ${e.message}`);
      setLoading(false);
      return;
    }
    setLoading(false);

    // Update URL so the page is shareable.
    const u = new URL(window.location.href);
    u.searchParams.set("a", a);
    u.searchParams.set("b", b);
    window.history.replaceState({}, "", u);

    renderVerdictBar(analysis);
    renderTechnical(analysis);
    // Reset the plain-language tab.
    document.getElementById("llm-area").innerHTML = `
      <div class="cmp-llm-empty">
        <p>Click Explain to ask the local LLM to summarise the gap between these clusters
          in plain language. Takes 10-30 seconds. The Technical detail tab is ready now
          with the raw analysis.</p>
        <button id="cmp-explain" class="cmp-btn">Explain</button>
      </div>`;
    document.getElementById("cmp-explain").addEventListener("click", runExplain);

    document.getElementById("cmp-result").classList.remove("hidden");
  }

  // ---- run the LLM ------------------------------------------------------

  async function runExplain() {
    if (!analysis) return;
    const area = document.getElementById("llm-area");
    area.innerHTML = `
      <div class="cmp-llm-empty">
        <p><span class="cmp-spinner"></span>Asking the local LLM for an explanation…
        Usually takes 10-30 seconds.</p>
      </div>`;
    try {
      const r = await fetch("/api/compare/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analysis: analysis }),
      });
      if (!r.ok) {
        const txt = await r.text();
        throw new Error(`HTTP ${r.status}: ${txt}`);
      }
      llm = await r.json();
    } catch (e) {
      area.innerHTML = `<div class="cmp-error">LLM call failed: ${escapeHtml(e.message)}</div>`;
      return;
    }
    renderLLM(llm);
  }

  // ---- render: verdict bar ----------------------------------------------

  function renderVerdictBar(a) {
    const sim = a.centroid_similarity;
    const t = a.merge_threshold;
    const gap = a.gap_to_merge;
    const wm = a.would_merge;
    const bar = document.getElementById("cmp-verdict-bar");
    bar.innerHTML = `
      <div class="cmp-vb-side">
        <h3>${escapeHtml(a.a.cluster_id)}</h3>
        <div class="meta">
          size ${a.a.size} · playbook
          <span class="pb">${escapeHtml(a.a.playbook_name || '(unnamed)')}</span>
          <br>
          <code style="font-size:10px;color:#6b7494">${escapeHtml(a.a.playbook_id || '')}</code>
        </div>
      </div>
      <div class="cmp-vb-side">
        <h3>${escapeHtml(a.b.cluster_id)}</h3>
        <div class="meta">
          size ${a.b.size} · playbook
          <span class="pb">${escapeHtml(a.b.playbook_name || '(unnamed)')}</span>
          <br>
          <code style="font-size:10px;color:#6b7494">${escapeHtml(a.b.playbook_id || '')}</code>
        </div>
      </div>
      <div class="cmp-sim-row">
        <span>cosine sim <b>${sim.toFixed(4)}</b></span>
        <span>merge threshold <b>${t.toFixed(4)}</b></span>
        <span>gap <b>${gap >= 0 ? '+' : ''}${gap.toFixed(4)}</b></span>
        <span class="${wm ? 'merged-yes' : 'merged-no'}">
          ${wm ? '✓ would merge at current τ' : '✗ BELOW threshold — kept separate'}
        </span>
      </div>`;
  }

  // ---- render: plain language -------------------------------------------

  function renderLLM(d) {
    const area = document.getElementById("llm-area");
    const verdict = (d.verdict || 'marginal_split').replace(/[^a-z_]/g, '');
    const rec     = (d.recommendation || 'accept_split').replace(/[^a-z_]/g, '');
    area.innerHTML = `
      <div class="cmp-llm-card">
        <div class="row">
          <span class="label">Verdict</span>
          <span class="value verdict-tag ${verdict}">${escapeHtml(d.verdict || '')}</span>
        </div>
        <div class="row">
          <span class="label">Evidence</span>
          <span class="value">${escapeHtml(d.evidence || '')}</span>
        </div>
        <div class="row">
          <span class="label">Recommendation</span>
          <span class="value rec-tag ${rec}">${escapeHtml(d.recommendation || '')}</span>
        </div>
        ${d.rationale ? `
        <div class="row">
          <span class="label">Rationale</span>
          <span class="value">${escapeHtml(d.rationale)}</span>
        </div>` : ''}
        <div class="row" style="margin-top:14px;font-size:10px;color:#414b62">
          Local-LLM output. Not authoritative — verify against the Technical detail tab.
        </div>
      </div>`;
  }

  // ---- render: technical detail -----------------------------------------

  function renderTechnical(a) {
    const aId = a.a.cluster_id;
    const bId = a.b.cluster_id;
    let html = '';

    // Scalars block
    html += `<div class="cmp-block">
      <h4>Scalar distributions <span style="text-transform:none;color:#6b7494">
        — HDBSCAN clustered on [embedding | 4 scalars × ${a.scalar_weight}]
      </span></h4>
      <table class="cmp-table">
        <thead><tr><th>scalar</th>
          <th class="right">${escapeHtml(aId)} mean ± std</th>
          <th class="right">${escapeHtml(bId)} mean ± std</th>
          <th class="right">Δ (A − B)</th></tr></thead>
        <tbody>`;
    for (const [k, vs] of Object.entries(a.scalars)) {
      html += `<tr>
        <td>${k}</td>
        <td class="right">${vs.a_mean.toFixed(3)} ± ${vs.a_std.toFixed(3)}</td>
        <td class="right">${vs.b_mean.toFixed(3)} ± ${vs.b_std.toFixed(3)}</td>
        <td class="right">${vs.delta >= 0 ? '+' : ''}${vs.delta.toFixed(3)}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;

    // Top commands two-column
    html += `<div class="cmp-block">
      <h4>Top commands (by count in sampled sessions)</h4>
      <div class="cmp-twocol">
        ${commandTable(aId, a.top_commands_a)}
        ${commandTable(bId, a.top_commands_b)}
      </div>
    </div>`;

    // Command-set diff
    const d = a.command_set_diff;
    const union = new Set([...(d.shared || []), ...(d.only_a || []), ...(d.only_b || [])]);
    html += `<div class="cmp-block">
      <h4>Command-set diff (top-K only)</h4>
      <div style="font-size:11px;color:#c8d0e7;font-family:ui-monospace,monospace">
        Jaccard: <b>${d.jaccard.toFixed(3)}</b>
        &nbsp;·&nbsp; shared: ${d.shared.length}
        &nbsp;·&nbsp; only A: ${d.only_a.length}
        &nbsp;·&nbsp; only B: ${d.only_b.length}
        &nbsp;·&nbsp; union: ${union.size}
      </div>
    </div>`;

    // Off-centroid tables
    if (a.off_centroid_a && a.off_centroid_a.length) {
      html += offCentroidTable(`Commands only in ${aId}`, aId, bId, a.off_centroid_a);
    }
    if (a.off_centroid_b && a.off_centroid_b.length) {
      html += offCentroidTable(`Commands only in ${bId}`, aId, bId, a.off_centroid_b);
    }

    // Sample sequences
    html += `<div class="cmp-block">
      <h4>Sample command sequences</h4>
      <div class="cmp-twocol">
        ${sequenceColumn(aId, a.sample_sequences_a)}
        ${sequenceColumn(bId, a.sample_sequences_b)}
      </div>
    </div>`;

    document.getElementById("tech-area").innerHTML = html;
  }

  function commandTable(label, rows) {
    let inner = `<div style="margin-bottom:6px;color:#4cc1ff;
      font-family:ui-monospace,monospace;font-size:11px">${escapeHtml(label)}</div>`;
    if (!rows || !rows.length) {
      return inner + `<em style="font-size:11px;color:#414b62">(no commands)</em>`;
    }
    inner += `<table class="cmp-table"><thead><tr>
      <th class="right">count</th><th>command</th></tr></thead><tbody>`;
    for (const r of rows) {
      inner += `<tr><td class="right">${r.count}</td>
        <td class="cmd">${escapeHtml(r.command)}</td></tr>`;
    }
    inner += `</tbody></table>`;
    return inner;
  }

  function offCentroidTable(title, aId, bId, rows) {
    let html = `<div class="cmp-block">
      <h4>${escapeHtml(title)}
        <span style="text-transform:none;color:#6b7494">
          — sim to each centroid (sorted by 'pulls toward ${escapeHtml(aId)}')
        </span></h4>
      <table class="cmp-table"><thead><tr>
        <th>command</th>
        <th class="right">sim → ${escapeHtml(aId)}</th>
        <th class="right">sim → ${escapeHtml(bId)}</th>
        <th class="right">diff</th></tr></thead><tbody>`;
    for (const r of rows) {
      const sa = r.sim_a == null ? 'n/a' : r.sim_a.toFixed(3);
      const sb = r.sim_b == null ? 'n/a' : r.sim_b.toFixed(3);
      const df = r.diff  == null ? 'n/a' : (r.diff >= 0 ? '+' : '') + r.diff.toFixed(3);
      html += `<tr>
        <td class="cmd">${escapeHtml(r.command)}</td>
        <td class="right">${sa}</td>
        <td class="right">${sb}</td>
        <td class="right">${df}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
    return html;
  }

  function sequenceColumn(label, seqs) {
    let html = `<div>
      <div style="margin-bottom:6px;color:#4cc1ff;
        font-family:ui-monospace,monospace;font-size:11px">${escapeHtml(label)}</div>`;
    if (!seqs || !seqs.length) {
      return html + `<em style="font-size:11px;color:#414b62">(no sessions)</em></div>`;
    }
    for (const s of seqs) {
      const more = s.total_commands > s.commands.length
        ? `\n  ... +${s.total_commands - s.commands.length} more`
        : '';
      const lines = (s.commands || []).map(c => '  | ' + c).join('\n');
      html += `<div class="cmp-seq">
        <div><span class="sid">${escapeHtml(s.sid)}</span>
          <span class="meta">  (${s.total_commands} command events)</span></div>
${escapeHtml(lines + more)}
      </div>`;
    }
    return html + `</div>`;
  }

  // ---- helpers ----------------------------------------------------------

  function setLoading(on) {
    document.getElementById("loading").classList.toggle("hidden", !on);
    document.getElementById("loading").textContent = on ? "loading…" : "";
    document.getElementById("cmp-go").disabled = on;
  }

  function showError(msg) {
    document.getElementById("cmp-error-section").classList.remove("hidden");
    document.getElementById("cmp-error").textContent = msg;
  }
  function hideError() {
    document.getElementById("cmp-error-section").classList.add("hidden");
  }

  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
})();
