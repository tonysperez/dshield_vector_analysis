// Health page — command-grounding coverage report (ROADMAP #11.5).
//
// Single fetch to /api/health/commands, renders three blocks:
//   - stat bar (totals + counts per status)
//   - "needs definition" list
//   - "tldr only" list
//
// The structure is intentionally generic so future health sections
// (cluster stability, LLM cost, pipeline timer status, etc.) can drop
// in as additional <section> blocks without rewriting this one.

(() => {
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function statCard(label, value, sub, kind = "") {
    const card = el("div", `stat-card ${kind}`.trim());
    card.appendChild(el("div", "stat-label", label));
    card.appendChild(el("div", "stat-value", String(value)));
    if (sub) card.appendChild(el("div", "stat-sub", sub));
    return card;
  }

  function renderStats(stats) {
    const bar = document.getElementById("grounding-stats");
    bar.innerHTML = "";
    if (!stats) return;
    bar.appendChild(statCard(
      "unique commands in corpus",
      stats.total_unique_cmds,
      "after shell-line parsing",
      "info"
    ));
    bar.appendChild(statCard(
      "curated",
      stats.curated,
      "structured per-flag entries",
      "ok"
    ));
    bar.appendChild(statCard(
      "tldr only",
      stats.tldr_only,
      "fallback description, no per-flag detail",
      stats.tldr_only > 0 ? "info" : "ok"
    ));
    bar.appendChild(statCard(
      "needs definition",
      stats.needs_def,
      "no entry of any kind",
      stats.needs_def > 0 ? "warn" : "ok"
    ));
    if (typeof stats.denied === "number") {
      bar.appendChild(statCard(
        "denied",
        stats.denied,
        "flagged as not-a-command",
        "info"
      ));
    }
    if (typeof stats.total_corpus_occurrences === "number") {
      bar.appendChild(statCard(
        "total occurrences",
        stats.total_corpus_occurrences.toLocaleString(),
        "weighted by occurrence_count",
        "info"
      ));
    }
  }

  function renderList(containerId, items, emptyMsg, opts = {}) {
    const c = document.getElementById(containerId);
    c.innerHTML = "";
    if (!items || items.length === 0) {
      c.appendChild(el("em", "hs-empty", emptyMsg));
      return;
    }
    for (const it of items) {
      const row = el("div", "hs-item");
      row.appendChild(el("div", "hs-cmd", it.name));

      const samplesWrap = el("div", "hs-samples");
      // For denied rows, the rationale is more useful than samples.
      if (opts.rationale && it.rationale) {
        samplesWrap.appendChild(el("div", "hs-sample", it.rationale));
      }
      for (const s of (it.samples || [])) {
        samplesWrap.appendChild(el("div", "hs-sample", s));
      }
      row.appendChild(samplesWrap);

      // Action column: count + per-row button. Block on non-denied rows,
      // Unblock on denied rows. Both call back into `load()` after a
      // successful write so the UI reflects the new bucket.
      const actions = el("div", "hs-actions");
      actions.appendChild(el("div", "hs-count", `${it.count} occ`));
      if (opts.allowBlock) {
        const btn = el("button", "hs-btn hs-btn-block", "Block");
        btn.title = "Add this token to the denylist (suppresses it from the LLM grounding block and moves it to the Denied bucket here).";
        btn.addEventListener("click", () => blockToken(it.name, btn));
        actions.appendChild(btn);
      } else if (opts.allowUnblock) {
        const btn = el("button", "hs-btn", "Unblock");
        btn.title = "Remove this token from the denylist (it will go back to needs_def or tldr_only on the next refresh).";
        btn.addEventListener("click", () => unblockToken(it.name, btn));
        actions.appendChild(btn);
      }
      row.appendChild(actions);

      c.appendChild(row);
    }
  }

  async function blockToken(name, btn) {
    const rationale = window.prompt(
      `Add "${name}" to the denylist.\n\nRationale ` +
      `(one short sentence — appears in the YAML and on the Denied bucket):`,
      "added via Health page"
    );
    if (rationale === null) return;   // user cancelled
    btn.disabled = true;
    btn.textContent = "…";
    try {
      const r = await fetch("/api/health/commands/denylist", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({token: name, rationale: rationale || "added via Health page"}),
      });
      if (!r.ok) {
        const text = await r.text();
        throw new Error(`HTTP ${r.status} — ${text}`);
      }
      await load();
    } catch (e) {
      window.alert(`Failed to block ${name}: ${e.message}`);
      btn.disabled = false;
      btn.textContent = "Block";
    }
  }

  async function unblockToken(name, btn) {
    if (!window.confirm(
      `Remove "${name}" from the denylist?\n\n` +
      "It will reappear in needs_def or tldr_only on the next refresh."
    )) return;
    btn.disabled = true;
    btn.textContent = "…";
    try {
      const r = await fetch(
        `/api/health/commands/denylist/${encodeURIComponent(name)}`,
        {method: "DELETE"}
      );
      if (!r.ok) {
        const text = await r.text();
        throw new Error(`HTTP ${r.status} — ${text}`);
      }
      await load();
    } catch (e) {
      window.alert(`Failed to unblock ${name}: ${e.message}`);
      btn.disabled = false;
      btn.textContent = "Unblock";
    }
  }

  function renderError(containerId, msg) {
    const c = document.getElementById(containerId);
    c.innerHTML = "";
    c.appendChild(el("div", "hs-error", msg));
  }

  async function load() {
    try {
      const r = await fetch("/api/health/commands");
      if (!r.ok) {
        const text = await r.text();
        throw new Error(`HTTP ${r.status} — ${text}`);
      }
      const data = await r.json();
      if (!data.available) {
        const reason = data.reason || "command grounding module not available on this install.";
        renderError("grounding-stats", reason);
        document.getElementById("grounding-needs-def").innerHTML = "";
        document.getElementById("grounding-tldr-only").innerHTML = "";
        return;
      }
      renderStats(data.stats);
      renderList(
        "grounding-needs-def",
        data.needs_def,
        "every command in the corpus has at least a tldr entry — nothing urgent to curate.",
        { allowBlock: true }
      );
      renderList(
        "grounding-tldr-only",
        data.tldr_only,
        "every command in the corpus has a curated entry.",
        { allowBlock: true }
      );
      renderList(
        "grounding-denied",
        data.denied,
        "no denylisted tokens have appeared in the corpus.",
        { rationale: true, allowUnblock: true }
      );
    } catch (e) {
      renderError("grounding-stats", `Failed to load health data: ${e.message}`);
    }
  }

  load();
})();
