// Artifact pane — IP. Renders the /api/artifact/ip/<value> join.
// First pass of the findings-first redesign: per-artifact view that
// surfaces external TI alongside local observations.

(function () {
  "use strict";

  // Path is /artifact/ip/<value>; the page can be linked to directly.
  // Parse the last segment as the value, fall back to query-string `value`.
  function getIpFromUrl() {
    const parts = window.location.pathname.split("/").filter(Boolean);
    if (parts.length >= 3 && parts[0] === "artifact" && parts[1] === "ip") {
      return decodeURIComponent(parts[2]);
    }
    const qp = new URLSearchParams(window.location.search);
    return qp.get("value") || "";
  }

  function setText(elId, text) {
    const el = document.getElementById(elId);
    if (el) el.textContent = text;
  }

  function setHTML(elId, html) {
    const el = document.getElementById(elId);
    if (el) el.innerHTML = html;
  }

  function badge(label, kind) {
    const cls = kind ? ` ${kind}` : "";
    return `<span class="art-badge${cls}">${escapeHtml(label)}</span>`;
  }

  function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function renderBadges(data) {
    const out = [];
    const intel = data.intel;
    if (!intel) {
      out.push(badge("no intel data", "unknown"));
    } else {
      const d = intel.derived || {};
      if (d.consensus_malicious) {
        out.push(badge("MALICIOUS (consensus)", "malicious"));
      } else if (d.providers_with_data > 0) {
        out.push(badge("not flagged", "benign"));
      } else {
        out.push(badge("no provider data", "unknown"));
      }
      if (d.consensus_label && d.consensus_label !== "unknown") {
        out.push(badge(d.consensus_label, "neutral"));
      }
      (d.tags || []).forEach((tag) => out.push(badge(tag, "neutral")));
    }
    setHTML("art-badges", out.join(""));
  }

  function renderDerived(intel) {
    if (!intel) {
      setHTML("derived-card", '<em class="empty-hint">no intel doc — this IP has not been refreshed yet</em>');
      return;
    }
    const d = intel.derived || {};
    const rows = [
      ["consensus_malicious",   d.consensus_malicious === true ? "TRUE" : "false"],
      ["consensus_label",       d.consensus_label || "unknown"],
      ["external_rarity_score", (d.external_rarity_score !== undefined && d.external_rarity_score !== null)
                                  ? d.external_rarity_score.toFixed(3) : "—"],
      ["providers_with_data",   `${d.providers_with_data || 0} / ${d.providers_total || 0}`],
      ["tags",                  (d.tags || []).join(", ") || "—"],
      ["last_refreshed",        intel.last_refreshed || "—"],
    ];
    const html = `<div class="art-kv">${
      rows.map(([k, v]) =>
        `<div class="art-kv-key">${escapeHtml(k)}</div><div class="art-kv-val">${escapeHtml(v)}</div>`
      ).join("")
    }</div>`;
    setHTML("derived-card", html);
  }

  function renderRollup(rollup) {
    if (!rollup) {
      setHTML("rollup-card", '<em class="empty-hint">no local observations — this IP is not in the rollup index</em>');
      return;
    }
    const enrich = ((rollup.dshield || {}).cowrie || {}).enrichment || {};
    const ip = enrich.ip || {};
    const src = rollup.source || {};
    const geo = (src.geo || {});
    const asn = ((src.as || {}).organization || {}).name || (src.as || {}).number;
    const rows = [
      ["total_sessions",          ip.total_sessions ?? "—"],
      ["successful_sessions",     ip.successful_sessions ?? "—"],
      ["command_sessions",        ip.command_sessions ?? "—"],
      ["total_commands",          ip.total_commands ?? "—"],
      ["dominant_intent",         ip.dominant_intent ?? "—"],
      ["mean_novelty_score",      ip.mean_novelty_score !== undefined ? ip.mean_novelty_score.toFixed(3) : "—"],
      ["max_novelty_score",       ip.max_novelty_score !== undefined ? ip.max_novelty_score.toFixed(3) : "—"],
      ["first_seen",              ip.first_seen ?? "—"],
      ["last_seen",               ip.last_seen ?? "—"],
      ["geo.country",             geo.country_iso_code ?? "—"],
      ["geo.city",                geo.city_name ?? "—"],
      ["as",                      asn ?? "—"],
      ["credentials_seen",        Array.isArray(ip.credentials) ? ip.credentials.length : "—"],
    ];
    const html = `<div class="art-kv">${
      rows.map(([k, v]) =>
        `<div class="art-kv-key">${escapeHtml(k)}</div><div class="art-kv-val">${escapeHtml(v)}</div>`
      ).join("")
    }</div>`;
    setHTML("rollup-card", html);
  }

  function renderProviders(intel) {
    if (!intel || !intel.providers || Object.keys(intel.providers).length === 0) {
      setHTML("providers-grid", '<em class="empty-hint">no provider data yet — run <code>intel refresh</code></em>');
      return;
    }
    const providers = intel.providers || {};
    const cards = Object.keys(providers).sort().map((name) => {
      const p = providers[name] || {};
      const verdict = p.malicious === true ? badge("malicious", "malicious")
                    : p.malicious === false ? badge("benign", "benign")
                    : badge("no opinion", "unknown");
      const labelHtml = p.label ? `<div style="font-size:11px;color:#8a96b8;margin:4px 0">label: <code>${escapeHtml(p.label)}</code></div>` : "";
      const confHtml = (p.confidence !== null && p.confidence !== undefined)
                       ? `<div style="font-size:11px;color:#8a96b8">confidence: <code>${p.confidence}</code></div>` : "";
      const tagsHtml = (p.tags && p.tags.length) ? `<div style="font-size:11px;color:#8a96b8;margin-top:3px">tags: ${p.tags.map(t => `<code>${escapeHtml(t)}</code>`).join(" ")}</div>` : "";
      const fetchedHtml = `<div style="font-size:10px;color:#414b62;margin-top:6px">fetched ${escapeHtml(p.fetched_at || "?")}</div>`;
      const structured = p.structured || {};
      const rawJson = JSON.stringify(structured, null, 2);
      return `<div class="provider-card">
        <div class="pc-name">${escapeHtml(name)}</div>
        <div class="pc-verdict">${verdict}</div>
        ${labelHtml}${confHtml}${tagsHtml}${fetchedHtml}
        <pre>${escapeHtml(rawJson)}</pre>
      </div>`;
    });
    setHTML("providers-grid", cards.join(""));
  }

  async function load() {
    const value = getIpFromUrl();
    if (!value) {
      setText("art-value", "no IP in URL");
      return;
    }
    setText("art-value", value);
    let data;
    try {
      const res = await fetch(`/api/artifact/ip/${encodeURIComponent(value)}`);
      if (!res.ok) {
        setText("art-value", `${value} — error ${res.status}`);
        return;
      }
      data = await res.json();
    } catch (e) {
      setText("art-value", `${value} — fetch failed`);
      return;
    }
    if (data.rejected_reason) {
      setHTML("derived-card", `<em class="empty-hint">${escapeHtml(data.rejected_reason)}</em>`);
      setHTML("rollup-card", "");
      setHTML("providers-grid", "");
      return;
    }
    renderBadges(data);
    renderDerived(data.intel);
    renderRollup(data.rollup);
    renderProviders(data.intel);
  }

  document.addEventListener("DOMContentLoaded", load);
})();
