// URL artifact pane — M4. Renders /api/artifact/url/<value>.
// Mirrors artifact_ip.js but adds the host-IP cross-reference panel.

(function () {
  "use strict";

  function getUrlFromQuery() {
    // URL is passed as a `?value=<percent-encoded URL>` query
    // parameter so the artifact-pane URL doesn't collide with the
    // embedded `://`, `/`, `?` of the artifact URL itself.
    const qp = new URLSearchParams(window.location.search);
    return qp.get("value") || "";
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }
  function setHTML(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }
  function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
  function badge(label, kind) {
    const cls = kind ? ` ${kind}` : "";
    return `<span class="art-badge${cls}">${escapeHtml(label)}</span>`;
  }

  function renderBadges(data) {
    const out = [];
    const intel = data.intel;
    if (!intel) {
      out.push(badge("no URL intel yet", "unknown"));
    } else {
      const d = intel.derived || {};
      if (d.consensus_malicious) {
        out.push(badge("MALICIOUS (URL consensus)", "malicious"));
      } else if ((d.providers_with_data || 0) > 0) {
        out.push(badge("URL providers: no flag", "benign"));
      } else {
        out.push(badge("URL providers: no data", "unknown"));
      }
      if (d.consensus_label && d.consensus_label !== "unknown") {
        out.push(badge(d.consensus_label, "neutral"));
      }
    }
    // Host IP verdict — separate signal, surfaced as its own badge.
    if (data.host_ip_intel) {
      const hd = data.host_ip_intel.derived || {};
      if (hd.consensus_malicious) {
        out.push(badge(`HOST IP MALICIOUS: ${data.host_ip}`, "malicious"));
      } else if (hd.override_applied === "authoritative_clean") {
        out.push(badge(`HOST IP CLEAN: ${data.host_ip}`, "benign"));
      } else {
        out.push(badge(`host IP known: ${data.host_ip}`, "neutral"));
      }
    } else if (data.host_ip) {
      out.push(badge(`host IP ${data.host_ip} (no intel data)`, "unknown"));
    }
    setHTML("art-badges", out.join(""));
  }

  function renderDerived(intel) {
    if (!intel) {
      setHTML("derived-card",
        '<em class="empty-hint">no URL intel doc yet — this URL has not been refreshed against URLhaus / ThreatFox</em>');
      return;
    }
    const d = intel.derived || {};
    const rows = [
      ["consensus_malicious",       d.consensus_malicious === true ? "TRUE" : "false"],
      ["consensus_label",           d.consensus_label || "unknown"],
      ["override_applied",          d.override_applied || "(none)"],
      ["external_rarity_score",     d.external_rarity_score !== undefined ? d.external_rarity_score.toFixed(3) : "—"],
      ["malicious_provider_count",  d.malicious_provider_count !== undefined ? d.malicious_provider_count : "—"],
      ["confidence_max",            d.confidence_max !== undefined && d.confidence_max !== null ? d.confidence_max : "—"],
      ["tags",                      (d.tags || []).join(", ") || "—"],
      ["last_refreshed",            intel.last_refreshed || "—"],
    ];
    setHTML("derived-card",
      `<div class="art-kv">${
        rows.map(([k, v]) =>
          `<div class="art-kv-key">${escapeHtml(k)}</div><div class="art-kv-val">${escapeHtml(v)}</div>`
        ).join("")
      }</div>`);
  }

  function renderHostIp(data) {
    if (!data.host_ip) {
      setHTML("host-ip-card",
        '<em class="empty-hint">URL host is a domain, not an IP literal — host-IP cross-reference not applicable (passive DNS is a later milestone)</em>');
      return;
    }
    const link = `<a class="host-ip-link" href="/artifact/ip/${encodeURIComponent(data.host_ip)}">open IP artifact pane →</a>`;
    if (!data.host_ip_intel) {
      setHTML("host-ip-card",
        `<div class="art-kv">
          <div class="art-kv-key">host IP</div>
          <div class="art-kv-val">${escapeHtml(data.host_ip)} ${link}</div>
          <div class="art-kv-key">intel</div>
          <div class="art-kv-val"><em class="empty-hint">no intel doc — this host IP isn't in the rollup or hasn't been refreshed yet</em></div>
        </div>`);
      return;
    }
    const d = (data.host_ip_intel.derived || {});
    const rows = [
      ["host IP",                    `${data.host_ip} &nbsp;&nbsp; ${link}`],
      ["consensus_malicious",        d.consensus_malicious === true ? "TRUE" : "false"],
      ["consensus_label",            d.consensus_label || "unknown"],
      ["override_applied",           d.override_applied || "(none)"],
      ["malicious_provider_count",   d.malicious_provider_count !== undefined ? d.malicious_provider_count : "—"],
      ["external_rarity_score",      d.external_rarity_score !== undefined ? d.external_rarity_score.toFixed(3) : "—"],
      ["tags",                       (d.tags || []).join(", ") || "—"],
    ];
    setHTML("host-ip-card",
      `<div class="art-kv">${
        rows.map(([k, v]) =>
          `<div class="art-kv-key">${escapeHtml(k)}</div><div class="art-kv-val">${v}</div>`
        ).join("")
      }</div>`);
  }

  function renderCommands(cmds) {
    if (!cmds || cmds.length === 0) {
      setHTML("commands-list",
        '<em class="empty-hint">no enriched commands reference this URL in threat.indicator</em>');
      return;
    }
    const html = cmds.map((c) => {
      const cmdline = (c.process || {}).command_line || "";
      const ts = c["@timestamp"] || "?";
      const en = ((c.dashield || {}).cowrie || {}).enrichment || (((c.dshield || {}).cowrie || {}).enrichment || {});
      const occ = en.occurrence_count !== undefined ? en.occurrence_count : "?";
      const ips = en.unique_source_ips !== undefined ? en.unique_source_ips : "?";
      const intent = en.intent || "?";
      return `<div class="cmd-row">
        <div class="cmd-line">${escapeHtml(cmdline)}</div>
        <div class="cmd-meta">ts=${escapeHtml(ts)} &nbsp; intent=${escapeHtml(intent)} &nbsp; occurrence=${escapeHtml(occ)} &nbsp; unique_source_ips=${escapeHtml(ips)}</div>
      </div>`;
    }).join("");
    setHTML("commands-list", html);
  }

  function renderProviders(intel) {
    if (!intel || !intel.providers || Object.keys(intel.providers).length === 0) {
      setHTML("providers-grid",
        '<em class="empty-hint">no provider data yet — run <code>intel refresh</code></em>');
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
      const tagsHtml = (p.tags && p.tags.length)
                       ? `<div style="font-size:11px;color:#8a96b8;margin-top:3px">tags: ${p.tags.map(t => `<code>${escapeHtml(t)}</code>`).join(" ")}</div>` : "";
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
    const value = getUrlFromQuery();
    if (!value) {
      setText("art-value",
        "no URL in query string — use /artifact/url?value=<percent-encoded URL>");
      return;
    }
    setText("art-value", value);
    let data;
    try {
      const res = await fetch(
        `/api/artifact/url?value=${encodeURIComponent(value)}`,
      );
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
      setHTML("derived-card",
        `<em class="empty-hint">${escapeHtml(data.rejected_reason)}</em>`);
      setHTML("host-ip-card", "");
      setHTML("commands-list", "");
      setHTML("providers-grid", "");
      return;
    }
    renderBadges(data);
    renderDerived(data.intel);
    renderHostIp(data);
    renderCommands(data.command_docs);
    renderProviders(data.intel);
  }

  document.addEventListener("DOMContentLoaded", load);
})();
