/* DShield Console — graph view.
 *
 * Strict layered (swim-lane) layout with bubble-set cluster regions and
 * badge-demoted attributes (ASN/Country/MITRE). Pure Canvas2D — no physics,
 * no external graph library — so layout is deterministic and snappy at
 * the medium scale (200–1000 nodes) we target.
 *
 * Layout model
 * ------------
 *   columns (left→right) by IOC kind:
 *     0 = geo (asn / country)            — usually empty unless anchored
 *     1 = ip
 *     2 = session
 *     3 = command
 *     4 = mitre  (technique + tactic)    — usually empty unless anchored
 *
 *   Cluster nodes (ip_cluster / session_cluster / command_cluster) live in
 *   the column of their member kind and are rendered as a header pill above
 *   their members. The bubble-set hull is drawn behind those members so
 *   "cluster" reads spatially, not as a separate edge type.
 *
 *   Playbooks are super-bubbles that may span Session and Command columns,
 *   wrapping every node tagged with that playbook_id.
 *
 *   Within a column, nodes are grouped by cluster_id, then ordered to put
 *   the anchor (when present) first and outliers last. Group ordering is
 *   stable by cluster id for deterministic layouts across renders.
 *
 * Badges
 * ------
 *   ASN, country, and MITRE IDs are usually attributes, not nodes. When a
 *   node carries them via metadata (e.g. ip.asn, command.mitre_techniques),
 *   we draw them as small chips next to the node body. Clicking a chip
 *   pivots to the corresponding IOC. If the user anchors directly on an
 *   ASN / country / MITRE, that IOC becomes a real node in column 0 / 4
 *   and badges are not drawn for it.
 *
 * Sets (for the UpSet sidecar)
 * ---------------------------
 *   The view's "sets" are: every cluster id present (3 kinds), every
 *   playbook, every campaign, every ASN, every country, every MITRE id.
 *   getSets() walks the current node list and produces {sets, members,
 *   intersections}.
 *
 * Public API (compatible-ish with the previous force-graph version):
 *   Graph.init(containerId)
 *   Graph.replace(graph, anchorId)
 *   Graph.merge(graph, originId)
 *   Graph.setAnchor(id)
 *   Graph.onSelect(fn) / Graph.onExpand(fn)
 *   Graph.fit()
 *   New:
 *     Graph.getSets()                       -- {sets, nodeSets}
 *     Graph.highlightSets(setIds | null)    -- highlight nodes in these sets
 *     Graph.highlightIntersection(setIds | null) -- highlight nodes in ALL of these
 *     Graph.onDataChange(fn)                -- fires when nodes/edges change
 */
(function () {
  // ===================================================================
  // Constants / styling
  // ===================================================================
  // Column order, left-to-right. `campaign` (multi-session) and `playbook`
  // (LLM-named session cluster) each get their own columns; both are
  // auto-shown only when nodes of that type are present. Neither has a
  // lane checkbox.
  const COLUMNS = ["campaign", "playbook", "geo", "ip", "session", "command", "mitre"];
  const COL_LABEL = {
    campaign: "Campaign", playbook: "Playbook",
    geo: "ASN / Country", ip: "IP", session: "Session", command: "Command", mitre: "MITRE",
  };

  const TYPE_TO_COLUMN = {
    campaign: "campaign",       // multi-session pattern (mined)
    playbook: "playbook",       // LLM-named session cluster
    asn: "geo", country: "geo",
    ip: "ip", ip_cluster: "ip",
    session: "session", session_cluster: "session",
    command: "command", command_cluster: "command",
    mitre_technique: "mitre", mitre_tactic: "mitre",
  };

  const TYPE_COLOR = {
    ip: "#ff9f43",
    session: "#4cc1ff",
    command: "#4ade80",
    command_cluster: "#ef4444",
    session_cluster: "#b91c1c",
    ip_cluster: "#a855f7",
    playbook: "#facc15",
    campaign: "#fb923c",
    asn: "#94a3b8",
    country: "#cbd5e1",
    mitre_technique: "#2dd4bf",
    mitre_tactic: "#14b8a6",
  };

  // Hash a string to a stable hue (used for playbook bubble tints
  // so two different clusters can be told apart even when they overlap).
  function hashHue(s) {
    let h = 0;
    s = String(s);
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
    return Math.abs(h) % 360;
  }

  // ===================================================================
  // State
  // ===================================================================
  let containerEl = null;
  let canvas = null;
  let tooltipEl = null;
  let ctx = null;
  let dpr = 1;
  let viewW = 0, viewH = 0;

  let nodesById = new Map();       // id -> node (with computed layout fields)
  let edges = [];                  // {source, target, kind, label}
  let anchorId = null;

  // View transform (CSS pixels → world pixels)
  let zoom = 1;
  let panX = 0;
  let panY = 0;

  let hoverId = null;
  // Click semantics:
  //   plain click  -> pinnedIds = {id}            (replace, persistent highlight)
  //   shift+click  -> toggle id in pinnedIds      (build up a multi-IOC focus)
  //   alt+click    -> toggle id in greyedIds      (subtract / inverse highlight)
  //   ESC          -> clear both sets
  // greyedIds nodes + their pipeline neighbors are forced dim even when
  // nothing is pinned (so alt-click stands on its own with a neutral graph).
  let pinnedIds = new Set();
  let greyedIds = new Set();
  let lastClick = { id: null, ts: 0 };
  let hoverBadge = null;           // {nodeId, idx} when hovering a badge chip

  let highlightSetIds = null;      // Set of set-ids to keep visible (union)
  let highlightIntersectionIds = null; // Set whose members must appear in ALL listed sets

  let selectHandler = null;
  let expandHandler = null;
  let dataChangeHandler = null;
  let pivotHandler = null;

  // For deterministic group ordering, remember insertion order of cluster ids.
  let clusterOrder = new Map();    // column -> [cluster_id, ...]

  let dragState = null;            // {x0, y0, panX0, panY0}
  let needsRender = false;
  // Lane visibility — drives both ingest filtering and column rendering.
  // Default: every lane is visible.
  // "campaign" is intentionally omitted from laneVisibility — the campaign
  // column is auto-shown when campaign nodes exist and can't be hidden via the
  // lane checkboxes (its visibility is purely data-driven, not user-controlled).
  let laneVisibility = new Set(["geo", "ip", "session", "command", "mitre"]);

  // ===================================================================
  // Init / sizing
  // ===================================================================
  function init(containerId) {
    containerEl = document.getElementById(containerId);
    canvas = document.createElement("canvas");
    canvas.style.position = "absolute";
    canvas.style.inset = "0";
    canvas.style.width = "100%";
    canvas.style.height = "100%";
    canvas.style.display = "block";
    containerEl.appendChild(canvas);
    ctx = canvas.getContext("2d", { alpha: true });

    // Hover tooltip: small DOM overlay that follows the cursor when the
    // user is over an interactive node. Lets the hunter read a node's
    // metadata (campaign membership, novelty, intent, etc.) without
    // committing a click. Hidden by default.
    tooltipEl = document.createElement("div");
    tooltipEl.className = "graph-hover-tooltip hidden";
    containerEl.appendChild(tooltipEl);

    new ResizeObserver(_resize).observe(containerEl);
    _resize();

    canvas.addEventListener("mousemove", _onMouseMove);
    canvas.addEventListener("mousedown", _onMouseDown);
    canvas.addEventListener("mouseup", _onMouseUp);
    canvas.addEventListener("mouseleave", _onMouseLeave);
    canvas.addEventListener("click", _onClick);
    canvas.addEventListener("dblclick", _onDoubleClick);
    canvas.addEventListener("contextmenu", _onContextMenu);
    canvas.addEventListener("wheel", _onWheel, { passive: false });
    // ESC clears all persistent highlight state. Bound on the document
    // because the canvas isn't focusable; we guard against firing while
    // the user is typing in an input.
    document.addEventListener("keydown", _onKeyDown);

    _scheduleRender();
  }

  function _onKeyDown(e) {
    if (e.key !== "Escape") return;
    const t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
    if (pinnedIds.size === 0 && greyedIds.size === 0) return;
    pinnedIds.clear();
    greyedIds.clear();
    _neighborCacheKey = null;
    _neighborCache = null;
    _scheduleRender();
  }

  function _resize() {
    if (!containerEl) return;
    dpr = window.devicePixelRatio || 1;
    viewW = containerEl.clientWidth;
    viewH = containerEl.clientHeight;
    canvas.width = Math.floor(viewW * dpr);
    canvas.height = Math.floor(viewH * dpr);
    canvas.style.width = viewW + "px";
    canvas.style.height = viewH + "px";
    if (nodesById.size > 0) _layout();
    _scheduleRender();
  }

  // ===================================================================
  // Data ingest
  // ===================================================================
  function replace(graph, anchorIdIn) {
    nodesById = new Map();
    edges = [];
    anchorId = anchorIdIn || null;
    clusterOrder = new Map();
    pinnedIds.clear();
    greyedIds.clear();
    hoverId = null;
    highlightSetIds = null;
    highlightIntersectionIds = null;
    _ingest(graph);
    _layout();
    _resetView();
    if (dataChangeHandler) dataChangeHandler();
    _scheduleRender();
  }

  function merge(graph, originIdIn) {
    _ingest(graph);
    _layout();
    if (dataChangeHandler) dataChangeHandler();
    _scheduleRender();
  }

  function _laneFor(type) {
    return TYPE_TO_COLUMN[type];
  }

  function _ingest(graph) {
    for (const n of (graph.nodes || [])) {
      const d = Object.assign({}, n.data || {});
      // Skip nodes whose lane is hidden. Campaign and playbook nodes live
      // in their own auto-visible columns (driven by data presence, not by
      // user lane checkboxes), so they bypass this filter.
      if (d.type !== "campaign" && d.type !== "playbook") {
        const lane = _laneFor(d.type);
        if (lane && !laneVisibility.has(lane)) continue;
      }
      // Normalize cluster_id to string so int/string round-trips don't
      // break group-membership comparisons in layout/getSets.
      if (d.cluster_id !== undefined && d.cluster_id !== null) {
        d.cluster_id = String(d.cluster_id);
      }
      const existing = nodesById.get(d.id);
      if (existing) {
        // Merge field-by-field, preferring non-null incoming values. We
        // can't compare key counts because after the first layout pass,
        // every node carries x/y/w/h/group — making a freshly-sparse-API
        // response always look "smaller" than the laid-out node.
        for (const k of Object.keys(d)) {
          if (d[k] === null || d[k] === undefined) continue;
          existing[k] = d[k];
        }
        continue;
      }
      nodesById.set(d.id, d);
    }
    // Dedup edges by (source, target, kind).
    const seen = new Set(edges.map((e) => `${e.source}|${e.target}|${e.kind || ""}`));
    for (const e of (graph.edges || [])) {
      const d = e.data || {};
      const key = `${d.source}|${d.target}|${d.kind || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({
        id: d.id, source: d.source, target: d.target,
        label: d.label, kind: d.kind,
      });
    }
    _neighborCacheKey = null;
    _neighborCache = null;
  }

  function setAnchor(id) {
    anchorId = id;
    _layout();
    _scheduleRender();
  }

  function hasNode(id) {
    return nodesById.has(id);
  }

  function allNodes() {
    const out = [];
    for (const n of nodesById.values()) out.push(_publicData(n));
    return out;
  }

  function getPinned() {
    return Array.from(pinnedIds);
  }

  function getFocusReach() {
    // Test-friendly: returns the set of node ids that should remain
    // undimmed given the current pin+hover state. Mirrors what the
    // renderer uses to decide each node's globalAlpha.
    const u = _focusUndimmed();
    return u ? Array.from(u) : [];
  }

  function setPinned(ids) {
    pinnedIds = new Set(ids || []);
    _neighborCacheKey = null; _neighborCache = null;
    _scheduleRender();
  }

  function nodeScreenPos(id) {
    const n = nodesById.get(id);
    if (!n || !isFinite(n.x)) return null;
    return { x: n.x * zoom + panX, y: n.y * zoom + panY };
  }

  function setLaneVisibility(lanes) {
    laneVisibility = new Set(lanes);
    // Drop any nodes whose lane is now hidden. Campaign + playbook nodes
    // live in their own auto-visible columns (data-driven, not lane-
    // toggled) so they're always kept.
    const toRemove = [];
    for (const [id, n] of nodesById) {
      if (n.type === "campaign" || n.type === "playbook") continue;
      const lane = _laneFor(n.type);
      if (lane && !laneVisibility.has(lane)) toRemove.push(id);
    }
    if (toRemove.length > 0) removeNodes(toRemove);
    else _layout();
    // Re-fit so the remaining columns actually re-center; without this
    // the pan/zoom is still anchored to the previous column count and
    // the canvas just shows a wider empty band where the hidden lane
    // used to live.
    fit(0);
    _scheduleRender();
  }

  function removeNodes(ids) {
    if (!ids) return;
    const set = ids instanceof Set ? ids : new Set(ids);
    if (set.size === 0) return;
    let removed = 0;
    for (const id of set) {
      if (id === anchorId) continue; // never remove the anchor by accident
      if (nodesById.delete(id)) removed++;
    }
    if (removed === 0) return;
    edges = edges.filter((e) => !set.has(e.source) && !set.has(e.target));
    _neighborCacheKey = null; _neighborCache = null;
    for (const id of set) pinnedIds.delete(id);
    if (hoverId && set.has(hoverId)) hoverId = null;
    _layout();
    if (dataChangeHandler) dataChangeHandler();
    _scheduleRender();
  }

  // ===================================================================
  // Layout
  // ===================================================================
  function _layout() {
    if (!viewW || !viewH) return;

    // 1. Bucket nodes by column. Cluster nodes count as part of their
    //    member column. Campaign nodes are stored separately. Badge-kinds
    //    (asn/country/mitre) are demoted to chips on host nodes unless
    //    the user has anchored on one (then we render it as a real
    //    column node so the user sees what they pivoted to).
    const anchorNode = anchorId && nodesById.get(anchorId);
    const anchorIsBadgeKind = anchorNode && _isBadgeKind(anchorNode.type);
    const buckets = { campaign: [], playbook: [], geo: [], ip: [], session: [], command: [], mitre: [] };
    for (const n of nodesById.values()) {
      // Clear any stale layout coords so a node demoted to a badge has
      // !isFinite(x) and edge-draw will skip it.
      n.x = NaN; n.y = NaN;
      if (_isBadgeKind(n.type) && n.id !== anchorId && !anchorIsBadgeKind) continue;
      const col = TYPE_TO_COLUMN[n.type];
      if (!col) continue;
      buckets[col].push(n);
    }

    // 2. Decide which columns to show. A column is shown when:
    //      a) its lane is checked in laneVisibility (user can hide any
    //         column via the lane checkboxes), AND
    //      b) it has ≥1 node OR it's a core pipeline column (ip/session/
    //         command) OR it hosts the current anchor.
    //    Hiding a lane removes its column entirely; the layout
    //    re-spaces the remaining columns to fill the width.
    const anchorCol = anchorId && nodesById.has(anchorId)
      ? TYPE_TO_COLUMN[nodesById.get(anchorId).type] : null;
    const visible = COLUMNS.filter((c) => {
      // Campaign and playbook columns are auto-visible when nodes exist,
      // never user-hidden via the lane checkboxes.
      if (c === "campaign") return buckets.campaign.length > 0 || c === anchorCol;
      if (c === "playbook") return buckets.playbook.length > 0 || c === anchorCol;
      if (!laneVisibility.has(c)) return false;
      return c === "ip" || c === "session" || c === "command"
        || buckets[c].length > 0 || c === anchorCol;
    });

    // 3. Allocate column x positions. Cap per-column width so removing a
    //    lane visibly *narrows* the layout (columns don't balloon to fill
    //    the canvas). Columns live at world x ∈ [0, totalW] — fit()
    //    handles centering the band horizontally in the viewport so
    //    "lane removed" reads as an obvious narrowing of the band.
    const minPad = 28;
    const maxColW = 360;
    const naturalColW = (viewW - minPad * 2) / Math.max(1, visible.length);
    const colW = Math.min(naturalColW, maxColW);
    const colX = {};
    visible.forEach((c, i) => { colX[c] = i * colW + colW / 2; });

    // 4. For each visible column, group items by cluster id and lay them
    //    out vertically.
    //
    //    Within a column, the ordering is:
    //      a. cluster groups in stable insertion order (clusterOrder), each
    //         showing its cluster pill as a "header" above the members.
    //      b. an "unclustered" pseudo-group at the bottom (no header).
    //    Anchor (if it lives in this column) is forced to the top of its
    //    group, otherwise centroid first then by label.
    const lineH = 18;                 // member node row height
    const groupGap = 30;              // vertical gap between cluster groups
    const playbookTransitionGap = 44; // must exceed padTop + pad of playbook bubbles
    const headerH = 26;               // cluster-pill height
    const colHeaderH = 26;            // column title strip at top
    // Extra top space so campaign/cluster bubble labels (drawn inside the
    // bubbles) can't bleed into the column-title strip.
    const startY = colHeaderH + 34;

    // Remember total content height per column so we can centre the
    // shortest columns vertically against the tallest.
    const colHeights = {};
    const layoutByCol = {};

    for (const c of visible) {
      // separate cluster nodes from member nodes
      const items = buckets[c] || [];
      const clusterNodes = [];
      const members = [];
      for (const n of items) {
        if (n.type && n.type.endsWith("_cluster")) clusterNodes.push(n);
        else members.push(n);
      }
      // group members by cluster_id (if any)
      const groups = new Map();
      const unclustered = [];
      for (const m of members) {
        const cid = m.cluster_id;
        if (!cid) { unclustered.push(m); continue; }
        if (!groups.has(cid)) groups.set(cid, []);
        groups.get(cid).push(m);
      }
      // ensure stable cluster order across renders / merges
      if (!clusterOrder.has(c)) clusterOrder.set(c, []);
      const order = clusterOrder.get(c);
      for (const cid of groups.keys()) {
        if (!order.includes(cid)) order.push(cid);
      }
      // also include cluster nodes that have no expanded members (so the
      // pill still renders at the top of its column).
      for (const cn of clusterNodes) {
        const cid = _clusterPillId(cn);
        if (!order.includes(cid)) order.push(cid);
        if (!groups.has(cid)) groups.set(cid, []);
      }

      // sort members within each group
      for (const list of groups.values()) {
        list.sort(_compareMembers);
      }
      unclustered.sort(_compareMembers);

      // pin anchor (if in this column) to the top of its group
      if (anchorId && nodesById.has(anchorId)) {
        const a = nodesById.get(anchorId);
        if (TYPE_TO_COLUMN[a.type] === c) {
          const cid = a.cluster_id;
          if (cid && groups.has(cid)) {
            const list = groups.get(cid);
            const i = list.indexOf(a);
            if (i > 0) { list.splice(i, 1); list.unshift(a); }
          } else if (!cid) {
            const i = unclustered.indexOf(a);
            if (i > 0) { unclustered.splice(i, 1); unclustered.unshift(a); }
          }
        }
      }

      let y = startY;
      let prevPlaybook = undefined; // sentinel; undefined = nothing placed yet
      const placements = []; // {kind:'header'|'member'|'unc-spacer', node, x, y, w, h, group}
      for (const cid of order) {
        if (!groups.has(cid)) continue;
        const list = groups.get(cid);
        // Detect when adjacent cluster groups belong to different
        // playbooks and add breathing room so the per-playbook bubbles
        // don't visually merge.
        const thisPlaybook = list.length > 0 ? (list[0].playbook_id || null) : null;
        if (prevPlaybook !== undefined &&
            thisPlaybook !== prevPlaybook &&
            (thisPlaybook !== null || prevPlaybook !== null)) {
          y += playbookTransitionGap;
        }
        prevPlaybook = thisPlaybook;
        // header (cluster pill)
        const clusterNode = clusterNodes.find((cn) => _clusterPillId(cn) === cid);
        if (clusterNode) {
          clusterNode.x = colX[c];
          clusterNode.y = y + headerH / 2;
          clusterNode.w = Math.min(colW - 28, 180);
          clusterNode.h = headerH;
          placements.push({ kind: "header", node: clusterNode });
          y += headerH + 6;
        } else {
          // synthesized header for cluster_id known only via cluster_id on members
          y += headerH * 0.4; // small breathing room
        }
        // members
        for (const m of list) {
          m.x = colX[c];
          m.y = y + lineH / 2;
          m.w = Math.min(colW - 28, _memberWidth(m));
          m.h = lineH;
          m.group = cid;
          placements.push({ kind: "member", node: m });
          y += lineH + 3;
        }
        y += groupGap - 3;
      }
      // unclustered members at the bottom
      if (unclustered.length > 0) {
        for (const m of unclustered) {
          m.x = colX[c];
          m.y = y + lineH / 2;
          m.w = Math.min(colW - 28, _memberWidth(m));
          m.h = lineH;
          m.group = null;
          placements.push({ kind: "member", node: m });
          y += lineH + 3;
        }
      }

      layoutByCol[c] = { x: colX[c], width: colW, placements, height: y };
      colHeights[c] = y;
    }

    // 5. Vertically centre shorter columns against the tallest one (so
    //    everything sits in roughly the same visual band).
    const maxH = Math.max(0, ...Object.values(colHeights));
    for (const c of visible) {
      const dy = (maxH - colHeights[c]) / 2;
      if (dy <= 1) continue;
      for (const p of layoutByCol[c].placements) {
        p.node.y += dy;
      }
    }

    // 5b. (Removed) Playbook cluster-top alignment used to shift earlier
    // columns down to match the deepest playbook-cluster top across the
    // graph, so a playbook bubble could bridge cleanly across columns. In
    // busy graphs (siblings ≥ 1) the deepest top is often hundreds of
    // pixels down, which left the shallow columns mostly empty and the
    // playbook's cross-column bridge floating mid-canvas. With per-
    // connected-component labels on playbooks, a disconnected playbook
    // reads fine: each visual region is labelled with the playbook name.
    // The natural layout wins on density.

    // 6. Position playbook pill nodes. Playbook pills live in the playbook
    //    column; their Y is the vertical midpoint of their member sessions
    //    so the pill sits at the centre of its bubble region.
    if (visible.includes("playbook") && colX.playbook !== undefined) {
      for (const pb of buckets.playbook) {
        const pbId = pb.playbook_id || pb.id.replace(/^pb:/, "");
        let minY = Infinity, maxY = -Infinity;
        for (const n of nodesById.values()) {
          if (!isFinite(n.y)) continue;
          if (n.playbook_id === pbId) {
            minY = Math.min(minY, n.y - n.h / 2);
            maxY = Math.max(maxY, n.y + n.h / 2);
          }
        }
        pb.x = colX.playbook;
        pb.y = isFinite(minY) ? (minY + maxY) / 2 : viewH / 2;
        pb.w = Math.min(colW - 12, 190);
        pb.h = 26;
      }
    } else {
      for (const pb of buckets.playbook) { pb.x = NaN; pb.y = NaN; }
    }

    // 6b. Position campaign pill nodes (multi-session). Each campaign
    //     anchors at the vertical centre of its sessions; the join is via
    //     the `in_campaign` edge rather than a per-node field.
    if (visible.includes("campaign") && colX.campaign !== undefined) {
      const campMembers = new Map();   // campaign_id -> [session-node-id, ...]
      for (const e of edges) {
        if (e.kind !== "in_campaign") continue;
        const sid = e.source.startsWith("camp:") ? e.target : e.source;
        const cid = e.source.startsWith("camp:") ? e.source : e.target;
        if (!cid.startsWith("camp:")) continue;
        const list = campMembers.get(cid) || [];
        list.push(sid);
        campMembers.set(cid, list);
      }
      for (const camp of buckets.campaign) {
        const mems = campMembers.get(camp.id) || [];
        let minY = Infinity, maxY = -Infinity;
        for (const sid of mems) {
          const n = nodesById.get(sid);
          if (!n || !isFinite(n.y)) continue;
          minY = Math.min(minY, n.y - n.h / 2);
          maxY = Math.max(maxY, n.y + n.h / 2);
        }
        camp.x = colX.campaign;
        camp.y = isFinite(minY) ? (minY + maxY) / 2 : viewH / 2;
        camp.w = Math.min(colW - 12, 200);
        camp.h = 26;
      }
    } else {
      for (const camp of buckets.campaign) { camp.x = NaN; camp.y = NaN; }
    }

    // 7. Cache layout meta for renderer
    _layoutMeta = { visible, colX, colW, colHeaderH, maxH, layoutByCol };
  }

  let _layoutMeta = null;

  function _clusterPillId(clusterNode) {
    // cluster pill id is the cluster_id; ip/session/command members carry
    // the same string in `cluster_id`.
    // graph.py emits cluster pill labels like "ip cluster 4" but the
    // node payload doesn't carry cluster_id. Derive it from the id
    // prefix (e.g. "ipcl:4" -> "4").
    if (clusterNode.cluster_id) return String(clusterNode.cluster_id);
    const id = clusterNode.id || "";
    const idx = id.indexOf(":");
    return idx >= 0 ? id.slice(idx + 1) : id;
  }

  function _compareMembers(a, b) {
    // anchor always wins
    if (a.id === anchorId) return -1;
    if (b.id === anchorId) return 1;
    // outliers last
    const ao = a.is_outlier ? 1 : 0;
    const bo = b.is_outlier ? 1 : 0;
    if (ao !== bo) return ao - bo;
    // higher novelty pulled up (more interesting)
    const an = a.novelty || 0;
    const bn = b.novelty || 0;
    if (an !== bn) return bn - an;
    // stable by label
    return String(a.label || a.id).localeCompare(String(b.label || b.id));
  }

  function _memberWidth(n) {
    // Width grows with size hint so high-volume IPs/sessions are visually
    // taller targets, but clamps so a single fat node doesn't overflow.
    const sz = (typeof n.size === "number" && isFinite(n.size)) ? n.size : null;
    const base = 156;
    if (sz === null) return base;
    return Math.max(base, Math.min(280, base + (sz - 24) * 3));
  }

  // ===================================================================
  // View / pan / zoom
  // ===================================================================
  function _resetView() {
    zoom = 1; panX = 0; panY = 0;
    // After layout, fit content into view.
    fit(0);
  }

  function fit(animMs) {
    if (!_layoutMeta) return;
    const meta = _layoutMeta;
    if (meta.visible.length === 0) return;
    // The column band lives at world x ∈ [0, bandW]. Pad with 30px on
    // each side when sizing the zoom so columns don't kiss the canvas
    // edges. Then position so the band's center matches the viewport's.
    const bandW = meta.visible.length * meta.colW;
    const h = meta.maxH + 80;
    const zx = viewW / (bandW + 60);
    const zy = viewH / h;
    const targetZ = Math.min(2, Math.max(0.3, Math.min(zx, zy)));
    const targetPanX = (viewW - bandW * targetZ) / 2;
    const targetPanY = (viewH - h * targetZ) / 2;
    zoom = targetZ;
    panX = targetPanX;
    panY = targetPanY;
    _scheduleRender();
  }

  function _onWheel(e) {
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const px = e.clientX - rect.left;
    const py = e.clientY - rect.top;
    const wx = (px - panX) / zoom;
    const wy = (py - panY) / zoom;
    const factor = Math.exp(-e.deltaY * 0.001);
    zoom = Math.max(0.2, Math.min(3.5, zoom * factor));
    panX = px - wx * zoom;
    panY = py - wy * zoom;
    _scheduleRender();
  }

  function _onMouseDown(e) {
    if (e.button !== 0) return;
    const t = _hitTest(e);
    if (t && t.kind === "background") {
      const rect = canvas.getBoundingClientRect();
      dragState = {
        x0: e.clientX - rect.left, y0: e.clientY - rect.top,
        panX0: panX, panY0: panY, moved: false,
      };
    }
  }

  function _onMouseMove(e) {
    const rect = canvas.getBoundingClientRect();
    const px = e.clientX - rect.left;
    const py = e.clientY - rect.top;

    if (dragState) {
      const dx = px - dragState.x0;
      const dy = py - dragState.y0;
      if (!dragState.moved && Math.hypot(dx, dy) > 3) dragState.moved = true;
      panX = dragState.panX0 + dx;
      panY = dragState.panY0 + dy;
      _scheduleRender();
      return;
    }

    const t = _hitTest(e);
    let cursor = "default";
    let newHover = null;
    let newHoverBadge = null;
    if (t && t.kind === "node") { newHover = t.node.id; cursor = "pointer"; }
    else if (t && t.kind === "badge") { newHoverBadge = { nodeId: t.node.id, idx: t.idx }; cursor = "pointer"; }
    if (newHover !== hoverId || JSON.stringify(newHoverBadge) !== JSON.stringify(hoverBadge)) {
      hoverId = newHover;
      hoverBadge = newHoverBadge;
      canvas.style.cursor = cursor;
      _scheduleRender();
    } else {
      canvas.style.cursor = cursor;
    }
    _updateHoverTooltip(t, px, py);
  }

  // Render the hover tooltip near the cursor when hovering an interactive
  // element. Content is type-specific: sessions get their playbook + cluster
  // + novelty; IPs get their cluster + playbook-count; campaigns get their
  // size. Hides itself otherwise. Pure DOM — no canvas redraw needed.
  function _updateHoverTooltip(hit, px, py) {
    if (!tooltipEl) return;
    if (!hit || hit.kind === "background") {
      tooltipEl.classList.add("hidden");
      return;
    }
    let n = null;
    if (hit.kind === "node") n = hit.node;
    else if (hit.kind === "badge") n = hit.node;  // host node for the badge
    if (!n) {
      tooltipEl.classList.add("hidden");
      return;
    }
    const html = _tooltipHtml(n);
    if (!html) {
      tooltipEl.classList.add("hidden");
      return;
    }
    tooltipEl.innerHTML = html;
    tooltipEl.classList.remove("hidden");
    // Position with a 12px offset so the cursor doesn't sit on top of the
    // tooltip body. Clamp to the container so it stays on-screen near
    // edges.
    const rect = containerEl.getBoundingClientRect();
    const w = tooltipEl.offsetWidth || 180;
    const h = tooltipEl.offsetHeight || 60;
    let x = px + 12;
    let y = py + 12;
    if (x + w > rect.width)  x = px - w - 12;
    if (y + h > rect.height) y = py - h - 12;
    if (x < 4) x = 4;
    if (y < 4) y = 4;
    tooltipEl.style.left = `${x}px`;
    tooltipEl.style.top  = `${y}px`;
  }

  function _tooltipHtml(n) {
    if (!n) return "";
    const rows = [];
    const head = `<div class="tt-head"><span class="tt-type">${_escapeTT(n.type || "?")}</span> <span class="tt-label">${_escapeTT(n.label || n.id || "")}</span></div>`;
    rows.push(head);
    if (n.type === "session") {
      if (n.playbook_name || n.playbook_id) {
        rows.push(`<div class="tt-row"><span class="tt-k">playbook</span><span class="tt-v">${_escapeTT(n.playbook_name || n.playbook_id)}</span></div>`);
      }
      if (n.cluster_id) {
        rows.push(`<div class="tt-row"><span class="tt-k">cluster</span><span class="tt-v">${_escapeTT(n.cluster_id)}${n.is_outlier ? " (outlier)" : ""}</span></div>`);
      }
      if (typeof n.novelty === "number") {
        rows.push(`<div class="tt-row"><span class="tt-k">novelty</span><span class="tt-v">${n.novelty.toFixed(2)}</span></div>`);
      }
      if (typeof n.size === "number") {
        rows.push(`<div class="tt-row"><span class="tt-k">commands</span><span class="tt-v">${Math.round(n.size)}</span></div>`);
      }
    } else if (n.type === "ip") {
      const npb = _ipPlaybookCount(n.id);
      if (npb > 0) {
        rows.push(`<div class="tt-row"><span class="tt-k">playbooks</span><span class="tt-v">${npb}</span></div>`);
      }
      if (n.cluster_id) {
        rows.push(`<div class="tt-row"><span class="tt-k">actor cluster</span><span class="tt-v">${_escapeTT(n.cluster_id)}${n.is_outlier ? " (outlier)" : ""}</span></div>`);
      }
      if (n.country) rows.push(`<div class="tt-row"><span class="tt-k">country</span><span class="tt-v">${_escapeTT(n.country)}</span></div>`);
      if (n.asn) rows.push(`<div class="tt-row"><span class="tt-k">asn</span><span class="tt-v">AS${_escapeTT(n.asn)}</span></div>`);
    } else if (n.type === "playbook") {
      if (n.playbook_id) {
        rows.push(`<div class="tt-row"><span class="tt-k">id</span><span class="tt-v tt-mono">${_escapeTT(n.playbook_id)}</span></div>`);
      }
    } else if (n.type === "campaign") {
      if (n.campaign_id) {
        rows.push(`<div class="tt-row"><span class="tt-k">id</span><span class="tt-v tt-mono">${_escapeTT(n.campaign_id)}</span></div>`);
      }
      if (n.campaign_kind) rows.push(`<div class="tt-row"><span class="tt-k">kind</span><span class="tt-v">${_escapeTT(n.campaign_kind)}</span></div>`);
      if (typeof n.ip_count === "number") rows.push(`<div class="tt-row"><span class="tt-k">ips</span><span class="tt-v">${n.ip_count}</span></div>`);
      if (typeof n.session_count === "number") rows.push(`<div class="tt-row"><span class="tt-k">sessions</span><span class="tt-v">${n.session_count}</span></div>`);
    } else if (n.type === "command") {
      if (n.intent) rows.push(`<div class="tt-row"><span class="tt-k">intent</span><span class="tt-v">${_escapeTT(n.intent)}</span></div>`);
      if (typeof n.novelty === "number") {
        rows.push(`<div class="tt-row"><span class="tt-k">novelty</span><span class="tt-v">${n.novelty.toFixed(2)}</span></div>`);
      }
    } else if (n.type && n.type.endsWith("_cluster")) {
      if (n.playbook_name) rows.push(`<div class="tt-row"><span class="tt-k">playbook</span><span class="tt-v">${_escapeTT(n.playbook_name)}</span></div>`);
      if (typeof n.member_count === "number") rows.push(`<div class="tt-row"><span class="tt-k">members</span><span class="tt-v">${n.member_count}</span></div>`);
    }
    return rows.length > 1 ? rows.join("") : "";
  }

  function _escapeTT(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function _onMouseUp(e) {
    if (dragState && !dragState.moved) {
      // not a drag; fall through to click handler
    }
    dragState = null;
  }

  function _onMouseLeave() {
    if (hoverId || hoverBadge) {
      hoverId = null;
      hoverBadge = null;
      _scheduleRender();
    }
    if (tooltipEl) tooltipEl.classList.add("hidden");
    dragState = null;
  }

  function _onClick(e) {
    if (dragState && dragState.moved) return;
    const t = _hitTest(e);
    if (!t) return;
    if (t.kind === "background") {
      // Clicking empty space drops the persistent highlight. Grey-outs
      // stay — they're a separate filter the user accumulates on purpose
      // and shouldn't evaporate just because they panned past a node.
      if (pinnedIds.size > 0) {
        pinnedIds.clear();
        _neighborCacheKey = null; _neighborCache = null;
        _scheduleRender();
      }
      return;
    }
    if (t.kind === "badge") {
      _handleBadgeClick(t.node, t.idx);
      return;
    }
    if (t.kind === "node") {
      const id = t.node.id;
      if (e.altKey) {
        // Alt-click: toggle in grey-out set. Inverse of highlight — used
        // to subtract noisy nodes from the visible field. Doesn't open
        // the detail pane; the user isn't asking "what is this", they're
        // asking "hide this and its connections".
        if (greyedIds.has(id)) greyedIds.delete(id);
        else greyedIds.add(id);
        _neighborCacheKey = null; _neighborCache = null;
        _scheduleRender();
        return;
      }
      if (e.shiftKey) {
        // Shift-click: extend the highlight set. Clicking an already-
        // highlighted node removes it (so users can refine the set
        // without starting over).
        if (pinnedIds.has(id)) pinnedIds.delete(id);
        else pinnedIds.add(id);
      } else {
        // Plain click: replace the highlight with just this node. New
        // click on the same node still updates the detail pane below.
        pinnedIds = new Set([id]);
      }
      _neighborCacheKey = null; _neighborCache = null;
      _scheduleRender();
      if (selectHandler) selectHandler(_publicData(t.node));
    }
  }

  function _onDoubleClick(e) {
    const t = _hitTest(e);
    if (!t || t.kind !== "node") return;
    if (expandHandler) expandHandler(_publicData(t.node), t.node.id);
  }

  function _onContextMenu(e) {
    const t = _hitTest(e);
    if (!t || t.kind !== "node") return;
    e.preventDefault();
    if (expandHandler) expandHandler(_publicData(t.node), t.node.id);
  }

  function _handleBadgeClick(parentNode, idx) {
    const b = (parentNode._badges || [])[idx];
    if (!b) return;
    // Some badges (e.g. the "N camps" multi-campaign flag) are informational
    // counters, not pivots — they describe the host node, not a separate IOC.
    if (b.nonPivot) return;
    // Badge click = pivot to that IOC. (Reading details on an ASN/MITRE
    // without leaving the current anchor isn't useful — the badge already
    // says everything we know.)
    if (pivotHandler) pivotHandler({ type: b.type, id: b.id });
  }

  // ===================================================================
  // Hit testing
  // ===================================================================
  function _hitTest(e) {
    const rect = canvas.getBoundingClientRect();
    const px = e.clientX - rect.left;
    const py = e.clientY - rect.top;
    const wx = (px - panX) / zoom;
    const wy = (py - panY) / zoom;
    // Iterate nodes in reverse layout order so top-most badges/nodes win.
    for (const n of nodesById.values()) {
      if (!isFinite(n.x) || !isFinite(n.y)) continue;
      // node body
      const left = n.x - n.w / 2;
      const right = n.x + n.w / 2;
      const top = n.y - n.h / 2;
      const bot = n.y + n.h / 2;
      if (wx >= left && wx <= right && wy >= top && wy <= bot) {
        return { kind: "node", node: n };
      }
      // badges (drawn just to the right of the node)
      if (n._badges && n._badges.length > 0) {
        let bx = right + 4;
        for (let i = 0; i < n._badges.length; i++) {
          const bw = n._badges[i]._w || 18;
          if (wx >= bx && wx <= bx + bw && wy >= top + 2 && wy <= bot - 2) {
            return { kind: "badge", node: n, idx: i };
          }
          bx += bw + 3;
        }
      }
    }
    return { kind: "background" };
  }

  // ===================================================================
  // Rendering
  // ===================================================================
  function _scheduleRender() {
    if (needsRender) return;
    needsRender = true;
    requestAnimationFrame(() => { needsRender = false; _render(); });
  }

  function _render() {
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, viewW, viewH);
    // background already painted by CSS; nothing to draw here.

    // World transform
    ctx.save();
    ctx.translate(panX, panY);
    ctx.scale(zoom, zoom);

    if (_layoutMeta) {
      _drawColumnHeaders();
      _drawBubbles();        // cluster + campaign
      _drawEdges();
      _drawNodes();
    }
    ctx.restore();
  }

  function _drawColumnHeaders() {
    const meta = _layoutMeta;
    ctx.save();
    ctx.font = "600 11px ui-sans-serif,system-ui";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    for (const c of meta.visible) {
      const x = meta.colX[c];
      // column divider
      ctx.strokeStyle = "rgba(155,167,194,0.10)";
      ctx.lineWidth = 1 / zoom;
      ctx.beginPath();
      ctx.moveTo(x - meta.colW / 2 + 8, 6);
      ctx.lineTo(x - meta.colW / 2 + 8, meta.maxH + 30);
      ctx.stroke();
      // title strip
      ctx.fillStyle = "rgba(155,167,194,0.55)";
      ctx.fillText(COL_LABEL[c].toUpperCase(), x, 14);
    }
    ctx.restore();
  }

  // Bubble pads — exposed as constants so the cluster/playbook relationship
  // (playbook always wraps its cluster with a uniform gap) is obvious.
  const CLUSTER_PAD     = { pad: 8,  padTop: 8 };
  const PLAYBOOK_PAD    = { pad: 12, padTop: 28 }; // padTop reserves room for the playbook label tag
  // Extra space placed *outside* a cluster bubble when a playbook has to
  // grow to enclose it. Chosen so the absolute distance from a contained
  // node to the playbook edge is the same whether the playbook wraps a
  // bare node or a cluster bubble: enclosePad = PLAYBOOK_PAD - CLUSTER_PAD.
  const PLAYBOOK_ENCLOSE_GAP = {
    pad:    PLAYBOOK_PAD.pad    - CLUSTER_PAD.pad,    // 4
    padTop: PLAYBOOK_PAD.padTop - CLUSTER_PAD.padTop, // 20
  };

  function _drawBubbles() {
    const clusterGroups  = _buildClusterGroups();
    const playbookGroups = _buildPlaybookGroups();

    // Geometry pass — compute each bubble's per-column rects up front.
    //
    //   1. Clusters are simple: one padded rect per column. A cluster's
    //      members all sit contiguously in one column, so each cluster has
    //      exactly one rect (or zero, if its pill has no expanded members).
    //   2. Playbooks are *fragmented*. A single playbook can span multiple
    //      columns AND have multiple disjoint vertical regions per column
    //      when its tagged clusters/members are separated by unrelated
    //      content. We compute one (col, l, r, t, b) segment per contiguous
    //      band so the bubble never swallows non-playbook content sitting
    //      between two playbook regions.
    for (const g of clusterGroups.values()) {
      g.rects = _bubbleColumnRects(g.members, CLUSTER_PAD);
    }
    for (const g of playbookGroups.values()) {
      g.rects = _playbookSegments(g, clusterGroups);
    }

    // Render pass — clusters first so their inner shape is visible against
    // the playbook tint laid on top. The playbook label tag is drawn last
    // (inside _drawBubble) so it stays readable above everything.
    for (const g of clusterGroups.values()) {
      const realCount = g.members.filter((n) => n !== g.pill).length;
      if (realCount < 1 || g.rects.length === 0) continue;
      const total     = (g.pill && typeof g.pill.member_count === "number") ? g.pill.member_count : null;
      const isPartial = total !== null && realCount < total;
      const state     = _bubbleActivityState(g.members.map((n) => n.id));
      _drawBubble(g.rects, {
        hue: hashHue("cluster:" + g.cid),
        ..._clusterBubbleStyle(state, isPartial),
        dashed: true, dashOn: 3, dashOff: 4,
      });
    }
    // Iterate by playbook_id (stable id, sorted for determinism). The label
    // shows the LLM display name; two playbooks with identical names render
    // as separate bubbles because they have different ids.
    const pbIds = [...playbookGroups.keys()].sort();
    for (const pid of pbIds) {
      const g = playbookGroups.get(pid);
      if (g.rects.length === 0) continue;
      const activityIds = g.members.map((n) => n.id);
      if (g.pill) activityIds.push(g.pill.id);
      const state = _bubbleActivityState(activityIds);
      // Hash the id (not the display name) so identically-named playbooks
      // get distinct hues — visually different where the data is different.
      const hue   = hashHue("pb:" + pid);
      _drawBubble(g.rects, {
        hue,
        labelText: `playbook \xb7 ${g.displayName || pid}`,
        ..._playbookBubbleStyle(state),
        dashed: true,
        dashOn:  5 + (hue % 5),
        dashOff: 2 + (hue % 3),
      });
    }
  }

  // Cluster groups keyed by `${col}|${cid}`. A group holds its pill node (if
  // present) and every member node carrying that cluster_id in that column.
  // The pill is intentionally included in `members` so the cluster bubble's
  // bbox covers it.
  function _buildClusterGroups() {
    const out = new Map();
    for (const n of nodesById.values()) {
      if (!isFinite(n.x)) continue;
      if (n.type && n.type.endsWith("_cluster")) {
        const col = TYPE_TO_COLUMN[n.type];
        const cid = _clusterPillId(n);
        const key = `${col}|${cid}`;
        if (!out.has(key)) out.set(key, { cid, col, members: [], pill: null });
        const g = out.get(key);
        g.pill = n;
        g.members.push(n);
      }
      if (n.group) {
        const col = TYPE_TO_COLUMN[n.type];
        if (!col) continue;
        const key = `${col}|${n.group}`;
        if (!out.has(key)) out.set(key, { cid: n.group, col, members: [], pill: null });
        out.get(key).members.push(n);
      }
    }
    return out;
  }

  // Playbook groups keyed by `playbook_id`. `displayName` is the LLM label.
  // `clusterKeys` records every cluster group whose member-set intersects
  // this playbook (used by the bubble-segments code to wrap them).
  // Multi-session campaigns are a separate concept that does NOT
  // participate in this bubble grouping.
  function _buildPlaybookGroups() {
    const out = new Map();
    const isReal = (v) => v !== null && v !== undefined && (typeof v !== "string" || v.trim() !== "");
    for (const n of nodesById.values()) {
      if (!isFinite(n.x)) continue;
      if (n.type === "playbook") {
        // Playbook pill nodes carry `playbook_id` on their data payload;
        // node id form is `pb:<playbook_id>`.
        const cid = n.playbook_id || n.id.replace(/^pb:/, "");
        if (!isReal(cid)) continue;
        if (!out.has(cid)) out.set(cid, {
          playbookId: cid,
          displayName: n.label || cid,
          members: [], pill: null, clusterKeys: new Set(),
        });
        const g = out.get(cid);
        g.pill = n;
        if (n.label) g.displayName = n.label;
        continue;
      }
      // Skip multi-session campaign pills — they have no bubble grouping;
      // each is a one-off pill in the campaign column connected via
      // in_campaign edges.
      if (n.type === "campaign") continue;
      const pid = n.playbook_id;
      if (!isReal(pid)) continue;
      if (!out.has(pid)) out.set(pid, {
        playbookId: pid,
        displayName: n.playbook_name || pid,
        members: [], pill: null, clusterKeys: new Set(),
      });
      const g = out.get(pid);
      if (n.playbook_name && (!g.displayName || g.displayName === pid)) {
        g.displayName = n.playbook_name;
      }
      g.members.push(n);
      if (n.group) {
        const col = TYPE_TO_COLUMN[n.type];
        if (col) g.clusterKeys.add(`${col}|${n.group}`);
      }
    }
    return out;
  }

  // For one playbook, compute the list of contiguous rectangular regions
  // it occupies, per column. Each playbook-tagged unclustered node
  // contributes its own padded rect; each implicated cluster bubble
  // contributes its rect expanded outward by PLAYBOOK_ENCLOSE_GAP.
  // Intervals in the same column that overlap (or are within
  // SEGMENT_MERGE_GAP of each other) merge into a single segment;
  // otherwise they stay separate, so a playbook with tagged clusters at
  // the top and bottom of a column (with unrelated content between them)
  // renders as two segments instead of one bar swallowing the middle.
  const SEGMENT_MERGE_GAP = 6;
  function _playbookSegments(g, clusterGroups) {
    const intervalsByCol = new Map();
    function add(col, l, r, t, b) {
      if (!intervalsByCol.has(col)) intervalsByCol.set(col, []);
      intervalsByCol.get(col).push({ l, r, t, b });
    }

    for (const n of g.members) {
      if (!isFinite(n.x) || !isFinite(n.y)) continue;
      const c = TYPE_TO_COLUMN[n.type];
      if (!c) continue;
      add(
        c,
        n.x - n.w / 2 - PLAYBOOK_PAD.pad,
        n.x + n.w / 2 + PLAYBOOK_PAD.pad,
        n.y - n.h / 2 - PLAYBOOK_PAD.padTop,
        n.y + n.h / 2 + PLAYBOOK_PAD.pad,
      );
    }
    for (const ckey of g.clusterKeys) {
      const cg = clusterGroups.get(ckey);
      if (!cg || cg.rects.length === 0) continue;
      for (const er of cg.rects) {
        add(
          er.col,
          er.l - PLAYBOOK_ENCLOSE_GAP.pad,
          er.r + PLAYBOOK_ENCLOSE_GAP.pad,
          er.t - PLAYBOOK_ENCLOSE_GAP.padTop,
          er.b + PLAYBOOK_ENCLOSE_GAP.pad,
        );
      }
    }

    const out = [];
    for (const [col, ivs] of intervalsByCol) {
      ivs.sort((a, b) => a.t - b.t);
      let cur = null;
      for (const iv of ivs) {
        if (!cur) { cur = { ...iv }; continue; }
        if (iv.t - cur.b <= SEGMENT_MERGE_GAP) {
          cur.t = Math.min(cur.t, iv.t);
          cur.b = Math.max(cur.b, iv.b);
          cur.l = Math.min(cur.l, iv.l);
          cur.r = Math.max(cur.r, iv.r);
        } else {
          out.push({ col, ...cur });
          cur = { ...iv };
        }
      }
      if (cur) out.push({ col, ...cur });
    }
    // Sort left-to-right by column, then top-to-bottom within a column,
    // so rects[0] is the leftmost-topmost segment (where the label tag sits).
    out.sort((a, b) => {
      const d = COLUMNS.indexOf(a.col) - COLUMNS.indexOf(b.col);
      return d !== 0 ? d : a.t - b.t;
    });
    return out;
  }

  // Returns "active" | "dim" | "neutral" for a bubble given its member node ids.
  //   active  = ≥1 member is in focus reach, or passes the active set filter
  //   dim     = something else is focused/highlighted but not this bubble
  //   neutral = nothing focused or highlighted
  function _bubbleActivityState(nodeIds) {
    const undimmed = _focusUndimmed();
    if (undimmed) {
      for (const id of nodeIds) {
        if (undimmed.has(id)) return "active";
      }
      return "dim";
    }
    if (_setHighlightActive()) {
      for (const id of nodeIds) {
        const n = nodesById.get(id);
        if (n && _passesSetHighlight(n)) return "active";
      }
      return "dim";
    }
    return "neutral";
  }

  function _clusterBubbleStyle(state, isPartial) {
    if (state === "active") return { alpha: isPartial ? 0.13 : 0.20, strokeAlpha: isPartial ? 0.75 : 1.00, strokeWidth: isPartial ? 1.5 : 2.0 };
    if (state === "dim")    return { alpha: isPartial ? 0.03 : 0.04, strokeAlpha: 0.20, strokeWidth: 0.8 };
    /* neutral */           return { alpha: isPartial ? 0.09 : 0.16, strokeAlpha: isPartial ? 0.55 : 0.90, strokeWidth: isPartial ? 1.2 : 1.8 };
  }

  function _playbookBubbleStyle(state) {
    if (state === "active") return { alpha: 0.11, strokeAlpha: 1.00, strokeWidth: 2.2 };
    if (state === "dim")    return { alpha: 0.03, strokeAlpha: 0.22, strokeWidth: 0.9 };
    /* neutral */           return { alpha: 0.07, strokeAlpha: 0.80, strokeWidth: 1.6 };
  }

  // ── Bubble geometry & drawing ─────────────────────────────────────────
  // A "bubble" is a rounded shape that wraps a set of nodes. Because every
  // node sits in a strict swim-lane column, a bubble is just one padded
  // rectangle per column it touches, joined by capsule bridges where adjacent
  // columns overlap vertically. Geometry and drawing are split so a campaign
  // bubble can grow to enclose a cluster bubble *before* either is drawn.

  // Pure: returns `[{col, l, r, t, b}, ...]` sorted left-to-right by column.
  // Each rect is the per-column bounding box of `nodes` expanded by `pad`
  // (and `padTop` on the top edge). Nodes whose layout hasn't been computed
  // are skipped.
  function _bubbleColumnRects(nodes, opts) {
    const pad    = opts.pad;
    const padTop = opts.padTop !== undefined ? opts.padTop : pad;
    const byCol  = new Map();
    for (const n of nodes) {
      if (!isFinite(n.x) || !isFinite(n.y)) continue;
      const c = TYPE_TO_COLUMN[n.type];
      if (!c) continue;
      const cur = byCol.get(c) || { l: Infinity, r: -Infinity, t: Infinity, b: -Infinity };
      cur.l = Math.min(cur.l, n.x - n.w / 2);
      cur.r = Math.max(cur.r, n.x + n.w / 2);
      cur.t = Math.min(cur.t, n.y - n.h / 2);
      cur.b = Math.max(cur.b, n.y + n.h / 2);
      byCol.set(c, cur);
    }
    const out = [];
    for (const [c, box] of byCol) {
      out.push({ col: c, l: box.l - pad, r: box.r + pad, t: box.t - padTop, b: box.b + pad });
    }
    out.sort((a, b) => COLUMNS.indexOf(a.col) - COLUMNS.indexOf(b.col));
    return out;
  }

  // Pure draw: takes pre-computed `rects` (sorted left-to-right, top-to-
  // bottom within a column) and paints them as a single path. Rects in
  // *adjacent* columns whose vertical bands overlap are joined by a capsule
  // bridge; rects in the same column are NOT bridged (a fragmented campaign
  // reads as separate regions, not one bar swallowing what sits between
  // them). When `labelText` is set, one label tag is drawn per *connected
  // component* of the bubble so a campaign with multiple disjoint regions
  // shows its name in every visually-separate piece — never an unnamed slab.
  function _drawBubble(rects, opts) {
    if (!rects || rects.length === 0) return;
    ctx.save();
    ctx.fillStyle   = `hsla(${opts.hue}, 70%, 60%, ${opts.alpha})`;
    ctx.strokeStyle = `hsla(${opts.hue}, 80%, 70%, ${opts.strokeAlpha})`;
    ctx.lineWidth   = (opts.strokeWidth || 1.4) / zoom;
    if (opts.dashed) {
      ctx.setLineDash([(opts.dashOn || 6) / zoom, (opts.dashOff || 4) / zoom]);
    }
    const radius = 10;
    ctx.beginPath();
    for (const r of rects) {
      _roundRectPath(r.l, r.t, r.r - r.l, r.b - r.t, radius);
    }
    // Bridge across adjacent columns where Y-bands overlap. Track which
    // rect-indices end up connected so the label loop below can place one
    // tag per disjoint piece of the bubble.
    const uf = rects.map((_, i) => i);
    const ufFind = (i) => uf[i] === i ? i : uf[i] = ufFind(uf[i]);
    const ufUnion = (i, j) => { const ri = ufFind(i), rj = ufFind(j); if (ri !== rj) uf[ri] = rj; };
    for (let i = 0; i < rects.length; i++) {
      const a    = rects[i];
      const aIdx = COLUMNS.indexOf(a.col);
      for (let j = 0; j < rects.length; j++) {
        if (i === j) continue;
        const b    = rects[j];
        const bIdx = COLUMNS.indexOf(b.col);
        if (bIdx - aIdx !== 1) continue;  // adjacent columns only, left→right
        const yTop = Math.max(a.t, b.t);
        const yBot = Math.min(a.b, b.b);
        if (yBot > yTop) {
          ctx.rect(a.r - 1, yTop, (b.l - a.r) + 2, yBot - yTop);
          ufUnion(i, j);
        }
      }
    }
    ctx.fill("evenodd");
    ctx.stroke();
    ctx.setLineDash([]);

    if (opts.labelText) {
      // One label per connected component, anchored to its leftmost-topmost
      // rect. Picking by (column-index, top-Y) is stable and matches what
      // a reader expects when scanning the bubble.
      const leaders = new Map(); // root -> rect index
      for (let i = 0; i < rects.length; i++) {
        const root = ufFind(i);
        const cur  = leaders.get(root);
        if (cur === undefined) { leaders.set(root, i); continue; }
        const a = rects[cur], b = rects[i];
        const ai = COLUMNS.indexOf(a.col), bi = COLUMNS.indexOf(b.col);
        if (bi < ai || (bi === ai && b.t < a.t)) leaders.set(root, i);
      }
      for (const idx of leaders.values()) {
        _drawBubbleLabel(rects[idx], opts);
      }
    }
    ctx.restore();
  }

  function _drawBubbleLabel(rect, opts) {
    const text   = opts.labelText.toUpperCase();
    ctx.font     = "600 9px ui-sans-serif,system-ui";
    const tagPad = 5;
    const tagH   = 14;
    const tagW   = ctx.measureText(text).width + tagPad * 2;
    const tagX   = rect.l + 6;
    const tagY   = rect.t + 3;
    ctx.fillStyle   = `hsla(${opts.hue}, 50%, 18%, 0.88)`;
    ctx.strokeStyle = `hsla(${opts.hue}, 60%, 55%, 0.70)`;
    ctx.lineWidth   = 0.7 / zoom;
    ctx.setLineDash([]);
    ctx.beginPath();
    _roundRectPath(tagX, tagY, tagW, tagH, 3);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle    = `hsl(${opts.hue}, 75%, 78%)`;
    ctx.textAlign    = "left";
    ctx.textBaseline = "middle";
    ctx.fillText(text, tagX + tagPad, tagY + tagH / 2);
  }

  function _roundRectPath(x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2);
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  function _drawEdges() {
    const focus = _focusSet();
    const undimmed = focus ? _focusUndimmed() : null;
    const greyed = _greyedReach();
    // Skip cluster-membership and campaign-membership edges — bubbles
    // convey both. Skip MITRE/ASN/Country edges — those become badges
    // unless one of their endpoints is the *anchored* node (in which
    // case rendering them as real edges helps the user see the pivot).
    for (const e of edges) {
      if (e.kind === "member_of" || e.kind === "belongs_to" || e.kind === "playbook_of" || e.kind === "in_campaign" || e.kind === "named") continue;
      if (_isBadgeEdge(e) && !_endpointIsRealNode(e)) continue;
      const a = nodesById.get(e.source);
      const b = nodesById.get(e.target);
      if (!a || !b || !isFinite(a.x) || !isFinite(b.x)) continue;

      // An edge is "on path" when both endpoints are inside the
      // pipeline-reach of some focus node. Edges touching only one
      // endpoint (e.g. the boundary between in-reach and out-of-reach)
      // get dimmed so the visible focus chain reads cleanly.
      const focused = undimmed && undimmed.has(a.id) && undimmed.has(b.id);
      // Edge gets dimmed by grey-out only when BOTH endpoints are in the
      // grey reach and neither is being held un-dim by the active focus.
      const greyDim = greyed
        && greyed.has(a.id) && greyed.has(b.id)
        && !(focus && (focus.has(a.id) || focus.has(b.id)));
      const dim = (focus && !focused) || greyDim;
      if (_setHighlightActive() && !_passesSetHighlight(a) && !_passesSetHighlight(b)) continue;

      ctx.save();
      ctx.strokeStyle = focused ? "rgba(125,211,252,0.95)" : (dim ? "rgba(155,167,194,0.06)" : "rgba(155,167,194,0.28)");
      ctx.lineWidth = focused ? 1.6 / zoom : 0.8 / zoom;
      _bezier(a.x + a.w / 2, a.y, b.x - b.w / 2, b.y);
      ctx.stroke();
      ctx.restore();
    }
  }

  function _bezier(x1, y1, x2, y2) {
    const dx = Math.abs(x2 - x1);
    const k = Math.max(40, dx * 0.45);
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.bezierCurveTo(x1 + k, y1, x2 - k, y2, x2, y2);
  }

  function _isBadgeEdge(e) {
    return e.kind === "asn" || e.kind === "country" || e.kind === "ttp";
  }

  function _endpointIsRealNode(e) {
    // A badge-eligible relation is rendered as a real edge when one of the
    // endpoints is the *anchored* node of that kind (i.e. the user
    // explicitly anchored on an ASN or MITRE), or simply when the anchor
    // is the badge-side IOC and we want to see who points at it.
    if (!anchorId) return false;
    return e.source === anchorId || e.target === anchorId;
  }

  // Build the set of cluster pill ids whose members are currently in view.
  // A pill without expanded members is drawn with a slimmer / dashed look
  // to signal "more in here, click to load".
  function _expandedClusterIds() {
    const out = new Set();
    for (const n of nodesById.values()) {
      if (!n.group) continue;
      const col = TYPE_TO_COLUMN[n.type];
      if (!col) continue;
      out.add(`${col}|${n.group}`);
    }
    return out;
  }

  function _drawCampaignPill(n) {
    const focus = _focusSet();
    const undimmed = _focusUndimmed();
    const setActive = _setHighlightActive();
    const setPass = !setActive || _passesSetHighlight(n);
    const focused = focus && focus.has(n.id);
    const greyed = _greyedReach();
    const dim = (focus && !undimmed.has(n.id))
              || (setActive && !setPass)
              || (greyed && greyed.has(n.id) && !(focus && focus.has(n.id)));
    const isAnchor = n.id === anchorId;

    const hue = hashHue("camp:" + n.id.replace(/^camp:/, ""));
    const color = `hsl(${hue},60%,62%)`;
    const left = n.x - n.w / 2;
    const top  = n.y - n.h / 2;
    const label = (n.label || n.id.replace(/^camp:/, ""));

    ctx.save();
    ctx.globalAlpha = dim ? 0.20 : 1;

    // Fill
    ctx.fillStyle = `hsla(${hue},45%,35%,0.22)`;
    ctx.strokeStyle = isAnchor ? "#e2f2ff" : (focused ? `hsl(${hue},70%,75%)` : `hsla(${hue},60%,62%,0.75)`);
    ctx.lineWidth = (isAnchor ? 2.0 : (focused ? 1.6 : 1.2)) / zoom;
    ctx.beginPath();
    _roundRectPath(left, top, n.w, n.h, 5);
    ctx.fill(); ctx.stroke();

    // Left color tab
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(left + 8, n.y, 4, 0, Math.PI * 2);
    ctx.fill();

    // "camp" type chip
    ctx.fillStyle = `hsla(${hue},55%,55%,0.5)`;
    const chipW = 28;
    ctx.beginPath();
    _roundRectPath(left + 15, top + 3, chipW, n.h - 6, 3);
    ctx.fill();
    ctx.font = "600 8px ui-sans-serif,system-ui";
    ctx.fillStyle = `hsl(${hue},80%,82%)`;
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText("CAMP", left + 15 + chipW / 2, n.y);

    // Campaign name
    ctx.font = `600 11px ui-sans-serif,system-ui`;
    ctx.fillStyle = isAnchor ? "#f0f7ff" : (focused ? "#e2efff" : color);
    ctx.textAlign = "left"; ctx.textBaseline = "middle";
    const labelX = left + 15 + chipW + 5;
    const labelMaxW = n.w - (labelX - left) - 6;
    ctx.fillText(_truncateToWidth(label, labelMaxW, ctx), labelX, n.y);

    ctx.restore();
  }

  function _drawNodes() {
    const focus = _focusSet();
    const undimmed = _focusUndimmed();
    const expandedClusters = _expandedClusterIds();
    for (const n of nodesById.values()) {
      if (n.type === "campaign") {
        // Render as a campaign pill node — distinct from cluster pills.
        if (!isFinite(n.x)) continue;
        _drawCampaignPill(n);
        continue;
      }
      if (!isFinite(n.x)) continue;
      // Geo / MITRE nodes are only rendered when they're the anchor (so
      // we keep the geo/mitre columns visible) OR when the user has
      // explicitly anchored on one of them. Otherwise they live as
      // badges on the host nodes.
      if (_isBadgeKind(n.type)) {
        const isAnchor = n.id === anchorId;
        const anchorIsBadgeKind = anchorId && nodesById.has(anchorId) && _isBadgeKind(nodesById.get(anchorId).type);
        if (!isAnchor && !anchorIsBadgeKind) continue;
      }

      const setActive = _setHighlightActive();
      const setPass = !setActive || _passesSetHighlight(n);
      const focused = focus && focus.has(n.id);
      const isAnchor = n.id === anchorId;
      const greyed = _greyedReach();
      const dim = (focus && !undimmed.has(n.id))
                || (setActive && !setPass)
                || (greyed && greyed.has(n.id) && !focused);

      ctx.save();
      ctx.globalAlpha = dim ? 0.20 : 1;
      const isCluster = n.type && n.type.endsWith("_cluster");
      // A cluster pill counts as "collapsed" if no other nodes in its
      // column carry its cluster_id. Visually we keep the pill but skip
      // the surrounding bubble (handled in _drawBubbles) and tone the
      // pill down: dashed border + lower fill alpha.
      let isCollapsedCluster = false;
      if (isCluster) {
        const cid = _clusterPillId(n);
        const col = TYPE_TO_COLUMN[n.type];
        isCollapsedCluster = !expandedClusters.has(`${col}|${cid}`);
      }

      // Body
      const color = TYPE_COLOR[n.type] || "#9aa3b3";
      const left = n.x - n.w / 2;
      const top = n.y - n.h / 2;
      ctx.fillStyle = isCluster
        ? _hexA(color, isCollapsedCluster ? 0.10 : 0.18)
        : _hexA(color, 0.14);
      ctx.strokeStyle = isAnchor ? "#e2f2ff" : (focused ? "#cfe6ff" : _hexA(color, isCollapsedCluster ? 0.55 : 0.7));
      ctx.lineWidth = (isAnchor ? 2.0 : (focused ? 1.6 : 1.0)) / zoom;
      if (isCollapsedCluster && !isAnchor && !focused) {
        ctx.setLineDash([3 / zoom, 3 / zoom]);
      }
      ctx.beginPath();
      _roundRectPath(left, top, n.w, n.h, isCluster ? 6 : 4);
      ctx.fill();
      ctx.stroke();
      if (isCollapsedCluster) ctx.setLineDash([]);
      if (n.is_outlier) {
        ctx.strokeStyle = _hexA("#f87171", 0.85);
        ctx.setLineDash([3 / zoom, 2 / zoom]);
        ctx.lineWidth = 1.2 / zoom;
        ctx.beginPath();
        _roundRectPath(left - 2, top - 2, n.w + 4, n.h + 4, 5);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // Type chip (small color dot at left)
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(left + 7, n.y, 3.5, 0, Math.PI * 2);
      ctx.fill();

      // Label
      const label = _labelFor(n);
      ctx.fillStyle = isAnchor ? "#f0f7ff" : (focused ? "#e2efff" : "#cdd6e3");
      ctx.font = `${isAnchor || isCluster ? "600" : "500"} ${isCluster ? 12 : 11}px ui-sans-serif,system-ui`;
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      const labelX = left + 16;
      const labelMaxW = n.w - 22 - _rightDecorationsWidth(n);
      ctx.fillText(_truncateToWidth(label, labelMaxW, ctx), labelX, n.y);

      // Right-side metric (count / novelty)
      const metric = _rightMetricFor(n);
      if (metric) {
        ctx.fillStyle = "rgba(155,167,194,0.75)";
        ctx.font = "500 10px ui-mono,SFMono-Regular,Menlo,Consolas,monospace";
        ctx.textAlign = "right";
        ctx.fillText(metric, left + n.w - 6, n.y);
      }

      ctx.restore();

      // Badges
      _drawBadges(n);
    }
  }

  function _drawBadges(n) {
    if (_isBadgeKind(n.type)) return; // don't badge badge-anchored nodes
    const badges = _badgesFor(n);
    n._badges = badges;
    if (!badges || badges.length === 0) return;
    const left = n.x - n.w / 2;
    const right = n.x + n.w / 2;
    let bx = right + 4;
    const by = n.y;
    ctx.save();
    ctx.font = "600 9px ui-sans-serif,system-ui";
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    for (let i = 0; i < badges.length; i++) {
      const b = badges[i];
      const w = ctx.measureText(b.label).width + 10;
      b._w = w;
      const hovered = hoverBadge && hoverBadge.nodeId === n.id && hoverBadge.idx === i;
      const color = TYPE_COLOR[b.type] || "#94a3b8";
      ctx.fillStyle = hovered ? _hexA(color, 0.35) : _hexA(color, 0.18);
      ctx.strokeStyle = _hexA(color, 0.7);
      ctx.lineWidth = (hovered ? 1.2 : 0.8) / zoom;
      ctx.beginPath();
      _roundRectPath(bx, by - n.h / 2 + 2, w, n.h - 4, 3);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = hovered ? "#f0f7ff" : "#cdd6e3";
      ctx.fillText(b.label, bx + 5, by);
      bx += w + 3;
    }
    ctx.restore();
  }

  function _badgesFor(n) {
    const out = [];
    if (n.type === "ip") {
      // Multi-playbook flag: count distinct playbook neighbours reachable
      // via this IP's sessions (IP -> session -> playbook), pulled from
      // the in-memory edge graph. Only shown when >1 — a single-playbook
      // IP is the common case and adding "1" to every IP would be noise.
      const npb = _ipPlaybookCount(n.id);
      if (npb > 1) {
        out.push({
          type:   "playbook",
          id:     n.id,                // not pivotable on its own — informational counter
          prefix: "pb",
          label:  `${npb} pbks`,
          nonPivot: true,
        });
      }
      if (n.asn) out.push({ type: "asn", id: String(n.asn), prefix: "asn", label: `AS${n.asn}` });
      if (n.country) out.push({ type: "country", id: String(n.country), prefix: "cc", label: String(n.country) });
    }
    if (n.type === "command") {
      const tt = n.mitre_techniques || [];
      const ta = n.mitre_tactics || [];
      for (const t of tt) {
        out.push({ type: "mitre_technique", id: t, prefix: "tt", label: t });
      }
      for (const t of ta) {
        out.push({ type: "mitre_tactic", id: t, prefix: "ta", label: t });
      }
    }
    // truncate to avoid blowing past row height
    return out.slice(0, 4);
  }

  // For an IP node id, count the distinct `playbook` neighbours reachable
  // via the IP -> session -> playbook chain through current edges. Cached
  // per render via the edges array's identity check so we don't rebuild
  // the adjacency on every node draw.
  let _ipPbCountCache = { edgesRef: null, byIp: new Map() };
  function _ipPlaybookCount(ipId) {
    if (_ipPbCountCache.edgesRef !== edges) {
      const adj = new Map();           // session_id -> Set<playbook-id>
      const ipSessions = new Map();    // ip_id -> Set<session_id>
      for (const e of edges) {
        if (e.kind === "playbook_of") {
          if (!adj.has(e.source)) adj.set(e.source, new Set());
          adj.get(e.source).add(e.target);
        } else if (e.kind === "saw") {
          if (!ipSessions.has(e.source)) ipSessions.set(e.source, new Set());
          ipSessions.get(e.source).add(e.target);
        }
      }
      const byIp = new Map();
      for (const [ip, sids] of ipSessions) {
        const pbs = new Set();
        for (const sid of sids) {
          const cs = adj.get(sid);
          if (!cs) continue;
          for (const c of cs) pbs.add(c);
        }
        byIp.set(ip, pbs.size);
      }
      _ipPbCountCache = { edgesRef: edges, byIp };
    }
    return _ipPbCountCache.byIp.get(ipId) || 0;
  }

  function _isBadgeKind(t) {
    return t === "asn" || t === "country" || t === "mitre_technique" || t === "mitre_tactic";
  }

  function _rightDecorationsWidth(n) {
    return _rightMetricFor(n) ? 32 : 0;
  }

  function _rightMetricFor(n) {
    if (n.type && n.type.endsWith("_cluster")) {
      const c = n.member_count;
      return c ? `n=${c}` : null;
    }
    // Prefer the most useful metric per kind. Keep it short.
    if (n.type === "ip") {
      if (typeof n.size === "number") return null;
    }
    if (n.type === "session") return null;
    if (n.type === "command") {
      if (typeof n.novelty === "number") {
        return `nov ${(n.novelty).toFixed(2)}`;
      }
    }
    return null;
  }

  function _labelFor(n) {
    if (n.type && n.type.endsWith("_cluster")) {
      // "ip cluster 4" -> "ipcl 4"; tighter for the pill
      return (n.label || "").replace(" cluster ", "cl ").replace(/ +/g, " ");
    }
    return n.label || n.id;
  }

  function _truncateToWidth(s, maxW, c) {
    s = String(s || "");
    if (maxW <= 0) return "";
    if (c.measureText(s).width <= maxW) return s;
    let lo = 0, hi = s.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (c.measureText(s.slice(0, mid) + "…").width <= maxW) lo = mid + 1;
      else hi = mid;
    }
    return s.slice(0, Math.max(0, lo - 1)) + "…";
  }

  function _hexA(hex, a) {
    let h = hex.replace("#", "");
    if (h.length === 3) h = h.split("").map((c) => c + c).join("");
    const r = parseInt(h.slice(0, 2), 16);
    const g = parseInt(h.slice(2, 4), 16);
    const b = parseInt(h.slice(4, 6), 16);
    return `rgba(${r},${g},${b},${a})`;
  }

  // Focus = union of click-pinned ids plus the current hover (if any).
  // Returns null when nothing is focused so callers can skip the dim path.
  function _focusSet() {
    if (pinnedIds.size === 0 && !hoverId) return null;
    if (pinnedIds.size === 0) return new Set([hoverId]);
    if (!hoverId || pinnedIds.has(hoverId)) return pinnedIds;
    const s = new Set(pinnedIds);
    s.add(hoverId);
    return s;
  }

  // Cache: node ids that should remain undimmed = focus ids themselves
  // plus everything reachable along pipeline edges within FOCUS_REACH
  // hops, WITHOUT bouncing back into the focus's own column. Two hops
  // is enough to trace the full IP→session→command chain from any
  // starting point. The "don't bounce back to my own column" rule keeps
  // a session click from fanning out to other sessions that share an IP
  // or a command — matching the user's expectation that the dim-focus
  // reach mirrors what a siblings=0 view of just this IOC would show.
  //
  // Pipeline edges are everything except cluster-membership and badge
  // edges, so walking never crosses into cluster siblings (those are
  // only reachable via the pill, which connects via "member_of").
  const FOCUS_REACH = 2;
  const PIPELINE_COL = { ip: 1, session: 2, command: 3 };
  let _neighborCacheKey = null;
  let _neighborCache = null;
  function _focusUndimmed() {
    const focus = _focusSet();
    if (!focus) return null;
    const key = Array.from(focus).sort().join(",");
    if (_neighborCacheKey === key && _neighborCache) return _neighborCache;
    const adj = new Map();
    for (const e of edges) {
      if (!_isPipelineEdge(e)) continue;
      if (!adj.has(e.source)) adj.set(e.source, new Set());
      if (!adj.has(e.target)) adj.set(e.target, new Set());
      adj.get(e.source).add(e.target);
      adj.get(e.target).add(e.source);
    }
    const u = new Set(focus);
    // BFS per focus node so the "don't re-enter my column" rule is
    // scoped to each starting point — pinning both an IP and a command
    // still gives each pin its own full directional reach.
    for (const start of focus) {
      const startNode = nodesById.get(start);
      const startCol = startNode ? PIPELINE_COL[startNode.type] : undefined;
      let frontier = new Set([start]);
      for (let d = 0; d < FOCUS_REACH; d++) {
        const next = new Set();
        for (const id of frontier) {
          const ns = adj.get(id);
          if (!ns) continue;
          for (const nb of ns) {
            if (u.has(nb)) continue;
            if (startCol !== undefined) {
              const nbNode = nodesById.get(nb);
              if (nbNode && PIPELINE_COL[nbNode.type] === startCol) continue;
            }
            u.add(nb);
            next.add(nb);
          }
        }
        if (next.size === 0) break;
        frontier = next;
      }
    }
    // Campaign pills and cluster pills have no pipeline edges (belongs_to /
    // member_of are excluded), so BFS alone gives them zero reach beyond
    // themselves. Extend the undimmed set using set membership so clicking
    // a pill highlights its members the same way the sidecar filter does.
    for (const fid of focus) {
      const fn = nodesById.get(fid);
      if (!fn) continue;
      const isPill = fn.type === "campaign" || (fn.type && fn.type.endsWith("_cluster"));
      if (!isPill) continue;
      const pillSets = getSetsForNode(fn);
      if (pillSets.size === 0) continue;
      for (const n of nodesById.values()) {
        const ns = getSetsForNode(n);
        for (const s of pillSets) {
          if (ns.has(s)) { u.add(n.id); break; }
        }
      }
    }
    _neighborCacheKey = key;
    _neighborCache = u;
    return u;
  }

  // Grey-out reach: greyedIds plus the same 2-hop, no-self-column-bounce
  // pipeline walk used for focus. Mirrors _focusUndimmed so "grey out" is
  // visually the exact inverse of "highlight" on the same anchor.
  let _greyedCacheKey = null;
  let _greyedCache = null;
  function _greyedReach() {
    if (greyedIds.size === 0) return null;
    const key = Array.from(greyedIds).sort().join(",");
    if (_greyedCacheKey === key && _greyedCache) return _greyedCache;
    const adj = new Map();
    for (const e of edges) {
      if (!_isPipelineEdge(e)) continue;
      if (!adj.has(e.source)) adj.set(e.source, new Set());
      if (!adj.has(e.target)) adj.set(e.target, new Set());
      adj.get(e.source).add(e.target);
      adj.get(e.target).add(e.source);
    }
    const u = new Set(greyedIds);
    for (const start of greyedIds) {
      const startNode = nodesById.get(start);
      const startCol = startNode ? PIPELINE_COL[startNode.type] : undefined;
      let frontier = new Set([start]);
      for (let d = 0; d < FOCUS_REACH; d++) {
        const next = new Set();
        for (const id of frontier) {
          const ns = adj.get(id);
          if (!ns) continue;
          for (const nb of ns) {
            if (u.has(nb)) continue;
            if (startCol !== undefined) {
              const nbNode = nodesById.get(nb);
              if (nbNode && PIPELINE_COL[nbNode.type] === startCol) continue;
            }
            u.add(nb);
            next.add(nb);
          }
        }
        if (next.size === 0) break;
        frontier = next;
      }
    }
    // Extend pill greys via set membership, matching _focusUndimmed.
    for (const gid of greyedIds) {
      const fn = nodesById.get(gid);
      if (!fn) continue;
      const isPill = fn.type === "campaign" || (fn.type && fn.type.endsWith("_cluster"));
      if (!isPill) continue;
      const pillSets = getSetsForNode(fn);
      if (pillSets.size === 0) continue;
      for (const n of nodesById.values()) {
        const ns = getSetsForNode(n);
        for (const s of pillSets) {
          if (ns.has(s)) { u.add(n.id); break; }
        }
      }
    }
    _greyedCacheKey = key;
    _greyedCache = u;
    return u;
  }

  function _isPipelineEdge(e) {
    if (e.kind === "member_of" || e.kind === "belongs_to" || e.kind === "playbook_of" || e.kind === "in_campaign" || e.kind === "named") return false;
    if (_isBadgeEdge(e)) return false;
    return true;
  }

  // ===================================================================
  // Sets / sidecar
  // ===================================================================
  // A "set" is an identifier the sidecar lets the user filter by.
  // Membership is derived from node metadata: cluster_id, campaign(_name),
  // asn, country, and the (multi-valued) mitre_techniques/mitre_tactics.
  function getSets() {
    const sets = new Map();   // setId -> {id, kind, label, count}
    const nodeSets = new Map(); // nodeId -> Set(setId)

    function add(node, setId, kind, label) {
      if (!setId) return;
      if (!sets.has(setId)) sets.set(setId, { id: setId, kind, label, count: 0 });
      const s = sets.get(setId);
      if (!nodeSets.has(node.id)) nodeSets.set(node.id, new Set());
      if (!nodeSets.get(node.id).has(setId)) {
        s.count++;
        nodeSets.get(node.id).add(setId);
      }
    }
    for (const n of nodesById.values()) {
      // Skip pill nodes — they're not data points, they're handles.
      if (n.type === "campaign" || n.type === "playbook") continue;
      const col = TYPE_TO_COLUMN[n.type];
      if (n.cluster_id) {
        const kind = col + "_cluster";
        add(n, `${kind}:${n.cluster_id}`, kind, `${col}cl ${n.cluster_id}`);
      }
      // Playbook set (was "campaign" pre-redefinition) keyed by playbook_id.
      const pb = n.playbook_id;
      if (pb) add(n, `playbook:${pb}`, "playbook", n.playbook_name || pb);
      if (n.asn) add(n, `asn:${n.asn}`, "asn", `AS${n.asn}`);
      if (n.country) add(n, `country:${n.country}`, "country", String(n.country));
      for (const t of (n.mitre_techniques || [])) add(n, `mitre_technique:${t}`, "mitre_technique", t);
      for (const t of (n.mitre_tactics || [])) add(n, `mitre_tactic:${t}`, "mitre_tactic", t);
    }

    // Intersections: pairwise only (matrix scales O(n^2); we keep only
    // ones with non-zero count to keep the sidecar useful).
    const setList = Array.from(sets.values());
    const intersections = []; // {a, b, count}
    for (let i = 0; i < setList.length; i++) {
      for (let j = i + 1; j < setList.length; j++) {
        let cnt = 0;
        for (const ns of nodeSets.values()) {
          if (ns.has(setList[i].id) && ns.has(setList[j].id)) cnt++;
        }
        if (cnt > 0) intersections.push({ a: setList[i].id, b: setList[j].id, count: cnt });
      }
    }

    return { sets: setList, nodeSets, intersections };
  }

  function highlightSets(setIds) {
    highlightSetIds = setIds && setIds.length ? new Set(setIds) : null;
    highlightIntersectionIds = null;
    _scheduleRender();
  }

  function highlightIntersection(setIds) {
    highlightIntersectionIds = setIds && setIds.length ? new Set(setIds) : null;
    highlightSetIds = null;
    _scheduleRender();
  }

  function _setHighlightActive() {
    return !!(highlightSetIds || highlightIntersectionIds);
  }

  function _passesSetHighlight(node) {
    const ns = getSetsForNode(node);
    if (highlightIntersectionIds) {
      for (const sid of highlightIntersectionIds) {
        if (!ns.has(sid)) return false;
      }
      return true;
    }
    if (highlightSetIds) {
      for (const sid of highlightSetIds) {
        if (ns.has(sid)) return true;
      }
      return false;
    }
    return true;
  }

  function getSetsForNode(n) {
    const out = new Set();
    if (!n) return out;
    if (n.type === "playbook") {
      // The playbook pill node passes its own playbook set filter.
      const pb = n.playbook_id || n.id.replace(/^pb:/, "");
      out.add(`playbook:${pb}`);
      return out;
    }
    if (n.type === "campaign") {
      // The (new) campaign pill node passes its own campaign set filter.
      const cid = n.campaign_id || n.id.replace(/^camp:/, "");
      out.add(`campaign:${cid}`);
      return out;
    }
    const col = TYPE_TO_COLUMN[n.type];
    if (n.cluster_id) out.add(`${col}_cluster:${n.cluster_id}`);
    if (n.playbook_id) out.add(`playbook:${n.playbook_id}`);
    if (n.asn) out.add(`asn:${n.asn}`);
    if (n.country) out.add(`country:${n.country}`);
    for (const t of (n.mitre_techniques || [])) out.add(`mitre_technique:${t}`);
    for (const t of (n.mitre_tactics || [])) out.add(`mitre_tactic:${t}`);
    return out;
  }

  // ===================================================================
  // Public surface
  // ===================================================================
  function onSelect(fn) { selectHandler = fn; }
  function onExpand(fn) { expandHandler = fn; }
  function onPivot(fn) { pivotHandler = fn; }
  function onDataChange(fn) { dataChangeHandler = fn; }

  function _publicData(n) {
    const { x, y, w, h, group, _badges, ...rest } = n;
    return Object.assign({}, rest, { id: n.id });
  }

  window.Graph = {
    init, replace, merge, setAnchor, hasNode, removeNodes, setLaneVisibility,
    onSelect, onExpand, onPivot, onDataChange,
    fit: () => fit(300),
    getSets, highlightSets, highlightIntersection, allNodes,
    getPinned, setPinned, nodeScreenPos, getFocusReach,
  };
})();
