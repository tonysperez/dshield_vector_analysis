/* Timeline view — Canvas2D swimlane renderer.
 *
 * Pan/zoom model
 *   Regular scroll (trackpad or mouse wheel) = pan left/right.
 *   Ctrl/Cmd + scroll = zoom in/out.
 *   Drag on main canvas = pan.
 *   Drag on minimap = jump to that time position.
 *
 * Zoom/pan bounds
 *   Minimum zoom = fit entire dataset in the available width (cannot zoom
 *   out further than "everything in view").
 *   panX is clamped so the timeline never scrolls entirely off-screen.
 *
 * Grouping (Y-axis)
 *   groupBy = { playbook, cluster, ip } booleans, evaluated in that order.
 *   The active levels form the lane hierarchy; the deepest active level is
 *   the one that carries session bars. Parent levels render as compact
 *   header rows.
 *
 * Minimap
 *   A narrow strip below the main canvas shows the complete timeline and
 *   a highlight box for the current viewport. Dragging on the minimap pans
 *   the main view.
 */
window.Timeline = (function () {
  "use strict";

  // ── constants ────────────────────────────────────────────────────────────

  const LABEL_W    = 170;    // left label column width
  const AXIS_H     = 36;     // time-tick strip at top of main canvas
  const LANE_H     = 74;     // leaf lane height (where bars are drawn)
  const HDR_H      = 22;     // group header row height
  const BAR_W      = 10;     // session bar fixed width
  const MIN_H      = 6;      // bar height for 0 commands
  const MAX_H      = 54;     // bar height cap
  const EXPAND_H   = 150;    // inline command list height
  const MM_H       = 52;     // minimap height

  const MAX_ZOOM   = 2000;   // max ms→px ratio (~1px per 0.5 ms)

  const INTENT_COLOR = {
    reconnaissance: "#4ade80",
    execution:      "#f87171",
    persistence:    "#fb923c",
    exfiltration:   "#facc15",
    benign:         "#64748b",
    unknown:        "#7c8ba1",
  };

  function intentColor(s) {
    return INTENT_COLOR[(s || "").toLowerCase()] || INTENT_COLOR.unknown;
  }
  function hexA(color, a) {
    // works for both rgb(...) and hsl(...) strings, falls back to safe rgba
    const m = /^#?([0-9a-f]{6})$/i.exec(color);
    if (m) {
      const r = parseInt(m[1].slice(0, 2), 16);
      const g = parseInt(m[1].slice(2, 4), 16);
      const b = parseInt(m[1].slice(4, 6), 16);
      return `rgba(${r},${g},${b},${a})`;
    }
    return color;
  }
  // Deterministic color per playbook. Hash the stable `playbook_id` (not the
  // display name) so identically-named playbooks still get distinct hues.
  function playbookColor(playbookId) {
    if (!playbookId) return null;
    const s = String(playbookId);
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return `hsl(${h % 360},45%,55%)`;
  }

  // ── state ────────────────────────────────────────────────────────────────

  let canvas = null, ctx = null;
  let mmCanvas = null, mmCtx = null;

  let _data = null;
  let _tMin = 0, _tMax = 1;
  let _lanes = [];    // flat list of { type, key, label, depth, isLeaf, sessions[], y, h, expanded }

  let panX  = 0;
  let zoom  = 1.0;
  let _raf  = null;

  let drag        = null;   // {x0, panX0}
  let mmDrag      = false;
  let hoverHit    = null;   // {session, lane} or null
  let expandedMap = new Map(); // session.id → commands[]

  let _pivotHandler = null;

  let _groupBy = { playbook: false, cluster: true, ip: false };

  // ── public API ───────────────────────────────────────────────────────────

  function init(mainEl, minimapEl) {
    canvas   = mainEl;
    mmCanvas = minimapEl;
    ctx    = canvas.getContext("2d");
    mmCtx  = mmCanvas ? mmCanvas.getContext("2d") : null;

    canvas.addEventListener("mousemove",   _onMouseMove);
    canvas.addEventListener("mouseleave",  _onMouseLeave);
    canvas.addEventListener("mousedown",   _onMouseDown);
    canvas.addEventListener("mouseup",     _onMouseUp);
    canvas.addEventListener("click",       _onClick);
    canvas.addEventListener("dblclick",    _onDblClick);
    canvas.addEventListener("wheel",       _onWheel, { passive: false });

    if (mmCanvas) {
      mmCanvas.addEventListener("mousedown",  _onMmMouseDown);
      mmCanvas.addEventListener("mousemove",  _onMmMouseMove);
      mmCanvas.addEventListener("mouseup",    () => { mmDrag = false; });
      mmCanvas.addEventListener("mouseleave", () => { mmDrag = false; });
    }

    const ro = new ResizeObserver(_onResize);
    ro.observe(canvas.parentElement);
    _onResize();
  }

  function onPivot(fn) { _pivotHandler = fn; }

  function load(data) {
    _data = data;
    expandedMap.clear();
    hoverHit = null;
    _buildLanes();
    fit();
  }

  function clear() {
    _data = null;
    _lanes = [];
    expandedMap.clear();
    hoverHit = null;
    _scheduleRender();
    _scheduleMinimapRender();
  }

  function fit() {
    if (!_data || !_data.sessions.length || !canvas) return;
    const tr = _data.time_range;
    _tMin = tr ? new Date(tr.start).getTime() : 0;
    _tMax = tr ? new Date(tr.end).getTime()   : Date.now();
    if (_tMax <= _tMin) _tMax = _tMin + 60000;

    const dpr = window.devicePixelRatio || 1;
    const W = canvas.width / dpr - LABEL_W;
    const H = canvas.height / dpr;
    if (W <= 0) return;

    zoom = Math.max(W / (_tMax - _tMin), 1e-9);
    panX = 0;
    _scheduleRender();
    _scheduleMinimapRender();
  }

  function setGroupBy(options) {
    _groupBy = { ...options };
    if (_data) {
      _buildLanes();
      _scheduleRender();
      _scheduleMinimapRender();
    }
  }

  // ── lanes ─────────────────────────────────────────────────────────────────

  function _activeLevels() {
    const all = ["playbook", "cluster", "ip"];
    return all.filter(k => _groupBy[k]);
  }

  // Grouping key for a session at a given level.
  // - playbook: stable `playbook_id` (two playbooks can share a display name).
  // - cluster:  cluster.id (run-scoped, distinct).
  // - ip:       source IP.
  function _sessionField(level, session) {
    if (level === "playbook") return session.playbook_id || null;
    if (level === "cluster")  return session.cluster_id || null;
    if (level === "ip")       return session.src_ip || null;
    return null;
  }

  // Human-facing label for a group key. For playbooks we look up the display
  // name from any session in the group (queries.py emits both id + name).
  function _levelLabel(level, key, samples) {
    if (!key || key === "none") {
      if (level === "playbook") return "No Playbook";
      if (level === "cluster")  return "No Cluster";
      if (level === "ip")       return "Unknown IP";
    }
    if (level === "playbook") {
      const named = samples && samples.find(s => s.playbook_name);
      return (named && named.playbook_name) || key;
    }
    return key;
  }

  function _buildLanesRecursive(sessions, levels, depth) {
    const [level, ...rest] = levels;
    const isLeaf = rest.length === 0;

    // Group sessions by this level's field
    const groups = new Map();
    for (const s of sessions) {
      const key = _sessionField(level, s) || "__none__";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(s);
    }

    // Sort: named groups first, "none" last; within named sort by count desc
    const sorted = [...groups.entries()].sort(([ak, av], [bk, bv]) => {
      if (ak === "__none__" && bk !== "__none__") return 1;
      if (bk === "__none__" && ak !== "__none__") return -1;
      return bv.length - av.length;
    });

    const flat = [];
    for (const [key, subs] of sorted) {
      const label = _levelLabel(level, key === "__none__" ? null : key, subs);
      flat.push({
        type: level,
        key: key === "__none__" ? null : key,
        label,
        depth,
        isLeaf,
        sessions: subs,
        expanded: null,
        y: 0,
        h: isLeaf ? LANE_H : HDR_H,
      });
      if (!isLeaf) {
        flat.push(..._buildLanesRecursive(subs, rest, depth + 1));
      }
    }
    return flat;
  }

  function _buildLanes() {
    if (!_data || !_data.sessions.length) { _lanes = []; return; }

    const levels = _activeLevels();
    if (levels.length === 0) {
      // No grouping: one lane with all sessions
      _lanes = [{
        type: "all", key: null, label: "All Sessions",
        depth: 0, isLeaf: true, sessions: _data.sessions,
        expanded: null, y: AXIS_H, h: LANE_H,
      }];
    } else {
      _lanes = _buildLanesRecursive(_data.sessions, levels, 0);
    }
    _recomputeLaneY();
  }

  function _recomputeLaneY() {
    let y = AXIS_H;
    for (const lane of _lanes) {
      lane.y = y;
      // Expand the lane as soon as lane.expanded is set — even before the
      // command list has arrived — so the user gets immediate visual feedback.
      const extraH = lane.isLeaf && lane.expanded ? EXPAND_H : 0;
      lane.h = (lane.isLeaf ? LANE_H : HDR_H) + extraH;
      y += lane.h + 1;
    }
  }

  // ── coordinate helpers ────────────────────────────────────────────────────

  function _minZoom() {
    if (!canvas) return 1e-9;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.width / dpr - LABEL_W;
    const span = _tMax - _tMin;
    return span > 0 ? W / span : 1e-9;
  }

  function _clampZoom(z) {
    return Math.max(_minZoom(), Math.min(MAX_ZOOM, z));
  }

  function _clampPan(p) {
    if (!canvas) return p;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.width / dpr - LABEL_W;
    const timelineW = (_tMax - _tMin) * zoom;
    // Right bound: don't push timeline start past the right edge of the view
    const maxP = W * 0.15;
    // Left bound: don't push timeline end past the left edge of the view
    const minP = -(timelineW - W * 0.85);
    return Math.max(minP, Math.min(maxP, p));
  }

  function _timeToX(t) {
    return LABEL_W + (t - _tMin) * zoom + panX;
  }

  function _xToTime(x) {
    return _tMin + (x - LABEL_W - panX) / zoom;
  }

  function _barH(cmd) {
    const n = Math.max(0, cmd || 0);
    return n === 0 ? MIN_H : Math.min(MAX_H, MIN_H + Math.log1p(n) * 12);
  }

  function _barRect(s, lane) {
    const t = s.start ? new Date(s.start).getTime() : _tMin;
    const bh = _barH(s.command_count);
    const midY = lane.y + LANE_H / 2;
    return { x: _timeToX(t) - BAR_W / 2, y: midY - bh, w: BAR_W, h: bh };
  }

  function _hitTest(mx, my) {
    for (const lane of _lanes) {
      if (!lane.isLeaf) continue;
      if (my < lane.y || my > lane.y + lane.h) continue;
      for (const s of lane.sessions) {
        const r = _barRect(s, lane);
        if (mx >= r.x - 3 && mx <= r.x + r.w + 3 && my >= r.y - 3 && my <= r.y + r.h + 2)
          return { session: s, lane };
      }
    }
    return null;
  }

  // ── render ────────────────────────────────────────────────────────────────

  function _scheduleRender() {
    if (_raf) cancelAnimationFrame(_raf);
    _raf = requestAnimationFrame(_render);
  }

  let _mmRaf = null;
  function _scheduleMinimapRender() {
    if (_mmRaf) cancelAnimationFrame(_mmRaf);
    _mmRaf = requestAnimationFrame(_renderMinimap);
  }

  function _render() {
    _raf = null;
    if (!canvas || !ctx) return;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.width / dpr;
    const H = canvas.height / dpr;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (!_data || !_lanes.length) {
      _drawEmpty(W, H);
      return;
    }

    ctx.save();
    ctx.scale(dpr, dpr);
    _drawAxisBg(W);
    _drawLanesBg(W, H);
    _drawGridLines(W, H);
    _drawLanes(W);
    _drawAxis(W);
    _drawLabels();
    if (hoverHit) _drawTooltip(hoverHit, W, H);
    ctx.restore();
  }

  function _drawEmpty(W, H) {
    const dpr = window.devicePixelRatio || 1;
    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.fillStyle = "#0c1018";
    ctx.fillRect(0, 0, W, H);
    ctx.fillStyle = "#2a3148";
    ctx.font = "13px ui-sans-serif,system-ui,sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("Search an IP, session cluster, or playbook to load the timeline.", W / 2, H / 2);
    ctx.restore();
  }

  function _drawAxisBg(W) {
    ctx.fillStyle = "#0d1120";
    ctx.fillRect(LABEL_W, 0, W - LABEL_W, AXIS_H);
    ctx.fillStyle = "#0b0f1a";
    ctx.fillRect(0, 0, LABEL_W, AXIS_H);
  }

  function _drawLanesBg(W, H) {
    ctx.fillStyle = "#0b0f1a";
    ctx.fillRect(0, AXIS_H, LABEL_W, H - AXIS_H);

    for (let i = 0; i < _lanes.length; i++) {
      const lane = _lanes[i];
      if (!lane.isLeaf) {
        // Header row: slightly distinct background
        ctx.fillStyle = "rgba(255,255,255,0.035)";
      } else {
        ctx.fillStyle = i % 2 === 0 ? "rgba(255,255,255,0.01)" : "#00000000";
      }
      ctx.fillRect(LABEL_W, lane.y, W - LABEL_W, lane.h);
    }
  }

  function _drawGridLines(W, H) {
    if (_tMax <= _tMin) return;
    const span = _tMax - _tMin;
    const avail = W - LABEL_W;
    const idealCount = Math.max(3, Math.floor(avail / 100));
    const rawInterval = span / idealCount;
    const NICE = [
      1000,5000,10000,30000,
      60000,300000,600000,1800000,
      3600000,6*3600000,12*3600000,
      86400000,7*86400000,30*86400000,
    ];
    const interval = NICE.find(i => i >= rawInterval) || NICE[NICE.length - 1];
    const first = Math.ceil(_tMin / interval) * interval;

    ctx.strokeStyle = "#161c2e";
    ctx.lineWidth = 1;
    for (let t = first; t <= _tMax; t += interval) {
      const x = _timeToX(t);
      if (x < LABEL_W || x > W) continue;
      ctx.beginPath();
      ctx.moveTo(x, AXIS_H);
      ctx.lineTo(x, H);
      ctx.stroke();
    }
  }

  function _drawAxis(W) {
    if (_tMax <= _tMin) return;
    const span = _tMax - _tMin;
    const avail = W - LABEL_W;
    const idealCount = Math.max(3, Math.floor(avail / 100));
    const rawInterval = span / idealCount;
    const NICE = [
      1000,5000,10000,30000,
      60000,300000,600000,1800000,
      3600000,6*3600000,12*3600000,
      86400000,7*86400000,30*86400000,
    ];
    const interval = NICE.find(i => i >= rawInterval) || NICE[NICE.length - 1];
    const first = Math.ceil(_tMin / interval) * interval;

    ctx.save();
    ctx.font = "10px ui-mono,SFMono-Regular,Menlo,monospace";
    ctx.textBaseline = "middle";
    ctx.textAlign = "center";
    ctx.fillStyle = "#4b5470";
    for (let t = first; t <= _tMax; t += interval) {
      const x = _timeToX(t);
      if (x < LABEL_W + 2 || x > W - 2) continue;
      ctx.fillText(_fmtTick(t, interval), x, AXIS_H / 2);
    }
    ctx.restore();

    // Axis bottom border
    ctx.strokeStyle = "#1a2035";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(LABEL_W, AXIS_H);
    ctx.lineTo(W, AXIS_H);
    ctx.stroke();
  }

  function _fmtTick(t, interval) {
    const d = new Date(t);
    if (interval < 60000)   return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    if (interval < 3600000) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (interval < 86400000) {
      return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " +
             d.toLocaleTimeString([], { hour: "2-digit" });
    }
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  }

  function _drawLanes(W) {
    for (const lane of _lanes) {
      if (lane.isLeaf) {
        _drawLeafLane(lane, W);
      } else {
        _drawHeaderLane(lane, W);
      }
      // Lane separator
      ctx.strokeStyle = "#1a2035";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(LABEL_W, lane.y + lane.h);
      ctx.lineTo(W, lane.y + lane.h);
      ctx.stroke();
    }
  }

  function _drawHeaderLane(lane, W) {
    // Horizontal rule and depth indent cue
    const indent = lane.depth * 14;
    ctx.strokeStyle = "#252c3e";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(LABEL_W, lane.y + lane.h - 0.5);
    ctx.lineTo(W, lane.y + lane.h - 0.5);
    ctx.stroke();
    // Small count indicator on the right side
    ctx.font = "10px ui-mono,monospace";
    ctx.fillStyle = "#3a4460";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    ctx.fillText(lane.sessions.length, W - 8, lane.y + lane.h / 2);
  }

  function _drawLeafLane(lane, W) {
    const midY = lane.y + LANE_H / 2;

    // Centre guideline
    ctx.strokeStyle = "#161c2e";
    ctx.lineWidth = 0.5;
    ctx.beginPath();
    ctx.moveTo(LABEL_W, midY);
    ctx.lineTo(W, midY);
    ctx.stroke();

    // Bars
    for (const s of lane.sessions) {
      _drawBar(s, lane, midY);
    }

    // Expanded commands
    if (lane.expanded && expandedMap.has(lane.expanded)) {
      _drawExpandedCmds(lane, W);
    }
  }

  function _drawBar(s, lane, midY) {
    const r = _barRect(s, lane);
    if (r.x + r.w < LABEL_W || r.x > canvas.width / (window.devicePixelRatio||1)) return;
    const color = intentColor(s.intent);
    const isHover = hoverHit && hoverHit.session.id === s.id;
    const isExpanded = lane.expanded === s.id;

    ctx.save();
    // Playbook glow outline — color is derived from the stable playbook_id
    // so two playbooks with the same display name still read distinctly.
    const cc = playbookColor(s.playbook_id);
    if (cc) {
      ctx.fillStyle = cc.replace("hsl", "hsla").replace(")", ",0.18)");
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(r.x - 1, r.y - 1, r.w + 2, r.h + 2, 2);
      else ctx.rect(r.x - 1, r.y - 1, r.w + 2, r.h + 2);
      ctx.fill();
    }
    ctx.fillStyle = isHover || isExpanded ? color : hexA(color, 0.72);
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(r.x, r.y, r.w, r.h, 2);
    else ctx.rect(r.x, r.y, r.w, r.h);
    ctx.fill();
    ctx.strokeStyle = isHover || isExpanded ? color : hexA(color, 0.4);
    ctx.lineWidth = isHover ? 1.5 : 0.8;
    ctx.stroke();
    if (isHover) {
      ctx.fillStyle = "rgba(255,255,255,0.55)";
      ctx.beginPath();
      ctx.arc(r.x + r.w / 2, r.y, 2.5, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
  }

  function _drawExpandedCmds(lane, W) {
    const y0 = lane.y + LANE_H + 4;
    const x0 = LABEL_W + 10;
    const boxW = W - LABEL_W - 14;
    const boxH = EXPAND_H - 8;

    ctx.save();
    ctx.fillStyle = "rgba(8,12,20,0.94)";
    ctx.strokeStyle = "#2a3148";
    ctx.lineWidth = 1;
    if (ctx.roundRect) ctx.roundRect(x0 - 6, y0 - 4, boxW, boxH, 4);
    else ctx.rect(x0 - 6, y0 - 4, boxW, boxH);
    ctx.fill(); ctx.stroke();

    // Hint top-right: how to close and how to pivot
    ctx.font = "9px ui-sans-serif,sans-serif";
    ctx.fillStyle = "#2e374e";
    ctx.textAlign = "right";
    ctx.textBaseline = "top";
    ctx.fillText("click bar to close  ·  double-click → Prism", x0 - 6 + boxW - 8, y0 - 1);

    ctx.font = "10px ui-mono,SFMono-Regular,monospace";
    ctx.textAlign = "left";
    ctx.textBaseline = "top";
    const maxW = boxW - 20;
    let y = y0 + 16;

    const cmds = expandedMap.get(lane.expanded);
    if (cmds === undefined) {
      // Still fetching
      ctx.fillStyle = "#3a4460";
      ctx.fillText("loading commands…", x0, y);
    } else if (cmds.length === 0) {
      ctx.fillStyle = "#3a4460";
      ctx.fillText("No commands recorded for this session.", x0, y);
    } else {
      for (const cmd of cmds.slice(0, 8)) {
        if (y > y0 + boxH - 10) break;
        ctx.fillStyle = "#9aa3b8";
        ctx.fillText(_truncTextCtx(cmd.command_line || "(no command)", maxW), x0, y);
        y += 15;
      }
      if (cmds.length > 8) {
        ctx.fillStyle = "#3a4460";
        ctx.fillText(`  … ${cmds.length - 8} more`, x0, y);
      }
    }
    ctx.restore();
  }

  function _drawLabels() {
    ctx.save();
    // Label column right border
    ctx.strokeStyle = "#1e2540";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(LABEL_W, 0);
    ctx.lineTo(LABEL_W, canvas.height / (window.devicePixelRatio||1));
    ctx.stroke();

    for (const lane of _lanes) {
      const indent = lane.depth * 14;
      const midY = lane.y + (lane.isLeaf ? LANE_H : HDR_H) / 2;

      if (!lane.isLeaf) {
        // Header: bold label + count chip
        ctx.font = "600 10px ui-sans-serif,system-ui,sans-serif";
        ctx.textBaseline = "middle"; ctx.textAlign = "left";
        // Vertical depth cue: a small colored bar
        const hueMap = { playbook: "#facc15", cluster: "#b91c1c", ip: "#ff9f43", all: "#4cc1ff" };
        ctx.fillStyle = hueMap[lane.type] || "#4b5470";
        ctx.fillRect(indent + 4, lane.y + 4, 2, lane.h - 8);
        ctx.fillStyle = "#8490a8";
        ctx.fillText(_truncTextCtx(lane.label, LABEL_W - indent - 30), indent + 10, midY);
        // Count
        ctx.fillStyle = "#3a4460";
        ctx.font = "10px ui-mono,monospace";
        ctx.textAlign = "right";
        ctx.fillText(lane.sessions.length, LABEL_W - 8, midY);
      } else {
        // Leaf lane: count chip + label + sub-label if nested
        const cnt = lane.sessions.length;
        const cntStr = String(cnt);
        const bubW = Math.max(18, ctx.measureText(cntStr).width + 10);
        ctx.fillStyle = "#0e1525";
        if (ctx.roundRect) ctx.roundRect(indent + 4, midY - 9, bubW, 18, 3);
        else ctx.rect(indent + 4, midY - 9, bubW, 18);
        ctx.fill();
        ctx.font = "600 10px ui-mono,monospace";
        ctx.fillStyle = "#5a6278";
        ctx.textAlign = "center";
        ctx.fillText(cntStr, indent + 4 + bubW / 2, midY);

        ctx.font = "600 11px ui-sans-serif,system-ui,sans-serif";
        ctx.textAlign = "left";
        ctx.fillStyle = lane.key === null ? "#4b5470"
          : (lane.key === "outlier" ? "#f87171" : "#b4bcd0");
        ctx.fillText(_truncTextCtx(lane.label, LABEL_W - indent - bubW - 18),
                     indent + bubW + 12, midY);
      }
    }
    ctx.restore();
  }

  function _truncTextCtx(s, maxW) {
    if (!ctx) return s;
    if (ctx.measureText(s).width <= maxW) return s;
    let lo = 0, hi = s.length;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (ctx.measureText(s.slice(0, mid) + "…").width <= maxW) lo = mid;
      else hi = mid - 1;
    }
    return s.slice(0, lo) + "…";
  }

  // ── tooltip ───────────────────────────────────────────────────────────────

  function _drawTooltip({ session: s, lane }, W, H) {
    const r = _barRect(s, lane);
    const TW = 248, TH = 140;
    let tx = r.x + r.w + 10;
    let ty = r.y;
    if (tx + TW > W - 4) tx = r.x - TW - 10;
    if (ty + TH > H - 4) ty = H - TH - 4;
    if (ty < 0) ty = 4;

    ctx.save();
    ctx.fillStyle = "rgba(7,10,18,0.94)";
    ctx.strokeStyle = "#2a3148";
    ctx.shadowColor = "rgba(0,0,0,0.7)"; ctx.shadowBlur = 14;
    ctx.lineWidth = 1;
    if (ctx.roundRect) ctx.roundRect(tx, ty, TW, TH, 6);
    else ctx.rect(tx, ty, TW, TH);
    ctx.fill(); ctx.shadowBlur = 0; ctx.stroke();

    const color = intentColor(s.intent);
    ctx.fillStyle = color;
    if (ctx.roundRect) ctx.roundRect(tx + 1, ty + 1, 3, TH - 2, [3, 0, 0, 3]);
    else ctx.rect(tx + 1, ty + 1, 3, TH - 2);
    ctx.fill();

    const x0 = tx + 12;
    let y = ty + 11;
    ctx.textBaseline = "top"; ctx.textAlign = "left";

    ctx.font = "600 11px ui-mono,monospace"; ctx.fillStyle = "#c8d0e7";
    ctx.fillText(s.id, x0, y); y += 16;
    ctx.font = "10px ui-sans-serif,sans-serif"; ctx.fillStyle = "#7c8ba1";
    ctx.fillText(s.src_ip, x0, y); y += 15;
    const dt = s.start ? new Date(s.start).toLocaleString([], {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    }) : "—";
    ctx.fillText(dt, x0, y); y += 15;
    ctx.fillStyle = s.command_count > 0 ? "#c8d0e7" : "#3a4460";
    ctx.fillText(`${s.command_count || 0} commands`, x0, y); y += 15;
    if (s.playbook_name || s.playbook_id) {
      const cc = playbookColor(s.playbook_id);
      ctx.fillStyle = cc || "#7c8ba1";
      ctx.fillText(_truncTextCtx(s.playbook_name || s.playbook_id, TW - 22), x0, y); y += 15;
    }
    ctx.fillStyle = color;
    ctx.font = "600 10px ui-sans-serif,sans-serif";
    ctx.fillText((s.intent || "unknown").toUpperCase(), x0, y);
    if (s.command_count > 0) {
      ctx.fillStyle = "#3a4460"; ctx.font = "9px ui-sans-serif,sans-serif";
      ctx.textAlign = "right";
      ctx.fillText("click · expand   dbl-click · prism", tx + TW - 8, ty + TH - 10);
    }
    ctx.restore();
  }

  // ── minimap ───────────────────────────────────────────────────────────────

  function _renderMinimap() {
    _mmRaf = null;
    if (!mmCanvas || !mmCtx) return;
    const dpr = window.devicePixelRatio || 1;
    const mW = mmCanvas.width / dpr;
    const mH = mmCanvas.height / dpr;
    mmCtx.save();
    mmCtx.scale(dpr, dpr);
    mmCtx.clearRect(0, 0, mW, mH);
    mmCtx.fillStyle = "#08090e";
    mmCtx.fillRect(0, 0, mW, mH);
    mmCtx.fillStyle = "#0a0e14";
    mmCtx.fillRect(0, 0, LABEL_W, mH);
    mmCtx.strokeStyle = "#1e2540";
    mmCtx.lineWidth = 1;
    mmCtx.beginPath();
    mmCtx.moveTo(LABEL_W, 0); mmCtx.lineTo(LABEL_W, mH); mmCtx.stroke();

    if (!_data || !_data.sessions.length) { mmCtx.restore(); return; }

    const xScale = (mW - LABEL_W) / (_tMax - _tMin);

    // All session marks (1px wide, full height, intent-colored)
    for (const s of _data.sessions) {
      if (!s.start) continue;
      const t = new Date(s.start).getTime();
      const x = LABEL_W + (t - _tMin) * xScale;
      mmCtx.fillStyle = hexA(intentColor(s.intent), 0.6);
      mmCtx.fillRect(Math.floor(x), 4, 1.5, mH - 8);
    }

    // Viewport box
    if (canvas) {
      const cW = canvas.width / dpr;
      const tLeft  = _xToTime(LABEL_W);
      const tRight = _xToTime(cW);
      const vLeft  = Math.max(LABEL_W, LABEL_W + (tLeft  - _tMin) * xScale);
      const vRight = Math.min(mW,      LABEL_W + (tRight - _tMin) * xScale);
      const vw = vRight - vLeft;
      mmCtx.fillStyle = "rgba(76,193,255,0.10)";
      mmCtx.fillRect(vLeft, 1, vw, mH - 2);
      mmCtx.strokeStyle = "rgba(76,193,255,0.50)";
      mmCtx.lineWidth = 1;
      mmCtx.strokeRect(vLeft + 0.5, 1.5, vw - 1, mH - 3);
    }

    // Label: "OVERVIEW" in the label column
    mmCtx.fillStyle = "#2a3148";
    mmCtx.font = "9px ui-sans-serif,sans-serif";
    mmCtx.textAlign = "center";
    mmCtx.textBaseline = "middle";
    mmCtx.fillText("OVERVIEW", LABEL_W / 2, mH / 2);

    mmCtx.restore();
  }

  function _mmTimeFromX(mx) {
    const dpr = window.devicePixelRatio || 1;
    const mW = mmCanvas.width / dpr;
    return _tMin + (mx - LABEL_W) / ((mW - LABEL_W) / (_tMax - _tMin));
  }

  function _panToTime(t) {
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.width / dpr - LABEL_W;
    panX = W / 2 - (t - _tMin) * zoom;
    panX = _clampPan(panX);
    _scheduleRender();
    _scheduleMinimapRender();
  }

  function _onMmMouseDown(e) {
    mmDrag = true;
    const rect = mmCanvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (mmCanvas.width / rect.width) / (window.devicePixelRatio||1);
    if (mx > LABEL_W) _panToTime(_mmTimeFromX(mx));
  }

  function _onMmMouseMove(e) {
    if (!mmDrag) return;
    const rect = mmCanvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (mmCanvas.width / rect.width) / (window.devicePixelRatio||1);
    if (mx > LABEL_W) _panToTime(_mmTimeFromX(mx));
  }

  // ── interaction ───────────────────────────────────────────────────────────

  function _canvasPos(e) {
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    return {
      x: (e.clientX - rect.left) * (canvas.width / rect.width) / dpr,
      y: (e.clientY - rect.top)  * (canvas.height / rect.height) / dpr,
    };
  }

  function _onMouseMove(e) {
    const { x, y } = _canvasPos(e);
    if (drag) {
      const rawPan = drag.panX0 + (x - drag.x0);
      panX = _clampPan(rawPan);
      _scheduleRender();
      _scheduleMinimapRender();
      return;
    }
    const hit = _hitTest(x, y);
    const prev = hoverHit ? hoverHit.session.id : null;
    const curr = hit ? hit.session.id : null;
    if (prev !== curr) {
      hoverHit = hit;
      canvas.style.cursor = hit ? "pointer" : "default";
      _scheduleRender();
    }
  }

  function _onMouseLeave() {
    hoverHit = null; drag = null;
    canvas.style.cursor = "default";
    _scheduleRender();
  }

  function _onMouseDown(e) {
    if (e.button !== 0) return;
    drag = { x0: _canvasPos(e).x, panX0: panX };
  }

  function _onMouseUp() { drag = null; }

  function _onClick(e) {
    if (drag && Math.abs(_canvasPos(e).x - drag.x0) > 3) return;
    const { x, y } = _canvasPos(e);
    const hit = _hitTest(x, y);
    if (!hit) return;
    const { session: s, lane } = hit;

    if (lane.expanded === s.id) {
      // Second click → collapse (close the command list)
      lane.expanded = null;
      _recomputeLaneY();
      _scheduleRender();
    } else {
      // First click → expand and fetch command list
      // Close any other expanded session in this lane first.
      lane.expanded = s.id;
      _recomputeLaneY();          // immediate layout update (shows loading state)
      _scheduleRender();           // draw loading state right away
      if (!expandedMap.has(s.id)) {
        _fetchCommands(s.id).then(cmds => {
          expandedMap.set(s.id, cmds);
          _scheduleRender();       // re-draw with actual commands
        });
      }
    }
  }

  function _onDblClick(e) {
    if (!_pivotHandler) return;
    const { x, y } = _canvasPos(e);
    const hit = _hitTest(x, y);
    if (hit) _pivotHandler(hit.session.id);
  }

  async function _fetchCommands(sid) {
    try {
      const r = await fetch(`/api/ioc/session/${encodeURIComponent(sid)}/commands?limit=20`);
      if (!r.ok) return [];
      const d = await r.json();
      return d.rows || [];
    } catch (_) { return []; }
  }

  function _onWheel(e) {
    e.preventDefault();
    const { x } = _canvasPos(e);
    if (e.ctrlKey || e.metaKey) {
      // Ctrl/Cmd + scroll = zoom
      const worldX = x - LABEL_W - panX;
      const factor = e.deltaY < 0 ? 1.25 : 0.8;
      const newZoom = _clampZoom(zoom * factor);
      const zoomChange = newZoom / zoom;
      panX = _clampPan(x - LABEL_W - worldX * zoomChange);
      zoom = newZoom;
    } else {
      // Regular scroll = pan (use deltaX for trackpad horizontal, deltaY for wheel)
      const delta = Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY;
      panX = _clampPan(panX - delta * 1.8);
    }
    _scheduleRender();
    _scheduleMinimapRender();
  }

  function _onResize() {
    if (!canvas || !canvas.parentElement) return;
    const dpr = window.devicePixelRatio || 1;
    const parent = canvas.parentElement;
    const w = parent.clientWidth;
    const h = parent.clientHeight;
    const mainH = h - MM_H - 1;  // leave room for minimap + its border

    // Main canvas
    canvas.style.width  = w + "px";
    canvas.style.height = mainH + "px";
    canvas.style.bottom = (MM_H + 1) + "px";   // absolute position above minimap
    canvas.width  = Math.round(w * dpr);
    canvas.height = Math.round(mainH * dpr);

    // Minimap canvas
    if (mmCanvas) {
      mmCanvas.style.width  = w + "px";
      mmCanvas.style.height = MM_H + "px";
      mmCanvas.width  = Math.round(w * dpr);
      mmCanvas.height = Math.round(MM_H * dpr);
    }

    if (_data) {
      zoom = _clampZoom(zoom);
      panX = _clampPan(panX);
    }
    _scheduleRender();
    _scheduleMinimapRender();
  }

  // ── public surface ────────────────────────────────────────────────────────

  return { init, load, clear, fit, setGroupBy, onPivot };
})();
