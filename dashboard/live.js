/* Undertow Security: the Dashboard tab's live scene. Each light is a sampled request replayed from
   data/live.json (about 1-2 minutes behind, admins only); synthetic lights when the feed is missing.
   index.html exposes window.Undertow (data, call, live, role, email, esc, fmt) before this runs. */
(() => {
  "use strict";
  const U = window.Undertow || {};
  const card = document.getElementById("lv"), root = document.getElementById("lv-root");
  if (!card || !root) return;
  const esc = U.esc || (s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
  const fmt = U.fmt || (n => Math.round(+n || 0).toLocaleString());
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // identity is hue + motion + position + label, never hue alone. The seven hues pass the dataviz
  // palette checks with ALL pairs on #0b0b0f; allowed traffic is neutral gray on purpose.
  const CLASSES = [
    { k: "allow", label: "Allowed", color: "#8f8b82", r: 1.6, how: "flows into its lane" },
    { k: "verified", label: "Verified", color: "#76a016", r: 2.3, ring: true, how: "flows in, ringed" },
    { k: "watch", label: "Watch", color: "#11a1b4", r: 2.4, glow: true, how: "flows in, glowing" },
    { k: "challenge", label: "Challenge", color: "#0559d2", r: 2.4, how: "waits at the line, then passes" },
    { k: "tarpit", label: "Tarpit", color: "#a06024", r: 2.4, how: "crawls through slowly" },
    { k: "cell", label: "Padded cell", color: "#8a70f0", r: 2.6, how: "pulled down into the cell" },
    { k: "block", label: "Blocked", color: "#e8286f", r: 2.6, how: "bounces off the line" },
    { k: "flood", label: "Flood", color: "#e8286f", r: 2.0, square: true, how: "breaks on the line as a wave" },
    { k: "decoy", label: "Decoy hit", color: "#7b489e", r: 2.8, how: "diverted up to the decoys" },
  ];
  const CLS = Object.fromEntries(CLASSES.map(c => [c.k, c]));
  // decoy hits always go up to the decoys zone, so "decoys" is not a lane
  const ASPECTS = { login: "Login and account", api: "API", search: "Search", checkout: "Checkout and orders",
                    admin: "Admin", static: "Pages and assets", other: "Other" };
  const WIDGETS = {
    rpm: { title: "Requests per minute", one: (d, f) => [fmt((f.counts || {}).requests || ((d.anomalies || {}).series || []).slice(-1)[0] || 0), "last full minute"] },
    flagged: { title: "Agents flagged", one: d => [fmt(((d.ladder || {}).block || 0) + ((d.ladder || {}).tarpit || 0)), `${(d.ladder || {}).block || 0} blocked`] },
    cell: { title: "In the padded cell", one: d => [fmt(((d.cell || {}).agents || []).filter(a => a.status === "in").length), `${fmt((d.cell || {}).requests || 0)} requests absorbed`] },
    tokens: { title: "Tokens burned", one: d => [fmt((d.cell || {}).tokens || 0), (d.cell || {}).cost ? `about $${(+d.cell.cost).toFixed(2)} of theirs` : "the agents' own budget"] },
    flood: { title: "Flood mode", one: d => { const F = d.flood || {}; return [!F.enabled && F.enabled !== undefined ? "off" : F.active ? "surge" : "calm", `${fmt(F.rpm || 0)}/min · ${fmt(F.flagged || 0)} IPs blocked`]; } },
    budget: { title: "Budget this month", one: d => d.budget ? [`$${(+d.budget.mtd).toFixed(2)}`, `projected $${Math.round(d.budget.projection)} of $${d.budget.limit}`] : ["–", "no estimate yet"] },
    decoys: { title: "Decoy hits", one: d => [fmt((d.kpis || {}).decoyHits || 0), "certain detections"] },
    agents: { title: "Top agents", list: d => (d.actors || []).slice(0, 4).map(a => `${a.ips[0]} · ${a.verdict} ${(+a.score).toFixed(2)}`) },
    moves: { title: "Recent moves", list: d => (d.board || []).slice(0, 4).map(m => `${m.side === "them" ? "♟" : "♞"} ${m.move.replaceAll("_", " ")}`) },
  };
  const KEY = "undertow.dashboard.layout.v1:" + (U.email || "viewer");
  const DEFAULT = { lanes: ["login", "api", "checkout"], widgets: [{ t: "rpm", x: 0.012, y: 0.03 }, { t: "flood", x: 0.012, y: 0.21 }, { t: "cell", x: 0.012, y: 0.62 }] };
  const MAX_LIGHTS = 800;

  function load() {
    try {
      const v = JSON.parse(localStorage.getItem(KEY) || "null");
      if (v && Array.isArray(v.lanes) && Array.isArray(v.widgets)) {
        return { lanes: v.lanes.filter(l => typeof l === "string").slice(0, 12),
                 widgets: v.widgets.filter(w => w && WIDGETS[w.t]).slice(0, 12).map(w => ({ t: w.t, x: clamp(+w.x, 0, 0.9), y: clamp(+w.y, 0, 0.9) })) };
      }
    } catch (_) { /* storage blocked or corrupt: the default layout */ }
    return JSON.parse(JSON.stringify(DEFAULT));
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(S.layout)); } catch (_) { /* private mode */ } }
  const clamp = (v, a, b) => Math.min(b, Math.max(a, isFinite(v) ? v : a));

  const S = { layout: load(), focus: null, only: false, feed: null, demo: true, why: "", lights: [], ripples: [],
              queue: [], seen: new Set(), clock: null, mult: {}, spawned: 0, running: false, pinned: null, counts: {} };

  // ---------- DOM ----------
  root.innerHTML = `
    <div class="lv-bar">
      <span class="lv-note" id="lv-note" aria-live="polite"></span>
      <div class="lv-tools">
        <button id="lv-pal-btn" aria-expanded="false" aria-controls="lv-pal">Add to the scene</button>
        <button id="lv-reset" title="Back to the default lanes and widgets">Reset layout</button>
        <button id="lv-fs" title="Full screen (Esc to leave)">Full screen</button>
      </div>
    </div>
    <div class="lv-legend" role="group" aria-label="Highlight a class of traffic">
      <button id="lv-mode" aria-pressed="false" title="Show only the chosen class instead of dimming the rest">Only the chosen class</button>
      <span id="lv-chips" class="lv-legend" style="margin:0"></span>
    </div>
    <div class="lv-stage" id="lv-stage">
      <canvas id="lv-canvas" role="img" aria-label="Live traffic scene"></canvas>
      <div class="lv-lanes" id="lv-lanes"></div>
      <div class="lv-widgets" id="lv-widgets"></div>
      <aside class="lv-pal" id="lv-pal" hidden aria-label="Things to add to the scene"></aside>
      <div class="lv-tip" id="lv-tip" role="tooltip"></div>
    </div>
    <details class="lv-alt" id="lv-alt"><summary>Text view: counts and the latest requests</summary><div id="lv-alt-body"></div></details>`;
  const $ = id => document.getElementById(id);
  const stage = $("lv-stage"), cv = $("lv-canvas"), cx = cv.getContext("2d"), tip = $("lv-tip");

  // ---------- geometry ----------
  const G = { W: 800, H: 500, dpr: 1 };
  function lanes() { return [...S.layout.lanes, "*"]; }
  function geom() {
    const b = stage.getBoundingClientRect();
    G.W = Math.max(320, b.width); G.H = Math.max(300, b.height); G.dpr = Math.min(2, devicePixelRatio || 1);
    cv.width = G.W * G.dpr; cv.height = G.H * G.dpr; cx.setTransform(G.dpr, 0, 0, G.dpr, 0, 0);
    G.line = G.W * 0.36; G.appL = G.W * 0.42; G.appR = G.W - 8;
    G.top = G.H * 0.15; G.cellTop = G.H * 0.82;
    const ls = lanes(), h = (G.cellTop - G.top) / ls.length;
    G.lane = Object.fromEntries(ls.map((l, i) => [l, { y0: G.top + i * h, y1: G.top + (i + 1) * h, y: G.top + (i + 0.5) * h }]));
    drawLanes();
  }
  function laneOf(ev) {
    for (const l of S.layout.lanes) {
      if (l.startsWith("app:") ? ev.app === l.slice(4) : ev.z === l) return l;
    }
    return "*";
  }
  const laneLabel = l => l === "*" ? "Everything else" : l.startsWith("app:") ? l.slice(4) : ASPECTS[l] || l;

  // ---------- lights ----------
  const SPEED = 170;
  function spawn(ev, echo) {
    if (S.lights.length >= MAX_LIGHTS) { if (echo) return; S.lights.shift(); }
    const c = CLS[ev.c] || CLS.allow, lane = G.lane[laneOf(ev)] || G.lane["*"];
    S.lights.push({ ev, c, echo, x: -6 - Math.random() * 30, y: G.top + Math.random() * (G.cellTop - G.top),
                    v: SPEED * (0.8 + Math.random() * 0.45), ty: lane.y0 + 4 + Math.random() * Math.max(1, lane.y1 - lane.y0 - 8),
                    ph: "in", a: 1, t: 0, vy: 0, vx: 0 });
    if (!echo) S.spawned++;
  }
  function step(L, dt) {
    L.t += dt;
    const k = L.ev.c;
    if (L.ph === "in") {
      L.x += L.v * dt;
      if (L.x >= G.line - 2) {
        L.x = G.line - 2; L.t = 0;
        if (k === "block" || k === "flood") {
          L.ph = "bounce"; L.vx = -L.v * (k === "flood" ? 0.9 : 0.55); L.vy = (Math.random() - 0.5) * (k === "flood" ? 160 : 60);
          if (k === "flood" && Math.random() < 0.25) S.ripples.push({ y: L.y, r: 4, a: 0.7 });
        } else if (k === "challenge") L.ph = "hold";
        else if (k === "decoy") L.ph = "up";
        else if (k === "cell") L.ph = "down";
        else L.ph = k === "tarpit" ? "crawl" : "pass";
      }
    } else if (L.ph === "hold") {
      if (L.t > 0.8) { L.ph = "pass"; L.t = 0; }
    } else if (L.ph === "pass" || L.ph === "crawl") {
      L.x += L.v * (L.ph === "crawl" ? 0.12 : 1) * dt;
      L.y += (L.ty - L.y) * Math.min(1, dt * (L.ph === "crawl" ? 0.8 : 3));
      if (L.x > G.appR - 40) L.a -= dt * 1.6;
    } else if (L.ph === "bounce") {
      L.x += L.vx * dt; L.y += L.vy * dt; L.a -= dt * 0.9;
    } else if (L.ph === "up") {        // diverted up and out of the app, into the decoys zone
      L.x += L.v * 0.6 * dt; L.y += (G.top * 0.45 - L.y) * Math.min(1, dt * 2.2);
      if (L.y < G.top * 0.6) L.a -= dt * 0.7;
    } else if (L.ph === "down") {      // the undertow: pulled down into the padded cell and swirled
      const cyy = (G.cellTop + G.H) / 2;
      L.x += (L.v * 0.35 + Math.sin(L.t * 6) * 40) * dt; L.y += (cyy - L.y) * Math.min(1, dt * 1.6);
      if (L.y > G.cellTop) L.a -= dt * 0.35;
    }
    return L.a > 0 && L.x > -40 && L.x < G.W + 10;
  }
  function alphaOf(k) {
    if (!S.focus) return 1;
    if (k === S.focus) return 1;
    return S.only ? 0 : 0.16;
  }

  // ---------- drawing ----------
  function backdrop() {
    cx.clearRect(0, 0, G.W, G.H);
    cx.font = "11px JetBrains Mono, monospace";
    cx.fillStyle = "rgba(241,238,230,.45)";
    cx.fillText("the internet", 10, 18);
    // the decoys zone and the padded cell pool
    cx.fillStyle = "rgba(123,72,158,.10)"; cx.fillRect(G.appL, 0, G.appR - G.appL, G.top - 6);
    cx.fillStyle = "rgba(241,238,230,.5)"; cx.fillText("decoys", G.appL + 8, 18);
    const pool = cx.createLinearGradient(0, G.cellTop, 0, G.H);
    pool.addColorStop(0, "rgba(138,112,240,.06)"); pool.addColorStop(1, "rgba(138,112,240,.22)");
    cx.fillStyle = pool; cx.fillRect(G.line - 40, G.cellTop, G.appR - G.line + 40, G.H - G.cellTop);
    cx.fillStyle = "rgba(241,238,230,.55)"; cx.fillText("the padded cell", G.line + 10, G.H - 10);
    // lanes of the app
    lanes().forEach((l, i) => {
      const g = G.lane[l];
      cx.fillStyle = i % 2 ? "rgba(255,255,255,.018)" : "rgba(255,255,255,.035)";
      cx.fillRect(G.appL, g.y0, G.appR - G.appL, g.y1 - g.y0);
    });
    cx.fillStyle = "rgba(241,238,230,.4)"; cx.fillText("your app", G.appL + 8, G.top + 14);
    // the line
    const grd = cx.createLinearGradient(G.line - 22, 0, G.line + 22, 0);
    grd.addColorStop(0, "rgba(200,255,62,0)"); grd.addColorStop(0.5, "rgba(200,255,62,.13)"); grd.addColorStop(1, "rgba(200,255,62,0)");
    cx.fillStyle = grd; cx.fillRect(G.line - 22, 0, 44, G.H);
    cx.strokeStyle = "rgba(200,255,62,.55)"; cx.lineWidth = 1; cx.beginPath(); cx.moveTo(G.line, 6); cx.lineTo(G.line, G.H - 6); cx.stroke();
    cx.fillStyle = "rgba(241,238,230,.55)"; cx.fillText("undertow", G.line + 6, 18);
  }
  function frame(dt) {
    backdrop();
    S.ripples = S.ripples.filter(r => (r.r += 90 * dt, r.a -= dt * 0.9) > 0);
    for (const r of S.ripples) {
      cx.globalAlpha = r.a * alphaOf("flood"); cx.strokeStyle = CLS.flood.color; cx.lineWidth = 1.2;
      cx.beginPath(); cx.arc(G.line, r.y, r.r, Math.PI * 0.5, Math.PI * 1.5); cx.stroke();
    }
    const keep = [];
    for (const L of S.lights) {
      if (!step(L, dt)) continue;
      keep.push(L);
      const al = alphaOf(L.ev.c) * Math.max(0, Math.min(1, L.a));
      if (!al) continue;
      const c = L.c, bright = S.focus === c.k;
      cx.globalAlpha = al;
      cx.fillStyle = c.color; cx.strokeStyle = c.color;
      if (c.glow || bright) { cx.shadowColor = c.color; cx.shadowBlur = bright ? 10 : 8; }
      if (c.square) cx.fillRect(L.x - c.r, L.y - c.r, c.r * 2, c.r * 2);
      else if (c.ring) { cx.lineWidth = 1.4; cx.beginPath(); cx.arc(L.x, L.y, c.r + 0.8, 0, 7); cx.stroke(); }
      else { cx.beginPath(); cx.arc(L.x, L.y, bright ? c.r + 0.7 : c.r, 0, 7); cx.fill(); }
      if (L.ph === "hold") { cx.lineWidth = 1; cx.beginPath(); cx.arc(L.x, L.y, 5 + 3 * Math.abs(Math.sin(L.t * 8)), 0, 7); cx.stroke(); }
      cx.shadowBlur = 0;
    }
    cx.globalAlpha = 1;
    S.lights = keep;
  }
  function staticView() {           // reduced motion: no animation, the counts by lane and class
    backdrop();
    const f = S.feed || { counts: S.counts };
    const byLane = {};
    for (const e of (f.events || [])) byLane[laneOf(e)] = (byLane[laneOf(e)] || 0) + 1;
    cx.font = "12px JetBrains Mono, monospace"; cx.fillStyle = "rgba(241,238,230,.8)";
    lanes().forEach(l => cx.fillText(`${laneLabel(l)}: ${fmt(byLane[l] || 0)} sampled`, G.appL + 12, G.lane[l].y + 4));
    const cc = (f.counts || {}).class || {};
    const x0 = Math.max(12, G.line - 200);     // beside the line, clear of the default widgets
    CLASSES.forEach((c, i) => {
      cx.fillStyle = c.color; cx.fillRect(x0, G.top + 10 + i * 20, 10, 10);
      cx.fillStyle = "rgba(241,238,230,.8)"; cx.fillText(`${c.label}: ${fmt(cc[c.k] || 0)}/min`, x0 + 16, G.top + 19 + i * 20);
    });
  }

  // ---------- replay of the feed, or the demo stream ----------
  function useFeed(f) {
    S.feed = f;
    const evs = (f.events || []).slice().sort((a, b) => a.t - b.t);
    const newest = evs.length ? evs[evs.length - 1].t : 0;
    const sampled = {};
    for (const e of evs) if (e.t > newest - 60) sampled[e.c] = (sampled[e.c] || 0) + 1;
    // each sampled light stands for this many real requests (capped: the scene shows density, not every request)
    S.mult = Object.fromEntries(CLASSES.map(c => [c.k, clamp(Math.round((((f.counts || {}).class || {})[c.k] || 0) / Math.max(1, sampled[c.k] || 0)), 1, 12)]));
    for (const e of evs) {
      const id = `${e.t}|${e.ip}|${e.p}|${e.c}`;
      if (!S.seen.has(id)) { S.seen.add(id); S.queue.push(e); }
    }
    if (S.seen.size > 4000) S.seen = new Set([...S.seen].slice(-2000));
    S.queue.sort((a, b) => a.t - b.t);
    if (!S.clock || S.clock.t < newest - 150) S.clock = { at: performance.now(), t: newest - 60 };   // replay the last minute
    S.counts = f.counts || {};
    renderChips(); renderAlt(); renderPalette();
  }
  function replay() {
    if (!S.clock) return;
    const now = S.clock.t + (performance.now() - S.clock.at) / 1000;
    let n = 0;
    while (S.queue.length && S.queue[0].t <= now && n++ < 200) {
      const e = S.queue.shift();
      spawn(e, false);
      for (let i = 1; i < (S.mult[e.c] || 1); i++) spawn(e, true);
    }
  }
  // demo: synthetic requests from documentation IP ranges, every class, a flood wave now and then
  const DEMO = { mix: [["allow", 70], ["verified", 5], ["watch", 5], ["challenge", 4], ["tarpit", 3], ["cell", 3], ["block", 4], ["decoy", 1.2]],
                 apps: ["shop.example", "billing.example"], nets: ["192.0.2.", "198.51.100.", "203.0.113."], cc: ["US", "DE", "NL", "SG", "BR", "GB", "JP"],
                 paths: { login: ["/login", "/account", "/api/auth/token"], api: ["/api/v2/products", "/api/v2/orders/1042", "/openapi.json"],
                          search: ["/search", "/api/v2/search"], checkout: ["/cart", "/checkout", "/api/v2/payments"], admin: ["/admin", "/admin/users"],
                          static: ["/", "/products/7", "/assets/app.js"], other: ["/contact"] } };
  let demoAcc = 0, demoWave = 0, demoTick = 0;
  const pick = a => a[Math.floor(Math.random() * a.length)];
  function demoEvent(c) {
    const z = c === "decoy" ? "decoys" : pick(["static", "static", "api", "login", "search", "checkout", "admin", "other"]);
    const p = z === "decoys" ? "/api/v1/internal/ops/export" : pick(DEMO.paths[z]);
    return { t: Date.now() / 1000, c, app: Math.random() < 0.8 ? DEMO.apps[0] : DEMO.apps[1], z, m: z === "checkout" || z === "login" ? pick(["GET", "POST"]) : "GET",
             p, cc: pick(DEMO.cc), a: Math.floor(Math.random() * 0xffffffffff).toString(16).padStart(10, "0"),
             ip: pick(DEMO.nets) + (2 + Math.floor(Math.random() * 250)) };
  }
  function demoFeed() {             // reduced motion: one still sample instead of a stream
    const evs = [], total = DEMO.mix.reduce((a, [, w]) => a + w, 0), now = Date.now() / 1000;
    for (let i = 0; i < 240; i++) {
      let r = Math.random() * total, c = "allow";
      for (const [k, w] of DEMO.mix) { if ((r -= w) <= 0) { c = k; break; } }
      evs.push({ ...demoEvent(i < 20 ? "flood" : c), t: now - 60 + i / 4 });
    }
    const tally = k => evs.reduce((m, e) => (m[e[k]] = (m[e[k]] || 0) + 20, m), {});
    return { events: evs.reverse(), counts: { requests: evs.length * 20, class: tally("c"), aspect: tally("z") }, apps: DEMO.apps, mode: "observe" };
  }
  function demoStep(dt) {
    demoAcc += dt * 24; demoWave -= dt; demoTick += dt;
    const total = DEMO.mix.reduce((a, [, w]) => a + w, 0);
    while (demoAcc >= 1) {
      demoAcc -= 1;
      let r = Math.random() * total, c = "allow";
      for (const [k, w] of DEMO.mix) { if ((r -= w) <= 0) { c = k; break; } }
      spawn(demoEvent(c), false); S.counts.class = S.counts.class || {};
      S.counts.class[c] = (S.counts.class[c] || 0) + 1;
    }
    if (demoWave <= 0) {             // a flood wave every half minute or so
      demoWave = 22 + Math.random() * 14;
      const ip = pick(DEMO.nets) + (2 + Math.floor(Math.random() * 250));
      for (let i = 0; i < 90; i++) setTimeout(() => S.running && spawn({ ...demoEvent("flood"), ip }, i > 0), i * 18);
      S.counts.class.flood = (S.counts.class.flood || 0) + 90;
    }
    if (demoTick > 5) { demoTick = 0; renderChips(); }
  }

  // ---------- loop: paused when the tab or the page is hidden ----------
  let last = 0;
  function loop(ts) {
    if (!S.running) return;
    const dt = Math.min(0.1, last ? (ts - last) / 1000 : 0.016); last = ts;   // capped so a tab switch never jumps the scene
    if (S.demo) demoStep(dt); else replay();
    frame(dt);
    requestAnimationFrame(loop);
  }
  function visible() { return !document.hidden && !card.closest(".view").classList.contains("hidden"); }
  function setRunning() {
    const want = visible() && !reduced;
    if (want && !S.running) { S.running = true; last = 0; geom(); requestAnimationFrame(loop); }
    if (!want) S.running = false;
    if (visible() && reduced) { geom(); staticView(); }
  }

  // ---------- the feed ----------
  async function poll() {
    if (!visible()) return;
    let why = "";
    if (U.live && U.call) {
      try {
        const r = await U.call("data/live");
        if (r.ok) { const f = await r.json(); S.demo = false; S.why = ""; useFeed(f); note(); return; }
        why = r.status === 403 ? "the live feed is for admins" : r.status === 404 ? "no live feed yet (the scorer writes one every minute)" : "the live feed did not load";
      } catch (_) { why = "the live feed did not load"; }
    }
    S.demo = true; S.why = why || "opened without the live feed";
    if (reduced) { useFeed(demoFeed()); S.demo = true; } else if (!S.counts.class) S.counts = { class: {} };
    note(); renderChips(); renderAlt(); renderPalette();
  }
  function note() {
    const f = S.feed, el = $("lv-note");
    if (S.demo) { el.className = "lv-note warn"; el.innerHTML = `<b>Demo traffic</b> · ${esc(S.why)}. Synthetic requests, documentation IP ranges.`; return; }
    el.className = "lv-note";
    el.innerHTML = `<b>Live</b> · a sample of requests, not every one, replayed about ${Math.max(1, Math.round(((f.delay || 60) + 60) / 60))} min behind`
      + ` · ${fmt((f.counts || {}).requests || 0)} requests in the last full minute`
      + (f.mode === "observe" ? ` · <b>observe mode</b>: verdicts shown, not applied at the edge` : "");
  }

  // ---------- legend and highlight ----------
  function renderChips() {
    const cc = (S.counts || {}).class || {};
    $("lv-chips").innerHTML = CLASSES.map(c => `<button class="lv-chip" data-k="${c.k}" aria-pressed="${S.focus === c.k}"
        title="${esc(c.label)}: ${esc(c.how)}. Click to highlight."><i class="lv-sw${c.ring ? " ring" : ""}${c.square ? " sq" : ""}" style="background:${c.color};color:${c.color}"></i>${esc(c.label)}
        <span class="n">${fmt(cc[c.k] || 0)}${S.demo ? "" : "/min"}</span></button>`).join("");
    document.querySelectorAll("#lv-chips .lv-chip").forEach(b => b.onclick = () => {
      S.focus = S.focus === b.dataset.k ? null : b.dataset.k; renderChips(); if (reduced) staticView();
    });
  }
  $("lv-mode").onclick = e => { S.only = !S.only; e.currentTarget.setAttribute("aria-pressed", S.only); };

  // ---------- lanes: drop, reorder, remove ----------
  function drawLanes() {
    const box = $("lv-lanes");
    const sampled = {};
    for (const e of ((S.feed || {}).events || [])) sampled[laneOf(e)] = (sampled[laneOf(e)] || 0) + 1;
    box.innerHTML = lanes().map((l, i) => `<div class="lv-lane" data-l="${esc(l)}" style="top:${G.lane[l].y}px" ${l === "*" ? "" : 'draggable="true"'}
        aria-label="Lane: ${esc(laneLabel(l))}"><span>${esc(laneLabel(l))}</span>${S.demo ? "" : `<span class="n">${sampled[l] || 0}</span>`}
        ${l === "*" ? "" : `<button data-mv="-1" aria-label="Move ${esc(laneLabel(l))} up" ${i ? "" : "disabled"}>↑</button>
        <button data-mv="1" aria-label="Move ${esc(laneLabel(l))} down">↓</button><button data-rm aria-label="Remove ${esc(laneLabel(l))}">✕</button>`}</div>`).join("");
    box.querySelectorAll(".lv-lane").forEach(el => {
      const l = el.dataset.l, i = S.layout.lanes.indexOf(l);
      el.querySelectorAll("[data-mv]").forEach(b => b.onclick = () => moveLane(i, i + +b.dataset.mv));
      const rm = el.querySelector("[data-rm]"); if (rm) rm.onclick = () => { S.layout.lanes.splice(i, 1); changed(); };
      el.ondragstart = ev => ev.dataTransfer.setData("text/x-undertow", JSON.stringify({ kind: "move-lane", id: l }));
      el.ondragover = ev => { ev.preventDefault(); el.classList.add("over"); };
      el.ondragleave = () => el.classList.remove("over");
      el.ondrop = ev => {
        ev.preventDefault(); ev.stopPropagation(); el.classList.remove("over");
        const d = parse(ev); if (!d) return;
        const to = l === "*" ? S.layout.lanes.length : i;
        if (d.kind === "move-lane") moveLane(S.layout.lanes.indexOf(d.id), to);
        else if (d.kind === "lane") addLane(d.id, to);
        else if (d.kind === "widget") addWidget(d.id, ev);
      };
    });
  }
  function moveLane(from, to) {
    const L = S.layout.lanes;
    if (from < 0 || to < 0 || from >= L.length) return;
    const [x] = L.splice(from, 1); L.splice(Math.min(to, L.length), 0, x); changed();
  }
  function addLane(id, at) {
    const L = S.layout.lanes;
    if (L.includes(id) || L.length >= 12) return;
    L.splice(at == null ? L.length : at, 0, id); changed();
  }
  function changed() { save(); geom(); renderPalette(); if (reduced) staticView(); }
  const parse = ev => { try { return JSON.parse(ev.dataTransfer.getData("text/x-undertow")); } catch (_) { return null; } };
  stage.ondragover = ev => { ev.preventDefault(); stage.classList.add("drop"); };
  stage.ondragleave = () => stage.classList.remove("drop");
  stage.ondrop = ev => {
    ev.preventDefault(); stage.classList.remove("drop");
    const d = parse(ev); if (!d) return;
    const b = stage.getBoundingClientRect(), x = ev.clientX - b.left, y = ev.clientY - b.top;
    if (d.kind === "widget") return addWidget(d.id, ev);
    if (d.kind === "lane" && x > G.line) {
      const i = S.layout.lanes.findIndex(l => y < G.lane[l].y);
      addLane(d.id, i < 0 ? S.layout.lanes.length : i);
    }
  };

  // ---------- widgets: drop anywhere, drag to move, remove ----------
  function addWidget(t, ev) {
    if (!WIDGETS[t] || S.layout.widgets.length >= 12) return;
    const b = stage.getBoundingClientRect();
    const x = ev && ev.clientX ? (ev.clientX - b.left) / b.width : 0.45, y = ev && ev.clientY ? (ev.clientY - b.top) / b.height : 0.05;
    S.layout.widgets.push({ t, x: clamp(x, 0, 0.85), y: clamp(y, 0, 0.85) }); save(); renderWidgets();
  }
  function renderWidgets() {
    const d = U.data || {}, f = S.feed || { counts: S.counts };
    $("lv-widgets").innerHTML = S.layout.widgets.map((w, i) => {
      const W = WIDGETS[w.t];
      let body;
      try {
        if (W.list) { const rows = W.list(d); body = rows.length ? `<ul>${rows.map(r => `<li>${esc(r)}</li>`).join("")}</ul>` : `<div class="d">nothing yet</div>`; }
        else { const [v, sub] = W.one(d, f); body = `<div class="v">${esc(v)}</div><div class="d">${esc(sub)}</div>`; }
      } catch (_) { body = `<div class="d">no data yet</div>`; }
      return `<section class="lv-w" tabindex="0" data-i="${i}" style="left:${w.x * 100}%;top:${w.y * 100}%"
          aria-label="${esc(W.title)} widget. Arrow keys move it, Delete removes it.">
        <header><span>${esc(W.title)}</span><button data-rm aria-label="Remove ${esc(W.title)}">✕</button></header>${body}</section>`;
    }).join("");
    $("lv-widgets").querySelectorAll(".lv-w").forEach(el => {
      const i = +el.dataset.i, w = S.layout.widgets[i];
      el.querySelector("[data-rm]").onclick = () => { S.layout.widgets.splice(i, 1); save(); renderWidgets(); };
      const head = el.querySelector("header");
      head.onpointerdown = ev => {
        if (ev.target.closest("button")) return;
        head.setPointerCapture(ev.pointerId);
        const b = stage.getBoundingClientRect(), ox = ev.clientX - el.offsetLeft, oy = ev.clientY - el.offsetTop;
        head.onpointermove = m => {
          w.x = clamp((m.clientX - ox) / b.width, 0, 0.92); w.y = clamp((m.clientY - oy) / b.height, 0, 0.92);
          el.style.left = w.x * 100 + "%"; el.style.top = w.y * 100 + "%";
        };
        head.onpointerup = () => { head.onpointermove = null; save(); };
      };
      el.onkeydown = ev => {
        const dx = { ArrowLeft: -0.02, ArrowRight: 0.02 }[ev.key] || 0, dy = { ArrowUp: -0.02, ArrowDown: 0.02 }[ev.key] || 0;
        if (dx || dy) { ev.preventDefault(); w.x = clamp(w.x + dx, 0, 0.92); w.y = clamp(w.y + dy, 0, 0.92); save(); renderWidgets(); document.querySelector(`.lv-w[data-i="${i}"]`).focus(); }
        if (ev.key === "Delete" || ev.key === "Backspace") { ev.preventDefault(); S.layout.widgets.splice(i, 1); save(); renderWidgets(); }
      };
    });
  }

  // ---------- the palette (drawer) ----------
  function renderPalette() {
    const apps = [...new Set([...(((U.data || {}).apps) || []).map(a => a.host), ...((S.feed || {}).apps || []),
                              ...(S.demo ? DEMO.apps : [])])].filter(Boolean).slice(0, 20);
    const item = (kind, id, label, used) => `<button class="lv-item" draggable="true" data-kind="${kind}" data-id="${esc(id)}"
        ${used ? 'aria-disabled="true" title="Already on the scene"' : `title="Drag onto the scene, or press Enter to add"`}>${esc(label)}</button>`;
    $("lv-pal").innerHTML = `<p>Drag onto the scene, or select to add. Lanes go on the app side; widgets anywhere.</p>
      <h3>App aspects</h3><div class="items">${Object.entries(ASPECTS).map(([k, l]) => item("lane", k, l, S.layout.lanes.includes(k))).join("")}</div>
      <h3>Apps</h3><div class="items">${apps.length ? apps.map(h => item("lane", "app:" + h, h, S.layout.lanes.includes("app:" + h))).join("") : "<p>No apps seen yet.</p>"}</div>
      <h3>Widgets</h3><div class="items">${Object.entries(WIDGETS).map(([k, w]) => item("widget", k, w.title, false)).join("")}</div>`;
    $("lv-pal").querySelectorAll(".lv-item").forEach(b => {
      b.ondragstart = ev => ev.dataTransfer.setData("text/x-undertow", JSON.stringify({ kind: b.dataset.kind, id: b.dataset.id }));
      b.onclick = () => b.dataset.kind === "lane" ? addLane(b.dataset.id) : addWidget(b.dataset.id);
    });
  }
  $("lv-pal-btn").onclick = e => {
    const p = $("lv-pal"), open = p.hidden;
    p.hidden = !open; e.currentTarget.setAttribute("aria-expanded", open);
    if (open) { renderPalette(); const f = p.querySelector("button"); if (f) f.focus(); }
  };
  $("lv-reset").onclick = () => { S.layout = JSON.parse(JSON.stringify(DEFAULT)); changed(); renderWidgets(); };

  // ---------- full screen ----------
  $("lv-fs").onclick = () => {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    else if (card.requestFullscreen) card.requestFullscreen().catch(() => {});
  };
  document.addEventListener("fullscreenchange", () => {
    $("lv-fs").textContent = document.fullscreenElement ? "Leave full screen" : "Full screen";
    setTimeout(() => { geom(); if (reduced) staticView(); }, 60);
  });

  // ---------- tooltip: hover a light, click to pin ----------
  function nearest(mx, my) {
    let best = null, bd = 100;
    for (const L of S.lights) {
      if (!alphaOf(L.ev.c)) continue;
      const d = (L.x - mx) ** 2 + (L.y - my) ** 2;
      if (d < bd) { bd = d; best = L; }
    }
    return best;
  }
  function showTip(L, mx, my) {
    if (!L) { tip.classList.remove("on"); return; }
    const e = L.ev, c = CLS[e.c] || CLS.allow;
    const row = (k, v) => v ? `<div class="r"><span>${k}</span><span>${esc(v)}</span></div>` : "";
    tip.innerHTML = `<div class="t">${esc(new Date(e.t * 1000).toLocaleTimeString())} · ${esc(c.label)}${L.echo ? " (one of a crowd)" : ""}</div>`
      + row("What happened", c.how) + row("App", e.app) + row("Aspect", ASPECTS[e.z] || e.z) + row("Request", `${e.m} ${e.p}`)
      + row("Country", e.cc) + row("Agent tag", e.a) + row("IP", e.ip);
    let left = mx + 14; if (left + 320 > G.W) left = mx - 334;
    tip.style.left = Math.max(4, left) + "px"; tip.style.top = Math.max(4, my - 10) + "px"; tip.classList.add("on");
  }
  cv.onmousemove = ev => {
    if (S.pinned) return;
    const b = cv.getBoundingClientRect();
    showTip(nearest(ev.clientX - b.left, ev.clientY - b.top), ev.clientX - b.left, ev.clientY - b.top);
  };
  cv.onmouseleave = () => { if (!S.pinned) showTip(null); };
  cv.onclick = ev => {
    const b = cv.getBoundingClientRect(), L = nearest(ev.clientX - b.left, ev.clientY - b.top);
    S.pinned = S.pinned || !L ? null : L;
    showTip(S.pinned || null, ev.clientX - b.left, ev.clientY - b.top);
  };

  // ---------- the text alternative ----------
  function renderAlt() {
    const f = S.feed || {}, cc = (S.counts || {}).class || {}, zc = (f.counts || {}).aspect || {};
    const evs = (f.events || []).slice(0, 12);
    $("lv-alt-body").innerHTML = `<p>${S.demo ? "Demo traffic." : `Last full minute: ${fmt((f.counts || {}).requests || 0)} requests.`}
        ${CLASSES.map(c => `${esc(c.label)} ${fmt(cc[c.k] || 0)}`).join(", ")}.
        ${S.demo ? "" : "By aspect: " + Object.entries(ASPECTS).map(([k, l]) => `${esc(l)} ${fmt(zc[k] || 0)}`).join(", ") + `, decoys ${fmt(zc.decoys || 0)}.`}</p>`
      + (evs.length ? `<table><tr><th>Time</th><th>What happened</th><th>App</th><th>Aspect</th><th>Request</th><th>Country</th><th>IP</th></tr>`
        + evs.map(e => `<tr><td class="m">${esc(new Date(e.t * 1000).toLocaleTimeString())}</td><td>${esc((CLS[e.c] || CLS.allow).label)}</td>
          <td class="m">${esc(e.app)}</td><td>${esc(ASPECTS[e.z] || e.z)}</td><td class="m">${esc(e.m)} ${esc(e.p)}</td><td>${esc(e.cc || "")}</td><td class="m">${esc(e.ip)}</td></tr>`).join("")
        + `</table>` : "");
  }

  // ---------- wiring ----------
  document.addEventListener("visibilitychange", setRunning);
  document.addEventListener("undertow:tab", () => { setRunning(); poll(); renderWidgets(); });
  document.addEventListener("undertow:data", () => { renderWidgets(); renderPalette(); });
  new ResizeObserver(() => { if (visible()) { geom(); if (reduced) staticView(); } }).observe(stage);
  setInterval(poll, 60000);
  if (reduced) $("lv-alt").open = true;
  geom(); renderChips(); renderWidgets(); renderPalette(); poll(); setRunning();
  // read-only numbers for tests and debugging
  window.__undertowLive = { stats: () => ({ running: S.running, demo: S.demo, lights: S.lights.length, spawned: S.spawned,
                                            lanes: lanes(), widgets: S.layout.widgets.map(w => w.t), focus: S.focus }) };
})();
