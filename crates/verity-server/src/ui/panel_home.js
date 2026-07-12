"use strict";
/* ==========================================================================
   panel_home.js — HOME · "Needs decision" (UI-ACTIONS N3)
   --------------------------------------------------------------------------
   Reads (all admin-token gated; dev mode allows + is disclosed):
     • GET /v1/admin/entity-resolution/review-queue?tenant_id&limit — same
       query as the Entities panel's queue view
     • GET /v1/knowledge?tenant_id — same list the Knowledge panel renders;
       "awaiting" = status ∈ {candidate, eligible}
     • GET /v1/admin/quarantine?tenant_id — same list the Quarantine panel
       renders
     • GET /v1/slo/freshness?tenant_id — per-source ingest→queryable
       percentiles, measured server-side from real samples

   HONESTY:
     • every count is as-of-stamped and computed from the SAME query as the
       panel it links to — never a separate estimate;
     • the freshness "slow" flag uses a DISCLOSED console display threshold
       (p95 > 60 s), labeled as such — it is not a configured SLO and is
       never presented as one;
     • a failed probe renders a failed state chip with the server's error —
       never a fabricated zero;
     • urgency never cheapens a gate: the cards link to the panels; every
       decision keeps its full dialog weight there.
   ========================================================================== */
(function () {
  var V = window.Verity;

  // Console display threshold for "slow source" (disclosed, not an SLO).
  var SLOW_P95_MS = 60000;

  var lastLoadedAt = 0;

  function el(id) { return V.$(id); }

  /* One attention card. spec: {id, title, desc, href(panel,params), state,
     count(text or number), foot, fail} */
  function cardHtml(c) {
    var cls = "attn-card" + (c.tone === "attn" ? " attn-needs" : c.tone === "fail" ? " attn-fail" : "");
    return '<button type="button" class="' + cls + '" id="' + c.id + '">' +
      '<div class="attn-top"><span class="attn-title">' + c.title + "</span>" + c.state + "</div>" +
      '<div class="attn-count">' + c.count + "</div>" +
      '<div class="attn-desc">' + c.desc + "</div>" +
      '<div class="attn-foot"><span class="asof">' + c.foot + "</span>" +
        '<span class="asof">open &rsaquo;</span></div>' +
    "</button>";
  }

  function asofNow() { return "checked " + new Date().toTimeString().slice(0, 8); }

  /* ---- no-tenant teach state (species A for the whole console) ---------- */
  function renderNoTenant(host) {
    host.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Connect to a tenant to see what needs you</div>' +
        '<div class="et-body">Verity scopes everything to one <b>tenant</b>. Give the console one, three ways:' +
          "<ul style=\"margin:8px 0 0 18px;color:var(--dim)\">" +
          "<li><b>Paste a tenant id</b> into the session bar above and press Enter.</li>" +
          "<li><b>Mint a scope handle</b> — the tenant fills in automatically.</li>" +
          "<li><b>Decode a handle</b> you already hold on the Scope Inspector.</li></ul>" +
          '<div style="margin-top:8px">Running locally? <span class="ref">verity-cli dev</span> prints your dev tenant and a ready-made handle.</div>' +
        "</div>" +
        '<div class="et-actions">' +
          '<button class="primary" id="home-mint">Mint a scope handle</button>' +
          '<button id="home-goscope">Open Scope Inspector</button>' +
        "</div>" +
      "</div>";
    el("home-mint").onclick = function () { V.openMint(); };
    el("home-goscope").onclick = function () { V.show("scope"); };
  }

  /* ---- the four probes -------------------------------------------------- */

  async function probeEntities(tenant) {
    var rows = await V.api("/v1/admin/entity-resolution/review-queue?tenant_id=" +
      encodeURIComponent(tenant) + "&limit=500", { admin: true });
    rows = rows || [];
    var oldest = 0;
    rows.forEach(function (r) { var w = Number(r.wait_age_secs); if (isFinite(w) && w > oldest) oldest = w; });
    V.setCount("entities", rows.length);
    return {
      id: "home-card-entities",
      title: "Same or different?",
      tone: rows.length ? "attn" : "ok",
      state: rows.length ? V.stateChip("attn") : V.stateChip("ok", "queue clear"),
      count: String(rows.length),
      desc: rows.length
        ? "possible entity match" + (rows.length === 1 ? "" : "es") + " waiting for a human yes/no — oldest has waited <b>" + V.esc(V.fmtAge(oldest)) + "</b>"
        : "no possible matches waiting — matching settled everything it saw",
      foot: asofNow(),
      go: function () { V.show("entities", { view: "queue" }); },
    };
  }

  async function probeKnowledge(tenant) {
    var res = await V.api("/v1/knowledge?tenant_id=" + encodeURIComponent(tenant));
    var items = (res && res.items) || [];
    var waiting = items.filter(function (k) {
      return k.status === "candidate" || k.status === "eligible";
    });
    var oldest = null;
    waiting.forEach(function (k) {
      var t = Date.parse(k.first_seen);
      if (isFinite(t) && (oldest === null || t < oldest)) oldest = t;
    });
    V.setCount("knowledge", waiting.length);
    return {
      id: "home-card-knowledge",
      title: "Knowledge awaiting review",
      tone: waiting.length ? "attn" : "ok",
      state: waiting.length ? V.stateChip("attn") : V.stateChip("ok", "queue clear"),
      count: String(waiting.length),
      desc: waiting.length
        ? "proposed learning" + (waiting.length === 1 ? "" : "s") + " not yet published — publishing stays a human gate" +
          (oldest ? " · oldest proposed <b>" + V.esc(V.timeAgo(oldest)) + "</b>" : "")
        : "nothing proposed and unpublished — the queue is drained",
      foot: asofNow(),
      go: function () { V.show("knowledge"); },
    };
  }

  async function probeQuarantine(tenant) {
    var rows = await V.api("/v1/admin/quarantine?tenant_id=" + encodeURIComponent(tenant), { admin: true });
    rows = rows || [];
    var oldest = null;
    rows.forEach(function (r) {
      var t = Date.parse(r.at);
      if (isFinite(t) && (oldest === null || t < oldest)) oldest = t;
    });
    V.setCount("quarantine", rows.length);
    return {
      id: "home-card-quarantine",
      title: "Quarantine",
      tone: rows.length ? "attn" : "ok",
      state: rows.length ? V.stateChip("attn") : V.stateChip("ok", "empty"),
      count: String(rows.length),
      desc: rows.length
        ? "payload" + (rows.length === 1 ? "" : "s") + " Verity refused to index (no mappable permissions) — fix &amp; re-ingest, or dismiss" +
          (oldest ? " · oldest arrived <b>" + V.esc(V.timeAgo(oldest)) + "</b>" : "")
        : "nothing held — every payload arrived with mappable permissions",
      foot: asofNow(),
      go: function () { V.show("quarantine"); },
    };
  }

  async function probeFreshness(tenant) {
    var rows = await V.api("/v1/slo/freshness?tenant_id=" + encodeURIComponent(tenant), { admin: true });
    rows = rows || [];
    var slow = rows.filter(function (r) { return Number(r.p95_ms) > SLOW_P95_MS; });
    var slowest = null;
    rows.forEach(function (r) {
      if (!slowest || Number(r.p95_ms) > Number(slowest.p95_ms)) slowest = r;
    });
    var desc;
    if (!rows.length) {
      desc = "no ingest measured in the last 24 h — nothing to report is a valid answer";
    } else if (slow.length) {
      desc = "source" + (slow.length === 1 ? "" : "s") + " slower than the console's <b>60 s p95</b> display threshold (not a configured SLO) — slowest: " +
        '<span class="ref">' + V.esc(slowest.source) + "</span> at <b>" + V.esc(V.fmtMs(slowest.p95_ms)) + "</b> p95";
    } else {
      desc = "all " + rows.length + " source" + (rows.length === 1 ? "" : "s") + " fresh — slowest p95 " +
        "<b>" + V.esc(V.fmtMs(slowest.p95_ms)) + "</b> (" + '<span class="ref">' + V.esc(slowest.source) + "</span>)";
    }
    return {
      id: "home-card-freshness",
      title: "Ingest freshness",
      tone: slow.length ? "attn" : "ok",
      state: rows.length === 0 ? V.stateChip("off", "no samples")
        : slow.length ? V.stateChip("attn", slow.length + " slow") : V.stateChip("ok"),
      count: slow.length ? String(slow.length) : String(rows.length),
      desc: desc + " · measured server-side from real samples (24 h window)",
      foot: asofNow(),
      go: function () { V.show("sources"); },
    };
  }

  /* A failed probe → an honest failed card, never a fabricated zero. */
  function failCard(id, title, err, go) {
    var msg = String((err && err.message) || err);
    var needsToken = msg.indexOf("401") >= 0 || msg.indexOf("403") >= 0;
    return {
      id: id,
      title: title,
      tone: "fail",
      state: V.stateChip("fail", needsToken ? "admin token required" : "failed"),
      count: "—",
      desc: needsToken
        ? "this count needs the admin token — set it in the session bar above"
        : V.esc(msg.slice(0, 140)),
      foot: asofNow(),
      go: go,
    };
  }

  /* ---- render ------------------------------------------------------------ */
  async function refresh(tenant) {
    var host = el("home-mount");
    if (!host) return;
    lastLoadedAt = Date.now();

    host.innerHTML =
      '<div class="toolbar"><span class="asof">checking the queues&hellip;</span></div>' +
      '<div class="attn-grid" id="home-grid"></div>';

    var probes = [
      [probeEntities, "home-card-entities", "Same or different?", function () { V.show("entities", { view: "queue" }); }],
      [probeKnowledge, "home-card-knowledge", "Knowledge awaiting review", function () { V.show("knowledge"); }],
      [probeQuarantine, "home-card-quarantine", "Quarantine", function () { V.show("quarantine"); }],
      [probeFreshness, "home-card-freshness", "Ingest freshness", function () { V.show("sources"); }],
    ];
    var results = await Promise.all(probes.map(function (p) {
      return p[0](tenant).catch(function (e) { return failCard(p[1], p[2], e, p[3]); });
    }));

    var allClear = results.every(function (c) { return c.tone === "ok"; });
    var anyFail = results.some(function (c) { return c.tone === "fail"; });

    var grid = results.map(cardHtml).join("");
    var banner = "";
    if (allClear) {
      banner =
        '<div class="empty-teach sp-c" style="margin-top:0">' +
          '<div class="et-title">Nothing needs you right now</div>' +
          '<div class="et-body">All four queues are clear — the counts above are the evidence, checked just now. ' +
            "New matches, proposed knowledge, and refused payloads will appear here the moment they need a human.</div>" +
        "</div>";
    }

    host.innerHTML =
      '<div class="toolbar">' +
        V.stateChip(anyFail ? "fail" : allClear ? "ok" : "attn",
          anyFail ? "some checks failed" : allClear ? "all clear" : "decisions waiting") +
        '<span class="asof">counts come from the same queries as the panels they open &middot; ' + asofNow() + "</span>" +
        '<span class="spacer"></span>' +
        '<button id="home-refresh">Refresh</button>' +
      "</div>" +
      banner +
      '<div class="attn-grid" id="home-grid">' + grid + "</div>" +
      '<div class="card">' +
        "<h2>Shortcuts</h2>" +
        '<div class="toolbar" style="margin-bottom:0">' +
          '<button id="home-mint2">Mint a scope handle</button>' +
          '<button id="home-run-res">Review entity matches</button>' +
          '<button id="home-goaudit">Open the access audit</button>' +
          '<span class="asof">add memory from the CLI: <span class="ref">verity-cli add &lt;file|url|-&gt;</span></span>' +
        "</div>" +
      "</div>";

    results.forEach(function (c) {
      var btn = el(c.id);
      if (btn) btn.onclick = c.go;
    });
    el("home-refresh").onclick = function () { refresh(tenant); };
    el("home-mint2").onclick = function () { V.openMint(); };
    el("home-run-res").onclick = function () { V.show("entities", { view: "queue" }); };
    el("home-goaudit").onclick = function () { V.show("audit"); };
  }

  V.register({
    id: "home",
    mount: function () {
      var host = el("home-mount");
      if (host && !V.tenant()) renderNoTenant(host);
      V.onTenant(function (t) {
        if (!t) { var h = el("home-mount"); if (h) renderNoTenant(h); }
      });
    },
    // v2 AUTOLOAD: the router calls this once the tenant is known.
    load: function (_section, tenant) { return refresh(tenant); },
    // Re-check on every visit if the counts are older than 30 s.
    onShow: function () {
      var t = V.tenant();
      if (t && Date.now() - lastLoadedAt > 30000) refresh(t);
    },
  });
})();
