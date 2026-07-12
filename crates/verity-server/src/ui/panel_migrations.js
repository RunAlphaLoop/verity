"use strict";
/* ==========================================================================
   panel_migrations.js — Search index upgrade (v2 rebuild)
   --------------------------------------------------------------------------
   THE LAW, applied:
     • plain-language primaries — "Rebuild the search index", "Switch searches
       to the new index", "Source history backfill", "Refresh entity
       summaries"; re-embed / cutover / dense-route / embedding_v2 live ONLY
       in .sub / mono .ref secondary text;
     • one-sentence purpose on every operation; visible state chips + as-of;
     • AUTOLOADS backfill progress once the tenant is known (no cold Load
       button); no-tenant and empty states TEACH with working buttons;
     • honesty kept verbatim: determinate bars only with a known total,
       striped indeterminate otherwise, total==0 its own state, honest ETA,
       the live-route "not known yet" seam (no GET exists), and
       every count painted from a live server response — never fabricated;
     • fail-closed kept: coverage-gated cutover (server 409), force only
       behind an explicit acknowledgment (omission refuses client-side),
       writes refuse when no scope is named rather than silently going global.
   Endpoints verified against crates/verity-server/src/{main,backfill}.rs.
   Zero LLM / zero live-ReBAC calls from this panel.
   ========================================================================== */
(function () {
  var V = window.Verity;

  // Default target model id for the new column; the server registers it on
  // the first batch (idempotent). An honest non-empty default, overridable.
  var DEFAULT_MODEL = "bge-small-en-v1.5";

  /* ------------------------------------------------------------- state */
  var lastCoverage = null;  // { total, covered, fraction } from the last server response
  var lastCutover = null;   // { route, tenant, forced, at } — the only honest "live route" source
  var looping = false;
  var stopRequested = false;

  function el(id) { return V.$(id); }
  function nowStamp() { return new Date().toTimeString().slice(0, 8); }

  // Mirror the server's rule (EmbeddingCoverage::is_complete):
  // total==0 OR covered>=total.
  function coverageComplete(cov) {
    if (!cov || cov.total == null) return false;
    return cov.total <= 0 || (cov.covered != null && cov.covered >= cov.total);
  }

  /* ------------------------------------------------------------ register */
  V.register({
    id: "migrations",
    mount: function () {
      var host = el("migrations-mount");
      if (!host) return;
      // The backfill chip + as-of live in the backfill card's header (see
      // buildCards), NOT here — under the panel title they read as the state
      // of the whole index upgrade.
      host.innerHTML =
        '<div class="toolbar">' +
          '<span class="spacer"></span>' +
          '<button id="mig-refresh">Refresh</button>' +
        "</div>" +
        '<div class="err" id="mig-err"></div>' +
        '<div id="mig-cards"></div>';
      buildCards(el("mig-cards"));
      el("mig-refresh").onclick = function () {
        var t = V.tenant();
        if (t) refreshBackfill(t); else paintNoTenant();
      };
      if (!V.tenant()) paintNoTenant();
    },
    // AUTOLOAD — the router runs this when the panel shows and a tenant is
    // known (and again on tenant change): backfill progress is the loadable
    // read here. Coverage and route stay honestly "unmeasured/unknown" until
    // an operation runs — there is no read-only endpoint for either.
    load: function (_s, tenant) { return refreshBackfill(tenant); },
  });

  /* ------------------------------------------------------------- cards */
  function buildCards(host) {
    host.innerHTML =
      /* 1 · rebuild */
      '<div class="card">' +
        '<h2>1 · Rebuild the search index <span class="sub">re-embed<span class="api-crumb"> · POST /v1/admin/reembed/batch</span></span></h2>' +
        '<div class="note">Re-encodes stored text into the new model’s index, in batches. Safe to stop at any ' +
          "time — it resumes where it left off, and it <b>never re-fetches source data</b>. Needs the server’s " +
          "built-in encoder: a keyword-search-only (sparse) server refuses, and the reason is shown as-is" +
          '<span class="api-crumb"> · 503</span>.</div>' +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><label for="mig-model">New model <span class="note">(target model id)</span></label> ' +
            '<input type="text" id="mig-model" class="field" value="' + V.esc(DEFAULT_MODEL) + '" size="24" spellcheck="false"></div>' +
          '<div class="tight"><label for="mig-batch">Text chunks per batch <span class="note">(1–10000)</span></label> ' +
            '<input type="number" id="mig-batch" class="field" min="1" max="10000" step="1" value="512"></div>' +
          '<div class="tight"><label style="display:flex;gap:8px;align-items:center;margin-top:18px">' +
            '<input type="checkbox" id="mig-global" style="width:auto;min-width:0">' +
            '<span>All spaces <span class="note">(unchecked = the active space <span class="api-crumb">(tenant)</span> only)</span></span></label></div>' +
        "</div>" +
        '<div style="margin-top:12px"><b>How much is ready</b></div>' +
        '<div id="mig-cov-bar" style="margin-top:6px"></div>' +
        '<div id="mig-cov-stat"></div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:12px">' +
          '<button class="primary" id="mig-run" title="Loop batches until the server reports no pending items, repainting readiness after each batch.">Rebuild until done</button>' +
          '<button id="mig-run-one" title="Fill exactly one batch, then stop — a careful step-through.">Do one batch</button>' +
          '<button id="mig-run-stop" disabled title="Stop after the in-flight batch returns — never mid-write.">Stop</button>' +
          '<span class="asof" id="mig-run-status"></span>' +
        "</div>" +
        '<div class="dc-meta api-crumb-block">re-embed → embedding_v2 · model registered idempotently · dims must match (384-d today; a true dim change needs docs/EMBEDDING_MIGRATION.md)</div>' +
      "</div>" +

      /* backfill (auto-loaded) — NOT a numbered step of the index upgrade */
      '<div class="card">' +
        '<h2>Source history backfill — separate from the index upgrade ' +
          '<span class="sub">latest run per source · auto-loaded<span class="api-crumb"> · GET /v1/admin/backfill</span></span> ' +
          '<span id="mig-state"></span> <span class="asof" id="mig-asof"></span></h2>' +
        '<div class="note">This watches connected sources pulling in their history. It is not a step of the ' +
          "index switch — shown here so you can see data landing while you rebuild. Progress is posted " +
          "best-effort by the ingest side — a <b>progress signal, not an audit ledger</b>; the authoritative " +
          "rows live in the store. A bar is exact only when the source declared a total.</div>" +
        '<div id="mig-bf-out" style="margin-top:8px"></div>' +
      "</div>" +

      /* 2 · cutover */
      '<div class="card">' +
        '<h2>2 · Switch searches to the new index <span class="sub">coverage-gated<span class="api-crumb"> · POST /v1/admin/reembed/cutover</span></span></h2>' +
        '<div class="note">Flips recall queries to the rebuilt index. Below 100% readiness the server refuses ' +
          "unless you explicitly force it" +
          '<span class="api-crumb"> · 409</span>. Switching back to the old index is always safe — its data ' +
          "still exists, so no gate applies.</div>" +
        '<div id="mig-route-state" style="margin-top:8px"></div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:12px">' +
          '<button class="good" id="mig-cutover">Switch to the new index…</button>' +
          '<button id="mig-rollback">Switch back to the old index…</button>' +
        "</div>" +
        '<div class="dc-meta api-crumb-block">dense route v1→v2 cutover · embedding_route() has no GET — the live route is not readable over HTTP</div>' +
      "</div>" +

      /* 3 · briefs */
      '<div class="card">' +
        '<h2>3 · Refresh entity summaries <span class="sub"><span class="api-crumb">POST /v1/admin/briefs/refresh?tenant=</span></span></h2>' +
        '<div class="note">After a rebuild, re-computes every <b>stale</b> entity summary for the active space ' +
          "so downstream reads stay fresh. Summaries that are already current are left alone.</div>" +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><button id="mig-briefs">Refresh summaries</button></div>' +
        "</div>" +
        '<div id="mig-briefs-out"></div>' +
      "</div>" +

      /* cutover confirm dialog */
      '<div class="dialog-backdrop" id="mig-cutover-dialog"><div class="dialog" style="max-width:600px">' +
        '<h3 id="mig-cut-title">Switch the search index</h3>' +
        '<div class="note" id="mig-cut-stmt"></div>' +
        '<div class="card" id="mig-cut-force-card" style="margin-top:10px;display:none">' +
          '<div class="note" style="margin-bottom:8px"><b>Readiness is below 100% (or unmeasured).</b> ' +
            "The server refuses a plain switch<span class=\"api-crumb\"> · 409</span>. Forcing it flips anyway — items not yet rebuilt " +
            "<b>fall back to keyword-only search</b> until the rebuild finishes. An explicit, acknowledged " +
            "degradation, never a silent one.</div>" +
          '<label class="tight" style="display:flex;gap:8px;align-items:center">' +
            '<input type="checkbox" id="mig-cut-force" style="width:auto;min-width:0">' +
            "<span>I understand some items will fall back to keyword-only search, and I want to force the switch.</span>" +
          "</label>" +
        "</div>" +
        '<div class="err" id="mig-cut-err"></div>' +
        '<div class="actions">' +
          '<button class="primary" id="mig-cut-confirm">Switch</button>' +
          '<button id="mig-cut-cancel">Cancel</button>' +
        "</div>" +
      "</div></div>";

    wireRebuild();
    wireCutover();
    wireBriefs();
    paintCoverage(null);
    paintRouteState();
  }

  /* -------------------------------------------------- scope for writes */
  // Fail closed: with no active tenant and "all tenants" unchecked we REFUSE
  // instead of silently widening a write to every tenant.
  function writeScope() {
    if (el("mig-global").checked) return { global: true };
    var t = V.tenant() || "";
    if (t) return { tenant: t };
    return null;
  }
  function scopeSentence(scope) {
    return scope.global ? "<b>all spaces</b> (global)" : "space " + V.refSpan(scope.tenant);
  }
  function noScopeError() {
    return new Error(
      "no active space — set one in the session bar, or tick “All spaces” to run globally (this screen never widens a write silently)");
  }

  /* ------------------------------------------------- coverage painting */
  // Honest readiness only: determinate bar when the total is known; total==0
  // is its own state ("nothing to rebuild"); unknown → striped, no number.
  function paintCoverage(cov) {
    var barEl = el("mig-cov-bar"), statEl = el("mig-cov-stat");
    if (!barEl || !statEl) return;
    if (!cov) {
      barEl.innerHTML = '<div class="bar indet"></div>';
      statEl.innerHTML = '<span class="note">unmeasured — readiness is only reported after a rebuild batch runs, ' +
        "and running a batch does real rebuild work (there is no look-without-touching check). " +
        "Use “Do one batch” to measure. No percentage is invented.</span>";
      return;
    }
    if (cov.total == null) {
      barEl.innerHTML = '<div class="bar indet"></div>';
      statEl.innerHTML = '<span class="note">' + V.esc(cov.covered == null ? "?" : cov.covered) +
        " text chunks rebuilt · total unknown — no percentage is invented</span>";
      return;
    }
    if (cov.total <= 0) {
      barEl.innerHTML = '<div class="bar completed"><i style="width:100%"></i></div>';
      statEl.innerHTML = V.stateChip("ok", "nothing to rebuild") +
        ' <span class="note">no text chunks exist for this scope — complete by definition, not 0%</span>';
      return;
    }
    var pct = Math.max(0, Math.min(100, (cov.covered / cov.total) * 100));
    var complete = coverageComplete(cov);
    barEl.innerHTML = '<div class="bar' + (complete ? " completed" : "") +
      '"><i style="width:' + pct.toFixed(1) + '%"></i></div>';
    statEl.innerHTML =
      "<b>" + V.esc(cov.covered) + "</b> of <b>" + V.esc(cov.total) + "</b> text chunks rebuilt (" +
      pct.toFixed(1) + "%)" +
      (complete ? " · " + V.stateChip("ok", "100% — ready to switch") : "") +
      ' <span class="asof">as of the last server response</span>';
  }

  /* ------------------------------------------------ route-state painting */
  function paintRouteState() {
    var wrap = el("mig-route-state");
    if (!wrap) return;

    var routeLine;
    if (lastCutover) {
      var isV2 = lastCutover.route === "v2";
      routeLine = "<dt>Live index now</dt><dd>" +
        V.stateChip("ok", isV2 ? "new index" : "old index") + " " + V.refSpan(lastCutover.route) +
        ' <span class="note">as flipped by this session at ' + V.esc(V.fmtTime(lastCutover.at)) +
        (lastCutover.forced ? " — <b>forced below 100%</b>" : "") +
        (lastCutover.tenant ? " · space " + V.esc(lastCutover.tenant) : " · all spaces") +
        "</span></dd>";
    } else {
      // The honest seam: no GET exists for the live route; we will not guess.
      routeLine = "<dt>Live index now</dt><dd>" + V.stateChip("off", "not known yet") +
        ' <span class="note">the console only learns which index is live when you switch it from this ' +
        "screen, and no switch has happened this session. A server that has never been switched serves " +
        "the old index." +
        "</span>" + '<span class="api-crumb"> ' + V.refSpan("embedding_route() — storage-only, no HTTP GET") + "</span></dd>";
    }

    var covLine;
    if (lastCoverage == null) {
      covLine = "<dt>Readiness gate</dt><dd>" + V.stateChip("off", "unmeasured") +
        ' <span class="note">run a rebuild batch first — the server refuses an unforced switch below 100%<span class="api-crumb"> · 409</span></span></dd>';
    } else if (lastCoverage.total == null) {
      covLine = "<dt>Readiness gate</dt><dd>" + V.stateChip("off", "total unknown") + "</dd>";
    } else if (coverageComplete(lastCoverage)) {
      covLine = "<dt>Readiness gate</dt><dd>" + V.stateChip("ok", "open — 100% ready") +
        (lastCoverage.total <= 0
          ? ' <span class="note">nothing to rebuild — the gate is satisfied by definition</span>'
          : ' <span class="note">' + V.esc(lastCoverage.covered) + " / " + V.esc(lastCoverage.total) + "</span>") +
        "</dd>";
    } else {
      var pct = Math.max(0, Math.min(100, (lastCoverage.covered / lastCoverage.total) * 100));
      covLine = "<dt>Readiness gate</dt><dd>" +
        V.stateChip("attn", pct.toFixed(1) + "% — server refuses without force") +
        ' <span class="note">' + V.esc(lastCoverage.covered) + " / " + V.esc(lastCoverage.total) + "</span></dd>";
    }

    wrap.innerHTML = '<dl class="kv">' + routeLine + covLine + "</dl>";
  }

  /* --------------------------------------------------- rebuild (batches) */
  function wireRebuild() {
    function batchSize() {
      var n = parseInt(el("mig-batch").value, 10);
      if (isNaN(n) || n < 1) n = 1;
      if (n > 10000) n = 10000;
      return n;
    }
    function modelId() { return el("mig-model").value.trim() || DEFAULT_MODEL; }
    function setRunButtons(running) {
      el("mig-run").disabled = running;
      el("mig-run-one").disabled = running;
      el("mig-run-stop").disabled = !running;
    }

    async function runOneBatch(scope) {
      var body = { model: modelId(), batch: batchSize() };
      if (!scope.global) body.tenant = scope.tenant; // omit → all tenants
      var res = await V.api("/v1/admin/reembed/batch", { admin: true, json: body });
      if (res && res.coverage) {
        lastCoverage = res.coverage;
        paintCoverage(res.coverage);
        paintRouteState();
      }
      return res;
    }

    el("mig-run").onclick = async function () {
      if (looping) return;
      V.clearErr("mig-err");
      var scope = writeScope();
      if (!scope) { V.err("mig-err", noScopeError()); return; }
      looping = true;
      stopRequested = false;
      setRunButtons(true);
      var batches = 0, written = 0, scanned = 0;
      try {
        for (;;) {
          var res = await runOneBatch(scope);
          batches++;
          written += (res && res.written) || 0;
          scanned += (res && res.scanned) || 0;
          el("mig-run-status").textContent =
            batches + " batch" + (batches === 1 ? "" : "es") + " · " +
            written + " rebuilt · " + scanned + " scanned";
          // `done` = the server found no pending items this batch — the honest
          // terminal signal, not a client-side % guess.
          if (!res || res.done) {
            el("mig-run-status").textContent += " · done (no pending items)";
            break;
          }
          if (stopRequested) {
            el("mig-run-status").textContent += " · stopped by operator";
            break;
          }
        }
      } catch (e) {
        V.err("mig-err", e); // incl. the verbatim 503 on a sparse-only server
      } finally {
        looping = false;
        stopRequested = false;
        setRunButtons(false);
      }
    };

    el("mig-run-stop").onclick = function () {
      if (looping) {
        stopRequested = true;
        el("mig-run-stop").disabled = true;
        el("mig-run-status").textContent += " · stopping after this batch…";
      }
    };

    el("mig-run-one").onclick = async function () {
      if (looping) return;
      V.clearErr("mig-err");
      var scope = writeScope();
      if (!scope) { V.err("mig-err", noScopeError()); return; }
      setRunButtons(true);
      try {
        var res = await runOneBatch(scope);
        el("mig-run-status").textContent =
          "one batch · " + ((res && res.written) || 0) + " rebuilt · " +
          ((res && res.scanned) || 0) + " scanned" +
          (res && res.done ? " · done (no pending items)" : "");
      } catch (e) {
        V.err("mig-err", e);
      } finally {
        setRunButtons(false);
      }
    };
  }

  /* --------------------------------------------- backfill (auto-loaded) */
  function bfChip(state) {
    var s = String(state || "").toLowerCase();
    if (s === "completed") return V.stateChip("ok", "done");
    if (s === "failed") return V.stateChip("fail", "failed");
    if (s === "paused") return V.stateChip("wait", "paused");
    return V.stateChip("wait", s || "running");
  }

  function bfBar(run) {
    var state = String(run.state || "").toLowerCase();
    var total = run.total, processed = run.processed || 0;
    if (total != null && total > 0) {
      var pct = Math.max(0, Math.min(100, (processed / total) * 100));
      var cls = (state === "completed" || state === "failed" || state === "paused") ? " " + state : "";
      return '<div class="bar' + cls + '"><i style="width:' + pct.toFixed(1) + '%"></i></div>' +
        '<span class="note">' + pct.toFixed(1) + "% · " + V.esc(processed) + " / " + V.esc(total) + "</span>";
    }
    // No declared total → striped track, never a fabricated percentage.
    return '<div class="bar indet"></div>' +
      '<span class="note">' + V.esc(processed) + " processed · total unknown</span>";
  }

  // Time-left only for a running job with a known total and forward progress.
  function bfEta(run) {
    var state = String(run.state || "").toLowerCase();
    var total = run.total, processed = run.processed || 0;
    if (state !== "running" || total == null || total <= 0 || processed <= 0 || processed >= total) {
      return '<span class="note" title="time-left is shown only for a running job with a known total and forward progress">—</span>';
    }
    var elapsed = new Date(run.updated_at).getTime() - new Date(run.started_at).getTime();
    if (!(elapsed > 0)) return '<span class="note" title="not enough elapsed time to project honestly">—</span>';
    var rate = processed / elapsed;
    if (!(rate > 0)) return '<span class="note">—</span>';
    return '<span title="projected from processed/elapsed at the last progress post — an estimate, not a promise">~' +
      V.esc(V.fmtMs((total - processed) / rate)) + " left</span>";
  }

  function paintNoTenant() {
    var out = el("mig-bf-out");
    if (!out) return;
    el("mig-state").innerHTML = V.stateChip("off", "no space");
    el("mig-asof").textContent = "";
    out.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a space</div>' +
        '<div class="et-body">Backfill progress and summary refresh are per-space. Paste a space id in the ' +
          "session bar, or mint a scope handle to adopt one. (The rebuild and switch above can still run " +
          "globally via “All spaces”.)</div>" +
        '<div class="et-actions"><button class="primary" id="mig-mint">Mint a scope handle</button></div>' +
      "</div>";
    el("mig-mint").onclick = function () { V.openMint(); };
  }

  async function refreshBackfill(tenant) {
    var out = el("mig-bf-out");
    if (!out) return;
    if (!tenant) { paintNoTenant(); return; }
    V.clearErr("mig-err");
    el("mig-state").innerHTML = V.stateChip("wait", "loading");
    try {
      var runs = await V.api(
        "/v1/admin/backfill?tenant_id=" + encodeURIComponent(tenant), { admin: true }) || [];
      var failed = 0, running = 0;
      runs.forEach(function (r) {
        var s = String(r.state || "").toLowerCase();
        if (s === "failed") failed++;
        else if (s !== "completed" && s !== "paused") running++;
      });
      el("mig-state").innerHTML =
        failed ? V.stateChip("fail", failed + " source" + (failed === 1 ? "" : "s") + " failed")
        : running ? V.stateChip("wait", running + " backfill" + (running === 1 ? "" : "s") + " running")
        : runs.length ? V.stateChip("ok", "all backfills settled")
        : V.stateChip("ok", "no backfill activity");
      el("mig-asof").textContent = "checked " + nowStamp();

      if (!runs.length) {
        out.innerHTML =
          '<div class="empty-teach sp-a">' +
            '<div class="et-title">No backfill activity yet</div>' +
            '<div class="et-body">A source appears here once its ingest side posts progress — an empty list ' +
              "is not an error. Connect a source to start pulling in history.</div>" +
            '<div class="et-actions"><button class="primary" id="mig-open-sources">Open Sources &amp; freshness</button></div>' +
          "</div>";
        el("mig-open-sources").onclick = function () { V.show("sources"); };
        return;
      }

      var rows = runs.map(function (r) {
        return "<tr>" +
          "<td><b>" + V.esc(r.source || "no name on record") + "</b><br>" + V.refSpan(r.run_id) + "</td>" +
          "<td>" + bfChip(r.state) + "</td>" +
          '<td style="min-width:180px">' + bfBar(r) + "</td>" +
          "<td>" + bfEta(r) + "</td>" +
          "<td>" + (r.error ? '<span class="note">' + V.esc(r.error) + "</span>" : '<span class="note">—</span>') + "</td>" +
          "<td>" + V.esc(r.updated_at ? V.timeAgo(r.updated_at) : "—") + "</td>" +
          "</tr>";
      }).join("");
      out.innerHTML =
        '<div class="tablewrap"><table><thead><tr>' +
          "<th>source</th><th>state</th><th>progress</th><th>time left</th><th>last error</th><th>updated</th>" +
        "</tr></thead><tbody>" + rows + "</tbody></table></div>";
    } catch (e) {
      // Label the failure: only the backfill check failed, not the upgrade.
      el("mig-state").innerHTML = V.stateChip("fail", "backfill check failed");
      V.err("mig-err", e);
    }
  }

  /* --------------------------------------------------------- cutover */
  function wireCutover() {
    var cutDlg = V.dialog("mig-cutover-dialog");
    var pendingRoute = "v2";
    var pendingScope = null;

    function openCutover(route) {
      V.clearErr("mig-cut-err");
      var scope = writeScope();
      if (!scope) { V.err("mig-err", noScopeError()); return; }
      pendingRoute = route;
      pendingScope = scope;
      var toV2 = route === "v2";
      el("mig-cut-title").textContent = toV2 ? "Switch to the new index" : "Switch back to the old index";
      var forceCard = el("mig-cut-force-card");
      el("mig-cut-force").checked = false;

      if (toV2) {
        el("mig-cut-stmt").innerHTML =
          "Point search queries at the <b>new index</b> for " + scopeSentence(scope) + "." +
          '<span class="api-crumb"> ' + V.refSpan("route=v2 · recall/brief read embedding_v2") + "</span>";
        // The force acknowledgment appears ONLY when readiness is sub-100% or
        // unmeasured — when the server is the authority and would 409.
        var measured = lastCoverage != null && lastCoverage.total != null;
        forceCard.style.display = (measured && coverageComplete(lastCoverage)) ? "none" : "";
      } else {
        forceCard.style.display = "none";
        el("mig-cut-stmt").innerHTML =
          "Point search queries back at the <b>old index</b> for " + scopeSentence(scope) + ". " +
          "Always safe — the old index still exists, so no gate applies." + '<span class="api-crumb"> ' + V.refSpan("route=v1 · un-gated rollback") + "</span>";
      }
      cutDlg.open();
    }

    el("mig-cutover").onclick = function () { openCutover("v2"); };
    el("mig-rollback").onclick = function () { openCutover("v1"); };
    el("mig-cut-cancel").onclick = function () { cutDlg.close(); };

    el("mig-cut-confirm").onclick = async function () {
      V.clearErr("mig-cut-err");
      var scope = pendingScope || writeScope();
      if (!scope) { V.err("mig-cut-err", noScopeError()); return; }
      var toV2 = pendingRoute === "v2";
      var forceShown = el("mig-cut-force-card").style.display !== "none";
      var force = toV2 && forceShown && el("mig-cut-force").checked;
      // Omission refuses: if the acknowledgment is showing and unchecked, we
      // refuse client-side instead of firing a POST the server will 409.
      if (toV2 && forceShown && !force) {
        V.err("mig-cut-err", new Error(
          "readiness is below 100% (or unmeasured) — tick the acknowledgment to force the switch, or Cancel and finish the rebuild first"));
        return;
      }
      var body = { route: pendingRoute, force: force };
      if (!scope.global) body.tenant = scope.tenant;
      var btn = el("mig-cut-confirm");
      btn.disabled = true;
      try {
        var res = await V.api("/v1/admin/reembed/cutover", { admin: true, json: body });
        // Record what WE flipped — the only honest source of "live route".
        lastCutover = {
          route: (res && res.route) || pendingRoute,
          tenant: (res && res.tenant) || (scope.global ? "" : scope.tenant),
          forced: !!(res && res.forced),
          at: Date.now(),
        };
        if (res && res.coverage) { lastCoverage = res.coverage; paintCoverage(res.coverage); }
        paintRouteState();
        cutDlg.close();
      } catch (e) {
        // A 409 here is the readiness gate doing its job — surfaced verbatim.
        V.err("mig-cut-err", e);
      } finally {
        btn.disabled = false;
      }
    };
  }

  /* ---------------------------------------------------------- briefs */
  function wireBriefs() {
    el("mig-briefs").onclick = async function () {
      var out = el("mig-briefs-out");
      out.innerHTML = "";
      var tenant = V.tenant() || "";
      if (!tenant) {
        // briefs/refresh REQUIRES a tenant (AdminTenantParam) — fail closed
        // with the reason instead of firing a doomed POST.
        out.innerHTML = '<div class="err on">summary refresh needs a space — set one in the session bar</div>';
        return;
      }
      var btn = el("mig-briefs");
      btn.disabled = true;
      try {
        var res = await V.api(
          "/v1/admin/briefs/refresh?tenant=" + encodeURIComponent(tenant),
          { admin: true, json: {} });
        var n = res && typeof res.refreshed === "number" ? res.refreshed : null;
        out.innerHTML =
          '<div class="note" style="margin-top:8px">' + V.stateChip("ok", "refreshed") + " " +
          (n == null
            ? "summary refresh requested"
            : n === 0
              ? "nothing was stale — 0 summaries needed refreshing"
              : "<b>" + V.esc(n) + "</b> stale summar" + (n === 1 ? "y" : "ies") + " refreshed") +
          ' <span class="asof">' + nowStamp() + "</span></div>";
      } catch (e) {
        out.innerHTML = '<div class="err on">' + V.esc((e && e.message) || String(e)) + "</div>";
      } finally {
        btn.disabled = false;
      }
    };
  }
})();
