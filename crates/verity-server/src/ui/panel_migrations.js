"use strict";
/* ==========================================================================
   panel_migrations.js — Search model upgrade
   --------------------------------------------------------------------------
   THE LAW (UI-ACTIONS §0), applied:
     • whether-you-need-to-act-now is answered FIRST: a calm opening banner
       ("you probably don't need to do anything here") shows before any
       machinery, and the three-step flow stays collapsed behind an explicit
       "Start a search-model upgrade" affordance;
     • plain language first — "Build the new index", "Switch search to the new
       index", "Refresh entity summaries"; every glossed term (embedding /
       re-embed / cutover / coverage / vector / brief) is defined once in
       visible copy, with the raw term / endpoint kept to api-crumb only;
     • every number is labeled with what it counts ("X of Y text chunks
       re-indexed (Z%)");
     • empty / loading / error states TEACH; backfill autoloads once a space
       is known;
     • honesty kept verbatim: readiness is "not measured yet" until a rebuild
       batch runs (no read-only coverage check), the live route is "not known
       yet" unless THIS session switched it (no GET exists), determinate bars
       only with a known total, total==0 its own state, honest ETA;
     • fail-closed kept: coverage-gated cutover (server 409 rendered plain),
       force only behind an explicit checkbox acknowledgment (omission refuses
       client-side), writes refuse when no space is named rather than silently
       going global; the "Switch to the new index" button is disabled until
       readiness reads 100%, with the force path living only inside the dialog.
   Endpoints verified against crates/verity-server/src/{main,backfill}.rs.
   Zero LLM / zero live-ReBAC calls from this panel.
   ========================================================================== */
(function () {
  var V = window.Verity;

  // Default target model id for the new index; the server registers it on the
  // first batch (idempotent). An honest non-empty default, overridable.
  var DEFAULT_MODEL = "bge-small-en-v1.5";

  /* ------------------------------------------------------------- state */
  var lastCoverage = null;  // { total, covered, fraction } from the last server response
  var lastCutover = null;   // { route, tenant, forced, at } — the only honest "live route" source
  var looping = false;
  var stopRequested = false;
  var stepsRevealed = false; // the machinery starts collapsed; this flips true on "Start…"

  function el(id) { return V.$(id); }
  function nowStamp() { return new Date().toTimeString().slice(0, 8); }

  // Mirror the server's rule (EmbeddingCoverage::is_complete):
  // total==0 OR covered>=total.
  function coverageComplete(cov) {
    if (!cov || cov.total == null) return false;
    return cov.total <= 0 || (cov.covered != null && cov.covered >= cov.total);
  }
  // "Measured" means a batch has actually run and returned a coverage total.
  function coverageMeasured() {
    return lastCoverage != null && lastCoverage.total != null;
  }

  /* ------------------------------------------------------------ register */
  V.register({
    id: "migrations",
    mount: function () {
      var host = el("migrations-mount");
      if (!host) return;
      host.innerHTML =
        '<div class="err" id="mig-err"></div>' +
        buildBanner() +
        '<div id="mig-steps" style="display:none"></div>' +
        buildRelated();
      wireBanner();
      buildSteps(el("mig-steps"));
      wireBackfillRefresh();
      if (!V.tenant()) paintNoTenant();
    },
    // AUTOLOAD — the router runs this when the panel shows and a space is known
    // (and again on space change): the source-history catch-up list is the only
    // loadable read here. Readiness and live route stay honestly
    // "not measured / not known yet" until an operation runs — no read-only
    // endpoint exists for either.
    load: function (_s, tenant) { return refreshBackfill(tenant); },
  });

  /* ------------------------------------------------------ opening banner */
  // Answered FIRST, before any machinery: do you need to act right now?
  function buildBanner() {
    return '' +
      '<div class="card" id="mig-banner">' +
        '<h2>You probably don&rsquo;t need to do anything here.</h2>' +
        '<div class="note">This page is only for the rare job of upgrading the AI model that turns your ' +
          'stored text into the numbers search uses — its <b>embedding model</b> ' +
          '<span class="api-crumb">(embedding = the numeric fingerprint Verity makes of each piece of text ' +
          'so search can match by meaning, not just keywords)</span>. Live search keeps working the whole ' +
          'time, whether or not you ever use this page.</div>' +
        '<div class="note" style="margin-top:10px">' +
          '<b>You need this only if</b> the Verity team told you to move to a newer/better search model, or ' +
          'you&rsquo;re switching off the built-in local model. ' +
          '<b>You do NOT need this</b> to add data, connect a source, fix day-to-day search quality, or catch ' +
          'a connector up on history.</div>' +
        '<div class="note" style="margin-top:10px">' + V.stateChip("off", "one honest caveat") +
          ' This console can only tell you an upgrade is <b>underway</b> if it was started from this browser ' +
          'session &mdash; it can&rsquo;t yet read the live search index or rebuild progress from the server ' +
          '<span class="api-crumb">(no read-only GET for the live route or coverage)</span>. So on a fresh ' +
          'load it can&rsquo;t prove a migration is or isn&rsquo;t running elsewhere.</div>' +
        '<div id="mig-session-state" style="margin-top:10px"></div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:12px">' +
          '<button class="primary" id="mig-start">Start a search-model upgrade</button>' +
          '<button id="mig-what">What is this?</button>' +
        '</div>' +
        '<div class="note" id="mig-what-body" style="display:none;margin-top:12px">' +
          '<b>The 1&mdash;2&mdash;3 of a search-model upgrade:</b><br>' +
          '<b>1. Build the new index.</b> Re-encode every stored text chunk with the new model into a ' +
          'separate, second index, in the background. Live search never changes while this runs.<br>' +
          '<b>2. Switch search to the new index.</b> Point live searches at the new index &mdash; only ' +
          'allowed once the new index covers 100% of your searchable memories, so nothing quietly drops out ' +
          'of search.<br>' +
          '<b>3. Refresh entity summaries.</b> Recompute the short auto-written blurbs Verity keeps for each ' +
          'person/company, which a model change can leave out of date.<br>' +
          '<span class="note">Re-encoding every chunk takes real compute, so this is usually a planned, ' +
          'multi-hour, one-in-a-blue-moon job done with guidance. If nobody told you &ldquo;we&rsquo;re ' +
          'upgrading the search model,&rdquo; you&rsquo;re probably not supposed to be here.</span>' +
        '</div>' +
      '</div>';
  }

  function wireBanner() {
    el("mig-start").onclick = function () { revealSteps(true); };
    el("mig-what").onclick = function () {
      var body = el("mig-what-body");
      var open = body.style.display !== "none";
      body.style.display = open ? "none" : "";
      el("mig-what").textContent = open ? "What is this?" : "Hide";
    };
    paintSessionState();
  }

  // Surface remembered session state prominently on the banner: if THIS session
  // started a rebuild or performed a switch, say so (and auto-reveal the steps
  // so the operator can continue). Otherwise stay calm and collapsed.
  function paintSessionState() {
    var wrap = el("mig-session-state");
    if (!wrap) return;
    var bits = [];
    if (lastCutover) {
      var toNew = lastCutover.route === "v2";
      bits.push(V.stateChip(toNew ? "attn" : "ok",
        toNew ? "you switched search to the NEW index" : "you switched search back to the OLD index") +
        ' <span class="note">at ' + V.esc(V.fmtTime(lastCutover.at)) + " this session" +
        (lastCutover.forced ? " — <b>forced below 100%</b>" : "") +
        (lastCutover.tenant ? " · space " + V.esc(lastCutover.tenant) : " · all spaces") +
        "</span>");
    }
    if (coverageMeasured()) {
      bits.push('<span class="note">A rebuild has run this session &mdash; readiness is measured below.</span>');
    }
    if (!bits.length) { wrap.innerHTML = ""; return; }
    wrap.innerHTML = '<div class="note"><b>This session:</b><br>' + bits.join("<br>") + "</div>";
  }

  function revealSteps(scroll) {
    stepsRevealed = true;
    var steps = el("mig-steps");
    if (steps) steps.style.display = "";
    var start = el("mig-start");
    if (start) start.textContent = "Steps shown below";
    if (scroll && steps && steps.scrollIntoView) {
      try { steps.scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { /* ok */ }
    }
  }

  /* ------------------------------------------------------------- steps */
  function buildSteps(host) {
    if (!host) return;
    host.innerHTML =
      /* STEP 1 · build the new index */
      '<div class="card">' +
        '<h2>Step 1 &mdash; Build the new index ' +
          '<span class="sub">creates a second, separate index<span class="api-crumb"> · re-embed every ' +
          'stored text chunk with the new model → embedding_v2 · POST /v1/admin/reembed/batch</span></span> ' +
          '<span id="mig-encoder-chip"></span></h2>' +
        '<div class="note">Re-encodes your stored text with the new model in the background, into a ' +
          '<b>brand-new index alongside the current one</b>. Live search keeps using the current index, so ' +
          'search quality never dips while this runs. It re-reads the canonical text Verity already stored ' +
          '&mdash; it <b>never re-downloads source data</b>. Safe to stop anytime: it picks up exactly where ' +
          'it left off.</div>' +
        '<div class="note" style="margin-top:8px">This only works if your Verity server was set up to make ' +
          'its own text fingerprints. Some servers are keyword-search-only and can&rsquo;t &mdash; if so, ' +
          '&ldquo;Rebuild&rdquo; stops and shows you the server&rsquo;s exact reason' +
          '<span class="api-crumb"> · 503</span>.</div>' +
        '<div class="row" style="margin-top:10px">' +
          '<div class="tight"><label for="mig-model">The new model you&rsquo;re upgrading to ' +
            '<span class="note">(the model id to build with)</span></label> ' +
            '<input type="text" id="mig-model" class="field" value="' + V.esc(DEFAULT_MODEL) + '" size="24" spellcheck="false"></div>' +
          '<div class="tight"><label for="mig-batch">Text chunks per batch ' +
            '<span class="note">(1&ndash;10000 &mdash; bigger = faster but heavier load; leave at 512 if unsure)</span></label> ' +
            '<input type="number" id="mig-batch" class="field" min="1" max="10000" step="1" value="512"></div>' +
          '<div class="tight"><label style="display:flex;gap:8px;align-items:center;margin-top:18px">' +
            '<input type="checkbox" id="mig-global" style="width:auto;min-width:0">' +
            '<span>All spaces <span class="note">(unchecked = the active space only; a space is one tenant. ' +
            'Ticking this re-indexes <b>every tenant&rsquo;s</b> data)</span><span class="api-crumb"> ' +
            '· space = tenant</span></span></label></div>' +
        "</div>" +
        '<div class="note" style="margin-top:12px">The new model must produce the <b>same-size fingerprint</b> ' +
          'as your current one (384 numbers per chunk today). A true change of fingerprint size is a much ' +
          'bigger, separate operation<span class="api-crumb"> · dims must match (384-d today); a true dim ' +
          'change needs docs/EMBEDDING_MIGRATION.md</span>.</div>' +
        '<div style="margin-top:14px"><b>How much of your data has been re-indexed with the new model</b> ' +
          '<span class="note">(this must reach 100% before you can safely switch in Step 2)</span></div>' +
        '<div id="mig-cov-bar" style="margin-top:6px"></div>' +
        '<div id="mig-cov-stat"></div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:12px">' +
          '<button id="mig-run-one" class="primary" title="Encode exactly one batch, then stop — a careful step-through, and the only way to measure readiness.">Do one batch (also measures readiness)</button>' +
          '<button id="mig-run" title="Keep running batches automatically until the server reports nothing left to encode.">Rebuild until done</button>' +
          '<button id="mig-run-stop" disabled title="Stop after the batch currently in flight finishes — never mid-write.">Stop after this batch</button>' +
          '<span class="asof" id="mig-run-status"></span>' +
        "</div>" +
      "</div>" +

      /* STEP 2 · cutover */
      '<div class="card">' +
        '<h2>Step 2 &mdash; Switch search to the new index ' +
          '<span class="sub">only allowed once every memory is re-indexed<span class="api-crumb"> · the ' +
          'coverage-gated cutover · POST /v1/admin/reembed/cutover</span></span></h2>' +
        '<div class="note">Points live searches at the new index. Verity <b>refuses this until the new index ' +
          'covers 100% of your searchable memories</b> &mdash; switching to a half-built index would quietly ' +
          'drop the not-yet-rebuilt memories to keyword-only search, so search would silently get worse for ' +
          'part of your data. That gate is a safety rail, not a bug' +
          '<span class="api-crumb"> · server returns 409 below 100%</span>. Switching back to the old ' +
          'index is always safe &mdash; the old index still exists, so no gate applies.</div>' +
        '<div class="note" style="margin-top:8px">Forcing the switch below 100% <b>is</b> possible but ' +
          'discouraged &mdash; it lives behind an explicit acknowledgment in the dialog below.</div>' +
        '<div id="mig-route-state" style="margin-top:10px"></div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:12px">' +
          '<button class="good" id="mig-cutover" disabled>Switch to the new index&hellip;</button>' +
          '<button id="mig-rollback" title="Always safe — the old index still exists.">Switch back to the old index&hellip;</button>' +
        "</div>" +
        '<div class="note" id="mig-cutover-hint" style="margin-top:6px"></div>' +
      "</div>" +

      /* STEP 3 · briefs */
      '<div class="card">' +
        '<h2>Step 3 &mdash; Refresh entity summaries ' +
          '<span class="sub">recompute the stale per-entity blurbs<span class="api-crumb"> · briefs = the ' +
          'cached one-call &ldquo;current state of this entity&rdquo; summaries · ' +
          'POST /v1/admin/briefs/refresh?tenant=</span></span></h2>' +
        '<div class="note">Entity summaries are the short auto-written blurbs Verity keeps for each ' +
          'person/company. After the model change, this recomputes only the ones that are now <b>out of ' +
          'date</b>, for the active space &mdash; already-current summaries are left alone. It&rsquo;s a ' +
          'nice-to-have cleanup after switching, not a step that blocks search.</div>' +
        '<div class="row" style="margin-top:10px">' +
          '<div class="tight"><button id="mig-briefs">Refresh summaries</button></div>' +
        "</div>" +
        '<div id="mig-briefs-out"></div>' +
      "</div>" +

      /* cutover confirm dialog */
      '<div class="dialog-backdrop" id="mig-cutover-dialog"><div class="dialog" style="max-width:620px">' +
        '<h3 id="mig-cut-title">Switch the search index</h3>' +
        '<div class="note" id="mig-cut-stmt"></div>' +
        '<div class="card" id="mig-cut-force-card" style="margin-top:10px;display:none">' +
          '<h3 style="margin-top:0">Force the switch below 100%?</h3>' +
          '<div class="note" style="margin-bottom:8px">The new index isn&rsquo;t 100% built yet ' +
            '<span id="mig-cut-force-pct"></span>, so the server refuses a plain switch' +
            '<span class="api-crumb"> · 409</span>. If you force it anyway, then <b>until the rebuild ' +
            'finishes, searches over the not-yet-rebuilt memories will be less accurate</b> &mdash; keyword ' +
            'matching only, with no meaning-based match. This is a deliberate, acknowledged trade-off, never ' +
            'a silent one.</div>' +
          '<label class="tight" style="display:flex;gap:8px;align-items:center">' +
            '<input type="checkbox" id="mig-cut-force" style="width:auto;min-width:0">' +
            "<span>I understand some memories will fall back to keyword-only search until the rebuild " +
            "finishes, and I want to force the switch.</span>" +
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

  /* ------------------------------------------------ related: backfill */
  // Fenced HARD below the three steps and OUTSIDE #mig-steps, so it can never
  // read as "step 1.5". It is auto-loaded whether or not the steps are revealed
  // (it's genuinely useful to watch data landing during a long rebuild), but it
  // is verbally and visually quarantined and never numbered. The word
  // "backfill" appears ONLY here, glossed, and never in the migration steps.
  function buildRelated() {
    return '' +
      '<div class="card" id="mig-related">' +
        '<h2>Source history catch-up &mdash; <b>not</b> part of the search-model upgrade ' +
          '<span class="sub">latest connector run per source<span class="api-crumb"> · &ldquo;backfill&rdquo; ' +
          '· GET /v1/admin/backfill</span></span> ' +
          '<span id="mig-state"></span> <span class="asof" id="mig-asof"></span> ' +
          '<button id="mig-refresh" style="margin-left:8px">Refresh catch-up status</button></h2>' +
        '<div class="note">This shows connected data sources pulling in their <b>history</b> &mdash; ' +
          'connectors catching a source up on its older records. It has <b>nothing to do</b> with the ' +
          'search-model upgrade above; it&rsquo;s shown here only so you can watch data still landing during a ' +
          'long rebuild. Progress is a <b>best-effort signal, not an exact ledger</b>; a bar is exact only ' +
          'when the source declared a total.</div>' +
        '<div id="mig-bf-out" style="margin-top:8px"></div>' +
      "</div>";
  }

  function wireBackfillRefresh() {
    el("mig-refresh").onclick = function () {
      var t = V.tenant();
      if (t) refreshBackfill(t); else paintNoTenant();
    };
  }

  /* -------------------------------------------------- scope for writes */
  // Fail closed: with no active space and "All spaces" unchecked we REFUSE
  // instead of silently widening a write to every tenant.
  function writeScope() {
    if (el("mig-global").checked) return { global: true };
    var t = V.tenant() || "";
    if (t) return { tenant: t };
    return null;
  }
  function scopeSentence(scope) {
    return scope.global ? "<b>all spaces</b> (every tenant)" : "space " + V.refSpan(scope.tenant);
  }
  function noScopeError() {
    return new Error(
      "no active space — set one in the session bar, or tick “All spaces” to run across every " +
      "tenant (this screen never widens a write silently)");
  }

  /* ------------------------------------------------- coverage painting */
  // Honest readiness only: determinate bar when the total is known; total==0 is
  // its own state ("nothing to re-index"); not-yet-measured → striped, no
  // number. Every painted number is labeled with what it counts.
  function paintCoverage(cov) {
    var barEl = el("mig-cov-bar"), statEl = el("mig-cov-stat");
    if (!barEl || !statEl) return;
    if (!cov) {
      barEl.innerHTML = '<div class="bar indet"></div>';
      statEl.innerHTML = '<span class="note"><b>Not measured yet.</b> We can&rsquo;t check progress without ' +
        "doing some rebuild work — there&rsquo;s no look-without-touching check — so this stays " +
        "blank until you run at least one batch. Use “Do one batch” above to measure. " +
        "No percentage is invented.</span>";
      return;
    }
    if (cov.total == null) {
      barEl.innerHTML = '<div class="bar indet"></div>';
      statEl.innerHTML = '<span class="note"><b>' + V.esc(cov.covered == null ? "?" : cov.covered) +
        "</b> text chunks re-indexed so far · total unknown — no percentage is invented</span>";
      return;
    }
    if (cov.total <= 0) {
      barEl.innerHTML = '<div class="bar completed"><i style="width:100%"></i></div>';
      statEl.innerHTML = V.stateChip("ok", "nothing to re-index") +
        ' <span class="note">no text chunks exist for this scope — complete by definition, not 0%</span>';
      return;
    }
    var pct = Math.max(0, Math.min(100, (cov.covered / cov.total) * 100));
    var complete = coverageComplete(cov);
    barEl.innerHTML = '<div class="bar' + (complete ? " completed" : "") +
      '"><i style="width:' + pct.toFixed(1) + '%"></i></div>';
    statEl.innerHTML =
      "<b>" + V.esc(cov.covered) + "</b> of <b>" + V.esc(cov.total) + "</b> text chunks re-indexed with the " +
      "new model (" + pct.toFixed(1) + "%)" +
      (complete ? " · " + V.stateChip("ok", "100% — ready to switch in Step 2") : "") +
      ' <span class="asof">as of the last rebuild batch</span>';
  }

  /* ------------------------------------------------ route-state painting */
  function paintRouteState() {
    var wrap = el("mig-route-state");
    if (!wrap) return;

    var routeLine;
    if (lastCutover) {
      var isV2 = lastCutover.route === "v2";
      routeLine = "<dt>Live index now</dt><dd>" +
        V.stateChip(isV2 ? "ok" : "off", isV2 ? "new index" : "old index") +
        ' <span class="note">as switched from this session at ' + V.esc(V.fmtTime(lastCutover.at)) +
        (lastCutover.forced ? " — <b>forced below 100%</b>" : "") +
        (lastCutover.tenant ? " · space " + V.esc(lastCutover.tenant) : " · all spaces") +
        "</span>" +
        '<span class="api-crumb"> ' + V.refSpan("route=" + lastCutover.route) + "</span></dd>";
    } else {
      // The honest seam: no GET exists for the live route; we will not guess.
      routeLine = "<dt>Live index now</dt><dd>" + V.stateChip("off", "not known yet") +
        ' <span class="note">this console only learns the live index when <b>you</b> switch it here, and no ' +
        "switch has happened this session. It can&rsquo;t read the live index from the server. " +
        "(A server that has never been switched serves the old index.)" +
        "</span>" + '<span class="api-crumb"> ' + V.refSpan("embedding_route() — storage-only, no HTTP GET") + "</span></dd>";
    }

    var covLine;
    if (!coverageMeasured()) {
      covLine = "<dt>Readiness gate</dt><dd>" + V.stateChip("off", "not measured yet") +
        ' <span class="note">run a rebuild batch first (Step 1) — the server refuses an unforced switch ' +
        'below 100%<span class="api-crumb"> · 409</span></span></dd>';
    } else if (coverageComplete(lastCoverage)) {
      covLine = "<dt>Readiness gate</dt><dd>" + V.stateChip("ok", "100% — ready to switch") +
        (lastCoverage.total <= 0
          ? ' <span class="note">nothing to re-index — the gate is satisfied by definition</span>'
          : ' <span class="note"><b>' + V.esc(lastCoverage.covered) + "</b> of <b>" + V.esc(lastCoverage.total) +
            "</b> text chunks covered</span>") +
        "</dd>";
    } else {
      var pct = Math.max(0, Math.min(100, (lastCoverage.covered / lastCoverage.total) * 100));
      covLine = "<dt>Readiness gate</dt><dd>" +
        V.stateChip("attn", pct.toFixed(1) + "% built — server refuses until 100%") +
        ' <span class="note"><b>' + V.esc(lastCoverage.covered) + "</b> of <b>" + V.esc(lastCoverage.total) +
        "</b> text chunks re-indexed</span></dd>";
    }

    wrap.innerHTML = '<dl class="kv">' + routeLine + covLine + "</dl>";

    // Gate the "Switch to the new index" button on measured 100% readiness;
    // the force path lives ONLY inside the dialog (reached via rollback? no —
    // via a still-enabled switch button? no). We keep switch disabled until
    // ready, and expose forcing through a small "force anyway" affordance in the
    // hint so it isn't a surprise but also isn't the default.
    var cutBtn = el("mig-cutover");
    var hint = el("mig-cutover-hint");
    if (cutBtn) {
      var ready = coverageMeasured() && coverageComplete(lastCoverage);
      cutBtn.disabled = !ready;
      cutBtn.title = ready
        ? "The new index covers 100% of your memories — safe to switch."
        : "Available once the rebuild reaches 100% (Step 1).";
      if (hint) {
        if (ready) {
          hint.innerHTML = "";
        } else if (!coverageMeasured()) {
          hint.innerHTML = '<span class="note">&ldquo;Switch to the new index&rdquo; unlocks once a rebuild ' +
            'batch has measured readiness at 100%. Not measured yet — run Step 1 first. ' +
            '<a href="#" id="mig-force-open">Force the switch anyway&hellip;</a> (discouraged).</span>';
        } else {
          hint.innerHTML = '<span class="note">&ldquo;Switch to the new index&rdquo; unlocks at 100% ' +
            're-indexed. <a href="#" id="mig-force-open">Force the switch below 100%&hellip;</a> ' +
            '(discouraged — uncovered memories fall back to keyword-only search).</span>';
        }
        var fo = el("mig-force-open");
        if (fo) fo.onclick = function (e) { e.preventDefault(); openCutoverV2(); };
      }
    }
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
        paintSessionState();
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
            written + " chunks re-indexed · " + scanned + " scanned";
          // `done` = the server found no pending items this batch — the honest
          // terminal signal, not a client-side % guess.
          if (!res || res.done) {
            el("mig-run-status").textContent += " · done (nothing left to re-index)";
            break;
          }
          if (stopRequested) {
            el("mig-run-status").textContent += " · stopped after this batch";
            break;
          }
        }
      } catch (e) {
        V.err("mig-err", e); // incl. the verbatim 503 on a keyword-only server
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
          "one batch · " + ((res && res.written) || 0) + " chunks re-indexed · " +
          ((res && res.scanned) || 0) + " scanned" +
          (res && res.done ? " · done (nothing left to re-index)" : "");
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
        '<span class="note">' + pct.toFixed(1) + "% · " + V.esc(processed) + " of " + V.esc(total) + " records</span>";
    }
    // No declared total → striped track, never a fabricated percentage.
    return '<div class="bar indet"></div>' +
      '<span class="note">' + V.esc(processed) + " records processed · total not declared by this source</span>";
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
        '<div class="et-title">Pick a space to see catch-up progress</div>' +
        '<div class="et-body">Source-history catch-up and summary refresh (Step 3) are per-space (a space is ' +
          "one tenant). Paste a space id in the session bar, or mint a scope handle to adopt one. " +
          "The rebuild and switch above can still run across all spaces via “All spaces”.</div>" +
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
        : running ? V.stateChip("wait", running + " catch-up" + (running === 1 ? "" : "s") + " running")
        : runs.length ? V.stateChip("ok", "all caught up")
        : V.stateChip("ok", "no catch-up activity");
      el("mig-asof").textContent = "checked " + nowStamp();

      if (!runs.length) {
        out.innerHTML =
          '<div class="empty-teach sp-a">' +
            '<div class="et-title">No source catch-up activity yet</div>' +
            '<div class="et-body">A source appears here once its connector posts catch-up progress — an ' +
              "empty list is not an error. Connect a source to start pulling in history. " +
              "(Reminder: this panel is unrelated to the search-model upgrade above.)</div>" +
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
      // Label the failure: only the catch-up check failed, not the upgrade.
      el("mig-state").innerHTML = V.stateChip("fail", "catch-up check failed");
      V.err("mig-err", e);
    }
  }

  /* --------------------------------------------------------- cutover */
  var _openCutover = null; // exposed so the "force anyway" hint link can open it
  function openCutoverV2() { if (_openCutover) _openCutover("v2"); }

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
          "Point live searches at the <b>new index</b> for " + scopeSentence(scope) + ". Once switched, " +
          "search finds things by meaning using the new model." +
          '<span class="api-crumb"> ' + V.refSpan("route=v2 · recall/brief read embedding_v2") + "</span>";
        // The force acknowledgment appears ONLY when readiness is sub-100% or
        // unmeasured — when the server is the authority and would 409.
        var ready = coverageMeasured() && coverageComplete(lastCoverage);
        forceCard.style.display = ready ? "none" : "";
        var pctEl = el("mig-cut-force-pct");
        if (pctEl) {
          if (!coverageMeasured()) {
            pctEl.textContent = "(readiness not measured yet — run a rebuild batch to measure)";
          } else if (lastCoverage.total > 0) {
            var pct = Math.max(0, Math.min(100, (lastCoverage.covered / lastCoverage.total) * 100));
            pctEl.textContent = "(" + pct.toFixed(1) + "% of your memories re-indexed so far)";
          } else {
            pctEl.textContent = "";
          }
        }
      } else {
        forceCard.style.display = "none";
        el("mig-cut-stmt").innerHTML =
          "Point live searches back at the <b>old index</b> for " + scopeSentence(scope) + ". " +
          "Always safe — the old index still exists, so no gate applies." +
          '<span class="api-crumb"> ' + V.refSpan("route=v1 · un-gated rollback") + "</span>";
      }
      cutDlg.open();
    }
    _openCutover = openCutover;

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
          "the new index isn’t ready — tick the acknowledgment to force the switch below 100%, or " +
          "Cancel and finish the rebuild first"));
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
        paintSessionState();
        cutDlg.close();
      } catch (e) {
        // A 409 here is the readiness gate doing its job. Render it plain.
        V.err("mig-cut-err", plainCutoverError(e));
      } finally {
        btn.disabled = false;
      }
    };
  }

  // Turn a raw 409 (or any cutover failure) into the plain-language message
  // the LAW asks for, while still surfacing the server's own reason.
  function plainCutoverError(e) {
    var msg = (e && e.message) || String(e);
    if (/\b409\b/.test(msg) || /coverage|not ready|incomplete/i.test(msg)) {
      var suffix = "";
      if (coverageMeasured() && lastCoverage.total > 0) {
        var pct = Math.max(0, Math.min(100, (lastCoverage.covered / lastCoverage.total) * 100));
        suffix = " — " + pct.toFixed(1) + "% of memories re-indexed so far";
      }
      return new Error("The new index isn’t ready" + suffix +
        ". The server refused the switch so search can’t silently miss the not-yet-rebuilt memories. " +
        "Finish the rebuild, or tick the force acknowledgment above to switch anyway. (Server said: " +
        msg + ")");
    }
    return e;
  }

  /* ---------------------------------------------------------- briefs */
  function wireBriefs() {
    el("mig-briefs").onclick = async function () {
      var out = el("mig-briefs-out");
      out.innerHTML = "";
      var tenant = V.tenant() || "";
      if (!tenant) {
        // briefs/refresh REQUIRES a tenant (AdminTenantParam) — fail closed with
        // the reason instead of firing a doomed POST.
        out.innerHTML = '<div class="err on">Refreshing summaries needs a space — set one in the ' +
          "session bar (a space is one tenant).</div>";
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
          '<div class="note" style="margin-top:8px">' + V.stateChip("ok", "done") + " " +
          (n == null
            ? "summary refresh requested"
            : n === 0
              ? "nothing was stale — 0 summaries needed refreshing"
              : "refreshed <b>" + V.esc(n) + "</b> summar" + (n === 1 ? "y" : "ies")) +
          ' <span class="asof">' + nowStamp() + "</span></div>";
      } catch (e) {
        out.innerHTML = '<div class="err on">' + V.esc((e && e.message) || String(e)) + "</div>";
      } finally {
        btn.disabled = false;
      }
    };
  }
})();
