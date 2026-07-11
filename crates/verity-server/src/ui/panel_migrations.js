"use strict";
/* ==========================================================================
   panel_migrations.js — Screen 7 · Migrations (UI-SPEC §5 Screen 7)
   --------------------------------------------------------------------------
   Reads / actions (every one already exists server-side; verified in main.rs):
     • POST /v1/admin/reembed/batch   — admin; body { model, tenant?, batch }.
       Returns { model, scanned, written, coverage:{total,covered,fraction},
       done }. We LOOP this (each call fills up to `batch` chunks) and after
       every batch repaint the coverage bar from the live server number.
     • GET  /v1/admin/backfill?tenant_id= — admin; latest run per source.
       Same feed the Sources screen reads; reused verbatim honest discipline.
     • POST /v1/admin/reembed/cutover — admin; body { tenant?, route, force }.
       COVERAGE-GATED: route=v2 below 100% → 409 unless force=true. We surface
       the gate state and force only behind an explicit acknowledgment. The
       v2→v1 ROLLBACK is the un-gated inverse (v1 vectors already exist).
     • POST /v1/admin/briefs/refresh?tenant= — admin; refreshes stale briefs
       after a re-embed (the brief text is unchanged, but a refresh re-touches
       staleness so downstream reads are honest).

   HONESTY CONTRACT (SPEC §5c, and the panel's whole reason to exist):
     • Coverage: DETERMINATE bar only when coverage.total is known (>0). A
       genuinely-unknown/zero total shows the striped indeterminate track — we
       NEVER paint a fabricated percentage. total==0 is its own honest state
       ("nothing to embed"), not 0%.
     • Backfill: determinate only when a run's total is known; ETA only for a
       running job with a known total and forward progress.
     • Current dense route: there is NO GET endpoint for it (honest seam). We
       show the LAST cutover this session performed, and otherwise say
       "unknown from the UI — no read endpoint", never a guess.
     • Zero LLM calls, zero live-ReBAC calls from this panel.
   ========================================================================== */
(function () {
  // Default target model id for the v2 column. The server registers it on the
  // first batch (idempotent) and stamps each filled chunk with it. Operator can
  // override in the field; this is just an honest, non-empty default.
  var DEFAULT_MODEL = "bge-small-en-v1.5";

  // The only routes the cutover endpoint accepts (EmbeddingRoute, snake_case).
  // v2 is the migration target (gated); v1 is the rollback (un-gated).
  // ------------------------------------------------------------------------

  Verity.register({
    id: "migrations",
    mount: function (section) {
      var el = Verity.$("migrations-mount");
      if (!el) return;

      // Session-local memory of the last cutover WE performed (honest seam:
      // there is no GET for the current route, so this is all the UI can
      // truthfully say about the live route). Null until a cutover succeeds.
      var lastCutover = null; // { route, tenant, coverage, forced, at }
      // Last coverage number seen from a batch/cutover response, for the bar.
      var lastCoverage = null; // { total, covered, fraction } | null

      /* -- controls / tenant card ------------------------------------------ */
      var controls = document.createElement("div");
      controls.className = "card";
      controls.innerHTML =
        '<h2>Migration target <span class="sub">admin-token · all calls admin-plane</span></h2>' +
        '<div class="row">' +
          '<div class="tight"><label for="mig-tenant">tenant_id ' +
            '<span class="note">(blank = all tenants)</span></label> ' +
            '<input type="text" id="mig-tenant" placeholder="(uses active tenant · blank = global)" spellcheck="false"></div>' +
          '<div class="tight"><label for="mig-model">target model id</label> ' +
            '<input type="text" id="mig-model" class="field" value="' + Verity.esc(DEFAULT_MODEL) + '" spellcheck="false"></div>' +
          '<div class="tight"><label for="mig-batch">batch size ' +
            '<span class="note">(1–10000)</span></label> ' +
            '<input type="number" id="mig-batch" class="field" min="1" max="10000" step="1" value="512"></div>' +
        "</div>" +
        '<div class="note"><em>Dims must match.</em> The v2 column is the same width today (384-d), so this ' +
          're-embeds into <b>embedding_v2</b> under the target model id. A true dim change needs a wider ' +
          'column (docs/EMBEDDING_MIGRATION.md) and is out of scope for this button. This server must have ' +
          'the local encoder built — a sparse-only server returns 503 here, which we surface verbatim.</div>' +
        '<div class="err" id="mig-err"></div>';
      el.appendChild(controls);

      /* -- re-embed coverage card ------------------------------------------ */
      var coverageCard = document.createElement("div");
      coverageCard.className = "card";
      coverageCard.innerHTML =
        '<h2>Re-embed coverage <span class="sub">POST /v1/admin/reembed/batch · live</span></h2>' +
        '<div class="note"><em>Honest coverage only.</em> The bar is determinate <b>only</b> when the ' +
          'server reports a known total; an unknown total shows a striped indeterminate track — never a ' +
          'fabricated percentage. A total of <b>0</b> means there is nothing to embed (its own state), not 0%.</div>' +
        '<div id="mig-cov-bar" style="margin-top:10px"></div>' +
        '<div id="mig-cov-stat"></div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:12px">' +
          '<button class="primary" id="mig-run" ' +
            'title="Loop POST /v1/admin/reembed/batch until done, repainting coverage after each batch.">' +
            'Run re-embed batch…</button>' +
          '<button id="mig-run-one" ' +
            'title="Fill exactly one batch, then stop — for a careful step-through.">Fill one batch</button>' +
          '<button id="mig-run-stop" disabled ' +
            'title="Stop looping after the in-flight batch returns (never mid-write).">Stop</button>' +
          '<span class="refreshed" id="mig-run-status"></span>' +
        "</div>";
      el.appendChild(coverageCard);

      /* -- backfill per-source card (reuses the honest bar) ---------------- */
      var backfillCard = document.createElement("div");
      backfillCard.className = "card";
      backfillCard.innerHTML =
        '<h2>Connector backfill <span class="sub">GET /v1/admin/backfill · latest run per source</span></h2>' +
        '<div class="note"><em>Same honesty as the heartbeat.</em> Progress is posted best-effort by the ' +
          'ingest side, so <b>processed</b> can undercount on a missed post — a progress signal, not an audit ' +
          'ledger (the authoritative count stays in the L0/L1 rows). Determinate bar only when a run declares ' +
          'a total; ETA only for a running job with a known total and forward progress.</div>' +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><button id="mig-bf-load" ' +
            'title="GET /v1/admin/backfill?tenant_id= — requires a tenant.">Load backfill runs</button></div>' +
          '<span class="refreshed" id="mig-bf-status"></span>' +
        "</div>" +
        '<div id="mig-bf-out"></div>';
      el.appendChild(backfillCard);

      /* -- dense route + cutover card -------------------------------------- */
      var routeCard = document.createElement("div");
      routeCard.className = "card";
      routeCard.innerHTML =
        '<h2>Dense query route <span class="sub">POST /v1/admin/reembed/cutover · coverage-gated</span></h2>' +
        '<div id="mig-route-state"></div>' +
        '<div class="note" style="margin-top:8px"><em>Coverage gate.</em> Cutting over to <b>v2</b> below 100% ' +
          'coverage is refused by the server (409) unless you force it — uncovered chunks fall back to ' +
          'sparse-only for the new route (SPEC §5c). Forcing here demands an explicit acknowledgment. The ' +
          '<b>v1 rollback</b> is the un-gated inverse: v1 vectors already exist, so v2→v1 is always safe.</div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:12px">' +
          '<button class="primary" id="mig-cutover" ' +
            'title="POST /v1/admin/reembed/cutover route=v2 — coverage-gated.">Cut over to v2…</button>' +
          '<button id="mig-rollback" ' +
            'title="POST /v1/admin/reembed/cutover route=v1 — the un-gated rollback.">Roll back to v1…</button>' +
          '<button id="mig-briefs" ' +
            'title="POST /v1/admin/briefs/refresh — re-touch stale briefs after a re-embed.">Refresh all briefs…</button>' +
        "</div>" +
        '<div id="mig-briefs-out"></div>';
      el.appendChild(routeCard);

      /* -- cutover confirm dialog (force acknowledgment when sub-100%) ------ */
      var cutDlgEl = document.createElement("div");
      cutDlgEl.className = "dialog-backdrop";
      cutDlgEl.id = "mig-cutover-dialog";
      cutDlgEl.innerHTML =
        '<div class="dialog" style="max-width:600px">' +
          '<h3 id="mig-cut-title">Cut over dense route</h3>' +
          '<div class="note" id="mig-cut-stmt"></div>' +
          '<div class="card" id="mig-cut-force-card" style="margin-top:10px;display:none">' +
            '<div class="note" style="margin-bottom:8px"><em>Coverage is below 100%.</em> The server will ' +
              'refuse a plain cutover (409). Forcing it flips the route anyway — <b>uncovered chunks fall ' +
              'back to sparse-only</b> for the new route until the backfill finishes (SPEC §5c). This is an ' +
              'explicit, acknowledged degradation, not a silent one.</div>' +
            '<label class="tight" style="display:flex;gap:8px;align-items:center">' +
              '<input type="checkbox" id="mig-cut-force" style="width:auto;min-width:0">' +
              '<span>I acknowledge the sub-100% coverage and want to force the cutover.</span>' +
            "</label>" +
          "</div>" +
          '<div class="err" id="mig-cut-err"></div>' +
          '<div class="actions">' +
            '<button class="primary" id="mig-cut-confirm">Cut over</button>' +
            '<button id="mig-cut-cancel">Cancel</button>' +
          "</div>" +
        "</div>";
      el.appendChild(cutDlgEl);
      var cutDlg = Verity.dialog("mig-cutover-dialog");

      /* ==================================================================== */
      /* helpers                                                              */
      /* ==================================================================== */

      function typedTenant() { return Verity.$("mig-tenant").value.trim(); }
      // For batch/cutover the tenant is OPTIONAL (blank = all/global), so we do
      // not force one. We prefer the typed value, else the shared tenant, else
      // omit the key entirely so the server takes its all-tenants path.
      function scopeTenant() { return typedTenant() || Verity.tenant() || ""; }

      function batchSize() {
        var n = parseInt(Verity.$("mig-batch").value, 10);
        if (isNaN(n) || n < 1) n = 1;
        if (n > 10000) n = 10000;
        return n;
      }
      function modelId() {
        var m = Verity.$("mig-model").value.trim();
        return m || DEFAULT_MODEL;
      }

      // Render the coverage bar HONESTLY from a { total, covered, fraction }.
      // total>0  → determinate bar + "covered / total (xx.x%)".
      // total==0 → "nothing to embed" (an honest terminal state, NOT 0%).
      // null     → indeterminate striped track, "coverage unknown".
      function paintCoverage(cov) {
        var barEl = Verity.$("mig-cov-bar");
        var statEl = Verity.$("mig-cov-stat");
        if (!cov) {
          barEl.innerHTML = '<div class="bar indet"></div>';
          statEl.innerHTML = '<span class="pct">coverage unknown — run a batch to measure it (no fabricated %)</span>';
          return;
        }
        var total = cov.total;
        var covered = cov.covered;
        if (total == null) {
          barEl.innerHTML = '<div class="bar indet"></div>';
          statEl.innerHTML = '<span class="pct">' + Verity.esc(covered == null ? "?" : covered) +
            " covered · total unknown</span>";
          return;
        }
        if (total <= 0) {
          // Nothing to embed — its own honest state. A full green bar would
          // imply "100% of something"; we say the truth instead.
          barEl.innerHTML = '<div class="bar completed"><i style="width:100%"></i></div>';
          statEl.innerHTML = '<span class="pct">nothing to embed for this scope · ' +
            Verity.statusBadge("published") + " coverage vacuously complete</span>";
          return;
        }
        var pct = Math.max(0, Math.min(100, (covered / total) * 100));
        var complete = covered >= total;
        var cls = complete ? " completed" : "";
        barEl.innerHTML = '<div class="bar' + cls + '"><i style="width:' + pct.toFixed(1) + '%"></i></div>';
        statEl.innerHTML = '<span class="pct">' + pct.toFixed(1) + "% · " +
          Verity.esc(covered) + " / " + Verity.esc(total) + " chunks covered" +
          (complete ? " · " + Verity.statusBadge("published") : "") + "</span>";
      }

      // Is the last-seen coverage complete? Mirror the server's rule
      // (EmbeddingCoverage::is_complete): total==0 OR covered>=total.
      function coverageComplete(cov) {
        if (!cov || cov.total == null) return false;
        return cov.total <= 0 || (cov.covered != null && cov.covered >= cov.total);
      }

      // Route-state block: honest about the missing GET. Shows the last cutover
      // WE did this session (if any) + the coverage gate state; never guesses
      // the live route.
      function paintRouteState() {
        var wrap = Verity.$("mig-route-state");
        var covLine;
        if (lastCoverage == null) {
          covLine = '<dt>backfill coverage</dt><dd><span class="note">unmeasured — run a re-embed batch to ' +
            'learn it before cutting over</span></dd>';
        } else if (lastCoverage.total == null) {
          covLine = '<dt>backfill coverage</dt><dd><span class="note">total unknown</span></dd>';
        } else if (lastCoverage.total <= 0) {
          covLine = '<dt>backfill coverage</dt><dd>' + Verity.badge("nothing to embed", "b-st-published") +
            ' <span class="note">gate is vacuously satisfied</span></dd>';
        } else {
          var pct = Math.max(0, Math.min(100, (lastCoverage.covered / lastCoverage.total) * 100));
          var done = coverageComplete(lastCoverage);
          covLine = '<dt>backfill coverage</dt><dd>' +
            (done ? Verity.badge("100% — gate open", "b-st-published")
                  : Verity.badge(pct.toFixed(1) + "% — gate CLOSED (force required for v2)", "b-st-eligible")) +
            ' <span class="note">' + Verity.esc(lastCoverage.covered) + " / " +
            Verity.esc(lastCoverage.total) + "</span></dd>";
        }

        var routeLine;
        if (lastCutover) {
          routeLine = '<dt>current dense route</dt><dd>' +
            Verity.badge(lastCutover.route, lastCutover.route === "v2" ? "b-tier" : "b-trust") +
            ' <span class="note">as set by this session’s last cutover' +
            (lastCutover.forced ? " (FORCED below 100%)" : "") + " · " +
            Verity.esc(Verity.fmtTime(lastCutover.at)) +
            (lastCutover.tenant ? " · tenant " + Verity.esc(lastCutover.tenant) : " · global") +
            "</span></dd>";
        } else {
          // The honest seam: no read endpoint for the live route.
          routeLine = '<dt>current dense route</dt><dd><span class="note"><em>unknown from the UI.</em> ' +
            'There is no GET for the live dense route — <code>embedding_route()</code> exists in storage but ' +
            'is not exposed over HTTP. This panel only knows a route once <b>it</b> flips one. Default at ' +
            'rest is <b>v1</b>, but the UI will not assert that as fact.</span></dd>';
        }

        wrap.innerHTML = '<dl class="kv">' + routeLine + covLine + "</dl>";
      }

      /* ==================================================================== */
      /* re-embed batch loop                                                  */
      /* ==================================================================== */

      var looping = false;
      var stopRequested = false;

      function setRunButtons(running) {
        Verity.$("mig-run").disabled = running;
        Verity.$("mig-run-one").disabled = running;
        Verity.$("mig-run-stop").disabled = !running;
        // Cutover/rollback stay usable, but a run in flight moves coverage, so
        // we simply repaint route state after each batch.
      }

      // One batch. Returns the parsed response, or throws (surfaced inline).
      async function runOneBatch() {
        var body = { model: modelId(), batch: batchSize() };
        var t = scopeTenant();
        if (t) body.tenant = t; // omit → server backfills across all tenants
        var res = await Verity.api("/v1/admin/reembed/batch", { admin: true, json: body });
        if (res && res.coverage) {
          lastCoverage = res.coverage;
          paintCoverage(res.coverage);
          paintRouteState();
        }
        return res;
      }

      async function loopBatches() {
        if (looping) return;
        Verity.clearErr("mig-err");
        looping = true;
        stopRequested = false;
        setRunButtons(true);
        var batches = 0, totalWritten = 0, totalScanned = 0;
        try {
          for (;;) {
            var res = await runOneBatch();
            batches++;
            totalWritten += (res && res.written) || 0;
            totalScanned += (res && res.scanned) || 0;
            Verity.$("mig-run-status").textContent =
              batches + " batch" + (batches === 1 ? "" : "es") + " · " +
              totalWritten + " written · " + totalScanned + " scanned";
            // `done` = the server found no pending chunks this batch. That is
            // the honest terminal signal — not a client-side % guess.
            if (!res || res.done) break;
            if (stopRequested) {
              Verity.$("mig-run-status").textContent += " · stopped by operator";
              break;
            }
          }
        } catch (e) {
          Verity.err("mig-err", e);
        } finally {
          looping = false;
          stopRequested = false;
          setRunButtons(false);
        }
      }

      Verity.$("mig-run").onclick = loopBatches;
      Verity.$("mig-run-stop").onclick = function () {
        if (looping) {
          stopRequested = true;
          Verity.$("mig-run-stop").disabled = true;
          Verity.$("mig-run-status").textContent += " · stopping after this batch…";
        }
      };
      Verity.$("mig-run-one").onclick = async function () {
        if (looping) return;
        Verity.clearErr("mig-err");
        setRunButtons(true);
        try {
          var res = await runOneBatch();
          Verity.$("mig-run-status").textContent =
            "one batch · " + ((res && res.written) || 0) + " written · " +
            ((res && res.scanned) || 0) + " scanned" +
            (res && res.done ? " · done (no pending chunks)" : "");
        } catch (e) {
          Verity.err("mig-err", e);
        } finally {
          setRunButtons(false);
        }
      };

      /* ==================================================================== */
      /* backfill per source (reused honest bar + ETA)                        */
      /* ==================================================================== */

      function bfProgressBar(run) {
        var state = String(run.state || "").toLowerCase();
        var total = run.total;
        var processed = run.processed || 0;
        if (total != null && total > 0) {
          var pct = Math.max(0, Math.min(100, (processed / total) * 100));
          var stateCls = (state === "completed" || state === "failed" || state === "paused") ? " " + state : "";
          return '<div class="bar' + stateCls + '"><i style="width:' + pct.toFixed(1) + '%"></i></div>' +
            '<span class="pct">' + pct.toFixed(1) + "% · " +
            Verity.esc(processed) + " / " + Verity.esc(total) + "</span>";
        }
        // No total → NEVER fabricate a percentage. Striped indeterminate track.
        return '<div class="bar indet"></div>' +
          '<span class="pct">' + Verity.esc(processed) + " processed · total unknown</span>";
      }

      function bfEta(run) {
        var state = String(run.state || "").toLowerCase();
        var total = run.total, processed = run.processed || 0;
        if (state !== "running" || total == null || total <= 0 || processed <= 0 || processed >= total) {
          return '<span class="refreshed" title="ETA is shown only for a running job with a known total and forward progress">—</span>';
        }
        var started = new Date(run.started_at).getTime();
        var updated = new Date(run.updated_at).getTime();
        var elapsed = updated - started;
        if (!(elapsed > 0)) {
          return '<span class="refreshed" title="not enough elapsed time to project honestly">—</span>';
        }
        var rate = processed / elapsed; // items per ms
        if (!(rate > 0)) return '<span class="refreshed">—</span>';
        var remainingMs = (total - processed) / rate;
        return '<span title="projected from processed/elapsed at last heartbeat; as-of ' +
          Verity.esc(Verity.fmtTime(run.updated_at)) + '">~' +
          Verity.esc(Verity.fmtMs(remainingMs)) + " left</span>";
      }

      function bfStateBadge(state) {
        var s = String(state || "").toLowerCase();
        if (s === "completed") return Verity.badge("completed", "b-st-published");
        if (s === "failed") return Verity.badge("failed", "b-st-quarantined");
        if (s === "paused") return Verity.badge("paused", "b-st-candidate");
        return Verity.badge(s || "running", "b-st-eligible");
      }

      async function loadBackfill() {
        Verity.clearErr("mig-err");
        Verity.$("mig-bf-out").innerHTML = "";
        Verity.$("mig-bf-status").textContent = "";
        var tenant = typedTenant() || Verity.tenant() || "";
        if (!tenant) {
          // Backfill GET REQUIRES a tenant_id (it is not optional server-side),
          // so we fail closed with the reason instead of firing a doomed GET.
          Verity.err("mig-err", new Error(
            "backfill needs a tenant_id — decode a scope handle on Scope Inspector or type a tenant_id above"));
          return;
        }
        try {
          var runs = await Verity.api(
            "/v1/admin/backfill?tenant_id=" + encodeURIComponent(tenant), { admin: true });
          runs = runs || [];
          if (!runs.length) {
            Verity.$("mig-bf-out").innerHTML =
              '<div class="empty">No backfill runs for tenant <b>' + Verity.esc(tenant) +
              "</b>. A source only appears here once its ingest side posts progress — an empty list is not an error.</div>";
          } else {
            var rows = runs.map(function (r) {
              return '<tr class="' + (String(r.state).toLowerCase() === "failed" ? "flag" : "") + '">' +
                "<td>" + Verity.esc(r.source) + "</td>" +
                "<td>" + bfStateBadge(r.state) + "</td>" +
                '<td style="min-width:180px">' + bfProgressBar(r) + "</td>" +
                "<td>" + bfEta(r) + "</td>" +
                "<td>" + (r.error ? '<span class="note"><em>' + Verity.esc(r.error) + "</em></span>"
                                  : '<span class="note">—</span>') + "</td>" +
                "<td>" + Verity.esc(r.updated_at ? Verity.fmtTime(r.updated_at) : "—") + "</td>" +
                "</tr>";
            }).join("");
            Verity.$("mig-bf-out").innerHTML =
              '<div class="tablewrap"><table><thead><tr>' +
                "<th>source</th><th>state</th><th>progress</th><th>ETA</th><th>last error</th><th>updated</th>" +
              "</tr></thead><tbody>" + rows + "</tbody></table></div>";
          }
          Verity.$("mig-bf-status").textContent =
            runs.length + " source" + (runs.length === 1 ? "" : "s") +
            " · loaded " + Verity.fmtTime(Date.now());
        } catch (e) {
          Verity.err("mig-err", e);
        }
      }

      Verity.$("mig-bf-load").onclick = loadBackfill;

      /* ==================================================================== */
      /* cutover / rollback (coverage-gated v2; un-gated v1)                  */
      /* ==================================================================== */

      var pendingRoute = "v2"; // which route the open dialog will flip to

      function openCutover(route) {
        pendingRoute = route;
        Verity.clearErr("mig-cut-err");
        var toV2 = route === "v2";
        Verity.$("mig-cut-title").textContent = toV2 ? "Cut over to v2" : "Roll back to v1";
        var forceCard = Verity.$("mig-cut-force-card");
        var forceBox = Verity.$("mig-cut-force");
        forceBox.checked = false;

        var t = scopeTenant();
        var scopeStr = t ? "tenant <b>" + Verity.esc(t) + "</b>" : "<b>all tenants</b> (global default)";

        if (toV2) {
          // Gate visible only for v2. Show force UI ONLY when we know coverage
          // is sub-100% (or unmeasured — then the server is the authority and
          // may 409; forcing pre-empts that honestly).
          var complete = coverageComplete(lastCoverage);
          var measured = lastCoverage != null && lastCoverage.total != null;
          Verity.$("mig-cut-stmt").innerHTML =
            "Flip the dense query route to <b>v2</b> for " + scopeStr + ". " +
            "recall/brief will search the <b>embedding_v2</b> column.";
          if (measured && complete) {
            forceCard.style.display = "none";
          } else {
            // Sub-100% or unmeasured → force acknowledgment required.
            forceCard.style.display = "";
          }
        } else {
          // v1 rollback — un-gated. No force UI at all.
          forceCard.style.display = "none";
          Verity.$("mig-cut-stmt").innerHTML =
            "Roll the dense query route back to <b>v1</b> for " + scopeStr + ". " +
            "This is always safe — the v1 <b>embedding</b> vectors already exist, so no coverage gate applies.";
        }
        cutDlg.open();
      }

      Verity.$("mig-cutover").onclick = function () { openCutover("v2"); };
      Verity.$("mig-rollback").onclick = function () { openCutover("v1"); };
      Verity.$("mig-cut-cancel").onclick = function () { cutDlg.close(); };

      Verity.$("mig-cut-confirm").onclick = async function () {
        Verity.clearErr("mig-cut-err");
        var toV2 = pendingRoute === "v2";
        var forceCardShown = Verity.$("mig-cut-force-card").style.display !== "none";
        var force = toV2 && forceCardShown && Verity.$("mig-cut-force").checked;
        // If the force card is showing (sub-100%/unmeasured) but not checked,
        // REFUSE client-side rather than fire a POST the server will 409 —
        // omission of the acknowledgment is a refusal, not a silent force.
        if (toV2 && forceCardShown && !force) {
          Verity.err("mig-cut-err", new Error(
            "coverage is below 100% (or unmeasured) — check the acknowledgment to force the cutover, or Cancel and finish the re-embed first"));
          return;
        }
        var body = { route: pendingRoute, force: force };
        var t = scopeTenant();
        if (t) body.tenant = t;
        var btn = Verity.$("mig-cut-confirm");
        btn.disabled = true;
        try {
          var res = await Verity.api("/v1/admin/reembed/cutover", { admin: true, json: body });
          // Record what WE flipped — the only honest source of "current route".
          lastCutover = {
            route: (res && res.route) || pendingRoute,
            tenant: (res && res.tenant) || t || "",
            coverage: res && res.coverage,
            forced: !!(res && res.forced),
            at: Date.now(),
          };
          if (res && res.coverage) { lastCoverage = res.coverage; paintCoverage(res.coverage); }
          paintRouteState();
          cutDlg.close();
        } catch (e) {
          // A 409 here is the coverage gate doing its job — surface it verbatim.
          Verity.err("mig-cut-err", e);
        } finally {
          btn.disabled = false;
        }
      };

      /* ==================================================================== */
      /* refresh all briefs                                                   */
      /* ==================================================================== */

      Verity.$("mig-briefs").onclick = async function () {
        Verity.$("mig-briefs-out").innerHTML = "";
        var tenant = typedTenant() || Verity.tenant() || "";
        if (!tenant) {
          // briefs/refresh takes a required tenant query param (AdminTenantParam).
          Verity.$("mig-briefs-out").innerHTML =
            '<div class="err on">briefs/refresh needs a tenant_id — decode a scope handle or type one above</div>';
          return;
        }
        var btn = Verity.$("mig-briefs");
        btn.disabled = true;
        try {
          var res = await Verity.api(
            "/v1/admin/briefs/refresh?tenant=" + encodeURIComponent(tenant),
            { admin: true, json: {} });
          var n = res && typeof res.refreshed === "number" ? res.refreshed : null;
          Verity.$("mig-briefs-out").innerHTML =
            '<div class="note" style="margin-top:8px">' +
            (n == null ? "briefs refresh requested."
                       : "<b>" + Verity.esc(n) + "</b> stale brief" + (n === 1 ? "" : "s") + " refreshed") +
            " · " + Verity.esc(Verity.fmtTime(Date.now())) + "</div>";
        } catch (e) {
          Verity.$("mig-briefs-out").innerHTML =
            '<div class="err on">' + Verity.esc((e && e.message) || String(e)) + "</div>";
        } finally {
          btn.disabled = false;
        }
      };

      /* ==================================================================== */
      /* initial paint + tenant glue                                          */
      /* ==================================================================== */

      paintCoverage(null);   // unmeasured striped track until a batch runs
      paintRouteState();     // honest "unknown route" seam until a cutover

      Verity.onTenant(function (t) {
        var f = Verity.$("mig-tenant");
        if (f && !f.value.trim()) f.placeholder = t ? "(active: " + t + ")" : "(uses active tenant · blank = global)";
      });
      (function () {
        var t = Verity.tenant();
        var f = Verity.$("mig-tenant");
        if (f && t) f.placeholder = "(active: " + t + ")";
      })();
    },
  });
})();
