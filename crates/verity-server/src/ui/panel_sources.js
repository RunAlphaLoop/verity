"use strict";
/* ==========================================================================
   panel_sources.js — Screen 5 · Sources & Freshness  (v0.2 · READ-ONLY)
   --------------------------------------------------------------------------
   Backing reads (all admin-token, all pure — zero LLM, zero live-ReBAC):
     • GET /v1/admin/connector-status?tenant_id=  → [{ source, cursor,
         items_synced, last_event_at|null, updated_at }]
     • GET /v1/slo/freshness?tenant_id=&window_hours= → [{ source, samples,
         p50_ms|null, p95_ms|null }]                 (NOTE: no p99, no target)
     • GET /v1/admin/backfill?tenant_id=          → [{ run_id, source, state,
         total|null, processed, cursor, error|null, started_at, updated_at }]

   HONESTY CONTRACT (SPEC §3 / §5 Screen 5 / CLAUDE.md 'measured or absent'):
   1. connector-status has NO provenance-tier, NO lane, NO error column. We
      render tier/lane ONLY from a real per-row field if one ever appears; else
      an explicit 'not reported' seam. We NEVER default a source into a lane —
      a wrong lane label breaks 'never blurred' (SPEC §5e.6). The inline
      error/last-failure is sourced from the matching BACKFILL run's `error`
      (the only real failure signal we have), disclosed as such.
   2. Freshness emits p50 + p95 only. p99 is an honest seam ('not computed'),
      never fabricated. The SLO target is OPERATOR-SET (an input) and labeled as
      such; breach = a REAL percentile exceeding the STATED target.
   3. True cadence is derived from real timestamps (event age + heartbeat gap),
      never a flagship 'seconds' claim inherited by a daily source (SPEC §5d).
   4. Backfill: determinate bar only when total known; striped indeterminate
      otherwise. ETA only when running + known total + forward progress.
   5. v0.2 is READ-ONLY: manifest install/activate + webhook mint/revoke are
      Later and rendered as DISABLED seams (designed, never faked). The
      graduation prompt for convenience-lane sources is shown, but only for a
      source whose lane is actually KNOWN to be convenience — never guessed.
   ========================================================================== */
(function () {
  // Last-event / heartbeat staleness thresholds (SPEC §5: green <15m / amber
  // <24h / red beyond). Milliseconds.
  var FRESH_MS = 15 * 60 * 1000;      // < 15m → green
  var STALE_MS = 24 * 60 * 60 * 1000; // < 24h → amber, else red

  // -------------------------------------------------- pure age helpers -----

  function ageMs(iso) {
    if (!iso) return null;
    var t = new Date(iso).getTime();
    if (isNaN(t)) return null;
    return Date.now() - t;
  }

  // Humanize a positive duration in ms into a coarse, honest label.
  function humanAge(ms) {
    if (ms == null) return "—";
    if (ms < 0) ms = 0;
    var s = Math.round(ms / 1000);
    if (s < 60) return s + "s ago";
    var m = Math.round(s / 60);
    if (m < 60) return m + "m ago";
    var h = Math.round(m / 60);
    if (h < 48) return h + "h ago";
    var d = Math.round(h / 24);
    return d + "d ago";
  }

  // Coarse cadence bucket from a representative gap (ms). Honest: this is the
  // OBSERVED cadence of the newest event vs now — a daily source reads daily.
  function cadenceLabel(ms) {
    if (ms == null) return null;
    if (ms < 5 * 60 * 1000) return "sub-5-minute";
    if (ms < FRESH_MS) return "minutes";
    if (ms < 60 * 60 * 1000) return "hourly-ish";
    if (ms < STALE_MS) return "intra-day";
    if (ms < 7 * STALE_MS) return "daily";
    return "weekly+";
  }

  // Staleness → the theme's green/amber/red badge classes (reused, not new).
  // We map onto the confidentiality hue classes purely for the fill color:
  // b-conf-0 = green, b-conf-2 = amber, b-conf-3 = red. This keeps us inside
  // the FROZEN badge vocabulary without inventing a class.
  function ageBadge(ms, label) {
    if (ms == null) {
      // Honest 'no event time' fallback (SPEC §5): a dim neutral chip, never
      // a fake-fresh green.
      return Verity.badge("no event time", "b-kind");
    }
    var cls = ms < FRESH_MS ? "b-conf-0" : (ms < STALE_MS ? "b-conf-2" : "b-conf-3");
    return Verity.badge(label, cls);
  }

  // -------------------------------------------------- provenance / lane ----
  // connector-status does NOT report these. If a future row carries them we
  // render faithfully; otherwise we surface an explicit 'not reported' seam and
  // NEVER guess a lane.

  function provenanceTier(row) {
    // Accept any of the plausible field names a future connector-status might
    // carry. Absent → null (seam).
    return row.provenance_tier || row.acl_provenance || row.tier || null;
  }
  function laneOf(row) {
    // Explicit lane field only. We do NOT infer a lane from the tier here,
    // because a wrong lane is worse than an admitted-unknown one.
    var l = row.lane;
    return l == null || l === "" ? null : String(l).toLowerCase();
  }
  function tierBadgeCell(row) {
    var t = provenanceTier(row);
    if (!t) {
      return '<span class="refreshed" title="connector-status does not report an ' +
        'ACL-provenance tier; this is a telemetry gap, not a permissive default">' +
        'not reported</span>';
    }
    // Reuse the frozen provenance badge vocabulary
    // (mirrored / approximated / admin-assigned / quarantined).
    return Verity.provenanceBadge(t);
  }
  function laneBadgeCell(row) {
    var l = laneOf(row);
    if (!l) {
      return '<span class="refreshed" title="connector-status does not report a ' +
        'truth-vs-convenience lane; never guessed — a mislabeled lane would blur ' +
        'the two lanes (SPEC §5e.6)">not reported</span>';
    }
    if (l === "truth") return Verity.badge("truth lane", "b-conf-0");
    if (l === "convenience") return Verity.badge("convenience lane", "b-conf-2");
    return Verity.badge(l + " lane", "b-kind");
  }

  // -------------------------------------------------- backfill helpers -----
  // Reuse the same determinate/indeterminate + honest-ETA discipline the
  // Migrations panel is speced for. total==null → uncountable → striped bar.

  function progressBar(run) {
    var state = String(run.state || "").toLowerCase();
    var total = run.total;
    var processed = run.processed || 0;
    if (total != null && total > 0) {
      var pct = Math.max(0, Math.min(100, (processed / total) * 100));
      var stateCls = (state === "completed" || state === "failed" || state === "paused") ? " " + state : "";
      return {
        html: '<div class="bar' + stateCls + '"><i style="width:' + pct.toFixed(1) + '%"></i></div>' +
          '<span class="pct">' + pct.toFixed(1) + "% · " +
          Verity.esc(processed) + " / " + Verity.esc(total) + "</span>",
        pct: pct, determinate: true,
      };
    }
    // No total → NEVER fabricate a percentage. Striped indeterminate track.
    return {
      html: '<div class="bar indet"></div>' +
        '<span class="pct">' + Verity.esc(processed) + " processed · total unknown</span>",
      pct: null, determinate: false,
    };
  }

  // ETA is honest ONLY for a running job with a known total and forward
  // progress; otherwise we say nothing (no fabricated ETA).
  function etaCell(run) {
    var state = String(run.state || "").toLowerCase();
    var total = run.total, processed = run.processed || 0;
    if (state !== "running" || total == null || total <= 0 || processed <= 0 || processed >= total) {
      return '<span class="refreshed" title="ETA is shown only for a running job ' +
        'with a known total and forward progress">—</span>';
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
    return '<span title="projected from processed/elapsed at last heartbeat; ' +
      'as-of ' + Verity.esc(Verity.fmtTime(run.updated_at)) + '">~' +
      Verity.esc(Verity.fmtMs(remainingMs)) + " left</span>";
  }

  function backfillStateBadge(state) {
    var s = String(state || "").toLowerCase();
    if (s === "completed") return Verity.badge("completed", "b-st-published");
    if (s === "failed") return Verity.badge("failed", "b-st-quarantined");
    if (s === "paused") return Verity.badge("paused", "b-st-candidate");
    if (s === "running") return Verity.badge("running", "b-tier");
    return Verity.badge(s || "—", "b-kind");
  }

  // -------------------------------------------------- freshness helpers ----

  function pctCell(ms, targetMs) {
    if (ms == null) return '<span class="refreshed">—</span>';
    var over = targetMs != null && ms > targetMs;
    var txt = Verity.fmtMs(ms);
    return over
      ? Verity.badge(txt + " · breach", "b-conf-3")     // red — real value over stated target
      : '<span>' + Verity.esc(txt) + "</span>";
  }

  Verity.register({
    id: "sources",
    mount: function (section) {
      var el = Verity.$("sources-mount");
      if (!el) return;

      // Per-panel read-only ribbon (v0.1/v0.2 disclosure). This screen's write
      // actions (manifest install/activate, webhook mint/revoke) are Later, so
      // the ribbon stays and the writes are disabled seams below.
      var tpl = Verity.$("ribbon-tpl");
      if (tpl && tpl.content) {
        var rib = tpl.content.cloneNode(true);
        var act = rib.querySelector(".ribbon-action");
        if (act) act.textContent = "install-manifest / mint-webhook";
        el.appendChild(rib);
      }

      var LAST = { status: [], fresh: [], backfill: [] };

      // ---- controls card ------------------------------------------------
      var controls = document.createElement("div");
      controls.className = "card";
      controls.innerHTML =
        '<h2>Sources <span class="sub">GET /v1/admin/connector-status · /v1/slo/freshness · /v1/admin/backfill · admin token</span></h2>' +
        '<div class="row">' +
          '<div class="tight"><label for="src-tenant">tenant_id</label>' +
            '<input type="text" id="src-tenant" placeholder="(uses active tenant)" size="30"></div>' +
          '<div class="tight"><label for="src-window">freshness window (h)</label>' +
            '<input type="number" id="src-window" value="24" min="1" max="2160" style="width:110px"></div>' +
          '<div class="tight"><label for="src-target">SLO target (ms) <span class="note">operator-set</span></label>' +
            '<input type="number" id="src-target" value="900000" min="0" step="1000" style="width:130px" ' +
            'title="Operator-set target, NOT server-authoritative. Breach highlighting compares real p50/p95 to this."></div>' +
          '<div class="tight" style="align-self:flex-end"><button id="src-load" class="primary">Load inventory</button></div>' +
        "</div>" +
        '<div class="note"><em>Two lanes, labeled, never blurred.</em> A source is <b>truth lane</b> ' +
          '(mirrored, source-fidelity ACLs) or <b>convenience lane</b> (admin-assigned/approximated, no ' +
          'per-object ACL fidelity). The <code>connector-status</code> heartbeat does not yet carry the ' +
          'tier or lane, so where it is absent this panel says <b>not reported</b> rather than guessing — ' +
          'a mislabeled lane is worse than an admitted-unknown one (SPEC §5e.6).</div>' +
        '<div class="err" id="src-err"></div>' +
        '<div id="src-stamp"></div>';
      el.appendChild(controls);

      // Mount points for the three sub-sections.
      var invCard = document.createElement("div");
      invCard.className = "card";
      invCard.innerHTML =
        '<h2>Source inventory <span class="sub">provenance tier · lane · sync · staleness</span></h2>' +
        '<div id="src-inv"></div>';
      el.appendChild(invCard);

      var freshCard = document.createElement("div");
      freshCard.className = "card";
      freshCard.innerHTML =
        '<h2>Freshness SLO <span class="sub">source-change → queryable · GET /v1/slo/freshness</span></h2>' +
        '<div class="note"><em>Honest percentiles.</em> The endpoint computes <b>p50</b> and <b>p95</b> ' +
          'from real samples. It does <b>not</b> compute <b>p99</b>, so that column is a labeled seam, ' +
          'never a fabricated number. The <b>SLO target</b> is <b>operator-set</b> above (not ' +
          'server-authoritative); a value over target is highlighted as a breach (SPEC §5 Screen 5 / ' +
          'CLAUDE.md honest-numbers).</div>' +
        '<div id="src-fresh"></div>';
      el.appendChild(freshCard);

      var backCard = document.createElement("div");
      backCard.className = "card";
      backCard.innerHTML =
        '<h2>Backfill <span class="sub">latest run per source · GET /v1/admin/backfill</span></h2>' +
        '<div class="note"><em>Determinate only when countable.</em> A run with a known total shows a ' +
          'real progress bar; an uncountable run shows a striped indeterminate track, never a fabricated ' +
          'percentage. ETA appears only for a running job with a known total and forward progress.</div>' +
        '<div id="src-back"></div>';
      el.appendChild(backCard);

      // ---- Later-only write seams (designed, never faked) ---------------
      var seamCard = document.createElement("div");
      seamCard.className = "card";
      seamCard.innerHTML =
        '<h2>Source writes <span class="sub">Later — disabled seams, not faked buttons</span></h2>' +
        '<div class="note">v0.2 is <b>read-only</b> for this screen. Installing a manifest, activating it as ' +
          'an explicit human-approved step, and minting/revoking webhooks are <b>Later</b> ' +
          '(SPEC §5 Screen 5 · §6 checklist). We render the seams so the destination is visible, but we do ' +
          '<b>not</b> fake a working button — and there will never be an "index it anyway" permissive ' +
          'shortcut (SPEC §3 fail-closed).</div>' +
        '<div class="actions" style="justify-content:flex-start;flex-wrap:wrap;gap:8px;margin-top:8px">' +
          '<button disabled title="POST /v1/manifests — Later. Install as a DRAFT; activation is a separate audited human-approval step.">Install manifest (draft) — seam</button>' +
          '<button disabled title="POST /v1/manifests/{id}/activate — Later. Explicit, human-approver-recorded, audited — never a flag flip.">Activate manifest — seam</button>' +
          '<button disabled title="POST /v1/webhooks — Later. Show-once secret with copy-once UI.">Mint webhook — seam</button>' +
          '<button disabled title="DELETE /v1/webhooks/{id} — Later.">Revoke webhook — seam</button>' +
        "</div>";
      el.appendChild(seamCard);

      // ---- tenant/window helpers ----------------------------------------
      function activeTenant() {
        var typed = Verity.$("src-tenant").value.trim();
        return typed || Verity.tenant() || "";
      }
      function targetMs() {
        var v = parseInt(Verity.$("src-target").value, 10);
        return isNaN(v) || v < 0 ? null : v;
      }

      // ---- render: source inventory -------------------------------------
      function renderInventory() {
        var rows = LAST.status;
        var backBySource = {};
        LAST.backfill.forEach(function (b) { backBySource[b.source] = b; });

        if (!rows.length) {
          Verity.$("src-inv").innerHTML =
            '<div class="empty">No connector heartbeats for this tenant. An empty inventory means no ' +
            'source has reported in — that is a real state (nothing hidden), not an error.</div>';
          return;
        }
        var body = rows.map(function (r) {
          var evAge = ageMs(r.last_event_at);
          var hbAge = ageMs(r.updated_at);
          var cad = cadenceLabel(evAge != null ? evAge : hbAge);
          // Inline error/last-failure: connector-status has no error column, so
          // the only real failure signal is the matching backfill run's error.
          var bf = backBySource[r.source];
          var errCell;
          if (bf && bf.error) {
            errCell = Verity.badge("last-failure", "b-conf-3") +
              ' <span class="note" title="from the source\'s latest backfill run — connector-status carries no error column">' +
              Verity.esc(bf.error) + "</span>";
          } else {
            errCell = '<span class="refreshed" title="no error on this source\'s latest backfill run; ' +
              'connector-status itself reports no error field">none reported</span>';
          }
          var lane = laneOf(r);
          var gradRow = lane === "convenience"
            ? '<tr class="grad-row"><td colspan="9">' +
                '<div class="note"><em>Graduation.</em> This source is on the <b>convenience lane</b> ' +
                '(admin-assigned/approximated ACLs). Connect the native <b>Tier-A</b> connector to graduate ' +
                'it to <b>mirrored</b> ACLs with per-object source fidelity (SPEC §5e.4). ' +
                '<span class="refreshed">(install-manifest write is Later — seam above)</span></div></td></tr>'
            : "";
          return '<tr>' +
            "<td><b>" + Verity.esc(r.source) + "</b></td>" +
            "<td>" + tierBadgeCell(r) + "</td>" +
            "<td>" + laneBadgeCell(r) + "</td>" +
            '<td class="num">' + Verity.esc(r.items_synced == null ? "—" : r.items_synced) + "</td>" +
            '<td>' + (r.cursor
              ? '<span class="note" title="opaque connector checkpoint — display only">' + Verity.esc(r.cursor) + "</span>"
              : '<span class="refreshed">—</span>') + "</td>" +
            "<td>" + ageBadge(evAge, humanAge(evAge)) + "</td>" +
            "<td>" + (cad
              ? Verity.badge("cadence: " + cad, "b-kind")
              : '<span class="refreshed">—</span>') + "</td>" +
            '<td>' + (hbAge != null
              ? '<span title="last heartbeat updated_at ' + Verity.esc(Verity.fmtTime(r.updated_at)) + '">' +
                  Verity.esc(humanAge(hbAge)) + "</span>"
              : '<span class="refreshed">—</span>') + "</td>" +
            "<td>" + errCell + "</td>" +
          "</tr>" + gradRow;
        }).join("");

        Verity.$("src-inv").innerHTML =
          '<div class="tablewrap"><table><thead><tr>' +
            "<th>source</th>" +
            '<th>provenance tier</th>' +
            "<th>lane</th>" +
            '<th class="num">items synced</th>' +
            "<th>cursor</th>" +
            "<th>last-event age</th>" +
            "<th>cadence <span class=\"sub\">(observed)</span></th>" +
            "<th>heartbeat</th>" +
            "<th>inline error</th>" +
          "</tr></thead><tbody>" + body + "</tbody></table></div>" +
          '<div class="note">Last-event age: ' +
            Verity.badge("&lt;15m", "b-conf-0") + " fresh · " +
            Verity.badge("&lt;24h", "b-conf-2") + " stale · " +
            Verity.badge("&ge;24h", "b-conf-3") + " cold · " +
            Verity.badge("no event time", "b-kind") + " honest fallback (a source with no source-side " +
            "clock — e.g. webhook-only — never shows a fake-fresh green).</div>";
      }

      // ---- render: freshness SLO ----------------------------------------
      function renderFreshness() {
        var rows = LAST.fresh;
        var tgt = targetMs();
        if (!rows.length) {
          Verity.$("src-fresh").innerHTML =
            '<div class="empty">No freshness samples in this window. Nothing measured means no number — ' +
            'we show the empty state rather than a fabricated percentile.</div>';
          return;
        }
        var body = rows.map(function (r) {
          var breach = (r.p50_ms != null && tgt != null && r.p50_ms > tgt) ||
                       (r.p95_ms != null && tgt != null && r.p95_ms > tgt);
          return '<tr' + (breach ? ' class="flag"' : "") + ">" +
            "<td><b>" + Verity.esc(r.source) + "</b></td>" +
            '<td class="num">' + Verity.esc(r.samples == null ? "—" : r.samples) + "</td>" +
            '<td class="num">' + pctCell(r.p50_ms, tgt) + "</td>" +
            '<td class="num">' + pctCell(r.p95_ms, tgt) + "</td>" +
            '<td class="num"><span class="refreshed" ' +
              'title="/v1/slo/freshness computes p50 and p95 only — p99 is not computed; ' +
              'we do not fabricate it">not computed</span></td>' +
            '<td class="num">' + (tgt != null
              ? '<span title="operator-set target, not server-authoritative">' + Verity.esc(Verity.fmtMs(tgt)) + "</span>"
              : '<span class="refreshed">unset</span>') + "</td>" +
          "</tr>";
        }).join("");

        Verity.$("src-fresh").innerHTML =
          '<div class="tablewrap"><table><thead><tr>' +
            "<th>source</th>" +
            '<th class="num">samples</th>' +
            '<th class="num">p50</th>' +
            '<th class="num">p95</th>' +
            '<th class="num">p99 <span class="sub">(seam)</span></th>' +
            '<th class="num">SLO target <span class="sub">(operator-set)</span></th>' +
          "</tr></thead><tbody>" + body + "</tbody></table></div>" +
          '<div class="note">A red <b>breach</b> chip marks a real p50/p95 exceeding the stated ' +
            (tgt != null ? "target of " + Verity.esc(Verity.fmtMs(tgt)) : "target (unset)") +
            ". The ACL-sync / grant-staleness window is itself an SLO here — never claimed 'instant' " +
            "(SPEC §7b/§14).</div>";
      }

      // ---- render: backfill ---------------------------------------------
      function renderBackfill() {
        var rows = LAST.backfill;
        if (!rows.length) {
          Verity.$("src-back").innerHTML =
            '<div class="empty">No backfill runs for this tenant.</div>';
          return;
        }
        var body = rows.map(function (r) {
          var bar = progressBar(r);
          return "<tr>" +
            "<td><b>" + Verity.esc(r.source) + "</b></td>" +
            "<td>" + backfillStateBadge(r.state) + "</td>" +
            '<td style="min-width:180px">' + bar.html + "</td>" +
            "<td>" + etaCell(r) + "</td>" +
            '<td>' + (r.error
              ? Verity.badge("error", "b-conf-3") + ' <span class="note">' + Verity.esc(r.error) + "</span>"
              : '<span class="refreshed">—</span>') + "</td>" +
            '<td><span class="refreshed" title="latest heartbeat for this run">' +
              Verity.esc(Verity.fmtTime(r.updated_at)) + "</span></td>" +
          "</tr>";
        }).join("");

        Verity.$("src-back").innerHTML =
          '<div class="tablewrap"><table><thead><tr>' +
            "<th>source</th><th>state</th><th>progress</th><th>ETA</th>" +
            "<th>error</th><th>updated</th>" +
          "</tr></thead><tbody>" + body + "</tbody></table></div>";
      }

      function renderAll() {
        renderInventory();
        renderFreshness();
        renderBackfill();
      }

      // ---- load ---------------------------------------------------------
      async function load() {
        Verity.clearErr("src-err");
        var tenant = activeTenant();
        if (!tenant) {
          Verity.err("src-err", new Error(
            "no tenant selected — decode a scope handle on Scope Inspector or type a tenant_id above"));
          return;
        }
        Verity.setTenant(tenant);
        var win = Math.max(1, Math.min(2160, parseInt(Verity.$("src-window").value, 10) || 24));
        var q = "tenant_id=" + encodeURIComponent(tenant);
        try {
          // Three independent reads — fire together; each surfaces its own error
          // honestly rather than one failure blanking the whole screen.
          var results = await Promise.allSettled([
            Verity.api("/v1/admin/connector-status?" + q, { admin: true }),
            Verity.api("/v1/slo/freshness?" + q + "&window_hours=" + win, { admin: true }),
            Verity.api("/v1/admin/backfill?" + q, { admin: true }),
          ]);
          var errs = [];
          LAST.status   = results[0].status === "fulfilled" && Array.isArray(results[0].value) ? results[0].value : [];
          if (results[0].status === "rejected") errs.push(results[0].reason.message || String(results[0].reason));
          LAST.fresh    = results[1].status === "fulfilled" && Array.isArray(results[1].value) ? results[1].value : [];
          if (results[1].status === "rejected") errs.push(results[1].reason.message || String(results[1].reason));
          LAST.backfill = results[2].status === "fulfilled" && Array.isArray(results[2].value) ? results[2].value : [];
          if (results[2].status === "rejected") errs.push(results[2].reason.message || String(results[2].reason));

          renderAll();
          Verity.$("src-stamp").innerHTML =
            '<span class="refreshed">loaded ' + Verity.esc(Verity.fmtTime(Date.now())) + " · " +
            LAST.status.length + " source(s) · " + LAST.fresh.length + " freshness row(s) · " +
            LAST.backfill.length + " backfill run(s)</span>";
          if (errs.length) Verity.err("src-err", new Error(errs.join("  |  ")));
        } catch (e) {
          Verity.err("src-err", e);
        }
      }

      Verity.$("src-load").onclick = load;
      Verity.$("src-target").addEventListener("input", function () {
        // Re-highlight breaches live against the new operator-set target.
        renderFreshness();
      });

      // Auto-fill the tenant field from shared state.
      Verity.onTenant(function (t) {
        var f = Verity.$("src-tenant");
        if (f && !f.value.trim()) f.placeholder = t ? "(active: " + t + ")" : "(uses active tenant)";
      });
      (function () {
        var t = Verity.tenant();
        var f = Verity.$("src-tenant");
        if (f && t) f.placeholder = "(active: " + t + ")";
      })();
    },
  });
})();
