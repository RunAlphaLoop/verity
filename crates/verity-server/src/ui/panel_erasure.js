"use strict";
/* ==========================================================================
   panel_erasure.js — Screen 4 · Erasure & DSAR  [v0.2]
   --------------------------------------------------------------------------
   STRUCTURAL admin gate (SPEC §5 Screen 4 / §8f): the destructive/admin surface
   is only INSTANTIATED when an admin token is present. A scope-handle session
   never renders the controls — it sees an honest "admin-token required" state.
   We re-check on every show (onShow) so setting/clearing the token in the
   session card flips the panel live, and we NEVER partially build the tools
   with the token absent.

   Backing endpoints (shapes verified against the server):
     • POST /v1/admin/erasure/preview  { tenant_id, subject?, entity?, media_ids?[] }
         → { dry_run: true, would_erase: <ErasureReport>,
             coverage_gaps: { operator_named_media, exact_string_matching,
                              backup_retention_window },
             rebac_tuples_would_delete: bool }. TRUE dry run — rolls back its
             own transaction and purges nothing. `would_erase` is the exact same
             ErasureReport a real erasure produces (both call walk_lineage), so
             it covers subject-, entity- AND media-only erasures. At least one of
             subject / entity / media_ids required (else 422).
     • POST /v1/admin/erasure   { tenant_id, subject?, entity?, media_ids?[] }
         → { erased: <ErasureReport>, rebac_tuples_deleted: bool,
             purge_report: { facts, algorithm, domain, signature, signed } }.
         ErasureReport = { episodes, chunks, facts, actions, knowledge_evidence,
                           knowledge_invalidated, quarantine_preview, audit_log,
                           media } (all u64). `purge_report` is SERVER-SIGNED:
                           signature = HMAC-SHA256 over the compact JSON of the
                           `facts` object; signed=false means an ephemeral/dev
                           key (process-scoped, not durable). Identifiers in
                           `facts` are sha256-hashed, matching the surviving
                           verb='erasure' audit row. At least one of
                           subject / entity / media_ids is required (else 422).
     • GET  /v1/admin/dsar/export?tenant_id=&subject=
         → { tenant_id, subject, generated_at, episodes[], chunks[], actions[],
             audit_log[], knowledge[] }. The export self-audits (writes a
             dsar_export audit row) — it appears in Access Audit.
     • GET  /v1/admin/media?tenant_id=&limit=
         → [ { id, filename, sha256, mime, size_bytes, created_at } … ]
     • POST /v1/forget { scope_handle, ref:{kind:"chunk"|"episode", id}, reason }
         → { retired: <u64> }. INVALIDATION (reversible), not deletion.

   SEAMS NOW CLOSED (were honest seams; now backed by real endpoints):
     1. The erasure PREVIEW is a REAL dry run against POST /v1/admin/erasure/preview
        — it rolls back its own transaction (purges nothing) and returns the exact
        would-purge counts, because preview and erase share one walk_lineage. It
        covers entity- and media-only erasures too, not just subject.
     2. The purge report is SERVER-SIGNED (HMAC-SHA256, domain-separated) — the
        console displays the server's signature, it does not assemble one. When
        the server runs on an ephemeral/dev key (signed=false), that is surfaced
        honestly as process-scoped, not a durable attestation.

   STILL DISCLOSED (real coverage gaps, returned by the server): operator-named
   media (no auto subject attribution), exact-string subject/entity match, and
   the backup-retention window.

   Zero LLM / zero live-ReBAC calls from this panel — pure admin fetches.
   ========================================================================== */
(function () {

  // The purge-report tables in the order we render them, with human labels and
  // a one-line meaning. Keys match ErasureReport fields exactly.
  var REPORT_ROWS = [
    ["episodes", "L0 episodes", "source events attributable to the subject/entity — hard-deleted"],
    ["chunks", "chunks", "retrieval units derived from those episodes (+ entity-tagged, deleted whole)"],
    ["facts", "facts", "structured L1 rows by provenance / entity key — hard-deleted"],
    ["actions", "actions", "the subject's actions / the entity's actions + their provenance episodes"],
    ["knowledge_evidence", "knowledge evidence", "evidence rows withdrawn from cross-customer generalizations"],
    ["knowledge_invalidated", "knowledge invalidated", "published items dropped below the k=3 floor — invalidated by cascade"],
    ["quarantine_preview", "quarantine payloads", "quarantined webhook previews mentioning the subject/entity (substring match)"],
    ["audit_log", "audit rows", "the subject's own access-audit rows"],
    ["media", "media blobs", "operator-named media_ids purged (+ their object-store blobs)"],
  ];

  function fmtBytes(n) {
    if (n == null) return "—";
    n = Number(n);
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  function download(name, mime, text) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  // A collapsible <details> of a pretty-printed JSON payload (DSAR sections).
  function jsonDetails(label, count, obj) {
    return '<details class="card" style="margin-top:8px">' +
      '<summary><b>' + Verity.esc(label) + '</b> ' +
        '<span class="sub">' + Verity.esc(count) + " row(s)</span></summary>" +
      '<div class="tablewrap" style="margin-top:8px"><pre class="note" style="white-space:pre;margin:0">' +
        Verity.esc(JSON.stringify(obj, null, 2)) +
      "</pre></div></details>";
  }

  Verity.register({
    id: "erasure",

    // The router calls mount() ONCE (lazily) then onShow() every time. We keep
    // all real wiring inside a build step that only runs behind the admin gate,
    // and re-evaluate the gate on each show so a token set/cleared in the
    // session card flips the whole panel without a reload.
    mount: function () { /* deferred entirely to onShow — see gate below */ },

    onShow: function () {
      var el = Verity.$("erasure-mount");
      if (!el) return;
      var hasAdmin = !!Verity.getAdminToken();

      // If the gate state is unchanged AND already built, do nothing (avoid
      // rebuilding — and wiping — a live report on every tab return).
      if (el.getAttribute("data-gate") === (hasAdmin ? "admin" : "locked")) return;
      el.setAttribute("data-gate", hasAdmin ? "admin" : "locked");
      el.innerHTML = "";

      if (!hasAdmin) { renderLocked(el); return; }
      build(el);
    },
  });

  /* --------------------------------------------------------------------------
     STRUCTURAL GATE — admin-token-required state.
     Not merely hidden: with no admin token we never construct the destructive
     controls at all. This is the visible half of §8f's structural quarantine.
     -------------------------------------------------------------------------- */
  function renderLocked(el) {
    var card = document.createElement("div");
    card.className = "card";
    card.innerHTML =
      '<h2>Admin token required <span class="sub">erasure is structurally behind the admin token (SPEC §8f)</span></h2>' +
      '<div class="empty" style="margin-top:4px">' +
        "<b>This screen is not available from a scope handle.</b><br>" +
        "Erasure and DSAR are admin/compliance verbs. Their controls are only " +
        "instantiated when an admin token is present — a scope-handle session can " +
        "never reach the destructive path (SPEC §8f). This is a structural quarantine, " +
        "not a hidden button." +
      "</div>" +
      '<div class="note" style="margin-top:10px">Set an <b>admin token</b> in the ' +
        '<em>Session</em> card at the top of the page (held in sessionStorage only, ' +
        "never persisted to disk). This panel will unlock as soon as it is set.</div>";
    el.appendChild(card);
  }

  /* --------------------------------------------------------------------------
     LIVE ADMIN SURFACE (only reached behind the gate).
     -------------------------------------------------------------------------- */
  function build(el) {

    /* -- subject-lookup + coverage-gap disclosure card -------------------- */
    var lookup = document.createElement("div");
    lookup.className = "card";
    lookup.innerHTML =
      '<h2>Subject lookup <span class="sub">who / what to act on</span></h2>' +
      '<div class="row">' +
        '<div class="tight"><label for="er-tenant">tenant_id</label> ' +
          '<input type="text" id="er-tenant" class="field" placeholder="(uses active tenant)" size="30"></div>' +
        '<div class="tight"><label for="er-subject">subject <span class="note">(writer/actor sub — exact string)</span></label> ' +
          '<input type="text" id="er-subject" class="field" placeholder="e.g. user:alice@acme" size="24" autocomplete="off"></div>' +
        '<div class="tight"><label for="er-entity">entity <span class="note">(source_entity — exact string)</span></label> ' +
          '<input type="text" id="er-entity" class="field" placeholder="e.g. account:acme-inc" size="20" autocomplete="off"></div>' +
      "</div>" +
      '<div class="row" style="margin-top:6px">' +
        '<div class="tight" style="flex:1 1 100%"><label for="er-media">media_ids ' +
          '<span class="note">(operator-named blob UUIDs, comma/space separated — no automatic subject attribution)</span></label> ' +
          '<input type="text" id="er-media" class="field" placeholder="uuid, uuid …" style="width:100%" autocomplete="off"></div>' +
      "</div>" +
      '<div class="row" style="margin-top:6px">' +
        '<div class="tight"><button id="er-media-list">Find named media…</button></div>' +
        '<div class="tight"><span class="refreshed">at least one of subject / entity / media_ids is required</span></div>' +
      "</div>" +

      // Honest coverage-gap disclosure (SPEC §8b): disclose the window, do not
      // claim perfection.
      '<div class="note" style="margin-top:12px;border-left:3px solid var(--amber,#c90);padding-left:10px">' +
        '<b>Coverage gaps — disclosed, not hidden.</b><br>' +
        "• <b>Media has no automatic subject attribution.</b> Blobs are only purged when you " +
          "explicitly name their <code>media_ids</code> — use <em>Find named media</em> to list candidates. " +
          "An unnamed blob survives.<br>" +
        "• <b>Matching is exact-string on subject / entity.</b> An alias, a differently-cased sub, or a " +
          "mistyped entity will not be walked. Confirm identifiers before running.<br>" +
        "• <b>Backup-retention window.</b> Hard purge removes live rows and destroys keys in the primary store; " +
          "physical backups already taken persist until they age out of the retention window and are then " +
          "unrecoverable (crypto-shredded). This is a real window, disclosed — not instantaneous perfection." +
      "</div>" +
      '<div id="er-media-out"></div>' +
      '<div class="err" id="er-lookup-err"></div>';
    el.appendChild(lookup);

    /* -- erasure PREVIEW card (real dry run — POST /v1/admin/erasure/preview) */
    var preview = document.createElement("div");
    preview.className = "card";
    preview.innerHTML =
      '<h2>Erasure preview <span class="sub">what would purge — true dry run, purges nothing</span></h2>' +
      '<div class="note"><b>This is a real dry run.</b> It calls ' +
        "<code>POST /v1/admin/erasure/preview</code>, which runs the exact same lineage walk as the " +
        "destructive erasure inside a transaction it then <b>rolls back</b> — <b>nothing is purged</b>. " +
        "The counts below are the <b>true would-purge counts</b>: one shared <code>walk_lineage</code> " +
        "feeds both preview and erase, so they cannot drift. Unlike the old DSAR-based proxy, this covers " +
        "<em>entity-</em> and <em>media-only</em> erasures too, not just subject.</div>" +
      '<div class="row" style="margin-top:8px">' +
        '<div class="tight"><button id="er-preview" class="primary">Preview would-purge counts</button></div>' +
        '<div class="tight"><span class="refreshed" id="er-preview-stamp"></span></div>' +
      "</div>" +
      '<div class="err" id="er-preview-err"></div>' +
      '<div id="er-preview-out"></div>';
    el.appendChild(preview);

    /* -- run-erasure card ------------------------------------------------- */
    var run = document.createElement("div");
    run.className = "card";
    run.innerHTML =
      '<h2>Run erasure <span class="sub">POST /v1/admin/erasure — irreversible crypto-shred</span></h2>' +
      '<div class="note"><b>This is a hard purge, not <code>forget</code>.</b> It deletes rows and destroys ' +
        "keys in one transaction and returns per-table counts. When SpiceDB is configured and the subject " +
        "is a <code>user:</code> principal, its ReBAC tuples are deleted <b>first</b> (fail-closed: a tuple " +
        "failure aborts the whole erasure — nothing is half-purged). There is <b>no undo</b>.</div>" +
      '<div class="row" style="margin-top:8px">' +
        '<div class="tight"><button id="er-run" class="primary">Run erasure…</button></div>' +
      "</div>" +
      '<div class="err" id="er-run-err"></div>' +
      '<div id="er-run-out"></div>';
    el.appendChild(run);

    /* -- DSAR export card ------------------------------------------------- */
    var dsar = document.createElement("div");
    dsar.className = "card";
    dsar.innerHTML =
      '<h2>DSAR export <span class="sub">GET /v1/admin/dsar/export — audited bundle</span></h2>' +
      '<div class="note">One machine-readable JSON bundle of everything attributable to the <b>subject</b>: ' +
        "episodes (decrypted under admin authority), their derived chunks, the subject's actions, the " +
        "access-event skeleton (audit rows), and proposed knowledge. <b>The export self-audits</b> — it " +
        "writes a <code>dsar_export</code> row that appears in <em>Access Audit</em>, so the subject-data " +
        "access is itself on the record.</div>" +
      '<div class="row" style="margin-top:8px">' +
        '<div class="tight"><button id="er-dsar" class="primary">Preview &amp; export DSAR bundle</button></div>' +
        '<div class="tight"><span class="refreshed" id="er-dsar-stamp"></span></div>' +
      "</div>" +
      '<div class="err" id="er-dsar-err"></div>' +
      '<div id="er-dsar-out"></div>';
    el.appendChild(dsar);

    /* -- item-level retract (forget) card --------------------------------- */
    var forget = document.createElement("div");
    forget.className = "card";
    forget.innerHTML =
      '<h2>Item-level retract <span class="sub">POST /v1/forget — ' +
        Verity.badge("invalidate (reversible), not delete", "b-inferred") + "</span></h2>" +
      '<div class="note"><b>This is invalidation, not erasure.</b> <code>forget</code> retires a single ' +
        "chunk or episode by stamping <code>valid_to</code> — the row keeps existing, as-of history is " +
        "preserved, and it can be reversed. It is a <b>scope-token</b> call (the tenant comes from the " +
        "signed handle, never the body), so paste the scope handle it should run under. Use " +
        "<em>Run erasure</em> above for the irreversible hard purge.</div>" +
      '<div class="row" style="margin-top:8px">' +
        '<div class="tight" style="flex:1 1 100%"><label for="er-fg-handle">scope_handle</label> ' +
          '<input type="text" id="er-fg-handle" class="field" placeholder="vs_…" style="width:100%" autocomplete="off"></div>' +
      "</div>" +
      '<div class="row" style="margin-top:6px">' +
        '<div class="tight"><label for="er-fg-kind">ref kind</label> ' +
          '<select id="er-fg-kind" class="field">' +
            '<option value="episode">episode</option>' +
            '<option value="chunk">chunk</option>' +
          "</select></div>" +
        '<div class="tight"><label for="er-fg-id">id <span class="note">(uuid)</span></label> ' +
          '<input type="text" id="er-fg-id" class="field" placeholder="uuid" size="30" autocomplete="off"></div>' +
        '<div class="tight"><label for="er-fg-reason">reason</label> ' +
          '<input type="text" id="er-fg-reason" class="field" placeholder="why invalidate" size="24" autocomplete="off"></div>' +
        '<div class="tight"><button id="er-fg-run">Invalidate (reversible)…</button></div>' +
      "</div>" +
      '<div class="err" id="er-fg-err"></div>' +
      '<div id="er-fg-out"></div>';
    el.appendChild(forget);

    /* -- typed-confirm dialog (erasure) ----------------------------------- */
    var confirmEl = document.createElement("div");
    confirmEl.className = "dialog-backdrop";
    confirmEl.id = "er-confirm-dialog";
    confirmEl.innerHTML =
      '<div class="dialog" style="max-width:620px">' +
        '<h3>Confirm irreversible crypto-shred</h3>' +
        '<div class="note" id="er-confirm-summary"></div>' +
        '<div class="note" style="margin-top:8px;border-left:3px solid var(--red,#c33);padding-left:10px">' +
          "<b>This cannot be undone.</b> Rows are hard-deleted and keys destroyed in one transaction. " +
          "This is not <code>forget</code>; there is no reversal." +
        "</div>" +
        '<div class="tight" style="margin-top:12px">' +
          '<label for="er-confirm-input">To confirm, type the <b>subject id</b> exactly ' +
            '(<span id="er-confirm-target" class="note"></span>)</label>' +
          '<input type="text" id="er-confirm-input" class="field" placeholder="type the subject id to confirm" style="width:100%" autocomplete="off">' +
        "</div>" +
        '<div class="note" id="er-confirm-hint" style="margin-top:6px"></div>' +
        '<div class="err" id="er-confirm-err"></div>' +
        '<div class="actions">' +
          '<button class="primary" id="er-confirm-go" disabled>Crypto-shred — irreversible</button>' +
          '<button id="er-confirm-cancel">Cancel</button>' +
        "</div>" +
      "</div>";
    el.appendChild(confirmEl);
    var confirmDlg = Verity.dialog("er-confirm-dialog");

    /* ==================================================================== */
    /*  helpers over the shared inputs                                       */
    /* ==================================================================== */
    function activeTenant() {
      var typed = Verity.$("er-tenant").value.trim();
      return typed || Verity.tenant() || "";
    }
    function currentSubject() { return Verity.$("er-subject").value.trim(); }
    function currentEntity() { return Verity.$("er-entity").value.trim(); }
    function parseMediaIds() {
      var raw = Verity.$("er-media").value.trim();
      if (!raw) return [];
      return raw.split(/[\s,]+/).filter(function (s) { return s.length; });
    }
    // Auto-fill tenant placeholder from shared state.
    Verity.onTenant(function (t) {
      var f = Verity.$("er-tenant");
      if (f && !f.value.trim()) f.placeholder = t ? "(active: " + t + ")" : "(uses active tenant)";
    });
    (function () {
      var t = Verity.tenant(); var f = Verity.$("er-tenant");
      if (f && t) f.placeholder = "(active: " + t + ")";
    })();

    /* ==================================================================== */
    /*  FIND NAMED MEDIA (GET /v1/admin/media)                               */
    /* ==================================================================== */
    Verity.$("er-media-list").onclick = async function () {
      Verity.clearErr("er-lookup-err");
      var tenant = activeTenant();
      if (!tenant) { Verity.err("er-lookup-err", new Error("enter a tenant_id first")); return; }
      var out = Verity.$("er-media-out");
      out.innerHTML = '<div class="note">loading GET /v1/admin/media …</div>';
      try {
        var rows = await Verity.api(
          "/v1/admin/media?tenant_id=" + encodeURIComponent(tenant) + "&limit=200",
          { admin: true });
        rows = Array.isArray(rows) ? rows : [];
        if (!rows.length) {
          out.innerHTML = '<div class="empty">No media blobs for this tenant. ' +
            "Nothing to name in an erasure — that is not an error.</div>";
          return;
        }
        var body = rows.map(function (m) {
          var idAttr = Verity.esc(m.id);
          return "<tr>" +
            '<td><code>' + idAttr + "</code></td>" +
            "<td>" + Verity.esc(m.filename || "—") + "</td>" +
            "<td>" + Verity.esc(m.mime || "—") + "</td>" +
            '<td class="num">' + Verity.esc(fmtBytes(m.size_bytes)) + "</td>" +
            "<td>" + Verity.esc(m.created_at ? Verity.fmtTime(m.created_at) : "—") + "</td>" +
            '<td><button class="er-add-media" data-id="' + idAttr + '">Add to media_ids</button></td>' +
            "</tr>";
        }).join("");
        out.innerHTML =
          '<div class="note" style="margin-top:8px"><b>' + rows.length + " blob(s).</b> " +
            "Media carries no automatic subject attribution — you name the ones to purge (SPEC §8b).</div>" +
          '<div class="tablewrap" style="margin-top:6px"><table><thead><tr>' +
            "<th>id</th><th>filename</th><th>mime</th><th class=\"num\">size</th><th>created</th><th></th>" +
          "</tr></thead><tbody>" + body + "</tbody></table></div>";
        var btns = out.querySelectorAll(".er-add-media");
        for (var i = 0; i < btns.length; i++) {
          btns[i].onclick = function () {
            var id = this.getAttribute("data-id");
            var f = Verity.$("er-media");
            var have = parseMediaIds();
            if (have.indexOf(id) < 0) {
              f.value = (f.value.trim() ? f.value.trim() + ", " : "") + id;
            }
          };
        }
      } catch (e) {
        out.innerHTML = "";
        Verity.err("er-lookup-err", e);
      }
    };

    /* ==================================================================== */
    /*  PREVIEW (real dry run — POST /v1/admin/erasure/preview)              */
    /* ==================================================================== */
    Verity.$("er-preview").onclick = async function () {
      Verity.clearErr("er-preview-err");
      Verity.$("er-preview-out").innerHTML = "";
      Verity.$("er-preview-stamp").textContent = "";
      var tenant = activeTenant();
      var s = currentSubject(), e = currentEntity(), m = parseMediaIds();
      if (!tenant) { Verity.err("er-preview-err", new Error("enter a tenant_id")); return; }
      if (!s && !e && !m.length) {
        Verity.err("er-preview-err", new Error(
          "nothing to preview — provide at least one of subject / entity / media_ids (server returns 422 otherwise)"));
        return;
      }
      var body = { tenant_id: tenant };
      if (s) body.subject = s;
      if (e) body.entity = e;
      if (m.length) body.media_ids = m;
      var out = Verity.$("er-preview-out");
      out.innerHTML = '<div class="note">POST /v1/admin/erasure/preview … (dry run — rolls back, purges nothing)</div>';
      try {
        var res = await Verity.api("/v1/admin/erasure/preview", { admin: true, json: body });
        renderPreview(out, res, { tenant: tenant, subject: s, entity: e, media_ids: m });
        Verity.$("er-preview-stamp").textContent =
          "previewed " + Verity.fmtTime(Date.now()) + " · dry run, nothing purged";
      } catch (e2) {
        out.innerHTML = "";
        Verity.err("er-preview-err", e2);
      }
    };

    function renderPreview(out, res, req) {
      res = res || {};
      var report = res.would_erase || {};
      var gaps = res.coverage_gaps || {};

      // Same per-table rows the real erasure result renders, from the SAME
      // ErasureReport shape — preview and erase share walk_lineage, so these are
      // the true would-purge counts, not an approximation.
      var anything = 0;
      var rows = REPORT_ROWS.map(function (r) {
        var key = r[0], label = r[1], meaning = r[2];
        var n = report[key];
        anything += Number(n || 0);
        return "<tr>" +
          "<td>" + Verity.esc(label) + "</td>" +
          '<td class="num">' + Verity.esc(n == null ? "0" : n) + "</td>" +
          '<td><span class="note">' + Verity.esc(meaning) + "</span></td>" +
        "</tr>";
      }).join("");

      var target =
        (req.subject ? "subject <code>" + Verity.esc(req.subject) + "</code>" : "") +
        (req.entity ? (req.subject ? " · " : "") + "entity <code>" + Verity.esc(req.entity) + "</code>" : "") +
        (req.media_ids && req.media_ids.length
          ? ((req.subject || req.entity) ? " · " : "") + req.media_ids.length + " media_id(s)" : "");

      var rebacLine = res.rebac_tuples_would_delete === true
        ? '<div style="margin-top:8px">' + Verity.badge("ReBAC tuples would be deleted", "b-provenance") + "</div>"
        : '<div style="margin-top:8px">' + Verity.badge("no ReBAC tuple delete", "b-inferred") +
          ' <span class="note">(SpiceDB not configured, or the subject is not a <code>user:</code> principal)</span></div>';

      var head =
        '<div class="note" style="margin-top:10px"><b>True would-purge counts for ' + target + ".</b> " +
          "This is a real dry run: the server ran the destructive lineage walk and <b>rolled it back</b>. " +
          "The same <code>walk_lineage</code> runs on erasure, so these counts cannot drift from what a " +
          "real erasure would purge.</div>" +
        rebacLine +
        '<div class="tablewrap" style="margin-top:8px"><table><thead><tr>' +
          "<th>table</th><th class=\"num\">would purge</th><th>what</th>" +
        "</tr></thead><tbody>" + rows + "</tbody></table></div>";
      if (!anything) {
        head += '<div class="empty" style="margin-top:8px">Nothing attributable to this target was found. ' +
          "An erasure would purge 0 rows — verify the identifiers (exact-string match).</div>";
      }

      // Coverage-gap disclosure, driven by the SERVER's own returned strings.
      var gapRows = [
        ["operator_named_media", "operator-named media"],
        ["exact_string_matching", "exact-string matching"],
        ["backup_retention_window", "backup-retention window"],
      ].filter(function (g) { return gaps[g[0]]; })
       .map(function (g) {
        return "<li><b>" + Verity.esc(g[1]) + ".</b> " + Verity.esc(gaps[g[0]]) + "</li>";
      }).join("");
      var gapBlock = gapRows
        ? '<div class="note" style="margin-top:12px;border-left:3px solid var(--amber,#c90);padding-left:10px">' +
            "<b>Coverage gaps — reported by the server, not hidden.</b>" +
            '<ul style="margin:6px 0 0 0;padding-left:18px">' + gapRows + "</ul></div>"
        : "";

      out.innerHTML = head + gapBlock;
    }

    /* ==================================================================== */
    /*  RUN ERASURE (typed confirm → POST /v1/admin/erasure)                 */
    /* ==================================================================== */
    // The confirm token: the subject id if present, else the entity, else a
    // synthetic "media-only" phrase so a media-only purge still requires a typed
    // acknowledgement of exactly what is being destroyed.
    function confirmTarget() {
      var s = currentSubject();
      if (s) return { token: s, label: "subject", human: s };
      var e = currentEntity();
      if (e) return { token: e, label: "entity", human: e };
      var m = parseMediaIds();
      if (m.length) return { token: "ERASE MEDIA", label: "media-only", human: m.length + " media_id(s)" };
      return null;
    }

    Verity.$("er-run").onclick = function () {
      Verity.clearErr("er-run-err");
      var tenant = activeTenant();
      if (!tenant) { Verity.err("er-run-err", new Error("enter a tenant_id")); return; }
      var t = confirmTarget();
      if (!t) {
        Verity.err("er-run-err", new Error(
          "nothing to erase — provide at least one of subject / entity / media_ids (SPEC: server returns 422 otherwise)"));
        return;
      }
      // Prime the dialog.
      var s = currentSubject(), e = currentEntity(), m = parseMediaIds();
      Verity.$("er-confirm-summary").innerHTML =
        "<b>tenant:</b> <code>" + Verity.esc(tenant) + "</code><br>" +
        "<b>subject:</b> " + (s ? "<code>" + Verity.esc(s) + "</code>" : '<span class="refreshed">—</span>') + "<br>" +
        "<b>entity:</b> " + (e ? "<code>" + Verity.esc(e) + "</code>" : '<span class="refreshed">—</span>') + "<br>" +
        "<b>media_ids:</b> " + (m.length ? m.length + " named" : '<span class="refreshed">none</span>');
      Verity.$("er-confirm-target").textContent =
        t.label === "media-only"
          ? 'no subject/entity — type ERASE MEDIA to confirm the media-only purge'
          : t.label + ": " + t.human;
      Verity.$("er-confirm-hint").innerHTML =
        t.label === "media-only"
          ? "No subject or entity was given. Type <code>ERASE MEDIA</code> exactly to confirm."
          : "Type the <b>" + Verity.esc(t.label) + " id</b> exactly: <code>" + Verity.esc(t.token) + "</code>";
      var input = Verity.$("er-confirm-input");
      var go = Verity.$("er-confirm-go");
      input.value = "";
      go.disabled = true;
      Verity.clearErr("er-confirm-err");
      input.oninput = function () { go.disabled = input.value !== t.token; };
      go.onclick = async function () {
        if (input.value !== t.token) return; // belt-and-suspenders
        Verity.clearErr("er-confirm-err");
        go.disabled = true;
        var body = { tenant_id: tenant };
        if (s) body.subject = s;
        if (e) body.entity = e;
        if (m.length) body.media_ids = m;
        try {
          var res = await Verity.api("/v1/admin/erasure", { admin: true, json: body });
          confirmDlg.close();
          renderErasureResult(res);
        } catch (err) {
          Verity.err("er-confirm-err", err);
          go.disabled = false;
        }
      };
      confirmDlg.open();
    };
    Verity.$("er-confirm-cancel").onclick = function () { confirmDlg.close(); };

    function renderErasureResult(res) {
      res = res || {};
      var report = res.erased || {};

      // Per-table purge counts.
      var rows = REPORT_ROWS.map(function (r) {
        var key = r[0], label = r[1], meaning = r[2];
        var n = report[key];
        return "<tr>" +
          "<td>" + Verity.esc(label) + "</td>" +
          '<td class="num">' + Verity.esc(n == null ? "0" : n) + "</td>" +
          '<td><span class="note">' + Verity.esc(meaning) + "</span></td>" +
        "</tr>";
      }).join("");

      var rebac = res.rebac_tuples_deleted;
      var rebacLine = rebac === true
        ? Verity.badge("ReBAC tuples deleted first", "b-provenance")
        : Verity.badge("no ReBAC tuple delete", "b-inferred") +
          ' <span class="note">(SpiceDB not configured, or the subject is not a <code>user:</code> principal — no tuples exist for it)</span>';

      // Knowledge-retraction cascade note (honest, driven by the real count).
      var invalidated = report.knowledge_invalidated || 0;
      var cascade =
        '<div class="note" style="margin-top:10px"><b>Knowledge-retraction cascade.</b> ' +
        (invalidated > 0
          ? "<b>" + invalidated + "</b> published generalization(s) fell below the k=3 distinct-entity floor " +
            "after this subject's evidence was withdrawn and were <b>invalidated</b> (not deleted — the " +
            "de-identified statement itself carries no subject data). "
          : "No published generalization dropped below the k=3 floor from this erasure. ") +
        "Withdrawn evidence rows: <b>" + (report.knowledge_evidence || 0) + "</b>.</div>";

      // The purge report is now SERVER-SIGNED. The server returns a `purge_report`
      // envelope { facts, algorithm, domain, signature, signed }. We DISPLAY the
      // server's signature — we do not assemble one. `signed:false` = ephemeral/
      // dev key (process-scoped, not durable); surfaced honestly below.
      var pr = res.purge_report || null;
      var reportJson = pr ? JSON.stringify(pr, null, 2) : "";
      var signed = !!(pr && pr.signed);
      var sig = (pr && pr.signature) || "";
      var facts = (pr && pr.facts) || {};

      var sigBlock;
      if (!pr) {
        // Backward-compat: an older server without purge_report. Say so honestly.
        sigBlock =
          '<div class="note" style="margin-top:10px;border-left:3px solid var(--amber,#c90);padding-left:10px">' +
            "<b>No signed report returned.</b> This server build did not include a " +
            "<code>purge_report</code> in its response. What survives is one <code>erasure</code> audit row " +
            "holding a <code>sha256</code> of the subject/entity + these counts — cross-check against Access Audit." +
          "</div>";
      } else {
        var trustLine = signed
          ? Verity.badge("server-signed", "b-provenance") +
            ' <span class="note">HMAC-SHA256 over the compact <code>facts</code> object, domain ' +
            "<code>" + Verity.esc(pr.domain || "") + "</code>, under the server's persistent signing key.</span>"
          : Verity.badge("dev key — unsigned", "b-inferred") +
            ' <span class="note">The server is running on an <b>ephemeral/dev key</b> ' +
            "(no <code>VERITY_SIGNING_KEY</code>/<code>VERITY_SCOPE_KEY</code> set). The tag below only " +
            "verifies within the current process lifetime — it is <b>process-scoped, not a durable " +
            "attestation</b>. Set a persistent key for a real signature.</span>";
        sigBlock =
          '<div class="note" style="margin-top:10px;border-left:3px solid var(--' +
            (signed ? "green,#2a7" : "amber,#c90") + ');padding-left:10px">' +
            "<b>Server-signed purge report.</b> " + trustLine + "<br>" +
            "Identifiers in the report are <code>sha256</code>-hashed (never plaintext) and match the " +
            "surviving <code>erasure</code> audit row, so a report holder can cross-check it against " +
            "Access Audit." +
          '<div style="margin-top:8px"><b>algorithm:</b> <code>' + Verity.esc(pr.algorithm || "—") + "</code> · " +
            "<b>domain:</b> <code>" + Verity.esc(pr.domain || "—") + "</code></div>" +
          '<div style="margin-top:6px"><b>signature:</b><br>' +
            '<code style="word-break:break-all">' + Verity.esc(sig || "(none)") + "</code></div>" +
          '<div style="margin-top:6px"><b>signed_at:</b> <code>' +
            Verity.esc(facts.signed_at ? Verity.fmtTime(facts.signed_at) : "—") + "</code></div>" +
          "</div>";
      }

      var out = Verity.$("er-run-out");
      out.innerHTML =
        '<div class="card" style="margin-top:10px">' +
          '<h2>Erasure complete <span class="sub">per-table hard-delete counts</span></h2>' +
          '<div>' + rebacLine + "</div>" +
          '<div class="tablewrap" style="margin-top:8px"><table><thead><tr>' +
            "<th>table</th><th class=\"num\">purged</th><th>what</th>" +
          "</tr></thead><tbody>" + rows + "</tbody></table></div>" +
          cascade +
          sigBlock +
          (pr
            ? '<div class="actions" style="margin-top:8px">' +
                '<button class="primary" id="er-report-dl">Download signed purge report</button>' +
                '<button id="er-report-copy">Copy JSON</button>' +
              "</div>"
            : "") +
        "</div>";

      if (pr) {
        Verity.$("er-report-dl").onclick = function () {
          download("verity-erasure-report-" + Date.now() + ".json", "application/json", reportJson);
        };
        Verity.$("er-report-copy").onclick = function () {
          try { navigator.clipboard && navigator.clipboard.writeText(reportJson); } catch (e) { /* clipboard best-effort */ }
        };
      }
    }

    /* ==================================================================== */
    /*  DSAR EXPORT (GET /v1/admin/dsar/export — self-audits)                */
    /* ==================================================================== */
    Verity.$("er-dsar").onclick = async function () {
      Verity.clearErr("er-dsar-err");
      Verity.$("er-dsar-out").innerHTML = "";
      Verity.$("er-dsar-stamp").textContent = "";
      var tenant = activeTenant();
      var subject = currentSubject();
      if (!tenant) { Verity.err("er-dsar-err", new Error("enter a tenant_id")); return; }
      if (!subject) { Verity.err("er-dsar-err", new Error("DSAR export keys on subject — enter a subject")); return; }
      var out = Verity.$("er-dsar-out");
      out.innerHTML = '<div class="note">GET /v1/admin/dsar/export … (this self-audits)</div>';
      try {
        var b = await Verity.api(
          "/v1/admin/dsar/export?tenant_id=" + encodeURIComponent(tenant) +
            "&subject=" + encodeURIComponent(subject),
          { admin: true });
        renderDsar(out, b);
        Verity.$("er-dsar-stamp").textContent =
          "exported " + Verity.fmtTime(Date.now()) + " · a dsar_export row is now in Access Audit";
      } catch (e) {
        out.innerHTML = "";
        Verity.err("er-dsar-err", e);
      }
    };

    function renderDsar(out, b) {
      b = b || {};
      var counts = {
        episodes: (b.episodes || []).length,
        chunks: (b.chunks || []).length,
        actions: (b.actions || []).length,
        audit_log: (b.audit_log || []).length,
        knowledge: (b.knowledge || []).length,
      };
      var bundleJson = JSON.stringify(b, null, 2);
      out.innerHTML =
        '<div class="card" style="margin-top:10px">' +
          '<h2>DSAR bundle <span class="sub">subject ' +
            "<code>" + Verity.esc(b.subject || "") + "</code></span></h2>" +
          '<div class="note">generated_at ' + Verity.esc(b.generated_at ? Verity.fmtTime(b.generated_at) : "—") +
            " · this read self-audited as a <code>dsar_export</code> (see Access Audit).</div>" +
          '<div class="tablewrap" style="margin-top:8px"><table><thead><tr>' +
            "<th>section</th><th class=\"num\">rows</th></tr></thead><tbody>" +
            "<tr><td>episodes (decrypted)</td><td class=\"num\">" + counts.episodes + "</td></tr>" +
            "<tr><td>chunks</td><td class=\"num\">" + counts.chunks + "</td></tr>" +
            "<tr><td>actions</td><td class=\"num\">" + counts.actions + "</td></tr>" +
            "<tr><td>access-event skeleton (audit)</td><td class=\"num\">" + counts.audit_log + "</td></tr>" +
            "<tr><td>proposed knowledge</td><td class=\"num\">" + counts.knowledge + "</td></tr>" +
          "</tbody></table></div>" +
          jsonDetails("episodes", counts.episodes, b.episodes || []) +
          jsonDetails("chunks", counts.chunks, b.chunks || []) +
          jsonDetails("actions", counts.actions, b.actions || []) +
          jsonDetails("access-event skeleton", counts.audit_log, b.audit_log || []) +
          jsonDetails("proposed knowledge", counts.knowledge, b.knowledge || []) +
          '<div class="actions" style="margin-top:8px">' +
            '<button class="primary" id="er-dsar-dl">Download bundle (JSON)</button>' +
          "</div>" +
        "</div>";
      Verity.$("er-dsar-dl").onclick = function () {
        download("verity-dsar-" + (b.subject || "subject") + "-" + Date.now() + ".json",
          "application/json", bundleJson);
      };
    }

    /* ==================================================================== */
    /*  ITEM-LEVEL RETRACT (POST /v1/forget — reversible invalidation)       */
    /* ==================================================================== */
    Verity.$("er-fg-run").onclick = async function () {
      Verity.clearErr("er-fg-err");
      Verity.$("er-fg-out").innerHTML = "";
      var handle = Verity.$("er-fg-handle").value.trim();
      var kind = Verity.$("er-fg-kind").value;
      var id = Verity.$("er-fg-id").value.trim();
      var reason = Verity.$("er-fg-reason").value.trim();
      if (!handle) { Verity.err("er-fg-err", new Error("paste the scope_handle to run forget under (tenant comes from the signed handle)")); return; }
      if (!id) { Verity.err("er-fg-err", new Error("enter the chunk/episode id to invalidate")); return; }
      if (!reason) { Verity.err("er-fg-err", new Error("a reason is required — it is recorded on the invalidation")); return; }
      var btn = Verity.$("er-fg-run");
      btn.disabled = true;
      try {
        // forget is a SCOPE-TOKEN call — NOT admin. Tenant/actor come from the
        // signed handle, never the request body (SPEC §2/§9a: never trust
        // client-supplied scope). We send the handle in-body per the endpoint.
        var res = await Verity.api("/v1/forget", {
          json: { scope_handle: handle, ref: { kind: kind, id: id }, reason: reason },
        });
        var retired = (res && res.retired) || 0;
        Verity.$("er-fg-out").innerHTML =
          '<div class="note" style="margin-top:8px">' +
            Verity.badge("invalidated (reversible)", "b-provenance") + " " +
            "<b>" + Verity.esc(retired) + "</b> row(s) retired (stamped <code>valid_to</code>) for " +
            Verity.esc(kind) + " <code>" + Verity.esc(id) + "</code>. " +
            "As-of history is preserved; this is not a delete.</div>";
      } catch (e) {
        Verity.err("er-fg-err", e);
      } finally {
        btn.disabled = false;
      }
    };
  }
})();
