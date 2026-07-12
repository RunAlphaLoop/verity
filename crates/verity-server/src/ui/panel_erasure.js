"use strict";
/* ==========================================================================
   panel_erasure.js — Erasure & data export (v2 rebuild)
   --------------------------------------------------------------------------
   THE LAW, applied:
     • plain-language primary labels — "conversations / events", "search
       snippets", "files"; the table/column jargon (L0 episodes, chunks,
       knowledge_evidence, …) lives ONLY in mono secondary text;
     • names first — files render filename-first with the UUID as a .ref;
     • the screen auto-loads the tenant's files once tenant + admin token are
       known (never a cold Load button); locked/no-tenant states TEACH;
     • every fail-closed gate kept: structural admin gate (controls never
       built without a token), typed-confirm crypto-shred, at-least-one-target
       (server 422 mirrored), server-signed report displayed (never assembled;
       dev-key signed:false disclosed), forget always labeled reversible;
     • honesty: preview is a real dry run (rolls back), coverage gaps are the
       SERVER's returned strings, zero results say "0 — check the identifiers",
       never a fabricated name or number.
   Endpoints verified against crates/verity-server/src/{main,compliance,media}.rs.
   Zero LLM / zero live-ReBAC calls from this panel.
   ========================================================================== */
(function () {
  var V = window.Verity;

  /* ------------------------------------------------- plain-word vocabulary */
  // ErasureReport keys → humane words. `noun` [singular, plural] feeds the
  // headline sentence; `meaning` the table; `jargon` is mono-secondary ONLY.
  var REPORT_ROWS = [
    { key: "episodes", noun: ["conversation / event", "conversations / events"],
      meaning: "the original events written about them — deleted outright",
      jargon: "L0 episodes" },
    { key: "chunks", noun: ["search snippet", "search snippets"],
      meaning: "the searchable pieces made from those events",
      jargon: "chunks (entity-tagged ones deleted whole)" },
    { key: "facts", noun: ["profile fact", "profile facts"],
      meaning: "structured field values keyed to this person / record",
      jargon: "L1 facts (keyed upserts)" },
    { key: "actions", noun: ["recorded action", "recorded actions"],
      meaning: "actions they took, or actions targeting the record",
      jargon: "actions + provenance episodes" },
    { key: "knowledge_evidence", noun: ["piece of evidence behind a shared lesson", "pieces of evidence behind shared lessons"],
      meaning: "their evidence withdrawn from shared lessons",
      jargon: "knowledge_evidence" },
    { key: "knowledge_invalidated", noun: ["published lesson taken down", "published lessons taken down"],
      meaning: "published lessons left with fewer than 3 supporting entities get unpublished",
      jargon: "knowledge_invalidated · k=3 cascade" },
    { key: "quarantine_preview", noun: ["quarantined preview", "quarantined previews"],
      meaning: "refused webhook payloads that mention them",
      jargon: "quarantine_preview · substring match" },
    { key: "audit_log", noun: ["access-log row", "access-log rows"],
      meaning: "their own rows in the access log",
      jargon: "audit_log" },
    { key: "media", noun: ["file", "files"],
      meaning: "the files named in step 1, including their stored blobs",
      jargon: "media + object-store blobs" },
  ];

  // "Would remove 3 conversations / events, 12 search snippets and 1 file."
  function headline(report, verb) {
    var parts = [];
    REPORT_ROWS.forEach(function (r) {
      var n = Number((report || {})[r.key] || 0);
      if (n > 0) parts.push("<b>" + n + " " + V.esc(n === 1 ? r.noun[0] : r.noun[1]) + "</b>");
    });
    if (!parts.length) return verb + " <b>nothing</b> — no rows match these identifiers.";
    var last = parts.pop();
    return verb + " " + (parts.length ? parts.join(", ") + " and " + last : last) + ".";
  }

  function reportTable(report, colHead) {
    var rows = REPORT_ROWS.map(function (r) {
      var n = (report || {})[r.key];
      return "<tr><td>" + V.esc(r.noun[1]) + "</td>" +
        '<td class="num">' + V.esc(n == null ? "0" : n) + "</td>" +
        '<td><span class="note">' + V.esc(r.meaning) + "</span> " +
        V.refSpan(r.jargon) + "</td></tr>";
    }).join("");
    return '<div class="tablewrap" style="margin-top:8px"><table><thead><tr>' +
      "<th>what</th><th class=\"num\">" + V.esc(colHead) + "</th><th>meaning</th>" +
      "</tr></thead><tbody>" + rows + "</tbody></table></div>";
  }

  var GAP_LABELS = {
    operator_named_media: "Files must be named by hand",
    exact_string_matching: "Exact-name matching only",
    backup_retention_window: "Old backups linger for a while",
  };

  // Coverage gaps — the SERVER's own strings, plain headers, never invented.
  function gapsBlock(gaps) {
    gaps = gaps || {};
    var items = Object.keys(GAP_LABELS).filter(function (k) { return gaps[k]; })
      .map(function (k) {
        return "<li><b>" + V.esc(GAP_LABELS[k]) + ".</b> " + V.esc(gaps[k]) + "</li>";
      }).join("");
    if (!items) return "";
    return '<div class="note" style="margin-top:12px;border-left:3px solid var(--state-attn);padding-left:10px">' +
      "<b>What this cannot reach — reported by the server, not hidden:</b>" +
      '<ul style="margin:6px 0 0 0;padding-left:18px">' + items + "</ul></div>";
  }

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

  function jsonDetails(label, count, obj) {
    return '<details class="card" style="margin-top:8px">' +
      "<summary><b>" + V.esc(label) + "</b> " +
      '<span class="sub">' + V.esc(count) + " row(s)</span></summary>" +
      '<div class="tablewrap" style="margin-top:8px"><pre class="note" style="white-space:pre;margin:0">' +
      V.esc(JSON.stringify(obj, null, 2)) + "</pre></div></details>";
  }

  // One clock for the whole panel: same UTC format as V.fmtTime, so a
  // "previewed/erased/exported HH:MM:SSZ" stamp never disagrees with a
  // server "generated …Z" timestamp shown beside it.
  function nowStamp() { return new Date().toISOString().slice(11, 19) + "Z"; }
  function el(id) { return V.$(id); }

  // Human name first, raw uuid dimmed — the id alone is never the primary
  // label at the irreversible moment. Falls back to the raw id when the
  // tenant directory has no name for it (never fabricate a name).
  function tenantLabel(id) {
    var name = V.tenantName(id);
    if (!name) return "tenant " + V.refSpan(id);
    var short = id.length > 14 ? id.slice(0, 8) + "…" + id.slice(-4) : id;
    return "<b>" + V.esc(name) + "</b> " + V.refSpan("(tenant id " + short + ")");
  }

  /* ------------------------------------------------------------- state */
  var gateKey = null;           // "locked|" / "admin|<tenant>" — rebuild trigger
  var files = [];               // GET /v1/admin/media rows (auto-loaded)
  // Last dry run: when + for exactly which target body + total rows found +
  // the built headline sentence. The confirm step keys off THIS target (a
  // preview of a different target proves nothing), the free-entry 0-match
  // gate keys off `total`, and the confirm dialog repeats `headline` so the
  // counts are visible where the decision happens — never re-typed.
  var lastPreview = { at: 0, key: "", total: 0, headline: "" };
  // Soft format lint (ENTITY-PICKER.md §1) — convention, never a hard block.
  var TAG_LINT = /^[a-z0-9_-]+:[a-z0-9._@-]+$/;
  var entPicker = null;         // entity target picker — rebuilt with the surface

  /* ------------------------------------------------------------ register */
  V.register({
    id: "erasure",
    mount: function () {
      var host = el("erasure-mount");
      if (!host) return;
      host.innerHTML =
        '<div class="toolbar">' +
          '<span id="er-state"></span>' +
          '<span class="asof" id="er-asof"></span>' +
          '<span class="spacer"></span>' +
          '<button id="er-refresh">Refresh</button>' +
        "</div>" +
        '<div class="err" id="er-err"></div>' +
        '<div id="er-body"></div>';
      el("er-refresh").onclick = function () {
        gateKey = null; // force a rebuild + reload of the file list
        sync();
      };
      sync();
    },
    // AUTOLOAD — the router runs this when the panel shows and a tenant is
    // known (and again on tenant change). It rebuilds the surface for the
    // gate × tenant pair and loads the tenant's files.
    load: function () { return sync(); },
    // Re-check the structural gate on every show: setting/clearing the admin
    // token in the session bar flips this panel live, and the destructive
    // controls are NEVER built while the token is absent.
    onShow: function () { sync(); },
  });

  /* --------------------------------------------------------------- gate */
  function sync() {
    var body = el("er-body");
    if (!body) return;
    var hasAdmin = !!V.getAdminToken();
    var tenant = V.tenant() || "";
    var key = hasAdmin ? "admin|" + tenant : "locked|";
    if (key === gateKey) return; // don't wipe live results on tab return
    gateKey = key;
    V.clearErr("er-err");

    if (!hasAdmin) {
      el("er-state").innerHTML = V.stateChip("attn", "admin token required");
      el("er-asof").textContent = "";
      body.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Unlock with an admin token</div>' +
          '<div class="et-body">Erasing data is permanent, so this screen only builds its controls ' +
            "when an admin token is set — a scope handle can never reach it. That is a structural gate, " +
            "not a hidden button. The token lives in this tab only (sessionStorage), never on disk. " +
            "On a dev server that enforces no token, any value unlocks it — that is dev mode, " +
            "disclosed, not security.</div>" +
          '<div class="et-actions"><button class="primary" id="er-focus-token">Set the admin token</button></div>' +
        "</div>";
      el("er-focus-token").onclick = function () {
        var t = document.getElementById("adminToken");
        if (t) { t.focus(); if (t.scrollIntoView) t.scrollIntoView({ block: "nearest" }); }
      };
      return;
    }

    if (!tenant) {
      el("er-state").innerHTML = V.stateChip("off", "no tenant");
      el("er-asof").textContent = "";
      body.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Pick a tenant</div>' +
          '<div class="et-body">Erasure, export, and the file list are all per-tenant. ' +
            "Paste a tenant id in the session bar, or mint a scope handle to adopt one.</div>" +
          '<div class="et-actions"><button class="primary" id="er-mint">Mint a scope handle</button></div>' +
        "</div>";
      el("er-mint").onclick = function () { V.openMint(); };
      return;
    }

    buildTools(body, tenant);
    return refreshFiles(tenant);
  }

  /* ---------------------------------------------------- the admin surface */
  function buildTools(body, tenant) {
    lastPreview = { at: 0, key: "", total: 0, headline: "" };
    body.innerHTML =
      '<div class="note" style="margin-bottom:4px">Acting on ' + tenantLabel(tenant) +
        " — change it in the session bar.</div>" +

      /* Step 1 — who */
      '<div class="card">' +
        '<h2>Step 1 · Who is this about? <span class="sub">exact-string match · subject / entity / media_ids</span></h2>' +
        '<div class="note">Fill in at least one. Matching is <b>exact</b> — a nickname, alias, or different ' +
          "casing will not be found, so double-check the identifier before acting on the counts. " +
          "For any hand-typed identifier, run the preview first: <b>0 everywhere usually means a mistyped id</b>, not clean data.</div>" +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><label for="er-subject">Person <span class="note">(subject id, e.g. user:alice@acme)</span></label> ' +
            '<input type="text" id="er-subject" class="field" placeholder="user:alice@acme" size="28" autocomplete="off">' +
            '<div class="asof" id="er-subject-lint" style="display:block;margin-top:2px"></div></div>' +
          '<div class="tight" style="min-width:280px"><label>Company or record <span class="note">(entity tag)</span></label>' +
            '<div id="er-entity"></div>' +
            '<div class="asof" style="display:block;margin-top:3px"><a href="#" id="er-entity-reveal">target an unlisted id (exact string match) →</a></div>' +
            '<div id="er-entity-free-wrap" style="display:none;margin-top:4px">' +
              '<input type="text" id="er-entity-free" class="field" placeholder="account:acme-inc" size="24" autocomplete="off">' +
              '<div class="asof" id="er-entity-free-lint" style="display:block;margin-top:2px"></div>' +
            "</div></div>" +
        "</div>" +
        '<div class="row" style="margin-top:6px">' +
          '<div class="tight" style="flex:1 1 100%"><label for="er-media">Files to remove ' +
            '<span class="note">(add from the list below — files are only ever removed when you name them here; an unnamed file survives)</span></label> ' +
            '<input type="text" id="er-media" class="field" placeholder="add file ids from the list below" style="width:100%" autocomplete="off"></div>' +
        "</div>" +
        '<div id="er-files-out" style="margin-top:8px"></div>' +
      "</div>" +

      /* Step 2 — preview */
      '<div class="card">' +
        '<h2>Step 2 · Preview what would be removed <span class="sub">POST /v1/admin/erasure/preview · true dry run</span></h2>' +
        '<div class="note">The server walks <b>exactly</b> what an erasure would delete, then rolls the whole ' +
          "thing back — <b>previewing removes nothing</b>, and the counts cannot drift from a real erasure " +
          "because preview and erase share one code path.</div>" +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><button id="er-preview" class="primary">Preview — removes nothing</button></div>' +
          '<span class="asof" id="er-preview-stamp"></span>' +
        "</div>" +
        '<div class="err" id="er-preview-err"></div>' +
        '<div id="er-preview-out"></div>' +
      "</div>" +

      /* Step 3 — erase */
      '<div class="card">' +
        '<h2>Step 3 · Erase permanently <span class="sub">POST /v1/admin/erasure · crypto-shred · no undo</span></h2>' +
        '<div class="note">Hard-deletes everything the preview shows and destroys the keys, in one transaction. ' +
          "There is <b>no undo</b> — unlike <i>Take back one item</i> below, which is reversible. " +
          "If the permissions engine is configured and the target is a person, their access grants are deleted " +
          "<b>first</b>; a failure there stops the whole erasure — nothing is half-removed. " +
          "Backups already taken keep the purged rows until they age out of the retention window — a real, " +
          "disclosed window, not instantaneous perfection.</div>" +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><button id="er-run" class="danger">Erase permanently…</button></div>' +
        "</div>" +
        '<div class="err" id="er-run-err"></div>' +
        '<div id="er-run-out"></div>' +
      "</div>" +

      /* DSAR export */
      '<div class="card">' +
        '<h2>Export instead of erasing <span class="sub">GET /v1/admin/dsar/export · the export self-audits</span></h2>' +
        '<div class="note">One JSON bundle of what is on record about the <b>person</b> — their conversations / events, ' +
          "the search snippets made from them, the profile facts derived from those events, their actions, access-log rows, " +
          "and proposed lessons — for a data-subject access request. The export runs under admin authority, so it includes " +
          "every profile fact attributable to the person regardless of who could normally see it. The export writes its own " +
          "row in the access log, so this read is itself on the record.</div>" +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><button id="er-dsar">Export what is on record about this person</button></div>' +
          '<span class="asof" id="er-dsar-stamp"></span>' +
        "</div>" +
        '<div class="err" id="er-dsar-err"></div>' +
        '<div id="er-dsar-out"></div>' +
      "</div>" +

      /* forget — reversible */
      '<div class="card">' +
        '<h2>Take back one item <span class="sub">POST /v1/forget · reversible invalidation · scope-token, not admin</span></h2>' +
        '<div class="note">' + V.badge("reversible — not a delete", "b-inferred") +
          " Marks a single item expired instead of deleting it — history is kept and it can be reversed. " +
          "It runs under a <b>scope handle</b> (the tenant comes from the signed handle, never this page), " +
          "so paste the handle it should run under — mint one with “+ Mint a scope handle” in the top bar " +
          "if you don’t have one. Copy the item id from the Memories panel (every conversation and snippet " +
          "shows its id).</div>" +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight" style="flex:1 1 100%"><label for="er-fg-handle">Scope handle</label> ' +
            '<input type="text" id="er-fg-handle" class="field" placeholder="vs_…" style="width:100%" autocomplete="off"></div>' +
        "</div>" +
        '<div class="row" style="margin-top:6px">' +
          '<div class="tight"><label for="er-fg-kind">What kind of item</label> ' +
            '<select id="er-fg-kind" class="field">' +
              '<option value="episode">a conversation / event (episode)</option>' +
              '<option value="chunk">a search snippet (chunk)</option>' +
            "</select></div>" +
          '<div class="tight"><label for="er-fg-id">Item id <span class="note">(uuid)</span></label> ' +
            '<input type="text" id="er-fg-id" class="field" placeholder="uuid" size="30" autocomplete="off"></div>' +
          '<div class="tight"><label for="er-fg-reason">Reason <span class="note">(required — recorded on the invalidation)</span></label> ' +
            '<input type="text" id="er-fg-reason" class="field" placeholder="why take this back" size="24" autocomplete="off"></div>' +
          '<div class="tight"><button id="er-fg-run">Take back (reversible)</button></div>' +
        "</div>" +
        '<div class="err" id="er-fg-err"></div>' +
        '<div id="er-fg-out"></div>' +
      "</div>" +

      /* typed-confirm dialog */
      '<div class="dialog-backdrop" id="er-confirm-dialog"><div class="dialog" style="max-width:620px">' +
        '<h3>Erase permanently — this cannot be undone</h3>' +
        '<div class="note" id="er-confirm-summary"></div>' +
        '<div class="note" id="er-confirm-preview" style="margin-top:8px"></div>' +
        '<div class="note" style="margin-top:8px;border-left:3px solid var(--state-fail);padding-left:10px">' +
          "<b>No undo exists.</b> Rows are hard-deleted and keys destroyed in one transaction. " +
          "This is not the reversible <i>take back</i> — there is no reversal." +
        "</div>" +
        '<label class="checkline" id="er-confirm-zero-wrap" style="display:none;margin-top:10px">' +
          '<input type="checkbox" id="er-confirm-zero"> ' +
          'I understand <b>nothing matches this id</b> — the preview found 0 rows everywhere.' +
        "</label>" +
        '<div class="tight" style="margin-top:12px">' +
          '<label for="er-confirm-input" id="er-confirm-label">To confirm, type the id exactly</label>' +
          '<input type="text" id="er-confirm-input" class="field" style="width:100%" autocomplete="off">' +
        "</div>" +
        '<div class="err" id="er-confirm-err"></div>' +
        '<div class="actions">' +
          '<button class="danger" id="er-confirm-go" disabled>Erase permanently</button>' +
          '<button id="er-confirm-cancel">Cancel</button>' +
        "</div>" +
      "</div></div>";

    var confirmDlg = V.dialog("er-confirm-dialog");

    /* --------------------------------- entity target picker + escape hatch */
    // ENTITY-PICKER.md §5.3: target mode — the picker only OFFERS observed
    // tags (allowNew:false; inventing an entity to erase is never correct),
    // liveOnly:false because erasure targets physical rows: a tag carried
    // only by invalidated rows is a legitimate target a live-only directory
    // would hide. Counts render as "N live / M total" in this mode.
    if (entPicker) { entPicker.destroy(); entPicker = null; }
    entPicker = V.entityPicker(el("er-entity"), {
      mode: "target",
      multiple: false,
      allowNew: false,
      liveOnly: false,
      emptyBehavior: "hide",
      placeholder: "account:acme-inc",
      explainer: "pick the exact tag as your data carries it — erasure matches strings exactly. Counts include invalidated rows; erasure targets those too.",
      tenantId: function () { return tenant; },
    });
    // Advanced escape hatch (required by §5.3): lint-only free entry for ids
    // that never appear in chunk/action tags. Free-entry targets MUST be
    // previewed, and a 0-everywhere preview gates the confirm button behind
    // an explicit acknowledgement — never a silent no-op erasure.
    var entFree = false;
    el("er-entity-reveal").onclick = function (ev) {
      ev.preventDefault();
      entFree = !entFree;
      el("er-entity").style.display = entFree ? "none" : "";
      el("er-entity-free-wrap").style.display = entFree ? "" : "none";
      el("er-entity-reveal").textContent = entFree
        ? "← back to the known-entity list"
        : "target an unlisted id (exact string match) →";
      if (entFree) el("er-entity-free").focus();
    };
    el("er-entity-free").oninput = function () {
      var v = el("er-entity-free").value.trim();
      el("er-entity-free-lint").textContent = !v ? ""
        : (TAG_LINT.test(v)
          ? "unchecked id — run the preview first; a 0-everywhere preview needs an explicit acknowledgement to erase."
          : "doesn't look like type:name — entity tags are lowercase like account:acme. Erasure matches this string exactly.");
    };
    // Subject stays free text in v1 (its vocabulary lives partly in L1 facts,
    // which the directory honestly does not cover) — it gains the same lint.
    el("er-subject").oninput = function () {
      var v = el("er-subject").value.trim();
      el("er-subject-lint").textContent = (v && !TAG_LINT.test(v))
        ? "doesn't look like type:name — subject ids are usually lowercase like user:alice@acme. Matching is exact; preview first."
        : "";
    };

    /* ------------------------------------------------ shared input readers */
    function subj() { return el("er-subject").value.trim(); }
    function ent() {
      if (entFree) return el("er-entity-free").value.trim();
      var v = entPicker.value();       // chips only — never in-progress text
      return v.length ? v[0] : "";
    }
    function entIsFree() { return entFree && !!el("er-entity-free").value.trim(); }
    function mediaIds() {
      var raw = el("er-media").value.trim();
      if (!raw) return [];
      return raw.split(/[\s,]+/).filter(function (s) { return s.length; });
    }
    function targetBody() {
      var b = { tenant_id: tenant };
      var s = subj(), e = ent(), m = mediaIds();
      if (s) b.subject = s;
      if (e) b.entity = e;
      if (m.length) b.media_ids = m;
      return { body: b, s: s, e: e, m: m, any: !!(s || e || m.length) };
    }
    function targetSentence(t) {
      var bits = [];
      if (t.s) bits.push("person <b>" + V.esc(t.s) + "</b>");
      if (t.e) bits.push("record <b>" + V.esc(t.e) + "</b>");
      if (t.m.length) bits.push("<b>" + t.m.length + " named file" + (t.m.length === 1 ? "" : "s") + "</b>");
      return bits.join(" · ");
    }

    /* -------------------------------------------------------- PREVIEW */
    el("er-preview").onclick = async function () {
      V.clearErr("er-preview-err");
      var out = el("er-preview-out");
      out.innerHTML = "";
      el("er-preview-stamp").textContent = "";
      var t = targetBody();
      if (!t.any) {
        // Mirror the server's own 422 refusal instead of firing a doomed POST.
        V.err("er-preview-err", new Error(
          "nothing to preview — fill in a person, a record, or at least one file in step 1 (the server refuses an empty target with 422)"));
        return;
      }
      out.innerHTML = '<div class="note">running the dry run… (removes nothing)</div>';
      try {
        var res = await V.api("/v1/admin/erasure/preview", { admin: true, json: t.body }) || {};
        var report = res.would_erase || {};
        var total = REPORT_ROWS.reduce(function (a, r) { return a + Number(report[r.key] || 0); }, 0);
        lastPreview = { at: Date.now(), key: JSON.stringify(t.body), total: total,
          headline: headline(report, "Would remove") };
        // The free-entry id this preview just ran for is no longer unchecked;
        // the oninput handler resets this to the unchecked wording on edit.
        if (entIsFree()) {
          el("er-entity-free-lint").textContent =
            "previewed ✓ — the dry run below is what this id matches. Edit the id and you must preview again.";
        }
        var rebac = res.rebac_tuples_would_delete === true
          ? V.badge("their access grants would also be deleted", "b-provenance")
          : V.badge("no access-grant delete", "b-inferred") +
            ' <span class="note">(permissions engine not configured, or the target is not a person)</span> ' +
            V.refSpan("rebac_tuples_would_delete=false");
        out.innerHTML =
          '<div class="dc-evidence" style="margin-top:10px">' +
            headline(report, "Would remove") + " For " + targetSentence(t) + "." +
          "</div>" +
          '<div style="margin-top:8px">' + rebac + "</div>" +
          reportTable(report, "would remove") +
          (total === 0
            ? '<div class="empty-teach sp-a" style="margin-top:8px">' +
                '<div class="et-title">0 everywhere — nothing matches</div>' +
                '<div class="et-body">Nothing on record matches these identifiers, so an erasure would ' +
                  "remove 0 rows. Check spelling and casing in step 1 — matching is exact, and 0 here " +
                  "usually means a mistyped id, not clean data." +
                  (entIsFree()
                    ? " Erasing this unlisted id anyway will require ticking an explicit “nothing matches” acknowledgement in the confirm step."
                    : "") + "</div>" +
              "</div>"
            : "") +
          gapsBlock(res.coverage_gaps);
        el("er-preview-stamp").textContent = "previewed " + nowStamp() + " · dry run — nothing removed";
      } catch (e2) {
        out.innerHTML = "";
        V.err("er-preview-err", e2);
      }
    };

    /* ---------------------------------------------------------- ERASE */
    // Typed-confirm token: the person id if given, else the record id, else
    // the literal phrase ERASE MEDIA for a files-only purge.
    function confirmTarget() {
      var s = subj();
      if (s) return { token: s, what: "person id" };
      var e = ent();
      if (e) return { token: e, what: "record id" };
      if (mediaIds().length) return { token: "ERASE MEDIA", what: "phrase" };
      return null;
    }

    el("er-run").onclick = function () {
      V.clearErr("er-run-err");
      var t = targetBody();
      var c = confirmTarget();
      if (!t.any || !c) {
        V.err("er-run-err", new Error(
          "nothing to erase — fill in a person, a record, or at least one file in step 1 (the server refuses an empty target with 422)"));
        return;
      }
      var previewMatches = lastPreview.at > 0 && lastPreview.key === JSON.stringify(t.body);
      var freeTarget = entIsFree();
      // Free-entry targets MUST preview first (ENTITY-PICKER.md §5.3): the
      // picked path only offers observed tags, but an unlisted id has no
      // count behind it — the dry run is the only evidence it matches at all.
      if (freeTarget && !previewMatches) {
        V.err("er-run-err", new Error(
          "this target uses an unlisted id — run the preview for exactly this target first. " +
          "Free-entry ids are unchecked strings; the dry run (removes nothing) is the only proof of what they match."));
        return;
      }
      var needsZeroAck = freeTarget && lastPreview.total === 0;
      el("er-confirm-summary").innerHTML =
        "You are about to permanently erase everything for " + targetSentence(t) +
        " on " + tenantLabel(tenant) + ".";
      // Repeat the stored preview headline INSIDE the dialog — the counts
      // table sits behind the dimmed backdrop, so the numbers must be
      // visible where the decision happens. Never re-typed: `headline` is
      // the exact string built from the dry-run report.
      el("er-confirm-preview").innerHTML = previewMatches
        ? V.stateChip("ok", "previewed") + ' <span class="note">last dry run ' +
          V.esc(V.timeAgo(lastPreview.at)) + ". " +
          lastPreview.headline.replace(/\.\s*$/, "") + " — this is exactly what goes.</span>"
        : (lastPreview.at
          ? V.stateChip("attn", "previewed a different target") + ' <span class="note">the last dry run was for ' +
            "a different target — Cancel and preview exactly this one (previewing removes nothing).</span>"
          : V.stateChip("attn", "not previewed") + ' <span class="note">you have not run the preview — ' +
            "Cancel and preview first to see what would go (previewing removes nothing).</span>");
      el("er-confirm-label").innerHTML = c.what === "phrase"
        ? "No person or record named — files only. To confirm, type <b>ERASE MEDIA</b> exactly."
        : "To confirm, type the " + V.esc(c.what) + " exactly: <code>" + V.esc(c.token) + "</code>";
      var input = el("er-confirm-input");
      var go = el("er-confirm-go");
      var zeroCb = el("er-confirm-zero");
      el("er-confirm-zero-wrap").style.display = needsZeroAck ? "" : "none";
      zeroCb.checked = false;
      input.value = "";
      go.disabled = true;
      V.clearErr("er-confirm-err");
      var reflect = function () {
        go.disabled = input.value !== c.token || (needsZeroAck && !zeroCb.checked);
      };
      input.oninput = reflect;
      zeroCb.onchange = reflect;
      go.onclick = async function () {
        if (input.value !== c.token) return; // belt and suspenders
        if (needsZeroAck && !zeroCb.checked) return;
        V.clearErr("er-confirm-err");
        go.disabled = true;
        try {
          var res = await V.api("/v1/admin/erasure", { admin: true, json: t.body });
          confirmDlg.close();
          renderReceipt(res || {}, t);
          refreshFiles(tenant); // named files may be gone now
          entPicker.refresh();  // counts changed — the directory must not lie
        } catch (err) {
          V.err("er-confirm-err", err);
          go.disabled = false;
        }
      };
      confirmDlg.open();
    };
    el("er-confirm-cancel").onclick = function () { confirmDlg.close(); };

    function renderReceipt(res, t) {
      var report = res.erased || {};
      var rebac = res.rebac_tuples_deleted === true
        ? V.badge("access grants deleted first", "b-provenance")
        : V.badge("no access-grant delete", "b-inferred") +
          ' <span class="note">(permissions engine not configured, or the target is not a person — no grants existed)</span>';

      var invalidated = Number(report.knowledge_invalidated || 0);
      var cascade =
        '<div class="note" style="margin-top:10px"><b>Published-lesson cascade.</b> ' +
        (invalidated > 0
          ? "<b>" + invalidated + "</b> published lesson" + (invalidated === 1 ? "" : "s") +
            " lost too much support (below the 3-entity floor) and " +
            (invalidated === 1 ? "was" : "were") + " taken down — the lesson text itself carries no " +
            "personal data, so it is unpublished, not shredded. "
          : "No published lesson fell below the 3-entity support floor. ") +
        "Evidence rows withdrawn: <b>" + Number(report.knowledge_evidence || 0) + "</b>. " +
        V.refSpan("k=3 · knowledge_invalidated / knowledge_evidence") + "</div>";

      // SERVER-signed report: displayed, never assembled here. signed=false =
      // ephemeral dev key — disclosed, not dressed up.
      var pr = res.purge_report || null;
      var prJson = pr ? JSON.stringify(pr, null, 2) : "";
      var sigBlock, dlButtons = "";
      if (!pr) {
        sigBlock =
          '<div class="note" style="margin-top:10px;border-left:3px solid var(--state-attn);padding-left:10px">' +
            "<b>No signed report returned.</b> This server build did not include a " +
            "<code>purge_report</code>. What survives is one <code>erasure</code> audit row holding a " +
            "sha256 of the target plus these counts — cross-check it in Access audit.</div>";
      } else {
        var signed = pr.signed === true;
        var trust = signed
          ? V.badge("signed by the server", "b-provenance") +
            ' <span class="note">HMAC-SHA256 over the report facts under the server’s persistent key.</span>'
          : V.badge("dev key — no durable signature", "b-inferred") +
            ' <span class="note">This server runs an ephemeral key, so no durable signature exists ' +
            "(<code>signature: null</code>). Set <code>VERITY_SIGNING_KEY</code> for a real attestation.</span>";
        sigBlock =
          '<div class="note" style="margin-top:10px;border-left:3px solid var(--' +
            (signed ? "state-ok" : "state-attn") + ');padding-left:10px">' +
            "<b>Purge report.</b> " + trust + "<br>" +
            "Identifiers inside are sha256-hashed — never plaintext — and match the surviving " +
            "<code>erasure</code> audit row, so the report can be cross-checked against the access log." +
            '<div style="margin-top:6px">' + V.refSpan("algorithm " + (pr.algorithm || "—") + " · domain " + (pr.domain || "—")) + "</div>" +
            (pr.signature
              ? '<div style="margin-top:6px"><b>signature:</b><br><code style="word-break:break-all">' +
                V.esc(pr.signature) + "</code></div>"
              : "") +
          "</div>";
        dlButtons =
          '<div class="actions" style="margin-top:8px">' +
            '<button class="primary" id="er-report-dl">' +
              (signed ? "Download signed report" : "Download report (unsigned — dev key)") + "</button>" +
            '<button id="er-report-copy">Copy JSON</button>' +
          "</div>";
      }

      el("er-run-out").innerHTML =
        '<div class="card" style="margin-top:10px">' +
          "<h2>Erased " +
            '<span class="sub">verb=erasure audit row written · ' + nowStamp() + "</span></h2>" +
          '<div class="dc-evidence">' + headline(report, "Removed") + " For " + targetSentence(t) + "." + "</div>" +
          '<div style="margin-top:8px">' + rebac + "</div>" +
          reportTable(report, "removed") +
          cascade + sigBlock + dlButtons +
        "</div>";

      if (pr) {
        el("er-report-dl").onclick = function () {
          download("verity-erasure-report-" + Date.now() + ".json", "application/json", prJson);
        };
        el("er-report-copy").onclick = function () {
          try { navigator.clipboard && navigator.clipboard.writeText(prJson); } catch (e) { /* best-effort */ }
        };
      }
    }

    /* ----------------------------------------------------------- DSAR */
    el("er-dsar").onclick = async function () {
      V.clearErr("er-dsar-err");
      var out = el("er-dsar-out");
      out.innerHTML = "";
      el("er-dsar-stamp").textContent = "";
      var s = subj();
      if (!s) {
        V.err("er-dsar-err", new Error("the export keys on a person — fill in the Person field in step 1"));
        return;
      }
      out.innerHTML = '<div class="note">exporting… (this read logs itself in the access audit)</div>';
      try {
        var b = await V.api(
          "/v1/admin/dsar/export?tenant_id=" + encodeURIComponent(tenant) +
          "&subject=" + encodeURIComponent(s), { admin: true }) || {};
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
            "<h2>What is on record about <b>" + V.esc(b.subject || s) + "</b> " +
              '<span class="sub">dsar_export · generated ' +
              V.esc(b.generated_at ? V.fmtTime(b.generated_at) : "—") + "</span></h2>" +
            '<div class="note">' + V.stateChip("ok", "on the record") +
              ' this export wrote a <code>dsar_export</code> row — see Access audit.</div>' +
            '<div class="tablewrap" style="margin-top:8px"><table><thead><tr>' +
              "<th>section</th><th class=\"num\">rows</th></tr></thead><tbody>" +
              '<tr><td>conversations / events (decrypted) ' + V.refSpan("episodes") + '</td><td class="num">' + counts.episodes + "</td></tr>" +
              '<tr><td>search snippets ' + V.refSpan("chunks") + '</td><td class="num">' + counts.chunks + "</td></tr>" +
              '<tr><td>recorded actions ' + V.refSpan("actions") + '</td><td class="num">' + counts.actions + "</td></tr>" +
              '<tr><td>access-log rows ' + V.refSpan("audit_log") + '</td><td class="num">' + counts.audit_log + "</td></tr>" +
              '<tr><td>proposed lessons ' + V.refSpan("knowledge") + '</td><td class="num">' + counts.knowledge + "</td></tr>" +
            "</tbody></table></div>" +
            '<div class="note" style="margin-top:6px">Profile facts are not included in this build’s export — ' +
              "erase covers them, export does not (yet).</div>" +
            jsonDetails("conversations / events", counts.episodes, b.episodes || []) +
            jsonDetails("search snippets", counts.chunks, b.chunks || []) +
            jsonDetails("recorded actions", counts.actions, b.actions || []) +
            jsonDetails("access-log rows", counts.audit_log, b.audit_log || []) +
            jsonDetails("proposed lessons", counts.knowledge, b.knowledge || []) +
            '<div class="actions" style="margin-top:8px">' +
              '<button class="primary" id="er-dsar-dl">Download bundle (JSON)</button>' +
            "</div>" +
          "</div>";
        el("er-dsar-stamp").textContent = "exported " + nowStamp();
        el("er-dsar-dl").onclick = function () {
          download("verity-dsar-" + (b.subject || s) + "-" + Date.now() + ".json",
            "application/json", bundleJson);
        };
      } catch (e) {
        out.innerHTML = "";
        V.err("er-dsar-err", e);
      }
    };

    /* --------------------------------------------------------- FORGET */
    el("er-fg-run").onclick = async function () {
      V.clearErr("er-fg-err");
      el("er-fg-out").innerHTML = "";
      var handle = el("er-fg-handle").value.trim();
      var kind = el("er-fg-kind").value;
      var id = el("er-fg-id").value.trim();
      var reason = el("er-fg-reason").value.trim();
      if (!handle) { V.err("er-fg-err", new Error("paste the scope handle to run under — the tenant comes from the signed handle")); return; }
      if (!id) { V.err("er-fg-err", new Error("enter the item id to take back")); return; }
      if (!reason) { V.err("er-fg-err", new Error("a reason is required — it is recorded on the invalidation")); return; }
      var btn = el("er-fg-run");
      btn.disabled = true;
      try {
        var res = await V.api("/v1/forget", {
          json: { scope_handle: handle, ref: { kind: kind, id: id }, reason: reason },
        });
        var retired = (res && res.retired) || 0;
        el("er-fg-out").innerHTML =
          '<div class="note" style="margin-top:8px">' +
            V.stateChip("ok", "taken back — reversible") + " <b>" + V.esc(retired) + "</b> row" +
            (Number(retired) === 1 ? "" : "s") + " marked expired for " +
            (kind === "episode" ? "conversation / event" : "search snippet") + " " + V.refSpan(id) +
            ". History is kept — this is not a delete. " + V.refSpan("valid_to stamped · forget audit row written") +
          "</div>";
      } catch (e) {
        V.err("er-fg-err", e);
      } finally {
        btn.disabled = false;
      }
    };
  }

  /* ------------------------------------------- auto-loaded file inventory */
  async function refreshFiles(tenant) {
    var out = el("er-files-out");
    if (!out) return;
    el("er-state").innerHTML = V.stateChip("wait", "loading files");
    try {
      files = await V.api(
        "/v1/admin/media?tenant_id=" + encodeURIComponent(tenant) + "&limit=200",
        { admin: true });
      files = Array.isArray(files) ? files : [];
      el("er-state").innerHTML = V.stateChip("ok", "ready · " + files.length + " file" + (files.length === 1 ? "" : "s") + " on record");
      el("er-asof").textContent = "checked " + nowStamp();
      if (!files.length) {
        out.innerHTML =
          '<div class="note">No files on record for this tenant — nothing to name in an erasure, ' +
          "and that is not an error. Files only ever purge when named here.</div>";
        return;
      }
      var body = files.map(function (m) {
        var idAttr = V.esc(m.id);
        return "<tr>" +
          "<td><b>" + V.esc(m.filename || "no name on record") + "</b><br>" + V.refSpan(m.id) + "</td>" +
          "<td>" + V.esc(m.mime || "—") + "</td>" +
          '<td class="num">' + V.esc(fmtBytes(m.size_bytes)) + "</td>" +
          "<td>" + V.esc(m.created_at ? V.timeAgo(m.created_at) : "—") + "</td>" +
          '<td><button class="er-add-file" data-id="' + idAttr + '">Add to “files to remove”</button></td>' +
          "</tr>";
      }).join("");
      out.innerHTML =
        '<div class="note"><b>' + files.length + " file" + (files.length === 1 ? "" : "s") +
          " on record.</b> Files carry no automatic person attribution — you name the ones to remove.</div>" +
        '<div class="tablewrap" style="margin-top:6px"><table><thead><tr>' +
          "<th>file</th><th>type</th><th class=\"num\">size</th><th>added</th><th></th>" +
        "</tr></thead><tbody>" + body + "</tbody></table></div>";
      var btns = out.querySelectorAll(".er-add-file");
      for (var i = 0; i < btns.length; i++) {
        btns[i].onclick = function () {
          var id = this.getAttribute("data-id");
          var f = el("er-media");
          var have = f.value.trim() ? f.value.trim().split(/[\s,]+/) : [];
          if (have.indexOf(id) < 0) {
            f.value = (f.value.trim() ? f.value.trim() + ", " : "") + id;
          }
        };
      }
    } catch (e) {
      el("er-state").innerHTML = V.stateChip("fail");
      V.err("er-err", e);
    }
  }
})();
