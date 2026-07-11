"use strict";
/* ==========================================================================
   panel_quarantine.js — Screen 6 · Quarantine  [v0.3]
   --------------------------------------------------------------------------
   Backing (read): GET /v1/admin/quarantine?tenant_id=&limit= (admin token).
   The endpoint returns, newest-first, an array of rows:
     { id, webhook_id, payload (full JSON — NOT truncated), reason, at }
   No server-side reason/time filtering is offered, so grouping, the reason
   filter, and the time-range filter all run CLIENT-SIDE over the fetched
   window — exactly like the audit panel. The window size is stated so the
   reviewer knows precisely what set the filters, groups, and export cover.

   Backing (write — the two ONLY exits from quarantine, both admin-gated and
   audited; migration 0023):
     POST /v1/admin/quarantine/{id}/reingest — re-admit a payload THROUGH a
       corrected, admin-supplied ACL mapping. `visibility` + `confidentiality`
       are REQUIRED and explicit (no default, no "inherit whatever the webhook
       had"); the result is stamped acl_provenance = admin-assigned and the
       ORIGINAL payload is preserved verbatim as the episode body so the
       admin's mapping is auditable. 409 if already resolved (atomic
       OPEN→reingested claim); 422 if the payload carries nothing ingestible —
       re-ingest never fabricates content. Audited: verb quarantine_reingest.
     POST /v1/admin/quarantine/{id}/dismiss — acknowledge WITHOUT indexing
       anything. Audited: verb quarantine_dismiss. 409 if already resolved.
   The quarantine row survives either exit (invalidate-don't-delete).

   THESIS (SPEC §5 Screen 6, §3): these events are invisible to recall BY
   DESIGN. An unmappable ACL → quarantine, never permissive indexing. This
   panel therefore offers NO permissive-fallback affordance and NO
   "index it anyway" shortcut — that shortcut must not exist, and the server
   gives it no request shape to exist through: there is no way to omit or
   inherit the ACL on re-ingest.

   HONEST LIMIT: GET /v1/admin/quarantine does not yet return the 0023
   resolution/resolved_at/resolution_note columns, so a previously resolved
   row can still appear in a freshly loaded window. The server's atomic claim
   is the authority — an action on such a row gets a 409 naming the prior
   disposition, and this panel marks the row the moment it learns it.
   Dispositions learned in THIS SESSION are badged locally.

   READ-PATH PURITY: reads are pure (no LLM calls, no live-ReBAC calls);
   filter, group, and export are local transforms over the fetched window.
   The two writes are worker/admin-plane calls — recall/get never run them.
   ========================================================================== */
(function () {

  // ---- reason bucketing (client-side grouping) --------------------------
  // The server writes free-form reason strings ("invalid JSON: …",
  // "unrecognized shape: …", "unmapped ACL: …", "delivered to a draft manifest
  // …", etc.). We bucket by the stable PREFIX before the first colon so counts
  // are meaningful; the full reason is always shown verbatim on the row. This
  // is display-only classification — never a fabricated new reason.
  function reasonGroup(reason) {
    var r = String(reason || "").trim();
    if (!r) return "(no reason recorded)";
    var colon = r.indexOf(":");
    var head = (colon >= 0 ? r.slice(0, colon) : r).trim().toLowerCase();
    if (!head) return "(no reason recorded)";
    // Normalize a few known families so near-duplicates group together.
    if (head.indexOf("unmapped acl") >= 0 || head.indexOf("unmappable acl") >= 0) return "unmapped ACL";
    if (head.indexOf("unrecognized shape") >= 0 || head.indexOf("unknown shape") >= 0) return "unrecognized shape";
    if (head.indexOf("invalid json") >= 0) return "invalid JSON";
    return head;
  }

  // ---- full-payload rendering (NOT truncated at 240 chars) --------------
  // The whole point of this panel over the CLI `quarantine tail` is that the
  // reviewer sees the ENTIRE payload. We pretty-print it and let it scroll
  // horizontally inside a .tablewrap (overflow-x:auto) so a wide payload never
  // makes the page body scroll.
  function payloadText(payload) {
    if (payload === undefined || payload === null) return "(null payload)";
    if (typeof payload === "string") return payload; // raw preview bytes kept as-is
    try { return JSON.stringify(payload, null, 2); }
    catch (e) { return String(payload); }
  }
  function payloadBlock(payload) {
    return '<div class="tablewrap"><pre style="margin:0;white-space:pre;font-family:var(--mono);' +
      'font-size:12px;line-height:1.5">' + Verity.esc(payloadText(payload)) + "</pre></div>";
  }

  // ---- time-range helpers (shared shape with audit panel) ---------------
  function tsOrNull(v) {
    if (!v) return null;
    var t = new Date(v).getTime();
    return isNaN(t) ? null : t;
  }

  // ---- export (offline analysis) ----------------------------------------
  function download(name, mime, text) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }
  function toJsonExport(rows, meta) {
    // Self-contained bundle for offline analysis: the FULL payloads are kept
    // intact (never truncated) so the export is the real evidence, plus a small
    // envelope naming the source, tenant, window, and the fail-closed thesis.
    return JSON.stringify({
      source: "verity.quarantine_preview",
      schema: "verity.quarantine.v1",
      tenant_id: meta.tenant,
      exported_at: new Date().toISOString(),
      build_hash: Verity.buildHash(),
      window_rows: rows.length,
      note: "Quarantined webhook payloads from GET /v1/admin/quarantine. " +
            "These are invisible to recall by design; nothing ambiguous was indexed " +
            "permissively. The only exits are POST …/{id}/reingest through a corrected " +
            "admin-supplied ACL mapping (stamped admin-assigned) and POST …/{id}/dismiss " +
            "(indexes nothing) — both audited; the row survives either way " +
            "(SPEC §5 Screen 6, §7b). The listing does not yet carry resolution status, " +
            "so resolved rows may be present in this export.",
      events: rows.map(function (r) {
        return {
          id: r.id,
          webhook_id: r.webhook_id,
          reason: r.reason,
          reason_group: reasonGroup(r.reason),
          at: r.at,
          payload: r.payload, // FULL payload, not truncated
        };
      }),
    }, null, 2);
  }

  // ---- corrected-mapping input parsing -----------------------------------
  // Principal tokens are i32s on the wire. We accept comma/space-separated
  // integers, de-duplicated; anything non-integer is a hard error (never
  // silently dropped — a typo must not shrink or widen visibility unnoticed).
  function parseTokens(raw) {
    var parts = String(raw || "").split(/[\s,]+/).filter(function (s) { return s.length; });
    var out = [];
    var seen = {};
    for (var i = 0; i < parts.length; i++) {
      if (!/^-?\d+$/.test(parts[i])) {
        throw new Error('visibility token "' + parts[i] + '" is not an integer principal token');
      }
      var n = parseInt(parts[i], 10);
      if (!seen[n]) { seen[n] = true; out.push(n); }
    }
    return out;
  }
  function parseTags(raw) {
    return String(raw || "").split(/[\s,]+/).filter(function (s) { return s.length; });
  }
  // "… HTTP 409: quarantine item already resolved (dismissed)" → "dismissed".
  function priorDisposition(message) {
    var m = /already resolved(?:\s*\(([^)]+)\))?/.exec(String(message || ""));
    if (!m) return null;
    return m[1] || "resolved";
  }

  Verity.register({
    id: "quarantine",
    mount: function (section) {
      var el = Verity.$("quarantine-mount");
      if (!el) return;

      var LAST = [];       // last fetched raw window (newest first)
      var BY_ID = {};      // id → row, for the per-row action dialogs
      var RESOLVED = {};   // id → disposition learned THIS SESSION (from our own
                           // 200s or a 409 naming the prior disposition). The
                           // listing doesn't carry resolution yet, so this is
                           // honest local knowledge, labeled as such.
      var ACTIVE = null;   // row a dialog is currently open for

      /* -- THESIS BANNER: the fail-closed non-negotiable is the panel's
            identity (SPEC §5 Screen 6). Rendered as a card so it reads as a
            standing statement, not a transient note. */
      var banner = document.createElement("div");
      banner.className = "card";
      banner.innerHTML =
        '<h2>These are invisible to recall <span class="sub">by design</span></h2>' +
        '<div class="note" style="font-size:13px;margin-top:6px">' +
          '<em>Nothing ambiguous is indexed permissively.</em> Every row below is a webhook payload ' +
          'whose ACL could not be mapped, or whose shape was unrecognized, so it was <b>refused at ' +
          'ingest and quarantined</b> instead of guessed at. A quarantined payload never reaches an ' +
          'index and never appears in any recall or brief. Under-visible is the correct, fail-closed ' +
          'behaviour here — an empty or shrinking queue is good news, not a missing feature ' +
          '(SPEC §3, §7b).</div>';
      el.appendChild(banner);

      /* -- controls: load window + reason filter + time range + export ----- */
      var controls = document.createElement("div");
      controls.className = "card";
      controls.innerHTML =
        '<h2>Quarantine queue <span class="sub">GET /v1/admin/quarantine &middot; newest first &middot; admin token</span></h2>' +

        // load row
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><input type="text" id="q-tenant" placeholder="tenant_id (uuid)" size="30"></div>' +
          '<div class="tight"><input type="number" id="q-limit" value="100" min="1" max="500" style="width:90px" title="rows fetched (window) — server clamps to 1..500"></div>' +
          '<div class="tight"><button id="q-load" class="primary">Load</button></div>' +
          '<div class="tight"><span class="refreshed" id="q-stamp"></span></div>' +
        '</div>' +

        // filter row (client-side over the fetched window)
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><select class="field" id="q-group"><option value="">reason group: any</option></select></div>' +
          '<div class="tight"><input type="text" id="q-reason" placeholder="search reason text" size="22"></div>' +
          '<div class="tight"><input type="text" id="q-webhook" placeholder="webhook_id" size="14"></div>' +
        '</div>' +
        '<div class="row" style="margin-top:6px">' +
          '<div class="tight"><label class="checkline">from&nbsp;<input type="text" id="q-from" placeholder="YYYY-MM-DD HH:MM" size="17"></label></div>' +
          '<div class="tight"><label class="checkline">to&nbsp;<input type="text" id="q-to" placeholder="YYYY-MM-DD HH:MM" size="17"></label></div>' +
          '<div class="tight"><button id="q-clear">Clear filters</button></div>' +
          '<div class="tight"><button id="q-json">Export JSON (full payloads)</button></div>' +
        '</div>' +

        '<div class="note"><em>Filters &amp; grouping run over the fetched window.</em> The endpoint takes only ' +
          '<b>tenant_id</b> + <b>limit</b>; grouping, the reason filter, and the time range are applied ' +
          'client-side to exactly the rows named in the window stamp above — that is the set the ' +
          'reason counts and the export cover.</div>' +

        '<div class="err" id="q-err"></div>' +
        '<div id="q-groups"></div>' +
        '<div id="q-out"></div>';
      el.appendChild(controls);

      /* -- THE TWO EXITS: the write surface exists now (migration 0023). The
            v0.2 disabled seam is replaced by the real actions — and the shape
            of the real actions keeps the promise the seam made: there is no
            "index it anyway" affordance, and the server gives it no request
            shape to exist through. */
      var exits = document.createElement("div");
      exits.className = "card";
      exits.innerHTML =
        '<h2>Two exits &mdash; both audited <span class="sub">POST /v1/admin/quarantine/{id}/reingest &middot; &hellip;/{id}/dismiss &middot; admin token</span></h2>' +
        '<div class="note" style="font-size:13px">' +
          'A quarantined payload leaves triage in exactly two ways, via the per-row buttons below: ' +
          '<b>re-map ACL &amp; re-ingest</b> re-admits it <em>through a corrected, admin-supplied mapping</em> ' +
          '(visibility + confidentiality are <b>required and explicit</b> — no default, no "inherit whatever ' +
          'the webhook had" — and the result is stamped ' + Verity.provenanceBadge("admin-assigned") +
          ' with the original payload preserved verbatim as the episode body, so the mapping is auditable); ' +
          '<b>dismiss / acknowledge</b> records the disposition and indexes <em>nothing</em>. ' +
          '<em>There is still no "index it anyway" affordance, and there never will be:</em> no request shape ' +
          'exists that indexes a payload under its original unmappable ACL or any permissive fallback, and ' +
          'unparseable facts are skipped fail-closed, never guessed into L1. The quarantine row survives ' +
          'either exit (invalidate-don&#39;t-delete); both are audit-logged ' +
          '(<span class="sub">quarantine_reingest / quarantine_dismiss</span>) (SPEC §3, §5 Screen 6, §7b).</div>' +
        '<div class="note"><em>Resolution status is session-local for now.</em> The listing endpoint does not ' +
          'yet return the resolution columns, so an already-resolved row can still appear in a freshly loaded ' +
          'window. The server&#39;s atomic claim is the authority: acting on such a row returns ' +
          '<b>409 naming the prior disposition</b>, and this panel badges the row the moment it learns it.</div>';
      el.appendChild(exits);

      /* -- RE-INGEST dialog: the corrected-mapping form. Confidentiality has
            a blank placeholder (a choice is forced, never defaulted) and an
            EMPTY visibility set needs an explicit fail-closed acknowledgement
            — it is accepted by the server but writes memory nobody can read. */
      var qrEl = document.createElement("div");
      qrEl.className = "dialog-backdrop";
      qrEl.id = "q-reingest-dialog";
      qrEl.innerHTML =
        '<div class="dialog" style="max-width:640px">' +
          '<h3>Re-map ACL &amp; re-ingest</h3>' +
          '<div class="note" id="qr-ctx"></div>' +
          '<div class="note" style="margin-top:10px;border-left:3px solid var(--red,#f85149);padding-left:10px">' +
            '<b>This is not "index it anyway".</b> You are supplying the corrected mapping yourself; the ' +
            'chunk (and any parseable native facts) will carry <em>exactly</em> the visibility, ' +
            'confidentiality, and tags below, stamped ' + Verity.provenanceBadge("admin-assigned") +
            ' — never the original unmappable ACL, never a default. The original payload is preserved ' +
            'verbatim as the episode body and the action is audit-logged.' +
          '</div>' +
          '<div style="margin-top:12px"><label>visibility — principal tokens (required, explicit)</label>' +
            '<input type="text" id="qr-vis" placeholder="e.g. 7, 9"></div>' +
          '<label class="checkline" style="margin-top:6px"><input type="checkbox" id="qr-vis-empty">' +
            'I mean an EMPTY visibility set &mdash; fail-closed: this writes memory nobody can read</label>' +
          '<div style="margin-top:10px"><label>confidentiality (required — choose explicitly)</label>' +
            '<select class="field" id="qr-conf">' +
              '<option value="">— choose —</option>' +
              '<option value="Public">public</option>' +
              '<option value="Internal">internal</option>' +
              '<option value="Confidential">confidential</option>' +
              '<option value="Restricted">restricted</option>' +
            '</select></div>' +
          '<div style="margin-top:10px"><label>entity tags (optional, comma-separated)</label>' +
            '<input type="text" id="qr-tags" placeholder="account:acme, deal:renewal-2026"></div>' +
          '<div style="margin-top:10px"><label>corrected text extraction (optional)</label>' +
            '<textarea id="qr-content" placeholder="Only for payloads whose text lives under a field the native parser doesn\'t know. Leave blank to use the payload\'s own content/observation/raw text. Re-ingest never fabricates content — a payload with nothing ingestible is refused (422)."></textarea></div>' +
          '<div style="margin-top:10px"><label>audit note (optional)</label>' +
            '<input type="text" id="qr-note" placeholder="why this mapping is correct"></div>' +
          '<div class="err" id="qr-dlg-err"></div>' +
          '<div id="qr-dlg-result"></div>' +
          '<div class="actions">' +
            '<button class="primary" id="qr-go">Re-ingest through corrected mapping</button>' +
            '<button id="qr-cancel">Cancel</button>' +
          '</div>' +
        '</div>';
      el.appendChild(qrEl);
      var qrDlg = Verity.dialog("q-reingest-dialog");

      /* -- DISMISS dialog: acknowledge without indexing anything. ---------- */
      var qdEl = document.createElement("div");
      qdEl.className = "dialog-backdrop";
      qdEl.id = "q-dismiss-dialog";
      qdEl.innerHTML =
        '<div class="dialog" style="max-width:560px">' +
          '<h3>Dismiss / acknowledge</h3>' +
          '<div class="note" id="qd-ctx"></div>' +
          '<div class="note" style="margin-top:10px">' +
            'Dismissing records the disposition and <b>indexes nothing</b> — the payload stays invisible ' +
            'to recall, and the quarantine row survives for audit (invalidate-don&#39;t-delete). ' +
            'The action is audit-logged (<span class="sub">quarantine_dismiss</span>).' +
          '</div>' +
          '<div style="margin-top:10px"><label>audit note (optional)</label>' +
            '<input type="text" id="qd-note" placeholder="e.g. duplicate delivery; fixed at the source"></div>' +
          '<div class="err" id="qd-dlg-err"></div>' +
          '<div class="actions">' +
            '<button class="primary" id="qd-go">Dismiss (indexes nothing)</button>' +
            '<button id="qd-cancel">Cancel</button>' +
          '</div>' +
        '</div>';
      el.appendChild(qdEl);
      var qdDlg = Verity.dialog("q-dismiss-dialog");

      // prefill tenant from shared state / decoded handle
      var tenantInput = Verity.$("q-tenant");
      if (Verity.tenant()) tenantInput.value = Verity.tenant();
      Verity.onTenant(function (t) {
        if (t && !tenantInput.value) tenantInput.value = t;
      });

      // ---- filtering (client-side over the fetched window) ---------------
      function currentFilters() {
        return {
          group: Verity.$("q-group").value,
          reason: Verity.$("q-reason").value.trim().toLowerCase(),
          webhook: Verity.$("q-webhook").value.trim().toLowerCase(),
          from: tsOrNull(Verity.$("q-from").value.trim()),
          to: tsOrNull(Verity.$("q-to").value.trim()),
        };
      }
      function passesFilters(r, f) {
        if (f.group && reasonGroup(r.reason) !== f.group) return false;
        if (f.reason && String(r.reason || "").toLowerCase().indexOf(f.reason) < 0) return false;
        if (f.webhook && String(r.webhook_id || "").toLowerCase().indexOf(f.webhook) < 0) return false;
        var t = new Date(r.at).getTime();
        if (f.from && t < f.from) return false;
        if (f.to && t > f.to) return false;
        return true;
      }
      function filtered() {
        var f = currentFilters();
        return LAST.filter(function (r) { return passesFilters(r, f); });
      }

      // ---- reason-group counts (over the FULL window, so the dropdown and
      //      the count strip describe the whole loaded set, not the filtered
      //      subset — the filter selects from these). ----------------------
      function groupCounts(rows) {
        var m = {};
        rows.forEach(function (r) {
          var g = reasonGroup(r.reason);
          m[g] = (m[g] || 0) + 1;
        });
        return m;
      }
      function refreshGroupOptions(counts) {
        var sel = Verity.$("q-group");
        var keep = sel.value;
        var keys = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
        sel.innerHTML = '<option value="">reason group: any</option>' +
          keys.map(function (g) {
            return '<option value="' + Verity.esc(g) + '">' + Verity.esc(g) + " (" + counts[g] + ")</option>";
          }).join("");
        // Preserve the current selection if it still exists.
        if (keep && counts[keep] != null) sel.value = keep;
      }
      function renderGroups(counts, total) {
        var keys = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
        if (!keys.length) { Verity.$("q-groups").innerHTML = ""; return; }
        var chips = keys.map(function (g) {
          // Every quarantine reason is a fail-closed refusal → red badge.
          return Verity.badge(g + " · " + counts[g], "b-quarantined");
        }).join(" ");
        Verity.$("q-groups").innerHTML =
          '<div class="note" style="margin-top:10px"><b>' + total + '</b> quarantined payload' +
          (total === 1 ? "" : "s") + " in the window &middot; grouped by reason:</div>" +
          '<div style="margin-top:6px">' + chips + "</div>";
      }

      // ---- resolution bookkeeping (session-local; see honesty note) -------
      function markResolved(id, disposition) {
        RESOLVED[id] = disposition;
        renderTable(filtered());
      }
      function resolutionCell(id) {
        var d = RESOLVED[id];
        if (!d) return null;
        var cls = d === "reingested" ? "b-admin-assigned" : "b-kind";
        return Verity.badge(d, cls) +
          '<div class="note" style="margin-top:4px">resolved &mdash; learned this session; ' +
          'row survives for audit</div>';
      }

      // ---- rendering -----------------------------------------------------
      function renderTable(rows) {
        if (!rows.length) {
          // Fail-closed / honest empty state WITH the reason (SPEC §3).
          Verity.$("q-out").innerHTML =
            '<div class="empty">No quarantined payloads match. An empty queue is <b>good news</b> — it ' +
            'means every delivered webhook mapped cleanly and nothing was refused. This is not an ' +
            'error, and nothing ambiguous was indexed to make it empty.</div>';
          return;
        }
        var head = '<div class="tablewrap"><table><thead><tr>' +
          '<th>at</th><th>webhook_id</th><th>reason</th><th>payload <span class="sub">(full — not truncated)</span></th>' +
          '<th>actions <span class="sub">(the only two exits)</span></th>' +
          '</tr></thead><tbody>';
        var body = rows.map(function (r) {
          // Every quarantine row is a fail-closed refusal → flag styling + a
          // quarantined badge carrying its reason group.
          var g = reasonGroup(r.reason);
          var reasonCell =
            Verity.badge("quarantined", "b-quarantined") + " " +
            Verity.badge(g, "b-quarantined", true) +
            '<div class="note" style="margin-top:4px">' + Verity.esc(r.reason || "—") + "</div>";
          var actions = resolutionCell(r.id) ||
            ('<button data-act="reingest" data-id="' + Verity.esc(r.id) + '" ' +
               'title="Re-admit THROUGH a corrected admin-supplied ACL mapping (visibility + confidentiality required, stamped admin-assigned). Never the original unmappable ACL, never a default.">' +
               'Re-map ACL &amp; re-ingest&hellip;</button>' +
             '<div style="height:4px"></div>' +
             '<button data-act="dismiss" data-id="' + Verity.esc(r.id) + '" ' +
               'title="Acknowledge without indexing anything. The row survives for audit (invalidate-don\'t-delete).">' +
               'Dismiss / acknowledge&hellip;</button>');
          return '<tr class="flag">' +
            '<td>' + Verity.esc(Verity.fmtTime(r.at)) + '</td>' +
            '<td>' + Verity.esc(r.webhook_id || "—") + '</td>' +
            '<td>' + reasonCell + '</td>' +
            '<td>' + payloadBlock(r.payload) + '</td>' +
            '<td style="white-space:nowrap">' + actions + '</td>' +
          '</tr>';
        }).join("");
        Verity.$("q-out").innerHTML = head + body + '</tbody></table></div>';
      }

      function rerender() {
        // Group dropdown/count strip describe the FULL window; the table shows
        // the filtered subset (the reason-group filter selects from the groups).
        var counts = groupCounts(LAST);
        refreshGroupOptions(counts);
        renderGroups(counts, LAST.length);
        renderTable(filtered());
      }

      // ---- load ----------------------------------------------------------
      async function load() {
        Verity.clearErr("q-err");
        var tenant = tenantInput.value.trim();
        if (!tenant) { Verity.err("q-err", new Error("enter a tenant_id to load its quarantine queue")); return; }
        Verity.setTenant(tenant);
        var limit = Math.max(1, Math.min(500, parseInt(Verity.$("q-limit").value, 10) || 100));
        try {
          var rows = await Verity.api(
            "/v1/admin/quarantine?tenant_id=" + encodeURIComponent(tenant) + "&limit=" + limit,
            { admin: true });
          LAST = Array.isArray(rows) ? rows : [];
          BY_ID = {};
          LAST.forEach(function (r) { BY_ID[r.id] = r; });
          Verity.$("q-stamp").textContent =
            "loaded " + Verity.fmtTime(Date.now()) + " · window " + LAST.length + " row(s)";
          rerender();
        } catch (e) {
          Verity.err("q-err", e);
        }
      }

      // ---- action dialogs --------------------------------------------------
      function requireTenantForAction() {
        var t = tenantInput.value.trim();
        if (!t) throw new Error("no tenant_id — the action must name the tenant that owns the row");
        return t;
      }
      function ctxLine(r) {
        return Verity.badge("quarantined", "b-quarantined") + " " +
          Verity.badge(reasonGroup(r.reason), "b-quarantined", true) +
          ' <b>' + Verity.esc(r.id) + '</b> &middot; ' + Verity.esc(Verity.fmtTime(r.at)) +
          '<div class="note" style="margin-top:4px">' + Verity.esc(r.reason || "—") + '</div>';
      }

      function openReingest(r) {
        ACTIVE = r;
        Verity.$("qr-ctx").innerHTML = ctxLine(r);
        Verity.$("qr-vis").value = "";
        Verity.$("qr-vis-empty").checked = false;
        Verity.$("qr-conf").value = "";
        Verity.$("qr-tags").value = "";
        Verity.$("qr-content").value = "";
        Verity.$("qr-note").value = "";
        Verity.$("qr-dlg-result").innerHTML = "";
        Verity.clearErr("qr-dlg-err");
        Verity.$("qr-go").disabled = false;
        Verity.$("qr-cancel").textContent = "Cancel";
        qrDlg.open();
      }

      async function doReingest() {
        if (!ACTIVE) return;
        Verity.clearErr("qr-dlg-err");
        Verity.$("qr-dlg-result").innerHTML = "";
        var tenant, tokens;
        try {
          tenant = requireTenantForAction();
          tokens = parseTokens(Verity.$("qr-vis").value);
          if (!tokens.length && !Verity.$("qr-vis-empty").checked) {
            throw new Error("visibility is empty — supply principal tokens, or tick the explicit " +
              "empty-set acknowledgement (fail-closed: it writes memory nobody can read)");
          }
          if (tokens.length && Verity.$("qr-vis-empty").checked) {
            throw new Error("the empty-set acknowledgement is ticked but tokens were supplied — " +
              "untick it or clear the tokens so the intent is unambiguous");
          }
          if (!Verity.$("qr-conf").value) {
            throw new Error("choose a confidentiality — it is required and explicit; there is no default");
          }
        } catch (e) { Verity.err("qr-dlg-err", e); return; }

        var body = {
          tenant_id: tenant,
          visibility: tokens,
          confidentiality: Verity.$("qr-conf").value,
        };
        var tags = parseTags(Verity.$("qr-tags").value);
        if (tags.length) body.entity_tags = tags;
        var content = Verity.$("qr-content").value.trim();
        if (content) body.content = content;
        var note = Verity.$("qr-note").value.trim();
        if (note) body.note = note;

        var go = Verity.$("qr-go");
        go.disabled = true;
        try {
          var res = await Verity.api(
            "/v1/admin/quarantine/" + encodeURIComponent(ACTIVE.id) + "/reingest",
            { admin: true, json: body });
          markResolved(ACTIVE.id, "reingested");
          // Result summary INCLUDING the server's honesty flags — what the
          // re-ingest could not carry over is disclosed, not glossed.
          var flags = [];
          if (res && res.facts_unparseable_skipped) {
            flags.push("<em>facts skipped:</em> the payload's `facts` did not parse as the native " +
              "shape and were NOT written to L1 (fail-closed, never guessed)");
          }
          if (res && res.raw_text_truncated_at_capture) {
            flags.push("<em>raw text was truncated at capture</em> (4096 chars) — the indexed chunk " +
              "came from that preserved prefix; supply a corrected extraction if the full text matters");
          }
          Verity.$("qr-dlg-result").innerHTML =
            '<div class="note" style="margin-top:10px;border-left:3px solid var(--green,#3fb950);padding-left:10px">' +
              '<b>Re-ingested</b> through the corrected mapping ' + Verity.provenanceBadge("admin-assigned") +
              '<div class="kv">' +
                '<dt>episode</dt><dd>' + Verity.esc(res.episode_id || "—") + '</dd>' +
                '<dt>chunks indexed</dt><dd>' + Verity.esc(String(res.chunks_indexed != null ? res.chunks_indexed : "—")) + '</dd>' +
                '<dt>facts written</dt><dd>' + Verity.esc(String(res.facts_written != null ? res.facts_written : "—")) + '</dd>' +
              '</div>' +
              (flags.length ? '<div class="note" style="margin-top:6px">' + flags.join("<br>") + '</div>' : "") +
              '<div class="note" style="margin-top:6px">Audited as <span class="sub">quarantine_reingest</span>; ' +
              'the quarantine row survives for audit. Original payload preserved verbatim as the episode body.</div>' +
            '</div>';
        } catch (e) {
          var prior = priorDisposition(e.message);
          if (prior) markResolved(ACTIVE.id, prior);
          // Keep the dialog open so the error is read in context (a 422
          // "nothing ingestible" points at the corrected-extraction field).
          Verity.err("qr-dlg-err", e);
          go.disabled = false;
          return;
        }
        go.disabled = true; // resolved — no double-submit; Cancel now reads as Close
        Verity.$("qr-cancel").textContent = "Close";
      }

      function openDismiss(r) {
        ACTIVE = r;
        Verity.$("qd-ctx").innerHTML = ctxLine(r);
        Verity.$("qd-note").value = "";
        Verity.clearErr("qd-dlg-err");
        Verity.$("qd-go").disabled = false;
        qdDlg.open();
      }

      async function doDismiss() {
        if (!ACTIVE) return;
        Verity.clearErr("qd-dlg-err");
        var tenant;
        try { tenant = requireTenantForAction(); }
        catch (e) { Verity.err("qd-dlg-err", e); return; }
        var body = { tenant_id: tenant };
        var note = Verity.$("qd-note").value.trim();
        if (note) body.note = note;
        var go = Verity.$("qd-go");
        go.disabled = true;
        try {
          await Verity.api(
            "/v1/admin/quarantine/" + encodeURIComponent(ACTIVE.id) + "/dismiss",
            { admin: true, json: body });
          markResolved(ACTIVE.id, "dismissed");
          qdDlg.close();
        } catch (e) {
          var prior = priorDisposition(e.message);
          if (prior) markResolved(ACTIVE.id, prior);
          Verity.err("qd-dlg-err", e);
          go.disabled = false;
        }
      }

      // ---- wiring --------------------------------------------------------
      Verity.$("q-load").onclick = load;
      ["q-reason", "q-webhook", "q-from", "q-to"].forEach(function (id) {
        Verity.$(id).addEventListener("input", function () { renderTable(filtered()); });
      });
      Verity.$("q-group").addEventListener("change", function () { renderTable(filtered()); });
      Verity.$("q-clear").onclick = function () {
        ["q-reason", "q-webhook", "q-from", "q-to"].forEach(function (id) { Verity.$(id).value = ""; });
        Verity.$("q-group").value = "";
        renderTable(filtered());
      };
      Verity.$("q-json").onclick = function () {
        var rows = filtered();
        if (!rows.length) { Verity.err("q-err", new Error("nothing in the filtered window to export")); return; }
        Verity.clearErr("q-err");
        download("verity-quarantine-" + Date.now() + ".json", "application/json",
          toJsonExport(rows, { tenant: tenantInput.value.trim() }));
      };
      // Per-row action buttons (event delegation — rows re-render freely).
      Verity.$("q-out").addEventListener("click", function (ev) {
        var btn = ev.target.closest ? ev.target.closest("button[data-act]") : null;
        if (!btn) return;
        var row = BY_ID[btn.getAttribute("data-id")];
        if (!row) return;
        if (btn.getAttribute("data-act") === "reingest") openReingest(row);
        else openDismiss(row);
      });
      Verity.$("qr-go").onclick = doReingest;
      Verity.$("qr-cancel").onclick = function () { qrDlg.close(); Verity.$("qr-cancel").textContent = "Cancel"; };
      Verity.$("qd-go").onclick = doDismiss;
      Verity.$("qd-cancel").onclick = function () { qdDlg.close(); };
    },
  });
})();
