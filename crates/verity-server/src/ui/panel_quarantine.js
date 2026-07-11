"use strict";
/* ==========================================================================
   panel_quarantine.js — Screen 6 · Quarantine  [v0.2]
   --------------------------------------------------------------------------
   Backing: GET /v1/admin/quarantine?tenant_id=&limit= (admin token). The
   endpoint returns, newest-first, an array of rows:
     { id, webhook_id, payload (full JSON — NOT truncated), reason, at }
   No server-side reason/time filtering is offered, so grouping, the reason
   filter, and the time-range filter all run CLIENT-SIDE over the fetched
   window — exactly like the audit panel. The window size is stated so the
   reviewer knows precisely what set the filters, groups, and export cover.

   THESIS (SPEC §5 Screen 6, §3): these events are invisible to recall BY
   DESIGN. An unmappable ACL → quarantine, never permissive indexing. This
   panel therefore offers NO permissive-fallback affordance and NO
   "index it anyway" shortcut — that shortcut must not exist.

   HONEST SEAM (SPEC §5 Screen 6 'Actions'): there is NO re-ingest / dismiss /
   acknowledge endpoint yet. That needs a new server WRITE surface the spec must
   add first, and re-ingest can only ever route through a CORRECTED mapping. We
   render it as a DISABLED seam — designed, never faked as a working button.

   READ-PATH PURITY: pure reads only. No LLM calls, no live-ReBAC calls. Filter,
   group, and export are all local transforms over the fetched window.
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
            "permissively. There is no re-ingest endpoint — re-ingest can only route " +
            "through a corrected mapping (SPEC §5 Screen 6, §7b).",
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

  Verity.register({
    id: "quarantine",
    mount: function (section) {
      var el = Verity.$("quarantine-mount");
      if (!el) return;

      var LAST = [];   // last fetched raw window (newest first)

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

      /* -- HONEST SEAM: no re-ingest / dismiss endpoint exists yet. We design
            the affordance and render it DISABLED — never a phantom button, and
            crucially never an "index it anyway" shortcut (SPEC §5 Screen 6). */
      var seam = document.createElement("div");
      seam.className = "card";
      seam.innerHTML =
        '<h2>Re-ingest &amp; dismiss <span class="sub">no write surface yet — honest seam, not a fake button</span></h2>' +
        '<div class="note" style="font-size:13px">' +
          'Correcting a mapping and re-ingesting a quarantined payload, or dismissing/acknowledging one, ' +
          'needs a server WRITE surface that <b>does not exist yet</b> — the spec must add it first ' +
          '(SPEC §5 Screen 6, Later). We render the action as a <b>disabled seam we design but never fake</b>. ' +
          '<em>There is no "index it anyway" affordance, and there never will be:</em> re-ingest can only ' +
          'ever route through a <b>corrected mapping</b>, so a quarantined payload is never indexed on a ' +
          'permissive fallback (SPEC §3, §7b).</div>' +
        '<div class="actions">' +
          '<button disabled title="No re-ingest endpoint. Re-ingest can only route through a corrected ACL mapping — that write surface does not exist yet (SPEC §5 Screen 6, Later). Seam is designed, not faked.">' +
            'Re-map ACL &amp; re-ingest (seam — needs new write surface)</button>' +
          '<button disabled title="No dismiss/acknowledge endpoint yet — quarantined rows are invalidate-don\'t-delete and never silently cleared (SPEC §5 Screen 6, Later). Seam is designed, not faked.">' +
            'Dismiss / acknowledge (seam — needs new write surface)</button>' +
        '</div>';
      el.appendChild(seam);

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
          '</tr></thead><tbody>';
        var body = rows.map(function (r) {
          // Every quarantine row is a fail-closed refusal → flag styling + a
          // quarantined badge carrying its reason group.
          var g = reasonGroup(r.reason);
          var reasonCell =
            Verity.badge("quarantined", "b-quarantined") + " " +
            Verity.badge(g, "b-quarantined", true) +
            '<div class="note" style="margin-top:4px">' + Verity.esc(r.reason || "—") + "</div>";
          return '<tr class="flag">' +
            '<td>' + Verity.esc(Verity.fmtTime(r.at)) + '</td>' +
            '<td>' + Verity.esc(r.webhook_id || "—") + '</td>' +
            '<td>' + reasonCell + '</td>' +
            '<td>' + payloadBlock(r.payload) + '</td>' +
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
          Verity.$("q-stamp").textContent =
            "loaded " + Verity.fmtTime(Date.now()) + " · window " + LAST.length + " row(s)";
          rerender();
        } catch (e) {
          Verity.err("q-err", e);
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
    },
  });
})();
