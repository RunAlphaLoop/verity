"use strict";
/* ==========================================================================
   panel_knowledge.js — Screen 3 · Knowledge Review (TA.3 · BeyondMVP)
   --------------------------------------------------------------------------
   Reads (unchanged):
     • GET /v1/knowledge                 — the review queue (admin-token)
     • GET /v1/admin/knowledge/{id}      — the item detail drawer (admin-token)
   The read-only ribbon is LIFTED here: the two flagship human-gated WRITES are
   wired live (SPEC §5 Screen 3 'Actions (v0.2)'):
     • POST /v1/knowledge/{id}/publish   — admin-token; body
       { tenant_id, visibility: [<i32 principal token>…], k_min }. visibility is
       REQUIRED and has NO DEFAULT — an unset/empty set REFUSES to submit
       (omission is a refusal, SPEC §3 / §5e.8). k_min is clamped ≥3 client-side
       for honesty; the server re-clamps as the authority.
     • POST /v1/admin/knowledge/{id}/reject — admin-token; body
       { tenant_id, reason } behind an explicit confirm.
   Both refresh the queue on success so the status badge updates. Still zero LLM
   calls and zero live-ReBAC calls from this panel.

   PROVENANCE FIREWALL (SPEC §2, §7g): this is the ADMIN surface, so exact
   distinct_entities / writer_count are shown. We render the split faithfully
   and disclose that the agent-facing preview would instead be a BUCKET
   (several | many | extensive). Evidence lineage in the drawer is present but
   LABELED audit-scope-only — never a recall/brief affordance.

   RETRACTION (honest gap, SPEC §5 Screen 3): there is NO un-publish endpoint.
   A published item renders a DISABLED Erasure/forget seam — designed, never
   faked as a working button.
   ========================================================================== */
(function () {
  var STATUSES = ["candidate", "eligible", "published", "quarantined", "rejected", "invalidated"];

  // Agent-facing bucket vocabulary (SPEC §2/§7g). The server's SupportTier
  // enum serializes as emerging(3-4) | established(5-9) | extensive(10+); the
  // agent-visible preview collapses those to the coarser several|many|extensive
  // ladder. This mapping is disclosure-only — the exact count never leaves the
  // admin surface.
  function agentBucket(item) {
    var d = item.distinct_entities;
    if (d == null || d < 3) return null; // below the k-support floor → nothing to disclose
    if (d >= 10) return "extensive";
    if (d >= 5) return "many";
    return "several";
  }

  // k-support gate math (SPEC §5 / knowledge-merge-tuning): publishable needs
  // ≥3 distinct entities AND (≥2 writers OR tier-1 evidence). Category floor is
  // a separate signal (has at least one category). We only DISPLAY the math —
  // the server is the authority; this is a read-side explanation, not a check.
  function kSupport(item) {
    var d = item.distinct_entities;
    var w = item.writer_count;
    var entOk = d != null && d >= 3;
    var writerOk = (w != null && w >= 2) || !!item.has_tier1_evidence;
    var catOk = (item.categories || []).length >= 1;
    return {
      entOk: entOk, writerOk: writerOk, catOk: catOk,
      pass: entOk && writerOk && catOk,
      d: d, w: w,
    };
  }

  function gateChip(ok, label) {
    // Solid green pass / dashed-amber unmet — deterministic gate, so solid on
    // pass. Unmet uses the eligible/amber lifecycle hue to read as "not yet".
    return ok
      ? Verity.badge("✓ " + label, "b-st-published")
      : Verity.badge("✗ " + label, "b-st-eligible");
  }

  function catBadges(cats) {
    return (cats || []).map(function (c) { return Verity.kindBadge(c); }).join(" ");
  }

  // merge_reason vs quarantine gate reason — render the split faithfully.
  function reasonCell(item) {
    if (item.quarantine_reason) {
      return Verity.statusBadge("quarantined") + " " +
        '<span class="note"><em>gate:</em> ' + Verity.esc(item.quarantine_reason) + "</span>";
    }
    if (item.merge_reason) {
      return '<span class="note">' + Verity.esc(item.merge_reason) + "</span>";
    }
    return '<span class="note">—</span>';
  }

  Verity.register({
    id: "knowledge",
    mount: function (section) {
      var el = Verity.$("knowledge-mount");
      if (!el) return;

      /* -- read-only ribbon LIFTED on this panel (SPEC §5 Screen 3): the two
            human-gated writes below are wired live, so no ribbon is cloned. */

      /* -- controls card: status filter + load ------------------------------ */
      var controls = document.createElement("div");
      controls.className = "card";
      controls.innerHTML =
        '<h2>Review queue <span class="sub">GET /v1/knowledge · admin-token</span></h2>' +
        '<div class="row">' +
          '<div class="tight">' +
            '<label for="know-status">status</label> ' +
            '<select id="know-status" class="field">' +
              '<option value="">all</option>' +
              STATUSES.map(function (s) {
                return '<option value="' + s + '">' + s + "</option>";
              }).join("") +
            "</select>" +
          "</div>" +
          '<div class="tight"><label for="know-tenant">tenant_id</label> ' +
            '<input type="text" id="know-tenant" placeholder="(uses active tenant)"></div>' +
          '<div class="tight"><button id="know-load">Load queue</button></div>' +
        "</div>" +
        '<div class="note"><em>Provenance firewall.</em> This is the admin surface: exact ' +
          '<b>distinct_entities</b> / <b>writer_count</b> are shown here. An agent-facing preview ' +
          'would instead see a BUCKET (<b>several</b> · <b>many</b> · <b>extensive</b>) and ' +
          'never the exact counts (SPEC §2/§7g). Evidence lineage in the detail drawer is ' +
          '<b>audit-scope-only</b> and is never rendered in a recall/brief context.</div>' +
        '<div class="err" id="know-err"></div>' +
        '<div id="know-refreshed"></div>' +
        '<div id="know-out"></div>';
      el.appendChild(controls);

      /* -- detail drawer (dialog-backdrop) ---------------------------------- */
      var drawer = document.createElement("div");
      drawer.className = "dialog-backdrop";
      drawer.id = "know-drawer";
      drawer.innerHTML =
        '<div class="dialog" style="max-width:760px">' +
          '<h3 id="know-drawer-title">Knowledge item</h3>' +
          '<div id="know-drawer-body"></div>' +
          '<div class="actions">' +
            // Human-gated WRITES — ribbon lifted (SPEC §5 Screen 3). Each opens
            // a confirm; Publish's confirm forces an explicit visibility set.
            '<button class="primary" id="know-publish" ' +
              'data-knowledge-action="publish" data-knowledge-id="" ' +
              'title="POST /v1/knowledge/{id}/publish (admin) — requires an explicit visibility set + k_min≥3. No default visibility.">' +
              'Publish…</button>' +
            '<button id="know-reject" ' +
              'data-knowledge-action="reject" data-knowledge-id="" ' +
              'title="POST /v1/admin/knowledge/{id}/reject (admin) — remembered so it will not resurrect.">' +
              'Reject…</button>' +
            '<button id="know-drawer-close">Close</button>' +
          "</div>" +
        "</div>";
      el.appendChild(drawer);

      var dlg = Verity.dialog("know-drawer");
      Verity.$("know-drawer-close").onclick = function () { dlg.close(); };

      /* -- publish confirm dialog (no default visibility — omission refuses) - */
      var pubDlgEl = document.createElement("div");
      pubDlgEl.className = "dialog-backdrop";
      pubDlgEl.id = "know-publish-dialog";
      pubDlgEl.innerHTML =
        '<div class="dialog" style="max-width:600px">' +
          '<h3>Publish knowledge item</h3>' +
          '<div class="note" id="know-pub-stmt"></div>' +
          '<div class="card" style="margin-top:10px">' +
            '<div class="note" style="margin-bottom:8px"><em>This grants BROAD visibility.</em> ' +
              'Publishing exposes this generalization to <b>every</b> principal token you list below, ' +
              'across scoped interactions. There is <b>no un-publish</b> — retraction is Erasure/forget only.</div>' +
            '<div class="tight">' +
              '<label for="know-pub-vis">visibility <span class="note">(required — principal tokens, comma/space separated i32)</span></label>' +
              '<input type="text" id="know-pub-vis" class="field" placeholder="e.g. 1001, 1002, 2003" autocomplete="off">' +
            "</div>" +
            '<div class="note" style="margin-top:6px"><em>No default visibility.</em> Leave this blank and the ' +
              'dialog will <b>refuse</b> to publish (SPEC §3 / §5e.8) — omission is a refusal, not a permissive default.</div>' +
            '<div class="tight" style="margin-top:10px">' +
              '<label for="know-pub-kmin">k_min <span class="note">(clamped ≥3 — server is the authority)</span></label>' +
              '<input type="number" id="know-pub-kmin" class="field" min="3" step="1" value="3">' +
            "</div>" +
          "</div>" +
          '<div class="err" id="know-pub-err"></div>' +
          '<div class="actions">' +
            '<button class="primary" id="know-pub-confirm">Grant broad visibility &amp; publish</button>' +
            '<button id="know-pub-cancel">Cancel</button>' +
          "</div>" +
        "</div>";
      el.appendChild(pubDlgEl);
      var pubDlg = Verity.dialog("know-publish-dialog");

      /* -- reject confirm dialog ------------------------------------------- */
      var rejDlgEl = document.createElement("div");
      rejDlgEl.className = "dialog-backdrop";
      rejDlgEl.id = "know-reject-dialog";
      rejDlgEl.innerHTML =
        '<div class="dialog" style="max-width:560px">' +
          '<h3>Reject knowledge item</h3>' +
          '<div class="note" id="know-rej-stmt"></div>' +
          '<div class="card" style="margin-top:10px">' +
            '<div class="note" style="margin-bottom:8px">Rejecting is <b>remembered</b>: the same canonical ' +
              'statement will not resurrect as a fresh candidate. Only candidate/eligible items can be ' +
              'rejected — a published item is refused (retraction is Erasure/forget’s job).</div>' +
            '<div class="tight">' +
              '<label for="know-rej-reason">reason <span class="note">(optional — defaults to "rejected by reviewer")</span></label>' +
              '<input type="text" id="know-rej-reason" class="field" placeholder="why this is refused" autocomplete="off">' +
            "</div>" +
          "</div>" +
          '<div class="err" id="know-rej-err"></div>' +
          '<div class="actions">' +
            '<button class="primary" id="know-rej-confirm">Reject item</button>' +
            '<button id="know-rej-cancel">Cancel</button>' +
          "</div>" +
        "</div>";
      el.appendChild(rejDlgEl);
      var rejDlg = Verity.dialog("know-reject-dialog");

      // The item currently open in the drawer (id + statement + tenant) — the
      // confirm dialogs act on this.
      var current = { id: "", statement: "", tenant: "" };

      /* -- parse a visibility input into an i32 principal-token set. Returns
            { tokens, error }. An empty/blank input is a REFUSAL, not a default:
            callers must treat a null tokens as "do not submit". */
      function parseVisibility(raw) {
        var parts = String(raw || "").split(/[\s,]+/).filter(function (s) { return s.length; });
        if (!parts.length) {
          return { tokens: null, error:
            "Visibility is required — no default visibility. Enter at least one principal token, " +
            "or Cancel. (SPEC §3 / §5e.8: omission refuses.)" };
        }
        var tokens = [];
        for (var i = 0; i < parts.length; i++) {
          if (!/^-?\d+$/.test(parts[i])) {
            return { tokens: null, error: 'not an integer principal token: "' + parts[i] + '"' };
          }
          tokens.push(parseInt(parts[i], 10));
        }
        return { tokens: tokens, error: null };
      }

      /* -- publish flow ---------------------------------------------------- */
      Verity.$("know-publish").onclick = function () {
        if (!current.id) return;
        Verity.clearErr("know-pub-err");
        Verity.$("know-pub-vis").value = "";
        Verity.$("know-pub-kmin").value = "3";
        Verity.$("know-pub-stmt").innerHTML =
          "<b>" + Verity.esc(current.statement || current.id) + "</b>";
        pubDlg.open();
      };
      Verity.$("know-pub-cancel").onclick = function () { pubDlg.close(); };
      Verity.$("know-pub-confirm").onclick = async function () {
        Verity.clearErr("know-pub-err");
        var vis = parseVisibility(Verity.$("know-pub-vis").value);
        if (vis.tokens === null) {
          // Omission (or a bad token) REFUSES — we never fall back to a default.
          Verity.err("know-pub-err", new Error(vis.error));
          return;
        }
        // Client-side honesty clamp; the server re-clamps as the authority.
        var kmin = parseInt(Verity.$("know-pub-kmin").value, 10);
        if (isNaN(kmin) || kmin < 3) kmin = 3;
        var btn = Verity.$("know-pub-confirm");
        btn.disabled = true;
        try {
          await Verity.api(
            "/v1/knowledge/" + encodeURIComponent(current.id) + "/publish",
            { admin: true, json: { tenant_id: current.tenant, visibility: vis.tokens, k_min: kmin } });
          pubDlg.close();
          dlg.close();
          await loadQueue();
        } catch (e) {
          Verity.err("know-pub-err", e);
        } finally {
          btn.disabled = false;
        }
      };

      /* -- reject flow ----------------------------------------------------- */
      Verity.$("know-reject").onclick = function () {
        if (!current.id) return;
        Verity.clearErr("know-rej-err");
        Verity.$("know-rej-reason").value = "";
        Verity.$("know-rej-stmt").innerHTML =
          "<b>" + Verity.esc(current.statement || current.id) + "</b>";
        rejDlg.open();
      };
      Verity.$("know-rej-cancel").onclick = function () { rejDlg.close(); };
      Verity.$("know-rej-confirm").onclick = async function () {
        Verity.clearErr("know-rej-err");
        var btn = Verity.$("know-rej-confirm");
        btn.disabled = true;
        try {
          await Verity.api(
            "/v1/admin/knowledge/" + encodeURIComponent(current.id) + "/reject",
            { admin: true, json: {
              tenant_id: current.tenant,
              reason: Verity.$("know-rej-reason").value.trim(),
            } });
          rejDlg.close();
          dlg.close();
          await loadQueue();
        } catch (e) {
          Verity.err("know-rej-err", e);
        } finally {
          btn.disabled = false;
        }
      };

      /* -- load handler ----------------------------------------------------- */
      function activeTenant() {
        var typed = Verity.$("know-tenant").value.trim();
        return typed || Verity.tenant() || "";
      }

      async function loadQueue() {
        Verity.clearErr("know-err");
        Verity.$("know-out").innerHTML = "";
        Verity.$("know-refreshed").innerHTML = "";
        var tenant = activeTenant();
        if (!tenant) {
          Verity.err("know-err", new Error(
            "no tenant selected — decode a scope handle on Scope Inspector or type a tenant_id above"));
          return;
        }
        var status = Verity.$("know-status").value;
        var url = "/v1/knowledge?tenant_id=" + encodeURIComponent(tenant);
        if (status) url += "&status=" + encodeURIComponent(status);
        try {
          var res = await Verity.api(url, { admin: true });
          var items = (res && res.items) || [];
          renderQueue(items, tenant);
          Verity.$("know-refreshed").innerHTML =
            '<span class="refreshed">' + items.length + " item" + (items.length === 1 ? "" : "s") +
            " · loaded " + Verity.esc(Verity.fmtTime(Date.now())) + "</span>";
        } catch (e) {
          Verity.err("know-err", e);
        }
      }

      function renderQueue(items, tenant) {
        if (!items.length) {
          // Fail-closed / honest empty state WITH the reason (SPEC §3).
          Verity.$("know-out").innerHTML =
            '<div class="empty">No knowledge items for tenant <b>' + Verity.esc(tenant) +
            "</b>" + (Verity.$("know-status").value ? " at status <b>" +
              Verity.esc(Verity.$("know-status").value) + "</b>" : "") +
            ". Nothing is auto-published; an empty queue means nothing has cleared the gate here — that is not an error.</div>";
          return;
        }
        var rows = items.map(function (it) {
          var bucket = agentBucket(it);
          // The BUCKET an agent would see (SPEC §2/§7g). Rendered dashed
          // (inferred=true) to read as a coarse disclosure, not an exact fact.
          var supportCell =
            '<span class="note">agent preview: </span>' +
            (bucket ? Verity.badge(bucket, "b-trust", true)
                    : Verity.badge("below k-floor", "b-st-candidate"));
          var exact = Verity.esc(it.distinct_entities == null ? "—" : it.distinct_entities);
          var writers = Verity.esc(it.writer_count == null ? "—" : it.writer_count) +
            (it.has_tier1_evidence ? " " + Verity.trustBadge("authoritative") : "");
          var evCount = (it.evidence || []).length;
          var idAttr = Verity.esc(it.id);
          return '<tr class="' + (it.quarantine_reason ? "flag" : "") + '">' +
            "<td>" + Verity.statusBadge(it.status) + "</td>" +
            "<td>" + Verity.esc(it.statement || "") +
              ((it.categories || []).length
                ? '<div style="margin-top:4px">' + catBadges(it.categories) + "</div>" : "") +
            "</td>" +
            "<td>" + supportCell + "</td>" +
            '<td class="num">' + exact + "</td>" +
            '<td class="num">' + writers + "</td>" +
            "<td>" + reasonCell(it) + "</td>" +
            '<td class="num">' + evCount + "</td>" +
            '<td><button class="know-detail" data-id="' + idAttr + '">Detail</button></td>' +
            "</tr>";
        }).join("");

        Verity.$("know-out").innerHTML =
          '<div class="tablewrap"><table>' +
          "<thead><tr>" +
            "<th>status</th><th>statement</th>" +
            '<th>support <span class="sub">(agent bucket)</span></th>' +
            '<th class="num">distinct entities <span class="sub">(admin-exact)</span></th>' +
            '<th class="num">writers <span class="sub">(admin-exact)</span></th>' +
            "<th>merge / gate reason</th>" +
            '<th class="num">evidence</th><th></th>' +
          "</tr></thead><tbody>" + rows + "</tbody></table></div>";

        // Wire per-row detail buttons.
        var btns = Verity.$("know-out").querySelectorAll(".know-detail");
        for (var i = 0; i < btns.length; i++) {
          btns[i].onclick = function () { openDetail(this.getAttribute("data-id"), tenant); };
        }
      }

      /* -- detail drawer load ---------------------------------------------- */
      async function openDetail(id, tenant) {
        var body = Verity.$("know-drawer-body");
        Verity.$("know-drawer-title").textContent = "Knowledge item " + id;
        body.innerHTML = '<div class="note">loading GET /v1/admin/knowledge/' + Verity.esc(id) + " …</div>";
        // Wire the write-action target. Statement is filled once the detail loads.
        current = { id: id, statement: "", tenant: tenant };
        Verity.$("know-publish").setAttribute("data-knowledge-id", id);
        Verity.$("know-reject").setAttribute("data-knowledge-id", id);
        // Until the item loads, keep the write actions disabled so we never act
        // on an unknown status.
        setActionsForStatus(null);
        dlg.open();
        try {
          var item = await Verity.api(
            "/v1/admin/knowledge/" + encodeURIComponent(id) +
              "?tenant_id=" + encodeURIComponent(tenant),
            { admin: true });
          current.statement = item.statement || "";
          setActionsForStatus(item.status);
          renderDetail(item);
        } catch (e) {
          setActionsForStatus(null);
          body.innerHTML = '<div class="err on">' + Verity.esc(e.message || String(e)) + "</div>";
        }
      }

      // Publish/Reject are only valid on a candidate/eligible item — the server
      // refuses otherwise (422). Reflect that honestly by disabling the buttons
      // and explaining why, rather than letting the operator fire a doomed POST.
      function setActionsForStatus(status) {
        var s = status == null ? null : String(status).toLowerCase();
        var actionable = s === "candidate" || s === "eligible";
        var pub = Verity.$("know-publish");
        var rej = Verity.$("know-reject");
        pub.disabled = !actionable;
        rej.disabled = !actionable;
        if (s === "published") {
          pub.title = "Already published — there is no un-publish endpoint (retraction is Erasure/forget).";
          rej.title = "A published item cannot be rejected — retraction is Erasure/forget’s job (SPEC §5 Screen 3).";
        } else if (!actionable && s != null) {
          pub.title = "Only candidate/eligible items are publishable (status: " + s + ").";
          rej.title = "Only candidate/eligible items are rejectable (status: " + s + ").";
        } else if (actionable) {
          pub.title = "POST /v1/knowledge/{id}/publish (admin) — requires an explicit visibility set + k_min≥3. No default visibility.";
          rej.title = "POST /v1/admin/knowledge/{id}/reject (admin) — remembered so it will not resurrect.";
        }
      }

      function renderDetail(item) {
        var body = Verity.$("know-drawer-body");
        var k = kSupport(item);
        var bucket = agentBucket(item);
        var gate = item.deid_gate || {};
        var deidPass = gate.passed !== false && !item.quarantine_reason;

        var claims =
          '<dl class="kv">' +
            "<dt>status</dt><dd>" + Verity.statusBadge(item.status) + "</dd>" +
            "<dt>statement</dt><dd>" + Verity.esc(item.statement || "—") + "</dd>" +
            "<dt>categories</dt><dd>" +
              ((item.categories || []).length ? catBadges(item.categories)
                : '<span class="note">none — category floor unmet</span>') + "</dd>" +
            "<dt>first seen</dt><dd>" + Verity.esc(item.first_seen ? Verity.fmtTime(item.first_seen) : "—") + "</dd>" +
            "<dt>last reinforced</dt><dd>" + Verity.esc(item.last_reinforced ? Verity.fmtTime(item.last_reinforced) : "—") + "</dd>" +
            "<dt>published at</dt><dd>" + (item.published_at
              ? Verity.esc(Verity.fmtTime(item.published_at)) + " " + Verity.statusBadge("published")
              : '<span class="note">not published</span>') + "</dd>" +
          "</dl>";

        // Support: admin-exact vs the bucket an agent would see.
        var support =
          '<div class="card"><h2>Support <span class="sub">admin-exact vs agent bucket</span></h2>' +
          '<dl class="kv">' +
            "<dt>distinct entities <span class=\"note\">(admin-exact)</span></dt><dd>" +
              Verity.esc(item.distinct_entities == null ? "—" : item.distinct_entities) + "</dd>" +
            "<dt>writer count <span class=\"note\">(admin-exact)</span></dt><dd>" +
              Verity.esc(item.writer_count == null ? "—" : item.writer_count) + "</dd>" +
            "<dt>episode count</dt><dd>" + Verity.esc(item.episode_count == null ? "—" : item.episode_count) + "</dd>" +
            "<dt>tier-1 evidence</dt><dd>" +
              (item.has_tier1_evidence ? Verity.trustBadge("authoritative")
                : '<span class="note">none</span>') + "</dd>" +
            "<dt>support tier</dt><dd>" +
              (item.support_tier ? Verity.badge(item.support_tier, "b-tier") : '<span class="note">below k-floor</span>') + "</dd>" +
            "<dt>agent-facing preview</dt><dd>" +
              (bucket ? Verity.badge(bucket, "b-trust", true) : Verity.badge("below k-floor", "b-st-candidate")) +
              ' <span class="note">buckets only — exact counts stay on this admin surface (SPEC §2/§7g)</span></dd>' +
          "</dl></div>";

        // k-support gate math — DISPLAY of the publish floor, server is authority.
        var math =
          '<div class="card"><h2>k-support gate <span class="sub">publish floor — display only, server enforces</span></h2>' +
          '<div class="row" style="gap:8px;flex-wrap:wrap">' +
            gateChip(k.entOk, "≥3 distinct entities (" + (k.d == null ? "—" : k.d) + ")") +
            gateChip(k.writerOk, "≥2 writers or tier-1 (" + (k.w == null ? "—" : k.w) + (item.has_tier1_evidence ? ", tier-1" : "") + ")") +
            gateChip(k.catOk, "category floor ≥1") +
          "</div>" +
          '<div class="note" style="margin-top:8px">Overall: ' +
            (k.pass ? Verity.badge("meets publish floor", "b-st-eligible")
                    : Verity.badge("below publish floor", "b-st-candidate")) +
            ". Publishing is the final human gate (v0.2) and requires an explicit visibility + k_min≥3 — " +
            "there is no default visibility, and omission refuses (SPEC §5e.8).</div>" +
          "</div>";

        // De-identification gate result (deterministic, auditable).
        var deid =
          '<div class="card"><h2>De-identification gate</h2>' +
          '<div>' + (deidPass
            ? Verity.badge("✓ passed", "b-st-published")
            : Verity.badge("✗ quarantined", "b-st-quarantined")) + "</div>" +
          (item.quarantine_reason
            ? '<div class="note" style="margin-top:6px"><em>reason:</em> ' + Verity.esc(item.quarantine_reason) + "</div>"
            : '<div class="note" style="margin-top:6px">no gate failure recorded</div>') +
          (item.merge_reason
            ? '<div class="note" style="margin-top:6px"><em>merge reason:</em> ' + Verity.esc(item.merge_reason) + "</div>"
            : "") +
          "</div>";

        // Lineage-to-episodes — LABELED audit-scope-only. Never a recall/brief
        // affordance: no "open in inspector" jump, no citation-to-brief link.
        var ev = item.evidence || [];
        var lineageRows = ev.map(function (e) {
          var tier = e.trust_tier;
          var tierBadge = (tier === 1 || tier === "1")
            ? Verity.trustBadge("authoritative")
            : Verity.badge("trust tier " + Verity.esc(tier == null ? "—" : tier), "b-trust");
          return "<tr>" +
            "<td>" + Verity.esc(e.episode_id || "—") + "</td>" +
            "<td>" + (e.entity ? Verity.badge(e.entity, "b-entity") : '<span class="note">—</span>') + "</td>" +
            "<td>" + (e.writer_azp ? Verity.esc(e.writer_azp) : '<span class="note">—</span>') + "</td>" +
            "<td>" + tierBadge + "</td>" +
            "</tr>";
        }).join("");
        var lineage =
          '<div class="card"><h2>Evidence lineage ' +
            '<span class="sub">' + ev.length + " episode" + (ev.length === 1 ? "" : "s") + "</span></h2>" +
          '<div class="note"><em>Audit-scope-only.</em> This episode/entity lineage is shown for review here ' +
            'and is <b>never</b> rendered in any recall or brief context (provenance firewall, SPEC §2/§7g). ' +
            "Writer/entity attribution is read from the L0 episodes, never caller-supplied.</div>" +
          (ev.length
            ? '<div class="tablewrap" style="margin-top:8px"><table><thead><tr>' +
                "<th>episode_id (L0)</th><th>entity</th><th>writer azp</th><th>trust tier</th>" +
              "</tr></thead><tbody>" + lineageRows + "</tbody></table></div>"
            : '<div class="empty">no evidence rows</div>') +
          "</div>";

        // Retraction seam (honest gap, SPEC §5 Screen 3): there is NO un-publish
        // endpoint. For a published item we render the retraction path as a
        // DISABLED seam — designed, never faked as a working button.
        var retraction = item.status && String(item.status).toLowerCase() === "published"
          ? '<div class="card" style="margin-top:8px">' +
            '<h2>Retraction <span class="sub">no un-publish endpoint</span></h2>' +
            '<div class="note"><em>Publishing is one-way here.</em> There is no un-publish endpoint. ' +
              "Retracting a published generalization is <b>Erasure &amp; DSAR / forget</b>'s job — " +
              "the lineage-driven cascade auto-invalidates it when its sources are forgotten (SPEC §5 Screen 3). " +
              "The seam is designed; we do not fake a working button for it.</div>" +
            '<div class="actions">' +
              '<button disabled title="No un-publish endpoint. Retraction is Erasure/forget (Screen 4, v0.2) — this seam is designed, not faked.">' +
                'Retract via Erasure / forget (seam — v0.2)</button>' +
            "</div></div>"
          : "";

        body.innerHTML = claims + support + math + deid + lineage + retraction;
      }

      Verity.$("know-load").onclick = loadQueue;

      // Auto-fill the tenant field from the shared tenant when it changes.
      Verity.onTenant(function (t) {
        var f = Verity.$("know-tenant");
        if (f && !f.value.trim()) f.placeholder = t ? "(active: " + t + ")" : "(uses active tenant)";
      });
      (function () {
        var t = Verity.tenant();
        var f = Verity.$("know-tenant");
        if (f && t) f.placeholder = "(active: " + t + ")";
      })();
    },
  });
})();
