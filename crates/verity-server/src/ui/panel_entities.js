"use strict";
/* ==========================================================================
   panel_entities.js — Screens 8-9 · Entities & Resolution (Later → live)
   --------------------------------------------------------------------------
   Reads / writes (all admin-token gated except the scope-gated merged view):
     • GET  /v1/admin/entities?tenant_id&limit                — entities browser
     • GET  /v1/admin/entity-resolution/review-queue?…        — Tier-2/3 queue
     • POST /v1/admin/entity-resolution/decide                — the HUMAN GATE
         { tenant_id, left_ref, right_ref, decision:"confirm"|"reject", note }
         confirm → human_confirmed edge (tier2,+1); reject → human_rejected
         anti-link (tier2,-1, PERMANENT must-not-link). Server re-runs the full
         fold, so the decision takes effect immediately, then resolves each
         ref's current canonical. We refresh queue + browser on success.
     • GET  /v1/entities/{canonical}?scope_handle             — merged field view
         SCOPE-GATED (not admin): per-field winning source + provenance +
         superseded alternatives. Requires a pasted scope handle; disclosed.
     • POST /v1/admin/entity-precedence                       — PRECEDENCE EDITOR
         { tenant_id, canonical, field, source_order[] } (SPEC §7f, Screen 9
         remainder): the per-field source-of-truth ranking, highest first.
         canonical/field default to "*" server-side; we save the CURRENT
         canonical with either a specific field or the "*" entity default.
         The per-field source lists are derived from the loaded merged view
         (there is no GET for precedence rows), so the editor requires the
         merged view first. "No rule" is INFERRED, honestly: with no rule the
         server tie-breaks by most-recent valid_from, so a winner that is NOT
         the newest cross-source fact proves a rule overrode recency; a winner
         that IS the newest is indistinguishable from no rule and is labelled
         exactly that way — never claimed as either.

   HONESTY (SPEC §3):
     • confidence rendered faithfully — deterministic / human_confirmed = SOLID
       badge (a guaranteed link); approximated = DASHED (the b-inferred encoding,
       a probabilistic link). Never blurred.
     • every merge card shows its justifying evidence (method/score/key/ns/
       rationale); the field detail shows winning source + provenance + the
       superseded alternatives that LOST — conflict made visible, not hidden.
     • empty review queue → honest empty state ("Tier-2 must run to populate
       it"), never a fabricated candidate row.
     • zero LLM / zero live-ReBAC calls from this panel; decide's fold runs
       server-side. The panel is admin-gated (audit-class, reads across scopes).
   ========================================================================== */
(function () {
  // A ref is "source:entity_id". Field summaries are empty for key:* / chunk:* /
  // malformed refs — the server sends {name:null,domain:null} in that case.
  function refSource(ref) {
    var s = String(ref || "");
    var i = s.indexOf(":");
    return i < 0 ? s : s.slice(0, i);
  }

  // Wait-age (SLA read-out): seconds → a compact "3d 4h" / "12m" / "45s" string.
  // The queue is ordered by a priority score with an UNBOUNDED aging term, so a
  // large wait age is the operator's cue that the anti-starvation term is (or
  // soon will be) floating this candidate up regardless of its intrinsic value.
  function fmtAge(secs) {
    secs = Math.max(0, Math.floor(Number(secs) || 0));
    var d = Math.floor(secs / 86400);
    var h = Math.floor((secs % 86400) / 3600);
    var m = Math.floor((secs % 3600) / 60);
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    if (m > 0) return m + "m";
    return secs + "s";
  }

  // Confidence → badge. The frozen encoding: deterministic / human_confirmed are
  // GUARANTEED links (solid); approximated is a PROBABILISTIC link (dashed via
  // the b-inferred modifier). Unknown confidence falls back to a neutral chip.
  function confidenceBadge(conf) {
    var c = String(conf || "").toLowerCase();
    if (c === "deterministic") return Verity.badge("deterministic", "b-provenance");
    if (c === "human_confirmed") return Verity.badge("human-confirmed", "b-provenance");
    if (c === "approximated") return Verity.badge("approximated", "b-inferred", true);
    return Verity.badge(c || "unbadged", "b-kind");
  }

  // A summary {name,domain} → compact display. Both null (key:*/chunk:*/
  // malformed) renders an honest "no field summary" note, not a blank.
  function summaryLine(sum) {
    sum = sum || {};
    var bits = [];
    if (sum.name) bits.push("<b>" + Verity.esc(sum.name) + "</b>");
    if (sum.domain) bits.push('<span class="badge b-kind">' + Verity.esc(sum.domain) + "</span>");
    if (!bits.length) return '<span class="note">no name/domain fact — a light display hint only, not precedence-resolved truth</span>';
    return bits.join(" ");
  }

  function memberChips(members) {
    return (members || []).map(function (m) {
      // source:entity_id chip; the source colours nothing (entity accent chip).
      return '<span class="badge b-entity" title="source member">' +
        Verity.esc(m.source) + ":" + Verity.esc(m.entity_id) + "</span>";
    }).join(" ");
  }

  Verity.register({
    id: "entities",
    mount: function (section) {
      var el = Verity.$("entities-mount");
      if (!el) return;

      // -- current-entity state for the detail drawer + split action --------
      var current = { canonical: "", members: [] };

      // -- precedence-editor state (rebuilt from each loaded merged view) ----
      //   names  : field names in merged-view order (index = stable DOM handle,
      //            so arbitrary field/source strings never leak into ids)
      //   orders : field -> editable source order (highest precedence first),
      //            seeded winner-first from the merged view
      //   star   : editable order for the "(canonical, *)" entity default —
      //            the union of sources across all fields
      //   fields : field -> the raw MergedField (for conflict/provenance render)
      var prec = { names: [], orders: {}, star: [], fields: {}, ready: false };

      /* ---- tabs: (A) browser  (B) review queue ------------------------- */
      var tabs = document.createElement("div");
      tabs.className = "card";
      tabs.innerHTML =
        '<div class="row">' +
          '<div class="tight"><button class="primary" id="ent-tab-browser">Entities browser</button></div>' +
          '<div class="tight"><button id="ent-tab-queue">Review queue</button></div>' +
          '<div class="tight"><label for="ent-tenant">tenant_id</label>' +
            '<input type="text" id="ent-tenant" placeholder="(uses active tenant)"></div>' +
          '<div class="tight"><label for="ent-limit">limit</label>' +
            '<input type="number" id="ent-limit" value="100" min="1" max="1000" style="width:80px"></div>' +
        "</div>" +
        '<div class="note"><em>Admin-gated · audit-class.</em> This screen reads <b>across scopes</b> — it is behind ' +
          'the admin token (<b>X-Admin-Token</b> via the session card above). The <b>decide</b> action re-runs the ' +
          'resolver fold server-side so a confirm/reject takes effect immediately; the merged field view is instead ' +
          '<b>scope-gated</b> (it needs a scope handle, disclosed in the detail drawer).</div>';
      el.appendChild(tabs);

      /* ---- (A) entities browser --------------------------------------- */
      var browser = document.createElement("div");
      browser.id = "ent-browser";
      browser.innerHTML =
        '<div class="card">' +
          '<h2>Canonical entities <span class="sub">GET /v1/admin/entities · admin-token</span></h2>' +
          '<div class="row">' +
            '<div class="tight"><button id="ent-load-browser">Load entities</button></div>' +
            '<div class="note" style="flex:1">One card per <b>distinct canonical</b> the fold has aliased. ' +
              'Unmapped / implicit-own-canonical entities have no alias row and are <b>not</b> listed. ' +
              'Ordered by canonical key.</div>' +
          "</div>" +
          '<div class="note"><em>Confidence encoding.</em> ' + confidenceBadge("deterministic") +
            " / " + confidenceBadge("human_confirmed") + " are <b>guaranteed</b> links (solid); " +
            confidenceBadge("approximated") + " is a <b>probabilistic</b> link (dashed). Never blurred (SPEC §3).</div>" +
          '<div class="err" id="ent-browser-err"></div>' +
          '<div id="ent-browser-refreshed"></div>' +
          '<div id="ent-browser-out"></div>' +
        "</div>";
      el.appendChild(browser);

      /* ---- (B) review queue ------------------------------------------- */
      var queue = document.createElement("div");
      queue.id = "ent-queue";
      queue.style.display = "none";
      queue.innerHTML =
        '<div class="card">' +
          '<h2>Review queue <span class="sub">GET /v1/admin/entity-resolution/review-queue · admin-token</span></h2>' +
          '<div class="row">' +
            '<div class="tight"><button id="ent-load-queue">Load review queue</button></div>' +
            '<div class="note" style="flex:1">The live <b>Tier-2 / Tier-3</b> candidates the deterministic fold ' +
              'cannot decide alone — a human confirms the merge or rejects it (a <b>permanent</b> anti-link). ' +
              '<b>Ranked</b> by <b>priority</b> (frequency · entity value · tier · recency) — each card shows its ' +
              '<b>#rank</b>, priority score, and wait-age. An <b>aging / SLA</b> term keeps the oldest-waiting ' +
              'candidate from ever being buried; the longest-waiting card not yet at the top is flagged ' +
              '<span class="badge b-st-eligible">⚠ SLA risk</span> (amber rail) so a reviewer clears it. ' +
              'This is a read-out of the server ordering — no client-side re-sort.</div>' +
          "</div>" +
          '<div class="err" id="ent-queue-err"></div>' +
          '<div id="ent-queue-refreshed"></div>' +
          '<div id="ent-queue-out"></div>' +
        "</div>";
      el.appendChild(queue);

      /* ---- detail drawer (merged field view + evidence trail) ---------- */
      var drawer = document.createElement("div");
      drawer.className = "dialog-backdrop";
      drawer.id = "ent-drawer";
      drawer.innerHTML =
        '<div class="dialog" style="max-width:820px">' +
          '<h3 id="ent-drawer-title">Canonical entity</h3>' +
          '<div id="ent-drawer-members"></div>' +
          '<div class="card" style="margin-top:10px">' +
            '<h2>Merged field view <span class="sub">GET /v1/entities/{canonical} · scope-gated</span></h2>' +
            '<div class="note"><em>Scope-gated, not admin.</em> The per-field merged view enforces per call from a ' +
              'signed scope handle (it is a read-path endpoint). Paste one to load the winning source + provenance + ' +
              'superseded alternatives for each field. <b>merged_record field-resolution is untouched</b> — this is a ' +
              'faithful projection, not a re-ranking.</div>' +
            '<div class="row" style="margin-top:8px">' +
              '<div><label for="ent-scope-handle">scope handle (vs_&hellip;)</label>' +
                '<input type="text" id="ent-scope-handle" placeholder="vs_…" autocomplete="off" spellcheck="false"></div>' +
              '<div class="tight"><button id="ent-load-merged">Load merged view</button></div>' +
            "</div>" +
            '<div class="err" id="ent-merged-err"></div>' +
            '<div id="ent-merged-out"></div>' +
          "</div>" +
          '<div class="card" style="margin-top:8px">' +
            '<h2>Precedence editor <span class="sub">POST /v1/admin/entity-precedence · admin-token</span></h2>' +
            '<div class="note"><em>Per-field source-of-truth ranking (SPEC §7f).</em> Reorder the sources below ' +
              '(highest precedence first) and save — the merged view above resolves each field to the highest-ranked ' +
              'source that has a current fact. Resolution is most-specific-wins: <b>(canonical, field)</b> → ' +
              '<b>(canonical, *)</b> → <b>(*, *)</b> → none (recency tie-break). The source lists come from the ' +
              '<b>loaded merged view</b> (there is no read endpoint for precedence rows); saving is <b>admin-gated</b> ' +
              'even though the view above is scope-gated.</div>' +
            '<div class="err" id="ent-prec-err"></div>' +
            '<div id="ent-prec-out"></div>' +
          "</div>" +
          '<div class="card" style="margin-top:8px">' +
            '<h2>Split <span class="sub">retract + anti-link via decide/reject</span></h2>' +
            '<div class="note">Splitting a cluster picks two of its members and files a <b>reject</b> decision — a ' +
              'permanent anti-link (human_rejected, tier2, polarity −1) that the re-fold honours as a must-not-link. ' +
              'This is the same decide endpoint the review queue uses, in its reject direction.</div>' +
            '<div id="ent-split"></div>' +
          "</div>" +
          '<div class="actions">' +
            '<button id="ent-drawer-close">Close</button>' +
          "</div>" +
        "</div>";
      el.appendChild(drawer);
      var dlg = Verity.dialog("ent-drawer");
      Verity.$("ent-drawer-close").onclick = function () { dlg.close(); };

      /* ---- decide confirm dialog (confirm merge / reject / split) ------ */
      var decideEl = document.createElement("div");
      decideEl.className = "dialog-backdrop";
      decideEl.id = "ent-decide-dialog";
      decideEl.innerHTML =
        '<div class="dialog" style="max-width:600px">' +
          '<h3 id="ent-decide-title">Decide</h3>' +
          '<div class="note" id="ent-decide-summary"></div>' +
          '<div class="card" style="margin-top:10px">' +
            '<div class="note" id="ent-decide-explain"></div>' +
            '<div class="tight" style="margin-top:8px">' +
              '<label for="ent-decide-note">note <span class="note">(optional — stored as the decision\'s lineage/rationale pointer)</span></label>' +
              '<input type="text" id="ent-decide-note" class="field" placeholder="reviewer rationale" autocomplete="off">' +
            "</div>" +
          "</div>" +
          '<div class="err" id="ent-decide-err"></div>' +
          '<div class="actions">' +
            '<button class="primary" id="ent-decide-confirm">Decide</button>' +
            '<button id="ent-decide-cancel">Cancel</button>' +
          "</div>" +
        "</div>";
      el.appendChild(decideEl);
      var decideDlg = Verity.dialog("ent-decide-dialog");

      // Pending decision the confirm dialog will submit.
      var pending = { left: "", right: "", decision: "" };

      Verity.$("ent-decide-cancel").onclick = function () { decideDlg.close(); };
      Verity.$("ent-decide-confirm").onclick = async function () {
        Verity.clearErr("ent-decide-err");
        var tenant = activeTenant();
        if (!tenant) { Verity.err("ent-decide-err", new Error("no tenant selected")); return; }
        var btn = Verity.$("ent-decide-confirm");
        btn.disabled = true;
        try {
          var note = Verity.$("ent-decide-note").value.trim();
          var res = await Verity.api(
            "/v1/admin/entity-resolution/decide",
            { admin: true, json: {
              tenant_id: tenant,
              left_ref: pending.left,
              right_ref: pending.right,
              decision: pending.decision,
              note: note || null,
            } });
          decideDlg.close();
          dlg.close();
          renderDecideResult(res);
          // Fold has re-run server-side; refresh both surfaces so badges/clusters update.
          await loadQueue();
          await loadBrowser();
        } catch (e) {
          Verity.err("ent-decide-err", e);
        } finally {
          btn.disabled = false;
        }
      };

      // Open the decide dialog for a confirm/reject/split with honest copy.
      function openDecide(left, right, decision) {
        pending = { left: left, right: right, decision: decision };
        Verity.clearErr("ent-decide-err");
        Verity.$("ent-decide-note").value = "";
        var confirming = decision === "confirm";
        Verity.$("ent-decide-title").textContent = confirming ? "Confirm merge" : "Reject (anti-link)";
        Verity.$("ent-decide-summary").innerHTML =
          Verity.badge(Verity.esc(left), "b-entity") + ' <span class="note">vs</span> ' +
          Verity.badge(Verity.esc(right), "b-entity");
        Verity.$("ent-decide-explain").innerHTML = confirming
          ? "<em>Confirm.</em> Files a <b>human_confirmed</b> edge (tier-2, polarity +1) — the sole Tier-2 " +
            "edge-former. The resolver re-folds immediately and these refs resolve to one canonical."
          : "<em>Reject.</em> Files a <b>human_rejected</b> anti-link (tier-2, polarity −1) — a <b>PERMANENT</b> " +
            "must-not-link. The re-fold will keep these two apart (and split them if currently merged).";
        Verity.$("ent-decide-confirm").textContent = confirming ? "Confirm merge" : "Reject / anti-link";
        Verity.$("ent-decide-confirm").className = confirming ? "primary" : "";
        decideDlg.open();
      }

      function renderDecideResult(res) {
        if (!res) return;
        var m = res.materialize || {};
        var same = res.left_canonical && res.left_canonical === res.right_canonical;
        var line =
          '<div class="card" style="margin-top:10px">' +
            '<div class="note"><b>Decision applied &amp; re-folded.</b> ' +
              (res.evidence ? "evidence " + Verity.badge(Verity.esc(res.evidence.method), "b-kind") + " " : "") +
              "left → " + Verity.badge(Verity.esc(res.left_canonical || "—"), "b-entity") + " · " +
              "right → " + Verity.badge(Verity.esc(res.right_canonical || "—"), "b-entity") + " " +
              (same ? Verity.badge("merged", "b-provenance") : Verity.badge("distinct", "b-inferred", true)) +
            "</div>" +
            '<div class="note">materialize: ' +
              "evidence_considered " + Verity.esc(m.evidence_considered == null ? "—" : m.evidence_considered) + " · " +
              "aliases_written " + Verity.esc(m.aliases_written == null ? "—" : m.aliases_written) + " · " +
              "link_meta_written " + Verity.esc(m.link_meta_written == null ? "—" : m.link_meta_written) + " · " +
              "review_items " + Verity.esc(m.review_items == null ? "—" : m.review_items) + " · " +
              "canonicals " + Verity.esc(m.canonicals == null ? "—" : m.canonicals) +
            "</div>" +
          "</div>";
        // Surface it at the top of whichever section is visible.
        var host = Verity.$("ent-queue").style.display !== "none"
          ? Verity.$("ent-queue-refreshed") : Verity.$("ent-browser-refreshed");
        if (host) host.innerHTML = line;
      }

      /* ---- tab switching ---------------------------------------------- */
      function showBrowser() {
        Verity.$("ent-browser").style.display = "block";
        Verity.$("ent-queue").style.display = "none";
        Verity.$("ent-tab-browser").className = "primary";
        Verity.$("ent-tab-queue").className = "";
      }
      function showQueue() {
        Verity.$("ent-browser").style.display = "none";
        Verity.$("ent-queue").style.display = "block";
        Verity.$("ent-tab-browser").className = "";
        Verity.$("ent-tab-queue").className = "primary";
      }
      Verity.$("ent-tab-browser").onclick = showBrowser;
      Verity.$("ent-tab-queue").onclick = showQueue;

      /* ---- shared tenant/limit ---------------------------------------- */
      function activeTenant() {
        var typed = Verity.$("ent-tenant").value.trim();
        return typed || Verity.tenant() || "";
      }
      function activeLimit() {
        var n = parseInt(Verity.$("ent-limit").value, 10);
        if (isNaN(n)) n = 100;
        return Math.max(1, Math.min(1000, n));
      }

      /* ================================================================
         (A) ENTITIES BROWSER
         ================================================================ */
      async function loadBrowser() {
        Verity.clearErr("ent-browser-err");
        Verity.$("ent-browser-out").innerHTML = "";
        var tenant = activeTenant();
        if (!tenant) {
          Verity.err("ent-browser-err", new Error(
            "no tenant selected — type a tenant_id above (or decode a handle on Scope Inspector)"));
          return;
        }
        var url = "/v1/admin/entities?tenant_id=" + encodeURIComponent(tenant) +
          "&limit=" + encodeURIComponent(activeLimit());
        try {
          var rows = await Verity.api(url, { admin: true });
          rows = rows || [];
          renderBrowser(rows);
          Verity.$("ent-browser-refreshed").innerHTML =
            '<span class="refreshed">' + rows.length + " canonical entit" + (rows.length === 1 ? "y" : "ies") +
            " · loaded " + Verity.esc(Verity.fmtTime(Date.now())) + "</span>";
        } catch (e) {
          Verity.err("ent-browser-err", e);
        }
      }

      function renderBrowser(rows) {
        if (!rows.length) {
          Verity.$("ent-browser-out").innerHTML =
            '<div class="empty">No canonical entities for this tenant. Only entities the fold has <b>aliased</b> ' +
            "(a real alias row across ≥2 members) are listed — an unmapped entity is its own implicit canonical and " +
            "has nothing to enumerate here. That is not an error.</div>";
          return;
        }
        Verity.$("ent-browser-out").innerHTML = rows.map(function (row) {
          var b = row.badge;
          var badgeHtml = b
            ? confidenceBadge(b.confidence) +
              (b.strongest_method
                ? ' <span class="badge b-kind" title="strongest justifying method">' + Verity.esc(b.strongest_method) + "</span>"
                : "") +
              ' <span class="badge b-kind" title="corroboration depth">evidence ×' + Verity.esc(b.evidence_count) + "</span>"
            : '<span class="badge b-kind" title="no entity_link_meta badge row">unbadged</span>';
          return '<div class="hit ent-card" data-canonical="' + Verity.esc(row.canonical_entity) + '" style="cursor:pointer">' +
            '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
              Verity.badge(Verity.esc(row.canonical_entity), "b-entity") + badgeHtml +
            "</div>" +
            '<div class="content" style="margin:6px 0">' + summaryLine(row.summary) + "</div>" +
            '<div class="meta">members: ' + (row.members && row.members.length ? memberChips(row.members) : "—") +
              ' <span class="note" style="margin-left:6px">· click to inspect the merged field view + evidence</span></div>' +
          "</div>";
        }).join("");

        // Wire card clicks → detail drawer.
        var cards = Verity.$("ent-browser-out").querySelectorAll(".ent-card");
        for (var i = 0; i < cards.length; i++) {
          cards[i].onclick = function () {
            var canonical = this.getAttribute("data-canonical");
            var row = rows.filter(function (r) { return r.canonical_entity === canonical; })[0];
            openDetail(row);
          };
        }
      }

      /* ---- detail drawer ---------------------------------------------- */
      function openDetail(row) {
        current = { canonical: row.canonical_entity, members: row.members || [] };
        Verity.$("ent-drawer-title").textContent = row.canonical_entity;
        var b = row.badge;
        Verity.$("ent-drawer-members").innerHTML =
          '<div class="note">' +
            (b ? confidenceBadge(b.confidence) +
                 (b.strongest_method ? " via " + Verity.badge(Verity.esc(b.strongest_method), "b-kind") : "") +
                 " · evidence ×" + Verity.esc(b.evidence_count) + " "
               : '<span class="badge b-kind">unbadged</span> ') +
            "· members: " + (current.members.length ? memberChips(current.members) : "—") +
          "</div>";
        Verity.$("ent-merged-out").innerHTML = "";
        Verity.clearErr("ent-merged-err");
        // Precedence editor resets with the drawer — its source lists are
        // derived from THIS canonical's merged view, which is not loaded yet.
        prec = { names: [], orders: {}, star: [], fields: {}, ready: false };
        Verity.clearErr("ent-prec-err");
        Verity.$("ent-prec-out").innerHTML =
          '<div class="note">Load the <b>merged field view</b> above first — the per-field source lists are derived ' +
          "from its live facts (there is no read endpoint for precedence rows), so there is nothing honest to edit " +
          "until it loads.</div>";
        // Prefill scope handle from a previous entry (kept between opens).
        renderSplit();
        dlg.open();
      }

      // The SPLIT affordance: pick two distinct members → reject (anti-link).
      function renderSplit() {
        var host = Verity.$("ent-split");
        if (current.members.length < 2) {
          host.innerHTML = '<div class="note">A split needs ≥2 members — this cluster has ' +
            current.members.length + ", nothing to split apart.</div>";
          return;
        }
        var opts = current.members.map(function (m) {
          var ref = m.source + ":" + m.entity_id;
          return '<option value="' + Verity.esc(ref) + '">' + Verity.esc(ref) + "</option>";
        }).join("");
        host.innerHTML =
          '<div class="row" style="margin-top:6px">' +
            '<div><label for="ent-split-left">member A</label><select class="field" id="ent-split-left">' + opts + "</select></div>" +
            '<div><label for="ent-split-right">member B</label><select class="field" id="ent-split-right">' + opts + "</select></div>" +
            '<div class="tight"><button id="ent-split-go">Split (reject / anti-link)</button></div>' +
          "</div>" +
          '<div class="err" id="ent-split-err"></div>';
        // Default member B to the second member so they differ.
        var rsel = Verity.$("ent-split-right");
        if (rsel.options.length > 1) rsel.selectedIndex = 1;
        Verity.$("ent-split-go").onclick = function () {
          Verity.clearErr("ent-split-err");
          var l = Verity.$("ent-split-left").value;
          var r = Verity.$("ent-split-right").value;
          if (l === r) { Verity.err("ent-split-err", new Error("pick two DIFFERENT members to split apart")); return; }
          openDecide(l, r, "reject");
        };
      }

      async function loadMerged() {
        Verity.clearErr("ent-merged-err");
        Verity.$("ent-merged-out").innerHTML = "";
        var handle = Verity.$("ent-scope-handle").value.trim();
        if (!handle) { Verity.err("ent-merged-err", new Error("paste a scope handle — this endpoint is scope-gated, not admin")); return; }
        try {
          var res = await Verity.api(
            "/v1/entities/" + encodeURIComponent(current.canonical) +
              "?scope_handle=" + encodeURIComponent(handle));
          renderMerged(res);
          buildPrec(res);
          renderPrecedence();
        } catch (e) {
          Verity.err("ent-merged-err", e);
        }
      }
      Verity.$("ent-load-merged").onclick = loadMerged;

      function renderMerged(res) {
        var fields = (res && res.fields) || {};
        var names = Object.keys(fields);
        var badgeLine = res && res.badge
          ? '<div class="note">link badge: ' + confidenceBadge(res.badge.confidence) +
            (res.badge.strongest_method ? " via " + Verity.badge(Verity.esc(res.badge.strongest_method), "b-kind") : "") +
            " · evidence ×" + Verity.esc(res.badge.evidence_count) + "</div>"
          : '<div class="note">link badge: <span class="badge b-kind">unbadged</span></div>';
        if (!names.length) {
          Verity.$("ent-merged-out").innerHTML = badgeLine +
            '<div class="empty">No merged fields visible under this scope handle. If the handle cannot see this ' +
            "entity, the fail-closed empty result is correct — not a bug.</div>";
          return;
        }
        var rows = names.map(function (name) {
          var f = fields[name];
          var alts = (f.superseded_alternatives || []).map(function (a) {
            return "<tr><td></td><td>" + Verity.badge(Verity.esc(a.source), "b-kind") + "</td>" +
              "<td>" + Verity.esc(fmtVal(a.value)) + "</td>" +
              '<td class="note">entity ' + Verity.esc(a.entity_id) + " · valid_from " + Verity.esc(Verity.fmtTime(a.valid_from)) +
                " · citation→L0 " + Verity.esc(a.provenance) + "</td></tr>";
          }).join("");
          return "<tr>" +
              "<td><b>" + Verity.esc(name) + "</b></td>" +
              "<td>" + Verity.badge(Verity.esc(f.winning_source), "b-provenance") + '<div class="note">winning source</div></td>' +
              "<td><b>" + Verity.esc(fmtVal(f.value)) + "</b></td>" +
              '<td class="note">entity ' + Verity.esc(f.winning_entity_id) + " · valid_from " + Verity.esc(Verity.fmtTime(f.valid_from)) +
                " · citation→L0 " + Verity.esc(f.provenance) + "</td>" +
            "</tr>" + alts;
        }).join("");
        Verity.$("ent-merged-out").innerHTML = badgeLine +
          '<div class="note"><em>Conflict made visible.</em> Each field shows its precedence-winning source; ' +
            'the indented rows are the <b>superseded alternatives</b> from other sources — shown, never silently dropped.</div>' +
          '<div class="tablewrap"><table><thead><tr>' +
            "<th>field</th><th>source</th><th>value</th><th>provenance</th>" +
          "</tr></thead><tbody>" + rows + "</tbody></table></div>";
      }

      function fmtVal(v) {
        if (v == null) return "—";
        if (typeof v === "string") return v;
        try { return JSON.stringify(v); } catch (e) { return String(v); }
      }

      /* ================================================================
         PRECEDENCE EDITOR — per-field source-of-truth ranking (SPEC §7f,
         UI-SPEC §5 Screen 9 remainder)
         ================================================================ */

      // Canonical value string for conflict comparison (jsonb-faithful).
      function valKey(v) {
        try { return JSON.stringify(v === undefined ? null : v); }
        catch (e) { return String(v); }
      }

      // Cross-source CONFLICT rows for a merged field: alternatives from a
      // DIFFERENT source carrying a DIFFERENT value than the winner. Same-source
      // history or agreeing duplicates are not conflicts.
      function fieldConflicts(f) {
        var wv = valKey(f.value);
        return (f.superseded_alternatives || []).filter(function (a) {
          return a.source !== f.winning_source && valKey(a.value) !== wv;
        });
      }

      // HONEST rule inference. There is no GET for precedence rows, but the
      // no-rule tie-break is deterministic: most-recent valid_from wins. So if
      // an alternative from ANOTHER source is NEWER than the winner, a
      // precedence rule demonstrably overrode recency ("rule in effect"). If
      // the winner IS the newest cross-source fact, a rule that agrees with
      // recency and no rule at all are indistinguishable — we say exactly that,
      // we never guess.
      function ruleInferred(f) {
        var wf = Date.parse(f.valid_from) || 0;
        return (f.superseded_alternatives || []).some(function (a) {
          return a.source !== f.winning_source && (Date.parse(a.valid_from) || 0) > wf;
        });
      }

      // Rebuild the editor state from a freshly loaded merged view: per field,
      // the distinct sources winner-first then alternatives in server order;
      // the "*" entity default is the union across fields in first-seen order.
      function buildPrec(res) {
        var fields = (res && res.fields) || {};
        prec = { names: Object.keys(fields), orders: {}, star: [], fields: fields, ready: true };
        var starSeen = {};
        prec.names.forEach(function (name) {
          var f = fields[name];
          var seen = {};
          var order = [];
          function push(s) {
            if (!seen[s]) { seen[s] = true; order.push(s); }
            if (!starSeen[s]) { starSeen[s] = true; prec.star.push(s); }
          }
          push(f.winning_source);
          (f.superseded_alternatives || []).forEach(function (a) { push(a.source); });
          prec.orders[name] = order;
        });
      }

      // One reorderable ranked source list. `fi` is the field index ("*" for
      // the entity default) — indexes, never raw strings, travel in data-attrs.
      function rankList(order, fi) {
        if (!order.length) return '<div class="note">no sources — nothing to rank</div>';
        return order.map(function (src, i) {
          return '<div class="row" style="align-items:center;gap:6px;margin:2px 0">' +
            '<span class="badge b-kind" style="font-variant-numeric:tabular-nums" title="precedence rank (1 = wins)">#' + (i + 1) + "</span>" +
            Verity.badge(Verity.esc(src), "b-kind") +
            '<button class="ent-prec-move" data-fi="' + fi + '" data-idx="' + i + '" data-dir="-1"' +
              (i === 0 ? " disabled" : "") + ' title="raise precedence">▲</button>' +
            '<button class="ent-prec-move" data-fi="' + fi + '" data-idx="' + i + '" data-dir="1"' +
              (i === order.length - 1 ? " disabled" : "") + ' title="lower precedence">▼</button>' +
          "</div>";
        }).join("");
      }

      // Side-by-side conflict panel: the winner and each cross-source
      // conflicting value as equal columns, each with full provenance.
      // "Conflict made visible beats conflict resolved wrong."
      function conflictPanel(f, conflicts) {
        function col(label, source, value, entityId, validFrom, provenance, winning) {
          return '<div style="min-width:200px;flex:1;border:1px solid var(--border);border-radius:6px;padding:8px' +
              (winning ? ";border-color:var(--accent)" : "") + '">' +
            '<div class="note">' + label + " " + Verity.badge(Verity.esc(source), winning ? "b-provenance" : "b-kind") + "</div>" +
            '<div class="content" style="margin:4px 0"><b>' + Verity.esc(fmtVal(value)) + "</b></div>" +
            '<div class="note">entity ' + Verity.esc(entityId) + " · valid_from " + Verity.esc(Verity.fmtTime(validFrom)) +
              " · citation→L0 " + Verity.esc(provenance) + "</div>" +
          "</div>";
        }
        var cols = [col("current winner", f.winning_source, f.value, f.winning_entity_id, f.valid_from, f.provenance, true)]
          .concat(conflicts.map(function (a) {
            return col("conflicting", a.source, a.value, a.entity_id, a.valid_from, a.provenance, false);
          }));
        return '<div class="row" style="align-items:stretch;gap:8px;margin-top:6px;flex-wrap:wrap">' + cols.join("") + "</div>";
      }

      function renderPrecedence() {
        Verity.clearErr("ent-prec-err");
        var host = Verity.$("ent-prec-out");
        if (!prec.ready) return;
        if (!prec.names.length) {
          host.innerHTML =
            '<div class="empty">The loaded merged view has <b>no visible fields</b> under this scope handle — there ' +
            "is no per-field source list to rank. If the handle cannot see this entity, that fail-closed emptiness " +
            "is correct, not a bug.</div>";
          return;
        }

        var blocks = prec.names.map(function (name, fi) {
          var f = prec.fields[name];
          var order = prec.orders[name];
          var conflicts = fieldConflicts(f);
          var multi = order.length > 1;
          var inferred = ruleInferred(f);

          // Rule-state chip: proven rule (solid) / indistinguishable (dashed,
          // inferred encoding) — never a fabricated "no rule" claim.
          var ruleChip = inferred
            ? Verity.badge("rule in effect (inferred)", "b-provenance")
            : Verity.badge(multi ? "no rule detected (winner = newest — rule-agrees or no rule)" : "single source", "b-inferred", true);
          var conflictChip = conflicts.length
            ? ' <span class="badge b-st-eligible" title="cross-source conflict: another source carries a DIFFERENT current value for this field">⚠ cross-source conflict ×' + conflicts.length + "</span>"
            : "";

          return '<div class="hit" style="margin-bottom:10px">' +
            '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
              "<b>" + Verity.esc(name) + "</b> " + ruleChip + conflictChip +
            "</div>" +
            // A visible, unresolved conflict renders SIDE-BY-SIDE with full
            // provenance so the admin ranks with the evidence in view.
            (conflicts.length && !inferred
              ? '<div class="note" style="margin-top:6px"><em>Conflict made visible.</em> No rule is detectable for ' +
                "this field, so the winner below is the <b>recency tie-break</b>, not a chosen source of truth. " +
                "Rank the sources and save to make the choice explicit.</div>" +
                conflictPanel(f, conflicts)
              : "") +
            '<div class="row" style="align-items:flex-start;margin-top:8px">' +
              '<div style="flex:1">' + rankList(order, fi) + "</div>" +
              '<div class="tight"><button class="primary ent-prec-save" data-fi="' + fi + '" ' +
                'title="POST /v1/admin/entity-precedence — saves this exact order for (canonical, field); highest first. Unlisted sources rank after all listed ones.">' +
                "Save field rule</button></div>" +
            "</div>" +
            '<div id="ent-prec-msg-' + fi + '"></div>' +
          "</div>";
        }).join("");

        // The "(canonical, *)" entity default — union of sources across fields.
        var starBlock = prec.star.length > 1
          ? '<div class="hit" style="margin-bottom:10px">' +
              '<div><b>* (entity default)</b> ' + Verity.badge("applies to every field without its own rule", "b-kind") + "</div>" +
              '<div class="note" style="margin-top:4px">Saved as <b>field = "*"</b> for this canonical: the fallback ' +
                "order for any field that has no field-specific rule. The global (*, *) default is out of scope here — " +
                "this editor writes only rules for <b>this</b> canonical.</div>" +
              '<div class="row" style="align-items:flex-start;margin-top:8px">' +
                '<div style="flex:1">' + rankList(prec.star, "*") + "</div>" +
                '<div class="tight"><button class="primary ent-prec-save" data-fi="*" ' +
                  'title="POST /v1/admin/entity-precedence with field=&quot;*&quot; — the entity-level default order.">' +
                  "Save entity default</button></div>" +
              "</div>" +
              '<div id="ent-prec-msg-star"></div>' +
            "</div>"
          : "";

        host.innerHTML =
          '<div class="note">Sources below are the ones with <b>live facts</b> in the merged view (winner-first ' +
            "seed). Reorder with ▲▼ — <b>highest precedence first</b> — then save. Saving re-loads the merged view " +
            "so the new winners are shown, not assumed.</div>" +
          blocks + starBlock;

        // Wire ▲▼ moves (index-addressed; re-render keeps buttons honest).
        var moves = host.querySelectorAll(".ent-prec-move");
        for (var i = 0; i < moves.length; i++) {
          moves[i].onclick = function () {
            var fi = this.getAttribute("data-fi");
            var idx = parseInt(this.getAttribute("data-idx"), 10);
            var dir = parseInt(this.getAttribute("data-dir"), 10);
            var order = fi === "*" ? prec.star : prec.orders[prec.names[parseInt(fi, 10)]];
            if (!order) return;
            var j = idx + dir;
            if (idx < 0 || j < 0 || idx >= order.length || j >= order.length) return;
            var t = order[idx]; order[idx] = order[j]; order[j] = t;
            renderPrecedence();
          };
        }

        // Wire saves.
        var saves = host.querySelectorAll(".ent-prec-save");
        for (var s = 0; s < saves.length; s++) {
          saves[s].onclick = function () { savePrecedence(this, this.getAttribute("data-fi")); };
        }
      }

      async function savePrecedence(btn, fi) {
        Verity.clearErr("ent-prec-err");
        var tenant = activeTenant();
        if (!tenant) { Verity.err("ent-prec-err", new Error("no tenant selected — type a tenant_id above")); return; }
        var star = fi === "*";
        var field = star ? "*" : prec.names[parseInt(fi, 10)];
        var order = star ? prec.star : prec.orders[field];
        if (!field || !order || !order.length) {
          Verity.err("ent-prec-err", new Error("nothing to save — no ranked sources for this field"));
          return;
        }
        btn.disabled = true;
        try {
          var res = await Verity.api("/v1/admin/entity-precedence", { admin: true, json: {
            tenant_id: tenant,
            canonical: current.canonical,
            field: field,
            source_order: order,
          } });
          var msg = Verity.$(star ? "ent-prec-msg-star" : "ent-prec-msg-" + fi);
          if (msg) {
            msg.innerHTML = '<span class="refreshed">saved: (' + Verity.esc(res.canonical) + ", " +
              Verity.esc(res.field) + ") → [" +
              (res.source_order || []).map(Verity.esc).join(" › ") + "] · " +
              Verity.esc(Verity.fmtTime(Date.now())) + " · re-loading merged view…</span>";
          }
          // Show the rule's effect, don't assert it: re-load the merged view so
          // winners/conflict chips re-derive from the server's own resolution.
          await loadMerged();
        } catch (e) {
          Verity.err("ent-prec-err", e);
          btn.disabled = false;
        }
      }

      /* ================================================================
         (B) REVIEW QUEUE — side-by-side diff cards
         ================================================================ */
      async function loadQueue() {
        Verity.clearErr("ent-queue-err");
        Verity.$("ent-queue-out").innerHTML = "";
        var tenant = activeTenant();
        if (!tenant) {
          Verity.err("ent-queue-err", new Error(
            "no tenant selected — type a tenant_id above (or decode a handle on Scope Inspector)"));
          return;
        }
        var url = "/v1/admin/entity-resolution/review-queue?tenant_id=" + encodeURIComponent(tenant) +
          "&limit=" + encodeURIComponent(activeLimit());
        try {
          var rows = await Verity.api(url, { admin: true });
          rows = rows || [];
          renderQueue(rows);
          Verity.$("ent-queue-refreshed").innerHTML =
            '<span class="refreshed">' + rows.length + " candidate" + (rows.length === 1 ? "" : "s") +
            " · loaded " + Verity.esc(Verity.fmtTime(Date.now())) + "</span>";
        } catch (e) {
          Verity.err("ent-queue-err", e);
        }
      }

      function renderQueue(rows) {
        if (!rows.length) {
          // HONEST empty state — never a fabricated candidate row (SPEC §3).
          Verity.$("ent-queue-out").innerHTML =
            '<div class="empty"><b>No Tier-2/3 candidates awaiting review.</b> The queue holds only live ' +
            "<b>tier IN (2,3)</b> evidence with no decision yet. An empty queue means the deterministic (Tier-1) fold " +
            "settled everything, or the Tier-2 producer has not run to populate it — not a hidden merge. Nothing " +
            "here is auto-decided; that is the point of the human gate.</div>";
          return;
        }

        // ---- starvation context (design §8 aging / SLA) --------------------
        // The server ORDERs by `priority` DESC (the unbounded aging term is one
        // signal inside it, not the sort key), so the row that has WAITED the
        // longest is not necessarily at the top — it may be sitting far down the
        // ranked list while its aging term slowly floats it up. We surface that
        // gap honestly: find the max wait-age across the loaded page and flag the
        // oldest-waiting candidate(s) that are NOT already near the top of the
        // queue, so a reviewer can clear an SLA risk before it starves. This is a
        // read-out over the server's own numbers — no re-ordering, no new policy.
        var maxWait = 0;
        for (var wi = 0; wi < rows.length; wi++) {
          var w = Number(rows[wi].wait_age_secs);
          if (isFinite(w) && w > maxWait) maxWait = w;
        }
        // Only meaningful once something has actually waited a while (≥1h) AND
        // the queue is deep enough that the oldest could be buried behind others.
        var STARVE_MIN_SECS = 3600;
        var starveActive = maxWait >= STARVE_MIN_SECS && rows.length > 1;

        Verity.$("ent-queue-out").innerHTML = rows.map(function (c, i) {
          // rank is 1-based over the server's priority DESC order.
          var oldest = starveActive &&
            c.wait_age_secs != null && Number(c.wait_age_secs) === maxWait;
          // A starvation RISK is the oldest-waiting card that the priority sort
          // has NOT already surfaced at the very top (rank 1). If the oldest also
          // ranks #1 the SLA term already won — no risk to flag.
          var starving = oldest && i > 0;
          return candidateCard(c, i + 1, rows.length, starving, oldest);
        }).join("");

        // Wire per-candidate confirm/reject.
        var host = Verity.$("ent-queue-out");
        var confirms = host.querySelectorAll(".ent-cand-confirm");
        var rejects = host.querySelectorAll(".ent-cand-reject");
        function wire(list, decision) {
          for (var i = 0; i < list.length; i++) {
            list[i].onclick = function () {
              openDecide(this.getAttribute("data-left"), this.getAttribute("data-right"), decision);
            };
          }
        }
        wire(confirms, "confirm");
        wire(rejects, "reject");
      }

      // One Tier-2/3 candidate → a side-by-side diff card.
      //   rank      : 1-based position in the server's priority DESC order
      //   total     : queue depth (for the "#3 / 12" read-out)
      //   starving  : oldest-waiting card that priority has NOT floated to #1
      //   oldest    : this card carries the max wait-age in the loaded page
      function candidateCard(c, rank, total, starving, oldest) {
        var polarity = Number(c.polarity);
        var polChip = polarity < 0
          ? Verity.badge("anti-link (−1)", "b-quarantined")
          : Verity.badge("link (+1)", "b-provenance");
        var scoreChip = c.score == null
          ? ""
          : ' <span class="badge b-kind" title="blocker/judge score">score ' + Number(c.score).toFixed(3) + "</span>";
        var keyChip = c.key_value
          ? ' <span class="badge b-kind" title="matched key">key ' + Verity.esc(c.key_value) + "</span>"
          : "";
        var nsChip = c.key_namespace
          ? ' <span class="badge b-kind" title="population fence namespace">ns ' + Verity.esc(c.key_namespace) + "</span>"
          : "";
        var tierChip = Verity.badge("tier " + Verity.esc(c.tier), "b-kind");
        var methodChip = Verity.badge(Verity.esc(c.method), "b-inferred", true);

        // Prioritization chips (design §8 Later). The server orders the queue by
        // `priority` DESC; we surface the RANK (position in that order), the
        // score, the wait-age (SLA read-out), and the frequency / entity-value
        // signals that fed it so the ordering is legible, not magic.
        //
        // Rank chip — the visible PRIORITY indicator: "#1 / 12". Solid entity
        // accent for #1 (the top call), neutral for the rest.
        var rankChip = '<span class="badge ' + (rank === 1 ? "b-entity" : "b-kind") +
          '" title="rank in the server\'s priority-DESC order (1 = highest priority)" ' +
          'style="font-variant-numeric:tabular-nums">#' + rank + " / " + total + "</span>";
        var prioChip = c.priority == null
          ? ""
          : Verity.badge("priority " + Number(c.priority).toFixed(2), "b-entity");
        // Wait-age. When this card is the oldest-waiting in the page we mark the
        // chip amber (via the frozen --amber token) so the SLA read-out is not
        // lost in the neutral run of chips.
        var ageChip = c.wait_age_secs == null
          ? ""
          : ' <span class="badge b-kind" ' +
            (oldest ? 'style="color:var(--amber);border-color:var(--amber-line);background:var(--amber-soft)" ' : "") +
            'title="wait age = now() − valid_from; the SLA / anti-starvation aging term floats this up as it grows">waited ' +
            Verity.esc(fmtAge(c.wait_age_secs)) + "</span>";
        // Starvation-risk flag — the oldest-waiting candidate that priority has
        // NOT yet floated to the top. An amber "SLA RISK" chip tells the reviewer
        // to clear this one so it can never be indefinitely buried.
        var starveChip = starving
          ? ' <span class="badge b-st-eligible" title="STARVATION RISK: the longest-waiting candidate in the queue, not yet at the top — clear it so the SLA aging term never has to bury it further. This is a read-out over the server ordering, not a re-sort.">⚠ SLA risk · oldest waiting</span>'
          : "";
        var freqChip = (c.frequency == null || Number(c.frequency) <= 1)
          ? ""
          : ' <span class="badge b-kind" title="FREQUENCY: live evidence rows recurring on this ref-pair">freq ' +
            Verity.esc(c.frequency) + "</span>";
        var valChip = (c.entity_value == null || Number(c.entity_value) <= 0)
          ? ""
          : ' <span class="badge b-kind" title="ENTITY VALUE: distinct alias members in the two refs\' clusters — bigger = higher blast radius">value ' +
            Verity.esc(c.entity_value) + "</span>";

        var lEsc = Verity.esc(c.left_ref);
        var rEsc = Verity.esc(c.right_ref);

        // Starving rows get an amber left rail (frozen --amber token) so the
        // SLA-risk card is scannable in a long queue without re-ordering it.
        var cardStyle = "margin-bottom:12px" +
          (starving ? ";border-left:3px solid var(--amber)" : "");

        return '<div class="card" style="' + cardStyle + '">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">' +
            rankChip + prioChip + starveChip + methodChip + tierChip + polChip + scoreChip + keyChip + nsChip +
            ageChip + freqChip + valChip +
            ' <span class="note">valid_from ' + Verity.esc(Verity.fmtTime(c.valid_from)) + "</span>" +
          "</div>" +
          '<div class="row" style="align-items:stretch">' +
            sideCol("left", c.left_ref, c.left_summary) +
            '<div class="tight" style="display:flex;align-items:center;color:var(--dim);font-size:18px">⇔</div>' +
            sideCol("right", c.right_ref, c.right_summary) +
          "</div>" +
          (c.rationale
            ? '<div class="note" style="margin-top:8px"><em>rationale:</em> ' + Verity.esc(c.rationale) +
              ' <span class="note">(from evidence_l0_ref — judge/reviewer lineage pointer)</span></div>'
            : '<div class="note" style="margin-top:8px">no rationale recorded on this candidate</div>') +
          '<div class="actions" style="margin-top:10px">' +
            '<button class="primary ent-cand-confirm" data-left="' + lEsc + '" data-right="' + rEsc + '" ' +
              'title="POST decide confirm — human_confirmed edge (tier2,+1), the sole Tier-2 edge-former; re-folds immediately.">' +
              'Confirm merge</button>' +
            '<button class="ent-cand-reject" data-left="' + lEsc + '" data-right="' + rEsc + '" ' +
              'title="POST decide reject — human_rejected anti-link (tier2,−1), a PERMANENT must-not-link.">' +
              'Reject</button>' +
          "</div>" +
        "</div>";
      }

      // One side of a diff card: the ref + its {name,domain} summary.
      function sideCol(which, ref, sum) {
        sum = sum || {};
        return '<div style="min-width:200px">' +
          '<div class="note">' + which + ' <span class="badge b-entity">' + Verity.esc(ref) + "</span>" +
            ' <span class="note">(' + Verity.esc(refSource(ref)) + ")</span></div>" +
          '<div class="content" style="margin:4px 0">' + summaryLine(sum) + "</div>" +
        "</div>";
      }

      /* ---- load buttons + initial state ------------------------------- */
      Verity.$("ent-load-browser").onclick = loadBrowser;
      Verity.$("ent-load-queue").onclick = loadQueue;
      showBrowser();

      // Reflect the active tenant into the placeholder honestly.
      Verity.onTenant(function (t) {
        var f = Verity.$("ent-tenant");
        if (f && !f.value.trim()) f.placeholder = t ? "(active: " + t + ")" : "(uses active tenant)";
      });
      (function () {
        var t = Verity.tenant();
        var f = Verity.$("ent-tenant");
        if (f && t) f.placeholder = "(active: " + t + ")";
      })();
    },
  });
})();
