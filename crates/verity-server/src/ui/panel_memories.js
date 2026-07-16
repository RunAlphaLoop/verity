"use strict";
/* ==========================================================================
   panel_memories.js — Memories  [frozen design contract]
   --------------------------------------------------------------------------
   Reads (both admin-gated; this panel writes nothing):
     • GET /v1/admin/memories?tenant_id=&source=&entity=&kind=&q=
           &include_superseded=&limit=&before= — the browse page: rows
       (chunk | fact | action in one shape, newest-recorded first), per-source
       counts for the dropdown (same filtered union), and a keyset cursor.
     • GET /v1/admin/memories?tenant_id=&id= — one row with FULL content
       (superseded included) for the detail drawer; fact/chunk history windows
       reuse the list read with pinned filters.

   THE LAW, applied:
     • autoloads once a tenant is known — no cold Load button;
     • filters are server-side and honest: the source dropdown offers only
       sources the OTHER filters can reach, with real counts; the entity
       filter is the shared Verity.entityPicker (offers what exists, invents
       nothing); "0 rows" names exactly which filter hid them;
     • the admin-plane nature is disclosed, not hidden: this browser sees
       across all scopes because it IS the admin plane — it grants agents
       nothing; per-scope retrievability is decided at read time on the
       scoped paths;
     • bi-temporal honesty: replaced values are hidden by default but never
       deleted — the toggle says so, and the drawer walks the supersession
       chain (old value → new value, with timestamps) when one exists;
     • visibility is a COUNT of principal tokens ("visible to N principals"),
       never the tokens; facts say honestly that L1 carries no per-row tokens.
   READ-PATH PURITY: pure admin GETs; zero LLM, zero live ReBAC, and nothing
   here touches recall/get.
   ========================================================================== */
(function () {
  var V = window.Verity;

  var KIND_LABEL = { chunk: "search snippet", fact: "fact", action: "action" };
  var TABLE_COLS = 4;
  var PAGE_LIMIT = 50;
  var HISTORY_WINDOW = 200;

  /* ------------------------------------------------------------ state */

  var ROWS = [];          // accumulated pages, server order (newest first)
  var SOURCES = [];       // [{source, count}] from the last (re)load
  var NEXT = null;        // keyset cursor: next_before, or null at the end
  var NEXT_ID = null;     // tie-breaker half of the cursor (next_before_id)
  var tenantNow = "";
  var entPicker = null;   // Verity.entityPicker (single-select, scope-ish)
  var kindNow = "";       // "" | chunk | fact | action
  var qTimer = null;      // debounce for the free-text search
  var seq = 0;            // fetch generation — stale responses are dropped

  function el(id) { return V.$(id); }

  /* ------------------------------------------------------------ helpers */

  function activeFilters() {
    var f = [];
    var src = el("mem-f-source").value;
    if (src) f.push('source "' + src + '"');
    var ent = entPicker ? (entPicker.value()[0] || "") : "";
    if (ent) f.push('entity "' + ent + '"');
    if (kindNow) f.push('kind "' + KIND_LABEL[kindNow] + '"');
    var q = el("mem-f-q").value.trim();
    if (q) f.push('search "' + q + '"');
    return f;
  }

  function queryString(extra) {
    var p = "/v1/admin/memories?tenant_id=" + encodeURIComponent(tenantNow) +
      "&limit=" + PAGE_LIMIT;
    var src = el("mem-f-source").value;
    if (src) p += "&source=" + encodeURIComponent(src);
    var ent = entPicker ? (entPicker.value()[0] || "") : "";
    if (ent) p += "&entity=" + encodeURIComponent(ent);
    if (kindNow) p += "&kind=" + kindNow;
    var q = el("mem-f-q").value.trim();
    if (q) p += "&q=" + encodeURIComponent(q);
    if (el("mem-f-sup").checked) p += "&include_superseded=true";
    if (extra) p += extra;
    return p;
  }

  function trustName(t) {
    return t === 1 ? "authoritative" : t === 2 ? "observation" : String(t);
  }

  // "(principals)" is glossed once per rendered list, then plain
  // "people & groups" — the flag resets on every render().
  var visGlossShown = false;

  function visiblePhrase(r) {
    if (r.visible_to == null) {
      return r.kind === "fact"
        ? "who can see it (visibility): the whole space at read time — the structured current-truth store (L1) carries no per-row visibility list"
        : "who can see it (visibility): not recorded";
    }
    if (r.visible_to === 0) return "who can see it (visibility): nobody — fail closed";
    var noun = r.visible_to === 1 ? "key" : "keys";
    if (!visGlossShown) {
      noun += r.visible_to === 1 ? " (a principal)" : " (principals — the keys and shared keys that read)";
      visGlossShown = true;
    }
    return "visible to " + r.visible_to + " " + noun;
  }

  /* ------------------------------------------------------------ register */

  V.register({
    id: "memories",

    mount: function () {
      var host = el("mem-mount");
      if (!host) return;
      host.innerHTML =
        /* ---- toolbar ---- */
        '<div class="toolbar">' +
          '<span id="mem-state">' + V.stateChip("off", "waiting for a space") + '</span>' +
          '<span class="asof" id="mem-asof"></span>' +
          '<span class="spacer"></span>' +
          '<button id="mem-refresh">Refresh</button>' +
        '</div>' +

        /* ---- the admin-plane disclosure (like the audit panel) ---- */
        '<div class="note" style="margin:2px 0 8px">&#9432; <b>Admin-plane read.</b> This browser sees across ' +
          'all scopes because it is the admin plane (like the access audit) &mdash; it bypasses no enforcement ' +
          'for agents. What an agent can retrieve is decided per-scope at read time, on the scoped paths only.</div>' +

        /* ---- filters (all server-side) ---- */
        '<div class="row">' +
          '<div class="tight" style="min-width:200px"><label for="mem-f-source">source</label>' +
            '<select class="field" id="mem-f-source"><option value="">all sources</option></select></div>' +
          '<div style="min-width:220px;max-width:340px"><label>entity</label>' +
            '<div id="mem-f-entity"></div></div>' +
          '<div class="tight"><label>kind</label>' +
            '<div class="seg" id="mem-f-kind">' +
              '<button data-kind="" class="on">all</button>' +
              '<button data-kind="chunk">snippets</button>' +
              '<button data-kind="fact">facts</button>' +
              '<button data-kind="action">actions</button>' +
            '</div></div>' +
          '<div style="min-width:180px"><label for="mem-f-q">search text</label>' +
            '<input type="text" id="mem-f-q" placeholder="substring of content / value / summary&hellip;" autocomplete="off"></div>' +
          '<div class="tight"><label class="checkline" style="margin-bottom:7px" ' +
              'title="replaced rows keep their valid_to + supersession link — Verity invalidates, it never deletes">' +
            '<input type="checkbox" id="mem-f-sup"> show replaced values too &mdash; the full history of what changed and when (bi-temporal), never deleted</label></div>' +
          '<div class="tight"><button id="mem-f-clear">Clear</button></div>' +
        '</div>' +

        '<div class="err" id="mem-err"></div>' +
        '<div id="mem-summary"></div>' +
        '<div id="mem-out"></div>' +
        '<div id="mem-more" style="margin-top:10px"></div>' +

        /* ---- detail drawer ---- */
        '<div class="dialog-backdrop" id="mem-drawer"><div class="dialog" style="max-width:860px">' +
          '<h3 id="mem-drawer-title">Memory</h3>' +
          '<div id="mem-drawer-body"></div>' +
          '<div class="actions"><button id="mem-drawer-close">Close</button></div>' +
        '</div></div>';

      /* ---- wiring ---- */
      el("mem-refresh").onclick = function () { V.reload("memories"); };
      el("mem-f-source").addEventListener("change", function () { refetch(); });
      el("mem-f-sup").addEventListener("change", function () { refetch(); });
      el("mem-f-q").addEventListener("input", function () {
        if (qTimer) clearTimeout(qTimer);
        qTimer = setTimeout(refetch, 300);
      });
      el("mem-f-kind").addEventListener("click", function (ev) {
        var b = ev.target.closest ? ev.target.closest("button") : null;
        if (!b) return;
        kindNow = b.getAttribute("data-kind") || "";
        el("mem-f-kind").querySelectorAll("button").forEach(function (x) {
          x.classList.toggle("on", x === b);
        });
        refetch();
      });
      el("mem-f-clear").onclick = function () {
        el("mem-f-source").value = "";
        el("mem-f-q").value = "";
        el("mem-f-sup").checked = false;
        kindNow = "";
        el("mem-f-kind").querySelectorAll("button").forEach(function (x) {
          x.classList.toggle("on", !x.getAttribute("data-kind"));
        });
        if (entPicker) entPicker.clear(); // fires onChange → refetch
        else refetch();
      };
      // The shared picker: single-select, scope-ish (offers what exists,
      // Emptiness Law hides the field when the tenant has no entities yet).
      entPicker = V.entityPicker(el("mem-f-entity"), {
        mode: "scope",
        multiple: false,
        allowNew: true,
        emptyBehavior: "hide",
        emptyLabel: "No entities yet — nothing to filter by. Entity tags appear as your data carries them (like account:acme).",
        placeholder: "account:acme",
        explainer: "only rows tagged with this entity (facts match their source:entity_id tag)",
        onChange: function () { refetch(); },
      });
      el("mem-more").addEventListener("click", function (ev) {
        var b = ev.target.closest ? ev.target.closest("#mem-loadmore") : null;
        if (b) loadMore();
      });
      // delegated row click → drawer (chunks + facts; actions are append-only
      // events with nothing more than the row already shows)
      el("mem-out").addEventListener("click", function (ev) {
        var row = ev.target && ev.target.closest ? ev.target.closest("tr.mem-row") : null;
        if (!row) return;
        var idx = parseInt(row.getAttribute("data-idx"), 10);
        var r = ROWS[idx];
        if (r && (r.kind === "chunk" || r.kind === "fact")) openDrawer(r);
      });
      el("mem-drawer-close").onclick = function () { V.dialog("mem-drawer").close(); };

      if (!V.tenant()) renderNoTenant();
    },

    // AUTOLOAD (LAW #3): runs when the panel is shown and a tenant is known;
    // re-runs on tenant change; deduped per tenant.
    load: function (_s, tenant) {
      tenantNow = tenant;
      if (entPicker) entPicker.refresh();
      return refetch();
    },
  });

  /* ------------------------------------------------------------ no tenant */

  function renderNoTenant() {
    el("mem-out").innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a space to browse its memory</div>' +
        '<div class="et-body">Choose it in the session bar above &mdash; this browser loads by itself ' +
          'the moment one is picked. Everything that space remembers is listed here: conversations and ' +
          'events (episodes), profile facts, and search snippets.</div>' +
      '</div>';
  }

  /* ------------------------------------------------------------ fetching */

  async function refetch() {
    if (!tenantNow) return;
    var my = ++seq;
    V.clearErr("mem-err");
    el("mem-state").innerHTML = V.stateChip("wait", "loading");
    try {
      var res = await V.api(queryString(), { admin: true });
      if (my !== seq) return; // a newer filter change superseded this fetch
      ROWS = (res && res.rows) || [];
      SOURCES = (res && res.sources) || [];
      NEXT = res ? res.next_before : null;
      NEXT_ID = res ? res.next_before_id : null;
      renderSources();
      el("mem-state").innerHTML = ROWS.length
        ? V.stateChip("ok", ROWS.length + (NEXT ? "+" : "") + " memor" + (ROWS.length === 1 && !NEXT ? "y" : "ies"))
        : V.stateChip("ok", "0 rows");
      el("mem-asof").textContent = "checked " + new Date().toTimeString().slice(0, 8);
      render();
    } catch (e) {
      if (my !== seq) return;
      el("mem-state").innerHTML = V.stateChip("fail");
      var msg = String(e.message);
      if (/HTTP 401/.test(msg)) {
        V.err("mem-err", new Error(msg +
          "\nThis read needs the admin token — set it in the session bar (it lives in this tab only)."));
      } else if (/HTTP 400/.test(msg) && /UUID parsing failed/.test(msg)) {
        // The server's serde text is honest but unreadable — translate it,
        // keep the raw refusal dimmed beneath.
        var box = el("mem-err");
        box.innerHTML = "This space (tenant) id isn't valid — Verity space ids are UUIDs " +
          "(they look like 019f53b8-…). Pick a real space in the session bar above." +
          '<div class="ref" style="margin-top:4px">' + V.esc(msg) + "</div>";
        box.classList.add("on");
      } else {
        V.err("mem-err", e);
      }
    }
  }

  async function loadMore() {
    if (!NEXT) return;
    var my = ++seq;
    var btn = el("mem-loadmore");
    if (btn) { btn.disabled = true; btn.textContent = "loading…"; }
    try {
      var res = await V.api(queryString("&before=" + encodeURIComponent(NEXT) +
        (NEXT_ID ? "&before_id=" + encodeURIComponent(NEXT_ID) : "")), { admin: true });
      if (my !== seq) return;
      ROWS = ROWS.concat((res && res.rows) || []);
      NEXT = res ? res.next_before : null;
      NEXT_ID = res ? res.next_before_id : null;
      render();
    } catch (e) {
      if (my !== seq) return;
      V.err("mem-err", e);
      render(); // restore the button
    }
  }

  /* ------------------------------------------------------------ sources */

  // Rebuild the dropdown from the endpoint's per-source counts (the SAME
  // filtered union as the rows — never a separate estimate). The current
  // selection survives even at count 0 so the operator can un-pick it.
  function renderSources() {
    var sel = el("mem-f-source");
    var cur = sel.value;
    var total = 0;
    SOURCES.forEach(function (s) { total += s.count; });
    var opts = '<option value="">all sources (' + total + ' row' + (total === 1 ? "" : "s") + ')</option>';
    var seen = false;
    SOURCES.forEach(function (s) {
      if (s.source === cur) seen = true;
      opts += '<option value="' + V.esc(s.source) + '">' + V.esc(s.source) + " (" + s.count + ")</option>";
    });
    if (cur && !seen) {
      opts += '<option value="' + V.esc(cur) + '">' + V.esc(cur) + " (0 under these filters)</option>";
    }
    sel.innerHTML = opts;
    sel.value = cur;
  }

  /* ------------------------------------------------------------ rows */

  // Shorten a raw uuid-ish entity id for the dimmed secondary line; the full
  // id stays on hover and in the drawer. Short human ids pass through whole.
  function shortEntity(id) {
    var s = String(id || "");
    return s.length > 14 ? s.slice(0, 8) + "…" : s;
  }

  function primaryHtml(r) {
    var cut = r.preview_truncated ? '<span class="ref">&hellip;</span>' : "";
    if (r.kind === "fact") {
      // The FIELD is the human label; the raw entity id is demoted to the
      // secondary line (no resolved display name in this payload — never guess).
      return '<b>' + V.esc(r.field || "") + '</b> = ' + V.esc(r.preview) + cut;
    }
    if (r.kind === "action") {
      return '<b>' + V.esc(r.action_type || "action") + '</b> ' + V.esc(r.preview) + cut +
        (r.outcome && r.outcome !== "succeeded"
          ? " " + V.badge(r.outcome, r.outcome === "failed" ? "b-quarantined" : "b-kind") : "");
    }
    return V.esc(r.preview) + cut;
  }

  function secondaryHtml(r) {
    var bits = ['from <b>' + V.esc(r.source) + '</b>'];
    if (r.kind === "fact" && r.entity_id) {
      bits.push('on <span class="ref" title="' + V.esc(r.entity_id) + '">' +
        V.esc(shortEntity(r.entity_id)) + '</span>');
    }
    if ((r.entities || []).length) bits.push(V.entityBadges(r.entities.slice(0, 4)) +
      (r.entities.length > 4 ? ' <span class="ref">+' + (r.entities.length - 4) + ' more</span>' : ""));
    if (r.acl_provenance) bits.push(V.provenanceBadge(r.acl_provenance));
    if (r.confidentiality != null) bits.push(V.confBadge(r.confidentiality));
    if (r.trust_tier != null) bits.push(V.trustBadge(trustName(r.trust_tier)));
    bits.push(V.esc(visiblePhrase(r)));
    if (r.valid_to) bits.push(V.badge("replaced " + V.timeAgo(r.valid_to), "b-quarantined"));
    if (V.isSample(r.source) || V.isSample(r.entities)) bits.push(V.sampleBadge("verity-sample"));
    return '<div class="note" style="margin-top:2px">' + bits.join(" · ") + '</div>';
  }

  function render() {
    var f = activeFilters();
    visGlossShown = false; // first row of every render carries the gloss
    // summary strip
    el("mem-summary").innerHTML = ROWS.length
      ? '<div class="toolbar" style="margin:2px 0 8px"><span class="asof"><b style="color:var(--text)">' +
          ROWS.length + '</b> row' + (ROWS.length === 1 ? "" : "s") + " loaded, newest first" +
          (el("mem-f-sup").checked ? " · replaced values shown" : " · live values only") +
          (f.length ? " · filtered by " + V.esc(f.join(", ")) : "") + '</span></div>'
      : "";

    if (!ROWS.length) {
      if (f.length || el("mem-f-sup").checked) {
        el("mem-out").innerHTML =
          '<div class="note" style="margin-top:10px">0 rows match ' +
          (f.length ? "these filters: <b>" + V.esc(f.join(", ")) + "</b>" : "this view") +
          (el("mem-f-sup").checked ? "" : " (replaced values are hidden — the toggle above shows history)") +
          '. <button id="mem-empty-clear" style="margin-left:8px">Clear all filters</button></div>';
        el("mem-empty-clear").onclick = function () { el("mem-f-clear").click(); };
      } else {
        el("mem-out").innerHTML =
          '<div class="empty-teach sp-a">' +
            '<div class="et-title">Nothing in this space&rsquo;s memory yet</div>' +
            '<div class="et-body">The moment anything lands &mdash; a pasted note, a document, a CDC event, ' +
              'an agent action &mdash; it appears here with its source, entities, and provenance. ' +
              'Start on <b>Add memory</b>.</div>' +
            '<div class="et-actions"><button class="primary" id="mem-empty-add">Add memory</button></div>' +
          '</div>';
        el("mem-empty-add").onclick = function () { V.show("ingest"); };
      }
      el("mem-more").innerHTML = "";
      return;
    }

    var head = '<div class="tablewrap"><table><thead><tr>' +
      '<th>kind</th><th>memory</th><th>recorded</th><th>event time</th>' +
      '</tr></thead><tbody>';
    var body = ROWS.map(function (r, i) {
      var clickable = r.kind === "chunk" || r.kind === "fact";
      return '<tr class="mem-row" data-idx="' + i + '"' +
        (clickable
          ? ' style="cursor:pointer" title="click for the full ' + (r.kind === "fact" ? "value and its supersession chain" : "content and its version history") + '"'
          : ' title="actions are append-only events — the row is the whole record"') + '>' +
        '<td>' + V.kindBadge(KIND_LABEL[r.kind] || r.kind) + '</td>' +
        '<td>' + primaryHtml(r) + secondaryHtml(r) + '</td>' +
        '<td style="white-space:nowrap" title="' + V.esc(V.fmtTime(r.recorded_at)) + '">' + V.esc(V.timeAgo(r.recorded_at)) + '</td>' +
        '<td style="white-space:nowrap" title="' + V.esc(V.fmtTime(r.valid_from)) + '">' + V.esc(V.timeAgo(r.valid_from)) + '</td>' +
      '</tr>';
    }).join("");
    el("mem-out").innerHTML = head + body + '</tbody></table></div>';

    el("mem-more").innerHTML = NEXT
      ? '<button id="mem-loadmore" title="keyset pagination by recorded time — fetches the next-older page under the same filters">Load older rows</button>'
      : (ROWS.length >= PAGE_LIMIT ? '<span class="asof">end of this view — every matching row is loaded</span>' : "");
  }

  /* ------------------------------------------------------------ drawer */

  async function openDrawer(row) {
    // Human phrase first; the raw document/entity id is a dimmed ref line
    // under the title, never the title itself.
    if (row.kind === "fact") {
      el("mem-drawer-title").innerHTML = "Fact — " + V.esc(row.field || "") +
        '<span class="ref" style="display:block;font-weight:400">on entity ' +
        V.esc(row.entity_id || "") + "</span>";
    } else {
      el("mem-drawer-title").innerHTML = "Search snippet from " + V.esc(row.source) +
        '<span class="ref" style="display:block;font-weight:400">document ' +
        V.esc(row.document_id || row.id) + "</span>";
    }
    el("mem-drawer-body").innerHTML = '<div class="asof">loading the full record&hellip;</div>';
    V.dialog("mem-drawer").open();

    // Detail = the id lookup (full untruncated content, superseded included).
    // History = the same list read with the row's identity pinned; the chain
    // is assembled client-side from rows the endpoint already returns.
    var base = "/v1/admin/memories?tenant_id=" + encodeURIComponent(tenantNow);
    var detailP = V.api(base + "&id=" + encodeURIComponent(row.id), { admin: true });
    var histP;
    if (row.kind === "fact") {
      histP = V.api(base + "&kind=fact&include_superseded=true&limit=" + HISTORY_WINDOW +
        "&source=" + encodeURIComponent(row.source) +
        "&entity=" + encodeURIComponent(row.source + ":" + (row.entity_id || "")), { admin: true });
    } else {
      histP = V.api(base + "&kind=chunk&include_superseded=true&limit=" + HISTORY_WINDOW +
        "&source=" + encodeURIComponent(row.source), { admin: true });
    }
    try {
      var results = await Promise.all([detailP, histP.catch(function () { return null; })]);
      var full = results[0] && results[0].rows && results[0].rows[0];
      if (!full) throw new Error("the row was not found on re-read — refresh the list");
      var hist = results[1];
      var chain = [];
      var histCapped = !!(hist && hist.next_before);
      if (hist && hist.rows) {
        chain = hist.rows.filter(function (h) {
          return row.kind === "fact"
            ? h.entity_id === row.entity_id && h.field === row.field
            : h.document_id === row.document_id && h.seq === row.seq;
        });
        chain.sort(function (a, b) { return new Date(a.valid_from) - new Date(b.valid_from); });
      }
      el("mem-drawer-body").innerHTML = drawerBody(full, chain, histCapped, !hist);
    } catch (e) {
      el("mem-drawer-body").innerHTML = '<div class="err on">' + V.esc(String(e.message || e)) + '</div>';
    }
  }

  function chainHtml(full, chain, capped, histFailed) {
    if (histFailed) {
      return '<div class="note">couldn&rsquo;t load this row&rsquo;s history window — the record above is still the full current read.</div>';
    }
    if (chain.length <= 1) {
      return '<div class="note">no supersession chain — this is the only recorded version' +
        (full.valid_to ? " (already replaced; its successor did not land in the history window)" : "") + '.</div>';
    }
    var steps = chain.map(function (h) {
      var current = !h.valid_to;
      return '<div style="margin:4px 0;padding:6px 10px;border-left:3px solid ' +
          (current ? "var(--green)" : "var(--border)") + '">' +
        (current ? '<b>current</b> · ' : '') +
        (h.id === full.id ? '<span class="badge b-kind">this row</span> ' : '') +
        V.esc(h.preview) + (h.preview_truncated ? "&hellip;" : "") +
        '<div class="ref">valid ' + V.esc(V.fmtTime(h.valid_from)) + ' &rarr; ' +
          (h.valid_to ? V.esc(V.fmtTime(h.valid_to)) : "now") +
          ' · from conversation/event ' + V.esc(h.provenance) + ' (episode)</div>' +
      '</div>';
    }).join('<div style="color:var(--faint);padding-left:14px">&darr; replaced by</div>');
    return steps +
      '<div class="note">old rows are stamped with the time they stopped being true and a link to the row that replaced them' +
      '<span class="api-crumb"> · <code>valid_to</code>' +
      (full.kind === "fact" ? ' + <code>superseded_by</code>' : '') + '</span>' +
      ' — invalidated, never deleted (hard purge only ever happens through the lineage-driven erasure pipeline).' +
      (capped ? ' History window shows the newest ' + HISTORY_WINDOW + ' rows of this source; older versions exist beyond it.' : '') +
      '</div>';
  }

  function drawerBody(full, chain, capped, histFailed) {
    visGlossShown = false; // the drawer stands alone — gloss again
    var kindLine = KIND_LABEL[full.kind] || full.kind;
    return '<div class="card" style="margin:6px 0">' +
        '<h2>Full ' + (full.kind === "fact" ? "value" : "content") +
          ' <span class="sub">' + V.esc(kindLine) + ' · read-only</span></h2>' +
        '<div style="white-space:pre-wrap;word-break:break-word;margin:6px 0;font-size:var(--fs-base)">' +
          V.esc(full.preview) + '</div>' +
        (full.valid_to
          ? '<div class="note"><em>replaced value</em> — superseded ' + V.esc(V.fmtTime(full.valid_to)) +
            (full.superseded_by ? ' by row ' + V.refSpan(full.superseded_by) : '') + '; kept as history, never deleted.</div>'
          : '') +

        '<h2 style="margin-top:14px">On the record</h2>' +
        '<dl class="kv">' +
          '<dt>kind</dt><dd>' + V.esc(kindLine) + '</dd>' +
          '<dt>source</dt><dd>' + V.esc(full.source) + '</dd>' +
          (full.kind === "fact"
            ? '<dt>entity · field</dt><dd>' + V.esc((full.entity_id || "") + " · " + (full.field || "")) + '</dd>'
            : '<dt>document · seq</dt><dd>' + V.esc((full.document_id || "—") + " · " + (full.seq == null ? "—" : full.seq)) + '</dd>') +
          '<dt>entities</dt><dd>' + ((full.entities || []).length ? V.entityBadges(full.entities) : '<span class="refreshed">none recorded</span>') + '</dd>' +
          '<dt>who can see it</dt><dd>' + V.esc(visiblePhrase(full)) +
            ' <span class="refreshed">— counted, never listed; retrievability is decided per-scope at read time</span></dd>' +
          '<dt>confidentiality</dt><dd>' + (full.confidentiality != null ? V.confBadge(full.confidentiality) : '<span class="refreshed">no per-row confidentiality class &mdash; facts inherit the space&rsquo;s gate (L1)</span>') + '</dd>' +
          '<dt>ACL provenance</dt><dd>' + (full.acl_provenance ? V.provenanceBadge(full.acl_provenance) : '<span class="refreshed">not recorded on this kind</span>') + '</dd>' +
          '<dt>trust</dt><dd>' + (full.trust_tier != null ? V.trustBadge(trustName(full.trust_tier)) : '<span class="refreshed">not recorded on this kind</span>') + '</dd>' +
          '<dt>valid</dt><dd>' + V.esc(V.fmtTime(full.valid_from)) + ' &rarr; ' + (full.valid_to ? V.esc(V.fmtTime(full.valid_to)) : '<span class="live">now</span>') + '</dd>' +
          '<dt>recorded</dt><dd>' + V.esc(V.fmtTime(full.recorded_at)) + '</dd>' +
          '<dt>citation — the original conversation/event it came from (episode)</dt><dd>' + V.refSpan(full.provenance) +
            ' <span class="refreshed">the immutable evidence-log entry this row derives from</span></dd>' +
          '<dt>row id</dt><dd>' + V.refSpan(full.id) + '</dd>' +
        '</dl>' +

        '<h2 style="margin-top:14px">Supersession chain</h2>' +
        chainHtml(full, chain, capped, histFailed) +

        '<div class="note" style="margin-top:10px"><em>Honest note.</em> You are reading the admin plane: ' +
          'this drawer shows the row because you hold the admin token, not because any scope allows it. ' +
          'Whether an agent can retrieve it is decided per-scope at read time — this browser bypasses ' +
          'no enforcement for agents; it IS the admin plane.</div>' +
      '</div>';
  }
})();
