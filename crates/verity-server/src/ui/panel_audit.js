"use strict";
/* ==========================================================================
   panel_audit.js — Access audit  [v2 rebuild — frozen design contract]
   --------------------------------------------------------------------------
   Reads:
     • GET /v1/admin/audit?tenant_id=&limit= (admin) — per row: id, tenant_id,
       actor_sub, actor_azp, verb, principals (i32 tokens), entity_scope,
       confidentiality (0-3), query_summary, result_ids, at. Newest first.
     • GET /v1/admin/principals?tenant_id=&after_token=&limit= (admin, N5) —
       the token ↔ string directory, used ONLY to NAME the tokens an audit
       row carries. Fetch failure degrades honestly to raw #tokens.

   THE LAW, applied:
     • every row is a plain sentence a first-timer parses in ten seconds
       ("support-bot searched memory · 3 results · about account:acme ·
       internal ceiling"); raw verbs/uuids live in mono secondary text only;
     • autoloads when the tenant is known — no cold Load button;
     • filters are progressive: a simple bar (search + action), advanced
       (actor / entity / ceiling / time / window) collapsed behind a toggle;
     • the blocked-injection summary is prominent AND honest: probes are
       counted ONLY from a real per-row signal; absent that signal the strip
       says so — an honest gap, never a fabricated zero;
     • fail-closed emptiness is stated as a correct answer, with a forensic
       CTA (Scope Inspector / Quarantine), never a fill-it button;
     • drill-down renders only what the row carries ("not recorded on this
       row", never guessed); the jump to Scope Inspector stays an honest
       seam — no handle is fabricated.
   READ-PATH PURITY: pure re-GETs; filters/exports are local transforms.
   ========================================================================== */
(function () {
  var V = window.Verity;

  var COMPLIANCE_VERBS = { forget: 1, erasure: 1, dsar_export: 1 };

  /* ------------------------------------------------------------ plain words */

  // verb → what a first-time operator reads. The raw verb stays available in
  // mono meta text; it is never the primary label.
  var VERB_PLAIN = {
    recall: "searched memory",
    get: "looked up one record",
    merged_entity: "viewed a merged entity",
    activity: "viewed an activity timeline",
    brief: "read an entity brief",
    forget: "asked Verity to forget something (reversible)",
    erasure: "ran a permanent erasure",
    dsar_export: "exported a person's data (DSAR)",
    media_sign: "signed a media download link",
    debug_recall: "ran a why-trace (debug recall)",
    fold_link: "linked two records after matching",
    quarantine_reingest: "re-ingested a quarantined payload with corrected permissions",
    quarantine_dismiss: "dismissed a quarantined payload (nothing indexed)",
  };
  function verbPlain(v) { return VERB_PLAIN[v] || String(v || "unknown action"); }

  // Who acted, name first, rendered as escaped HTML (callers must not
  // re-escape). fold_link rows are worker-plane (no actor); quarantine
  // dispositions carry azp='admin'. An azp alone is an APP's key, not a
  // person — it never sits unmarked in the person slot.
  function actorHtml(r, bold) {
    var b0 = bold ? "<b>" : "", b1 = bold ? "</b>" : "";
    if (r.actor_sub) return b0 + V.esc(r.actor_sub) + b1;
    if (r.verb === "fold_link") return b0 + "Verity’s matching worker" + b1;
    if (r.actor_azp === "admin") return b0 + "an admin" + b1;
    if (r.actor_azp) {
      return b0 + V.esc(r.actor_azp) + b1 +
        ' <span class="refreshed">(app — no person recorded)</span>';
    }
    return b0 + "actor not recorded" + b1;
  }
  function actorSecondary(r) {
    var bits = [];
    if (r.actor_sub && r.actor_azp) bits.push("via " + r.actor_azp);
    return bits.join(" ");
  }
  function confName(v) {
    var n = V.CONF_NAMES;
    return typeof v === "number" && n[v] ? n[v] : String(v);
  }
  function resultCount(r) { return (r.result_ids || []).length; }
  function resultPhrase(r) {
    var n = resultCount(r);
    if (COMPLIANCE_VERBS[r.verb] || r.verb === "fold_link") {
      return n + " item" + (n === 1 ? "" : "s") + " on the record";
    }
    return n + " result" + (n === 1 ? "" : "s");
  }
  function aboutPhrase(r) {
    var es = r.entity_scope || [];
    if (!es.length) return "";
    var shown = es.slice(0, 2).join(", ");
    var more = es.length > 2 ? " +" + (es.length - 2) + " more" : "";
    return "about " + shown + more;
  }

  // Honest defense signals: counted ONLY off a real per-row field or a verb
  // that names a blocked read. Never inferred, never fabricated.
  function isBlocked(r) {
    return r.blocked === true || r.injection_blocked === true ||
           r.defense === true || String(r.verb || "").indexOf("blocked") >= 0;
  }
  function hasDefenseSignal(r) {
    return r.blocked !== undefined || r.injection_blocked !== undefined ||
           r.defense !== undefined || r.leaked !== undefined;
  }
  function leakedCount(r) {
    if (typeof r.leaked === "number") return r.leaked;
    if (typeof r.leaked_items === "number") return r.leaked_items;
    return 0;
  }

  /* ------------------------------------------------------------ state */

  var LAST = [];        // fetched window, newest first (server order kept)
  var PRINC = null;     // token → principal string (null = directory unavailable)
  var SHOWN = [];       // rows currently painted (for drill lookup)
  var OPEN = -1;        // index of the expanded row
  var tenantNow = "";
  var timer = null;     // auto-refresh handle
  var TABLE_COLS = 5;

  function el(id) { return V.$(id); }

  // Name a principal token from the directory; degrade honestly.
  function principalHtml(t) {
    var name = PRINC && PRINC[t];
    if (name) return '<b>' + V.esc(name) + '</b> ' + V.refSpan("#" + t);
    return V.refSpan("#" + t) +
      (PRINC ? ' <span class="refreshed">not in this tenant’s directory</span>'
             : ' <span class="refreshed">directory unavailable</span>');
  }

  /* ------------------------------------------------------------ export */

  var CSV_COLS = [
    "at", "verb", "action_plain", "actor_sub", "actor_azp", "principals",
    "principals_named", "entity_scope", "confidentiality", "blocked", "leaked",
    "query_summary", "result_count",
  ];
  function csvCell(s) {
    s = s == null ? "" : String(s);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }
  function rowToFlat(r) {
    return {
      at: r.at,
      verb: r.verb,
      action_plain: verbPlain(r.verb),
      actor_sub: r.actor_sub || "",
      actor_azp: r.actor_azp || "",
      principals: (r.principals || []).join("|"),
      // Named ONLY from the real directory read; unknown tokens stay numeric.
      principals_named: (r.principals || [])
        .map(function (t) { return (PRINC && PRINC[t]) || ("#" + t); }).join("|"),
      entity_scope: (r.entity_scope || []).join("|"),
      confidentiality: confName(r.confidentiality),
      blocked: isBlocked(r),
      leaked: leakedCount(r),
      query_summary: r.query_summary || "",
      result_count: resultCount(r),
    };
  }
  function toCsv(rows) {
    var lines = [CSV_COLS.join(",")];
    rows.forEach(function (r) {
      var f = rowToFlat(r);
      lines.push(CSV_COLS.map(function (c) { return csvCell(f[c]); }).join(","));
    });
    return lines.join("\r\n");
  }
  function toSiemJson(rows) {
    return JSON.stringify({
      source: "verity.access_audit",
      schema: "verity.audit.v1",
      tenant_id: tenantNow,
      exported_at: new Date().toISOString(),
      build_hash: V.buildHash(),
      window_rows: rows.length,
      note: "Filtered window from GET /v1/admin/audit. Reading the audit is itself audited. " +
            "principals_named comes from GET /v1/admin/principals at export time.",
      events: rows.map(rowToFlat),
    }, null, 2);
  }
  function download(name, mime, text) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  /* ------------------------------------------------------------ filtering */

  function tsOrNull(v) {
    if (!v) return null;
    var t = new Date(v).getTime();
    return isNaN(t) ? null : t;
  }
  function currentFilters() {
    return {
      q: el("au-f-q").value.trim().toLowerCase(),
      verb: el("au-f-verb").value,
      compliance: el("au-f-comp").checked,
      actor: el("au-f-actor").value.trim().toLowerCase(),
      entity: el("au-f-entity").value.trim().toLowerCase(),
      conf: el("au-f-conf").value,
      from: tsOrNull(el("au-f-from").value.trim()),
      to: tsOrNull(el("au-f-to").value.trim()),
    };
  }
  function passesFilters(r, f) {
    if (f.verb && String(r.verb || "") !== f.verb) return false;
    if (f.compliance && !COMPLIANCE_VERBS[r.verb]) return false;
    if (f.actor) {
      var a = ((r.actor_sub || "") + " " + (r.actor_azp || "")).toLowerCase();
      if (a.indexOf(f.actor) < 0) return false;
    }
    if (f.entity) {
      var es = (r.entity_scope || []).join(" ").toLowerCase();
      if (es.indexOf(f.entity) < 0) return false;
    }
    if (f.conf !== "" && String(r.confidentiality) !== f.conf) return false;
    if (f.from && new Date(r.at).getTime() < f.from) return false;
    if (f.to && new Date(r.at).getTime() > f.to) return false;
    if (f.q) {
      var hay = ((r.query_summary || "") + " " + (r.verb || "") + " " + verbPlain(r.verb) +
        " " + (r.actor_sub || "") + " " + (r.actor_azp || "") + " " +
        (r.entity_scope || []).join(" ")).toLowerCase();
      if (hay.indexOf(f.q) < 0) return false;
    }
    return true;
  }
  function filtered() {
    var f = currentFilters();
    return LAST.filter(function (r) { return passesFilters(r, f); });
  }
  function anyFilterOn() {
    var f = currentFilters();
    return !!(f.q || f.verb || f.compliance || f.actor || f.entity ||
              f.conf !== "" || f.from || f.to);
  }

  /* =========================================================== register */

  V.register({
    id: "audit",

    mount: function () {
      var host = el("audit-mount");
      if (!host) return;
      host.innerHTML =
        /* ---- toolbar: state + as-of + refresh/export ---- */
        '<div class="toolbar">' +
          '<span id="au-state">' + V.stateChip("off", "waiting for a tenant") + '</span>' +
          '<span class="asof" id="au-asof"></span>' +
          '<span class="spacer"></span>' +
          '<label class="checkline" title="plain re-read of GET /v1/admin/audit every 5 s — nothing touches the read path">' +
            '<input type="checkbox" id="au-auto"> auto-refresh (5s)</label>' +
          '<button id="au-csv" title="CSV of the filtered window">Export CSV</button>' +
          '<button id="au-json" title="SIEM-shaped JSON of the filtered window">Export JSON</button>' +
          '<button id="au-refresh">Refresh</button>' +
        '</div>' +

        /* ---- simple filter bar (progressive; advanced collapsed) ---- */
        '<div class="row" id="au-simple">' +
          '<div><label for="au-f-q">search this window</label>' +
            '<input type="text" id="au-f-q" placeholder="actor, entity, query text…" autocomplete="off"></div>' +
          '<div class="tight" style="min-width:230px"><label for="au-f-verb">action</label>' +
            '<select class="field" id="au-f-verb">' +
              '<option value="">any action</option>' +
              '<option value="recall">searched memory (recall)</option>' +
              '<option value="get">looked up one record (get)</option>' +
              '<option value="merged_entity">viewed a merged entity</option>' +
              '<option value="brief">read an entity brief</option>' +
              '<option value="activity">viewed activity</option>' +
              '<option value="debug_recall">ran a why-trace</option>' +
              '<option value="media_sign">signed a media link</option>' +
              '<option value="fold_link">matching linked records</option>' +
              '<option value="forget">forget (reversible)</option>' +
              '<option value="erasure">permanent erasure</option>' +
              '<option value="dsar_export">DSAR export</option>' +
              '<option value="quarantine_reingest">quarantine re-ingest</option>' +
              '<option value="quarantine_dismiss">quarantine dismiss</option>' +
            '</select></div>' +
          '<div class="tight"><label class="checkline" style="margin-bottom:7px" title="forget / erasure / dsar_export">' +
            '<input type="checkbox" id="au-f-comp"> compliance events only</label></div>' +
          '<div class="tight"><button id="au-adv-toggle">More filters</button></div>' +
          '<div class="tight"><button id="au-f-clear">Clear</button></div>' +
        '</div>' +

        /* ---- advanced filters (collapsed by default) ---- */
        '<div class="row" id="au-advanced" style="display:none;margin-top:8px">' +
          '<div class="tight"><label for="au-f-actor">actor contains</label>' +
            '<input type="text" id="au-f-actor" size="16" autocomplete="off"></div>' +
          '<div class="tight"><label for="au-f-entity">entity contains</label>' +
            '<input type="text" id="au-f-entity" size="14" autocomplete="off"></div>' +
          '<div class="tight" style="min-width:150px"><label for="au-f-conf">ceiling</label>' +
            '<select class="field" id="au-f-conf">' +
              '<option value="">any ceiling</option>' +
              '<option value="0">public</option><option value="1">internal</option>' +
              '<option value="2">confidential</option><option value="3">restricted</option>' +
            '</select></div>' +
          '<div class="tight"><label for="au-f-from">from</label>' +
            '<input type="text" id="au-f-from" placeholder="YYYY-MM-DD HH:MM" size="17"></div>' +
          '<div class="tight"><label for="au-f-to">to</label>' +
            '<input type="text" id="au-f-to" placeholder="YYYY-MM-DD HH:MM" size="17"></div>' +
          '<div class="tight"><label for="au-limit" title="rows fetched from the server (1-1000) — changing it refetches">load newest</label>' +
            '<input type="number" id="au-limit" value="200" min="1" max="1000" style="width:90px"> ' +
            '<span class="refreshed">rows</span></div>' +
        '</div>' +

        '<div class="err" id="au-err"></div>' +
        '<div id="au-summary"></div>' +
        '<div id="au-out"></div>';

      /* ---- wiring ---- */
      el("au-refresh").onclick = function () { V.reload("audit"); };
      el("au-adv-toggle").onclick = function () {
        var adv = el("au-advanced");
        var on = adv.style.display === "none";
        adv.style.display = on ? "" : "none";
        el("au-adv-toggle").textContent = on ? "Fewer filters" : "More filters";
      };
      ["au-f-q", "au-f-actor", "au-f-entity", "au-f-from", "au-f-to"].forEach(function (id) {
        el(id).addEventListener("input", rerender);
      });
      ["au-f-verb", "au-f-conf"].forEach(function (id) {
        el(id).addEventListener("change", rerender);
      });
      el("au-f-comp").addEventListener("change", rerender);
      el("au-f-clear").onclick = function () {
        ["au-f-q", "au-f-actor", "au-f-entity", "au-f-from", "au-f-to"].forEach(function (id) { el(id).value = ""; });
        el("au-f-verb").value = ""; el("au-f-conf").value = "";
        el("au-f-comp").checked = false;
        rerender();
      };
      el("au-limit").addEventListener("change", function () { V.reload("audit"); });
      el("au-csv").onclick = function () { exportRows("csv"); };
      el("au-json").onclick = function () { exportRows("json"); };
      el("au-auto").onchange = function (e) {
        if (timer) { clearInterval(timer); timer = null; }
        if (e.target.checked && tenantNow) {
          timer = setInterval(function () { refresh(tenantNow); }, 5000);
        }
      };
      // delegated row click → drill
      el("au-out").addEventListener("click", function (ev) {
        var t = ev.target;
        if (t && t.closest && t.closest("button")) return;   // buttons handle themselves
        if (t && t.closest && t.closest("tr.au-drill")) return;
        var row = t && t.closest ? t.closest("tr.au-row") : null;
        if (!row) return;
        var idx = parseInt(row.getAttribute("data-idx"), 10);
        if (!isNaN(idx)) toggleDrill(idx);
      });

      if (!V.tenant()) renderNoTenant();
    },

    // AUTOLOAD (LAW #3): the router runs this when the panel is shown and a
    // tenant is known; re-runs on tenant change; deduped per tenant.
    load: function (_s, tenant) {
      tenantNow = tenant;
      return refresh(tenant);
    },

    onShow: function () {
      var p = V.navParams();
      if (p && p.verb && el("au-f-verb")) { el("au-f-verb").value = p.verb; rerender(); }
    },
  });

  /* ------------------------------------------------------------ no tenant */

  function renderNoTenant() {
    el("au-out").innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a tenant to see its audit tail</div>' +
        '<div class="et-body">Paste a tenant id in the session bar above, or mint a scope handle ' +
          '&mdash; the audit loads by itself the moment a tenant is known. Every scoped read lands ' +
          'here as it happens; nothing is sampled or summarized away.</div>' +
        '<div class="et-actions"><button class="primary" id="au-mint">Mint a scope handle</button></div>' +
      '</div>';
    el("au-mint").onclick = function () { V.openMint(); };
  }

  /* ------------------------------------------------------------ load */

  // Walk the principal directory (keyset pages) into a token→name map.
  // Failure returns null — naming degrades to raw #tokens, disclosed inline.
  async function fetchPrincipals(tenant) {
    var map = {};
    var after = 0;
    for (var page = 0; page < 10; page++) {
      var res = await V.api(
        "/v1/admin/principals?tenant_id=" + encodeURIComponent(tenant) +
        "&after_token=" + after + "&limit=1000", { admin: true });
      ((res && res.principals) || []).forEach(function (p) { map[p.token] = p.principal; });
      if (!res || res.next_after_token == null) break;
      after = res.next_after_token;
    }
    return map;
  }

  async function refresh(tenant) {
    V.clearErr("au-err");
    el("au-state").innerHTML = V.stateChip("wait", "loading");
    var limit = Math.max(1, Math.min(1000, parseInt(el("au-limit").value, 10) || 200));
    try {
      var results = await Promise.all([
        V.api("/v1/admin/audit?tenant_id=" + encodeURIComponent(tenant) + "&limit=" + limit,
          { admin: true }),
        fetchPrincipals(tenant).catch(function () { return null; }),
      ]);
      LAST = Array.isArray(results[0]) ? results[0] : [];
      PRINC = results[1];
      el("au-state").innerHTML = LAST.length
        ? V.stateChip("ok", LAST.length + " read" + (LAST.length === 1 ? "" : "s") + " on the record")
        : V.stateChip("ok", "no reads yet");
      el("au-asof").textContent = "checked " + new Date().toTimeString().slice(0, 8) +
        " · showing the newest " + LAST.length + " row" + (LAST.length === 1 ? "" : "s");
      rerender();
    } catch (e) {
      el("au-state").innerHTML = V.stateChip("fail");
      if (/HTTP 401/.test(String(e.message))) {
        V.err("au-err", new Error(e.message +
          "\nThis read needs the admin token — set it in the session bar (it lives in this tab only)."));
      } else {
        V.err("au-err", e);
      }
      if (timer) { clearInterval(timer); timer = null; el("au-auto").checked = false; }
    }
  }

  /* ------------------------------------------------------------ summary */

  function renderSummary(rows) {
    if (!LAST.length) { el("au-summary").innerHTML = ""; return; }
    var probes = 0, leaked = 0, signal = false;
    rows.forEach(function (r) {
      if (hasDefenseSignal(r)) signal = true;
      if (isBlocked(r)) { probes++; leaked += leakedCount(r); }
    });
    var compliance = rows.filter(function (r) { return COMPLIANCE_VERBS[r.verb]; }).length;

    // Blocked-injection summary — prominent AND honest (never a made-up zero).
    var defense;
    if (signal || probes > 0) {
      defense = (leaked === 0
          ? V.stateChip("ok", probes + " blocked probe" + (probes === 1 ? "" : "s") + " · 0 leaked — fail-closed held")
          : V.stateChip("fail", leaked + " leaked item" + (leaked === 1 ? "" : "s") + " — investigate now"));
    } else {
      defense = V.stateChip("off", "blocked attacks: not counted yet") +
        ' <span class="refreshed">Verity doesn’t yet record whether a read was a blocked injection ' +
        'attempt, so this page can’t count them. When it does, a real count will appear here — ' +
        'until then we show nothing rather than a fake 0.</span>';
    }
    el("au-summary").innerHTML =
      '<div class="toolbar" style="margin:2px 0 10px">' +
        '<span class="asof"><b style="color:var(--text)">' + rows.length + '</b> of ' + LAST.length +
          ' loaded read' + (LAST.length === 1 ? "" : "s") + ' shown</span>' +
        (compliance
          ? '<span class="asof"><b style="color:var(--text)">' + compliance +
            '</b> compliance event' + (compliance === 1 ? "" : "s") +
            ' <span class="refreshed">(forget / erasure / DSAR)</span></span>'
          : "") +
        '<span class="spacer"></span>' + defense +
      '</div>';
  }

  /* ------------------------------------------------------------ table */

  function sentence(r) {
    var about = aboutPhrase(r);
    var html = actorHtml(r, true) + ' ' + V.esc(verbPlain(r.verb)) +
      ' · <b>' + V.esc(resultPhrase(r)) + '</b>' +
      (about ? ' · ' + V.esc(about) : '') +
      ' · ' + V.esc(confName(r.confidentiality)) + ' ceiling';
    var sec = actorSecondary(r);
    var meta = [];
    if (r.query_summary) meta.push('asked: “' + V.esc(r.query_summary) + '”');
    if (sec) meta.push(V.esc(sec));
    if (meta.length) html += '<div class="note" style="margin-top:2px">' + meta.join(' · ') + '</div>';
    return html;
  }

  function rowChips(r) {
    var chips = "";
    if (COMPLIANCE_VERBS[r.verb]) chips += V.badge("compliance", "b-quarantined");
    if (isBlocked(r)) chips += V.badge("blocked probe", "b-defense");
    return chips;
  }

  function renderTable(rows) {
    SHOWN = rows; OPEN = -1;
    if (!LAST.length) {
      el("au-out").innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">No reads on the record yet</div>' +
          '<div class="et-body">The moment any agent or person reads through a scope handle ' +
            '&mdash; a memory search, a record lookup, a brief &mdash; a row appears here. ' +
            'Try it: mint a handle and run a probe in the Scope Inspector; your own read will ' +
            'show up on refresh.</div>' +
          '<div class="et-actions">' +
            '<button class="primary" id="au-empty-mint">Mint a scope handle</button>' +
            '<button id="au-empty-scope">Open the Scope Inspector</button>' +
          '</div>' +
        '</div>';
      el("au-empty-mint").onclick = function () { V.openMint({ tenant: tenantNow }); };
      el("au-empty-scope").onclick = function () { V.show("scope"); };
      return;
    }
    if (!rows.length) {
      el("au-out").innerHTML =
        '<div class="note" style="margin-top:10px">0 of the ' + LAST.length +
        ' loaded reads match these filters — the rows still exist one filter away. ' +
        '<button id="au-empty-clear" style="margin-left:8px">Clear all filters</button></div>';
      el("au-empty-clear").onclick = function () { el("au-f-clear").click(); };
      return;
    }
    var head = '<div class="tablewrap"><table><thead><tr>' +
      '<th aria-label="expand"></th>' +
      '<th>when</th><th>what happened</th><th></th><th class="num">results</th>' +
      '</tr></thead><tbody>';
    var body = rows.map(function (r, i) {
      var flag = (COMPLIANCE_VERBS[r.verb] || isBlocked(r)) ? " flag" : "";
      return '<tr class="au-row' + flag + '" data-idx="' + i + '" style="cursor:pointer" ' +
          'title="click to see exactly what this read returned and what the reader was allowed to see">' +
        '<td class="au-caret" aria-hidden="true">&#9656;</td>' +
        '<td style="white-space:nowrap" title="' + V.esc(V.fmtTime(r.at)) + '">' + V.esc(V.timeAgo(r.at)) + '</td>' +
        '<td>' + sentence(r) + '</td>' +
        '<td>' + rowChips(r) + '</td>' +
        '<td class="num">' + resultCount(r) + '</td>' +
      '</tr>' +
      '<tr class="au-drill" data-drill="' + i + '" style="display:none">' +
        '<td colspan="' + TABLE_COLS + '"></td>' +
      '</tr>';
    }).join("");
    el("au-out").innerHTML = head + body + '</tbody></table></div>';
  }

  function rerender() {
    var rows = filtered();
    renderSummary(rows);
    renderTable(rows);
  }

  /* ------------------------------------------------------------ drill-down */

  function toggleDrill(i) {
    var drill = document.querySelector('#au-out tr.au-drill[data-drill="' + i + '"]');
    var mainRow = document.querySelector('#au-out tr.au-row[data-idx="' + i + '"]');
    if (!drill || !mainRow) return;
    var caret = mainRow.querySelector(".au-caret");
    if (drill.style.display !== "none") {
      drill.style.display = "none";
      if (caret) caret.innerHTML = "&#9656;";
      OPEN = -1;
      return;
    }
    if (OPEN >= 0 && OPEN !== i) {
      var prev = document.querySelector('#au-out tr.au-drill[data-drill="' + OPEN + '"]');
      var prevRow = document.querySelector('#au-out tr.au-row[data-idx="' + OPEN + '"]');
      if (prev) prev.style.display = "none";
      if (prevRow) { var pc = prevRow.querySelector(".au-caret"); if (pc) pc.innerHTML = "&#9656;"; }
    }
    var cell = drill.querySelector("td");
    if (cell && !cell.getAttribute("data-rendered")) {
      cell.innerHTML = drillBody(SHOWN[i]);
      cell.setAttribute("data-rendered", "1");
      var jump = cell.querySelector(".au-jump");
      if (jump) jump.onclick = function () {
        if (SHOWN[i] && SHOWN[i].tenant_id) V.setTenant(SHOWN[i].tenant_id);
        V.show("scope");
      };
      var quar = cell.querySelector(".au-quar");
      if (quar) quar.onclick = function () { V.show("quarantine"); };
    }
    drill.style.display = "";
    if (caret) caret.innerHTML = "&#9662;";
    OPEN = i;
  }

  function drillBody(r) {
    var ids = Array.isArray(r.result_ids) ? r.result_ids : [];

    var returned;
    if (ids.length) {
      returned = '<div style="display:flex;flex-wrap:wrap;gap:4px 10px">' +
        ids.map(function (id) { return V.refSpan(id); }).join("") + '</div>' +
        '<div class="note" style="margin-top:4px">Record/chunk ids exactly as the audit stored them, ' +
        'shown for the record only — this page never re-runs the read.</div>';
    } else {
      returned =
        '<div class="empty-teach sp-b" style="margin:4px 0">' +
          '<div class="et-title">0 results — and that can be correct</div>' +
          '<div class="et-body">Fail-closed emptiness is a correct answer, not a bug: this reader ' +
            'saw nothing because nothing matched what they were <b>allowed</b> to see. To see exactly ' +
            'which filter dropped what, run this query through the why-trace in the Scope Inspector. ' +
            'If the data may never have been indexed at all, check Quarantine.</div>' +
          '<div class="et-actions">' +
            '<button class="au-jump">Investigate in the Scope Inspector</button>' +
            '<button class="au-quar">Check Quarantine</button>' +
          '</div>' +
        '</div>';
    }

    var ps = r.principals || [];
    var who = ps.length
      ? ps.map(principalHtml).join('<br>')
      : '<span class="refreshed">nobody — the read carried no keys, and an empty key set sees nothing (fail closed)</span>';

    var ents = (r.entity_scope || []).length
      ? V.esc((r.entity_scope || []).join(", "))
      : '<span class="refreshed">no entity restriction recorded on this row</span>';

    return '<div class="card" style="margin:6px 0">' +
        '<h2>What this read returned <span class="sub">' + ids.length + ' id(s) · read-only record</span></h2>' +
        returned +

        '<h2 style="margin-top:14px">What the reader was allowed to see</h2>' +
        '<div class="note" style="margin:0 0 6px">Read straight off this audit row — fields the row ' +
          'does not carry are said so, never guessed. Names come from the tenant’s principal directory.</div>' +
        '<dl class="kv">' +
          '<dt>acting as</dt><dd>' + actorHtml(r, false) +
            // azp-only rows already show the app id via actorHtml — don't repeat it
            (r.actor_sub && r.actor_azp ? ' <span class="ref">azp: ' + V.esc(r.actor_azp) + '</span>' : '') + '</dd>' +
          '<dt>held these keys (visibility tokens)</dt><dd>' + who + '</dd>' +
          '<dt>limited to entities</dt><dd>' + ents + '</dd>' +
          '<dt>confidentiality ceiling</dt><dd>' + V.confBadge(r.confidentiality) + '</dd>' +
          '<dt>purpose limits</dt><dd><span class="refreshed">none recorded — this server doesn’t record a purpose on reads yet</span></dd>' +
          '<dt>action</dt><dd>' + V.esc(verbPlain(r.verb)) + ' <span class="ref">' + V.esc(r.verb) + '</span></dd>' +
          '<dt>audit row</dt><dd>' + V.refSpan(r.id || "") + '</dd>' +
        '</dl>' +

        (ids.length
          ? '<div class="actions" style="margin-top:12px;justify-content:flex-start">' +
              '<button class="au-jump" title="Switches panels and carries the tenant. An audit row stores no signed vs_… handle, so live probes there still need you to paste or mint one — nothing is fabricated to make this button look live.">' +
              'Compare in the Scope Inspector &rarr;</button></div>'
          : '') +
        '<div class="note" style="margin-top:6px"><em>Honest seam.</em> The jump carries only the tenant. ' +
          'The row has no signed handle to decode — paste or mint one there to run live probes.</div>' +
      '</div>';
  }

  /* ------------------------------------------------------------ export */

  function exportRows(kind) {
    var rows = filtered();
    if (!rows.length) {
      V.err("au-err", new Error("nothing in the filtered window to export" +
        (anyFilterOn() ? " — clear filters to export the whole window" : "")));
      return;
    }
    V.clearErr("au-err");
    if (kind === "csv") {
      download("verity-audit-" + Date.now() + ".csv", "text/csv;charset=utf-8", toCsv(rows));
    } else {
      download("verity-audit-" + Date.now() + ".json", "application/json", toSiemJson(rows));
    }
  }
})();
