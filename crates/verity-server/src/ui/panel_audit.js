"use strict";
/* ==========================================================================
   panel_audit.js — Screen 2 · Access Audit  (TA.2, builder B)
   --------------------------------------------------------------------------
   Backing: GET /v1/admin/audit?tenant_id=&limit= (admin token). The endpoint
   returns, per row: id, tenant_id, actor_sub, actor_azp, verb, principals,
   entity_scope, confidentiality, query_summary, result_ids, at.

   HONESTY NOTES (read-path purity + honest-numbers non-negotiables):
   • The endpoint does NOT (yet) emit a purpose-policy version per row, nor a
     defense/blocked-injection flag, nor a leaked-item count. This panel NEVER
     fabricates those. It renders policy version only if a row actually carries
     one (policy_version / purpose_policy_version), else a dim "not recorded".
   • Adversarial probes are counted ONLY from a real per-row signal (a truthy
     `blocked`/`defense`/`injection_blocked` field, or a verb naming a blocked
     read). Absent that signal the summary strip says so honestly rather than
     inventing probes. `leaked` is likewise read from the row, never assumed.
   • Filters/search run client-side over the fetched window (the endpoint takes
     only tenant_id + limit); the window size is stated so the reviewer knows
     exactly what set the filters and the CSV/JSON export cover.
   • Auto-refresh is a pure re-GET on a ~5s timer; no LLM, no live-ReBAC.
   ========================================================================== */
(function () {
  var COMPLIANCE_VERBS = { forget: 1, erasure: 1, dsar_export: 1 };

  // ---- pure helpers over a raw audit row --------------------------------

  function actorStr(r) {
    return (r.actor_sub || "—") + " · " + (r.actor_azp || "—");
  }
  function resultCount(r) {
    return (r.result_ids || []).length;
  }
  function policyVersion(r) {
    // Only real, if present. Never invented.
    var v = r.policy_version;
    if (v == null) v = r.purpose_policy_version;
    if (v == null) v = r.policy_ver;
    return v == null || v === "" ? null : String(v);
  }
  function isBlocked(r) {
    return r.blocked === true || r.injection_blocked === true ||
           r.defense === true || String(r.verb || "").indexOf("blocked") >= 0;
  }
  function leakedCount(r) {
    // Honest: only if the row carries it. A blocked probe with no field is 0.
    if (typeof r.leaked === "number") return r.leaked;
    if (typeof r.leaked_items === "number") return r.leaked_items;
    return 0;
  }
  function confName(v) {
    var n = Verity.CONF_NAMES;
    return typeof v === "number" && n[v] ? n[v] : String(v);
  }

  // ---- CSV / JSON (SIEM-shaped) export ----------------------------------

  var CSV_COLS = [
    "at", "verb", "actor_sub", "actor_azp", "principals", "entity_scope",
    "confidentiality", "policy_version", "blocked", "leaked",
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
      actor_sub: r.actor_sub || "",
      actor_azp: r.actor_azp || "",
      principals: (r.principals || []).join("|"),
      entity_scope: (r.entity_scope || []).join("|"),
      confidentiality: confName(r.confidentiality),
      policy_version: policyVersion(r) || "",
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
  function toSiemJson(rows, meta) {
    // SIEM-shaped: a flat event array under a small envelope naming the source,
    // tenant, window, and export time so a downstream pipeline can attribute it.
    return JSON.stringify({
      source: "verity.access_audit",
      schema: "verity.audit.v1",
      tenant_id: meta.tenant,
      exported_at: new Date().toISOString(),
      build_hash: Verity.buildHash(),
      window_rows: rows.length,
      note: "Filtered window from GET /v1/admin/audit. Reading the audit is itself audited.",
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

  // ---- filtering (client-side over the fetched window) ------------------

  function passesFilters(r, f) {
    if (f.actor) {
      var a = (actorStr(r)).toLowerCase();
      if (a.indexOf(f.actor) < 0) return false;
    }
    if (f.verb && String(r.verb || "").toLowerCase() !== f.verb) return false;
    if (f.entity) {
      var es = (r.entity_scope || []).join(" ").toLowerCase();
      if (es.indexOf(f.entity) < 0) return false;
    }
    if (f.conf !== "" && String(r.confidentiality) !== f.conf) return false;
    if (f.policy) {
      var pv = (policyVersion(r) || "").toLowerCase();
      if (pv.indexOf(f.policy) < 0) return false;
    }
    if (f.from && new Date(r.at).getTime() < f.from) return false;
    if (f.to && new Date(r.at).getTime() > f.to) return false;
    if (f.q) {
      var hay = ((r.query_summary || "") + " " + (r.verb || "") + " " + actorStr(r)).toLowerCase();
      if (hay.indexOf(f.q) < 0) return false;
    }
    return true;
  }
  function tsOrNull(v) {
    if (!v) return null;
    var t = new Date(v).getTime();
    return isNaN(t) ? null : t;
  }

  Verity.register({
    id: "audit",
    mount: function (section) {
      var el = Verity.$("audit-mount");
      if (!el) return;

      var LAST = [];          // last fetched raw window (newest first)
      var timer = null;       // auto-refresh handle

      // per-panel read-only ribbon (v0.1 disclosure)
      var tpl = Verity.$("ribbon-tpl");
      if (tpl && tpl.content) {
        var r = tpl.content.cloneNode(true);
        var act = r.querySelector(".ribbon-action");
        if (act) act.textContent = "drill-into-row / jump-to-inspector";
        el.appendChild(r);
      }

      var card = document.createElement("div");
      card.className = "card";
      card.innerHTML =
        '<h2>Access Audit <span class="sub">GET /v1/admin/audit &middot; newest first &middot; admin token</span></h2>' +

        '<div class="note"><em>Audit of audit.</em> Reading this panel is itself an audited read and ' +
        'requires the audit-reader role (SPEC §7e). Every row below is a <b>scoped read on the ' +
        'record</b> — recall, get-by-id, adjacency, brief, subscription delivery, signed-media ' +
        'redemption — plus compliance verbs (forget / erasure / dsar_export).</div>' +

        // controls
        '<div class="row" style="margin-top:10px">' +
          '<div class="tight"><input type="text" id="au-tenant" placeholder="tenant_id (uuid)" size="30"></div>' +
          '<div class="tight"><input type="number" id="au-limit" value="200" min="1" max="1000" style="width:90px" title="rows fetched (window)"></div>' +
          '<div class="tight"><button id="au-load" class="primary">Load</button></div>' +
          '<div class="tight"><label class="checkline"><input type="checkbox" id="au-auto"> auto-refresh (~5s)</label></div>' +
          '<div class="tight"><span class="refreshed" id="au-stamp"></span></div>' +
        '</div>' +

        // filter bar (client-side over the fetched window)
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><input type="text" id="f-actor" placeholder="actor (sub/azp)" size="16"></div>' +
          '<div class="tight"><select class="field" id="f-verb">' +
            '<option value="">verb: any</option>' +
            '<option value="recall">recall</option>' +
            '<option value="get">get</option>' +
            '<option value="activity">activity</option>' +
            '<option value="brief">brief</option>' +
            '<option value="forget">forget</option>' +
            '<option value="erasure">erasure</option>' +
            '<option value="dsar_export">dsar_export</option>' +
          '</select></div>' +
          '<div class="tight"><input type="text" id="f-entity" placeholder="entity" size="12"></div>' +
          '<div class="tight"><select class="field" id="f-conf">' +
            '<option value="">conf: any</option>' +
            '<option value="0">public</option>' +
            '<option value="1">internal</option>' +
            '<option value="2">confidential</option>' +
            '<option value="3">restricted</option>' +
          '</select></div>' +
          '<div class="tight"><input type="text" id="f-policy" placeholder="policy ver" size="10"></div>' +
          '<div class="tight"><input type="text" id="f-q" placeholder="search query summary" size="20"></div>' +
        '</div>' +
        '<div class="row" style="margin-top:6px">' +
          '<div class="tight"><label class="checkline">from&nbsp;<input type="text" id="f-from" placeholder="YYYY-MM-DD HH:MM" size="17"></label></div>' +
          '<div class="tight"><label class="checkline">to&nbsp;<input type="text" id="f-to" placeholder="YYYY-MM-DD HH:MM" size="17"></label></div>' +
          '<div class="tight"><button id="f-clear">Clear filters</button></div>' +
          '<div class="tight"><button id="au-csv">Export CSV</button></div>' +
          '<div class="tight"><button id="au-json">Export JSON (SIEM)</button></div>' +
        '</div>' +

        '<div class="err" id="au-err"></div>' +
        '<div id="au-summary"></div>' +
        '<div id="au-out"></div>';
      el.appendChild(card);

      // prefill tenant from shared state / decoded handle
      var tenantInput = Verity.$("au-tenant");
      if (Verity.tenant()) tenantInput.value = Verity.tenant();
      Verity.onTenant(function (t) {
        if (t && !tenantInput.value) tenantInput.value = t;
      });

      // ---- rendering -----------------------------------------------------

      function currentFilters() {
        return {
          actor: Verity.$("f-actor").value.trim().toLowerCase(),
          verb: Verity.$("f-verb").value,
          entity: Verity.$("f-entity").value.trim().toLowerCase(),
          conf: Verity.$("f-conf").value,
          policy: Verity.$("f-policy").value.trim().toLowerCase(),
          q: Verity.$("f-q").value.trim().toLowerCase(),
          from: tsOrNull(Verity.$("f-from").value.trim()),
          to: tsOrNull(Verity.$("f-to").value.trim()),
        };
      }

      function filtered() {
        var f = currentFilters();
        return LAST.filter(function (r) { return passesFilters(r, f); });
      }

      function renderSummary(rows) {
        var probes = 0, leaked = 0, hasSignal = false;
        rows.forEach(function (r) {
          if (isBlocked(r)) { probes++; leaked += leakedCount(r); }
          if (r.blocked !== undefined || r.injection_blocked !== undefined ||
              r.defense !== undefined || r.leaked !== undefined) hasSignal = true;
        });
        var compliance = rows.filter(function (r) {
          return COMPLIANCE_VERBS[r.verb];
        }).length;

        var strip = '<div class="note" style="margin-top:12px">' +
          '<b>' + Verity.esc(rows.length) + '</b> row(s) in the filtered window' +
          ' &middot; <b>' + Verity.esc(compliance) + '</b> compliance event(s) ' +
          '(forget / erasure / dsar_export)';

        if (hasSignal || probes > 0) {
          strip += ' &middot; ' + Verity.badge(probes + " adversarial probe(s)", "b-defense") +
            ' &middot; <b>' + Verity.esc(leaked) + ' leaked item(s)</b>';
          if (leaked === 0) {
            strip += ' <span class="refreshed">— fail-closed held</span>';
          }
        } else {
          strip += ' &middot; <em>no defense signal in this window</em> ' +
            '<span class="refreshed">(the audit endpoint does not yet emit a blocked-injection ' +
            'flag; probes are not inferred — honest gap, not a fabricated zero)</span>';
        }
        strip += '</div>';
        Verity.$("au-summary").innerHTML = strip;
      }

      function verbCell(r) {
        if (isBlocked(r)) {
          return Verity.kindBadge(r.verb) + " " + Verity.badge("blocked probe", "b-defense");
        }
        return Verity.kindBadge(r.verb);
      }

      function policyCell(r) {
        var v = policyVersion(r);
        return v == null
          ? '<span class="refreshed" title="the audit row carries no purpose-policy version">not recorded</span>'
          : Verity.esc(v);
      }

      function renderTable(rows) {
        if (!rows.length) {
          Verity.$("au-out").innerHTML =
            '<div class="empty">no audit rows match — empty is a valid, on-the-record answer ' +
            '(fail closed). Widen the window or clear filters.</div>';
          return;
        }
        var head = '<div class="tablewrap"><table><thead><tr>' +
          '<th>at</th><th>verb</th><th>actor (sub · azp)</th><th>principals</th>' +
          '<th>entity scope</th><th>conf</th><th>policy ver</th><th>query summary</th>' +
          '<th class="num">results</th></tr></thead><tbody>';
        var body = rows.map(function (r) {
          var flag = (COMPLIANCE_VERBS[r.verb] || isBlocked(r)) ? ' class="flag"' : "";
          var principals = (r.principals || []).length
            ? (r.principals || []).map(function (t) { return "#" + Verity.esc(t); }).join(" ")
            : '<span class="refreshed">∅</span>';
          var ents = (r.entity_scope || []).length
            ? Verity.entityBadges(r.entity_scope)
            : '<span class="refreshed">—</span>';
          return '<tr' + flag + '>' +
            '<td>' + Verity.esc(Verity.fmtTime(r.at)) + '</td>' +
            '<td>' + verbCell(r) + '</td>' +
            '<td>' + Verity.esc(actorStr(r)) + '</td>' +
            '<td>' + principals + '</td>' +
            '<td>' + ents + '</td>' +
            '<td>' + Verity.confBadge(r.confidentiality) + '</td>' +
            '<td>' + policyCell(r) + '</td>' +
            '<td>' + Verity.esc(r.query_summary || "—") + '</td>' +
            '<td class="num">' + resultCount(r) + '</td>' +
          '</tr>';
        }).join("");
        Verity.$("au-out").innerHTML = head + body + '</tbody></table></div>';
      }

      function rerender() {
        var rows = filtered();
        renderSummary(rows);
        renderTable(rows);
      }

      // ---- load ----------------------------------------------------------

      async function load() {
        Verity.clearErr("au-err");
        var tenant = tenantInput.value.trim();
        if (!tenant) { Verity.err("au-err", new Error("enter a tenant_id to load its audit tail")); return; }
        Verity.setTenant(tenant);
        var limit = Math.max(1, Math.min(1000, parseInt(Verity.$("au-limit").value, 10) || 200));
        try {
          var rows = await Verity.api(
            "/v1/admin/audit?tenant_id=" + encodeURIComponent(tenant) + "&limit=" + limit,
            { admin: true });
          LAST = Array.isArray(rows) ? rows : [];
          Verity.$("au-stamp").textContent =
            "refreshed " + Verity.fmtTime(Date.now()) + " · window " + LAST.length + " row(s)";
          rerender();
        } catch (e) {
          Verity.err("au-err", e);
          if (timer) { clearInterval(timer); timer = null; Verity.$("au-auto").checked = false; }
        }
      }

      // ---- wiring --------------------------------------------------------

      Verity.$("au-load").onclick = load;
      ["f-actor", "f-entity", "f-policy", "f-q", "f-from", "f-to"].forEach(function (id) {
        Verity.$(id).addEventListener("input", rerender);
      });
      ["f-verb", "f-conf"].forEach(function (id) {
        Verity.$(id).addEventListener("change", rerender);
      });
      Verity.$("f-clear").onclick = function () {
        ["f-actor", "f-entity", "f-policy", "f-q", "f-from", "f-to"].forEach(function (id) {
          Verity.$(id).value = "";
        });
        Verity.$("f-verb").value = "";
        Verity.$("f-conf").value = "";
        rerender();
      };

      Verity.$("au-csv").onclick = function () {
        var rows = filtered();
        if (!rows.length) { Verity.err("au-err", new Error("nothing in the filtered window to export")); return; }
        Verity.clearErr("au-err");
        download("verity-audit-" + Date.now() + ".csv", "text/csv;charset=utf-8", toCsv(rows));
      };
      Verity.$("au-json").onclick = function () {
        var rows = filtered();
        if (!rows.length) { Verity.err("au-err", new Error("nothing in the filtered window to export")); return; }
        Verity.clearErr("au-err");
        download("verity-audit-" + Date.now() + ".json", "application/json",
          toSiemJson(rows, { tenant: tenantInput.value.trim() }));
      };

      Verity.$("au-auto").onchange = function (e) {
        if (e.target.checked) {
          load();
          timer = setInterval(load, 5000);
        } else if (timer) {
          clearInterval(timer); timer = null;
        }
      };
    },
  });
})();
