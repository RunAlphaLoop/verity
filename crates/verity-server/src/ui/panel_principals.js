"use strict";
/* ==========================================================================
   panel_principals.js — People & groups (v2 rebuild · UI-ACTIONS N5)
   --------------------------------------------------------------------------
   Reads / writes (all admin-bearer; {admin:true}):
     • GET    /v1/admin/principals?tenant_id&after_token&limit — THE directory
       read this rebuild exists for. Keyset-paginated by token; a non-null
       next_after_token means more may exist. Unknown tenant reads as empty.
     • POST   /v1/admin/principals — { tenant_id, principals:[str…] } →
       { mappings: { "<principal>": <token i32> } }. Idempotent: an existing
       name keeps its number.
     • POST   /v1/admin/groups — { tenant_id, group, member } →
       { written:true, tokens:{…} }. Requires ReBAC server-side; 503 surfaces
       verbatim, never faked as success.
     • DELETE /v1/admin/groups — same body → { deleted, tombstones,
       revoked_principals, affected_members }. Tombstones are written FIRST
       (fail-closed: a tombstone failure aborts the delete — over-hides,
       never under-hides) and the removed subtree is hidden on the very
       next read.

   THE LAW, applied:
     • autoloads once the tenant is known; no cold Load button;
     • names first (alice@corp.example, sales); token + raw principal string
       are mono-small secondary text, never primary;
     • plain verbs: "Add a person or group", "Put someone in a group",
       "Take someone out of a group" (tombstone jargon lives in .ref/.dc-meta
       lines only);
     • typed confirm (REMOVE) on the destructive verb;
     • every empty state teaches; honest disclosures kept: membership is not
       listable yet (no GET /v1/admin/groups), pagination truncation is said
       out loud, 503/401 surface verbatim with a pointer.
   ========================================================================== */
(function () {
  var V = window.Verity;
  var PAGE = 1000;      // server clamp max
  var MAX_PAGES = 5;    // 5000 rows per load — truncation is disclosed + resumable

  var GROUP_RE = /^group:.+/;
  var MEMBER_RE = /^(user:.+|group:.+)$/;

  var data = { rows: [], nextAfter: null, tenant: "", loadedAt: 0 };
  var filter = "";

  function el(id) { return V.$(id); }

  /* "user:alice@corp.example" → a person named alice@corp.example;
     "group:sales" → a group named sales; anything else is connector-written. */
  function classify(principal) {
    var s = String(principal || "");
    if (s.indexOf("user:") === 0) return { kind: "person", name: s.slice(5) };
    if (s.indexOf("group:") === 0) return { kind: "group", name: s.slice(6) };
    return { kind: "other", name: s };
  }

  function nameCell(name) {
    return '<b style="color:var(--bright)">' + V.esc(name) + "</b>";
  }
  function tokenCell(row) {
    return '<span class="ref">#' + V.esc(String(row.token)) + " · " + V.esc(row.principal) + "</span>";
  }
  function wire(host, sel, fn) {
    var nodes = host.querySelectorAll(sel);
    for (var i = 0; i < nodes.length; i++) {
      (function (n) { n.onclick = function () { fn(n); }; })(nodes[i]);
    }
  }
  function splitLines(raw) {
    return String(raw || "").split(/[\n,]+/).map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length; });
  }
  function asofNow() { return "checked " + new Date().toTimeString().slice(0, 8); }

  /* =========================================================== register */
  V.register({
    id: "principals",
    mount: mount,
    /* v2 AUTOLOAD — the router runs this when the tenant is known. */
    load: function (_section, tenant) { return refresh(tenant); },
    onShow: function () { if (!V.tenant()) renderNoTenant(); },
  });

  /* =========================================================== mount */
  function mount() {
    var host = el("principals-mount");
    if (!host) return;
    host.innerHTML =
      /* ---- toolbar ---- */
      '<div class="toolbar">' +
        '<span id="prn-state"></span>' +
        '<span class="asof" id="prn-asof"></span>' +
        '<span class="spacer"></span>' +
        '<input type="text" id="prn-filter" placeholder="filter by name…" ' +
          'style="max-width:220px" autocomplete="off" spellcheck="false">' +
        '<button id="prn-refresh" title="GET /v1/admin/principals — re-reads the directory">Refresh</button>' +
        '<button class="primary" id="prn-open-add" title="POST /v1/admin/principals — adding an existing name is safe; it keeps its number">Add a person or group</button>' +
      "</div>" +
      '<div class="err" id="prn-err"></div>' +
      '<div id="prn-hint"></div>' +
      '<div id="prn-receipt"></div>' +
      '<div id="prn-out"></div>' +
      '<datalist id="prn-groups-list"></datalist>' +
      '<datalist id="prn-all-list"></datalist>' +

      /* ---- ADD dialog: the founder-named task, in plain words ---- */
      '<div class="dialog-backdrop" id="prn-add-dialog"><div class="dialog" style="max-width:640px">' +
        "<h3>Add a person or group</h3>" +
        '<div class="note" style="margin-top:0">Verity gives each person or group a <b>number</b> that ' +
          '&ldquo;who can see this&rdquo; rules reference. Adding a name that already exists is safe — ' +
          "it keeps its number. Nothing added here can see anything by itself; visibility is granted " +
          "elsewhere, never defaulted.</div>" +
        '<div class="row" style="margin-top:12px">' +
          '<div><label for="prn-add-people">people <span style="font-weight:400">(email or id — one per line)</span></label>' +
            '<textarea id="prn-add-people" rows="3" placeholder="alice@corp.example&#10;bob@corp.example" ' +
              'autocomplete="off" spellcheck="false"></textarea></div>' +
          '<div><label for="prn-add-groups">groups <span style="font-weight:400">(name — one per line)</span></label>' +
            '<textarea id="prn-add-groups" rows="3" placeholder="sales&#10;support" ' +
              'autocomplete="off" spellcheck="false"></textarea></div>' +
        "</div>" +
        '<div style="margin-top:10px"><label for="prn-add-raw">raw principal strings ' +
          '<span style="font-weight:400">(advanced — connector-style, one per line, e.g. team:eng)</span></label>' +
          '<textarea id="prn-add-raw" rows="2" autocomplete="off" spellcheck="false"></textarea></div>' +
        '<div class="dc-meta">POST /v1/admin/principals · people are written as user:&lt;id&gt;, groups as group:&lt;name&gt;</div>' +
        '<div class="err" id="prn-add-err"></div>' +
        '<div class="actions">' +
          '<button id="prn-add-cancel">Cancel</button>' +
          '<button class="primary" id="prn-add-go">Add to directory</button>' +
        "</div>" +
      "</div></div>" +

      /* ---- MEMBERSHIP ADD dialog ---- */
      '<div class="dialog-backdrop" id="prn-mem-dialog"><div class="dialog" style="max-width:640px">' +
        "<h3>Put someone in a group</h3>" +
        '<div class="note" style="margin-top:0">Everything the group can see, the member can see — ' +
          "starting on their <b>very next read</b>. A group can contain another group; everyone inside " +
          "the inner group gets the same access.</div>" +
        '<div class="row" style="margin-top:12px">' +
          '<div><label for="prn-mem-group">group</label>' +
            '<input type="text" id="prn-mem-group" list="prn-groups-list" placeholder="sales" ' +
              'autocomplete="off" spellcheck="false"></div>' +
          '<div><label for="prn-mem-member">who goes in <span style="font-weight:400">(a person, or another group as group:&lt;name&gt;)</span></label>' +
            '<input type="text" id="prn-mem-member" list="prn-all-list" placeholder="alice@corp.example" ' +
              'autocomplete="off" spellcheck="false"></div>' +
        "</div>" +
        '<div class="note">Names not yet in the directory are added automatically and get their numbers here.</div>' +
        '<div class="dc-meta">POST /v1/admin/groups · writes a membership tuple · requires ReBAC (503 if unconfigured — surfaced verbatim)</div>' +
        '<div class="err" id="prn-mem-err"></div>' +
        '<div class="actions">' +
          '<button id="prn-mem-cancel">Cancel</button>' +
          '<button class="primary" id="prn-mem-go">Add to group</button>' +
        "</div>" +
      "</div></div>" +

      /* ---- MEMBERSHIP REMOVE dialog — typed confirm, human-words warning ---- */
      '<div class="dialog-backdrop" id="prn-rm-dialog"><div class="dialog" style="max-width:660px">' +
        "<h3>Take someone out of a group</h3>" +
        '<div class="row" style="margin-top:8px">' +
          '<div><label for="prn-rm-group">group</label>' +
            '<input type="text" id="prn-rm-group" list="prn-groups-list" placeholder="sales" ' +
              'autocomplete="off" spellcheck="false"></div>' +
          '<div><label for="prn-rm-member">who comes out <span style="font-weight:400">(a person, or an inner group as group:&lt;name&gt;)</span></label>' +
            '<input type="text" id="prn-rm-member" list="prn-all-list" placeholder="alice@corp.example" ' +
              'autocomplete="off" spellcheck="false"></div>' +
        "</div>" +
        '<div class="note">Verity cannot list a group&rsquo;s members yet (the read endpoint is planned) — ' +
          "type the member exactly as it appears in the directory.</div>" +
        '<div class="note" style="border-left:3px solid var(--state-attn);padding-left:10px">' +
          "<b>Removing hides everything this group grants — on the very next read.</b> " +
          "Verity writes the hide first, then removes the membership; if the hide cannot be written, " +
          "nothing is removed (it over-hides, never under-hides). Removing an inner group hides access " +
          "for everyone inside it too. Already-issued scope handles are affected immediately — there is " +
          "no permissive gap to wait out.</div>" +
        '<div class="dc-meta">DELETE /v1/admin/groups · revocation tombstones written first · fail-closed ordering</div>' +
        '<div style="margin-top:12px">' +
          '<label for="prn-rm-word">this hides access immediately — type <b>REMOVE</b> to continue</label>' +
          '<input type="text" id="prn-rm-word" autocomplete="off" spellcheck="false">' +
        "</div>" +
        '<div class="err" id="prn-rm-err"></div>' +
        '<div class="actions">' +
          '<button id="prn-rm-cancel">Cancel</button>' +
          '<button class="danger" id="prn-rm-go" disabled>Remove and hide</button>' +
        "</div>" +
      "</div></div>";

    /* ---- wiring ---- */
    el("prn-refresh").onclick = function () { V.reload("principals"); };
    el("prn-filter").oninput = function () { filter = el("prn-filter").value.trim().toLowerCase(); renderDirectory(); };
    el("prn-open-add").onclick = function () { openAdd(); };
    el("prn-add-cancel").onclick = function () { V.dialog("prn-add-dialog").close(); };
    el("prn-add-go").onclick = submitAdd;
    el("prn-mem-cancel").onclick = function () { V.dialog("prn-mem-dialog").close(); };
    el("prn-mem-go").onclick = submitMemberAdd;
    el("prn-rm-cancel").onclick = function () { V.dialog("prn-rm-dialog").close(); };
    el("prn-rm-go").onclick = submitMemberRemove;
    el("prn-rm-word").oninput = function () {
      el("prn-rm-go").disabled = el("prn-rm-word").value.trim() !== "REMOVE";
    };

    if (!V.tenant()) renderNoTenant();
  }

  /* =========================================================== no-tenant */
  function renderNoTenant() {
    var out = el("prn-out");
    if (!out) return;
    el("prn-state").innerHTML = V.stateChip("off", "no tenant");
    el("prn-receipt").innerHTML = "";
    el("prn-hint").innerHTML = "";
    out.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a tenant to see its people and groups</div>' +
        '<div class="et-body">Paste a tenant id in the session bar above, or mint a scope handle — ' +
          "the tenant fills in automatically and this directory loads itself.</div>" +
        '<div class="et-actions"><button class="primary" id="prn-teach-mint">Mint a scope handle</button></div>' +
      "</div>";
    el("prn-teach-mint").onclick = function () { V.openMint(); };
  }

  /* =========================================================== loading */
  async function refresh(tenant) {
    data.tenant = tenant;
    V.clearErr("prn-err");
    el("prn-hint").innerHTML = "";
    el("prn-state").innerHTML = V.stateChip("wait", "loading");
    try {
      var rows = [];
      var after = 0;
      data.nextAfter = null;
      for (var p = 0; p < MAX_PAGES; p++) {
        var res = await V.api(
          "/v1/admin/principals?tenant_id=" + encodeURIComponent(tenant) +
          "&after_token=" + encodeURIComponent(after) + "&limit=" + PAGE,
          { admin: true }
        );
        rows = rows.concat((res && res.principals) || []);
        if (!res || res.next_after_token == null) { data.nextAfter = null; break; }
        after = res.next_after_token;
        data.nextAfter = after; // still non-null after the last page ⇒ more may exist
      }
      data.rows = rows;
      data.loadedAt = Date.now();
      render();
    } catch (e) {
      var is401 = /HTTP 401/.test(String(e && e.message));
      el("prn-state").innerHTML = V.stateChip("fail", is401 ? "admin token required" : "failed");
      V.err("prn-err", e);
      if (is401) {
        el("prn-hint").innerHTML =
          '<div class="note">This directory is admin-only. Set the admin token in the session bar above — ' +
          "it is kept in this tab only and never stored.</div>";
      }
    }
  }

  async function loadMore(btn) {
    if (data.nextAfter == null) return;
    btn.disabled = true;
    try {
      var after = data.nextAfter;
      for (var p = 0; p < MAX_PAGES; p++) {
        var res = await V.api(
          "/v1/admin/principals?tenant_id=" + encodeURIComponent(data.tenant) +
          "&after_token=" + encodeURIComponent(after) + "&limit=" + PAGE,
          { admin: true }
        );
        data.rows = data.rows.concat((res && res.principals) || []);
        if (!res || res.next_after_token == null) { data.nextAfter = null; break; }
        after = res.next_after_token;
        data.nextAfter = after;
      }
      render();
    } catch (e) {
      V.err("prn-err", e);
      btn.disabled = false;
    }
  }

  /* =========================================================== render */
  function buckets() {
    var b = { people: [], groups: [], others: [] };
    data.rows.forEach(function (r) {
      var c = classify(r.principal);
      var row = { principal: r.principal, token: r.token, name: c.name };
      if (c.kind === "person") b.people.push(row);
      else if (c.kind === "group") b.groups.push(row);
      else b.others.push(row);
    });
    return b;
  }

  function render() {
    var b = buckets();
    var label = b.people.length + (b.people.length === 1 ? " person" : " people") +
      " · " + b.groups.length + " group" + (b.groups.length === 1 ? "" : "s") +
      (b.others.length ? " · " + b.others.length + " other" : "");
    el("prn-state").innerHTML = data.rows.length
      ? V.stateChip("ok", label)
      : V.stateChip("ok", "directory empty");
    el("prn-asof").textContent = asofNow();

    // Datalists feed the membership dialogs from the SAME read as the tables.
    el("prn-groups-list").innerHTML = b.groups.map(function (g) {
      return '<option value="' + V.esc(g.name) + '">';
    }).join("");
    el("prn-all-list").innerHTML = data.rows.map(function (r) {
      return '<option value="' + V.esc(r.principal) + '">';
    }).join("");

    renderDirectory();
  }

  function matches(row) {
    if (!filter) return true;
    return row.name.toLowerCase().indexOf(filter) >= 0 ||
      row.principal.toLowerCase().indexOf(filter) >= 0 ||
      String(row.token).indexOf(filter) >= 0;
  }

  function renderDirectory() {
    var out = el("prn-out");
    if (!out) return;

    if (!data.rows.length) {
      out.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">No people or groups yet</div>' +
          '<div class="et-body">This tenant&rsquo;s directory is empty — a valid answer, not an error. ' +
            "Entries appear when you add them here, when a group membership is written, or when a " +
            "connector mirrors source permissions in. Each entry gets a <b>number</b> that " +
            "&ldquo;who can see this&rdquo; rules and scope handles reference.</div>" +
          '<div class="et-actions"><button id="prn-empty-add">Add a person or group</button></div>' +
        "</div>";
      el("prn-empty-add").onclick = function () { openAdd(); };
      return;
    }

    var b = buckets();
    var gShown = b.groups.filter(matches);
    var pShown = b.people.filter(matches);
    var oShown = b.others.filter(matches);
    var hidden = data.rows.length - (gShown.length + pShown.length + oShown.length);

    var html = "";
    if (filter && !gShown.length && !pShown.length && !oShown.length) {
      html += '<div class="note">No matches for &ldquo;<b>' + V.esc(filter) + "</b>&rdquo; — " +
        data.rows.length + " entr" + (data.rows.length === 1 ? "y is" : "ies are") +
        " hidden by the filter. Clear it to see everyone.</div>";
      out.innerHTML = html;
      return;
    }
    if (hidden > 0) {
      html += '<div class="note">Filter active — ' + hidden + " entr" + (hidden === 1 ? "y" : "ies") +
        " hidden.</div>";
    }

    /* ---- groups ---- */
    html += '<div class="card"><h2>Groups (' + gShown.length + ') ' +
      '<span class="sub">group:* rows of GET /v1/admin/principals</span></h2>';
    if (!gShown.length) {
      html += '<div class="note">No groups' + (filter ? " match the filter" : " yet") +
        ". A group lets one rule cover many people — add one with <b>Add a person or group</b>.</div>";
    } else {
      html += '<div class="note" style="margin-top:0">Who is <em>inside</em> each group is not listable yet ' +
        "(the membership read endpoint is planned) — this screen writes membership and shows the " +
        "server&rsquo;s receipts.</div>" +
        '<div class="tablewrap"><table><thead><tr><th>group</th><th>number · raw string</th><th class="num">actions</th></tr></thead><tbody>' +
        gShown.map(function (g) {
          return "<tr><td>" + nameCell(g.name) + "</td><td>" + tokenCell(g) + "</td>" +
            '<td class="num">' +
              '<button class="prn-mem-open" data-group="' + V.esc(g.name) + '" ' +
                'title="POST /v1/admin/groups — the member sees what the group sees, on their next read">Add someone</button> ' +
              '<button class="prn-rm-open" data-group="' + V.esc(g.name) + '" ' +
                'title="DELETE /v1/admin/groups — typed confirm; hides what the group granted on the very next read">Remove someone&hellip;</button> ' +
              '<button class="prn-see-tokens" data-token="' + V.esc(String(g.token)) + '" ' +
                'title="opens the mint dialog pre-filled with this group’s token — POST /v1/scopes">See as this group</button>' +
            "</td></tr>";
        }).join("") +
        "</tbody></table></div>";
    }
    html += "</div>";

    /* ---- people ---- */
    html += '<div class="card"><h2>People (' + pShown.length + ') ' +
      '<span class="sub">user:* rows of GET /v1/admin/principals</span></h2>';
    if (!pShown.length) {
      html += '<div class="note">No people' + (filter ? " match the filter" : " yet") +
        ". Add one with <b>Add a person or group</b> — or mint a handle for a subject and identity " +
        "resolution will materialize them.</div>";
    } else {
      html += '<div class="tablewrap"><table><thead><tr><th>person</th><th>number · raw string</th><th class="num">actions</th></tr></thead><tbody>' +
        pShown.map(function (p) {
          return "<tr><td>" + nameCell(p.name) + "</td><td>" + tokenCell(p) + "</td>" +
            '<td class="num">' +
              '<button class="prn-mem-open" data-member="' + V.esc(p.principal) + '" ' +
                'title="POST /v1/admin/groups — they see what the group sees, on their next read">Put in a group</button> ' +
              '<button class="prn-rm-open" data-member="' + V.esc(p.principal) + '" ' +
                'title="DELETE /v1/admin/groups — typed confirm; hides what the group granted on the very next read">Take out of a group&hellip;</button> ' +
              '<button class="prn-see-subject" data-subject="' + V.esc(p.principal) + '" ' +
                'title="opens the mint dialog with this person as the subject — POST /v1/scopes re-resolves their identity server-side">Mint a handle as this person</button>' +
            "</td></tr>";
        }).join("") +
        "</tbody></table></div>";
    }
    html += "</div>";

    /* ---- other principal shapes (connector-written) ---- */
    if (oShown.length) {
      html += '<div class="card"><h2>Other principals (' + oShown.length + ') ' +
        '<span class="sub">non user:/group: shapes — typically written by a connector&rsquo;s ACL mapping</span></h2>' +
        '<div class="tablewrap"><table><thead><tr><th>principal</th><th>number</th><th class="num">actions</th></tr></thead><tbody>' +
        oShown.map(function (o) {
          return "<tr><td>" + nameCell(o.name) + "</td>" +
            '<td><span class="ref">#' + V.esc(String(o.token)) + "</span></td>" +
            '<td class="num"><button class="prn-see-tokens" data-token="' + V.esc(String(o.token)) + '" ' +
              'title="opens the mint dialog pre-filled with this token — POST /v1/scopes">See as this principal</button></td></tr>';
        }).join("") +
        "</tbody></table></div></div>";
    }

    /* ---- honest truncation ---- */
    if (data.nextAfter != null) {
      html += '<div class="note">Showing the first ' + data.rows.length +
        " entries in token order — <b>more may exist</b>. " +
        '<button id="prn-more">Load more</button></div>';
    }

    out.innerHTML = html;

    wire(out, ".prn-mem-open", function (btn) {
      openMemberAdd(btn.getAttribute("data-group") || "", btn.getAttribute("data-member") || "");
    });
    wire(out, ".prn-rm-open", function (btn) {
      openMemberRemove(btn.getAttribute("data-group") || "", btn.getAttribute("data-member") || "");
    });
    wire(out, ".prn-see-tokens", function (btn) {
      V.openMint({ tenant: data.tenant, principals: btn.getAttribute("data-token") || "" });
    });
    wire(out, ".prn-see-subject", function (btn) {
      V.openMint({ tenant: data.tenant, subject: btn.getAttribute("data-subject") || "" });
    });
    var more = el("prn-more");
    if (more) more.onclick = function () { loadMore(more); };
  }

  /* =========================================================== add flow */
  function openAdd() {
    if (!V.tenant()) { renderNoTenant(); return; }
    V.clearErr("prn-add-err");
    V.dialog("prn-add-dialog").open();
  }

  function buildAddList() {
    var out = [];
    var seen = {};
    function push(s) { if (!seen[s]) { seen[s] = true; out.push(s); } }
    var bad = null;
    splitLines(el("prn-add-people").value).forEach(function (line) {
      push(line.indexOf(":") >= 0 ? line : "user:" + line);
    });
    splitLines(el("prn-add-groups").value).forEach(function (line) {
      if (line.indexOf("group:") === 0) push(line);
      else if (line.indexOf(":") >= 0) bad = bad || line; // looks raw — refuse to guess
      else push("group:" + line);
    });
    splitLines(el("prn-add-raw").value).forEach(push);
    if (bad) throw new Error('"' + bad + '" in the groups box looks like a raw principal string — ' +
      "move it to the advanced box so nothing is guessed");
    return out;
  }

  async function submitAdd() {
    V.clearErr("prn-add-err");
    if (!data.tenant) { V.err("prn-add-err", new Error("no tenant selected")); return; }
    var list;
    try { list = buildAddList(); } catch (e) { V.err("prn-add-err", e); return; }
    if (!list.length) {
      V.err("prn-add-err", new Error("enter at least one person or group — nothing is assumed"));
      return;
    }
    var btn = el("prn-add-go");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/admin/principals",
        { admin: true, json: { tenant_id: data.tenant, principals: list } });
      V.dialog("prn-add-dialog").close();
      el("prn-add-people").value = "";
      el("prn-add-groups").value = "";
      el("prn-add-raw").value = "";
      renderAddReceipt(res && res.mappings, list.length);
      await refresh(data.tenant); // read the directory back — parity from the server, not assumed
    } catch (e) {
      V.err("prn-add-err", e);
    } finally {
      btn.disabled = false;
    }
  }

  function renderAddReceipt(mappings, asked) {
    mappings = mappings || {};
    var keys = Object.keys(mappings);
    var chips = keys.map(function (p) {
      var c = classify(p);
      return '<span class="entity-chip"><b>' + V.esc(c.name) + '</b><span class="src">' +
        (c.kind === "person" ? "person" : c.kind === "group" ? "group" : "principal") +
        ' · <span class="ref">#' + V.esc(String(mappings[p])) + "</span></span></span>";
    }).join(" ");
    el("prn-receipt").innerHTML =
      '<div class="card" style="border-left:3px solid var(--green)">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip("ok", "in the directory") +
          "<b>" + keys.length + "</b> of " + asked + " name" + (asked === 1 ? "" : "s") + " confirmed with numbers" +
        "</div>" +
        '<div style="margin-top:6px">' + chips + "</div>" +
        '<div class="note">Names that already existed kept their numbers — re-adding is always safe. ' +
          "These numbers are what visibility rules and scope handles reference. " +
          '<span class="ref">' + asofNow() + "</span></div>" +
      "</div>";
  }

  /* ============================================== membership add flow */
  function normalizeGroup(raw) {
    var g = String(raw || "").trim();
    if (!g) return "";
    return g.indexOf("group:") === 0 ? g : "group:" + g;
  }
  function normalizeMember(raw) {
    var m = String(raw || "").trim();
    if (!m) return "";
    return m.indexOf(":") >= 0 ? m : "user:" + m;
  }

  function openMemberAdd(groupName, memberPrincipal) {
    if (!V.tenant()) { renderNoTenant(); return; }
    V.clearErr("prn-mem-err");
    el("prn-mem-group").value = groupName || "";
    el("prn-mem-member").value = memberPrincipal || "";
    V.dialog("prn-mem-dialog").open();
  }

  async function submitMemberAdd() {
    V.clearErr("prn-mem-err");
    if (!data.tenant) { V.err("prn-mem-err", new Error("no tenant selected")); return; }
    var group = normalizeGroup(el("prn-mem-group").value);
    var member = normalizeMember(el("prn-mem-member").value);
    if (!GROUP_RE.test(group)) {
      V.err("prn-mem-err", new Error("name the group — e.g. sales (written as group:sales)"));
      return;
    }
    if (!MEMBER_RE.test(member)) {
      V.err("prn-mem-err", new Error("name who goes in — a person (alice@corp.example) or another group (group:inner)"));
      return;
    }
    if (member === group) {
      V.err("prn-mem-err", new Error("a group cannot be a member of itself"));
      return;
    }
    var btn = el("prn-mem-go");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/admin/groups",
        { admin: true, json: { tenant_id: data.tenant, group: group, member: member } });
      V.dialog("prn-mem-dialog").close();
      renderMemberAddReceipt(group, member, res);
      await refresh(data.tenant); // both tokens materialize — show them from the read
    } catch (e) {
      V.err("prn-mem-err", e); // includes the verbatim 503 when ReBAC is unconfigured
    } finally {
      btn.disabled = false;
    }
  }

  function renderMemberAddReceipt(group, member, res) {
    var g = classify(group), m = classify(member);
    var tokens = (res && res.tokens) || {};
    var refBits = Object.keys(tokens).map(function (p) {
      return V.esc(p) + " = #" + V.esc(String(tokens[p]));
    }).join(" · ");
    el("prn-receipt").innerHTML =
      '<div class="card" style="border-left:3px solid var(--green)">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip("ok", "membership written") +
          "<b>" + V.esc(m.name) + "</b>" +
          '<span style="color:var(--dim)">is now in</span>' +
          "<b>" + V.esc(g.name) + "</b>" +
        "</div>" +
        '<div class="note">Everything visible to <b>' + V.esc(g.name) + "</b> is visible to <b>" +
          V.esc(m.name) + "</b> on their very next read — no re-mint needed. " +
          '<span class="ref">' + refBits + " · " + asofNow() + "</span></div>" +
      "</div>";
  }

  /* =========================================== membership remove flow */
  function openMemberRemove(groupName, memberPrincipal) {
    if (!V.tenant()) { renderNoTenant(); return; }
    V.clearErr("prn-rm-err");
    el("prn-rm-group").value = groupName || "";
    el("prn-rm-member").value = memberPrincipal || "";
    el("prn-rm-word").value = "";
    el("prn-rm-go").disabled = true; // typed confirm gates the destructive verb
    V.dialog("prn-rm-dialog").open();
  }

  async function submitMemberRemove() {
    V.clearErr("prn-rm-err");
    if (!data.tenant) { V.err("prn-rm-err", new Error("no tenant selected")); return; }
    if (el("prn-rm-word").value.trim() !== "REMOVE") {
      V.err("prn-rm-err", new Error("type REMOVE to confirm — this hides access immediately"));
      return;
    }
    var group = normalizeGroup(el("prn-rm-group").value);
    var member = normalizeMember(el("prn-rm-member").value);
    if (!GROUP_RE.test(group)) {
      V.err("prn-rm-err", new Error("name the group — e.g. sales (written as group:sales)"));
      return;
    }
    if (!MEMBER_RE.test(member)) {
      V.err("prn-rm-err", new Error("name who comes out — a person (alice@corp.example) or an inner group (group:inner)"));
      return;
    }
    var btn = el("prn-rm-go");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/admin/groups", {
        admin: true,
        method: "DELETE",
        json: { tenant_id: data.tenant, group: group, member: member },
      });
      V.dialog("prn-rm-dialog").close();
      renderRemoveReceipt(group, member, res);
      await refresh(data.tenant);
    } catch (e) {
      // Keep the dialog open so the refusal is read in the destructive context.
      V.err("prn-rm-err", e);
      btn.disabled = el("prn-rm-word").value.trim() !== "REMOVE";
    }
  }

  function renderRemoveReceipt(group, member, res) {
    res = res || {};
    var g = classify(group), m = classify(member);
    var revoked = res.revoked_principals || [];
    var affected = res.affected_members || [];
    var revChips = revoked.length
      ? revoked.map(function (p) {
          var c = classify(p);
          return V.entityChip(c.name, c.kind === "group" ? "group" : c.kind === "person" ? "person" : "principal");
        }).join(" ")
      : '<span class="note">nothing had a number yet — there was nothing to hide</span>';
    var affChips = affected.length
      ? affected.map(function (p) {
          var c = classify(p);
          return V.entityChip(c.name, c.kind === "group" ? "group" : "person");
        }).join(" ")
      : '<span class="note">none</span>';
    el("prn-receipt").innerHTML =
      '<div class="card" style="border-left:3px solid var(--state-attn)">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip("ok", "removed — hidden on the very next read") +
          "<b>" + V.esc(m.name) + "</b>" +
          '<span style="color:var(--dim)">is out of</span>' +
          "<b>" + V.esc(g.name) + "</b>" +
        "</div>" +
        '<dl class="kv" style="margin-top:8px">' +
          "<dt>access hidden</dt><dd>" + revChips + "</dd>" +
          "<dt>who lost it</dt><dd>" + affChips + "</dd>" +
          "<dt>hides recorded</dt><dd>" +
            V.badge(String(res.tombstones == null ? "—" : res.tombstones), "b-kind") +
            ' <span class="ref">revocation tombstones — written before the membership delete</span></dd>' +
        "</dl>" +
        '<div class="note">The hidden numbers are subtracted from every scoped read from now on — ' +
          "including scope handles minted before this removal. " +
          '<span class="ref">' + asofNow() + "</span></div>" +
      "</div>";
  }
})();
