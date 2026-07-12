"use strict";
/* ==========================================================================
   panel_quarantine.js — Quarantine  [v2 rebuild — frozen design contract]
   --------------------------------------------------------------------------
   Reads:
     • GET /v1/admin/quarantine?tenant_id=&limit= (admin) — newest first:
       { id, webhook_id, payload (FULL json, never truncated), reason, at }.
       (No resolution columns yet — dispositions learned THIS SESSION are
       badged locally and said to be session-local. The server's atomic
       OPEN→resolved claim stays the authority: acting on an already-resolved
       row returns 409 naming the prior disposition.)
     • GET /v1/admin/principals (admin, N5) — token ↔ name directory, so the
       corrected mapping is picked BY NAME, not guessed by token number.

   Writes — the two ONLY exits, both audited, row survives either
   (invalidate-don't-delete):
     • POST /v1/admin/quarantine/{id}/reingest — re-admit THROUGH a corrected,
       admin-supplied mapping. visibility + confidentiality REQUIRED and
       explicit (empty visibility needs an explicit fail-closed
       acknowledgement); result stamped admin-assigned; original payload
       preserved verbatim; 409 already-resolved; 422 nothing-ingestible
       (re-ingest never fabricates content).
     • POST /v1/admin/quarantine/{id}/dismiss — acknowledge, index NOTHING.
   NO "index it anyway" affordance exists here or on the server — no request
   shape indexes a payload under its original unmappable ACL or any default.

   THE LAW, applied: cards say "we refused to index this and here is why" in
   plain words (verbatim reason + ids in mono secondary); autoloads when the
   tenant is known; empty queue celebrates with evidence; the fail-closed
   thesis is one human sentence in the lede.
   READ-PATH PURITY: reads are pure; filters/export are local transforms.
   ========================================================================== */
(function () {
  var V = window.Verity;

  /* ------------------------------------------------------------ reasons */

  // The server writes free-form reason strings. We bucket by the stable
  // prefix before the first colon — display-only classification; the full
  // reason is always shown verbatim in the card's mono meta line.
  function reasonGroup(reason) {
    var r = String(reason || "").trim();
    if (!r) return "(no reason recorded)";
    var colon = r.indexOf(":");
    var head = (colon >= 0 ? r.slice(0, colon) : r).trim().toLowerCase();
    if (!head) return "(no reason recorded)";
    if (head.indexOf("unmapped acl") >= 0 || head.indexOf("unmappable acl") >= 0) return "unmapped ACL";
    if (head.indexOf("unrecognized shape") >= 0 || head.indexOf("unknown shape") >= 0) return "unrecognized shape";
    if (head.indexOf("invalid json") >= 0) return "invalid JSON";
    if (head.indexOf("draft manifest") >= 0 || head.indexOf("manifest") >= 0) return "draft manifest";
    return head;
  }

  // group → what a first-time operator reads (the jargon lives in .dc-meta).
  function groupPlain(g) {
    switch (g) {
      case "unmapped ACL":
        return "its permissions name people or groups Verity doesn't know";
      case "unrecognized shape":
        return "Verity couldn't find any text or facts it recognized in it";
      case "invalid JSON":
        return "it wasn't valid JSON";
      case "draft manifest":
        return "it was delivered to a source that hasn't been approved yet";
      default:
        return "it couldn't be safely understood";
    }
  }
  function groupFix(g) {
    switch (g) {
      case "unmapped ACL":
        return "If you know who should see it, supply the permissions yourself below — that is the only way in.";
      case "unrecognized shape":
        return "You can supply a corrected text extraction and the permissions yourself below.";
      case "invalid JSON":
        return "The raw bytes were preserved. Fix the sender, or supply a corrected extraction and permissions below.";
      case "draft manifest":
        return "Activate the source's manifest (a human gate on the Sources panel), or re-ingest this one item with explicit permissions below.";
      default:
        return "Supply the permissions (and, if needed, a corrected extraction) yourself below — nothing is ever indexed on a guess.";
    }
  }

  /* ------------------------------------------------------------ helpers */

  function payloadText(payload) {
    if (payload === undefined || payload === null) return "(null payload)";
    if (typeof payload === "string") return payload;   // raw preview bytes kept as-is
    try { return JSON.stringify(payload, null, 2); }
    catch (e) { return String(payload); }
  }
  function tsOrNull(v) {
    if (!v) return null;
    var t = new Date(v).getTime();
    return isNaN(t) ? null : t;
  }
  function download(name, mime, text) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }
  // Principal tokens are i32s on the wire; a typo must never silently shrink
  // or widen visibility, so non-integers are hard errors.
  function parseTokens(raw) {
    var parts = String(raw || "").split(/[\s,]+/).filter(function (s) { return s.length; });
    var out = [], seen = {};
    for (var i = 0; i < parts.length; i++) {
      if (!/^-?\d+$/.test(parts[i])) {
        throw new Error('"' + parts[i] + '" is not an integer principal token — pick people from the directory or type token numbers');
      }
      var n = parseInt(parts[i], 10);
      if (!seen[n]) { seen[n] = true; out.push(n); }
    }
    return out;
  }
  // "… already resolved (dismissed)" → "dismissed".
  function priorDisposition(message) {
    var m = /already resolved(?:\s*\(([^)]+)\))?/.exec(String(message || ""));
    return m ? (m[1] || "resolved") : null;
  }

  /* ------------------------------------------------------------ state */

  var LAST = [];        // fetched window, newest first
  var BY_ID = {};       // id → row
  var RESOLVED = {};    // id → disposition learned THIS SESSION (honest, local)
  var DIR = null;       // [{principal, token}] directory (null = unavailable)
  var ACTIVE = null;    // row a dialog is open for
  var tenantNow = "";
  // Entity-tag picker for re-ingest (ENTITY-PICKER.md §5.5): tags mode —
  // whatever is committed here is immortalized on the audit row, so the
  // near-miss guard and the explicit new-tag flow are the protection inside
  // this careful-correction dialog. Chips are the only submission path.
  var qrTagsPicker = null;

  function el(id) { return V.$(id); }
  function waitingRows() {
    return LAST.filter(function (r) { return !RESOLVED[r.id]; });
  }

  /* =========================================================== register */

  V.register({
    id: "quarantine",

    mount: function () {
      var host = el("quarantine-mount");
      if (!host) return;
      host.innerHTML =
        /* ---- toolbar ---- */
        '<div class="toolbar">' +
          '<span id="q-state">' + V.stateChip("off", "waiting for a tenant") + '</span>' +
          '<span class="asof" id="q-asof"></span>' +
          '<span class="spacer"></span>' +
          '<button id="q-export" title="JSON export of the filtered items — full payloads, never truncated">Export JSON</button>' +
          '<button id="q-refresh">Refresh</button>' +
        '</div>' +

        /* ---- simple filters (advanced collapsed) ---- */
        '<div class="row" id="q-simple">' +
          '<div><label for="q-f-q">search reasons &amp; payloads</label>' +
            '<input type="text" id="q-f-q" placeholder="anything in the refusal reason or payload…" autocomplete="off"></div>' +
          '<div class="tight" style="min-width:260px"><label for="q-f-group">why it was refused</label>' +
            '<select class="field" id="q-f-group"><option value="">any reason</option></select></div>' +
          '<div class="tight"><button id="q-adv-toggle">More filters</button></div>' +
          '<div class="tight"><button id="q-f-clear">Clear</button></div>' +
        '</div>' +
        '<div class="row" id="q-advanced" style="display:none;margin-top:8px">' +
          '<div class="tight"><label for="q-f-webhook">webhook id contains</label>' +
            '<input type="text" id="q-f-webhook" size="16" autocomplete="off"></div>' +
          '<div class="tight"><label for="q-f-from">from</label>' +
            '<input type="text" id="q-f-from" placeholder="YYYY-MM-DD HH:MM" size="17"></div>' +
          '<div class="tight"><label for="q-f-to">to</label>' +
            '<input type="text" id="q-f-to" placeholder="YYYY-MM-DD HH:MM" size="17"></div>' +
          '<div class="tight"><label for="q-limit" title="rows fetched (server clamps 1-500) — changing it refetches">window</label>' +
            '<input type="number" id="q-limit" value="100" min="1" max="500" style="width:90px"></div>' +
        '</div>' +

        '<div class="err" id="q-err"></div>' +
        '<div id="q-out"></div>' +

        /* ---- RE-INGEST dialog: the corrected-mapping flow ---- */
        '<div class="dialog-backdrop" id="q-reingest-dialog"><div class="dialog" style="max-width:660px">' +
          '<h3>Fix who can see it &amp; re-ingest</h3>' +
          '<div id="qr-ctx"></div>' +
          '<div class="note" style="margin-top:10px;border-left:3px solid var(--red);padding-left:10px">' +
            '<b>This is not &ldquo;index it anyway&rdquo;.</b> You are supplying the permissions yourself. ' +
            'The result carries <em>exactly</em> what you choose below — stamped ' +
            V.provenanceBadge("admin-assigned") + ' — never the original unverifiable permissions, ' +
            'never a default. The original payload is preserved verbatim and the action is audited.' +
          '</div>' +

          '<div style="margin-top:12px"><label>who can see it <span style="font-weight:400">(required — pick from this tenant&rsquo;s directory)</span></label>' +
            '<div id="qr-dir" style="margin:4px 0 6px"></div>' +
            '<input type="text" id="qr-vis" placeholder="principal tokens, e.g. 7, 9 (picking names above fills this)" spellcheck="false"></div>' +
          '<label class="checkline" style="margin-top:6px"><input type="checkbox" id="qr-vis-empty">' +
            'I mean <b>nobody</b> can see it &mdash; fail-closed: this writes memory no one can read</label>' +

          '<div style="margin-top:10px"><label>confidentiality ceiling <span style="font-weight:400">(required — there is no default)</span></label>' +
            '<select class="field" id="qr-conf">' +
              '<option value="">— choose —</option>' +
              '<option value="Public">public</option>' +
              '<option value="Internal">internal</option>' +
              '<option value="Confidential">confidential</option>' +
              '<option value="Restricted">restricted</option>' +
            '</select></div>' +
          // Label fixed per ENTITY-PICKER.md §5.5: this field TAGS the
          // re-ingested record (entity_tags); it never limits a scope.
          '<div style="margin-top:10px"><label>entity tags for the corrected record <span style="font-weight:400">(optional)</span></label>' +
            '<div id="qr-tags"></div></div>' +
          '<div style="margin-top:10px"><label>corrected text extraction <span style="font-weight:400">(optional)</span></label>' +
            '<textarea id="qr-content" placeholder="Only if the text lives somewhere the parser doesn\'t know. Blank = use the payload\'s own text. Re-ingest never invents content — a payload with nothing ingestible is refused (422)."></textarea></div>' +
          '<div style="margin-top:10px"><label>note for the record <span style="font-weight:400">(optional — stored with the audit row)</span></label>' +
            '<input type="text" id="qr-note" placeholder="why this mapping is correct"></div>' +

          '<div class="err" id="qr-err"></div>' +
          '<div id="qr-result"></div>' +
          '<div class="actions">' +
            '<button id="qr-cancel">Cancel</button>' +
            '<button class="good" id="qr-go">Re-ingest with these permissions</button>' +
          '</div>' +
        '</div></div>' +

        /* ---- DISMISS dialog ---- */
        '<div class="dialog-backdrop" id="q-dismiss-dialog"><div class="dialog" style="max-width:560px">' +
          '<h3>Dismiss &mdash; keep it un-indexed</h3>' +
          '<div id="qd-ctx"></div>' +
          '<div class="note" style="margin-top:10px">Nothing gets indexed. The payload stays invisible ' +
            'to every search, and the record of the refusal survives for audit. This is the right exit ' +
            'for duplicates, junk, or things fixed at the source.</div>' +
          '<div style="margin-top:10px"><label>note for the record <span style="font-weight:400">(optional)</span></label>' +
            '<input type="text" id="qd-note" placeholder="e.g. duplicate delivery; fixed at the source"></div>' +
          '<div class="err" id="qd-err"></div>' +
          '<div class="actions">' +
            '<button id="qd-cancel">Cancel</button>' +
            '<button class="primary" id="qd-go">Dismiss — index nothing</button>' +
          '</div>' +
        '</div></div>';

      /* ---- wiring ---- */
      el("q-refresh").onclick = function () { V.reload("quarantine"); };
      el("q-adv-toggle").onclick = function () {
        var adv = el("q-advanced");
        var on = adv.style.display === "none";
        adv.style.display = on ? "" : "none";
        el("q-adv-toggle").textContent = on ? "Fewer filters" : "More filters";
      };
      ["q-f-q", "q-f-webhook", "q-f-from", "q-f-to"].forEach(function (id) {
        el(id).addEventListener("input", renderCards);
      });
      el("q-f-group").addEventListener("change", renderCards);
      el("q-f-clear").onclick = function () {
        ["q-f-q", "q-f-webhook", "q-f-from", "q-f-to"].forEach(function (id) { el(id).value = ""; });
        el("q-f-group").value = "";
        renderCards();
      };
      el("q-limit").addEventListener("change", function () { V.reload("quarantine"); });
      el("q-export").onclick = exportJson;

      // delegated card actions
      el("q-out").addEventListener("click", function (ev) {
        var btn = ev.target.closest ? ev.target.closest("button[data-act]") : null;
        if (!btn) return;
        var act = btn.getAttribute("data-act");
        if (act === "payload") {
          var box = document.getElementById("q-pl-" + btn.getAttribute("data-id"));
          if (box) {
            var showing = box.style.display !== "none";
            box.style.display = showing ? "none" : "";
            btn.textContent = showing ? "Show the original payload" : "Hide the original payload";
          }
          return;
        }
        var row = BY_ID[btn.getAttribute("data-id")];
        if (!row) return;
        if (act === "reingest") openReingest(row);
        else if (act === "dismiss") openDismiss(row);
      });

      el("qr-cancel").onclick = function () {
        V.dialog("q-reingest-dialog").close();
        el("qr-cancel").textContent = "Cancel";
      };
      el("qr-go").onclick = doReingest;
      el("qd-cancel").onclick = function () { V.dialog("q-dismiss-dialog").close(); };
      el("qd-go").onclick = doDismiss;

      if (!V.tenant()) renderNoTenant();
    },

    // AUTOLOAD (LAW #3): run by the router once a tenant is known.
    load: function (_s, tenant) {
      tenantNow = tenant;
      return refresh(tenant);
    },
  });

  /* ------------------------------------------------------------ no tenant */

  function renderNoTenant() {
    el("q-out").innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a tenant to see what it refused</div>' +
        '<div class="et-body">Paste a tenant id in the session bar above &mdash; the queue loads by ' +
          'itself the moment a tenant is known. Anything Verity refused to index (because it could not ' +
          'verify who should see it) waits here for a human decision.</div>' +
        '<div class="et-actions"><button class="primary" id="q-mint">Mint a scope handle</button></div>' +
      '</div>';
    el("q-mint").onclick = function () { V.openMint(); };
  }

  /* ------------------------------------------------------------ load */

  async function fetchDirectory(tenant) {
    var out = [];
    var after = 0;
    for (var page = 0; page < 10; page++) {
      var res = await V.api(
        "/v1/admin/principals?tenant_id=" + encodeURIComponent(tenant) +
        "&after_token=" + after + "&limit=1000", { admin: true });
      out = out.concat((res && res.principals) || []);
      if (!res || res.next_after_token == null) break;
      after = res.next_after_token;
    }
    return out;
  }

  async function refresh(tenant) {
    V.clearErr("q-err");
    el("q-state").innerHTML = V.stateChip("wait", "loading");
    var limit = Math.max(1, Math.min(500, parseInt(el("q-limit").value, 10) || 100));
    try {
      var results = await Promise.all([
        V.api("/v1/admin/quarantine?tenant_id=" + encodeURIComponent(tenant) + "&limit=" + limit,
          { admin: true }),
        fetchDirectory(tenant).catch(function () { return null; }),
      ]);
      LAST = Array.isArray(results[0]) ? results[0] : [];
      DIR = results[1];
      BY_ID = {};
      LAST.forEach(function (r) { BY_ID[r.id] = r; });
      el("q-asof").textContent = "checked " + new Date().toTimeString().slice(0, 8) +
        " · window " + LAST.length + " item" + (LAST.length === 1 ? "" : "s");
      refreshGroupOptions();
      renderCards();
    } catch (e) {
      el("q-state").innerHTML = V.stateChip("fail");
      if (/HTTP 401/.test(String(e.message))) {
        V.err("q-err", new Error(e.message +
          "\nThis read needs the admin token — set it in the session bar (it lives in this tab only)."));
      } else {
        V.err("q-err", e);
      }
    }
  }

  /* ------------------------------------------------------------ filtering */

  function currentFilters() {
    return {
      q: el("q-f-q").value.trim().toLowerCase(),
      group: el("q-f-group").value,
      webhook: el("q-f-webhook").value.trim().toLowerCase(),
      from: tsOrNull(el("q-f-from").value.trim()),
      to: tsOrNull(el("q-f-to").value.trim()),
    };
  }
  function passesFilters(r, f) {
    if (f.group && reasonGroup(r.reason) !== f.group) return false;
    if (f.webhook && String(r.webhook_id || "").toLowerCase().indexOf(f.webhook) < 0) return false;
    if (f.q) {
      var hay = (String(r.reason || "") + " " + payloadText(r.payload)).toLowerCase();
      if (hay.indexOf(f.q) < 0) return false;
    }
    var t = new Date(r.at).getTime();
    if (f.from && t < f.from) return false;
    if (f.to && t > f.to) return false;
    return true;
  }
  function filtered() {
    var f = currentFilters();
    return LAST.filter(function (r) { return passesFilters(r, f); });
  }

  // The reason dropdown describes the FULL window, in plain words + count.
  function refreshGroupOptions() {
    var counts = {};
    LAST.forEach(function (r) {
      var g = reasonGroup(r.reason);
      counts[g] = (counts[g] || 0) + 1;
    });
    var sel = el("q-f-group");
    var keep = sel.value;
    var keys = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; });
    sel.innerHTML = '<option value="">any reason</option>' +
      keys.map(function (g) {
        return '<option value="' + V.esc(g) + '">' +
          V.esc(groupPlain(g)) + " (" + counts[g] + ")</option>";
      }).join("");
    if (keep && counts[keep] != null) sel.value = keep;
  }

  /* ------------------------------------------------------------ cards */

  function stateStrip() {
    var waiting = waitingRows().length;
    // LAW: the rail count derives from the SAME query this list renders.
    V.setCount("quarantine", waiting);
    el("q-state").innerHTML = waiting
      ? V.stateChip("attn", waiting + " need" + (waiting === 1 ? "s" : "") + " a decision")
      : V.stateChip("ok", "queue clear");
  }

  function resolvedChip(id) {
    var d = RESOLVED[id];
    if (!d) return null;
    return V.stateChip("ok", d === "reingested" ? "re-ingested" : d) +
      ' <span class="asof">learned this session · the record of the refusal survives for audit</span>';
  }

  function card(r) {
    var g = reasonGroup(r.reason);
    var done = resolvedChip(r.id);
    var pid = V.esc(String(r.id));
    return '<div class="decision-card' + (done ? '' : ' dc-flag') + '">' +
      '<div class="dc-topline">' +
        (done || V.stateChip("attn", "needs you")) +
        '<span class="asof" title="' + V.esc(V.fmtTime(r.at)) + '">refused ' + V.esc(V.timeAgo(r.at)) + '</span>' +
      '</div>' +
      '<div class="dc-question">Verity refused to index this &mdash; ' + V.esc(groupPlain(g)) + '.</div>' +
      '<div class="dc-src" style="color:var(--dim);font-size:var(--fs-sm)">delivered by webhook ' +
        V.refSpan(r.webhook_id || "(unknown)") + '</div>' +
      '<div class="dc-evidence"><b>Why this is safe:</b> because the permissions could not be verified, ' +
        'this payload <b>never entered the index</b> — no search, brief, or agent can see it. ' +
        'Refusing was the correct answer, not an error. ' + V.esc(groupFix(g)) + '</div>' +
      '<div style="margin-top:8px">' +
        '<button data-act="payload" data-id="' + pid + '">Show the original payload</button>' +
        '<div id="q-pl-' + pid + '" style="display:none" class="tablewrap">' +
          '<pre style="margin:6px 0 0;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.5">' +
          V.esc(payloadText(r.payload)) + '</pre>' +
          '<div class="note">full payload, never truncated — this is the evidence, exactly as it arrived</div>' +
        '</div>' +
      '</div>' +
      '<div class="dc-meta">' + V.esc(r.reason || "(no reason recorded)") + ' · quarantine ' + pid + '</div>' +
      (done ? '' :
        '<div class="dc-actions">' +
          '<button class="good" data-act="reingest" data-id="' + pid + '" ' +
            'title="POST /v1/admin/quarantine/{id}/reingest — re-admit THROUGH a corrected admin-supplied mapping. Never the original unverifiable permissions, never a default.">' +
            'Fix who can see it &amp; re-ingest&hellip;</button>' +
          '<button data-act="dismiss" data-id="' + pid + '" ' +
            'title="POST /v1/admin/quarantine/{id}/dismiss — acknowledge without indexing anything; the record survives for audit.">' +
            'Dismiss — keep it un-indexed&hellip;</button>' +
        '</div>') +
    '</div>';
  }

  function renderCards() {
    stateStrip();
    if (!LAST.length) {
      // Queue drained (sp-c): celebrate WITH evidence — and restate the law.
      el("q-out").innerHTML =
        '<div class="empty-teach sp-c">' +
          '<div class="et-title">Nothing is waiting — the boundary held on its own</div>' +
          '<div class="et-body">Every payload delivered to this tenant carried permissions Verity could ' +
            'verify, so everything was indexed under real permissions and <b>nothing had to be refused</b>. ' +
            'An empty queue is the goal, not a gap — and nothing ambiguous was indexed to make it empty. ' +
            'Checked ' + V.esc(new Date().toTimeString().slice(0, 8)) + '.</div>' +
          '<div class="et-actions"><button id="q-empty-audit">See recent reads in the access audit</button></div>' +
        '</div>';
      el("q-empty-audit").onclick = function () { V.show("audit"); };
      return;
    }
    var rows = filtered();
    if (!rows.length) {
      el("q-out").innerHTML =
        '<div class="note" style="margin-top:10px">0 of the ' + LAST.length +
        ' loaded items match these filters — they still exist one filter away. ' +
        '<button id="q-empty-clear" style="margin-left:8px">Clear all filters</button></div>';
      el("q-empty-clear").onclick = function () { el("q-f-clear").click(); };
      return;
    }
    el("q-out").innerHTML =
      '<div class="note" style="margin:2px 0 10px">Every item below leaves in exactly <b>two ways</b>: ' +
      're-ingest <em>through permissions you supply</em>, or dismiss (indexes nothing). There is no ' +
      '&ldquo;index it anyway&rdquo; button — the server has no request shape for one. Both exits are ' +
      'audited and the record of the refusal survives either way.</div>' +
      rows.map(card).join("");
  }

  /* ------------------------------------------------------------ re-ingest */

  function ctxLine(r) {
    return '<div class="note" style="margin-top:0">' +
      V.stateChip("attn", "quarantined") + ' refused ' + V.esc(V.timeAgo(r.at)) +
      ' because ' + V.esc(groupPlain(reasonGroup(r.reason))) + '.' +
      '<div class="dc-meta" style="margin-top:4px">' + V.esc(r.reason || "—") +
      ' · quarantine ' + V.esc(String(r.id)) + '</div></div>';
  }

  // Directory picker: people/groups BY NAME; clicking toggles the token in
  // the mono input (which stays the single source of truth and editable).
  function renderDirPicker() {
    var box = el("qr-dir");
    if (DIR === null) {
      box.innerHTML = '<div class="note" style="margin:0">principal directory unavailable — ' +
        'type token numbers below</div>';
      return;
    }
    if (!DIR.length) {
      box.innerHTML = '<div class="note" style="margin:0">this tenant has no principals on record yet — ' +
        'create people &amp; groups first <button id="qr-dir-go" style="margin-left:6px">Open People &amp; groups</button></div>';
      var go = el("qr-dir-go");
      if (go) go.onclick = function () { V.dialog("q-reingest-dialog").close(); V.show("principals"); };
      return;
    }
    var current = {};
    try { parseTokens(el("qr-vis").value).forEach(function (t) { current[t] = true; }); }
    catch (e) { /* unparsable input — no chips highlighted */ }
    var shown = DIR.slice(0, 40);
    box.innerHTML = '<div style="display:flex;flex-wrap:wrap;gap:4px">' +
      shown.map(function (p) {
        return '<button type="button" data-tok="' + Number(p.token) + '" ' +
          'class="' + (current[p.token] ? "good" : "") + '" ' +
          'style="padding:3px 10px;font-weight:400" title="token #' + Number(p.token) + '">' +
          V.esc(p.principal) + ' <span class="ref">#' + Number(p.token) + '</span></button>';
      }).join("") + '</div>' +
      (DIR.length > shown.length
        ? '<div class="note">showing ' + shown.length + ' of ' + DIR.length +
          ' — type further token numbers below</div>' : "");
    box.querySelectorAll("button[data-tok]").forEach(function (btn) {
      btn.onclick = function () {
        var tok = parseInt(btn.getAttribute("data-tok"), 10);
        var toks;
        try { toks = parseTokens(el("qr-vis").value); } catch (e) { toks = []; }
        var idx = toks.indexOf(tok);
        if (idx >= 0) toks.splice(idx, 1); else toks.push(tok);
        el("qr-vis").value = toks.join(", ");
        renderDirPicker();
      };
    });
  }

  function openReingest(r) {
    ACTIVE = r;
    el("qr-ctx").innerHTML = ctxLine(r);
    el("qr-vis").value = "";
    el("qr-vis-empty").checked = false;
    el("qr-conf").value = "";
    if (!qrTagsPicker) {
      qrTagsPicker = V.entityPicker(el("qr-tags"), {
        mode: "tags",           // emptyBehavior "teach": tagging is how an entity is born
        multiple: true,
        allowNew: true,
        emptyBehavior: "teach",
        placeholder: "account:acme",
        explainer: "these tag the record — they decide which entity views can retrieve it. They do not limit a scope.",
        tenantId: function () { return tenantNow || V.tenant(); },
      });
    } else {
      qrTagsPicker.clear();
      qrTagsPicker.refresh();
    }
    el("qr-content").value = "";
    el("qr-note").value = "";
    el("qr-result").innerHTML = "";
    V.clearErr("qr-err");
    el("qr-go").disabled = false;
    el("qr-cancel").textContent = "Cancel";
    renderDirPicker();
    el("qr-vis").oninput = renderDirPicker;
    V.dialog("q-reingest-dialog").open();
  }

  async function doReingest() {
    if (!ACTIVE) return;
    V.clearErr("qr-err");
    el("qr-result").innerHTML = "";
    var tokens;
    try {
      if (!tenantNow) throw new Error("no tenant — the action must name the tenant that owns the item");
      tokens = parseTokens(el("qr-vis").value);
      if (!tokens.length && !el("qr-vis-empty").checked) {
        throw new Error("say who can see it — pick people from the directory, or tick the explicit " +
          "nobody-can-see-it acknowledgement (fail-closed: that writes memory no one can read)");
      }
      if (tokens.length && el("qr-vis-empty").checked) {
        throw new Error("the nobody-can-see-it acknowledgement is ticked but people are also picked — " +
          "untick it or clear them so the intent is unambiguous");
      }
      if (!el("qr-conf").value) {
        throw new Error("choose a confidentiality ceiling — it is required and explicit; there is no default");
      }
    } catch (e) { V.err("qr-err", e); return; }

    var body = {
      tenant_id: tenantNow,
      visibility: tokens,
      confidentiality: el("qr-conf").value,
    };
    // value() = committed chips only — never in-progress typed text, never a
    // whitespace/comma split (ENTITY-PICKER.md §2.1). Empty ⇒ field omitted.
    var tags = qrTagsPicker ? qrTagsPicker.value() : [];
    if (tags.length) body.entity_tags = tags;
    var content = el("qr-content").value.trim();
    if (content) body.content = content;
    var note = el("qr-note").value.trim();
    if (note) body.note = note;

    var go = el("qr-go");
    go.disabled = true;
    try {
      var res = await V.api(
        "/v1/admin/quarantine/" + encodeURIComponent(ACTIVE.id) + "/reingest",
        { admin: true, json: body });
      RESOLVED[ACTIVE.id] = "reingested";
      renderCards();
      // The corrected record just landed — any new tag committed above now
      // exists; re-fetch so the directory shows it (born by usage).
      if (qrTagsPicker) qrTagsPicker.refresh();
      // Receipt — including the server's honesty flags: what the re-ingest
      // could NOT carry over is disclosed, never glossed.
      var flags = [];
      if (res && res.facts_unparseable_skipped) {
        flags.push("some structured facts in the payload did not parse and were <b>not</b> written — " +
          "skipped fail-closed, never guessed");
      }
      if (res && res.raw_text_truncated_at_capture) {
        flags.push("the raw text was truncated when it was captured (4096 chars) — the indexed text " +
          "came from that preserved prefix; supply a corrected extraction if the full text matters");
      }
      var named = tokens.map(function (t) {
        var hit = (DIR || []).filter(function (p) { return p.token === t; })[0];
        return hit ? V.esc(hit.principal) : "#" + t;
      }).join(", ");
      el("qr-result").innerHTML =
        '<div class="note" style="margin-top:10px;border-left:3px solid var(--green);padding-left:10px">' +
          V.stateChip("ok", "re-ingested") + ' with the permissions you supplied ' +
          V.provenanceBadge("admin-assigned") +
          '<dl class="kv">' +
            '<dt>now visible to</dt><dd>' + (named || "nobody (explicit empty set)") + '</dd>' +
            '<dt>episode</dt><dd>' + V.esc(String(res.episode_id || "—")) + '</dd>' +
            '<dt>chunks indexed</dt><dd>' + V.esc(String(res.chunks_indexed != null ? res.chunks_indexed : "—")) + '</dd>' +
            '<dt>facts written</dt><dd>' + V.esc(String(res.facts_written != null ? res.facts_written : "—")) + '</dd>' +
          '</dl>' +
          (flags.length ? '<div class="note" style="margin-top:6px">' + flags.join("<br>") + '</div>' : "") +
          '<div class="note" style="margin-top:6px">Audited as <span class="ref">quarantine_reingest</span> · ' +
            'the record of the refusal survives · original payload preserved verbatim.</div>' +
          '<div class="actions" style="justify-content:flex-start;margin-top:8px">' +
            '<button id="qr-see-audit">See it in the access audit</button></div>' +
        '</div>';
      el("qr-see-audit").onclick = function () {
        V.dialog("q-reingest-dialog").close();
        V.show("audit");
        V.reload("audit");
      };
      go.disabled = true;   // resolved — no double submit
      el("qr-cancel").textContent = "Close";
    } catch (e) {
      var prior = priorDisposition(e.message);
      if (prior) { RESOLVED[ACTIVE.id] = prior; renderCards(); }
      // Keep the dialog open: a 422 "nothing ingestible" points straight at
      // the corrected-extraction field; a 409 names the prior disposition.
      V.err("qr-err", e);
      go.disabled = false;
    }
  }

  /* ------------------------------------------------------------ dismiss */

  function openDismiss(r) {
    ACTIVE = r;
    el("qd-ctx").innerHTML = ctxLine(r);
    el("qd-note").value = "";
    V.clearErr("qd-err");
    el("qd-go").disabled = false;
    V.dialog("q-dismiss-dialog").open();
  }

  async function doDismiss() {
    if (!ACTIVE) return;
    V.clearErr("qd-err");
    if (!tenantNow) { V.err("qd-err", new Error("no tenant — the action must name the tenant that owns the item")); return; }
    var body = { tenant_id: tenantNow };
    var note = el("qd-note").value.trim();
    if (note) body.note = note;
    var go = el("qd-go");
    go.disabled = true;
    try {
      await V.api(
        "/v1/admin/quarantine/" + encodeURIComponent(ACTIVE.id) + "/dismiss",
        { admin: true, json: body });
      RESOLVED[ACTIVE.id] = "dismissed";
      V.dialog("q-dismiss-dialog").close();
      renderCards();
    } catch (e) {
      var prior = priorDisposition(e.message);
      if (prior) { RESOLVED[ACTIVE.id] = prior; renderCards(); }
      V.err("qd-err", e);
      go.disabled = false;
    }
  }

  /* ------------------------------------------------------------ export */

  function exportJson() {
    var rows = filtered();
    if (!rows.length) { V.err("q-err", new Error("nothing in the filtered window to export")); return; }
    V.clearErr("q-err");
    download("verity-quarantine-" + Date.now() + ".json", "application/json",
      JSON.stringify({
        source: "verity.quarantine_preview",
        schema: "verity.quarantine.v1",
        tenant_id: tenantNow,
        exported_at: new Date().toISOString(),
        build_hash: V.buildHash(),
        window_rows: rows.length,
        note: "Payloads Verity refused to index (no verifiable permissions). Invisible to recall by " +
              "design; nothing ambiguous was indexed. The only exits are re-ingest through a corrected " +
              "admin-supplied mapping (stamped admin-assigned) or dismiss (indexes nothing) — both " +
              "audited; the row survives either. The listing does not yet carry resolution status, so " +
              "already-resolved items may appear; resolution_this_session is this console's local " +
              "knowledge only.",
        events: rows.map(function (r) {
          return {
            id: r.id,
            webhook_id: r.webhook_id,
            reason: r.reason,
            reason_group: reasonGroup(r.reason),
            reason_plain: groupPlain(reasonGroup(r.reason)),
            at: r.at,
            resolution_this_session: RESOLVED[r.id] || null,
            payload: r.payload,   // FULL payload, never truncated
          };
        }),
      }, null, 2));
  }
})();
