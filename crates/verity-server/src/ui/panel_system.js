"use strict";
/* ==========================================================================
   panel_system.js — "What's running" (infrastructure status + control)
   --------------------------------------------------------------------------
   Autoloads GET /v1/admin/planes?tenant_id=<uuid> and renders each
   infrastructure plane as a labeled row with a plain-language status chip and
   a class-keyed action cell. tenant_id is REQUIRED (the knowledge worker's
   observed-activity proxy and its start/stop are per-space) — so this panel is
   tenant-scoped and teaches a no-space state instead of a cold Load button
   (LAW #3).

   THE LAW (UI-ACTIONS §0): the label and the plain-words meaning come FIRST;
   the status word is drawn from a closed set (on · off · degraded · not seen);
   endpoints stay in api-crumbs; loading / error / empty / starting / stopping
   states teach.

   The one real control (founder's ask): exactly one plane is startable from a
   running server — the knowledge extraction worker. The server marks it with
   class:"startable" + startable/stoppable booleans; the UI keys off THOSE, it
   never re-derives which planes are startable. A startable-off plane gets a
   Start button; a running one gets Stop; a command-only plane shows its
   copyable start_hint COMMAND (never a dead button); a config-only plane shows
   only its meaning. Start makes paid LLM calls, so it confirms the cost first
   and states that nothing auto-publishes — every proposal goes to the review
   queue. Errors from the two POSTs are the teaching moment: the server's
   verbatim fix shows in the dialog and IS the next action (missing venv/key/
   repo → the exact command to fix it, never a generic error).

   Honesty (fail-visible): a knowledge row is AUTHORITATIVE (pid, "started from
   this console", a real Stop) only when the server owns the child; otherwise
   it is an OBSERVED proxy, labeled "(observed)", with no Stop and a note that
   it was started outside this console. A 401 surfaces the admin-token hint
   verbatim — a locked admin plane is a real state, not an error to soften.
   ========================================================================== */
(function () {
  var V = window.Verity;

  var data = { planes: [], summary: null, checkedAt: "", err: null };
  var tenantNow = "";

  function el(id) { return V.$(id); }

  /* Map a status word → the visible-state chip (LAW #4):
       on       → green   "on"
       off      → grey    "off"
       degraded → amber   "degraded"
       unknown  → blue    "not seen"  (indeterminate — the honest middle) */
  function statusChip(status, labelOverride) {
    switch (String(status || "").toLowerCase()) {
      case "on": return V.stateChip("ok", labelOverride || "on");
      case "off": return V.stateChip("off", labelOverride || "off");
      case "degraded": return V.stateChip("attn", labelOverride || "degraded");
      default: return V.stateChip("wait", labelOverride || "not seen");
    }
  }

  /* A one-word summary chip for the toolbar. Prefer the server's own up/total
     count (it computed the same rows below), fall back to deriving from rows. */
  function summaryChip() {
    if (data.err) return V.stateChip("fail", "couldn't load");
    if (!data.planes.length) return V.stateChip("off", "nothing to show");
    var has = function (s) { return data.planes.some(function (p) { return String(p.status).toLowerCase() === s; }); };
    var s = data.summary;
    if (s && typeof s.up === "number" && typeof s.total === "number") {
      var label = s.up + " of " + s.total + " up";
      if (has("degraded")) return V.stateChip("attn", label + " · one degraded");
      return V.stateChip("ok", label);
    }
    if (has("degraded")) return V.stateChip("attn", "needs attention");
    if (has("unknown")) return V.stateChip("wait", "some parts not seen");
    if (has("off")) return V.stateChip("ok", "up (some parts off by choice)");
    return V.stateChip("ok", "all up");
  }

  function hint401(msg) {
    return /HTTP 401/.test(String(msg || ""))
      ? '<div class="note"><em>admin token required</em> — this deployment enforces one; set it in the session bar above (kept in this tab only).</div>'
      : "";
  }

  /* =========================================================== register */

  V.register({
    id: "system",

    mount: function () {
      var host = el("system-mount");
      if (!host) return;
      host.innerHTML =
        '<div class="toolbar">' +
          '<span id="sys-state"></span>' +
          '<span class="asof" id="sys-asof"></span>' +
          '<span class="spacer"></span>' +
          '<button id="sys-refresh">Refresh</button>' +
        "</div>" +
        '<div class="err" id="sys-err"></div>' +
        '<div id="sys-hint"></div>' +
        '<div id="sys-receipt"></div>' +
        '<div class="card">' +
          '<h2>The moving parts <span class="sub api-crumb">GET /v1/admin/planes</span></h2>' +
          '<div class="note" style="margin-top:0">Each row is one piece of Verity&rsquo;s machinery and whether it&rsquo;s up right now, read from what this server actually knows. ' +
            "The plain-English line says what it being on or off <b>means for you</b> &mdash; not just a light. " +
            "Where a piece is off, the last column shows how to turn it on: the knowledge worker has a <b>Start</b> button (this running server can spawn it); everything else shows the <b>command</b> to bring it up.</div>" +
          '<div id="sys-rows"></div>' +
        "</div>" +

        /* ---- cost-confirm before starting the knowledge worker ---- */
        '<div class="dialog-backdrop" id="sys-start-dialog"><div class="dialog" style="max-width:600px">' +
          "<h3>Start the knowledge worker?</h3>" +
          '<div class="note" style="margin-top:0">This turns on an LLM. Until you stop it, Verity reads your new memories with <b>Anthropic (Claude)</b> every 30 seconds and proposes facts. ' +
            "<b>This makes paid API calls against your Anthropic key</b> &mdash; cost scales with how much new memory arrives.</div>" +
          '<div class="note"><b>Nothing publishes automatically.</b> Every proposal lands in the <b>Knowledge review</b> queue for a human to publish or reject. (Auto-publish stays off.)</div>' +
          '<div class="note">Your key is read from <span class="ref">~/.verity-anthropic-key</span> on the server when the worker starts &mdash; never shown, never logged.<span class="api-crumb"> POST /v1/admin/planes/knowledge/start</span></div>' +
          '<div class="err" id="sys-start-err"></div>' +
          '<div class="actions">' +
            '<button id="sys-start-cancel">Cancel</button>' +
            '<button class="primary" id="sys-start-go">Start the worker</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- stop the knowledge worker (cheap, reversible) ---- */
        '<div class="dialog-backdrop" id="sys-stop-dialog"><div class="dialog" style="max-width:560px">' +
          "<h3>Stop the knowledge worker?</h3>" +
          '<div class="note" style="margin-top:0">It stops leasing new episodes immediately. Anything already proposed stays in the <b>Knowledge review</b> queue. You can start it again anytime.<span class="api-crumb"> POST /v1/admin/planes/knowledge/stop</span></div>' +
          '<div class="err" id="sys-stop-err"></div>' +
          '<div class="actions">' +
            '<button id="sys-stop-cancel">Cancel</button>' +
            '<button class="danger" id="sys-stop-go">Stop it</button>' +
          "</div>" +
        "</div></div>";

      el("sys-refresh").onclick = function () { V.reload("system"); };
      el("sys-start-cancel").onclick = function () { V.dialog("sys-start-dialog").close(); };
      el("sys-start-go").onclick = startWorker;
      el("sys-stop-cancel").onclick = function () { V.dialog("sys-stop-dialog").close(); };
      el("sys-stop-go").onclick = stopWorker;

      if (!V.tenant()) renderNoTenant();
    },

    // v2 AUTOLOAD — the router runs this when the tenant is known (LAW #3).
    load: function (_section, tenant) { return refresh(tenant); },

    onShow: function () { if (!V.tenant()) renderNoTenant(); },
  });

  /* =========================================================== no space */

  function renderNoTenant() {
    tenantNow = "";
    el("sys-state").innerHTML = V.stateChip("off", "no space");
    el("sys-asof").textContent = "";
    V.clearErr("sys-err");
    el("sys-hint").innerHTML = "";
    el("sys-receipt").innerHTML = "";
    el("sys-rows").innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a space (tenant) to see what&rsquo;s running</div>' +
        '<div class="et-body">The knowledge worker runs per space, so this screen needs to know which one. ' +
          "Pick a space in the session bar above (or mint a scope handle) &mdash; the space fills in and this screen loads itself.</div>" +
        '<div class="et-actions"><button class="primary" id="sys-teach-mint">Mint a scope handle</button></div>' +
      "</div>";
    var b = el("sys-teach-mint");
    if (b) b.onclick = function () { V.openMint(); };
    V.setCount("system", null);
  }

  /* =========================================================== loading */

  async function refresh(tenant) {
    tenant = tenant || V.tenant();
    if (!tenant) { renderNoTenant(); return; }
    tenantNow = tenant;
    el("sys-state").innerHTML = V.stateChip("wait", "checking…");
    el("sys-rows").innerHTML = '<div class="empty">Checking what&rsquo;s running&hellip;</div>';
    V.clearErr("sys-err");
    el("sys-hint").innerHTML = "";
    try {
      var res = await V.api("/v1/admin/planes?tenant_id=" + encodeURIComponent(tenant), { admin: true });
      data.planes = (res && Array.isArray(res.planes)) ? res.planes : [];
      data.summary = (res && res.summary) || null;
      data.checkedAt = (res && res.checked_at) || "";
      data.err = null;
    } catch (e) {
      data.planes = [];
      data.summary = null;
      data.err = e && e.message ? e.message : String(e);
    }
    render();
  }

  /* Rail count: planes an operator could bring up right now that are OFF —
     command-only planes that are off/unknown (a copyable command exists) plus
     any degraded plane. Config-off and knowledge-off are NOT nagged: config
     planes are off by choice, and starting knowledge costs money (deliberate,
     never a red badge). Derived from the SAME rows this panel renders. */
  function bringableCount() {
    return data.planes.filter(function (p) {
      var st = String(p.status).toLowerCase();
      if (st === "degraded") return true;
      return p.class === "command-only" && (st === "off" || st === "unknown");
    }).length;
  }

  function receipt(kind, html) {
    el("sys-receipt").innerHTML =
      '<div class="card" style="border-left:3px solid var(--state-' +
        (kind === "ok" ? "ok" : "attn") + ')">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip(kind) + "<span>" + html + "</span>" +
          '<span class="spacer" style="flex:1"></span>' +
          '<button id="sys-receipt-x">Dismiss</button>' +
        "</div></div>";
    var x = el("sys-receipt-x");
    if (x) x.onclick = function () { el("sys-receipt").innerHTML = ""; };
  }

  /* ------------------------------------------------ the action cell (LAW) */
  /* Keyed strictly off the server's class + startable/stoppable — the UI
     never decides which plane is startable. The no-dead-button rule:
       startable  → Start… (off & startable) or Stop (stoppable); if off but
                    NOT startable, the start_hint fix as a ref line, NO button.
       command-only → a copyable <code>start_hint</code> + Copy button, when
                    off/unknown; when on, a plain "—". NEVER a Start button.
       config-only → "—" (its meaning is the whole story). */
  function actionCell(p, i) {
    var st = String(p.status).toLowerCase();
    if (p.class === "startable") {
      if (p.stoppable) {
        return '<button class="danger sys-stop-btn" data-i="' + i + '">Stop</button>';
      }
      if (p.startable) {
        return '<button class="primary sys-start-btn" data-i="' + i + '">Start&hellip;</button>';
      }
      // Off but not startable here (missing repo/venv/key, or an untracked
      // worker is already observed running). The reason IS the action: show
      // the exact fix the server reported, never a dead button.
      if (p.start_hint) {
        return '<span class="ref" style="word-break:normal;overflow-wrap:break-word" title="what to fix before this server can start it">' +
          V.esc(p.start_hint) + "</span>";
      }
      if (st === "on") return '<span class="ref">running elsewhere — no Stop here</span>';
      return '<span class="ref">&mdash;</span>';
    }
    if (p.class === "command-only") {
      if ((st === "off" || st === "unknown") && p.start_hint) {
        return '<div class="sys-cmd"><code style="word-break:break-all">' + V.esc(p.start_hint) + "</code>" +
          ' <button class="sys-copy-btn" data-i="' + i + '" title="copy this command">Copy</button></div>';
      }
      return '<span class="ref">&mdash;</span>';
    }
    // config-only (and any unknown class): the meaning column is the story.
    return '<span class="ref">&mdash;</span>';
  }

  function render() {
    el("sys-state").innerHTML = summaryChip();
    el("sys-asof").textContent = data.checkedAt
      ? "checked " + V.fmtTime(data.checkedAt)
      : "checked " + new Date().toTimeString().slice(0, 8);

    if (data.err) {
      V.err("sys-err", new Error(data.err));
      el("sys-hint").innerHTML = hint401(data.err);
      el("sys-rows").innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Couldn&rsquo;t read what&rsquo;s running</div>' +
          '<div class="et-body">The status read didn&rsquo;t come back. If this deployment locks its admin screens, set your admin token in the session bar above, then Refresh. Otherwise the server may be restarting.</div>' +
          '<div class="et-actions"><button class="primary" id="sys-retry">Try again</button></div>' +
        "</div>";
      var r = el("sys-retry");
      if (r) r.onclick = function () { V.reload("system"); };
      V.setCount("system", null);
      return;
    }

    if (!data.planes.length) {
      el("sys-rows").innerHTML =
        '<div class="empty">No planes reported. That&rsquo;s unusual &mdash; this list is built from the server&rsquo;s own wiring, so an empty answer means the read returned nothing. Refresh to re-check.</div>';
      V.setCount("system", null);
      return;
    }

    V.setCount("system", bringableCount(), "infrastructure planes that are off and can be brought up");

    var body = data.planes.map(function (p, i) {
      // Knowledge worker only: an "(observed)" note under the detail when the
      // status is a proxy (a worker is running but this console doesn't own
      // it), so a green chip is never read as "started here". The server
      // already labels the detail; this repeats the ownership fact plainly.
      var extra = "";
      if (p.class === "startable" && String(p.status).toLowerCase() === "on" && p.authority === "observed") {
        extra = '<div class="ref" style="word-break:normal;overflow-wrap:break-word">observed &mdash; started outside this console, so there&rsquo;s no Stop button here</div>';
      }
      return "<tr>" +
        "<td><b>" + V.esc(p.label || p.name || "(unnamed)") + "</b>" +
          '<div class="ref">' + V.esc(p.name || "") + "</div></td>" +
        "<td>" + statusChip(p.status) + "</td>" +
        '<td style="overflow-wrap:break-word;word-break:normal;max-width:520px">' +
          V.esc(p.detail || "") + extra + "</td>" +
        '<td style="max-width:320px">' + actionCell(p, i) + "</td>" +
      "</tr>";
    }).join("");

    el("sys-rows").innerHTML =
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>what it is</th><th>state</th><th>what it means for you</th><th>turn it on</th>" +
      "</tr></thead><tbody>" + body + "</tbody></table></div>" +
      '<div class="note">A green <b>on</b> means it&rsquo;s working now; grey <b>off</b> means it&rsquo;s not running (sometimes by choice, as each row explains); amber <b>degraded</b> means it&rsquo;s up but not at full strength; <b>not seen</b> means the server can&rsquo;t tell. ' +
        "The <b>knowledge extraction worker</b> is the one piece this running server can start for you (it makes paid LLM calls, so Start confirms first and nothing auto-publishes). " +
        "Everything else that is off is brought up with the <b>command</b> shown &mdash; a Docker container or a server restart with the right setting, which a running server can&rsquo;t do to itself.</div>";

    // Wire the per-row buttons.
    var host = el("sys-rows");
    Array.prototype.forEach.call(host.querySelectorAll(".sys-start-btn"), function (btn) {
      btn.onclick = function () { openStartDialog(); };
    });
    Array.prototype.forEach.call(host.querySelectorAll(".sys-stop-btn"), function (btn) {
      btn.onclick = function () { openStopDialog(); };
    });
    Array.prototype.forEach.call(host.querySelectorAll(".sys-copy-btn"), function (btn) {
      btn.onclick = function () {
        var p = data.planes[Number(btn.getAttribute("data-i"))];
        var cmd = p && p.start_hint ? p.start_hint : "";
        try { navigator.clipboard.writeText(cmd); } catch (e) { /* clipboard blocked — nothing to fall back to safely */ }
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      };
    });
  }

  /* ===================================================== start / stop */

  function openStartDialog() {
    if (!tenantNow) { V.openMint(); return; }
    V.clearErr("sys-start-err");
    el("sys-start-go").disabled = false;
    el("sys-start-go").textContent = "Start the worker";
    V.dialog("sys-start-dialog").open();
  }

  async function startWorker() {
    if (!tenantNow) { V.err("sys-start-err", new Error("pick a space first — the worker runs per space")); return; }
    V.clearErr("sys-start-err");
    var btn = el("sys-start-go");
    btn.disabled = true;
    btn.textContent = "Starting…";
    try {
      var res = await V.api("/v1/admin/planes/knowledge/start", { json: { tenant_id: tenantNow }, admin: true });
      V.dialog("sys-start-dialog").close();
      if (res && res.already_running) {
        receipt("attn", "Already running (pid " + V.esc(res.pid) + ") &mdash; nothing to do. This server was already leasing new memories.");
      } else {
        receipt("ok", "Knowledge worker started (pid " + V.esc(res && res.pid) + "). It&rsquo;s reading new memories with Claude and proposing facts into the <b>Knowledge review</b> queue &mdash; nothing publishes on its own.");
      }
      V.reload("system");
    } catch (e) {
      // The server's verbatim fix (missing venv/key/repo → the exact command)
      // IS the next action — keep the dialog open, re-enable, show it plainly.
      V.err("sys-start-err", e);
      btn.disabled = false;
      btn.textContent = "Start the worker";
    }
  }

  function openStopDialog() {
    V.clearErr("sys-stop-err");
    el("sys-stop-go").disabled = false;
    el("sys-stop-go").textContent = "Stop it";
    V.dialog("sys-stop-dialog").open();
  }

  async function stopWorker() {
    if (!tenantNow) { V.err("sys-stop-err", new Error("pick a space first")); return; }
    V.clearErr("sys-stop-err");
    var btn = el("sys-stop-go");
    btn.disabled = true;
    btn.textContent = "Stopping…";
    try {
      var res = await V.api("/v1/admin/planes/knowledge/stop", { json: { tenant_id: tenantNow }, admin: true });
      V.dialog("sys-stop-dialog").close();
      if (res && res.stopped) {
        receipt("ok", "Stopped the knowledge worker (pid " + V.esc(res.pid) + "). Anything already proposed stays in the <b>Knowledge review</b> queue. Start it again anytime.");
      } else {
        receipt("attn", V.esc((res && res.note) ||
          "Nothing to stop — this console doesn't own a worker. If one is running it was started outside this console; stop it there."));
      }
      V.reload("system");
    } catch (e) {
      V.err("sys-stop-err", e);
      btn.disabled = false;
      btn.textContent = "Stop it";
    }
  }
})();
