"use strict";
/* ==========================================================================
   panel_knowledge.js — Knowledge review (v2 rebuild, UI-ACTIONS §5)
   --------------------------------------------------------------------------
   Reads / writes:
     • GET  /v1/knowledge?tenant_id            — every lesson (admin-token);
       the rail count is derived from THIS query (eligible, plus candidates
       at/above the support floor — the same predicate the cards' "awaiting
       your review" chip uses) — never a separate estimate.
     • GET  /v1/admin/knowledge/{id}?tenant_id — one lesson's full story:
       support, de-identification gate, evidence lineage (audit-scope-only).
     • GET  /v1/admin/principals?tenant_id&after_token&limit — the NAMED
       people & groups directory feeding the publish picker (N5). Keyset-
       paginated; truncation is disclosed, never hidden.
     • POST /v1/knowledge/{id}/publish — THE human gate. visibility is
       REQUIRED with NO default (omission refuses, verbatim server 422s
       surface); k_min is clamped ≥3 client-side for honesty and re-clamped
       by the server as the authority.
     • POST /v1/admin/knowledge/{id}/reject — reason REQUIRED here (house
       rule); the decision is remembered so the lesson never resurrects.

   THE LAW, applied:
     • lesson cards read in plain words ("Learned across 3 customers: …" /
       "Waiting: only 1 customer supports this so far — needs 3");
     • lifecycle as state chips: proposed → gathering support → awaiting
       your review → published (quarantined/rejected shown as honest exits);
     • jargon (status enums, support_tier, distinct_entities, endpoints)
       lives ONLY in .dc-meta mono lines and card h2 .sub;
     • autoloads when the tenant is known; every empty state teaches;
     • provenance firewall kept: exact counts admin-only, the agent-facing
       bucket disclosed as a dashed (probabilistic-style) coarse chip;
     • NO un-publish exists — the retraction seam stays disabled and honest.
   ========================================================================== */
(function () {
  var V = window.Verity;

  /* ------------------------------------------------------------ state */

  var data = { items: [], byId: {}, loadedAt: 0 };
  var view = "review"; // "review" (candidate+eligible) | "all"
  var tenantNow = "";
  var current = { id: "", statement: "", status: "", item: null };
  var dir = { state: "idle", rows: [], truncated: false, error: "" };
  var pubSel = {}; // token(number as string) -> principal name

  function el(id) { return V.$(id); }

  function wire(host, sel, fn) {
    var nodes = host.querySelectorAll(sel);
    for (var i = 0; i < nodes.length; i++) {
      (function (n) { n.onclick = function () { fn(n); }; })(nodes[i]);
    }
  }

  /* ------------------------------------------------------------ plain words */

  function isWaiting(it) {
    var s = String(it.status || "").toLowerCase();
    return s === "candidate" || s === "eligible";
  }

  // A decision is actually possible — the SAME predicate lifeChip uses for
  // "awaiting your review". The rail badge, tab count, and state chip all
  // count with this, so the number never promises a decision the cards refuse.
  function isActionable(it) {
    var s = String(it.status || "").toLowerCase();
    return s === "eligible" || (s === "candidate" && kSupport(it).pass);
  }

  // k-support gate math — DISPLAY only; the server is the authority.
  function kSupport(it) {
    var d = it.distinct_entities, w = it.writer_count;
    var entOk = d != null && d >= 3;
    var writerOk = (w != null && w >= 2) || !!it.has_tier1_evidence;
    var catOk = (it.categories || []).length >= 1;
    return { entOk: entOk, writerOk: writerOk, catOk: catOk, pass: entOk && writerOk && catOk,
      d: d == null ? 0 : Number(d), w: w == null ? 0 : Number(w) };
  }

  // Tooltip for a publish button the privacy floor keeps disabled — built
  // from the live numbers, so it never contradicts the card's own sentence.
  function subFloorTitle(k) {
    return "Cannot publish yet — only " + k.d + " customer" + (k.d === 1 ? " supports" : "s support") +
      " this and 3 are required (privacy floor). Reject is still available.";
  }

  // The coarse bucket an agent would see (provenance firewall) — exact
  // counts never leave this admin surface.
  function agentBucket(it) {
    var d = it.distinct_entities;
    if (d == null || d < 3) return null;
    if (d >= 10) return "extensive";
    if (d >= 5) return "many";
    return "several";
  }

  // Lifecycle in plain words. candidate below the support floor is still
  // "gathering support"; at/above the floor it needs a human.
  function lifeChip(it) {
    var s = String(it.status || "").toLowerCase();
    if (s === "candidate") {
      return kSupport(it).pass
        ? V.stateChip("attn", "awaiting your review")
        : V.stateChip("wait", "gathering support");
    }
    if (s === "eligible") return V.stateChip("attn", "awaiting your review");
    if (s === "published") return V.stateChip("ok", "published");
    if (s === "quarantined") return V.stateChip("fail", "held back — identifying details");
    if (s === "rejected") return V.stateChip("off", "rejected by a person");
    if (s === "invalidated") return V.stateChip("off", "withdrawn — sources forgotten");
    return V.stateChip("off", s || "unknown");
  }

  // The one-sentence "why this card looks the way it does".
  function supportSentence(it) {
    var s = String(it.status || "").toLowerCase();
    var k = kSupport(it);
    var d = k.d, w = k.w;
    var ep = it.episode_count == null ? null : Number(it.episode_count);
    if (s === "quarantined") {
      return "<b>Held back before review:</b> this lesson may identify a specific customer, so Verity refused to consider it." +
        (it.quarantine_reason ? " Reason on record: <b>" + V.esc(it.quarantine_reason) + "</b>." : "");
    }
    if (s === "rejected") {
      return "<b>Rejected by a reviewer.</b> The decision is remembered — the same lesson will not be proposed again.";
    }
    if (s === "invalidated") {
      return "<b>Withdrawn automatically:</b> the conversations that supported this lesson were forgotten, so the lesson was invalidated with them.";
    }
    var learned = d > 0
      ? "Learned across <b>" + d + " customer" + (d === 1 ? "" : "s") + "</b>" +
        (ep ? " in " + ep + " conversation" + (ep === 1 ? "" : "s") : "") +
        (w ? ", written down by " + w + " independent writer" + (w === 1 ? "" : "s") : "") +
        (it.has_tier1_evidence ? " (includes an authoritative source)" : "")
      : "No supporting customers on record yet";
    if (s === "published") {
      return learned + ". <b>Published</b>" +
        (it.published_at ? " " + V.esc(V.timeAgo(it.published_at)) : "") +
        " — visible only to the people it was published to.";
    }
    if (k.pass) return learned + " — <b>enough independent support to publish</b>. Your call.";
    var needs = [];
    if (!k.entOk) needs.push("<b>" + Math.max(0, 3 - d) + " more customer" + ((3 - d) === 1 ? "" : "s") + "</b> (3 required)");
    if (!k.writerOk) needs.push("a <b>second independent writer</b> or an authoritative source");
    if (!k.catOk) needs.push("a <b>category</b>");
    var sofar = d === 0 ? "no customers support this yet"
      : "only " + d + " customer" + (d === 1 ? " supports" : "s support") + " this so far";
    return "<b>Waiting:</b> " + sofar + " — still needs " + needs.join(" and ") + ". It cannot be published before then.";
  }

  // Named-principal chip: "group:sales" → sales (group) · "user:alice@…" →
  // alice@… (person). The raw token renders as mono-small secondary text.
  function principalChip(principal) {
    var p = String(principal || "");
    var i = p.indexOf(":");
    if (i < 0) return V.entityChip(p);
    var kind = p.slice(0, i);
    var word = kind === "user" ? "person" : kind;
    return V.entityChip(p.slice(i + 1), word);
  }

  /* =========================================================== mount */

  V.register({
    id: "knowledge",
    mount: function () {
      var host = el("knowledge-mount");
      if (!host) return;
      host.innerHTML =
        /* ---- toolbar ---- */
        '<div class="toolbar">' +
          '<span class="seg">' +
            '<button id="know-view-review" class="on">Needs your review</button>' +
            '<button id="know-view-all">All lessons</button>' +
          "</span>" +
          '<span id="know-state"></span>' +
          '<span class="asof" id="know-asof"></span>' +
          '<span class="spacer"></span>' +
          '<button id="know-refresh" title="GET /v1/knowledge — reloads the same query the rail count uses">Refresh</button>' +
        "</div>" +
        '<div class="err" id="know-err"></div>' +
        '<div id="know-receipt"></div>' +
        '<div id="know-teach"></div>' +
        '<div id="know-out"></div>' +

        /* ---- lesson detail drawer ---- */
        '<div class="dialog-backdrop" id="know-drawer"><div class="dialog" style="max-width:820px">' +
          '<h3 id="know-drawer-title">Lesson</h3>' +
          '<div id="know-drawer-body"></div>' +
          '<div class="actions">' +
            '<button class="good" id="know-drawer-publish">Publish to people&hellip;</button>' +
            '<button class="danger" id="know-drawer-reject">Reject&hellip;</button>' +
            '<button id="know-drawer-close">Close</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- publish dialog (THE human gate — named audience, no default) ---- */
        '<div class="dialog-backdrop" id="know-pub-dialog"><div class="dialog" style="max-width:660px">' +
          "<h3>Publish this lesson</h3>" +
          '<div id="know-pub-stmt" style="font-size:var(--fs-md);font-weight:650;color:var(--bright)"></div>' +
          '<div class="note" id="know-pub-support" style="margin-top:6px"></div>' +
          '<div class="note" style="margin-top:8px"><b>Publishing is one-way.</b> Everyone you pick below will see this ' +
            "lesson in their scoped recalls, and there is <b>no un-publish</b> — retraction happens only through " +
            "Erasure &amp; data export.</div>" +
          '<div class="card" style="margin-top:10px">' +
            '<h2>Who can see it (visibility) <span class="sub">required<span class="api-crumb"> · GET /v1/admin/principals</span></span></h2>' +
            '<div class="note" style="margin-top:0">Pick the keys (principals) — the people and shared keys — this lesson becomes visible to. ' +
              "Picking <b>no one</b> refuses to publish — there is no default audience, here or anywhere.</div>" +
            '<input type="text" id="know-pub-filter" placeholder="filter people &amp; groups&hellip;" autocomplete="off" style="margin-top:6px">' +
            '<div id="know-pub-dir" style="max-height:220px;overflow-y:auto;margin-top:6px"></div>' +
            '<div class="api-crumb-block" style="margin-top:8px"><label for="know-pub-raw">raw key tokens ' +
              '<span style="font-weight:400">(dev mode — comma-separated integers, for keys with no name in the directory)</span></label>' +
              '<input type="text" id="know-pub-raw" placeholder="e.g. 11, 1001" autocomplete="off" spellcheck="false"></div>' +
            '<div class="note" id="know-pub-count" style="margin-top:6px"></div>' +
          "</div>" +
          '<div style="margin-top:10px"><label for="know-pub-kmin">privacy floor &mdash; fewest supporting customers allowed (the ceiling here is a floor: the fewest supporters a lesson may ever be published with)</label>' +
            '<input type="number" id="know-pub-kmin" min="3" step="1" value="3" style="max-width:130px">' +
            '<div class="note">Minimum <b>3</b> &mdash; and the server re-clamps it even if a smaller number is sent: ' +
              "at 2, either supporting customer could infer the other&rsquo;s situation." +
              '<span class="api-crumb"> <span class="ref">k_min · POST /v1/knowledge/{id}/publish</span></span></div></div>' +
          '<div class="err" id="know-pub-err"></div>' +
          '<div class="actions">' +
            '<button id="know-pub-cancel">Cancel</button>' +
            '<button class="good" id="know-pub-go" disabled>Publish</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- reject dialog (reason required — the decision is remembered) ---- */
        '<div class="dialog-backdrop" id="know-rej-dialog"><div class="dialog" style="max-width:560px">' +
          "<h3>Reject this lesson?</h3>" +
          '<div id="know-rej-stmt" style="font-size:var(--fs-md);font-weight:650;color:var(--bright)"></div>' +
          '<div class="note" style="margin-top:8px">Rejecting is <b>remembered</b>: the same lesson will not be proposed ' +
            "again. Only a lesson still waiting for review can be rejected — a published one is refused (retraction is " +
            "Erasure &amp; data export&rsquo;s job)." +
            '<span class="api-crumb"> <span class="ref">POST /v1/admin/knowledge/{id}/reject</span></span></div>' +
          '<div style="margin-top:10px"><label for="know-rej-reason">why <span style="font-weight:400">(required &mdash; stored with the decision, on the record)</span></label>' +
            '<input type="text" id="know-rej-reason" placeholder="e.g. too specific to one industry to generalize" autocomplete="off"></div>' +
          '<div class="err" id="know-rej-err"></div>' +
          '<div class="actions">' +
            '<button id="know-rej-cancel">Cancel</button>' +
            '<button class="danger" id="know-rej-go" disabled>Reject &mdash; remembered forever</button>' +
          "</div>" +
        "</div></div>";

      /* ---- wiring ---- */
      el("know-view-review").onclick = function () { switchView("review"); };
      el("know-view-all").onclick = function () { switchView("all"); };
      el("know-refresh").onclick = function () { V.reload("knowledge"); };
      el("know-drawer-close").onclick = function () { V.dialog("know-drawer").close(); };
      el("know-drawer-publish").onclick = function () { if (current.id) openPublish(current.id); };
      el("know-drawer-reject").onclick = function () { if (current.id) openReject(current.id); };
      el("know-pub-cancel").onclick = function () { V.dialog("know-pub-dialog").close(); };
      el("know-pub-go").onclick = submitPublish;
      el("know-pub-filter").oninput = renderDir;
      el("know-pub-raw").oninput = updatePubCount;
      el("know-rej-cancel").onclick = function () { V.dialog("know-rej-dialog").close(); };
      el("know-rej-go").onclick = submitReject;
      el("know-rej-reason").oninput = function () {
        el("know-rej-go").disabled = !el("know-rej-reason").value.trim();
      };

      if (!V.tenant()) renderNoTenant();
    },

    /* v2 AUTOLOAD — the router runs this once a tenant is known. */
    load: function (_section, tenant) { return loadAll(tenant); },

    onShow: function () {
      var p = V.navParams();
      if (p && p.view) switchView(p.view === "all" ? "all" : "review");
      if (!V.tenant()) renderNoTenant();
    },
  });

  /* =========================================================== loading */

  function renderNoTenant() {
    var teach = el("know-teach");
    if (!teach) return;
    el("know-out").innerHTML = "";
    el("know-state").innerHTML = V.stateChip("off", "no space");
    teach.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a space (tenant) to see its lessons</div>' +
        '<div class="et-body">Paste a space id in the session bar above, or mint a scope handle &mdash; the space ' +
          "fills in automatically and this screen loads itself.</div>" +
        '<div class="et-actions"><button class="primary" id="know-teach-mint">Mint a scope handle</button></div>' +
      "</div>";
    el("know-teach-mint").onclick = function () { V.openMint(); };
  }

  async function loadAll(tenant) {
    tenantNow = tenant;
    V.clearErr("know-err");
    el("know-teach").innerHTML = "";
    el("know-state").innerHTML = V.stateChip("wait", "loading");
    try {
      var res = await V.api("/v1/knowledge?tenant_id=" + encodeURIComponent(tenant), { admin: true });
      data.items = (res && res.items) || [];
      data.byId = {};
      data.items.forEach(function (it) { data.byId[it.id] = it; });
      data.loadedAt = Date.now();
      // Rail count = the SAME query + predicate the cards' "awaiting your
      // review" chip uses — never a number the buttons then refuse.
      V.setCount("knowledge", data.items.filter(isActionable).length);
      renderAll();
    } catch (e) {
      el("know-state").innerHTML = V.stateChip("fail");
      var msg = String((e && e.message) || e);
      if (msg.indexOf("400") !== -1 && msg.indexOf("UUID parsing failed") !== -1) {
        // A space NAME was pasted where the id belongs — say so in plain
        // words first; the verbatim server error stays, dimmed, below.
        var errEl = el("know-err");
        errEl.innerHTML =
          "That looks like a space name, not a space id &mdash; Verity needs the id " +
          "(it looks like 019f53b8-&hellip;). Pick the space from the menu in the session bar " +
          "and this screen reloads itself." +
          '<div style="color:var(--dim);margin-top:4px">' + V.esc(msg) + "</div>";
        errEl.classList.add("on");
      } else {
        V.err("know-err", e);
      }
      if (msg.indexOf("401") !== -1) {
        el("know-teach").innerHTML =
          '<div class="note">This read needs the admin token &mdash; paste it in the session bar above ' +
          "(it lives in this tab only and is never stored).</div>";
      }
    }
  }

  function renderAll() {
    var actionable = data.items.filter(isActionable);
    var gathering = data.items.filter(function (it) { return isWaiting(it) && !isActionable(it); });
    if (actionable.length) {
      el("know-state").innerHTML = V.stateChip("attn",
        actionable.length + " lesson" + (actionable.length === 1 ? "" : "s") + " awaiting review");
    } else if (gathering.length) {
      el("know-state").innerHTML = V.stateChip("wait",
        "0 need a decision · " + gathering.length + " still gathering support");
    } else {
      el("know-state").innerHTML = V.stateChip("ok", "queue clear");
    }
    el("know-asof").textContent =
      actionable.length + " need a decision · " + data.items.length + " total · checked " +
      new Date().toTimeString().slice(0, 8);
    el("know-view-review").textContent = "Needs your review" + (actionable.length ? " (" + actionable.length + ")" : "");
    el("know-view-all").textContent = "All lessons" + (data.items.length ? " (" + data.items.length + ")" : "");
    renderList();
  }

  function switchView(v) {
    view = v === "all" ? "all" : "review";
    el("know-view-review").className = view === "review" ? "on" : "";
    el("know-view-all").className = view === "all" ? "on" : "";
    if (data.loadedAt) renderList();
  }

  /* =========================================================== the list */

  function renderList() {
    var host = el("know-out");
    var actionable = data.items.filter(isActionable);
    var gathering = data.items.filter(function (it) { return isWaiting(it) && !isActionable(it); });
    // Review view = decidable lessons first, sub-floor waiters below a
    // dimmed divider — visible, but never counted as needing a decision.
    var rows = view === "review" ? actionable.concat(gathering) : data.items;

    if (!rows.length) {
      if (!data.items.length) {
        // Species A — nothing proposed yet: teach where lessons come from.
        host.innerHTML =
          '<div class="empty-teach sp-a">' +
            '<div class="et-title">No lessons proposed yet</div>' +
            '<div class="et-body">A lesson is a pattern Verity notices across several customers&rsquo; ' +
              "conversations. Verity proposes them automatically in the background (agents can also propose one" +
              "<span class=\"api-crumb\"> &mdash; POST /v1/knowledge</span>); every proposal stops here for a person " +
              "&mdash; nothing publishes itself. To give Verity something to learn from, start with " +
              "<b>Add memory</b>.</div>" +
            '<div class="et-actions"><button class="primary" id="know-empty-check">Check again</button></div>' +
          "</div>";
        el("know-empty-check").onclick = function () { V.reload("knowledge"); };
        return;
      }
      // Species C — the review queue is drained, with evidence.
      var byStatus = {};
      data.items.forEach(function (it) {
        var s = String(it.status || "").toLowerCase();
        byStatus[s] = (byStatus[s] || 0) + 1;
      });
      var evidence = [];
      if (byStatus.published) evidence.push(byStatus.published + " published");
      if (byStatus.rejected) evidence.push(byStatus.rejected + " rejected");
      if (byStatus.quarantined) evidence.push(byStatus.quarantined + " held back");
      if (byStatus.invalidated) evidence.push(byStatus.invalidated + " withdrawn");
      host.innerHTML =
        '<div class="empty-teach sp-c">' +
          '<div class="et-title">Nothing awaiting your review</div>' +
          '<div class="et-body">Every proposed lesson has been decided by a person &mdash; ' +
            V.esc(evidence.join(" · ") || "0 on record") +
            " · checked " + new Date().toTimeString().slice(0, 8) +
            ". Publishing stays a human gate; new proposals will stop here the moment they arrive.</div>" +
          '<div class="et-actions"><button id="know-empty-all">See all ' + data.items.length + " lesson" +
            (data.items.length === 1 ? "" : "s") + " &rsaquo;</button></div>" +
        "</div>";
      el("know-empty-all").onclick = function () { switchView("all"); };
      return;
    }

    // Longest-waiting flag: display heuristic only (threshold disclosed in
    // the tooltip), never a re-sort — server order is rendered as-is.
    var maxWait = 0;
    rows.forEach(function (it) {
      if (!isWaiting(it)) return;
      var t = Date.parse(it.first_seen);
      if (isFinite(t)) { var w = (Date.now() - t) / 1000; if (w > maxWait) maxWait = w; }
    });
    var flagActive = maxWait >= 86400; // amber only past 1 day — disclosed below

    var card = function (it) { return lessonCard(it, flagActive, maxWait); };
    if (view === "review" && gathering.length) {
      host.innerHTML = actionable.map(card).join("") +
        '<div style="margin:14px 0 8px;padding-top:8px;border-top:1px solid var(--border);color:var(--dim)">' +
          "Gathering support &mdash; no decision possible yet (" + gathering.length + ")</div>" +
        gathering.map(card).join("");
    } else {
      host.innerHTML = rows.map(card).join("");
    }
    wire(host, ".know-detail", function (btn) { openDetail(btn.getAttribute("data-id")); });
    wire(host, ".know-pub-open", function (btn) { openPublish(btn.getAttribute("data-id")); });
    wire(host, ".know-rej-open", function (btn) { openReject(btn.getAttribute("data-id")); });
  }

  // One lesson → one readable card.
  function lessonCard(it, flagActive, maxWait) {
    var s = String(it.status || "").toLowerCase();
    var actionable = s === "candidate" || s === "eligible";
    var waitSecs = null;
    var t = Date.parse(it.first_seen);
    if (isFinite(t)) waitSecs = (Date.now() - t) / 1000;
    var oldest = flagActive && actionable && waitSecs != null && Math.abs(waitSecs - maxWait) < 1;

    var chips = lifeChip(it);
    if (actionable && waitSecs != null) {
      chips += ' <span class="badge b-kind"' +
        (oldest ? ' style="color:var(--amber);border-color:var(--amber-line);background:var(--amber-soft)"' : "") +
        ' title="time since this lesson was proposed' +
        (oldest ? " — the longest-waiting lesson (over a day); decide it so it is never buried" : "") +
        '">waiting ' + V.esc(V.fmtAge(waitSecs)) + "</span>";
    }
    chips += (it.categories || []).map(function (c) { return " " + V.kindBadge(c); }).join("");

    // The publish button obeys the same floor the support sentence states:
    // sub-floor candidate/eligible lessons render it disabled, never green-lit.
    var k = kSupport(it);
    var pubBtn = k.pass
      ? '<button class="good know-pub-open" data-id="' + V.esc(it.id) + '" ' +
          'title="opens the publish gate — you pick the named people and groups; there is no default audience">' +
          "Publish to people&hellip;</button>"
      : '<button class="good" disabled title="' + V.esc(subFloorTitle(k)) + '">Publish to people&hellip;</button>';
    var actions = actionable
      ? pubBtn +
        '<button class="danger know-rej-open" data-id="' + V.esc(it.id) + '" ' +
          'title="refuses this lesson with a reason — remembered so it will not be proposed again">' +
          "Reject&hellip;</button>" +
        '<button class="know-detail" data-id="' + V.esc(it.id) + '">See the evidence</button>'
      : '<button class="know-detail" data-id="' + V.esc(it.id) + '">See the full story</button>';

    return '<div class="decision-card' + (oldest ? " dc-flag" : "") + '">' +
      '<div class="dc-topline">' + chips + "</div>" +
      '<div class="dc-question">' +
        (it.statement ? V.esc(it.statement)
          : '<span style="color:var(--dim);font-weight:400">no statement on record</span>') + "</div>" +
      '<div class="dc-evidence">' + supportSentence(it) + "</div>" +
      '<div class="dc-meta">' + V.esc(it.id) + " · status: " + V.esc(s) +
        " · customers: " + V.esc(it.distinct_entities == null ? "—" : it.distinct_entities) +
        " · independent writers: " + V.esc(it.writer_count == null ? "—" : it.writer_count) +
        " · evidence tier: " + V.esc(it.support_tier || "—") +
        seenAtMeta(it) +
        (it.merge_reason ? " · merged because: " + V.esc(it.merge_reason) : "") +
        '<span class="api-crumb"> · GET /v1/admin/knowledge/{id}</span></div>' +
      '<div class="dc-actions">' + actions + "</div>" +
    "</div>";
  }

  // Byte-identical statements are told apart by where they were seen —
  // "account:acme" renders name-first as "seen at: acme (account)".
  function seenAtMeta(it) {
    var e = (it.evidence && it.evidence[0] && it.evidence[0].entity) || "";
    if (!e) return "";
    var p = String(e), i = p.indexOf(":");
    return " · seen at: " + (i < 0 ? V.esc(p) : V.esc(p.slice(i + 1)) + " (" + V.esc(p.slice(0, i)) + ")");
  }

  /* =========================================================== detail drawer */

  function setDrawerActions(item) {
    var s = item == null ? null : String(item.status || "").toLowerCase();
    var actionable = s === "candidate" || s === "eligible";
    var k = item == null ? null : kSupport(item);
    var pub = el("know-drawer-publish"), rej = el("know-drawer-reject");
    pub.disabled = !actionable || !(k && k.pass);
    rej.disabled = !actionable;
    if (s === "published") {
      pub.title = "Already published — there is no un-publish; retraction is Erasure & data export.";
      rej.title = "A published lesson cannot be rejected — retraction is Erasure & data export's job.";
    } else if (!actionable && s != null) {
      pub.title = "Only a lesson still waiting for review can be published (this one is " + s + ").";
      rej.title = "Only a lesson still waiting for review can be rejected (this one is " + s + ").";
    } else if (actionable && !k.pass) {
      // Same privacy-floor guard the cards apply — Reject stays available.
      pub.title = subFloorTitle(k);
      rej.title = "refuses this lesson with a reason — remembered so it will not be proposed again";
    } else {
      pub.title = "opens the publish gate — you pick the named people and groups; there is no default audience";
      rej.title = "refuses this lesson with a reason — remembered so it will not be proposed again";
    }
  }

  async function openDetail(id) {
    var body = el("know-drawer-body");
    current = { id: id, statement: "", status: "", item: null };
    el("know-drawer-title").textContent = "Lesson";
    body.innerHTML = '<div class="note">loading&hellip;<span class="api-crumb"> <span class="ref">GET /v1/admin/knowledge/' + V.esc(id) + "</span></span></div>";
    setDrawerActions(null);
    V.dialog("know-drawer").open();
    try {
      var item = await V.api(
        "/v1/admin/knowledge/" + encodeURIComponent(id) + "?tenant_id=" + encodeURIComponent(tenantNow),
        { admin: true });
      current = { id: id, statement: item.statement || "", status: item.status, item: item };
      setDrawerActions(item);
      renderDetail(item);
    } catch (e) {
      body.innerHTML = '<div class="err on">' + V.esc((e && e.message) || String(e)) + "</div>";
    }
  }

  // The lifecycle as a strip of plain state chips: done → current → not yet.
  // Quarantine/rejection/withdrawal render as the honest exits they are.
  function lifeStrip(it) {
    var s = String(it.status || "").toLowerCase();
    var arrow = ' <span style="color:var(--faint)">&rarr;</span> ';
    if (s === "quarantined") {
      return V.stateChip("ok", "proposed") + arrow + V.stateChip("fail", "held back — identifying details");
    }
    if (s === "rejected") {
      return V.stateChip("ok", "proposed") + arrow + V.stateChip("off", "rejected by a person");
    }
    if (s === "invalidated") {
      return V.stateChip("ok", "proposed") + arrow + V.stateChip("off", "withdrawn — sources forgotten");
    }
    var stage = s === "published" ? 3 : (s === "eligible" || kSupport(it).pass) ? 2 : 1;
    var steps = [
      ["proposed", "ok"],
      ["gathering support", "wait"],
      ["awaiting your review", "attn"],
      ["published", "ok"],
    ];
    return steps.map(function (st, i) {
      if (i < stage) return V.stateChip("ok", st[0]);
      if (i === stage) return V.stateChip(st[1], st[0]);
      return V.stateChip("off", st[0]);
    }).join(arrow);
  }

  function renderDetail(item) {
    var body = el("know-drawer-body");
    var k = kSupport(item);
    var bucket = agentBucket(item);
    var gate = item.deid_gate || {};
    var deidPassed = gate.passed !== false;
    var ev = item.evidence || [];
    var s = String(item.status || "").toLowerCase();

    var head =
      '<div style="font-size:var(--fs-md);font-weight:650;color:var(--bright)">' +
        (item.statement ? V.esc(item.statement)
          : '<span style="color:var(--dim);font-weight:400">no statement on record</span>') + "</div>" +
      '<div style="margin-top:8px;display:flex;align-items:center;gap:4px;flex-wrap:wrap">' + lifeStrip(item) + "</div>" +
      '<div class="note" style="margin-top:6px">' +
        (item.first_seen ? "Proposed <b>" + V.esc(V.timeAgo(item.first_seen)) + "</b>" : "Proposal time not on record") +
        (item.last_reinforced ? " · last supported <b>" + V.esc(V.timeAgo(item.last_reinforced)) + "</b>" : "") +
        (item.published_at ? " · published <b>" + V.esc(V.timeAgo(item.published_at)) + "</b>" : "") +
        ((item.categories || []).length
          ? " · " + (item.categories || []).map(function (c) { return V.kindBadge(c); }).join(" ") : "") +
      "</div>";

    var support =
      '<div class="card" style="margin-top:12px"><h2>Support ' +
        '<span class="sub">customers / independent writers / evidence tier · exact counts, admin-only</span></h2>' +
      '<div class="note" style="margin-top:0">' + supportSentence(item) + "</div>" +
      '<div class="row" style="gap:6px;flex-wrap:wrap;margin-top:8px">' +
        V.stateChip(k.entOk ? "ok" : "wait", "3+ customers — has " + k.d) +
        V.stateChip(k.writerOk ? "ok" : "wait", "2+ writers or an authoritative source — has " + k.w +
          (item.has_tier1_evidence ? " + authoritative" : "")) +
        V.stateChip(k.catOk ? "ok" : "wait", "has a category — " +
          ((item.categories || []).length ? (item.categories || []).join(", ") : "none yet")) +
      "</div>" +
      '<div class="note" style="margin-top:8px">All three must pass before a lesson can be published, so no single ' +
        "customer&rsquo;s situation can be inferred from it. The chips only explain &mdash; the server enforces.</div>" +
      '<div class="note" style="margin-top:6px">Agents that recall this lesson only ever see a coarse bucket &mdash; ' +
        (bucket ? V.badge(bucket + " customers", "b-trust", true)
                : V.badge("below the floor — agents see nothing", "b-st-candidate")) +
        " &mdash; never the exact counts on this page.</div>" +
      "</div>";

    var deid =
      '<div class="card" style="margin-top:8px"><h2>Anonymity check <span class="sub">de-identification gate · deterministic</span></h2>' +
      '<div class="note" style="margin-top:0">Before review, every lesson is checked for details that could identify a ' +
        "specific customer &mdash; a lesson that names or singles one out is refused, never indexed. " +
        (deidPassed
          ? "This lesson <b>passed</b> that check. " + V.stateChip("ok", "passed")
          : "This lesson <b>failed</b> it and was held back" +
            (gate.reason ? ": <b>" + V.esc(gate.reason) + "</b>" : "") + ". " +
            V.stateChip("fail", "held back")) +
      "</div></div>";

    var evRows = ev.map(function (e) {
      var tier = e.trust_tier;
      var tierChip = (tier === 1 || tier === "1")
        ? V.badge("authoritative source", "b-tier")
        : V.badge("observation", "b-trust");
      return '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:4px 0;border-bottom:1px solid var(--border)">' +
        principalEvidenceChip(e.entity) +
        '<span class="note" style="margin-top:0">written by <b>' +
          (e.writer_azp ? V.esc(e.writer_azp) : "unknown writer") + "</b></span>" +
        tierChip +
        V.refSpan(e.episode_id || "—") +
      "</div>";
    }).join("");
    var evidence =
      '<div class="card" style="margin-top:8px"><h2>The evidence ' +
        '<span class="sub">' + ev.length + " conversation" + (ev.length === 1 ? "" : "s") + " · audit-scope-only</span></h2>" +
      '<div class="note" style="margin-top:0">' +
        (ev.length
          ? "Supported by <b>" + ev.length + " conversation" + (ev.length === 1 ? "" : "s") + "</b>. "
          : "<b>No evidence rows on record</b> &mdash; a lesson with no evidence cannot gather support. ") +
        "This lineage is shown here for your review only &mdash; agents never see which customers a lesson " +
        "came from (provenance firewall).</div>" +
      (ev.length ? '<div style="margin-top:6px">' + evRows + "</div>" : "") +
      "</div>";

    var retraction = s === "published"
      ? '<div class="card" style="margin-top:8px"><h2>Taking it back <span class="sub">no un-publish endpoint exists</span></h2>' +
        '<div class="note" style="margin-top:0">Publishing is one-way here. Retracting a published lesson is ' +
          "<b>Erasure &amp; data export</b>&rsquo;s job &mdash; when its source conversations are forgotten, the lesson is " +
          "invalidated automatically. This button is a designed seam, not a fake:</div>" +
        '<div class="actions"><button disabled title="No un-publish endpoint exists — retraction is Erasure &amp; data export. This seam is designed, never faked.">' +
          "Retract via Erasure &amp; data export (no endpoint yet)</button></div></div>"
      : "";

    body.innerHTML = head + support + deid + evidence + retraction;
  }

  // Evidence entities look like "account:acme" — name first, kind secondary.
  function principalEvidenceChip(entity) {
    if (!entity) return V.entityChip(null);
    var p = String(entity);
    var i = p.indexOf(":");
    return i < 0 ? V.entityChip(p) : V.entityChip(p.slice(i + 1), p.slice(0, i));
  }

  /* =========================================================== publish gate */

  function openPublish(id) {
    var it = (current.item && current.id === id) ? current.item : data.byId[id];
    if (!it) return;
    current = { id: id, statement: it.statement || "", status: it.status, item: it };
    pubSel = {};
    V.clearErr("know-pub-err");
    el("know-pub-stmt").textContent = it.statement || "no statement on record";
    el("know-pub-support").innerHTML = supportSentence(it);
    el("know-pub-filter").value = "";
    el("know-pub-raw").value = "";
    el("know-pub-kmin").value = "3";
    updatePubCount();
    V.dialog("know-pub-dialog").open();
    loadDirectory(); // async — the picker fills in when the read lands
  }

  async function loadDirectory() {
    dir = { state: "loading", rows: [], truncated: false, error: "" };
    renderDir();
    try {
      var rows = [], after = 0;
      for (var page = 0; page < 4; page++) {
        var res = await V.api(
          "/v1/admin/principals?tenant_id=" + encodeURIComponent(tenantNow) +
            "&after_token=" + after + "&limit=500",
          { admin: true });
        rows = rows.concat((res && res.principals) || []);
        if (!res || res.next_after_token == null) {
          dir = { state: "ready", rows: rows, truncated: false, error: "" };
          renderDir();
          return;
        }
        after = res.next_after_token;
      }
      dir = { state: "ready", rows: rows, truncated: true, error: "" };
    } catch (e) {
      dir = { state: "error", rows: [], truncated: false, error: (e && e.message) || String(e) };
    }
    renderDir();
  }

  function renderDir() {
    var host = el("know-pub-dir");
    if (!host) return;
    if (dir.state === "loading") {
      host.innerHTML = '<div class="note" style="margin-top:0">loading the people &amp; groups directory&hellip;</div>';
      return;
    }
    if (dir.state === "error") {
      host.innerHTML = '<div class="note" style="margin-top:0"><b>Could not load the directory</b> (' +
        V.esc(dir.error) + ") &mdash; you can still publish with raw tokens below.</div>";
      return;
    }
    if (!dir.rows.length) {
      host.innerHTML = '<div class="note" style="margin-top:0">No named people or groups exist for this space yet ' +
        "&mdash; create them on <b>People &amp; groups</b>, or use raw tokens below (dev mode). An empty directory " +
        "never publishes to anyone by default.</div>";
      return;
    }
    var q = el("know-pub-filter").value.trim().toLowerCase();
    var rows = q
      ? dir.rows.filter(function (r) { return String(r.principal).toLowerCase().indexOf(q) !== -1; })
      : dir.rows;
    if (!rows.length) {
      host.innerHTML = '<div class="note" style="margin-top:0">no names match &ldquo;' + V.esc(q) + "&rdquo;</div>";
      return;
    }
    host.innerHTML = rows.map(function (r) {
      var checked = pubSel[String(r.token)] ? " checked" : "";
      return '<label style="display:flex;align-items:center;gap:8px;padding:3px 2px;cursor:pointer">' +
        '<input type="checkbox" class="know-pub-cb" data-token="' + V.esc(r.token) + '" data-name="' + V.esc(r.principal) + '"' + checked + ">" +
        principalChip(r.principal) + V.refSpan("#" + r.token) +
      "</label>";
    }).join("") +
    (dir.truncated
      ? '<div class="note">showing the first ' + dir.rows.length +
        " directory entries &mdash; more exist; narrow with the filter or use raw tokens</div>"
      : "");
    var cbs = host.querySelectorAll(".know-pub-cb");
    for (var i = 0; i < cbs.length; i++) {
      cbs[i].onchange = function () {
        var tok = String(this.getAttribute("data-token"));
        if (this.checked) pubSel[tok] = this.getAttribute("data-name");
        else delete pubSel[tok];
        updatePubCount();
      };
    }
  }

  // Parse the dev-mode raw-token field. Empty is FINE (named picks may carry
  // the publish); an unparsable entry is an error only at submit time.
  function parseRawTokens(raw) {
    var parts = String(raw || "").split(/[\s,]+/).filter(function (s) { return s.length; });
    var tokens = [];
    for (var i = 0; i < parts.length; i++) {
      if (!/^-?\d+$/.test(parts[i])) return { tokens: null, bad: parts[i] };
      tokens.push(parseInt(parts[i], 10));
    }
    return { tokens: tokens, bad: null };
  }

  function selectedTokens() {
    var out = [], seen = {};
    Object.keys(pubSel).forEach(function (t) {
      var n = parseInt(t, 10);
      if (!seen[n]) { seen[n] = true; out.push(n); }
    });
    var raw = parseRawTokens(el("know-pub-raw").value);
    (raw.tokens || []).forEach(function (n) {
      if (!seen[n]) { seen[n] = true; out.push(n); }
    });
    return { tokens: out, bad: raw.bad };
  }

  function updatePubCount() {
    var sel = selectedTokens();
    var names = Object.keys(pubSel).map(function (t) { return pubSel[t]; });
    var line;
    if (!sel.tokens.length) {
      line = V.stateChip("attn", "no one selected") +
        ' <span class="note" style="margin-top:0">publishing will refuse &mdash; there is no default audience</span>';
    } else {
      var shown = names.slice(0, 5).map(function (n) { return principalChip(n); }).join(" ");
      var extra = sel.tokens.length - Math.min(names.length, 5);
      line = "will be seen by <b>" + sel.tokens.length + "</b> people &amp; groups: " + shown +
        (extra > 0 ? ' <span class="note" style="margin-top:0">+ ' + extra + " more</span>" : "");
    }
    el("know-pub-count").innerHTML = line;
    var go = el("know-pub-go");
    go.disabled = !sel.tokens.length;
    go.textContent = sel.tokens.length
      ? "Publish to " + sel.tokens.length + " people & groups"
      : "Publish";
  }

  async function submitPublish() {
    V.clearErr("know-pub-err");
    var sel = selectedTokens();
    if (sel.bad != null) {
      V.err("know-pub-err", new Error('not an integer key token: "' + sel.bad + '"'));
      return;
    }
    if (!sel.tokens.length) {
      // Omission REFUSES — never a permissive default.
      V.err("know-pub-err", new Error(
        "pick at least one person or group (or cancel) — there is no default audience; omission refuses"));
      return;
    }
    var kmin = parseInt(el("know-pub-kmin").value, 10);
    if (isNaN(kmin) || kmin < 3) kmin = 3; // honesty clamp; the server re-clamps as the authority
    var btn = el("know-pub-go");
    btn.disabled = true;
    try {
      await V.api("/v1/knowledge/" + encodeURIComponent(current.id) + "/publish",
        { admin: true, json: { tenant_id: tenantNow, visibility: sel.tokens, k_min: kmin } });
      V.dialog("know-pub-dialog").close();
      V.dialog("know-drawer").close();
      var names = Object.keys(pubSel).map(function (t) { return pubSel[t]; });
      var named = names.slice(0, 6).map(function (n) { return principalChip(n); }).join(" ");
      var unnamed = sel.tokens.length - names.length;
      el("know-receipt").innerHTML =
        '<div class="card" style="border-left:3px solid var(--green)">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            V.stateChip("ok", "published") +
            "<b>" + V.esc(current.statement || current.id) + "</b>" +
          "</div>" +
          '<div class="note">Now visible to <b>' + sel.tokens.length + "</b> people &amp; groups: " + named +
            (names.length > 6 ? " + " + (names.length - 6) + " more named" : "") +
            (unnamed > 0 ? " + " + unnamed + " raw token" + (unnamed === 1 ? "" : "s") : "") +
            " · privacy floor " + kmin + " customers. There is no un-publish — retraction is Erasure &amp; data export." +
            '<span class="api-crumb"> <span class="ref">POST /v1/knowledge/' + V.esc(current.id) + "/publish</span></span></div>" +
        "</div>";
      await loadAll(tenantNow);
    } catch (e) {
      // Server refusals surface verbatim — they are the teaching moment.
      V.err("know-pub-err", e);
      btn.disabled = false;
    }
  }

  /* =========================================================== reject gate */

  function openReject(id) {
    var it = (current.item && current.id === id) ? current.item : data.byId[id];
    if (!it) return;
    current = { id: id, statement: it.statement || "", status: it.status, item: it };
    V.clearErr("know-rej-err");
    el("know-rej-stmt").textContent = it.statement || "no statement on record";
    el("know-rej-reason").value = "";
    el("know-rej-go").disabled = true; // the reason is the gate — required
    V.dialog("know-rej-dialog").open();
  }

  async function submitReject() {
    V.clearErr("know-rej-err");
    var reason = el("know-rej-reason").value.trim();
    if (!reason) {
      V.err("know-rej-err", new Error("a reason is required — this decision is remembered forever and goes on the record"));
      return;
    }
    var btn = el("know-rej-go");
    btn.disabled = true;
    try {
      await V.api("/v1/admin/knowledge/" + encodeURIComponent(current.id) + "/reject",
        { admin: true, json: { tenant_id: tenantNow, reason: reason } });
      V.dialog("know-rej-dialog").close();
      V.dialog("know-drawer").close();
      el("know-receipt").innerHTML =
        '<div class="card" style="border-left:3px solid var(--green)">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            V.stateChip("ok", "rejected — remembered") +
            "<b>" + V.esc(current.statement || current.id) + "</b>" +
          "</div>" +
          '<div class="note">This exact lesson will not be proposed again. Reason on record: <b>' +
            V.esc(reason) + "</b>" +
            '<span class="api-crumb"> <span class="ref">POST /v1/admin/knowledge/' + V.esc(current.id) + "/reject</span></span></div>" +
        "</div>";
      await loadAll(tenantNow);
    } catch (e) {
      V.err("know-rej-err", e);
      btn.disabled = false;
    }
  }
})();
