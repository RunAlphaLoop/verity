"use strict";
/* ==========================================================================
   panel_entities.js — Entities & merges (v2 EXEMPLAR panel)
   --------------------------------------------------------------------------
   Reads / writes:
     • GET  /v1/admin/entity-resolution/review-queue?tenant_id&limit — the
       uncertain matches awaiting a human (admin)
     • GET  /v1/admin/entities?tenant_id&limit — the merged entities (admin)
     • POST /v1/admin/entity-resolution/decide — THE HUMAN GATE:
         confirm → a person-confirmed link (jargon: human_confirmed edge,
         tier 2, polarity +1); matching re-runs immediately.
         reject  → a PERMANENT do-not-link (human_rejected anti-link,
         tier 2, polarity −1); takes a typed confirm — it is irreversible.
     • POST /v1/admin/entity-resolution/run — "Run matching now"
       (UI-ACTIONS N6): populates evidence + the review queue; only exact
       identifiers merge deterministically; nothing uncertain auto-merges.
     • GET  /v1/entities/{canonical}?scope_handle — merged field view
       (SCOPE-gated, not admin — disclosed in the drawer, with a mint button)
     • POST /v1/admin/entity-precedence — "which source wins" ranking
       { tenant_id, canonical, field, source_order[] } highest first.

   THE LAW, applied:
     • names first — every ref renders as a name where one is on record;
       raw refs are mono-small secondary text;
     • evidence in plain words ("a similar name and the same website
       domain — 91% confidence"), jargon only in mono meta lines;
     • autoloads once the tenant is known; teaches in every empty state;
     • honest encodings kept: deterministic/person-confirmed = solid badge,
       probable = dashed; rule-vs-recency inference stated exactly, never
       guessed; server ordering rendered, never re-sorted.
   ========================================================================== */
(function () {
  var V = window.Verity;
  var LIMIT = 500;

  /* ------------------------------------------------------------ plain words */

  function methodPlain(method) {
    var m = String(method || "").toLowerCase();
    var map = {
      external_id: "the same external ID",
      duns: "the same DUNS number",
      duns_exact: "the same DUNS number",
      email: "the same email address",
      email_exact: "the same email address",
      domain: "the same website domain",
      domain_exact: "the same website domain",
      "name+domain_fuzzy": "a similar name and website domain",
      name_domain_fuzzy: "a similar name and website domain",
      name_fuzzy: "a similar name",
      name_mention: "a matching name mention",
      human_confirmed: "confirmed by a person",
    };
    // Unknown kinds still read as words, never as a raw enum; the exact
    // kind stays visible in the card's meta line.
    return map[m] || 'a "' + m.replace(/[_+]/g, " ") + '" signal';
  }

  function tierPlain(tier) {
    if (Number(tier) === 1) return "exact identifier";
    if (Number(tier) === 2) return "needs human confirmation";
    return "weak hint";
  }

  // How the link was made, in a sentence fragment. Encoding preserved:
  // solid = guaranteed, dashed = probabilistic.
  function confidencePlain(badgeRow) {
    if (!badgeRow) return { text: "not yet badged", chip: V.badge("unbadged", "b-kind") };
    var c = String(badgeRow.confidence || "").toLowerCase();
    if (c === "deterministic") {
      return {
        text: "merged automatically (" + methodPlain(badgeRow.strongest_method) + ")",
        chip: V.badge("automatic — exact match", "b-provenance"),
      };
    }
    if (c === "human_confirmed") {
      return {
        text: "merged by a person",
        chip: V.badge("confirmed by a person", "b-provenance"),
      };
    }
    if (c === "approximated") {
      return {
        text: "probable match — not confirmed",
        chip: V.badge("probable — not confirmed", "b-inferred", true),
      };
    }
    return { text: c, chip: V.badge(c, "b-kind") };
  }

  function refSource(ref) {
    var s = String(ref || "");
    var i = s.indexOf(":");
    return i < 0 ? s : s.slice(0, i);
  }

  function fmtVal(v) {
    if (v == null) return "—";
    if (typeof v === "string") return v;
    try { return JSON.stringify(v); } catch (e) { return String(v); }
  }

  function displayName(sum) { return (sum && sum.name) || null; }

  // A truthful, distinct label for a source record when no name is in the
  // payload: never a raw ref as the primary text, never a fabricated name.
  function describeRef(ref) {
    return "the " + refSource(ref) + " record (" + String(ref || "") + ")";
  }

  // First member record whose payload actually carries a name — the summary
  // endpoint can return name:null even when member facts have one.
  function memberWithName(members) {
    for (var i = 0; i < (members || []).length; i++) {
      if (members[i] && members[i].name) return members[i];
    }
    return null;
  }

  /* ------------------------------------------------------------ state */

  var data = { queue: [], entities: [], loadedAt: 0 };
  var view = "queue";           // "queue" | "browser"
  var browserFilter = "all";    // "all" | "merged" | "single"
  var tenantNow = "";
  var current = { canonical: "", members: [], name: "", row: null };
  var prec = { names: [], orders: {}, star: [], fields: {}, ready: false };
  var pending = { left: "", right: "", decision: "", leftName: "", rightName: "" };
  var lastHandle = "";          // scope handle reused across drawer opens

  function el(id) { return V.$(id); }

  /* =========================================================== mount */
  V.register({
    id: "entities",
    mount: function () {
      var host = el("entities-mount");
      if (!host) return;
      host.innerHTML =
        /* ---- toolbar ---- */
        '<div class="toolbar">' +
          '<span class="seg">' +
            '<button id="ent-view-queue" class="on">Needs your decision</button>' +
            '<button id="ent-view-browser">Entities</button>' +
          "</span>" +
          '<span id="ent-state"></span>' +
          '<span class="asof" id="ent-asof"></span>' +
          '<span class="spacer"></span>' +
          '<button id="ent-run" title="POST /v1/admin/entity-resolution/run — scans current facts for identity matches. Exact identifiers merge deterministically; anything uncertain is queued here for a human.">Run matching now</button>' +
        "</div>" +
        '<div class="err" id="ent-err"></div>' +
        '<div id="ent-receipt"></div>' +
        '<div id="ent-teach"></div>' +
        '<div id="ent-queue-view"></div>' +
        '<div id="ent-browser-view" style="display:none"></div>' +

        /* ---- decide dialog (merge / keep-separate) ---- */
        '<div class="dialog-backdrop" id="ent-decide-dialog"><div class="dialog" style="max-width:600px">' +
          '<h3 id="ent-decide-title">Decide</h3>' +
          '<div id="ent-decide-summary"></div>' +
          '<div class="note" id="ent-decide-explain" style="margin-top:10px"></div>' +
          '<div id="ent-decide-typed" style="margin-top:12px;display:none">' +
            '<label for="ent-decide-word">this is permanent — type <b>SEPARATE</b> to continue</label>' +
            '<input type="text" id="ent-decide-word" autocomplete="off" spellcheck="false">' +
          "</div>" +
          '<div style="margin-top:12px"><label for="ent-decide-note">note for the record <span style="font-weight:400">(optional — stored with the decision)</span></label>' +
            '<input type="text" id="ent-decide-note" placeholder="e.g. verified with the account owner" autocomplete="off"></div>' +
          '<div class="err" id="ent-decide-err"></div>' +
          '<div class="actions">' +
            '<button id="ent-decide-cancel">Cancel</button>' +
            '<button id="ent-decide-go">Decide</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- run-matching dialog ---- */
        '<div class="dialog-backdrop" id="ent-run-dialog"><div class="dialog" style="max-width:560px">' +
          "<h3>Run matching now?</h3>" +
          '<div class="note" style="margin-top:0">Scans this space&rsquo;s (tenant&rsquo;s) current facts for identity matches across sources.' +
            '<ul style="margin:8px 0 0 18px">' +
            "<li><b>Exact identifiers</b> (same external ID, DUNS, email) merge deterministically.</li>" +
            "<li><b>Anything uncertain</b> goes to the review queue for a human — it is never merged automatically.</li>" +
            "<li>Running twice is safe — an unchanged space produces no new evidence.</li></ul></div>" +
          '<div class="err" id="ent-run-err"></div>' +
          '<div class="actions">' +
            '<button id="ent-run-cancel">Cancel</button>' +
            '<button class="primary" id="ent-run-go">Run matching</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- entity detail drawer ---- */
        '<div class="dialog-backdrop" id="ent-drawer"><div class="dialog" style="max-width:860px">' +
          '<h3 id="ent-drawer-title">Entity</h3>' +
          '<div id="ent-drawer-head"></div>' +
          '<div id="ent-drawer-single"></div>' +
          '<div class="card" id="ent-merged-card" style="margin-top:12px">' +
            '<h2>Which source wins <span class="sub">scope-gated<span class="api-crumb"> · GET /v1/entities/{canonical}</span></span></h2>' +
            '<div class="note" style="margin-top:0">Every field below is merged from all sources. When sources disagree, the <b>highest-ranked source wins</b>; where you have set no ranking, the newest value wins. This view reads through a scope handle — the same fail-closed path agents use.</div>' +
            '<div class="row" style="margin-top:8px">' +
              '<div><label for="ent-scope-handle">scope handle</label>' +
                '<input type="text" id="ent-scope-handle" placeholder="vs_…" autocomplete="off" spellcheck="false"></div>' +
              '<div class="tight"><button class="primary" id="ent-load-merged">Load fields</button></div>' +
              '<div class="tight"><button id="ent-mint-here" title="mint a fresh scope handle for this space — it fills in here automatically">Mint a scope handle</button></div>' +
            "</div>" +
            '<div class="err" id="ent-merged-err"></div>' +
            '<div id="ent-merged-out"></div>' +
          "</div>" +
          '<div class="card" style="margin-top:8px" id="ent-split-card">' +
            '<h2>Not the same thing?</h2>' +
            '<div class="note" style="margin-top:0">Splitting records a <b>permanent do-not-link</b> between two of this entity&rsquo;s source records and re-runs matching — the same keep-separate decision the review queue uses.</div>' +
            '<div id="ent-split"></div>' +
          "</div>" +
          '<div class="actions"><button id="ent-drawer-close">Close</button></div>' +
        "</div></div>";

      /* ---- wiring ---- */
      el("ent-view-queue").onclick = function () { switchView("queue"); };
      el("ent-view-browser").onclick = function () { switchView("browser"); };
      el("ent-run").onclick = function () {
        V.clearErr("ent-run-err");
        V.dialog("ent-run-dialog").open();
      };
      el("ent-run-cancel").onclick = function () { V.dialog("ent-run-dialog").close(); };
      el("ent-run-go").onclick = runMatching;
      el("ent-drawer-close").onclick = function () { V.dialog("ent-drawer").close(); };
      el("ent-load-merged").onclick = loadMerged;
      el("ent-mint-here").onclick = function () { V.openMint({ tenant: tenantNow }); };
      el("ent-decide-cancel").onclick = function () { V.dialog("ent-decide-dialog").close(); };
      el("ent-decide-go").onclick = submitDecision;
      el("ent-decide-word") && (el("ent-decide-word").oninput = reflectTyped);

      // A mint anywhere feeds the drawer's handle input (and auto-loads when
      // the drawer is open) — the post-mint handoff, not a dead end.
      V.onMint(function (m) {
        lastHandle = m.handle;
        var input = el("ent-scope-handle");
        if (input) input.value = m.handle;
        var drawer = el("ent-drawer");
        if (drawer && drawer.classList.contains("open") && current.canonical) loadMerged();
      });
    },

    /* v2 AUTOLOAD — the router runs this when the tenant is known. */
    load: function (_section, tenant) { return loadAll(tenant); },

    onShow: function () {
      var p = V.navParams();
      if (p && p.view) switchView(p.view);
      if (!V.tenant()) renderNoTenant();
    },
  });

  /* =========================================================== loading */

  function renderNoTenant() {
    var teach = el("ent-teach");
    if (!teach) return;
    el("ent-queue-view").innerHTML = "";
    el("ent-browser-view").innerHTML = "";
    el("ent-state").innerHTML = V.stateChip("off", "no space");
    teach.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a space to see its entities</div>' +
        '<div class="et-body">Pick a space in the session bar above (or paste its space id), or mint a scope handle — the space fills in automatically and this screen loads itself.</div>' +
        '<div class="et-actions"><button class="primary" id="ent-teach-mint">Mint a scope handle</button></div>' +
      "</div>";
    el("ent-teach-mint").onclick = function () { V.openMint(); };
  }

  async function loadAll(tenant) {
    tenantNow = tenant;
    V.clearErr("ent-err");
    el("ent-teach").innerHTML = "";
    el("ent-state").innerHTML = V.stateChip("wait", "loading");
    try {
      var qs = "?tenant_id=" + encodeURIComponent(tenant) + "&limit=" + LIMIT;
      var results = await Promise.all([
        V.api("/v1/admin/entity-resolution/review-queue" + qs, { admin: true }),
        V.api("/v1/admin/entities" + qs, { admin: true }),
      ]);
      data.queue = results[0] || [];
      data.entities = results[1] || [];
      data.loadedAt = Date.now();
      V.setCount("entities", data.queue.length, "decisions waiting for you");
      renderAll();
    } catch (e) {
      el("ent-state").innerHTML = V.stateChip("fail");
      var msg = String((e && e.message) || e);
      if (msg.indexOf("400") >= 0 && msg.indexOf("UUID parsing failed") >= 0) {
        // A space NAME was pasted where a uuid belongs — teach, don't parrot serde.
        var box = el("ent-err");
        box.innerHTML =
          "That looks like the space&rsquo;s name, not its id. Pick the space from the list " +
          "in the bar above &mdash; ids look like 019f53b8-&hellip;." +
          '<div class="ref" style="margin-top:4px">' + V.esc(msg) + "</div>";
        box.classList.add("on");
      } else {
        V.err("ent-err", e);
      }
    }
  }

  function renderAll() {
    var q = data.queue.length;
    el("ent-state").innerHTML = q
      ? V.stateChip("attn", q + " decision" + (q === 1 ? "" : "s") + " waiting")
      : V.stateChip("ok", "queue clear");
    var total = data.entities.length;
    var mergedN = data.entities.filter(function (e) { return e.merged; }).length;
    el("ent-asof").textContent =
      q + " waiting · " + total + " entit" + (total === 1 ? "y" : "ies") +
      " (" + mergedN + " merged) · checked " + new Date().toTimeString().slice(0, 8);
    el("ent-view-queue").textContent = "Needs your decision" + (q ? " (" + q + ")" : "");
    el("ent-view-browser").textContent = "Entities" + (total ? " (" + total + ")" : "");
    renderQueue();
    renderBrowser();
  }

  function switchView(v) {
    view = v === "browser" ? "browser" : "queue";
    el("ent-queue-view").style.display = view === "queue" ? "block" : "none";
    el("ent-browser-view").style.display = view === "browser" ? "block" : "none";
    el("ent-view-queue").className = view === "queue" ? "on" : "";
    el("ent-view-browser").className = view === "browser" ? "on" : "";
  }

  /* =========================================================== queue view */

  function renderQueue() {
    var host = el("ent-queue-view");
    var rows = data.queue;
    if (!rows.length) {
      var hasEntities = data.entities.length > 0;
      host.innerHTML =
        '<div class="empty-teach ' + (hasEntities ? "sp-c" : "sp-a") + '">' +
          '<div class="et-title">' + (hasEntities
            ? "No matches waiting for you"
            : "Nothing to decide yet") + "</div>" +
          '<div class="et-body">' + (hasEntities
            ? "Every uncertain match has been decided — an empty queue means matching settled everything it saw, " +
              "not that a merge happened silently. Exact-identifier merges keep happening automatically; anything " +
              "uncertain will stop here for you."
            : "The queue fills when matching finds two records that <b>might</b> be the same thing but is not " +
              "certain. Run matching to scan this space&rsquo;s sources for cross-source matches now.") + "</div>" +
          '<div class="et-actions">' +
            '<button class="primary" id="ent-q-run">Run matching now</button>' +
            (hasEntities ? '<button id="ent-q-browse">See the ' + data.entities.length + " merged entit" + (data.entities.length === 1 ? "y" : "ies") + " &rsaquo;</button>" : "") +
          "</div>" +
        "</div>";
      el("ent-q-run").onclick = function () { V.clearErr("ent-run-err"); V.dialog("ent-run-dialog").open(); };
      var b = el("ent-q-browse");
      if (b) b.onclick = function () { switchView("browser"); };
      return;
    }

    // Starvation read-out (server orders by priority DESC; the oldest-waiting
    // card may sit below the top — flag it, never re-sort).
    var maxWait = 0;
    rows.forEach(function (r) { var w = Number(r.wait_age_secs); if (isFinite(w) && w > maxWait) maxWait = w; });
    var starveActive = maxWait >= 3600 && rows.length > 1;

    host.innerHTML = rows.map(function (c, i) {
      var oldest = starveActive && c.wait_age_secs != null && Number(c.wait_age_secs) === maxWait;
      return decisionCard(c, i + 1, rows.length, oldest && i > 0, oldest);
    }).join("");

    // verdict buttons
    wire(host, ".ent-cand-confirm", function (btn) {
      openDecide(btn.getAttribute("data-left"), btn.getAttribute("data-right"), "confirm",
        btn.getAttribute("data-lname"), btn.getAttribute("data-rname"));
    });
    wire(host, ".ent-cand-reject", function (btn) {
      openDecide(btn.getAttribute("data-left"), btn.getAttribute("data-right"), "reject",
        btn.getAttribute("data-lname"), btn.getAttribute("data-rname"));
    });
  }

  function wire(host, sel, fn) {
    var nodes = host.querySelectorAll(sel);
    for (var i = 0; i < nodes.length; i++) {
      (function (n) { n.onclick = function () { fn(n); }; })(nodes[i]);
    }
  }

  // One uncertain match → one human decision card.
  function decisionCard(c, rank, total, starving, oldest) {
    var lName = displayName(c.left_summary);
    var rName = displayName(c.right_summary);
    var isCompany = (c.left_summary && c.left_summary.domain) || (c.right_summary && c.right_summary.domain);
    var question = "Are these the same " + (isCompany ? "company" : "record") + "?";

    var confPct = c.score == null ? null : Math.round(Number(c.score) * 100);
    var evidence =
      "<b>Why they might match:</b> " + V.esc(methodPlain(c.method)) +
      (c.key_value ? ' — matched on &ldquo;<b>' + V.esc(c.key_value) + "</b>&rdquo;" : "") +
      (confPct != null ? " · <b>" + confPct + "% confidence</b>" : "") +
      (Number(c.polarity) < 0 ? " · " + V.badge("keep-apart evidence", "b-quarantined") : "");

    var chips =
      '<span class="badge ' + (rank === 1 ? "b-entity" : "b-kind") + '" title="position in the server\'s priority order">#' + rank + " of " + total + "</span>" +
      (c.wait_age_secs != null
        ? '<span class="badge b-kind"' + (oldest ? ' style="color:var(--amber);border-color:var(--amber-line);background:var(--amber-soft)"' : "") +
          ' title="how long this pair has waited for a decision">waiting ' + V.esc(V.fmtAge(c.wait_age_secs)) + "</span>"
        : "") +
      (starving ? '<span class="badge b-st-eligible" title="the longest-waiting pair, not yet at the top of the queue — decide it so it is never buried">longest waiting</span>' : "") +
      (Number(c.frequency) > 1 ? '<span class="badge b-kind" title="this pair keeps recurring in the evidence">seen ' + V.esc(c.frequency) + "×</span>" : "");

    return '<div class="decision-card' + (starving ? " dc-flag" : "") + '">' +
      '<div class="dc-topline">' + chips + "</div>" +
      '<div class="dc-question">' + question + "</div>" +
      '<div class="dc-sides">' +
        sideCol(c.left_ref, c.left_summary) +
        '<div class="dc-vs" style="font-size:var(--fs-sm)" title="are these the same? that\'s your decision">same?</div>' +
        sideCol(c.right_ref, c.right_summary) +
      "</div>" +
      '<div class="dc-evidence">' + evidence + "</div>" +
      '<div class="dc-meta">' + V.esc(c.method) + " · " + V.esc(tierPlain(c.tier)) +
        '<span class="api-crumb"> (tier ' + V.esc(c.tier) + ")</span>" +
        " · proposed " + V.esc(V.fmtTime(c.valid_from)) +
        (c.rationale ? " · rationale: " + V.esc(c.rationale) : "") + "</div>" +
      '<div class="dc-actions">' +
        '<button class="good ent-cand-confirm" ' + refAttrs(c, lName, rName) +
          ' title="records a person-confirmed link and re-runs matching immediately (you can split them later — but a split is itself permanent)">Yes, same &mdash; merge</button>' +
        '<button class="danger ent-cand-reject" ' + refAttrs(c, lName, rName) +
          ' title="records a PERMANENT do-not-link — matching will keep these apart forever">No, keep separate</button>' +
      "</div>" +
    "</div>";
  }

  function refAttrs(c, lName, rName) {
    return 'data-left="' + V.esc(c.left_ref) + '" data-right="' + V.esc(c.right_ref) +
      '" data-lname="' + V.esc(lName || "") + '" data-rname="' + V.esc(rName || "") + '"';
  }

  // One side of the question: name FIRST, source plain, ref mono-small.
  function sideCol(ref, sum) {
    sum = sum || {};
    // A null summary name is NOT proof the record is nameless (the summary
    // lookup can miss names the member facts carry) — say "not loaded".
    var name = sum.name
      ? '<div class="dc-name">' + V.esc(sum.name) + "</div>"
      : '<div class="dc-name" style="color:var(--dim);font-weight:400">name not loaded</div>';
    return '<div class="dc-side">' + name +
      '<div class="dc-src">in <b>' + V.esc(refSource(ref)) + "</b>" +
        (sum.domain ? " · " + V.esc(sum.domain) : "") + "</div>" +
      V.refSpan(ref) +
    "</div>";
  }

  /* ---------------------------------------------- decide (the human gate) */

  function openDecide(left, right, decision, leftName, rightName) {
    pending = { left: left, right: right, decision: decision, leftName: leftName, rightName: rightName };
    V.clearErr("ent-decide-err");
    el("ent-decide-note").value = "";
    el("ent-decide-word").value = "";
    var confirming = decision === "confirm";
    // Distinct, truthful labels: a real name when the payload has one,
    // otherwise "the {source} record ({ref})" — never a bare raw ref.
    var lLabel = leftName || describeRef(left), rLabel = rightName || describeRef(right);

    el("ent-decide-title").textContent = confirming
      ? "Merge these two?"
      : "Keep these separate — permanently?";
    el("ent-decide-summary").innerHTML =
      V.entityChip(lLabel, refSource(left)) +
      '<span style="color:var(--dim)"> and </span>' +
      V.entityChip(rLabel, refSource(right)) +
      '<div style="margin-top:4px">' + V.refSpan(left + "  ·  " + right) + "</div>";
    el("ent-decide-explain").innerHTML = confirming
      ? "<b>" + V.esc(lLabel) + "</b> and <b>" + V.esc(rLabel) + "</b> become one entity everywhere — recall, briefs, " +
        "and the merged record. Your confirmation is saved as evidence and outranks automatic matching, and matching " +
        "re-runs immediately. You can split them later from the entity&rsquo;s page, though a split permanently " +
        'forbids re-merging. <span class="ref api-crumb">human_confirmed · tier 2, +1</span>'
      : "Verity will record a <b>permanent do-not-link rule</b> between <b>" + V.esc(lLabel) + "</b> and <b>" +
        V.esc(rLabel) + "</b>: matching will keep them apart forever, even if stronger evidence appears later, and " +
        "will split them if they are currently merged. Your rejection is saved so these are never re-matched. " +
        '<b>This cannot be undone.</b> <span class="ref api-crumb">human_rejected · tier 2, −1</span>';
    el("ent-decide-typed").style.display = confirming ? "none" : "block";
    var go = el("ent-decide-go");
    go.textContent = confirming ? "Merge them" : "Keep separate forever";
    go.className = confirming ? "good" : "danger";
    go.disabled = !confirming; // typed confirm gates the permanent verb
    V.dialog("ent-decide-dialog").open();
  }

  function reflectTyped() {
    if (pending.decision !== "reject") return;
    el("ent-decide-go").disabled = el("ent-decide-word").value.trim() !== "SEPARATE";
  }

  async function submitDecision() {
    V.clearErr("ent-decide-err");
    if (!tenantNow) { V.err("ent-decide-err", new Error("no space selected")); return; }
    if (pending.decision === "reject" && el("ent-decide-word").value.trim() !== "SEPARATE") {
      V.err("ent-decide-err", new Error('type SEPARATE to confirm — this decision is permanent'));
      return;
    }
    var btn = el("ent-decide-go");
    btn.disabled = true;
    try {
      var note = el("ent-decide-note").value.trim();
      var res = await V.api("/v1/admin/entity-resolution/decide", { admin: true, json: {
        tenant_id: tenantNow,
        left_ref: pending.left,
        right_ref: pending.right,
        decision: pending.decision,
        note: note || null,
      } });
      V.dialog("ent-decide-dialog").close();
      V.dialog("ent-drawer").close();
      renderReceipt(res);
      await loadAll(tenantNow); // matching re-ran server-side; refresh both views
    } catch (e) {
      V.err("ent-decide-err", e);
      btn.disabled = false;
    }
  }

  // The decision receipt — evidence of your own act, in plain words.
  function renderReceipt(res) {
    if (!res) return;
    var m = res.materialize || {};
    var same = res.left_canonical && res.left_canonical === res.right_canonical;
    var verdict = pending.decision === "confirm" ? "Merged" : "Kept separate";
    var lLabel = pending.leftName || describeRef(pending.left);
    var rLabel = pending.rightName || describeRef(pending.right);
    el("ent-receipt").innerHTML =
      '<div class="card" style="border-left:3px solid var(--green)">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip("ok", verdict) +
          "<b>" + V.esc(lLabel) + "</b><span style=\"color:var(--dim)\">and</span><b>" + V.esc(rLabel) + "</b>" +
          (same ? V.badge("now one entity", "b-provenance") : V.badge("now provably separate", "b-kind")) +
        "</div>" +
        '<div class="note">Decision recorded and matching re-ran immediately: ' +
          V.esc(m.evidence_considered == null ? "—" : m.evidence_considered) + " pieces of evidence considered · " +
          V.esc(m.review_items == null ? "—" : m.review_items) + " still waiting for review · " +
          V.esc(m.canonicals == null ? "—" : m.canonicals) + " merged entities now. " +
          '<span class="ref">' + V.esc(pending.left) + " → " + V.esc(res.left_canonical || "—") +
          " · " + V.esc(pending.right) + " → " + V.esc(res.right_canonical || "—") + "</span></div>" +
      "</div>";
  }

  /* ---------------------------------------------------- run matching (N6) */

  async function runMatching() {
    V.clearErr("ent-run-err");
    if (!tenantNow) { V.err("ent-run-err", new Error("no space selected")); return; }
    var btn = el("ent-run-go");
    btn.disabled = true;
    try {
      var r = await V.api("/v1/admin/entity-resolution/run", { admin: true, json: { tenant_id: tenantNow } });
      V.dialog("ent-run-dialog").close();
      el("ent-receipt").innerHTML =
        '<div class="card" style="border-left:3px solid var(--green)">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            V.stateChip("ok", "matching ran") +
            "<b>" + V.esc(r.evidence_produced) + "</b> new exact-identifier match" + (Number(r.evidence_produced) === 1 ? "" : "es") + " found" +
          "</div>" +
          '<div class="note">' + V.esc(r.evidence_considered) + " pieces of evidence considered · " +
            V.esc(r.canonicals) + " merged entities now · <b>" + V.esc(r.review_items) +
            "</b> uncertain pair" + (Number(r.review_items) === 1 ? "" : "s") + " waiting for a human — nothing uncertain was merged.</div>" +
        "</div>";
      await loadAll(tenantNow);
    } catch (e) {
      V.err("ent-run-err", e);
    } finally {
      btn.disabled = false;
    }
  }

  /* =========================================================== browser view */

  function renderBrowser() {
    var host = el("ent-browser-view");
    var all = data.entities;
    if (!all.length) {
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">No entities yet</div>' +
          '<div class="et-body">Entities appear here as soon as this space has facts — one card per organization or ' +
            "person. When Verity can stitch two source records together (same email, domain, or external ID) they " +
            "collapse into a single <b>merged</b> entity; everything else is a healthy <b>single-source</b> entity. " +
            "Ingest a source or run matching to populate this.</div>" +
          '<div class="et-actions"><button class="primary" id="ent-b-run">Run matching now</button></div>' +
        "</div>";
      el("ent-b-run").onclick = function () { V.clearErr("ent-run-err"); V.dialog("ent-run-dialog").open(); };
      return;
    }

    var merged = all.filter(function (e) { return e.merged; });
    var single = all.filter(function (e) { return !e.merged; });
    var shown = browserFilter === "merged" ? merged : browserFilter === "single" ? single : all;

    function fchip(key, label, n) {
      return '<button class="badge ' + (browserFilter === key ? "b-entity" : "b-kind") +
        ' ent-bfilter" data-f="' + key + '" style="cursor:pointer;font:inherit">' + label + " " +
        '<b style="font-variant-numeric:tabular-nums">' + n + "</b></button>";
    }
    // A plain-words breakdown so an empty "Merged" is understood as a fact
    // about the data, not a missing feature — and the singletons are visible.
    var bar =
      '<div class="note" style="margin:0 0 10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
        '<span>' + all.length + " entit" + (all.length === 1 ? "y" : "ies") + " in this space — " +
          "<b>" + merged.length + "</b> merged across sources, <b>" + single.length + "</b> single-source.</span>" +
        '<span class="spacer" style="flex:1"></span>' +
        fchip("all", "All", all.length) + fchip("merged", "Merged", merged.length) +
        fchip("single", "Single-source", single.length) +
      "</div>";

    var cards = shown.length
      ? shown.map(function (row, i) { return entityCard(row, i); }).join("")
      : '<div class="note">No ' + (browserFilter === "merged" ? "merged" : "single-source") +
        " entities" + (browserFilter === "merged"
          ? " yet — nothing has matched across two or more sources."
          : ".") + "</div>";

    host.innerHTML = bar + cards;

    wire(host, ".ent-bfilter", function (btn) {
      browserFilter = btn.getAttribute("data-f");
      renderBrowser();
    });
    wire(host, ".ent-card", function (cardEl) {
      openDetail(shown[parseInt(cardEl.getAttribute("data-i"), 10)]);
    });
  }

  // One entity card. Merged entities (a resolution weld) get a green accent and
  // their confidence badge; single-source entities get a calm neutral badge and
  // an honest "not yet linked" line — never the misleading "unbadged".
  function entityCard(row, i) {
    var name = displayName(row.summary);
    // The summary can miss names the member payloads carry — prefer a member's
    // real name (source dimmed beside it) over asserting absence.
    var named = name ? null : memberWithName(row.members);
    var title = name
      ? V.esc(name)
      : named
        ? V.esc(named.name) + ' <span style="color:var(--dim);font-weight:400;font-size:var(--fs-sm)">from ' + V.esc(named.source) + "</span>"
        : '<span style="color:var(--dim);font-weight:400">name not loaded</span>';
    var n = (row.members || []).length;
    var memberChips = (row.members || []).map(function (m) {
      return '<span class="entity-chip"><b>' + V.esc(m.source) + '</b><span class="src ref">' + V.esc(m.entity_id) + "</span></span>";
    }).join(" ");

    var statusChip, statusNote, accent;
    if (row.merged) {
      var conf = confidencePlain(row.badge);
      statusChip = conf.chip;
      statusNote = n + " source" + (n === 1 ? "" : "s") + " · " + conf.text +
        (row.badge ? " · " + V.esc(row.badge.evidence_count) + " piece" + (Number(row.badge.evidence_count) === 1 ? "" : "s") + " of evidence" : "");
      accent = ";border-left:3px solid var(--green)";
    } else {
      statusChip = V.badge("single source", "b-kind");
      statusNote = n + " source" + (n === 1 ? "" : "s") + " · not yet linked to another record";
      accent = "";
    }

    return '<div class="card ent-card" data-i="' + i + '" style="cursor:pointer' + accent + '">' +
      '<div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">' +
        '<span style="font-size:var(--fs-md);font-weight:650;color:var(--bright)">' + title + "</span>" +
        (row.summary && row.summary.domain ? '<span class="badge b-kind">' + V.esc(row.summary.domain) + "</span>" : "") +
        statusChip +
        '<span class="spacer" style="flex:1"></span>' +
        '<span class="asof">inspect &rsaquo;</span>' +
      "</div>" +
      '<div class="note" style="margin-top:4px">' + statusNote + "</div>" +
      '<div style="margin-top:6px">' + memberChips + "</div>" +
      '<div style="margin-top:4px">' + V.refSpan(row.canonical_entity) + "</div>" +
    "</div>";
  }

  /* ------------------------------------------------------- detail drawer */

  function openDetail(row) {
    var named = memberWithName(row.members);
    var name = displayName(row.summary) || (named ? named.name : null);
    current = { canonical: row.canonical_entity, members: row.members || [], name: name || "", row: row };
    var statusChip = row.merged ? confidencePlain(row.badge).chip : V.badge("single source", "b-kind");
    var statusText = row.merged
      ? confidencePlain(row.badge).text +
        (row.badge ? " · " + V.esc(row.badge.evidence_count) + " piece" + (Number(row.badge.evidence_count) === 1 ? "" : "s") + " of evidence" : "")
      : "one source · not yet linked to another record";
    // A missing summary name is a lookup gap, not proof of namelessness.
    el("ent-drawer-title").textContent = name || "Entity (name not loaded)";
    el("ent-drawer-head").innerHTML =
      '<div>' + V.refSpan(row.canonical_entity) + "</div>" +
      '<div style="margin-top:6px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">' + statusChip +
        '<span class="note" style="margin-top:0">' + statusText + "</span>" +
      "</div>" +
      '<div style="margin-top:6px">' + current.members.map(function (m) {
        return '<span class="entity-chip"><b>' + V.esc(m.source) + '</b><span class="src ref">' + V.esc(m.entity_id) + "</span></span>";
      }).join(" ") + "</div>";

    // A single-source entity has nothing to merge and no cross-source winner to
    // pick — the scope-gated field-merge + split cards are for stitched
    // entities. Show an honest note instead of a card that can only come back
    // empty, and hide the two merge cards. Merged entities keep the full UI.
    var singleNote = el("ent-drawer-single");
    var mergedCard = el("ent-merged-card");
    var splitCard = el("ent-split-card");
    if (row.merged) {
      singleNote.innerHTML = "";
      mergedCard.style.display = "";
      splitCard.style.display = "";
      el("ent-merged-out").innerHTML = "";
      V.clearErr("ent-merged-err");
      prec = { names: [], orders: {}, star: [], fields: {}, ready: false };
      if (lastHandle) el("ent-scope-handle").value = lastHandle;
      renderSplit();
    } else {
      mergedCard.style.display = "none";
      splitCard.style.display = "none";
      singleNote.innerHTML =
        '<div class="card" style="margin-top:12px">' +
          "<h2>Single-source entity</h2>" +
          '<div class="note" style="margin-top:0">This entity comes from a single source record, so there is nothing to ' +
            "merge and no cross-source winner to choose. It will gain a merged view the moment matching links it to " +
            "another record (same email, website domain, or external ID)." +
            (row.summary && row.summary.domain ? " Website domain on record: <b>" + V.esc(row.summary.domain) + "</b>." : "") +
          "</div>" +
        "</div>";
    }
    V.dialog("ent-drawer").open();
  }

  function renderSplit() {
    var host = el("ent-split");
    if (current.members.length < 2) {
      host.innerHTML = '<div class="note">A split needs at least two source records — this entity has ' +
        current.members.length + ".</div>";
      return;
    }
    var opts = current.members.map(function (m) {
      var ref = m.source + ":" + m.entity_id;
      return '<option value="' + V.esc(ref) + '">' + V.esc(m.source) + " · " + V.esc(m.entity_id) + "</option>";
    }).join("");
    host.innerHTML =
      '<div class="row" style="margin-top:6px">' +
        '<div><label for="ent-split-left">this record</label><select class="field" id="ent-split-left">' + opts + "</select></div>" +
        '<div><label for="ent-split-right">is not the same as</label><select class="field" id="ent-split-right">' + opts + "</select></div>" +
        '<div class="tight"><button class="danger" id="ent-split-go">Split &mdash; keep separate</button></div>' +
      "</div>" +
      '<div class="err" id="ent-split-err"></div>';
    var rsel = el("ent-split-right");
    if (rsel.options.length > 1) rsel.selectedIndex = 1;
    // Each side of the permanent dialog gets its OWN label — the two source
    // records being split, never the merged entity's one name twice.
    function splitLabel(ref) {
      for (var i = 0; i < current.members.length; i++) {
        var m = current.members[i];
        if (m.source + ":" + m.entity_id === ref && m.name) return m.name + " — " + m.source;
      }
      return describeRef(ref);
    }
    el("ent-split-go").onclick = function () {
      V.clearErr("ent-split-err");
      var l = el("ent-split-left").value;
      var r = el("ent-split-right").value;
      if (l === r) { V.err("ent-split-err", new Error("pick two different records to split apart")); return; }
      openDecide(l, r, "reject", splitLabel(l), splitLabel(r));
    };
  }

  /* -------------------------------------- merged fields + source ranking */

  async function loadMerged() {
    V.clearErr("ent-merged-err");
    el("ent-merged-out").innerHTML = "";
    var handle = el("ent-scope-handle").value.trim();
    if (!handle) {
      V.err("ent-merged-err", new Error("this read is scope-gated (it uses the same fail-closed path agents do) — paste a scope handle or mint one"));
      return;
    }
    lastHandle = handle;
    try {
      var res = await V.api("/v1/entities/" + encodeURIComponent(current.canonical) +
        "?scope_handle=" + encodeURIComponent(handle));
      buildPrec(res);
      renderMerged(res);
    } catch (e) {
      V.err("ent-merged-err", e);
    }
  }

  function valKey(v) {
    try { return JSON.stringify(v === undefined ? null : v); } catch (e) { return String(v); }
  }
  // Cross-source conflicts: a DIFFERENT source carrying a DIFFERENT value.
  function fieldConflicts(f) {
    var wv = valKey(f.value);
    return (f.superseded_alternatives || []).filter(function (a) {
      return a.source !== f.winning_source && valKey(a.value) !== wv;
    });
  }
  // HONEST rule inference (no GET for ranking rows exists): the no-rule
  // tie-break is newest-wins, so a winner that is NOT the newest cross-source
  // value proves a ranking overrode recency. A winner that IS the newest is
  // indistinguishable from no rule — said exactly, never guessed.
  function ruleInferred(f) {
    var wf = Date.parse(f.valid_from) || 0;
    return (f.superseded_alternatives || []).some(function (a) {
      return a.source !== f.winning_source && (Date.parse(a.valid_from) || 0) > wf;
    });
  }

  function buildPrec(res) {
    var fields = (res && res.fields) || {};
    prec = { names: Object.keys(fields), orders: {}, star: [], fields: fields, ready: true };
    var starSeen = {};
    prec.names.forEach(function (name) {
      var f = fields[name];
      var seen = {}, order = [];
      function push(s) {
        if (!seen[s]) { seen[s] = true; order.push(s); }
        if (!starSeen[s]) { starSeen[s] = true; prec.star.push(s); }
      }
      push(f.winning_source);
      (f.superseded_alternatives || []).forEach(function (a) { push(a.source); });
      prec.orders[name] = order;
    });
  }

  function renderMerged(res) {
    var host = el("ent-merged-out");
    var fields = (res && res.fields) || {};
    var names = Object.keys(fields);
    if (!names.length) {
      host.innerHTML =
        '<div class="empty-teach sp-b" style="margin-bottom:0">' +
          '<div class="et-title">This handle cannot see any of this entity&rsquo;s fields</div>' +
          '<div class="et-body">Fail-closed emptiness is a correct answer, not a bug: the handle&rsquo;s claims do not ' +
            "reach this entity&rsquo;s records. To see why, decode the handle on the Scope Inspector; to see more, " +
            "mint a handle with broader claims.</div>" +
          '<div class="et-actions"><button id="ent-merged-whynot">Decode this handle on Scope Inspector</button></div>' +
        "</div>";
      el("ent-merged-whynot").onclick = function () {
        V.dialog("ent-drawer").close();
        V.show("scope", { handle: el("ent-scope-handle").value.trim() });
      };
      return;
    }

    var blocks = names.map(function (name, fi) {
      var f = fields[name];
      var order = prec.orders[name];
      var conflicts = fieldConflicts(f);
      var inferred = ruleInferred(f);
      var multi = order.length > 1;

      var ruleChip = inferred
        ? V.badge("ranking rule in effect", "b-provenance")
        : multi
          ? V.badge("no ranking detected — newest value wins", "b-inferred", true)
          : V.badge("single source", "b-kind");
      var conflictChip = conflicts.length
        ? '<span class="badge b-st-eligible" title="another source currently carries a different value for this field">sources disagree</span>'
        : "";

      var altRows = (f.superseded_alternatives || []).map(function (a) {
        return '<div class="note" style="margin-top:2px">also on record: <b>' + V.esc(fmtVal(a.value)) + "</b> from " +
          V.esc(a.source) + " (since " + V.esc(V.fmtTime(a.valid_from)) + ") " + V.refSpan(a.entity_id) + "</div>";
      }).join("");

      var ranking = multi
        ? '<div style="margin-top:8px"><div class="note" style="margin-top:0">Which source should win this field? Highest first:</div>' +
            rankList(order, fi) +
            '<div class="dc-actions" style="margin-top:6px">' +
              '<button class="ent-prec-save" data-fi="' + fi + '" title="POST /v1/admin/entity-precedence — saves this order for this field of this entity">Save ranking for this field</button>' +
            "</div>" +
            '<div id="ent-prec-msg-' + fi + '"></div>' +
          "</div>"
        : "";

      return '<div class="hit" style="margin-bottom:10px">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          "<b>" + V.esc(name) + "</b> = <b>" + V.esc(fmtVal(f.value)) + "</b>" +
          '<span class="note" style="margin-top:0">from ' + V.esc(f.winning_source) + "</span>" +
          ruleChip + conflictChip +
        "</div>" +
        altRows +
        (conflicts.length && !inferred
          ? '<div class="note"><em>Sources disagree and no ranking is set</em> — the winner above is simply the newest value. ' +
            "Set a ranking below to make the choice yours instead of the clock&rsquo;s.</div>"
          : "") +
        ranking +
      "</div>";
    }).join("");

    var starBlock = prec.star.length > 1
      ? '<div class="hit" style="margin-bottom:10px">' +
          "<div><b>Default for every other field</b> " +
            V.badge("applies where no per-field ranking exists", "b-kind") + "</div>" +
          rankList(prec.star, "*") +
          '<div class="dc-actions" style="margin-top:6px">' +
            '<button class="ent-prec-save" data-fi="*" title="POST /v1/admin/entity-precedence with field=&quot;*&quot;">Save default ranking</button>' +
          "</div>" +
          '<div id="ent-prec-msg-star"></div>' +
        "</div>"
      : "";

    host.innerHTML =
      '<div class="note">Saving a ranking reloads this view so the new winners come from the server&rsquo;s own ' +
        "resolution — shown, never assumed.</div>" + blocks + starBlock;

    wire(host, ".ent-prec-move", function (btn) {
      var fi = btn.getAttribute("data-fi");
      var idx = parseInt(btn.getAttribute("data-idx"), 10);
      var dir = parseInt(btn.getAttribute("data-dir"), 10);
      var order = fi === "*" ? prec.star : prec.orders[prec.names[parseInt(fi, 10)]];
      if (!order) return;
      var j = idx + dir;
      if (idx < 0 || j < 0 || idx >= order.length || j >= order.length) return;
      var t = order[idx]; order[idx] = order[j]; order[j] = t;
      renderMerged({ fields: prec.fields });
    });
    wire(host, ".ent-prec-save", function (btn) { savePrecedence(btn, btn.getAttribute("data-fi")); });
  }

  function rankList(order, fi) {
    return order.map(function (src, i) {
      return '<div class="row" style="align-items:center;gap:6px;margin:2px 0">' +
        '<span class="badge b-kind" style="font-variant-numeric:tabular-nums" title="rank (1 wins)">#' + (i + 1) + "</span>" +
        V.badge(src, "b-kind") +
        '<button class="ent-prec-move" data-fi="' + fi + '" data-idx="' + i + '" data-dir="-1"' +
          (i === 0 ? " disabled" : "") + ' title="rank higher">&#9650;</button>' +
        '<button class="ent-prec-move" data-fi="' + fi + '" data-idx="' + i + '" data-dir="1"' +
          (i === order.length - 1 ? " disabled" : "") + ' title="rank lower">&#9660;</button>' +
      "</div>";
    }).join("");
  }

  async function savePrecedence(btn, fi) {
    V.clearErr("ent-merged-err");
    if (!tenantNow) { V.err("ent-merged-err", new Error("no space selected")); return; }
    var star = fi === "*";
    var field = star ? "*" : prec.names[parseInt(fi, 10)];
    var order = star ? prec.star : prec.orders[field];
    if (!field || !order || !order.length) {
      V.err("ent-merged-err", new Error("nothing to save — no ranked sources for this field"));
      return;
    }
    btn.disabled = true;
    try {
      var res = await V.api("/v1/admin/entity-precedence", { admin: true, json: {
        tenant_id: tenantNow,
        canonical: current.canonical,
        field: field,
        source_order: order,
      } });
      var msg = el(star ? "ent-prec-msg-star" : "ent-prec-msg-" + fi);
      if (msg) {
        msg.innerHTML = '<span class="refreshed">saved: ' +
          (res.source_order || []).map(V.esc).join(" &rsaquo; ") + " · reloading the view…</span>";
      }
      await loadMerged(); // show the rule's effect from the server, not client-side
    } catch (e) {
      V.err("ent-merged-err", e);
      btn.disabled = false;
    }
  }
})();
