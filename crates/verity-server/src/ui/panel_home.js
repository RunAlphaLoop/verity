"use strict";
/* ==========================================================================
   panel_home.js — HOME · "Needs decision" (UI-ACTIONS N3)
   --------------------------------------------------------------------------
   Reads (all admin-token gated; dev mode allows + is disclosed):
     • GET /v1/admin/entity-resolution/review-queue?tenant_id&limit — same
       query as the Entities panel's queue view
     • GET /v1/knowledge?tenant_id — same list the Knowledge panel renders;
       "awaiting" = status ∈ {candidate, eligible}
     • GET /v1/admin/quarantine?tenant_id — same list the Quarantine panel
       renders
     • GET /v1/slo/freshness?tenant_id — per-source ingest→queryable
       percentiles, measured server-side from real samples
     • GET /v1/admin/connector-status?tenant_id — source heartbeats; decides
       whether the "connect a real source" step is still open (heartbeat rows
       exist only after a connected source actually delivered — sample casts
       and hand ingests never write one)

   HONESTY:
     • every count is as-of-stamped and computed from the SAME query as the
       panel it links to — never a separate estimate;
     • the freshness "slow" flag uses a DISCLOSED console display threshold
       (p95 > 60 s), labeled as such — it is not a configured SLO and is
       never presented as one;
     • a failed probe renders a failed state chip with the server's error —
       never a fabricated zero;
     • urgency never cheapens a gate: the cards link to the panels; every
       decision keeps its full dialog weight there;
     • the "connect a real source" step handles no secrets and triggers no
       backfill (Phase 1) — every action on it is a deep link into the
       Sources panel's existing flows, and its state derives from the same
       heartbeat rows that panel renders.
   ========================================================================== */
(function () {
  var V = window.Verity;

  // Console display threshold for "slow source" (disclosed, not an SLO).
  var SLOW_P95_MS = 60000;

  var lastLoadedAt = 0;

  function el(id) { return V.$(id); }

  /* One attention card. spec: {id, title, desc, href(panel,params), state,
     count(text or number), foot, fail} */
  function cardHtml(c) {
    var cls = "attn-card" + (c.tone === "attn" ? " attn-needs" : c.tone === "fail" ? " attn-fail" : "");
    return '<button type="button" class="' + cls + '" id="' + c.id + '">' +
      '<div class="attn-top"><span class="attn-title">' + c.title + "</span>" + c.state + "</div>" +
      '<div class="attn-count">' + c.count + "</div>" +
      '<div class="attn-desc">' + c.desc + "</div>" +
      '<div class="attn-foot"><span class="asof">' + c.foot + "</span>" +
        '<span class="asof">open &rsaquo;</span></div>' +
    "</button>";
  }

  function asofNow() { return "checked " + new Date().toTimeString().slice(0, 8); }

  /* ---- no-tenant teach state — FTUE §1: driven by SERVER TRUTH ---------- */
  /* GET /v1/admin/tenants (read once by core, refreshed on token change)
     decides which of the four states this card teaches. The old circular
     "paste a tenant id you cannot obtain" advice only survives on servers
     that cannot list tenants (State D). */
  function renderNoTenant(host) {
    var dir = V.tenantDir();

    if (dir.status === "ok" && dir.tenants.length === 0) {
      // State A — virgin server: Home renders the Welcome flow (FTUE step 0).
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Welcome to Verity</div>' +
          '<div class="et-body">Verity is shared memory for your AI agents — everything they learn, in one place, ' +
            "carrying the same sharing rules your company already has." +
            '<div style="margin-top:8px">One thing to know before you start: <b>when Verity isn’t sure someone may ' +
            "see a memory, it shows them nothing.</b> An empty result here is a safety answer, not a bug — and by " +
            "the end of setup you’ll see exactly why that’s the feature.</div>" +
            '<div style="margin-top:8px" class="asof">this server has no spaces yet (checked live against the server just now' +
            '<span class="api-crumb"> · GET /v1/admin/tenants</span>) — there is nothing to paste; setup creates the first one</div></div>' +
          '<div class="et-actions">' +
            '<button class="primary" id="home-setup">Set up Verity — about 5 minutes</button>' +
          "</div>" +
        "</div>";
      el("home-setup").onclick = function () { V.show("welcome"); };
      return;
    }

    if (dir.status === "ok") {
      // State B — spaces exist: the session strip is a picker of names now.
      // dir.total is the server's real count; the page may be truncated.
      var listed = dir.tenants.length;
      var total = typeof dir.total === "number" ? dir.total : listed;
      var countLine = total === listed
        ? "This server has " + total + " space" + (total === 1 ? "" : "s") +
          ". Pick one <b>by name</b> in the bar above — no ids to hunt for — or run setup to create a new one."
        : "This server has " + total + " spaces (the picker lists the newest " + listed +
          "). Pick one <b>by name</b> in the bar above, or run setup to create a new one.";
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Pick a space to see what needs you</div>' +
          '<div class="et-body">' + countLine + "</div>" +
          '<div class="et-actions">' +
            '<button class="primary" id="home-setup">Set up Verity</button>' +
            '<button id="home-newspace">Create a new space</button>' +
          "</div>" +
        "</div>";
      el("home-setup").onclick = function () { V.show("welcome"); };
      el("home-newspace").onclick = function () { V.openCreateTenant(); };
      return;
    }

    if (dir.status === "locked") {
      // State C — prod admin plane locked: no wizard until a token exists.
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Enter your admin token to list spaces and run setup</div>' +
          '<div class="et-body">This server’s admin plane is locked (a good sign in production). Set the ' +
            "<b>admin token</b> in the session bar above to see this server’s spaces (tenants) by name. Already know your " +
            "space id? Paste it in the bar — every screen loads itself once it’s set. The token stays in this " +
            "tab only, never on disk.</div>" +
        "</div>";
      return;
    }

    // State D — old server (can't list tenants) or directory unreachable:
    // today's teach card, unchanged.
    host.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Connect to a space to see what needs you</div>' +
        '<div class="et-body">Verity scopes everything to one <b>space (tenant)</b>. Give the console one, three ways:' +
          "<ul style=\"margin:8px 0 0 18px;color:var(--dim)\">" +
          "<li><b>Paste a space id</b> into the session bar above and press Enter.</li>" +
          "<li><b>Mint a scope handle</b> — the signed key an agent reads with; the space fills in automatically.</li>" +
          "<li><b>Decode a scope handle</b> you already hold on the Scope Inspector.</li></ul>" +
          '<div style="margin-top:8px">Running locally? <span class="ref">verity-cli dev</span> prints your dev space and a ready-made scope handle.</div>' +
          (dir.status === "error" ? '<div class="asof" style="margin-top:6px">couldn’t list this server’s spaces: ' + V.esc(dir.error.slice(0, 120)) + "</div>" : "") +
        "</div>" +
        '<div class="et-actions">' +
          '<button class="primary" id="home-mint">Mint a scope handle</button>' +
          '<button id="home-goscope">Open Scope Inspector</button>' +
        "</div>" +
      "</div>";
    el("home-mint").onclick = function () { V.openMint(); };
    el("home-goscope").onclick = function () { V.show("scope"); };
  }

  /* ---- ghost tenant (FTUE §1): a uuid the server never birthed ---------- */
  /* The directory page is truncated (limit=500) — absence from the PAGE is
     only a confirmed miss when the page holds the whole directory. Returns
     "listed" | "unlisted" (absent from a truncated page — NOT a ghost) |
     "ghost" (directory complete AND id absent) | "unknown". */
  function dirLookup(dir, tenant) {
    if (dir.status !== "ok") return "unknown";
    if (dir.tenants.some(function (x) { return x.tenant_id === tenant; })) return "listed";
    // Off the (possibly truncated) directory page: resolve DEFINITIVELY via
    // the point lookup instead of guessing from page arithmetic. Memoized;
    // re-emits onTenantDir when it lands, which re-runs this panel's derive.
    V.confirmTenantById(tenant);
    var c = V.confirmedTenant(tenant);
    if (!c) return "unknown"; // in flight — neutral, never a premature ghost
    return c.state === "confirmed" ? "unlisted" : c.state === "ghost" ? "ghost" : "unknown";
  }

  function renderGhost(host, tenant) {
    host.innerHTML =
      '<div class="empty-teach sp-a" style="border-left-color:var(--red)">' +
        '<div class="et-title">This space doesn’t exist on this server</div>' +
        '<div class="et-body">The id <span class="ref">' + V.esc(tenant) + "</span> is not in this server’s space " +
          "list (confirmed against the server just now). A made-up or stale id would otherwise show a permanently empty console that looks " +
          "plausible — so this is a loud stop, never a green all-clear. Pick a real space in the bar above, or set " +
          "one up.</div>" +
        '<div class="et-actions">' +
          '<button class="primary" id="home-setup">Set up Verity</button>' +
          '<button id="home-newspace">Create a new space</button>' +
        "</div>" +
      "</div>";
    el("home-setup").onclick = function () { V.show("welcome"); };
    el("home-newspace").onclick = function () { V.openCreateTenant(); };
  }

  /* ---- the four probes -------------------------------------------------- */

  async function probeEntities(tenant) {
    var rows = await V.api("/v1/admin/entity-resolution/review-queue?tenant_id=" +
      encodeURIComponent(tenant) + "&limit=500", { admin: true });
    rows = rows || [];
    var oldest = 0;
    rows.forEach(function (r) { var w = Number(r.wait_age_secs); if (isFinite(w) && w > oldest) oldest = w; });
    V.setCount("entities", rows.length);
    return {
      id: "home-card-entities",
      title: "Same or different?",
      tone: rows.length ? "attn" : "ok",
      state: rows.length ? V.stateChip("attn") : V.stateChip("ok", "queue clear"),
      count: String(rows.length),
      desc: rows.length
        ? "possible entity match" + (rows.length === 1 ? "" : "es") + " waiting for a human yes/no — oldest has waited <b>" + V.esc(V.fmtAge(oldest)) + "</b>"
        : "no possible matches waiting — matching settled everything it saw",
      foot: asofNow(),
      go: function () { V.show("entities", { view: "queue" }); },
    };
  }

  async function probeKnowledge(tenant) {
    var res = await V.api("/v1/knowledge?tenant_id=" + encodeURIComponent(tenant));
    var items = (res && res.items) || [];
    var waiting = items.filter(function (k) {
      return k.status === "candidate" || k.status === "eligible";
    });
    var oldest = null;
    waiting.forEach(function (k) {
      var t = Date.parse(k.first_seen);
      if (isFinite(t) && (oldest === null || t < oldest)) oldest = t;
    });
    V.setCount("knowledge", waiting.length);
    return {
      id: "home-card-knowledge",
      title: "Knowledge awaiting review",
      tone: waiting.length ? "attn" : "ok",
      state: waiting.length ? V.stateChip("attn") : V.stateChip("ok", "queue clear"),
      count: String(waiting.length),
      desc: waiting.length
        ? "lesson" + (waiting.length === 1 ? "" : "s") + " waiting for review — publishing stays a human gate" +
          (oldest ? " · oldest proposed <b>" + V.esc(V.timeAgo(oldest)) + "</b>" : "")
        : "nothing proposed and unpublished — the queue is drained",
      foot: asofNow(),
      go: function () { V.show("knowledge"); },
    };
  }

  async function probeQuarantine(tenant) {
    var rows = await V.api("/v1/admin/quarantine?tenant_id=" + encodeURIComponent(tenant), { admin: true });
    rows = rows || [];
    var oldest = null;
    rows.forEach(function (r) {
      var t = Date.parse(r.at);
      if (isFinite(t) && (oldest === null || t < oldest)) oldest = t;
    });
    V.setCount("quarantine", rows.length);
    return {
      id: "home-card-quarantine",
      title: "Quarantine",
      tone: rows.length ? "attn" : "ok",
      state: rows.length ? V.stateChip("attn") : V.stateChip("ok", "empty"),
      count: String(rows.length),
      desc: rows.length
        ? "payload" + (rows.length === 1 ? "" : "s") + " Verity refused to index (no mappable permissions) — fix &amp; re-ingest, or dismiss" +
          (oldest ? " · oldest arrived <b>" + V.esc(V.timeAgo(oldest)) + "</b>" : "")
        : "nothing held — every payload arrived with mappable permissions",
      foot: asofNow(),
      go: function () { V.show("quarantine"); },
    };
  }

  async function probeFreshness(tenant) {
    var rows = await V.api("/v1/slo/freshness?tenant_id=" + encodeURIComponent(tenant), { admin: true });
    rows = rows || [];
    var slow = rows.filter(function (r) { return Number(r.p95_ms) > SLOW_P95_MS; });
    var slowest = null;
    rows.forEach(function (r) {
      if (!slowest || Number(r.p95_ms) > Number(slowest.p95_ms)) slowest = r;
    });
    var desc;
    if (!rows.length) {
      desc = "no ingest measured in the last 24 h — nothing to report is a valid answer";
    } else if (slow.length) {
      desc = "source" + (slow.length === 1 ? "" : "s") + " where new memories take over <b>60 s</b> to become searchable for 5% of items " +
        "(p95 — a console display threshold, not a configured target/SLO) — slowest: " +
        '<span class="ref">' + V.esc(slowest.source) + "</span> at <b>" + V.esc(V.fmtMs(slowest.p95_ms)) + "</b>";
    } else {
      desc = "all " + rows.length + " source" + (rows.length === 1 ? "" : "s") + " fresh — slowest source: 95% of new memories searchable within " +
        "<b>" + V.esc(V.fmtMs(slowest.p95_ms)) + "</b> (p95, " + '<span class="ref">' + V.esc(slowest.source) + "</span>)";
    }
    return {
      id: "home-card-freshness",
      title: "Ingest freshness",
      tone: slow.length ? "attn" : "ok",
      state: rows.length === 0 ? V.stateChip("off", "no samples")
        : slow.length ? V.stateChip("attn", slow.length + " slow") : V.stateChip("ok"),
      count: slow.length ? String(slow.length) : String(rows.length),
      desc: desc + " · measured server-side from real samples (24 h window)",
      foot: asofNow(),
      go: function () { V.show("sources"); },
    };
  }

  /* A failed probe → an honest failed card, never a fabricated zero. */
  function failCard(id, title, err, go) {
    var msg = String((err && err.message) || err);
    var needsToken = msg.indexOf("401") >= 0 || msg.indexOf("403") >= 0;
    return {
      id: id,
      title: title,
      tone: "fail",
      state: V.stateChip("fail", needsToken ? "admin token required" : "failed"),
      count: "—",
      desc: needsToken
        ? "this count needs the admin token — set it in the session bar above"
        : V.esc(msg.slice(0, 140)),
      foot: asofNow(),
      go: go,
    };
  }

  /* ---- setup checklist (FTUE §4) — persistent by DERIVATION ------------- */
  /* Every item's state is recomputed from server truth by VerityFtue.derive
     (panel_welcome.js) on every Home load. There is no stored checklist
     state to lie, no "mark as done" anywhere: if the system can't observe
     it, it isn't an item. Item 3 is honestly labeled per-session. */
  function checklistItemRow(item) {
    var chip;
    if (item.done && item.celebrated) chip = V.stateChip("ok", "denied — correctly ✦");
    else if (item.done) chip = V.stateChip("ok", "done" + (item.perSession ? " · this tab" : ""));
    else if (item.needsAdmin) chip = V.stateChip("attn", "needs admin token");
    else chip = V.stateChip("off", "not yet");
    var sub = {
      space: "the space that owns this memory exists",
      keys: "at least one person or group holds a key",
      session: "this browser session holds a working handle (per-session — re-mint is one click)",
      memory: "at least one memory is stored (or quarantined — that counts: it means the gate works)",
      recall: "a scoped recall returned results",
      denial: "a session that holds no matching keys got zero results, with the why-trace to show for it",
      bench: "measure YOUR p50/p95/p99 on YOUR corpus",
    }[item.id] || "";
    var action = "";
    if (!item.done) {
      if (item.id === "session") action = '<button data-check-mint="1">Mint a handle</button>';
      else if (item.id === "bench") action = "";
      else action = '<button data-check-step="' + item.n + '">' +
        ({ space: "Create the space", keys: "Add keys", memory: "Put memory in", recall: "Run the recall proof", denial: "Run the denial proof" }[item.id] || "Open setup") +
        "</button>";
    }
    return '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:7px 0;border-bottom:1px solid var(--border)">' +
      chip +
      '<span><b style="color:var(--bright)">' + V.esc(item.title) + (item.optional ? " (optional)" : "") + "</b>" +
        ' <span style="color:var(--dim)">— ' + sub + "</span></span>" +
      '<span class="asof" style="flex:1;text-align:right">' + V.esc(item.evidence) + "</span>" + action +
    "</div>";
  }

  function renderChecklist(container, check, tenant) {
    var ftue = window.VerityFtue;
    var core = check.items.slice(0, 6);
    var allDone = core.every(function (i) { return i.done; });

    if (allDone && ftue.checklistHidden(tenant)) { container.innerHTML = ""; return; }

    if (allDone) {
      container.innerHTML =
        '<div class="empty-teach sp-c" style="margin-top:0">' +
          '<div class="et-title">Setup complete — your memory plane is up, and it already told someone “no.”</div>' +
          '<div class="et-body">All six facts re-derived from the server just now' +
            " · the benchmark slot stays honestly empty until your own run: " +
            '<span class="ref">cargo run -p verity-bench -- run</span></div>' +
          '<div class="et-actions">' +
            '<button id="home-next-toggle">Show next steps</button>' +
            '<button id="home-check-hide">Hide for this session</button>' +
          "</div>" +
        "</div>" +
        '<div id="home-next-cards" style="display:none"></div>';
      el("home-next-toggle").onclick = function () {
        var cards = el("home-next-cards");
        var open = cards.style.display !== "none";
        cards.style.display = open ? "none" : "";
        el("home-next-toggle").textContent = open ? "Show next steps" : "Hide next steps";
        if (!open && !cards.innerHTML) {
          cards.innerHTML = ftue.nextStepsHtml(check);
          ftue.wireNextSteps({});
        }
      };
      el("home-check-hide").onclick = function () {
        ftue.hideChecklist(tenant);
        container.innerHTML = "";
      };
      return;
    }

    var doneCount = core.filter(function (i) { return i.done; }).length;
    container.innerHTML =
      '<div class="card">' +
        "<h2>Setup checklist <span class=\"sub\">" + doneCount + " of 6 · checked live against the server just now — nothing here is a saved checkbox</span></h2>" +
        core.map(checklistItemRow).join("") +
        (core[5].done ? checklistItemRow(check.items[6]) : "") +
        '<div class="asof" style="margin-top:8px">the last step is watching Verity correctly tell someone <b>“no”</b> — ' +
          "a denial you can verify is the finish line, not an error · " + asofNow() + "</div>" +
      "</div>";
    var steps = container.querySelectorAll("[data-check-step]");
    for (var i = 0; i < steps.length; i++) {
      (function (btn) {
        btn.onclick = function () { V.show("welcome", { step: Number(btn.getAttribute("data-check-step")) }); };
      })(steps[i]);
    }
    var mint = container.querySelector("[data-check-mint]");
    if (mint) mint.onclick = function () { V.show("welcome", { step: 3 }); };
  }

  /* ---- "Connect a real source" (Phase 1) — an INDEPENDENT step ---------- */
  /* Deliberately NOT an eighth VerityFtue item: this panel and the wizard
     hard-code the 6-core proof-beat structure (slice(0,6), "of 6", id-keyed
     copy), so this step renders from its own container and its own probe.
     It appears once the memory beat is satisfied (any memory arrived —
     hand-added, sample, or quarantined) and retires once a connector
     heartbeat proves a connected source actually delivered: connector_status
     rows only exist after a first successful delivery, and neither sample
     casts nor hand ingests ever write one. The converse is NOT true — a
     webhook-fed source delivers without ever writing a heartbeat (only
     connector CLIs and folder watches report one), and freshness samples
     can't disambiguate (hand ingests write those too) — so the open-step
     copy claims only "no status report", never that nothing was delivered.
     Phase 1 ships no secret handling
     and no backfill triggering — every button here is a deep link into the
     Sources panel's existing flows (the zero-credential folder dialog is
     the only live write, and it lives THERE, not here). */
  function renderConnectSource(container, check, probe) {
    // Rides the same first-run flow as the checklist: no derivation (legacy
    // server, failed derive, or no tenant) → no step, same as its absence.
    if (!check || !probe) { container.innerHTML = ""; return; }
    var mem = null;
    check.items.forEach(function (i) { if (i.id === "memory") mem = i; });
    // No first ingest signal yet — checklist step 4 owns getting there.
    if (!mem || !mem.done) { container.innerHTML = ""; return; }

    if (probe.ok && probe.rows.length > 0) {
      // Satisfied: at least one connected source has delivered and reported.
      // Ongoing per-source status lives on the Sources panel — a completed
      // step is not a decision, so Home drops it rather than pinning a
      // permanent trophy card.
      container.innerHTML = "";
      return;
    }

    var chip, note;
    if (!probe.ok) {
      // A failed probe renders as failed — never a fabricated "not yet".
      chip = probe.needsAdmin ? V.stateChip("attn", "needs admin token") : V.stateChip("fail", "check failed");
      note = probe.needsAdmin
        ? "whether a connected source has delivered yet needs the admin token — set it in the session bar above"
        : "couldn’t check for source heartbeats: " + V.esc(probe.err.slice(0, 140));
    } else {
      chip = V.stateChip("off", "no status reports yet");
      note = "no source has sent a status report — connector CLIs and folder watches send one after " +
        "their first delivery; webhook sources never do, so a webhook you’ve minted may already be " +
        "delivering (its freshness lives on the Sources panel)";
    }

    container.innerHTML =
      '<div class="card">' +
        '<h2>Connect a real source <span class="sub api-crumb">GET /v1/admin/connector-status</span></h2>' +
        '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:7px 0">' +
          chip + '<span style="color:var(--dim)">' + note + "</span></div>" +
        '<div style="color:var(--dim)">Memory is flowing — the next step is a source that feeds itself. Fastest start, ' +
          "<b>no credentials</b>: watch a local folder on this computer — files you drop there become memory, visible " +
          "only to the viewers you pick. When you’re ready for live tools, <b>Google Drive</b>, <b>Gmail</b>, " +
          "<b>Google Directory</b>, and <b>HubSpot</b> connect today — Drive, Gmail, and HubSpot each run their own " +
          "connector from your terminal; Directory sync starts from the System panel (or <span class=\"ref\">verity-cli dev --directory</span>) " +
          "using a key-file path set on the server. Credentials never touch this console. <b>Salesforce</b> is listed but gated (awaiting a test org).</div>" +
        '<div class="toolbar" style="margin:10px 0 0">' +
          '<button class="primary" id="home-connect-folder">Watch a local folder</button>' +
          '<button id="home-connect-sources">Open Sources</button>' +
          '<span class="asof">' + asofNow() + "</span>" +
        "</div>" +
      "</div>";
    el("home-connect-folder").onclick = function () { V.show("sources", { view: "folder" }); };
    el("home-connect-sources").onclick = function () { V.show("sources"); };
  }

  /* ---- render ------------------------------------------------------------ */
  async function refresh(tenant) {
    var host = el("home-mount");
    if (!host) return;
    lastLoadedAt = Date.now();

    // Ghost guard (FTUE §1): a tenant id the server never birthed must be a
    // loud stop, never a plausible, permanently empty console. Absence from
    // a TRUNCATED directory page is not evidence of a ghost — load normally.
    var dir = V.tenantDir();
    if (dirLookup(dir, tenant) === "ghost") {
      renderGhost(host, tenant);
      return;
    }

    host.innerHTML =
      '<div class="toolbar"><span class="asof">checking the queues&hellip;</span></div>' +
      '<div class="attn-grid" id="home-grid"></div>';

    // Setup-checklist derivation runs alongside the queue probes (same
    // honesty rule: every state from server truth, stamped as-of). Skipped
    // on servers that cannot list tenants (State D — behavior unchanged).
    var ftue = window.VerityFtue;
    var checkPromise = (ftue && dir.status !== "unsupported")
      ? ftue.derive(tenant).catch(function (e) { console.error("ftue derive", e); return null; })
      : Promise.resolve(null);

    // The connect-a-real-source step's own probe (independent of the beats
    // model above; gated the same way so legacy servers skip both). Resolves
    // to an outcome, never throws — a failed read must render as failed.
    var connectPromise = (ftue && dir.status !== "unsupported")
      ? V.api("/v1/admin/connector-status?tenant_id=" + encodeURIComponent(tenant), { admin: true })
          .then(function (rows) { return { ok: true, rows: rows || [] }; })
          .catch(function (e) {
            var m = String((e && e.message) || e);
            return { ok: false, err: m, needsAdmin: /HTTP 40[13]/.test(m) };
          })
      : Promise.resolve(null);

    var probes = [
      [probeEntities, "home-card-entities", "Same or different?", function () { V.show("entities", { view: "queue" }); }],
      [probeKnowledge, "home-card-knowledge", "Knowledge awaiting review", function () { V.show("knowledge"); }],
      [probeQuarantine, "home-card-quarantine", "Quarantine", function () { V.show("quarantine"); }],
      [probeFreshness, "home-card-freshness", "Ingest freshness", function () { V.show("sources"); }],
    ];
    var results = await Promise.all(probes.map(function (p) {
      return p[0](tenant).catch(function (e) { return failCard(p[1], p[2], e, p[3]); });
    }));
    var check = await checkPromise;
    var connect = await connectPromise;

    // Re-check the ghost guard AFTER the async probes: the tenant directory
    // often lands mid-flight, and a ghost tenant's probes come back as clean
    // zeros — writing them would paint the exact plausible-empty-console
    // (green "all clear" for a space that doesn't exist) FTUE §1 forbids.
    // Same guard for a tenant switched away from while probes were in flight.
    if (V.tenant() !== tenant) return;
    dir = V.tenantDir();
    if (dirLookup(dir, tenant) === "ghost") {
      renderGhost(host, tenant);
      return;
    }

    var allClear = results.every(function (c) { return c.tone === "ok"; });
    var anyFail = results.some(function (c) { return c.tone === "fail"; });

    var grid = results.map(cardHtml).join("");
    var banner = "";
    if (allClear) {
      banner =
        '<div class="empty-teach sp-c" style="margin-top:0">' +
          '<div class="et-title">Nothing needs you right now</div>' +
          '<div class="et-body">All four queues are clear — the counts above are the evidence, checked just now. ' +
            "New matches, proposed knowledge, and refused payloads will appear here the moment they need a human.</div>" +
        "</div>";
    }

    host.innerHTML =
      '<div class="toolbar">' +
        V.stateChip(anyFail ? "fail" : allClear ? "ok" : "attn",
          anyFail ? "some checks failed" : allClear ? "all clear" : "decisions waiting") +
        // No off-page "loaded by id" note here — the top bar already carries it
        // on every screen (the cold reviewer flagged the per-panel repeats).
        '<span class="asof">counts come from the same queries as the panels they open &middot; ' + asofNow() + "</span>" +
        '<span class="spacer"></span>' +
        '<button id="home-refresh">Refresh</button>' +
      "</div>" +
      '<div id="home-checklist"></div>' +
      // Own container, OUTSIDE #home-checklist on purpose: the step must
      // survive "Hide for this session" (which empties the checklist).
      '<div id="home-connect-source"></div>' +
      banner +
      '<div class="attn-grid" id="home-grid">' + grid + "</div>" +
      '<div class="card">' +
        "<h2>Shortcuts</h2>" +
        '<div class="toolbar" style="margin-bottom:0">' +
          '<button id="home-goingest">Add memory</button>' +
          '<button id="home-mint2">Mint a scope handle</button>' +
          '<button id="home-run-res">Review entity matches</button>' +
          '<button id="home-goaudit">Open the access audit</button>' +
          '<span class="asof">or from a terminal: <span class="ref">verity-cli add &lt;file|url&gt;</span></span>' +
        "</div>" +
      "</div>";

    results.forEach(function (c) {
      var btn = el(c.id);
      if (btn) btn.onclick = c.go;
    });
    if (check) renderChecklist(el("home-checklist"), check, tenant);
    renderConnectSource(el("home-connect-source"), check, connect);
    el("home-refresh").onclick = function () { refresh(tenant); };
    el("home-goingest").onclick = function () { V.show("ingest"); };
    el("home-mint2").onclick = function () { V.openMint(); };
    el("home-run-res").onclick = function () { V.show("entities", { view: "queue" }); };
    el("home-goaudit").onclick = function () { V.show("audit"); };
  }

  V.register({
    id: "home",
    mount: function () {
      var host = el("home-mount");
      if (host && !V.tenant()) renderNoTenant(host);
      V.onTenant(function (t) {
        if (!t) { var h = el("home-mount"); if (h) renderNoTenant(h); }
      });
      // FTUE §1: the server's tenant-directory answer decides which teach
      // state (welcome / picker / locked / legacy) or ghost stop renders —
      // re-render when it lands or changes (e.g. admin token entered).
      V.onTenantDir(function (dir) {
        var h = el("home-mount");
        if (!h) return;
        var t = V.tenant();
        if (!t) { renderNoTenant(h); return; }
        // Ghost check must win even if a probe pass just started — a dead
        // uuid must never be left looking like a plausible empty console.
        if (dirLookup(dir, t) === "ghost") {
          renderGhost(h, t);
          return;
        }
        if (Date.now() - lastLoadedAt > 1500) refresh(t);
      });
    },
    // v2 AUTOLOAD: the router calls this once the tenant is known.
    load: function (_section, tenant) { return refresh(tenant); },
    // Re-check on every visit if the counts are older than 30 s.
    onShow: function () {
      var t = V.tenant();
      if (t && Date.now() - lastLoadedAt > 30000) refresh(t);
    },
  });
})();
