"use strict";
/* ==========================================================================
   panel_welcome.js — SET UP VERITY · first-run wizard + shared FTUE derivation
   --------------------------------------------------------------------------
   Implements FTUE.md §3 (steps 0–6) and exports `window.VerityFtue`, the ONE
   derivation of setup/checklist state that panel_home also renders (§4).

   Server truth, never a stored lie:
     • GET  /v1/admin/tenants        — space exists (item 1; States A–D)
     • GET  /v1/admin/principals     — keys exist (item 2) + token lookups
     • GET  /v1/knowledge, /v1/admin/quarantine, /v1/slo/freshness,
       GET  /v1/admin/audit          — memory-in (item 4), recall hit (5),
                                       verified denial (6)
   Per-session bits (working handle, proof runs when audit is unavailable)
   live in sessionStorage ONLY and are labeled per-session — never a fake
   checkmark, no "mark as done" anywhere.

   Fail-closed gates untouched: the proof is TWO ORDINARY POST /v1/recall
   calls composed client-side — nothing new on the read path, no LLM calls;
   the why-trace is the existing admin-gated POST /v1/admin/debug/recall.
   Sample data is another owner's module (sample_cast.js → window.VeritySample);
   when absent the card says so honestly instead of faking a seeder.
   ========================================================================== */
(function () {
  var V = window.Verity;

  var PROOF_KEY = "verity.session.proof";        // per-session proof evidence
  var BLIND_KEY = "verity.session.blind";        // the labeled blind handle
  var HIDE_KEY = "verity.session.checklist-hidden:"; // per-tenant, per-session

  /* ----------------------------------------------------- tiny helpers */
  function el(id) { return V.$(id); }
  function ssGet(k) { try { return JSON.parse(sessionStorage.getItem(k) || "null"); } catch (e) { return null; } }
  function ssSet(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* session-only */ } }
  function slug(s) {
    return String(s || "").trim().toLowerCase()
      .replace(/[^a-z0-9@._-]+/g, "-").replace(/^-+|-+$/g, "");
  }
  function asofNow() { return "checked " + new Date().toTimeString().slice(0, 8); }
  /* Materialized int tokens are never primary text (FTUE §3 step 2): render
     principal NAMES, falling back to "key #<n>" only when the directory
     doesn't know the token. */
  function nameTokens(tokens, principals) {
    var byToken = {};
    (principals || []).forEach(function (p) { byToken[p.token] = p.principal; });
    return (tokens || []).map(function (t) { return byToken[t] || "key #" + t; }).join(", ");
  }
  function proofState() { return ssGet(PROOF_KEY) || {}; }
  function setProof(patch) {
    var p = proofState();
    Object.keys(patch).forEach(function (k) { p[k] = patch[k]; });
    ssSet(PROOF_KEY, p);
  }

  /* An api() call that returns an outcome instead of throwing — a failed
     probe must render as failed, never as a fabricated zero. */
  async function tryApi(path, opts) {
    try { return { ok: true, value: await V.api(path, opts) }; }
    catch (e) {
      var m = String((e && e.message) || e);
      return { ok: false, err: m, needsAdmin: /HTTP 40[13]/.test(m) };
    }
  }

  /* ====================================================================
     THE DERIVATION (FTUE §4) — recomputed from endpoints on every call.
     Returns { dir, tenant, name, inList, items:[6+1], principals, users,
               groups, firstUser, sampleSeeded, probes }.
     ==================================================================== */
  async function derive(tenant) {
    var dir = V.tenantDir();
    if (dir.status === "unknown") { await V.refreshTenantDir(); dir = V.tenantDir(); }
    var enc = encodeURIComponent(tenant || "");
    var none = Promise.resolve({ ok: false, err: "no tenant yet", needsAdmin: false });
    var res = await Promise.all([
      tenant ? tryApi("/v1/admin/principals?tenant_id=" + enc + "&limit=1000", { admin: true }) : none,
      tenant ? tryApi("/v1/knowledge?tenant_id=" + enc) : none,
      tenant ? tryApi("/v1/admin/quarantine?tenant_id=" + enc, { admin: true }) : none,
      tenant ? tryApi("/v1/slo/freshness?tenant_id=" + enc, { admin: true }) : none,
      tenant ? tryApi("/v1/admin/audit?tenant_id=" + enc + "&limit=500", { admin: true }) : none,
    ]);
    var pr = res[0], kn = res[1], qu = res[2], fr = res[3], au = res[4];

    var principals = pr.ok ? ((pr.value && pr.value.principals) || []) : [];
    var named = principals.filter(function (p) { return /^(user|group):/.test(p.principal); });
    var users = principals.filter(function (p) { return p.principal.indexOf("user:") === 0; });
    var groups = principals.filter(function (p) { return p.principal.indexOf("group:") === 0; });
    var firstUser = users.filter(function (p) {
      return p.principal !== "user:sample-blind" && p.principal !== "user:proof-blind";
    })[0] || null;
    var sampleSeeded = principals.some(function (p) { return p.principal === "user:sample-blind"; });

    var knCount = kn.ok ? (((kn.value && kn.value.items) || []).length) : 0;
    var quCount = qu.ok ? ((qu.value || []).length) : 0;
    var frCount = fr.ok ? ((fr.value || []).length) : 0;
    var auditRows = au.ok ? (au.value || []) : [];
    var recalls = auditRows.filter(function (r) { return r.verb === "recall"; });
    var hitRow = null, zeroRow = null;
    recalls.forEach(function (r) { if (!hitRow && (r.result_ids || []).length > 0) hitRow = r; });
    if (hitRow) {
      recalls.forEach(function (r) {
        if (!zeroRow && (r.result_ids || []).length === 0 &&
            JSON.stringify(r.principals || []) !== JSON.stringify(hitRow.principals || [])) zeroRow = r;
      });
    }
    var proof = proofState();

    var name = tenant ? V.tenantName(tenant) : "";
    var inList = dir.status === "ok" && !!tenant &&
      dir.tenants.some(function (t) { return t.tenant_id === tenant; });

    /* --- item 1 · space created ------------------------------------- */
    var i1 = { n: 1, id: "space", title: "Space created", done: false, evidence: "", needsAdmin: false };
    if (dir.status === "ok") {
      var dirTotal = typeof dir.total === "number" ? dir.total : dir.tenants.length;
      if (inList) {
        i1.done = true;
        i1.evidence = "“" + (name || "(unnamed)") + "” exists on this server";
      } else if (!tenant) {
        i1.evidence = "no space yet";
      } else {
        /* Off the (possibly truncated) directory page — resolve existence
           DEFINITIVELY via the point lookup GET /v1/admin/tenants/{id} rather
           than inferring it from probe data. confirmTenantById is memoized and
           re-emits on land, so this fire-and-forget re-renders with the truth;
           until then item 1 stays neutral (never a premature green or a false
           ghost). */
        V.confirmTenantById(tenant);
        var c = V.confirmedTenant(tenant);
        if (!c) {
          i1.evidence = "confirming this space by its id…";
        } else if (c.state === "confirmed") {
          i1.done = true;
          i1.evidence = "“" + (c.name || "(unnamed)") + "” exists on this server — older than the newest " + dir.tenants.length + " the picker lists (this server has " + dirTotal + "), loaded by id";
        } else if (c.state === "ghost") {
          i1.ghost = true;
          i1.evidence = "this space id is NOT on this server — showing it as set up would be a lie, so it stays red";
        } else {
          i1.needsAdmin = !!c.locked;
          i1.evidence = c.locked
            ? "needs the admin token to confirm this space by its id"
            : "couldn’t confirm this space by its id just now";
        }
      }
    } else if (dir.status === "locked") {
      i1.needsAdmin = true;
      i1.evidence = "needs the admin token to verify this space against the server’s space directory";
    } else {
      i1.evidence = "this server build can't list spaces — existence unverifiable here";
    }

    /* --- item 2 · keys added ----------------------------------------- */
    var i2 = { n: 2, id: "keys", title: "Keys added", done: named.length >= 1, needsAdmin: !pr.ok && pr.needsAdmin };
    i2.evidence = pr.ok
      ? (named.length
        ? named.length + " key" + (named.length === 1 ? "" : "s") + ": " +
          named.slice(0, 4).map(function (p) { return p.principal; }).join(", ") + (named.length > 4 ? ", …" : "")
        : "no person or group holds a key yet")
      : (pr.needsAdmin ? "needs the admin token to read the key directory" : (tenant ? pr.err.slice(0, 90) : "no space yet"));

    /* --- item 3 · session open (honestly per-session) ------------------ */
    var wh = V.workingHandle();
    var whClaims = null, whOk = false, whWhy = "no working handle held by this tab yet";
    if (wh) {
      try {
        whClaims = V.decodeHandle(wh);
        var exp = whClaims.exp ? (whClaims.exp < 1e12 ? whClaims.exp * 1000 : whClaims.exp) : null;
        if (tenant && whClaims.tenant_id && whClaims.tenant_id !== tenant) {
          whWhy = "the held handle is for a different space — re-mint (one click)";
        } else if (exp && exp < Date.now()) {
          whWhy = "the held handle expired " + V.timeAgo(exp) + " — re-mint (one click)";
        } else { whOk = true; }
      } catch (e) { whWhy = "the held handle didn't decode — re-mint (one click)"; }
    }
    var i3 = {
      n: 3, id: "session", title: "Session open", done: whOk, perSession: true,
      evidence: whOk
        ? "working handle held — this tab only, cleared when the tab closes" +
          (whClaims && whClaims.principals ? " · keys: " + nameTokens(whClaims.principals, principals) : "")
        : whWhy,
    };

    /* --- item 4 · memory in ------------------------------------------- */
    var memBits = [];
    if (frCount) memBits.push(frCount + " source" + (frCount === 1 ? "" : "s") + " delivered memory in the last 24 h");
    if (knCount) memBits.push(knCount + " knowledge item" + (knCount === 1 ? "" : "s"));
    if (quCount) memBits.push(quCount + " item" + (quCount === 1 ? "" : "s") + " held in quarantine — held on purpose (its permissions couldn’t be mapped), which still proves memory is flowing in");
    var anyMemProbe = kn.ok || qu.ok || fr.ok;
    var i4 = {
      n: 4, id: "memory", title: "Memory in", done: memBits.length > 0,
      needsAdmin: !anyMemProbe && (qu.needsAdmin || fr.needsAdmin),
      evidence: memBits.length ? memBits.join(" · ")
        : (anyMemProbe ? "no memory stored or quarantined yet"
          : (tenant ? "counts unavailable — " + (qu.err || kn.err || "").slice(0, 80) : "no space yet")),
    };

    /* --- item 5 · first recall hit ------------------------------------ */
    var i5 = { n: 5, id: "recall", title: "First recall hit", done: false, needsAdmin: false };
    if (au.ok && hitRow) {
      i5.done = true;
      i5.evidence = "“" + String(hitRow.query_summary || "").slice(0, 60) + "” → " +
        hitRow.result_ids.length + " result" + (hitRow.result_ids.length === 1 ? "" : "s") +
        " · " + V.timeAgo(hitRow.at) + " (from the audit log)";
    } else if (proof.hitAt) {
      i5.done = true; i5.perSession = true;
      i5.evidence = "the proof step returned results this session (per-session evidence — audit " +
        (au.ok ? "has no recall rows yet" : "unavailable") + ")";
    } else {
      i5.needsAdmin = !au.ok && au.needsAdmin;
      i5.evidence = au.ok ? "no scoped recall has returned results yet"
        : (au.needsAdmin ? "needs the admin token to read the audit log" : "run the proof step");
    }

    /* --- item 6 · denial verified (the celebrated one) ----------------- */
    var i6 = { n: 6, id: "denial", title: "Denial verified", done: false, celebrated: true, needsAdmin: false };
    if (au.ok && zeroRow) {
      i6.done = true;
      i6.evidence = "a session holding only [" + nameTokens(zeroRow.principals, principals) +
        "] asked and got 0 results · " + V.timeAgo(zeroRow.at) + " (from the audit log)";
    } else if (proof.denyAt && proof.distinct) {
      i6.done = true; i6.perSession = true;
      i6.evidence = "the blind session got 0 results this session (per-session evidence — audit " +
        (au.ok ? "has no matching rows yet" : "unavailable") + ")";
    } else {
      i6.needsAdmin = !au.ok && au.needsAdmin;
      i6.evidence = "no blind session (a key on no memory’s sharing list) has been proven to see nothing yet — run the proof step";
    }

    /* --- optional · benchmark: honestly empty until run ---------------- */
    var iB = {
      n: 7, id: "bench", title: "Benchmark run", done: false, optional: true,
      evidence: "no numbers appear anywhere until your own benchmark has run — this slot stays honestly empty until then",
    };

    return {
      dir: dir, tenant: tenant || "", name: name, inList: inList,
      items: [i1, i2, i3, i4, i5, i6, iB],
      principals: principals, users: users, groups: groups, firstUser: firstUser,
      sampleSeeded: sampleSeeded,
      probes: { principals: pr, knowledge: kn, quarantine: qu, freshness: fr, audit: au },
    };
  }

  /* ====================================================================
     STEP-6 "LAND" CARDS (FTUE §3 step 6) — shared with panel_home.
     ==================================================================== */
  function nextStepsHtml(info) {
    var origin = location.origin;
    var u = info.firstUser;
    var mcp =
      "claude mcp add verity \\\n" +
      "  -e VERITY_URL=" + origin + " \\\n" +
      "  -e VERITY_TENANT_ID=" + info.tenant + " \\\n" +
      "  -e VERITY_PRINCIPALS=" + (u ? u.token : "<your key's token — see People & groups>") + " \\\n" +
      "  -e VERITY_ACTOR_SUB=" + (u ? u.principal : "user:me") + " \\\n" +
      "  -e VERITY_ACTOR_AZP=agent:claude-code \\\n" +
      "  -- /path/to/verity/target/release/verity-mcp";
    return (
      '<div class="card">' +
        "<h2>Next, when you’re ready</h2>" +
        '<div class="dc-sides">' +
          '<div class="dc-side"><div class="dc-name">Connect Claude Code</div>' +
            '<div class="dc-src">copy-paste MCP block, pre-filled with your url, space, and key' +
              (u ? "" : " (add a key in step 2 to fill in the token)") + "</div>" +
            '<textarea readonly id="ftue-mcp" style="margin-top:8px;min-height:120px;font-size:11px">' + V.esc(mcp) + "</textarea>" +
            '<div class="dc-actions"><button id="ftue-mcp-copy">Copy MCP block</button></div></div>' +
          '<div class="dc-side"><div class="dc-name">Connect a real source</div>' +
            '<div class="dc-src">mirror the permissions your tools already have — webhooks, CDC, documents</div>' +
            '<div class="dc-actions"><button id="ftue-gosources">Open Sources &amp; freshness</button></div></div>' +
          '<div class="dc-side"><div class="dc-name">Run the latency benchmark</div>' +
            '<div class="dc-src"><b>No numbers appear anywhere until your own benchmark has run</b> — this slot stays honestly empty until then.</div>' +
            '<div class="ref" style="margin-top:8px">cargo run -p verity-bench -- seed --chunks 100000<br>cargo run -p verity-bench -- run</div></div>' +
        "</div>" +
        '<div class="toolbar" style="margin:12px 0 0">' +
          (info.sampleSeeded ? '<button id="ftue-remove-sample">Remove sample data</button>' : "") +
          '<button id="ftue-replay">Replay setup</button>' +
        "</div>" +
      "</div>");
  }
  function wireNextSteps(opts) {
    var copy = el("ftue-mcp-copy");
    if (copy) copy.onclick = function () {
      var ta = el("ftue-mcp"); ta.select();
      try { navigator.clipboard.writeText(ta.value); } catch (e) { document.execCommand("copy"); }
      copy.textContent = "Copied";
    };
    var src = el("ftue-gosources");
    if (src) src.onclick = function () { V.show("sources"); };
    var rem = el("ftue-remove-sample");
    if (rem) rem.onclick = function () {
      // Honest removal runs the REAL erasure pipeline (preview → typed
      // confirm → purge). sample_cast.js owns that flow; without it, route
      // to the erasure panel rather than invent a special-cased delete.
      if (window.VeritySample && window.VeritySample.remove) window.VeritySample.remove();
      else V.show("erasure");
    };
    var rep = el("ftue-replay");
    if (rep) rep.onclick = function () {
      if (opts && opts.onReplay) opts.onReplay();
      else { V.show("welcome", { step: 1 }); }
    };
  }

  /* --------------- the shared namespace panel_home consumes ------------- */
  window.VerityFtue = {
    derive: derive,
    proofState: proofState,
    nextStepsHtml: nextStepsHtml,
    wireNextSteps: wireNextSteps,
    checklistHidden: function (tenant) { return !!ssGet(HIDE_KEY + tenant); },
    hideChecklist: function (tenant) { ssSet(HIDE_KEY + tenant, true); },
  };

  /* ====================================================================
     THE WIZARD PANEL
     ==================================================================== */
  /* mode: null (not yet discovered) | "identity" (ReBAC live — subject-based
     minting works) | "dev" (raw keys, disclosed). Discovered from real call
     outcomes (the membership write, or the step-3 mint attempt) and held
     IN MEMORY ONLY — never persisted; server truth re-derives on every load.
     mintNote is the mode disclosure step 3 shows once a mint happened. */
  var W = { open: null, info: null, expectMint: false, deriving: false, queued: false,
            groupNote: "", mode: null, mintNote: "" };

  /* Step 3 stores the minted handle ONLY when this wizard asked for the
     mint — disclosed in the step copy before the dialog opens. */
  V.onMint(function (m) {
    if (!W.expectMint) return;
    W.expectMint = false;
    // Only adopt a handle minted for the space this setup is about.
    if (m.claims && m.claims.tenant_id && m.claims.tenant_id !== V.tenant()) return;
    V.setWorkingHandle(m.handle);
    W.open = 4;
    kick();
  });

  V.register({
    id: "welcome",
    mount: function () {
      var host = el("welcome-mount");
      if (host) host.innerHTML = '<div class="toolbar"><span class="asof">deriving setup state from the server…</span></div>';
      V.onTenant(function () { kick(); });
      V.onTenantDir(function () { kick(); });
      V.onWorkingHandle(function () { kick(); });
      kick();
    },
    load: function () { return kick(); },
    onShow: function () {
      var p = V.navParams();
      if (p && p.step) W.open = Number(p.step);
      kick();
    },
  });

  async function kick() {
    var host = el("welcome-mount");
    if (!host) return;
    if (W.deriving) { W.queued = true; return; }
    W.deriving = true;
    try {
      do {
        W.queued = false;
        var info = await derive(V.tenant());
        W.info = info;
        render(host, info);
      } while (W.queued);
    } catch (e) {
      host.innerHTML = '<div class="err on">' + V.esc(String((e && e.message) || e)) + "</div>";
    } finally { W.deriving = false; }
  }

  /* ------------------------------------------------------------ render */
  function chipFor(item) {
    if (item.done && item.celebrated) return V.stateChip("ok", "denied — correctly ✦");
    if (item.done) return V.stateChip("ok", "done" + (item.perSession ? " · this tab" : ""));
    if (item.needsAdmin) return V.stateChip("attn", "needs admin token");
    return V.stateChip("off", "not yet");
  }

  function stepShell(n, title, item, bodyHtml, summaryHtml) {
    var isOpen = W.open === n;
    var head =
      '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">' +
        chipFor(item) +
        '<b style="color:var(--bright)">Step ' + n + " — " + V.esc(title) + "</b>" +
        '<span class="asof" style="flex:1">' + (item.done ? summaryHtml || "" : "") + "</span>" +
        '<button data-step-toggle="' + n + '">' + (isOpen ? "collapse" : (item.done ? "revisit" : "open")) + "</button>" +
      "</div>";
    return '<div class="card"' + (isOpen ? "" : ' style="padding:10px 16px"') + ">" + head +
      (isOpen ? '<div style="margin-top:12px">' + bodyHtml + "</div>" : "") + "</div>";
  }

  function whatsThis(inner) {
    return '<details class="note"><summary style="cursor:pointer">what’s this?</summary>' +
      '<div style="margin-top:6px">' + inner + "</div></details>";
  }

  function render(host, info) {
    var items = info.items;
    var doneCount = items.slice(0, 6).filter(function (i) { return i.done; }).length;
    if (W.open == null) {
      var firstOpen = items.slice(0, 6).find(function (i) { return !i.done; });
      W.open = firstOpen ? firstOpen.n : 6;
      if (doneCount === 6) W.open = 7; // land
    }

    var html = "";

    /* ---- Step 0 — Welcome (exact copy; prominent when nothing exists) --- */
    var virgin = info.dir.status === "ok" && info.dir.tenants.length === 0;
    if (!items[0].done) {
      html +=
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Welcome to Verity</div>' +
          '<div class="et-body">Verity is shared memory for your AI agents — everything they learn, in one place, ' +
            "carrying the same sharing rules your company already has." +
            '<div style="margin-top:8px">One thing to know before you start: <b>when Verity isn’t sure someone may ' +
            "see a memory, it shows them nothing.</b> An empty result here is a safety answer, not a bug — and by the " +
            "end of setup you’ll see exactly why that’s the feature.</div></div>" +
          '<div class="et-actions">' +
            '<button class="primary" id="wz-start">Set up Verity — about 5 minutes</button>' +
            (info.dir.status === "ok" && !virgin ? '<button id="wz-have-id">I already have a space id</button>' : "") +
          "</div>" +
          '<div id="wz-have-id-row" style="display:none;margin-top:10px;max-width:420px">' +
            '<label for="wz-have-id-in">space id — checked against this server’s list; an id that isn’t on it is rejected, never silently accepted</label>' +
            '<input type="text" id="wz-have-id-in" spellcheck="false" placeholder="paste the id an operator gave you">' +
            '<div class="err" id="wz-have-id-err"></div>' +
          "</div>" +
        "</div>";
    }

    /* ---- Step 1 — Your space ---- */
    var s1body =
      '<div class="dc-question" style="margin-bottom:6px">Name your space</div>' +
      '<div class="note" style="margin-top:0"><b>The company that owns this memory space — self-hosting means ' +
        "that’s you, and there’s exactly one.</b></div>" +
      whatsThis("&#9432; You are the <b>space (tenant)</b>; your customers are <b>entities</b> — things memories are " +
        "<i>about</i>, scoped inside your space. Customers never get their own space.") +
      '<div class="row" style="margin-top:10px;max-width:520px">' +
        '<div><label for="wz-space-name">Space name</label>' +
          '<input type="text" id="wz-space-name" placeholder="Acme Logistics" autocomplete="off"></div>' +
        '<div class="tight"><button class="primary" id="wz-space-create">Create</button></div>' +
      "</div>" +
      '<div class="err" id="wz-space-err"></div>' +
      '<div class="asof" style="margin-top:6px">the name is the only input — no uuid is ever typed by a human in this flow</div>';
    html += stepShell(1, "Your space", items[0],
      items[0].done
        ? '<div>' + V.stateChip("ok", "✓ " + (info.name || "(unnamed)") + " created") +
          '<div style="margin-top:6px">' + V.refSpan(info.tenant) + "</div></div>"
        : s1body,
      V.esc(items[0].evidence));

    /* ---- Step 2 — Who can ask ---- */
    var s2body =
      '<div class="dc-question" style="margin-bottom:6px">Add the first keys</div>' +
      '<div class="note" style="margin-top:0">A <b>key (principal)</b> is one identity that memories can be ' +
        "shared with. A <b>user is the person carrying the keyring</b>; a <b>shared key (group)</b> is one key many people " +
        "hold at once. Sharing rules are written against keys, never against logins.</div>" +
      whatsThis("<b>user</b> → the person · <b>key</b> → an identity that person (or an agent, or a team) holds · " +
        "<b>shared key</b> → one key many keyrings carry. Verity numbers each key internally; you never handle the numbers.") +
      '<div class="row" style="margin-top:10px;max-width:640px">' +
        '<div><label for="wz-you-name">Add yourself — your name</label>' +
          '<input type="text" id="wz-you-name" placeholder="Matt" autocomplete="off"></div>' +
        '<div><label for="wz-you-key">will create the key</label>' +
          '<input type="text" id="wz-you-key" placeholder="user:matt" spellcheck="false"></div>' +
      "</div>" +
      '<div class="row" style="margin-top:8px;max-width:640px">' +
        '<div><label for="wz-team-name">Add a team <span style="font-weight:400">(optional)</span></label>' +
          '<input type="text" id="wz-team-name" placeholder="sales" autocomplete="off"></div>' +
        '<div><label for="wz-team-key">will create the key</label>' +
          '<input type="text" id="wz-team-key" placeholder="group:sales" spellcheck="false"></div>' +
      "</div>" +
      '<div class="err" id="wz-keys-err"></div>' +
      '<div id="wz-keys-note"></div>' +
      '<div class="toolbar" style="margin:12px 0 0">' +
        '<button class="primary" id="wz-keys-create">Create keys</button>' +
        '<button id="wz-keys-skip">skip — I’ll add people later in People &amp; groups</button>' +
      "</div>";
    html += stepShell(2, "Who can ask", items[1], s2body, V.esc(items[1].evidence));

    /* ---- Step 3 — Open a session ---- */
    var tokens = [];
    if (info.firstUser) tokens.push(info.firstUser.token);
    info.groups.forEach(function (g) { tokens.push(g.token); });
    var s3body =
      (W.groupNote ? '<div class="note" style="margin-top:0"><em>' + V.esc(W.groupNote) + "</em></div>" : "") +
      '<div class="dc-question" style="margin-bottom:6px">Mint my working handle</div>' +
      '<div class="note" style="margin-top:0">A <b>scope handle is your signed pass for this session</b>: this space + whose ' +
        "keys are asking + which customers + how sensitive it may go. Every read is filtered through it — a session " +
        "can narrow it, never widen it. It is not an API token: it’s a pre-computed answer to <i>what this session " +
        "may see</i>.</div>" +
      whatsThis("The four fields: <b>space</b> — locked to yours · <b>who</b> — the keys asking (you + " +
        "your shared keys; empty = sees nothing, on purpose) · <b>entities</b> — entity limits appear here once your " +
        "data carries tags — nothing to limit to yet · <b>ceiling</b> — the widest sensitivity this session may ever " +
        "reach: public &lt; internal &lt; confidential &lt; restricted (defaults to internal).") +
      '<div class="note">Setup keeps the minted handle <b>for this tab only</b> (cleared when the tab closes) so the ' +
        "proof step can run recalls through it. The console never writes handles to disk.</div>" +
      /* Mode-aware wording — the production path is tried first; nothing is
         claimed before an actual call outcome has been observed. */
      (W.mode === "identity"
        ? '<div class="note">The identity plane is on: the handle is minted <b>as ' +
            V.esc(info.firstUser ? info.firstUser.principal : "you") + "</b> and the server assembles the keys " +
            "(the person plus every shared key they carry) — nobody types key lists by hand.</div>"
        : (W.mode === "dev"
          ? '<div class="note">Identity plane not available on this server — the handle names your raw keys ' +
              "directly (dev fallback, disclosed). Every fail-closed rule is identical either way.</div>"
          : "")) +
      '<div class="err" id="wz-mint-err"></div>' +
      '<div class="toolbar" style="margin:12px 0 0">' +
        '<button class="primary" id="wz-mint"' + (info.tenant ? "" : " disabled") + ">Mint my working handle</button>" +
        (info.tenant ? "" : '<span class="asof">create your space first (step 1)</span>') +
      "</div>";
    html += stepShell(3, "Open a session", items[2],
      items[2].done
        ? (W.mintNote ? '<div class="note" style="margin-top:0">' + V.esc(W.mintNote) + "</div>" : "") +
          '<div class="asof">' + V.esc(items[2].evidence) + '</div><div class="err" id="wz-mint-err"></div>' +
          '<div class="toolbar" style="margin:10px 0 0"><button id="wz-remint">Re-mint (one click)</button></div>'
        : s3body,
      V.esc(items[2].evidence));

    /* ---- Step 4 — Put memory in (the fork) ---- */
    var sampleReady = !!(window.VeritySample && window.VeritySample.seed);
    var s4body;
    if (items[3].done) {
      // DONE: one plain-language summary, ONE forward CTA. The untaken fork
      // never lingers at full volume (founder finding: "two CTAs = a stall").
      s4body =
        '<div class="dc-src">' +
          (info.sampleSeeded
            ? "Sample data is in — <b>Acme Logistics (sample)</b>: memories with real sharing rules, one lesson, " +
              "and one item Verity <b>refused to index on purpose</b> (that quarantine is the safety gate working, " +
              "not an error). It also matched <b>one company across two systems</b> automatically and left one " +
              "look-alike <b>waiting for your decision</b> on Entities &amp; merges. Everything is labeled " +
              V.badge("sample data", "b-kind") + " and removable in one click."
            : "Your memory is in — stored with exactly the visibility you chose, nothing more.") +
        "</div>" +
        '<div class="dc-actions" style="margin-top:10px">' +
          '<button class="primary" id="wz-continue5">Continue to Step 5 — the proof →</button>' +
          (info.sampleSeeded
            ? '<button id="wz-seed" title="keyed upserts — running it twice creates nothing new">Seed again (safe to repeat)</button>'
            : "") +
          '<button id="wz-goingest">Add a memory of your own</button>' +
        "</div>" +
        '<div class="err" id="wz-seed-err"></div><div id="wz-seed-out"></div>';
    } else {
      // NOT DONE: the "get data in" fork — TWO equal, clear paths, neither
      // pre-selected (the logical first-run home). Left: watch a folder and
      // drop real files in. Right: seed the sample cast. A quiet third link
      // opens the ingest panel for writing one memory by hand.
      s4body =
        '<div class="dc-sides">' +
          /* --- Path 1: watch a local folder --- */
          '<div class="dc-side">' +
            '<div class="dc-name">Watch a local folder ' + V.badge("your own files", "b-kind") + "</div>" +
            '<div class="dc-src" style="margin-top:6px">Point Verity at a folder on this machine and <b>drop files in — ' +
              "each one becomes memory you can query.</b> Verity runs right here, so it can watch a folder on this computer " +
              "directly (your browser can’t). Word docs, spreadsheets, slide decks, PDFs and plain text are read " +
              "automatically. Default folder: <span class=\"ref\">./verity-inbox</span> — Verity makes it for you if it " +
              "doesn’t exist, so you can drop a file in straight away.</div>" +
            whatsThis("You choose <b>who can see</b> the files when you set the folder up — there is no default. " +
              "Leave it empty and Verity refuses to watch: a folder whose files nobody could ever read is refused, not " +
              "silently created. Same fail-closed rule the proof step demonstrates.") +
            '<div class="dc-actions">' +
              '<button class="primary" id="wz-folder"' + (info.tenant ? "" : " disabled") + ">Set up a watched folder</button>" +
            "</div>" +
            (info.tenant ? "" :
              '<div class="asof" style="margin-top:6px">create your space first (step 1)</div>') +
          "</div>" +
          /* --- Path 2: seed sample data --- */
          '<div class="dc-side">' +
            '<div class="dc-name">Seed sample data ' + V.badge("fastest to the proof", "b-kind") + "</div>" +
            '<div class="dc-src" style="margin-top:6px">No files of your own handy? Meet <b>Acme Logistics (sample)</b> — ' +
              "three people, two teams, two connected systems (a CRM and billing), and fourteen memories carrying real " +
              "sharing rules: some org-visible, some team-only, one restricted, one field that got superseded, and one " +
              "item that lands in <b>quarantine on purpose</b>. Everything is labeled " + V.badge("sample data", "b-kind") +
              " and removable in one click, using the same erasure pipeline you’d use for a real deletion request.</div>" +
            '<div class="dc-actions">' +
              '<button class="primary" id="wz-seed"' + (sampleReady && info.tenant ? "" : " disabled") + ">Seed the sample org</button>" +
            "</div>" +
            (sampleReady ? "" :
              '<div class="asof" style="margin-top:6px">the sample seeder<span class="api-crumb"> · sample_cast.js</span> isn’t in this build yet — this button stays honestly disabled; watching a folder works today</div>') +
            '<div class="err" id="wz-seed-err"></div><div id="wz-seed-out"></div>' +
          "</div>" +
        "</div>" +
        /* --- quiet third path: write one memory by hand --- */
        '<div class="note" style="margin-top:12px">Prefer to write one memory yourself? ' +
          '<button id="wz-goingest" style="padding:2px 10px">Open the ingest panel</button> ' +
          "— you’ll be asked <b>who can see it</b> before anything else; leave visibility empty and nobody can see it, ever.</div>";
    }
    html += stepShell(4, "Put memory in", items[3], s4body, V.esc(items[3].evidence));

    /* ---- Step 5 — The proof (the aha) ---- */
    var proof = proofState();
    var s5body =
      '<div class="dc-question" style="margin-bottom:6px">Same question. Two sessions.</div>' +
      '<div class="note" style="margin-top:0">Two ordinary scoped recalls, composed side by side in this page — ' +
        "nothing new on the read path. Left runs through <b>your working handle</b>; right through a session for " +
        (info.sampleSeeded ? '<span class="ref">user:sample-blind</span>' :
          '<span class="ref">user:proof-blind</span>') +
        " — a key that <b>no memory has ever been shared with</b>, so it opens nothing.</div>" +
      '<div class="row" style="margin-top:10px;max-width:640px">' +
        '<div><label for="wz-proof-q">query</label>' +
          '<input type="text" id="wz-proof-q" value="' +
          V.esc(proof.query || (info.sampleSeeded ? "what's the latest on the Acme renewal?" : "what do we know so far?")) + '"></div>' +
        '<div class="tight"><button class="primary" id="wz-proof-run"' + (items[2].done ? "" : " disabled") + ">Run both</button></div>" +
      "</div>" +
      (items[2].done ? "" : '<div class="asof" style="margin-top:4px">mint your working handle first (step 3)</div>') +
      '<div class="err" id="wz-proof-err"></div>' +
      '<div id="wz-proof-out"></div>';
    html += stepShell(5, "The proof", items[4].done && items[5].done
      ? { n: 5, done: true, celebrated: true } : { n: 5, done: false, needsAdmin: items[4].needsAdmin },
      s5body,
      V.esc(items[5].done ? items[5].evidence : items[4].evidence));

    /* ---- Step 6 — Land ---- */
    if (doneCount === 6) {
      html +=
        '<div class="empty-teach sp-c">' +
          '<div class="et-title">Your memory plane is up — and it already told someone “no.”</div>' +
          '<div class="et-body">All six setup facts are re-derived from the server on every load — clear this ' +
            "browser and they stay green (the working handle is honestly per-tab).</div>" +
        "</div>" + nextStepsHtml(info);
    }

    host.innerHTML = html;
    wire(host, info);
  }

  /* ------------------------------------------------------------- wiring */
  function wire(host, info) {
    /* step toggles */
    var toggles = host.querySelectorAll("[data-step-toggle]");
    for (var i = 0; i < toggles.length; i++) {
      (function (btn) {
        btn.onclick = function () {
          var n = Number(btn.getAttribute("data-step-toggle"));
          W.open = W.open === n ? 0 : n;
          render(host, info);
        };
      })(toggles[i]);
    }

    var start = el("wz-start");
    if (start) start.onclick = function () { W.open = 1; render(host, info); };

    /* "I already have a tenant id" — validated against the list; ghosts are
       a loud error, never a lazily-born space. */
    var haveBtn = el("wz-have-id");
    if (haveBtn) haveBtn.onclick = function () {
      var row = el("wz-have-id-row");
      row.style.display = row.style.display === "none" ? "" : "none";
      var input = el("wz-have-id-in");
      input.focus();
      input.onchange = input.onblur = function () {
        var v = input.value.trim();
        if (!v) return;
        var dir = V.tenantDir();
        var hit = dir.tenants.find(function (t) { return t.tenant_id === v; });
        if (hit) { V.clearErr("wz-have-id-err"); V.setTenant(v); }
        else V.err("wz-have-id-err", new Error("This space doesn’t exist on this server. Pick a real one, or set one up."));
      };
    };

    /* step 1: create the space */
    var create = el("wz-space-create");
    if (create) create.onclick = async function () {
      V.clearErr("wz-space-err");
      var name = (el("wz-space-name").value || "").trim();
      if (!name) { V.err("wz-space-err", new Error("give the space a name — that’s the only field")); return; }
      create.disabled = true;
      try {
        var res = await V.api("/v1/admin/tenants", { json: { name: name }, admin: true });
        if (!res || !res.tenant_id) throw new Error("the server created no space id");
        await V.refreshTenantDir();
        W.open = 2;
        V.setTenant(res.tenant_id); // auto-adopt; triggers re-derive via onTenant
      } catch (e) {
        var msg = String((e && e.message) || e);
        V.err("wz-space-err", msg.indexOf("401") >= 0
          ? new Error("creating a space needs the admin token — set it in the session bar above (dev mode needs none)")
          : e);
        create.disabled = false;
      }
    };

    /* step 2: create-don't-paste keys */
    var youName = el("wz-you-name"), youKey = el("wz-you-key");
    var teamName = el("wz-team-name"), teamKey = el("wz-team-key");
    if (youName) youName.oninput = function () { youKey.value = youName.value.trim() ? "user:" + slug(youName.value) : ""; };
    if (teamName) teamName.oninput = function () { teamKey.value = teamName.value.trim() ? "group:" + slug(teamName.value) : ""; };
    var mkKeys = el("wz-keys-create");
    if (mkKeys) mkKeys.onclick = async function () {
      V.clearErr("wz-keys-err");
      var uk = (youKey.value || "").trim(), gk = (teamKey.value || "").trim();
      if (!uk) { V.err("wz-keys-err", new Error("add at least one person — type a name and the key derives itself")); return; }
      if (uk.indexOf("user:") !== 0) { V.err("wz-keys-err", new Error("a person’s key looks like user:<name>")); return; }
      if (gk && gk.indexOf("group:") !== 0) { V.err("wz-keys-err", new Error("a team’s key looks like group:<name>")); return; }
      mkKeys.disabled = true;
      try {
        var list = gk ? [uk, gk] : [uk];
        await V.api("/v1/admin/principals", { json: { tenant_id: info.tenant, principals: list }, admin: true });
        if (gk) {
          try {
            await V.api("/v1/admin/groups", { json: { tenant_id: info.tenant, group: gk, member: uk }, admin: true });
            // Membership landed in the identity plane — that only succeeds
            // with ReBAC live, so the mode is discovered right here.
            W.mode = "identity";
            W.groupNote = "membership recorded: " + uk + " now carries the shared key " + gk +
              " — the identity plane assembles it into handles automatically";
          } catch (ge) {
            // Stashed on W (not innerHTML) so the disclosure SURVIVES the
            // re-render that advances the wizard — step 3 shows it. Only the
            // server's own "requires ReBAC" answer means dev mode; any other
            // failure is disclosed as what it is, never mislabeled.
            var gm = String((ge && ge.message) || ge);
            if (/requires ReBAC/.test(gm)) {
              W.mode = "dev";
              W.groupNote = "shared key " + gk + " created — but this server can't record who belongs to it " +
                "(that needs the relationship-based permissions engine (ReBAC), set via VERITY_SPICEDB_URL). The shared key itself " +
                "still works, and setup adds it to your handle for you";
            } else {
              W.groupNote = "shared key " + gk + " created, but recording the membership failed (" +
                gm.slice(0, 90) + ") — the shared key itself still works, and setup pre-checks it on your handle";
            }
          }
        }
        W.open = 3;
        kick();
      } catch (e) {
        V.err("wz-keys-err", e);
        mkKeys.disabled = false;
      }
    };
    var skipKeys = el("wz-keys-skip");
    if (skipKeys) skipKeys.onclick = function () { W.open = 3; render(host, info); };

    /* step 3: try the PRODUCTION path first — mint AS the person from step 2
       (subject-based; the server resolves their keys through the identity
       plane). Only the server's specific 422 ("subject-based scopes require
       ReBAC") degrades to the raw-token dialog, disclosed in place; any
       other failure surfaces loudly — never a silent downgrade. */
    function openRawMint() {
      var tokens = [];
      if (info.firstUser) tokens.push(info.firstUser.token);
      info.groups.forEach(function (g) { tokens.push(g.token); });
      W.expectMint = true;
      V.openMint({
        tenant: info.tenant,
        lockTenant: true,
        principals: tokens.join(", "),
        entities: "",           // empty = all your customers
        confidentiality: "internal",
      });
    }
    async function wizardMint(btn) {
      V.clearErr("wz-mint-err");
      var u = info.firstUser;
      if (!u || W.mode === "dev") {
        // No person to mint as, or this session already learned the plane
        // is off — go straight to the disclosed raw-token dialog.
        if (u && W.mode === "dev" && !W.mintNote) {
          W.mintNote = "identity plane not available — this handle names raw keys directly (dev fallback)";
        }
        openRawMint();
        return;
      }
      if (btn) btn.disabled = true;
      try {
        var who = u.principal.replace(/^user:/, "");
        var res = await V.api("/v1/scopes", {
          json: {
            tenant_id: info.tenant,
            subject: u.principal,       // the server assembles the keys
            actor_sub: u.principal,
            actor_azp: "console:setup",
            max_confidentiality: "internal",
            ttl_seconds: 43200,
          },
        });
        if (!res || !res.scope_handle) throw new Error("mint returned no scope_handle");
        W.mode = "identity";
        W.mintNote = "minted as " + who + " — the identity plane assembled their keys " +
          "(them plus every shared key they carry; nothing was typed by hand)";
        W.open = 4;
        V.setWorkingHandle(res.scope_handle); // fires onWorkingHandle → kick
        kick();
      } catch (e) {
        var m = String((e && e.message) || e);
        if (/subject-based scopes require ReBAC/.test(m)) {
          W.mode = "dev";
          W.mintNote = "identity plane not available — this handle names raw keys directly (dev fallback)";
          openRawMint();
        } else {
          V.err("wz-mint-err", e);
          if (btn) btn.disabled = false;
        }
      }
    }
    var mint = el("wz-mint");
    if (mint) mint.onclick = function () { wizardMint(mint); };
    var remint = el("wz-remint");
    if (remint) remint.onclick = function () { wizardMint(remint); };

    /* step 4: the fork */
    var seed = el("wz-seed");
    if (seed) seed.onclick = async function () {
      if (!(window.VeritySample && window.VeritySample.seed)) return;
      V.clearErr("wz-seed-err");
      seed.disabled = true;
      el("wz-seed-out").innerHTML = '<div class="asof">seeding the sample cast through the ordinary ingest endpoints…</div>';
      try {
        var seeded = await window.VeritySample.seed({ tenant: info.tenant });
        el("wz-seed-out").innerHTML = '<div class="asof">' +
          (seeded && seeded.already
            ? V.stateChip("ok", "already seeded") + " nothing new was created — the completion marker exists and every id is keyed"
            : V.stateChip("ok", "seeded") + " every sample row carries the " + V.badge("sample data", "b-kind") + " label" +
              (seeded && seeded.membershipNote ? " · <em>" + V.esc(seeded.membershipNote) + "</em>" : "")) +
          " · " + asofNow() + "</div>";
        kick();
      } catch (e) {
        V.err("wz-seed-err", e);
      } finally { seed.disabled = false; }
    };
    var goIngest = el("wz-goingest");
    if (goIngest) goIngest.onclick = function () { V.show("ingest"); };

    /* step 4 fork — watch a local folder: hand off to Sources & freshness (the
       folder watch's home) with a nav param that opens the add-folder dialog. */
    var goFolder = el("wz-folder");
    if (goFolder) goFolder.onclick = function () { V.show("sources", { view: "folder" }); };

    /* step 4 done → single forward CTA to the proof */
    var cont5 = el("wz-continue5");
    if (cont5) cont5.onclick = function () { W.open = 5; render(host, info); };

    /* step 5: the proof */
    var run = el("wz-proof-run");
    if (run) run.onclick = function () { runProof(host, info); };
  }

  /* ------------------------------------------- the proof (two recalls) */
  async function ensureBlindHandle(info) {
    var cached = ssGet(BLIND_KEY);
    if (cached && cached.tenant === info.tenant && cached.handle) {
      try {
        var c = V.decodeHandle(cached.handle);
        var exp = c.exp ? (c.exp < 1e12 ? c.exp * 1000 : c.exp) : null;
        if (!exp || exp > Date.now() + 30000) return cached;
      } catch (e) { /* re-mint below */ }
    }
    var bp = info.sampleSeeded ? "user:sample-blind" : "user:proof-blind";
    var map = await V.api("/v1/admin/principals", {
      json: { tenant_id: info.tenant, principals: [bp] }, admin: true,
    });
    var token = map && map.mappings && map.mappings[bp];
    if (typeof token !== "number") throw new Error("could not register the blind principal " + bp);
    var res = await V.api("/v1/scopes", {
      json: {
        tenant_id: info.tenant, actor_azp: "console:setup-proof",
        principals: [token], max_confidentiality: "internal", ttl_seconds: 3600,
      },
    });
    if (!res || !res.scope_handle) throw new Error("mint for the blind session returned no handle");
    var out = { tenant: info.tenant, handle: res.scope_handle, principal: bp, token: token };
    ssSet(BLIND_KEY, out); // per-session, labeled: exists only to run the proof
    return out;
  }

  function hitHtml(h) {
    return '<div class="hit">' +
      '<div class="meta"><span class="score" title="how closely this memory matches the question, 0–1">' +
        (typeof h.score === "number" ? "match " + h.score.toFixed(3) : "") + "</span> " +
        V.kindBadge(h.kind || "content") + V.sampleBadge([h.document_id, h.entity_tags]) +
        (h.acl_provenance ? V.provenanceBadge(h.acl_provenance) : "") + "</div>" +
      '<div class="content">' + V.esc(String(h.content || "").slice(0, 220)) + "</div>" +
    "</div>";
  }

  async function runProof(host, info) {
    V.clearErr("wz-proof-err");
    var out = el("wz-proof-out");
    var q = (el("wz-proof-q").value || "").trim();
    if (!q) { V.err("wz-proof-err", new Error("type a question — any question")); return; }
    var wh = V.workingHandle();
    if (!wh) { V.err("wz-proof-err", new Error("no working handle held by this tab — mint one in step 3 first")); return; }
    out.innerHTML = '<div class="asof">running the same query through both sessions…</div>';
    var blind;
    try { blind = await ensureBlindHandle(info); }
    catch (e) { V.err("wz-proof-err", e); out.innerHTML = ""; return; }

    var left, right;
    try {
      var both = await Promise.all([
        V.api("/v1/recall", { json: { scope_handle: wh, text: q, k: 8 } }),
        V.api("/v1/recall", { json: { scope_handle: blind.handle, text: q, k: 8 } }),
      ]);
      left = both[0] || []; right = both[1] || [];
    } catch (e) {
      var pm = String((e && e.message) || e);
      if (/HTTP 401/.test(pm)) {
        // Either side may hold a handle the server no longer recognizes (a
        // dev-mode server re-keys on every restart — fail closed). Drop the
        // cached blind handle so the next run re-mints it, and say what the
        // one-click fix for the working handle is.
        try { sessionStorage.removeItem(BLIND_KEY); } catch (se) { /* session-only */ }
        V.err("wz-proof-err", new Error(
          "a held handle didn't verify — a dev-mode server forgets old session passes on every restart " +
          "(fail closed; your people and group keys are untouched). Re-mint in step 3 (one click), then " +
          "run the proof again — the blind session's pass will re-mint itself."));
      } else {
        V.err("wz-proof-err", e);
      }
      out.innerHTML = ""; return;
    }

    var leftWho = "your session";
    try {
      var c = V.decodeHandle(wh);
      leftWho = c.actor_sub || (info.firstUser ? info.firstUser.principal : "your session");
    } catch (e) { /* keep default */ }

    setProof({
      query: q,
      hitAt: left.length > 0 ? Date.now() : proofState().hitAt || null,
      denyAt: right.length === 0 ? Date.now() : null,
      distinct: true, // blind principal is by construction distinct from yours
    });

    var rightHtml;
    if (right.length === 0) {
      rightHtml =
        '<div class="dc-name">' + V.esc(blind.principal) + "’s session — <b>0 memories</b></div>" +
        '<div class="dc-src" style="margin-top:6px">This is correct. No memory here carries a key this session ' +
          "holds — <b>an empty result is a safety answer, not a bug.</b> Nothing about these memories — not even " +
          "that they exist — reached this session.</div>" +
        whatsThis("What exactly is guaranteed: the handle’s keys are <b>part of the search itself, applied before " +
          "anything is ranked</b> — not a redaction after the fact. A memory your keys don’t open is never fetched, " +
          "never ranked, never even counted. (Internally: a mandatory pre-filter materialized in the index, " +
          "enforced in one shared layer for every storage backend.)") +
        '<div class="dc-actions"><button id="wz-trace">Show the why-trace</button></div>' +
        '<div class="err" id="wz-trace-err"></div><div id="wz-trace-out"></div>';
    } else {
      rightHtml =
        '<div class="dc-name">' + V.esc(blind.principal) + "’s session — " + right.length + " memories</div>" +
        '<div class="note"><em>not a denial:</em> this session’s key appears in the visibility of ' +
          right.length + " memor" + (right.length === 1 ? "y" : "ies") + " — someone granted it. The proof needs a " +
          "key that no memory has been shared with.</div>" + right.map(hitHtml).join("");
    }

    out.innerHTML =
      '<div class="dc-sides" style="margin-top:12px">' +
        '<div class="dc-side">' +
          '<div class="dc-name">' + V.esc(leftWho) + "’s session — <b>" + left.length + " memor" + (left.length === 1 ? "y" : "ies") + "</b></div>" +
          (left.length ? left.map(hitHtml).join("")
            : '<div class="note">your session also sees nothing — put memory in (step 4) or check the handle’s keys. ' +
              "Empty is fail-closed working, but the proof needs a hit on this side.</div>") +
        "</div>" +
        '<div class="dc-side">' + rightHtml + "</div>" +
      "</div>" +
      (right.length === 0 && left.length > 0
        ? '<div class="empty-teach sp-c" style="margin-top:12px">' +
            '<div class="et-title">✓ Denied — correctly.</div>' +
            '<div class="et-body">This refusal is Verity’s whole pitch: scope filters are baked into the index as ' +
              "mandatory pre-filters, so out-of-scope memory never reaches the model at all. Everything else you " +
              "build on Verity sits on the guarantee you just watched work.</div>" +
            '<div class="et-actions"><button class="primary" id="wz-proof-continue">Continue — finish setup</button></div>' +
          "</div>"
        : "") +
      '<div class="asof" style="margin-top:6px">two ordinary recall calls — the same read path agents use, composed in this tab<span class="api-crumb"> · POST /v1/recall ×2</span> · ' + asofNow() + "</div>";

    var trace = el("wz-trace");
    if (trace) trace.onclick = async function () {
      V.clearErr("wz-trace-err");
      trace.disabled = true;
      try {
        var tr = await V.api("/v1/admin/debug/recall", {
          json: { scope_handle: blind.handle, text: q, candidates: 50 }, admin: true,
        });
        var cands = (tr && tr.candidates) || [];
        var dropped = cands.filter(function (c) { return !c.admitted; });
        el("wz-trace-out").innerHTML =
          '<div class="note" style="margin-top:8px"><b>' + cands.length + "</b> nearest candidates traced (admin-gated, " +
            "audited, off the read path); <b>" + dropped.length + "</b> dropped before ranking:</div>" +
          '<div class="tablewrap"><table><tr><th>memory</th><th>why it never reached this session</th></tr>' +
          dropped.slice(0, 10).map(function (c) {
            return "<tr><td>" + V.esc(String(c.content_preview || "").slice(0, 80)) + " " +
              V.sampleBadge([c.document_id, c.entity_tags]) + "</td><td>" +
              (c.drop_reasons || []).map(function (r) { return V.badge(r, "b-quarantined"); }).join(" ") + "</td></tr>";
          }).join("") + "</table></div>" +
          (dropped.length > 10 ? '<div class="asof">showing 10 of ' + dropped.length + "</div>" : "");
      } catch (e) {
        var msg = String((e && e.message) || e);
        V.err("wz-trace-err", msg.indexOf("401") >= 0
          ? new Error("the why-trace is admin-gated (explanations must not leak existence) — set the admin token in the session bar")
          : e);
      } finally { trace.disabled = false; }
    };

    // Re-derivation (items 5–6 green up from the audit log) is USER-driven —
    // an automatic re-render here would wipe the proof off the screen at
    // the exact moment it lands.
    var cont = el("wz-proof-continue");
    if (cont) cont.onclick = function () { W.open = null; kick(); };
  }
})();
