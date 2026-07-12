"use strict";
/* ==========================================================================
   panel_scope.js — Scope Inspector · v2 rebuild ("What can this agent see?")
   --------------------------------------------------------------------------
   READ-PATH PURITY (unchanged from v1): every probe is a pure read through
   Verity.api() — POST /v1/recall, GET /v1/briefs/{entity}, GET /v1/activity.
   Handle decode is client-side (Verity.decodeHandle). No LLM call, no live
   ReBAC call, no permissive-fallback affordance anywhere.

   TWO admin-plane calls, both labeled as such in the UI, both OFF the read
   path by construction:
     • POST /v1/admin/debug/recall — the audited why-filtered tracer
       (verb debug_recall; every disclosed chunk id is written to audit).
     • GET  /v1/admin/principals  — the read-only token↔name directory, used
       ONLY to render names beside tokens in the admin why-trace and claims.
       It never renders in any scope-handle context served to an agent.

   v2 interpretability contract honored here:
     • primary text is plain language; wire tokens/jargon live ONLY in
       .dc-meta / .ref / tooltips / h2 .sub;
     • a decoded handle AUTOLOADS a default recall probe (no cold Load);
     • hits render content-first; raw ids are mono-small, never primary;
     • explain-zero is a sp-b empty state: forensic CTAs only, never fill-it;
     • the why-trace names principals BY NAME (visibility_tokens joined
       against the directory) and turns "visibility_no_overlap" from a
       verdict into an instruction;
     • derive (narrow-only) / renew (expired-only) prominent; export kept;
     • session-local latency is labeled NOT the milestone-A benchmark;
     • no number is fabricated: recall scores are shown as rank + raw score
       (BM25/RRF scores are not probabilities — a percent would be a lie).
   ========================================================================== */
(function () {
  var V = window.Verity;

  var S = {
    handle: null,               // raw vs_… string last successfully decoded
    claims: null,               // decoded signed payload
    probes: { recall: null, brief: null, activity: null, why: null },
    lat: [],                    // session-local recall latencies (ms)
    dir: { tenant: null, map: null, error: null, promise: null }, // principal directory
    autoQ: null,                // the default probe query text, if auto-run
  };

  function el(id) { return V.$(id); }
  function esc(s) { return V.esc(s == null ? "" : s); }

  /* ------------------------------------------------------------ register */
  V.register({
    id: "scope",
    mount: function () {
      var m = el("scope-mount");
      if (!m) return;
      m.innerHTML = layout() + mintDialogHtml();
      wire();
      renderIntakeState(); // teach state until a handle exists (LAW #5)
    },
    // AUTOLOAD: a known tenant warms the principal directory so the why-trace
    // and claims can name tokens the moment they render. The panel's real
    // input is a HANDLE; with none present the teach state stands in.
    load: function (_s, tenant) {
      return ensureDirectory(tenant).then(function () {
        if (S.claims) renderClaims(S.claims);
        if (S.probes.why) renderWhy(S.probes.why);
      });
    },
    // One-shot nav params: Verity.show("scope", {handle}) — the shell mint
    // dialog's "Inspect in Scope Inspector" lands here. MUST auto-decode.
    onShow: function () {
      var p = V.navParams();
      if (p && p.handle) {
        el("sc-handle").value = p.handle;
        decode(p.handle);
      }
    },
  });

  /* -------------------------------------------------------------- layout */
  function layout() {
    return (
      // ---- 1. the handle ------------------------------------------------
      '<div class="card">' +
        '<h2>The handle <span class="sub">client-side decode — the payload is signed, not secret</span></h2>' +
        '<div class="row">' +
          '<div><label for="sc-handle">scope handle</label>' +
            '<textarea id="sc-handle" spellcheck="false" placeholder="vs_&hellip; (paste it — it decodes as you paste)"></textarea></div>' +
          '<div class="tight"><button class="primary" id="sc-decode">Read this handle</button></div>' +
          '<div class="tight"><button id="sc-copy-handle" disabled>Copy handle</button></div>' +
        '</div>' +
        '<div class="err" id="sc-decode-err"></div>' +
        '<div class="note">Decoding happens entirely in your browser (zero server calls). Anyone holding a handle can read what it grants; only the server-side signature makes it <em>usable</em>.</div>' +
        '<div id="sc-intake-teach"></div>' +
        '<div id="sc-claims"></div>' +
      '</div>' +

      // ---- 2. everything below exists only once a handle is decoded ----
      '<div id="sc-body" style="display:none">' +

        // toolbar: state + derive/renew prominent + export
        '<div class="toolbar">' +
          '<span id="sc-state"></span>' +
          '<span class="asof" id="sc-asof"></span>' +
          '<span class="spacer"></span>' +
          '<button id="sc-open">Open a narrower handle&hellip;</button>' +
          '<button id="sc-renew" disabled>Renew this handle</button>' +
          '<button id="sc-export">Export proof (evidence file)</button>' +
        '</div>' +
        '<div class="note" id="sc-mint-hint"></div>' +
        '<div class="err" id="sc-mint-err"></div>' +
        '<div id="sc-mint-out"></div>' +

        // ---- 3. prove it: live reads through the handle ----------------
        '<div class="card">' +
          '<h2>Prove it — real reads through this exact handle <span class="sub">POST /v1/recall &middot; GET /v1/briefs/{entity} &middot; GET /v1/activity — pure reads</span></h2>' +
          '<div class="row">' +
            '<div><label for="sc-q">search as this agent would</label><input type="text" id="sc-q" placeholder="e.g. renewal risk at acme"></div>' +
            '<div class="tight" style="width:70px"><label for="sc-k">results</label><input type="number" id="sc-k" value="8" min="1" max="100" style="width:70px"></div>' +
            '<div class="tight" style="width:70px"><label for="sc-runs" title="repeat the identical call N times for a session-local p50/p95/p99">repeats</label><input type="number" id="sc-runs" value="1" min="1" max="50" style="width:70px"></div>' +
            '<div class="tight"><button class="primary" id="sc-recall">Search</button></div>' +
          '</div>' +
          '<div class="err" id="sc-recall-err"></div>' +
          '<div id="sc-auto-note"></div>' +
          '<div id="sc-lat"></div>' +
          '<div id="sc-recall-out"></div>' +
          '<div id="sc-trace"></div>' +

          '<h3 style="margin-top:16px;font-size:12px">What does it see about one entity? <span class="refreshed">brief + activity</span></h3>' +
          '<div class="row">' +
            '<div><label for="sc-brief-e">entity</label><input type="text" id="sc-brief-e" placeholder="account:acme"></div>' +
            '<div class="tight"><button id="sc-brief">Show its brief</button></div>' +
            '<div class="tight"><button id="sc-act">Show visible actions</button></div>' +
          '</div>' +
          '<div class="err" id="sc-brief-err"></div>' +
          '<div id="sc-brief-out"></div>' +
          '<div class="err" id="sc-act-err"></div>' +
          '<div id="sc-act-out"></div>' +
        '</div>' +

        // ---- 4. why filtered? (admin, audited, off the read path) ------
        '<div class="card">' +
          '<h2>Why were things held back? <span class="sub">POST /v1/admin/debug/recall &middot; admin bearer &middot; audited &middot; OFF the read path</span></h2>' +
          '<div class="note">Asks the server to re-check the top candidates for the search text above and say, per item, exactly why it was returned or held back &mdash; with the people and groups who <em>can</em> see each item <b>named</b>. Needs the admin token (session bar) and a live handle; every run is written to the audit log (verb <code>debug_recall</code>). It explains the index as of <b>now</b>, never a past read. No LLM, no live permission-graph call &mdash; restricted-class rechecks are flagged, not run.</div>' +
          '<div class="row" style="margin-top:8px">' +
            '<div class="tight" style="width:110px"><label for="sc-why-n" title="how many top-N tenant-only candidates to trace (server clamps 1..500)">candidates to check</label><input type="number" id="sc-why-n" value="50" min="1" max="500" style="width:110px"></div>' +
            '<div class="tight"><button id="sc-why">Explain the filtering</button></div>' +
            '<span class="asof" id="sc-dir-note"></span>' +
          '</div>' +
          '<div class="err" id="sc-why-err"></div>' +
          '<div id="sc-why-out"></div>' +
        '</div>' +

      '</div>' // #sc-body
    );
  }

  /* -------------------------------------------------- teach / no handle */
  function renderIntakeState() {
    var teach = el("sc-intake-teach");
    if (S.claims) { teach.innerHTML = ""; return; }
    teach.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">No handle to inspect yet</div>' +
        '<div class="et-body">A scope handle is the signed pass an agent reads with — it names who the agent reads as, which entities it is limited to, and its confidentiality ceiling. Mint one from the button in the top bar (or right here), or copy the <span class="ref">vs_&hellip;</span> string printed by <span class="ref">verity-cli dev</span>, then paste it above.</div>' +
        '<div class="et-actions"><button class="primary" id="sc-teach-mint">Mint a scope handle</button></div>' +
      '</div>';
    var b = el("sc-teach-mint");
    if (b) b.onclick = function () { V.openMint(); }; // the SHELL owns the mint dialog — we link to it
  }

  /* --------------------------------------------------------------- wiring */
  function wire() {
    el("sc-decode").onclick = function () { decode(el("sc-handle").value); };
    // decode-as-you-paste: a first-timer should not have to find a button
    var deb = null;
    el("sc-handle").addEventListener("input", function () {
      clearTimeout(deb);
      deb = setTimeout(function () {
        var raw = (el("sc-handle").value || "").trim();
        if (raw && raw !== S.handle && raw.indexOf("vs_") === 0 && raw.indexOf(".") > 0) decode(raw);
      }, 250);
    });
    el("sc-copy-handle").onclick = function () { if (S.handle) copy(S.handle, this, "Copy handle"); };
    el("sc-recall").onclick = function () { runRecall(false); };
    el("sc-q").addEventListener("keydown", function (e) { if (e.key === "Enter") runRecall(false); });
    el("sc-why").onclick = runWhy;
    el("sc-brief").onclick = runBrief;
    el("sc-act").onclick = runActivity;
    el("sc-export").onclick = onExport;
    el("sc-open").onclick = openMintDialog;
    el("sc-renew").onclick = onRenew;
    var dlg = V.dialog("sc-mint-dialog");
    el("sc-mint-cancel").onclick = function () { dlg.close(); };
    el("sc-mint-confirm").onclick = onMintConfirm;
  }

  /* ===================================================================
     1 · DECODE — client-side, then AUTOLOAD the default probe (LAW #3)
     =================================================================== */
  function decode(raw) {
    V.clearErr("sc-decode-err");
    raw = (raw || "").trim();
    try {
      var p = V.decodeHandle(raw);
      S.handle = raw;
      S.claims = p;
      S.probes = { recall: null, brief: null, activity: null, why: null };
      S.lat = [];
      S.autoQ = null;
      ["sc-lat", "sc-recall-out", "sc-trace", "sc-why-out", "sc-brief-out",
       "sc-act-out", "sc-mint-out", "sc-auto-note"].forEach(function (id) {
        var n = el(id); if (n) n.innerHTML = "";
      });
      V.clearErr("sc-mint-err"); V.clearErr("sc-why-err");
      V.clearErr("sc-recall-err"); V.clearErr("sc-brief-err"); V.clearErr("sc-act-err");
      el("sc-copy-handle").disabled = false;
      renderIntakeState();
      renderClaims(p);
      el("sc-body").style.display = "block";
      updateDeriveControls(p);
      stampState(p);

      // shared tenant (an id, not a secret) + warm the name directory
      if (p.tenant_id) V.setTenant(p.tenant_id);
      ensureDirectory(p.tenant_id).then(function () {
        if (S.claims === p) { renderClaims(p); if (S.probes.why) renderWhy(S.probes.why); }
      });

      // prefill entity probes from the handle
      var firstEntity = (p.entity_scope && p.entity_scope.length) ? p.entity_scope[0] : "";
      if (firstEntity && !el("sc-brief-e").value) el("sc-brief-e").value = firstEntity;

      // AUTOLOAD: run a default recall immediately — never a cold Load screen.
      autoRecall(p);
    } catch (e) {
      S.handle = null; S.claims = null;
      el("sc-body").style.display = "none";
      el("sc-claims").innerHTML = "";
      el("sc-copy-handle").disabled = true;
      renderIntakeState();
      V.err("sc-decode-err", e);
    }
  }

  function isExpired(p) {
    return !!(p && p.expires_at) && new Date(p.expires_at).getTime() - Date.now() <= 0;
  }
  function seesNothing(p) {
    return !p || !p.principals || !p.principals.length;
  }

  function stampState(p) {
    var chips;
    if (isExpired(p)) chips = V.stateChip("fail", "expired — the server will refuse this handle");
    else if (seesNothing(p)) chips = V.stateChip("attn", "live — but it sees nothing (no one named)");
    else {
      var left = p.expires_at ? Math.max(0, (new Date(p.expires_at).getTime() - Date.now()) / 1000) : null;
      chips = V.stateChip("ok", left != null ? "live — expires in " + V.fmtAge(left) : "live");
    }
    el("sc-state").innerHTML = chips;
    el("sc-asof").textContent = "checked " + new Date().toTimeString().slice(0, 8);
  }

  /* ------------------------------------------------- claims, human-first */
  function renderClaims(p) {
    var expired = isExpired(p);
    var rows =
      kvRow("Who it reads as", principalsHtml(p)) +
      kvRow("Limited to", (p.entity_scope && p.entity_scope.length)
        ? V.entityBadges(p.entity_scope) + ' <span class="asof">only results about these entities can come back</span>'
        : '<span style="color:var(--dim)">any entity — no entity limit on this handle</span>') +
      kvRow("Confidentiality ceiling", V.confBadge(p.max_confidentiality) +
        ' <span class="asof">nothing classified above this will ever be returned — no query can raise it</span>') +
      kvRow("Expires", expiresHtml(p)) +
      (p.actor_sub || p.actor_azp
        ? kvRow("Minted for", actorPairHtml(p.actor_sub, p.actor_azp))
        : "");
    el("sc-claims").innerHTML =
      '<div style="margin-top:10px">' + (expired
        ? V.stateChip("fail", "expired") : seesNothing(p)
        ? V.stateChip("attn", "sees nothing") : V.stateChip("ok", "live")) + "</div>" +
      '<dl class="kv" style="margin-top:8px">' + rows + "</dl>" +
      '<details style="margin-top:8px"><summary style="cursor:pointer;color:var(--dim);font-size:var(--fs-sm)">raw signed claims (wire form)</summary>' +
        '<div class="dc-meta" style="margin-top:6px">tenant_id ' + esc(p.tenant_id) +
        ' · principals [' + (p.principals || []).map(function (t) { return esc(t); }).join(", ") + "]" +
        ' · entity_scope [' + (p.entity_scope || []).map(esc).join(", ") + "]" +
        " · max_confidentiality " + esc(p.max_confidentiality) +
        (p.subject ? " · subject " + esc(p.subject) : "") +
        " · actor " + esc((p.actor_sub || "—") + "/" + (p.actor_azp || "—")) +
        " · expires_at " + esc(p.expires_at) + "</div></details>";
  }

  function kvRow(dt, ddHtml) { return "<dt>" + esc(dt) + "</dt><dd>" + ddHtml + "</dd>"; }

  // actor_sub = the person, actor_azp = the app that made the request.
  // Both halves labeled — a bare "— · audit" reads as noise (LAW: every
  // value says what it is).
  function actorPairHtml(sub, azp) {
    var who = sub ? "<b>" + esc(sub) + "</b>" : '<span style="color:var(--dim)">no person recorded</span>';
    var app = azp ? "requested by app: " + esc(azp) : '<span style="color:var(--dim)">no app recorded</span>';
    return who + " · " + app;
  }

  // Names first; tokens as mono-small secondaries. Fail-closed empty set is
  // said out loud. Email-string principals keep the trust-downgrade flag.
  function principalsHtml(p) {
    if (seesNothing(p)) {
      return '<span class="expired"><b>no one</b> — this handle sees nothing. Verity fails closed: an empty "who" refuses, it never defaults open.</span>';
    }
    var lead = (typeof p.subject === "string" && p.subject)
      ? V.entityChip(p.subject, "identity-resolved at mint") + " "
      : "";
    return lead + p.principals.map(function (t) {
      if (typeof t === "string" && /@/.test(t)) {
        return V.entityChip(t, "email-mapped") +
          ' <span class="badge b-downgrade" title="Email-mapped principals are weaker than resolved identity: membership is a point-in-time string match, not a live group-graph resolution, so a revoked email can lag one read behind. Prefer a resolved user:&lt;id&gt; subject.">weaker identity</span>';
      }
      return tokChip(t);
    }).join(" ") + dirHintInline();
  }

  function expiresHtml(p) {
    if (!p.expires_at) return '<span style="color:var(--dim)">—</span>';
    var left = new Date(p.expires_at).getTime() - Date.now();
    var when = esc(V.fmtTime(p.expires_at));
    return left > 0
      ? when + ' <span class="live">(' + V.fmtAge(left / 1000) + " left)</span>"
      : when + ' <span class="expired">(EXPIRED — the server will reject it; use Renew below)</span>';
  }

  /* ===================================================================
     PRINCIPAL DIRECTORY — GET /v1/admin/principals (admin, read-only)
     Token → name map, keyset-paginated. Used ONLY to put names beside
     tokens in this admin console; a 401 degrades honestly to tokens.
     =================================================================== */
  function ensureDirectory(tenant) {
    if (!tenant) return Promise.resolve(null);
    if (S.dir.tenant === tenant && (S.dir.map || S.dir.promise)) {
      return S.dir.promise || Promise.resolve(S.dir.map);
    }
    S.dir = { tenant: tenant, map: null, error: null, promise: null };
    S.dir.promise = (async function () {
      var map = {};
      var after = 0, pages = 0;
      try {
        for (;;) {
          var res = await V.api("/v1/admin/principals?tenant_id=" + encodeURIComponent(tenant) +
            "&after_token=" + after + "&limit=1000", { admin: true });
          ((res && res.principals) || []).forEach(function (r) { map[r.token] = r.principal; });
          if (res && res.next_after_token != null && ++pages < 50) after = res.next_after_token;
          else break;
        }
        if (S.dir.tenant === tenant) { S.dir.map = map; S.dir.error = null; }
      } catch (e) {
        if (S.dir.tenant === tenant) S.dir.error = String((e && e.message) || e);
      } finally {
        if (S.dir.tenant === tenant) S.dir.promise = null;
        renderDirNote();
      }
      return map;
    })();
    return S.dir.promise;
  }

  function tokName(t) {
    if (typeof t === "string") return t;
    return (S.dir.map && S.dir.map[t]) || null;
  }
  // Directory strings are wire-form ("group:admin") — for prose, use the bare
  // human name ("admin"); the kind/token stay in chips and the wire block.
  function tokHumanName(t) {
    var n = tokName(t);
    if (!n) return null;
    var i = String(n).indexOf(":");
    return i > 0 ? n.slice(i + 1) : n;
  }
  // One principal token as a humane chip: name first, kind + #token dimmed —
  // matches People & groups (bold "admin", secondary "group · #2"). The raw
  // wire string stays in the wire-form details block only.
  function tokChip(t) {
    var n = tokName(t);
    if (n) {
      var i = String(n).indexOf(":");
      if (i > 0) {
        var kind = n.slice(0, i);
        return V.entityChip(n.slice(i + 1), (kind === "user" ? "person" : kind) + " · #" + t);
      }
      return V.entityChip(n, "#" + t);
    }
    return '<span class="entity-chip"><b>token #' + esc(t) + '</b><span class="src">name unknown</span></span>';
  }
  function tokChips(list) {
    if (!list || !list.length) {
      return '<span class="expired">no one — empty set (fail closed)</span>';
    }
    return list.map(tokChip).join(" ");
  }
  function dirHintInline() {
    if (S.dir.map || !S.dir.error) return "";
    return ' <span class="asof">names unavailable — the token&rarr;name directory needs the admin token (session bar)</span>';
  }
  function renderDirNote() {
    var n = el("sc-dir-note");
    if (!n) return;
    if (S.dir.map) {
      var c = Object.keys(S.dir.map).length;
      n.textContent = "name directory loaded — " + c + " principal" + (c === 1 ? "" : "s") + " known";
    } else if (S.dir.error) {
      n.textContent = "names unavailable (admin token required) — tokens will show as #numbers";
    } else n.textContent = "";
  }

  /* ===================================================================
     2 · RECALL PROBE — POST /v1/recall (pure read) + AUTOLOAD default
     =================================================================== */
  // Default probe: the entity the handle is bound to (most likely to hit),
  // else a generic phrase. It is a SEARCH INPUT, disclosed as the default —
  // never presented as a measurement or a claim about the corpus.
  function defaultQuery(p) {
    if (p.entity_scope && p.entity_scope.length) {
      var name = String(p.entity_scope[0]).split(":").pop();
      if (name) return name;
    }
    return "recent updates";
  }

  function autoRecall(p) {
    var q = (el("sc-q").value || "").trim() || defaultQuery(p);
    el("sc-q").value = q;
    S.autoQ = q;
    runRecall(true);
  }

  async function runRecall(auto) {
    V.clearErr("sc-recall-err");
    el("sc-recall-out").innerHTML = "";
    el("sc-trace").innerHTML = "";
    el("sc-lat").innerHTML = "";
    el("sc-auto-note").innerHTML = "";
    if (!S.handle) return V.err("sc-recall-err", "paste a scope handle above first");
    var k = clampInt(el("sc-k").value, 1, 100, 8);
    var runs = clampInt(el("sc-runs").value, 1, 50, 1);
    var q = (el("sc-q").value || "").trim() || null;
    var body = { scope_handle: S.handle, text: q, k: k };
    if (auto) {
      el("sc-auto-note").innerHTML =
        '<div class="note" style="margin-top:6px">Auto-ran a default search for &ldquo;<b>' + esc(q) +
        '&rdquo;</b> through this handle &mdash; type your own query above to test something specific.</div>';
    }
    var btn = el("sc-recall");
    btn.disabled = true;
    try {
      var hits = null, lat = [];
      for (var i = 0; i < runs; i++) {
        var t0 = performance.now();
        hits = await V.api("/v1/recall", { json: body });
        lat.push(performance.now() - t0);
      }
      S.lat = lat;
      S.probes.recall = { query: q, k: k, runs: runs, hits: hits, latency_ms: lat };
      renderLatency(lat);
      if (hits && hits.length) {
        el("sc-recall-out").innerHTML =
          '<div class="note" style="margin-top:8px"><b>' + hits.length + "</b> result" + (hits.length === 1 ? "" : "s") +
          " came back through this handle. All results are at or below this handle&rsquo;s ceiling (" +
          V.confBadge(S.claims ? S.claims.max_confidentiality : null) +
          ') <span class="asof">— per-item classification is not returned on the read path</span>.</div>' +
          hits.map(function (h, idx) { return hitCard(h, idx + 1); }).join("");
        renderTrace(hits);
      } else {
        el("sc-recall-out").innerHTML = explainZero(q);
      }
      stampState(S.claims);
    } catch (e) {
      V.err("sc-recall-err", e);
      el("sc-state").innerHTML = V.stateChip("fail", "read refused");
    } finally { btn.disabled = false; }
  }

  // Session-local latency — labeled, never confused with the real benchmark.
  function renderLatency(lat) {
    if (!lat || !lat.length) return;
    var srt = lat.slice().sort(function (a, b) { return a - b; });
    var p = function (q) { return srt[Math.min(srt.length - 1, Math.floor(q * (srt.length - 1) + 0.5))]; };
    el("sc-lat").innerHTML =
      '<div class="note" style="margin-top:8px">Round-trip from this browser &mdash; <b>p50</b> ' + V.fmtMs(p(0.5)) +
      " · <b>p95</b> " + V.fmtMs(p(0.95)) + " · <b>p99</b> " + V.fmtMs(p(0.99)) +
      ' <span class="badge b-kind">' + lat.length + " run" + (lat.length === 1 ? "" : "s") + "</span>" +
      "<br><em>session-local · your hardware · includes network — NOT the milestone-A benchmark.</em></div>";
  }

  /* ---------------------------------------------- readable result cards */
  // Content FIRST; provenance/trust/derivation as chips; ids mono-small.
  // Rank is primary; the raw score stays in the meta line — BM25/RRF scores
  // are not probabilities, so rendering them as "NN%" would fabricate one.
  function hitCard(h, rank) {
    var derivation = trustToDerivation(h.trust_tier);
    var support = h.support_tier
      ? ' <span class="badge b-kind" title="bucketed cross-customer support — never an exact count (provenance firewall)">support: ' + esc(h.support_tier) + "</span>"
      : "";
    // NO per-item confidentiality chip: the wire does not return one, and the
    // handle's ceiling is a bound, not the item's classification. The ceiling
    // is stated once above the results list instead.
    return (
      '<div class="hit">' +
        '<div class="content" style="margin-top:0">' + esc(h.content) + "</div>" +
        '<div style="margin-top:6px">' +
          '<span class="badge b-kind" title="result rank (raw score in the line below)">#' + rank + "</span> " +
          V.kindBadge(h.kind || "content") +
          V.provenanceBadge(h.acl_provenance) +
          V.trustBadge(h.trust_tier) +
          V.tagDerivationBadge(derivation) +
          support +
          V.entityBadges(h.entity_tags) +
        "</div>" +
        '<div class="dc-meta">score ' + Number(h.score).toFixed(3) +
          " · doc " + esc(h.document_id) + " · seq " + esc(h.seq) +
          " · valid_from " + esc(V.fmtTime(h.valid_from)) +
          " · citation&rarr;L0 episode " + esc(h.provenance) +
          ' <button class="sc-copy-doc" data-doc="' + esc(h.document_id) + '" style="padding:1px 7px;font-size:11px;margin-left:6px">Copy document_id</button>' +
        "</div>" +
      "</div>"
    );
  }

  // trust_tier → tag_derivation: the honest deterministic mapping (the wire
  // has no tag_derivation field). Disclosed in the boundary trace.
  function trustToDerivation(t) {
    var n = String(t || "").toLowerCase();
    return (n === "authoritative" || n === "tier1" || n === "tier-1") ? "provenance" : "inferred";
  }

  /* --------------------------------------- boundary trace (returned set) */
  function renderTrace(hits) {
    var p = S.claims || {};
    var lines = [];
    var mix = {}, auth = 0, obs = 0, knowledge = 0;
    hits.forEach(function (h) {
      var pv = String(h.acl_provenance || "admin-assigned").toLowerCase();
      mix[pv] = (mix[pv] || 0) + 1;
      if (trustToDerivation(h.trust_tier) === "provenance") auth++; else obs++;
      if (String(h.kind).toLowerCase() === "knowledge") knowledge++;
    });
    lines.push("Everything above passed every mandatory pre-filter of this handle — permission overlap, entity limit, confidentiality ceiling, and current-truth validity — <em>before</em> ranking.");
    lines.push("Where the permissions came from: " + Object.keys(mix).map(function (k) {
      return V.provenanceBadge(k) + "&times;" + mix[k];
    }).join(" "));
    lines.push("How the tags were made: " + V.tagDerivationBadge("provenance") + "&times;" + auth +
      " automatic from the source &nbsp; " + V.tagDerivationBadge("inferred") + "&times;" + obs + " model-/agent-derived (dashed = not confirmed)");
    if (knowledge) {
      lines.push('<span class="badge b-kind">knowledge</span>&times;' + knowledge +
        " — published generalizations; their support is a bucket, never an exact count.");
    }
    if (p.entity_scope && p.entity_scope.length) {
      lines.push("Entity limit applied: only items about {" + esc(p.entity_scope.join(", ")) + "} could come back.");
    }
    el("sc-trace").innerHTML =
      '<details style="margin-top:10px"><summary style="cursor:pointer;color:var(--accent)">How this set was allowed through</summary>' +
      '<div style="margin-top:6px">' +
      lines.map(function (l) { return '<div class="note" style="margin-top:4px">' + l + "</div>"; }).join("") +
      '<div class="note" style="margin-top:8px"><em>Honesty note:</em> this explains the returned set only. For per-item proof of what was <b>held back</b> and why, use &ldquo;Why were things held back?&rdquo; below — an audited admin call, deliberately off the read path.</div>' +
      "</div></details>";
  }

  /* ------------------------------------------ explain-zero (speaks human) */
  // sp-b: filtered-by-scope. Forensic CTAs ONLY — never a fill-it button.
  function explainZero(q) {
    var p = S.claims || {};
    var why = [];
    if (seesNothing(p)) {
      why.push("This handle names <b>no one</b>, so it sees <b>nothing</b> — that is fail-closed working as designed, not a bug.");
    } else {
      if (p.entity_scope && p.entity_scope.length) {
        var names = p.entity_scope.map(function (e) { return String(e).split(":").pop(); }).join(", ");
        why.push("This scope only covers <b>" + esc(names) + "</b> — anything about other entities is invisible to it.");
      }
      why.push("Its confidentiality ceiling is <b>" + esc(confName(p.max_confidentiality)) +
        "</b> — anything classified higher was filtered out before ranking, and no query can raise that.");
      why.push("And nothing visible to it matched &ldquo;" + esc(q || "") + "&rdquo;.");
    }
    var quarantineLine =
      'If a write you expected never shows up anywhere, it may never have been indexed at all — check <b>Quarantine</b> (payloads Verity refused to index because their permissions could not be mapped).';
    return (
      '<div class="empty-teach sp-b">' +
        '<div class="et-title">Nothing matches — and that can be the correct answer</div>' +
        '<div class="et-body">' + why.map(function (w) { return "<div style='margin-top:4px'>" + w + "</div>"; }).join("") +
          "<div style='margin-top:8px'>" + quarantineLine + "</div></div>" +
        '<div class="et-actions">' +
          '<button class="sc-goto-why">Explain the filtering (admin, audited)</button>' +
          '<button class="sc-goto-quar">Check Quarantine &rsaquo;</button>' +
        "</div>" +
      "</div>"
    );
  }
  // delegated wiring for forensic CTAs (they render after the fact, possibly
  // in more than one place — classes, never duplicate ids)
  document.addEventListener("click", function (ev) {
    var t = ev.target;
    if (!t || !t.classList) return;
    if (t.classList.contains("sc-goto-why")) runWhy();
    if (t.classList.contains("sc-goto-quar")) V.show("quarantine");
  });

  /* ===================================================================
     3 · WHY HELD BACK — POST /v1/admin/debug/recall (admin · audited ·
     OFF the read path). Names principals via the directory + the
     response's visibility_tokens field.
     =================================================================== */
  var DROP_PLAIN = {
    stale_superseded: ["an older version", "a newer value replaced this row (its validity window is closed); current-truth reads exclude it"],
    visibility_empty: ["visible to no one", "the item carries zero visibility permissions — invisible to everyone; Verity never guesses permissions (fail closed)"],
    visibility_no_overlap: ["not visible to this handle", "none of the people/groups who can see this item are on this handle"],
    confidentiality_above_ceiling: ["above the ceiling", "classified higher than this handle's confidentiality ceiling — filtered before ranking; no query can raise the ceiling"],
    entity_scope_untagged: ["no entity label", "this handle is limited to specific entities and the item carries no entity label — denied by default"],
    entity_scope_outside: ["about a different entity", "the item's entities fall outside what this handle is limited to"],
    restricted_dropped_no_rebac: ["restricted — live check unavailable", "restricted material needs a live permission recheck; with none available it is held back to be safe"],
  };
  var NOTE_PLAIN = {
    restricted_subject_to_live_recheck_not_reproduced_here:
      "on a real read this item would face one more live permission check; this explainer flags that instead of running it",
    restricted_served_without_rebac_by_explicit_override:
      "this server was explicitly configured to serve restricted material without the live check — disclosed, never hidden",
  };

  async function runWhy() {
    V.clearErr("sc-why-err");
    el("sc-why-out").innerHTML = "";
    if (!S.handle) return V.err("sc-why-err", "paste a scope handle above first");
    var q = (el("sc-q").value || "").trim();
    if (!q) return V.err("sc-why-err", "type a search above first — the explainer explains one concrete query");
    var n = clampInt(el("sc-why-n").value, 1, 500, 50);
    var btn = el("sc-why");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/admin/debug/recall", {
        admin: true,
        json: { scope_handle: S.handle, text: q, candidates: n },
      });
      S.probes.why = res;
      // make sure names are (or will be) available, then render
      await ensureDirectory(S.claims && S.claims.tenant_id);
      renderWhy(res);
      var out = el("sc-why-out");
      if (out) out.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      V.err("sc-why-err", e);
    } finally { btn.disabled = false; }
  }

  function renderWhy(res) {
    if (!res || !res.query) return V.err("sc-why-err", "server returned an unexpected trace shape");
    var cands = res.candidates || [];
    var admitted = 0;
    var reasonCounts = {};
    cands.forEach(function (c) {
      if (c.admitted) admitted++;
      (c.drop_reasons || []).forEach(function (r) { reasonCounts[r] = (reasonCounts[r] || 0) + 1; });
    });
    var sc = res.scope || {};

    var head =
      '<div class="note" style="margin-top:8px">Checked the top <b>' + esc(res.query.candidates_traced) +
        "</b> candidate" + (res.query.candidates_traced === 1 ? "" : "s") + " for this search: <b>" + admitted +
        "</b> would be returned, <b>" + (cands.length - admitted) + "</b> held back.</div>" +
      '<dl class="kv" style="margin-top:8px">' +
        "<dt>This handle carries</dt><dd>" + tokChips(sc.principals_effective) +
          ' <span class="asof">(its tokens minus any revoked in-window — exactly what a real read uses)</span></dd>' +
        (sc.principals_revoked && sc.principals_revoked.length
          ? "<dt>Revoked since mint</dt><dd>" + sc.principals_revoked.map(function (t) {
              return tokChip(t) + ' <span class="badge b-downgrade">revoked</span>';
            }).join(" ") + "</dd>" : "") +
        "<dt>Limited to</dt><dd>" + ((sc.entity_scope && sc.entity_scope.length)
          ? V.entityBadges(sc.entity_scope) : '<span style="color:var(--dim)">any entity</span>') + "</dd>" +
        "<dt>Ceiling</dt><dd>" + V.confBadge(sc.max_confidentiality) + "</dd>" +
      "</dl>";

    var hist = Object.keys(reasonCounts).length
      ? '<div class="note" style="margin-top:6px">Held back because: ' +
          Object.keys(reasonCounts).map(function (r) { return dropChip(r) + "&times;" + reasonCounts[r]; }).join(" &nbsp; ") + "</div>"
      : "";

    var honesty = (res.honesty && res.honesty.length)
      ? '<div class="note" style="margin-top:8px"><em>The server\'s own stated limits of this trace:</em><ul style="margin:4px 0 0 18px;padding:0">' +
          res.honesty.map(function (h) { return "<li>" + esc(h) + "</li>"; }).join("") + "</ul></div>"
      : "";

    var cards = cands.length
      ? cands.map(function (c) { return whyCard(c, sc); }).join("")
      : '<div class="empty-teach sp-b" style="margin-top:8px"><div class="et-title">Nothing to trace</div>' +
        '<div class="et-body">The tenant-wide candidate search surfaced nothing for this text. An item that was never indexed (quarantined) or fell outside the top-N is invisible to this tracer — by its own admission. If a write vanished entirely, check Quarantine.</div>' +
        '<div class="et-actions"><button class="sc-goto-quar">Check Quarantine &rsaquo;</button></div></div>';

    el("sc-why-out").innerHTML =
      '<div class="card" style="margin-top:10px">' +
        '<div class="note"><span class="badge b-defense">admin &middot; audited &middot; OFF the read path</span> ' +
        "This run was written to the audit log (verb <code>debug_recall</code>; every disclosed id recorded). It explains the index as of now, not any past read.</div>" +
        head + hist + honesty +
      "</div>" + cards;
  }

  // One traced candidate ("near-miss" is reserved for held-back rows only):
  // plain verdict + plain reasons; who-can-see-it NAMED via
  // visibility_tokens; wire tokens live only in the meta line + tooltips.
  function whyCard(c, sc) {
    var verdict = c.admitted
      ? V.stateChip("ok", "would be returned")
      : V.stateChip("off", "held back");
    var reasons = (c.drop_reasons || []).map(dropChip).join(" ");

    // who can see this item — names first (the N5 payoff)
    var visTokens = c.visibility_tokens || [];
    var who;
    if (!visTokens.length) {
      who = '<span class="expired">no one — it carries zero visibility permissions (fail closed)</span>';
    } else {
      who = visTokens.map(tokChip).join(" ");
    }

    // turn visibility_no_overlap from a verdict into an instruction
    var instruction = "";
    if ((c.drop_reasons || []).indexOf("visibility_no_overlap") >= 0) {
      var mine = (sc && sc.principals_effective) || [];
      instruction =
        '<div class="dc-evidence" style="margin-top:6px"><b>Why:</b> it is visible to ' +
        visTokens.map(function (t) { var n = tokHumanName(t); return n ? "<b>" + esc(n) + "</b>" : "token #" + esc(t); }).join(", ") +
        "; this handle carries " +
        (mine.length ? mine.map(function (t) { var n = tokHumanName(t); return n ? "<b>" + esc(n) + "</b>" : "token #" + esc(t); }).join(", ") : "<b>no one</b>") +
        " — no overlap. To see it, the reader needs one of those groups/people on its handle (granted at mint, never here).</div>";
    }

    var notes = (c.notes || []).map(function (n) {
      return '<div class="note" style="margin-top:4px">&#9888; ' + esc(NOTE_PLAIN[n] || n) +
        ' <span class="ref">' + esc(n) + "</span></div>";
    }).join("");

    var validity = "valid_from " + esc(V.fmtTime(c.valid_from)) +
      (c.valid_to ? " &rarr; valid_to " + esc(V.fmtTime(c.valid_to)) : " &rarr; current");

    return (
      '<div class="hit"' + (c.admitted ? "" : ' style="opacity:.8"') + ">" +
        "<div>" + verdict + " " + reasons + "</div>" +
        '<div class="content">' + esc(c.content_preview || "") + "</div>" +
        '<div style="margin-top:6px;font-size:var(--fs-sm);color:var(--dim)">Who can see it: ' + who + "</div>" +
        instruction + notes +
        '<div style="margin-top:6px">' +
          V.kindBadge(c.kind || "content") + V.provenanceBadge(c.acl_provenance) +
          V.confBadge(c.confidentiality) + V.trustBadge(c.trust_tier) +
          V.entityBadges(c.entity_tags) +
        "</div>" +
        '<div class="dc-meta">' +
          (c.drop_reasons && c.drop_reasons.length ? "wire: " + c.drop_reasons.map(esc).join(", ") + " · " : "") +
          "score " + Number(c.score).toFixed(3) +
          " · vis tokens [" + visTokens.map(esc).join(", ") + "]" +
          " · chunk " + esc(c.chunk_id) + " · doc " + esc(c.document_id) + " · seq " + esc(c.seq) +
          " · " + validity + " · citation&rarr;L0 episode " + esc(c.provenance) +
        "</div>" +
      "</div>"
    );
  }

  function dropChip(r) {
    var d = DROP_PLAIN[r] || [r, "pre-filter drop reason reported by the server"];
    return '<span class="badge b-st-rejected" title="' + esc(d[1] + " (wire: " + r + ")") + '">' + esc(d[0]) + "</span>";
  }

  /* ===================================================================
     4 · BRIEF + ACTIVITY PROBES (pure reads)
     =================================================================== */
  async function runBrief() {
    V.clearErr("sc-brief-err");
    el("sc-brief-out").innerHTML = "";
    if (!S.handle) return V.err("sc-brief-err", "paste a scope handle above first");
    var entity = (el("sc-brief-e").value || "").trim();
    if (!entity) return V.err("sc-brief-err", "name an entity, e.g. account:acme");
    try {
      var b = await V.api("/v1/briefs/" + encodeURIComponent(entity) +
        "?scope_handle=" + encodeURIComponent(S.handle));
      S.probes.brief = { entity: entity, result: b };
      var mem = (b && b.recent_memory) || [];
      var act = (b && b.recent_activity) || [];
      var fresh = b && b.is_stale
        ? V.stateChip("wait", "stale — not re-synced within its freshness window (disclosed, never hidden)")
        : V.stateChip("ok", "fresh");
      el("sc-brief-out").innerHTML =
        '<div class="note" style="margin-top:8px">' + fresh +
        " generated " + esc(V.fmtTime(b && b.generated_at)) +
        (b && b.last_synced_at ? " · last synced " + esc(V.fmtTime(b.last_synced_at)) : "") +
        " · " + mem.length + " memory item" + (mem.length === 1 ? "" : "s") +
        " · " + act.length + " action" + (act.length === 1 ? "" : "s") +
        (mem.length
          ? " · all at or below this handle&rsquo;s ceiling (" + V.confBadge(S.claims ? S.claims.max_confidentiality : null) + ")"
          : "") + "</div>" +
        mem.map(function (h, i) { return hitCard(h, i + 1); }).join("") +
        actionRows(act) +
        (mem.length || act.length ? "" :
          '<div class="empty-teach sp-b" style="margin-top:8px"><div class="et-title">Nothing visible about this entity under this handle</div>' +
          '<div class="et-body">Fail-closed emptiness is a correct answer, not a bug — the entity may exist and simply not be visible to this handle. Use &ldquo;Explain the filtering&rdquo; below for per-item proof.</div></div>');
    } catch (e) { V.err("sc-brief-err", e); }
  }

  async function runActivity() {
    V.clearErr("sc-act-err");
    el("sc-act-out").innerHTML = "";
    if (!S.handle) return V.err("sc-act-err", "paste a scope handle above first");
    var entity = (el("sc-brief-e").value || "").trim();
    if (!entity) return V.err("sc-act-err", "name an entity, e.g. account:acme");
    try {
      var actions = await V.api("/v1/activity?scope_handle=" + encodeURIComponent(S.handle) +
        "&entity=" + encodeURIComponent(entity));
      S.probes.activity = { entity: entity, result: actions };
      el("sc-act-out").innerHTML = (actions && actions.length)
        ? actionRows(actions)
        : '<div class="empty-teach sp-b" style="margin-top:8px"><div class="et-title">No visible actions on this entity under this handle</div>' +
          '<div class="et-body">Fail-closed emptiness is a correct answer, not a bug.</div></div>';
    } catch (e) { V.err("sc-act-err", e); }
  }

  function actionRows(actions) {
    if (!actions || !actions.length) return "";
    return (
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>when</th><th>what</th><th>by</th><th>outcome</th><th>summary</th><th>entities</th><th>evidence&rarr;L0</th>" +
      "</tr></thead><tbody>" +
      actions.map(function (a) {
        return "<tr><td>" + esc(V.fmtTime(a.occurred_at)) + "</td><td>" + esc(a.action_type) +
          "</td><td>" + actorPairHtml(a.actor_sub, a.actor_azp) +
          "</td><td>" + esc(a.outcome) +
          "</td><td>" + esc(a.summary) +
          "</td><td>" + V.entityBadges(a.entities) +
          "</td><td>" + V.refSpan(a.provenance != null ? a.provenance : "—") + "</td></tr>";
      }).join("") +
      "</tbody></table></div>"
    );
  }

  /* ===================================================================
     5 · DERIVE (narrow-only) + RENEW — POST /v1/scopes
     No widen affordance exists, not even disabled. Renew is offered only
     once the handle is EXPIRED. The TOP-LEVEL fresh mint lives in the
     shell (Verity.openMint) — this panel links to it, never duplicates.
     =================================================================== */
  function updateDeriveControls(p) {
    var openBtn = el("sc-open"), renewBtn = el("sc-renew"), hint = el("sc-mint-hint");
    if (!openBtn || !renewBtn) return;
    openBtn.disabled = !p;
    var expired = isExpired(p);
    renewBtn.disabled = !expired;
    renewBtn.title = expired
      ? "Re-mints the same permissions with a fresh expiry."
      : "Renew re-mints the same permissions with a fresh expiry — offered only once this handle has expired.";
    if (hint) {
      hint.innerHTML = !p ? "" : expired
        ? 'This handle is <span class="expired">expired</span> — <b>Renew</b> re-mints the same permissions with a fresh expiry. Narrowing and renewing reuse the old claims; for a fresh identity resolution, mint a new handle from the top bar.'
        : 'Narrowing only ever <em>tightens</em> — you cannot add people, raise the ceiling, or widen the entity limit from here. For a brand-new handle (fresh identity resolution), use <b>+ Mint scope handle</b> in the top bar.';
    }
  }

  function mintDialogHtml() {
    return (
      '<div class="dialog-backdrop" id="sc-mint-dialog">' +
        '<div class="dialog" style="max-width:640px">' +
          "<h3>Open a narrower handle</h3>" +
          '<div class="note">Derives a fresh handle from the one you decoded. Every field below can only <b>tighten</b> it. Who-it-reads-as is carried over unchanged — narrowing can never grant powers this handle lacks.</div>' +
          '<div class="card" style="margin-top:10px">' +
            '<div class="note" style="margin-bottom:6px"><b>Who it reads as</b> — carried over unchanged (not editable):</div>' +
            '<div id="sc-mint-principals"></div>' +
          "</div>" +
          '<div class="tight" style="margin-top:10px">' +
            '<label for="sc-mint-conf">confidentiality ceiling <span style="font-weight:400">(can only stay or go lower)</span></label>' +
            '<select class="field" id="sc-mint-conf"></select>' +
          "</div>" +
          '<div class="card" style="margin-top:10px">' +
            '<div class="note" style="margin-bottom:6px"><b>Limit to entities</b> — <span id="sc-mint-entity-note"></span></div>' +
            '<div id="sc-mint-entities"></div>' +
          "</div>" +
          '<div class="tight" style="margin-top:10px">' +
            '<label for="sc-mint-purpose">purpose <span style="font-weight:400">(optional — can only lower the ceiling; unknown purposes are refused by the server)</span></label>' +
            '<input type="text" id="sc-mint-purpose" class="field" list="sc-mint-purpose-list" placeholder="e.g. support_conversation" autocomplete="off">' +
            '<datalist id="sc-mint-purpose-list">' +
              '<option value="support_conversation"><option value="sales_negotiation">' +
              '<option value="marketing"><option value="analytics"><option value="audit">' +
            "</datalist>" +
          "</div>" +
          '<div class="tight" style="margin-top:10px">' +
            '<label for="sc-mint-ttl">expires after (seconds) <span style="font-weight:400">(the server enforces a 60&nbsp;s minimum)</span></label>' +
            '<input type="number" id="sc-mint-ttl" class="field" min="60" step="60" value="3600">' +
          "</div>" +
          '<div class="err" id="sc-mint-dlg-err"></div>' +
          '<div class="actions">' +
            '<button id="sc-mint-cancel">Cancel</button>' +
            '<button class="primary" id="sc-mint-confirm">Mint narrower handle</button>' +
          "</div>" +
        "</div>" +
      "</div>"
    );
  }

  // The server's Confidentiality enum wire form is the PascalCase variant
  // name ("Internal", …) — verified against main.rs OpenScopeRequest.
  var CONF_WIRE = ["Public", "Internal", "Confidential", "Restricted"];
  function confWire(idx) { return CONF_WIRE[idx] || "Internal"; }
  function ceilingIndex(p) {
    var v = p && p.max_confidentiality;
    if (typeof v === "number") return v;
    if (typeof v === "string") {
      var i = V.CONF_NAMES.indexOf(v.toLowerCase());
      if (i >= 0) return i;
    }
    return 1; // server default = Internal
  }

  function openMintDialog() {
    if (!S.claims) return;
    var p = S.claims;
    V.clearErr("sc-mint-dlg-err"); V.clearErr("sc-mint-err");

    // Honest disclosure: deriving from an identity-resolved handle carries
    // its already-resolved tokens; it does NOT re-resolve the group graph.
    var subjNote = (typeof p.subject === "string" && p.subject)
      ? '<div class="note" style="margin-top:6px"><em>This handle was identity-resolved from ' + esc(p.subject) +
        ".</em> Narrowing carries its resolved tokens as-is — it does <b>not</b> re-check group memberships. For a fresh identity pull, mint a new handle (top bar). Revocations are still applied at mint.</div>"
      : "";
    el("sc-mint-principals").innerHTML = principalsHtml(p) + subjNote;

    var ceil = ceilingIndex(p);
    var opts = "";
    for (var i = 0; i <= ceil; i++) {
      var nm = V.CONF_NAMES[i] || String(i);
      opts += '<option value="' + i + '"' + (i === ceil ? " selected" : "") + ">" +
        esc(nm) + (i === ceil ? " (current ceiling)" : "") + "</option>";
    }
    el("sc-mint-conf").innerHTML = opts;

    var eWrap = el("sc-mint-entities"), eNote = el("sc-mint-entity-note");
    if (p.entity_scope && p.entity_scope.length) {
      eNote.textContent = "uncheck to narrow further; you cannot add an entity outside this set.";
      eWrap.innerHTML = p.entity_scope.map(function (e) {
        return '<label style="display:block;margin:3px 0;text-transform:none;letter-spacing:0">' +
          '<input type="checkbox" class="sc-mint-ent" value="' + esc(e) + '" checked> ' +
          V.entityBadges([e]) + "</label>";
      }).join("");
    } else {
      eNote.textContent = "this handle has no entity limit. Adding one narrows it; leave blank to keep it unlimited.";
      eWrap.innerHTML =
        '<input type="text" id="sc-mint-ent-free" class="field" placeholder="account:acme, account:globex (optional)" autocomplete="off">';
    }
    el("sc-mint-purpose").value = (typeof p.purpose === "string") ? p.purpose : "";
    el("sc-mint-ttl").value = "3600";
    V.dialog("sc-mint-dialog").open();
  }

  function collectNarrowedEntities(p) {
    if (p.entity_scope && p.entity_scope.length) {
      var checked = Array.prototype.slice
        .call(document.querySelectorAll(".sc-mint-ent:checked"))
        .map(function (n) { return n.value; });
      for (var i = 0; i < checked.length; i++) {
        if (p.entity_scope.indexOf(checked[i]) < 0) {
          return { entities: null, error: "refusing to widen: " + checked[i] + " is not in the source handle's entity limit" };
        }
      }
      return { entities: checked, error: null };
    }
    var free = el("sc-mint-ent-free");
    var parts = String((free && free.value) || "").split(/[\s,]+/).filter(function (s) { return s.length; });
    return { entities: parts, error: null };
  }

  async function onMintConfirm() {
    V.clearErr("sc-mint-dlg-err");
    var p = S.claims;
    if (!p) return V.err("sc-mint-dlg-err", "decode a scope handle first");
    var ceil = ceilingIndex(p);
    var wantConf = clampInt(el("sc-mint-conf").value, 0, ceil, ceil);
    if (wantConf > ceil) return V.err("sc-mint-dlg-err", "refusing to widen the confidentiality ceiling");
    var ents = collectNarrowedEntities(p);
    if (ents.error) return V.err("sc-mint-dlg-err", ents.error);
    var ttl = clampInt(el("sc-mint-ttl").value, 60, 2147483647, 3600);
    var purpose = (el("sc-mint-purpose").value || "").trim();
    var body = {
      tenant_id: p.tenant_id,
      principals: p.principals || [],   // carried verbatim — never adds one
      entity_scope: ents.entities,
      max_confidentiality: confWire(wantConf),
      actor_sub: p.actor_sub != null ? p.actor_sub : undefined,
      actor_azp: p.actor_azp != null ? p.actor_azp : undefined,
      ttl_seconds: ttl,
    };
    if (purpose) body.purpose = purpose;
    stripUndefined(body);
    var btn = el("sc-mint-confirm");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/scopes", { json: body });
      V.dialog("sc-mint-dialog").close();
      renderMintResult(res, "Narrower handle minted", body);
    } catch (e) {
      V.err("sc-mint-dlg-err", e); // server refusals surface verbatim
    } finally { btn.disabled = false; }
  }

  async function onRenew() {
    V.clearErr("sc-mint-err");
    var p = S.claims;
    if (!p) return V.err("sc-mint-err", "decode a scope handle first");
    var body = {
      tenant_id: p.tenant_id,
      principals: p.principals || [],
      entity_scope: (p.entity_scope || []).slice(),
      max_confidentiality: confWire(ceilingIndex(p)),
      actor_sub: p.actor_sub != null ? p.actor_sub : undefined,
      actor_azp: p.actor_azp != null ? p.actor_azp : undefined,
      ttl_seconds: 3600,
    };
    if (typeof p.purpose === "string" && p.purpose) body.purpose = p.purpose;
    stripUndefined(body);
    var btn = el("sc-renew");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/scopes", { json: body });
      renderMintResult(res, "Renewed — same permissions, fresh expiry", body);
    } catch (e) {
      V.err("sc-mint-err", e);
    } finally { btn.disabled = !isExpired(p); }
  }

  function renderMintResult(res, title, body) {
    var handle = res && res.scope_handle;
    if (!handle) return V.err("sc-mint-err", "server returned no scope_handle");
    el("sc-mint-out").innerHTML =
      '<div class="card" style="margin-top:10px">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip("ok", "minted") +
          '<b>' + esc(title) + "</b>" +
          '<span class="asof">shown once — the console does not store handles</span>' +
        "</div>" +
        '<dl class="kv" style="margin-top:8px">' +
          "<dt>ceiling</dt><dd>" + V.confBadge(body.max_confidentiality) + "</dd>" +
          "<dt>limited to</dt><dd>" + (body.entity_scope && body.entity_scope.length
            ? V.entityBadges(body.entity_scope) : '<span style="color:var(--dim)">any entity</span>') + "</dd>" +
          (body.purpose ? "<dt>purpose</dt><dd>" + V.kindBadge(body.purpose) + "</dd>" : "") +
          "<dt>expires</dt><dd>" + esc(V.fmtTime(res.expires_at)) + "</dd>" +
        "</dl>" +
        '<div style="margin-top:8px"><textarea readonly spellcheck="false" style="min-height:60px" id="sc-mint-handle">' + esc(handle) + "</textarea></div>" +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><button class="primary" id="sc-mint-copy">Copy new handle</button></div>' +
          '<div class="tight"><button id="sc-mint-load">Inspect it here now</button></div>' +
        "</div>" +
      "</div>";
    el("sc-mint-copy").onclick = function () { copy(handle, this, "Copy new handle"); };
    el("sc-mint-load").onclick = function () {
      el("sc-handle").value = handle;
      decode(handle);
      el("sc-handle").scrollIntoView({ behavior: "smooth", block: "start" });
    };
  }

  /* ===================================================================
     6 · EXPORT PROOF — a self-contained evidence file (kept from v1,
     now including the why-trace and the token→name directory used)
     =================================================================== */
  function onExport() {
    if (!S.claims) return;
    var now = new Date();
    var snapshot = {
      artifact: "verity-scope-boundary-evidence",
      exported_at: now.toISOString(),
      build_hash: V.buildHash(),
      note: "Self-contained boundary evidence. Handle decode is client-side; probes are pure reads (no LLM, no live-ReBAC). Latency is session-local, NOT the milestone-A benchmark. The why-filtered trace, when present, came from the audited admin debug endpoint (off the read path). principal_directory is the admin token→name map used to render names.",
      claims: S.claims,
      probes: S.probes,
      principal_directory: S.dir.map || null,
    };
    var json = JSON.stringify(snapshot, null, 2);
    download(evidenceHtml(snapshot, json), "verity-boundary-" + stamp(now) + ".html", "text/html");
  }

  function evidenceHtml(snap, json) {
    var claims = snap.claims || {};
    var recall = snap.probes && snap.probes.recall;
    var lat = recall && recall.latency_ms ? recall.latency_ms.slice().sort(function (a, b) { return a - b; }) : null;
    var pick = function (q) { return lat ? V.fmtMs(lat[Math.min(lat.length - 1, Math.floor(q * (lat.length - 1) + 0.5))]) : "—"; };
    var claimRows = Object.keys(claims).map(function (k) {
      return "<tr><td class='k'>" + esc(k) + "</td><td>" + esc(JSON.stringify(claims[k])) + "</td></tr>";
    }).join("");
    var why = snap.probes && snap.probes.why;
    var whyLine = why && why.query
      ? "traced " + esc(why.query.candidates_traced) + " candidate(s); " +
        esc((why.candidates || []).filter(function (c) { return c.admitted; }).length) + " admitted."
      : "no why-filtered trace was run.";
    return (
      "<!doctype html><html><head><meta charset='utf-8'>" +
      "<title>Verity boundary evidence — " + esc(snap.exported_at) + "</title>" +
      "<style>" +
      "body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0d1117;color:#cdd6df;padding:24px;line-height:1.5}" +
      "h1{font-size:18px;color:#58a6ff}h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#58a6ff;margin:20px 0 8px}" +
      ".meta{color:#7d8894;font-size:12px}table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}" +
      "td{border-bottom:1px solid #2b3540;padding:5px 10px;vertical-align:top;word-break:break-all}td.k{color:#7d8894;width:200px}" +
      "pre{background:#131920;border:1px solid #2b3540;border-radius:8px;padding:12px;overflow-x:auto;font-size:11.5px;white-space:pre-wrap;word-break:break-word}" +
      ".pill{display:inline-block;border:1px solid #2b3540;border-radius:10px;padding:1px 8px;font-size:11px;color:#7d8894}" +
      "</style></head><body>" +
      "<h1>Verity — scope boundary evidence</h1>" +
      "<div class='meta'>exported " + esc(snap.exported_at) + " · build <b>" + esc(snap.build_hash) + "</b> · <span class='pill'>client decode · pure reads · admin trace disclosed</span></div>" +
      "<div class='meta' style='margin-top:6px'>" + esc(snap.note) + "</div>" +
      "<h2>Decoded claims</h2><table>" + claimRows + "</table>" +
      "<h2>Recall probe</h2>" +
      (recall
        ? "<div class='meta'>query " + esc(JSON.stringify(recall.query)) + " · k " + esc(recall.k) +
          " · " + (recall.hits ? recall.hits.length : 0) + " hit(s) · " + (recall.runs || 1) + " run(s)</div>" +
          (lat ? "<div class='meta'>session-local latency (NOT the benchmark): p50 " + pick(0.5) + " · p95 " + pick(0.95) + " · p99 " + pick(0.99) + "</div>" : "")
        : "<div class='meta'>no recall probe was run.</div>") +
      "<h2>Why-filtered trace</h2><div class='meta'>" + whyLine + "</div>" +
      "<h2>Machine-readable snapshot (JSON)</h2><pre>" + esc(json) + "</pre>" +
      "</body></html>"
    );
  }

  /* ------------------------------------------------------------- utils */
  document.addEventListener("click", function (ev) {
    var t = ev.target;
    if (t && t.classList && t.classList.contains("sc-copy-doc")) {
      copy(t.getAttribute("data-doc") || "", t, "Copy document_id");
    }
  });

  function copy(text, btn, label) {
    var done = function () {
      if (!btn) return;
      var prev = btn.textContent;
      btn.textContent = "copied";
      setTimeout(function () { btn.textContent = prev || label; }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  }
  function fallbackCopy(text) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    } catch (e) { /* best-effort */ }
  }
  function download(text, name, mime) {
    var blob = new Blob([text], { type: mime + ";charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function clampInt(v, lo, hi, def) {
    var n = parseInt(v, 10);
    if (isNaN(n)) n = def;
    return Math.max(lo, Math.min(hi, n));
  }
  function confName(v) {
    if (v == null) return "(none)";
    if (typeof v === "number") return V.CONF_NAMES[v] || String(v);
    return String(v).toLowerCase();
  }
  function stripUndefined(o) {
    Object.keys(o).forEach(function (k) { if (o[k] === undefined) delete o[k]; });
  }
  function stamp(d) {
    return d.toISOString().replace(/[:.]/g, "-").replace("T", "_").replace("Z", "");
  }
})();
