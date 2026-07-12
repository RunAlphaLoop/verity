"use strict";
/* ==========================================================================
   panel_playground.js — Playground  [build contract: docs/design/PLAYGROUND.md]
   --------------------------------------------------------------------------
   READ-PATH PURITY IS NOT VIOLATED BY THIS PANEL. POST /v1/recall and the
   point-read GET stay exactly as they are: zero LLM calls, zero live ReBAC
   calls, scope filters materialized into the index as mandatory pre-filters.
   The playground is a CONSUMER of the read path — the LLM lives server-side
   in POST /v1/playground/ask and calls recall/get as tools through the SAME
   enforced, fail-closed, audited pipeline the public handlers use. Nothing
   in this file (or that endpoint) can widen a handle; the Anthropic key
   never reaches this browser.

   HONEST NUMBERS: every displayed ms/token value is copied from the server
   response (std::time::Instant spans; the API's usage block). The browser
   adds exactly ONE number of its own — performance.now() around the fetch —
   always labeled "round-trip in this browser". Nothing is estimated; a
   missing value renders as absent, never as a placeholder.

   FAIL CLOSED: the agent answers only from tool results within the chosen
   scope. The server stamps `visibility` from MEASURED hit counts and this
   panel trusts that stamp, not the model's prose — a scope that sees
   nothing gets the denial hero regardless of what the model wrote.

   Endpoints:
     • GET  /v1/playground/status — key readiness + model allowlist (the
       picker never invents model ids). Always 200; no-key is a state.
     • POST /v1/playground/ask    — the ask. Called with raw fetch (not
       Verity.api) for two contractual reasons: (1) the ONE browser-side
       timing span must wrap exactly the fetch; (2) 502/504 bodies carry
       `partial` measured turns that Verity.api's 300-char error slice
       would truncate — measured work is never thrown away.
     • GET  /v1/admin/principals  — token→name directory (names beside
       tokens in claims; a 401 degrades honestly to "token #N · name
       unknown"). Admin-plane read, OFF the read path, panel_scope pattern.

   Handles live in panel memory + the sessionStorage "recently asked as"
   chips only (this tab, gone on close, labeled as such) — never
   localStorage, never disk, never logged.
   ========================================================================== */
(function () {
  var V = window.Verity;

  var RECENT_KEY = "verity.playground.askedAs"; // sessionStorage, ≤3 chips
  var Q_MAX = 2000;

  var S = {
    status: null,        // GET /v1/playground/status result
    statusErr: null,     // status fetch failure (network / not built yet)
    mode: "paste",       // "working" | "paste" — which radio is active
    active: null,        // { handle, claims, source } — the adopted scope
    dir: { tenant: null, map: null, error: null, promise: null },
    runs: [],            // session-local run records (die with this tab)
    latest: null,        // last successful ask response + client span
    inflight: false,
    tickTimer: null,     // in-flight "elapsed in this browser" ticker
    mounted: false,
  };

  function el(id) { return V.$(id); }
  function esc(s) { return V.esc(s == null ? "" : s); }

  /* -------------------------------------------------- number formatting */
  // Raw server ms, one decimal, thousands-separated — never "~2s".
  function ms1(x) {
    if (x == null || !isFinite(Number(x))) return "—";
    return Number(x).toLocaleString("en-US",
      { minimumFractionDigits: 1, maximumFractionDigits: 1 }) + " ms";
  }
  function intFmt(n) {
    if (n == null || !isFinite(Number(n))) return "—";
    return Number(n).toLocaleString("en-US");
  }
  function plural(n, word) { return n + " " + word + (Number(n) === 1 ? "" : "s"); }
  // Nearest-rank percentile — the panel_scope algorithm, verbatim.
  function pctl(sorted, q) {
    return sorted[Math.min(sorted.length - 1, Math.floor(q * (sorted.length - 1) + 0.5))];
  }

  /* ------------------------------------------------------ claims helpers */
  function isExpired(p) {
    return !!(p && p.expires_at) && new Date(p.expires_at).getTime() - Date.now() <= 0;
  }
  function seesNothing(p) {
    return !p || !p.principals || !p.principals.length;
  }
  function expiresLeft(p) {
    if (!p || !p.expires_at) return null;
    return Math.max(0, (new Date(p.expires_at).getTime() - Date.now()) / 1000);
  }

  /* ===================================================================
     PRINCIPAL DIRECTORY — GET /v1/admin/principals (admin, read-only,
     OFF the read path; the panel_scope pattern). Used ONLY to render
     names beside tokens. 401 degrades honestly to token #N.
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
      }
      return map;
    })();
    return S.dir.promise;
  }

  // "user:priya@corp" → "priya@corp" · "group:sales" → "sales (shared key)".
  function humanName(principalStr) {
    var s = String(principalStr || "");
    var i = s.indexOf(":");
    var kind = i > 0 ? s.slice(0, i) : "";
    var name = i > 0 ? s.slice(i + 1) : s;
    if (kind === "group") return name + " (shared key)";
    if (kind === "agent") return name + " (agent)";
    return name;
  }
  function tokName(t) {
    if (typeof t === "string") return t; // email-string principals name themselves
    return (S.dir.map && S.dir.map[t]) ? humanName(S.dir.map[t]) : null;
  }
  // One principal as a humane chip: name first, #token mono-small (LAW #1).
  function pChip(t) {
    var n = tokName(t);
    if (n) return V.entityChip(n, "#" + t);
    return '<span class="entity-chip"><b>token #' + esc(t) +
      '</b><span class="src">name unknown</span></span>';
  }
  // Short label for a "recently asked as" chip: "priya + sales".
  function labelFor(p) {
    if (seesNothing(p)) return "sees nothing";
    var names = p.principals.map(function (t) {
      var n = tokName(t);
      if (!n) return "#" + t;
      return String(n).replace(/ \(shared key\)| \(agent\)/, "").split("@")[0];
    });
    var out = names.slice(0, 2).join(" + ");
    if (names.length > 2) out += " +" + (names.length - 2);
    return out;
  }

  /* ------------------------------------------- recently-asked-as chips */
  function recentGet() {
    try { return JSON.parse(sessionStorage.getItem(RECENT_KEY) || "[]"); }
    catch (e) { return []; }
  }
  function recentSave(list) {
    try { sessionStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 3))); }
    catch (e) { /* storage unavailable — chips are a convenience only */ }
  }
  function recentPush(label, handle) {
    var list = recentGet().filter(function (c) { return c.handle !== handle; });
    list.unshift({ label: label, handle: handle });
    recentSave(list);
    renderRecent();
  }

  /* ------------------------------------------------------------ register */
  V.register({
    id: "playground",

    mount: function () {
      var host = el("pg-mount");
      if (!host) return;
      host.innerHTML = layout();
      S.mounted = true;
      wire();
      renderNoTenant();
      renderScopeModes();
      renderRecent();
      renderGate();
      // default adoption: this tab's working handle, when live (§3.1)
      var wh = V.workingHandle();
      if (wh) {
        try {
          if (!isExpired(V.decodeHandle(wh))) setMode("working");
        } catch (e) { /* undecodable working handle — paste stands */ }
      }
      renderScopeModes();
      if (!S.active) renderNoHandleTeach();
      fetchStatus();
    },

    // AUTOLOAD: a known tenant warms the token→name directory so claims and
    // chips can carry names. The panel's real input is a HANDLE — with none,
    // the teach states stand in; nothing here fires an ask.
    load: function (_s, tenant) {
      renderNoTenant();
      return ensureDirectory(tenant).then(function () {
        renderScopeModes();
        renderActiveClaims();
        renderRecent();
      });
    },

    onShow: function () {
      if (!S.status && !S.inflight) fetchStatus();
      var p = V.navParams();
      if (p && p.handle) {
        el("pg-paste").value = p.handle;
        setMode("paste");
        adoptPaste(p.handle);
      }
    },
  });

  /* -------------------------------------------------------------- layout */
  function layout() {
    return (
      '<div id="pg-notenant"></div>' +

      // ---- 1 · WHO IS ASKING -------------------------------------------
      '<div class="card">' +
        '<h2>1 &middot; Who is asking? <span class="sub">a principal is a key; a person carries a keyring; groups are shared keys</span></h2>' +
        '<div id="pg-mode-working" style="display:none;margin-top:6px">' +
          '<label style="display:flex;gap:8px;align-items:baseline;cursor:pointer;text-transform:none;letter-spacing:0">' +
            '<input type="radio" name="pg-src" id="pg-r-working" value="working">' +
            '<span>This tab&rsquo;s working handle <span class="asof">(kept in this tab only, gone on close)</span></span>' +
          '</label>' +
          '<div id="pg-working-claims" style="margin:4px 0 8px 24px"></div>' +
        '</div>' +
        '<div style="margin-top:6px">' +
          '<label style="display:flex;gap:8px;align-items:baseline;cursor:pointer;text-transform:none;letter-spacing:0">' +
            '<input type="radio" name="pg-src" id="pg-r-paste" value="paste" checked>' +
            '<span>Paste a handle <span class="asof">(it decodes as you type)</span></span>' +
          '</label>' +
          '<div style="margin:4px 0 0 24px">' +
            '<input type="text" id="pg-paste" placeholder="vs_&hellip;" spellcheck="false" autocomplete="off">' +
            '<div class="err" id="pg-paste-err"></div>' +
          '</div>' +
        '</div>' +
        '<div style="margin-top:10px;margin-left:24px">' +
          '<button id="pg-mint">Mint a handle &rarr;</button> ' +
          '<span class="asof">opens the one mint dialog &mdash; the fresh handle lands here automatically</span>' +
        '</div>' +
        '<div id="pg-claims" style="margin-top:10px"></div>' +
        '<div id="pg-recent" style="margin-top:10px"></div>' +
      '</div>' +

      // ---- gate: no model key on the server (state B) -------------------
      '<div id="pg-nokey"></div>' +

      // ---- 2 · ASK -------------------------------------------------------
      '<div class="card" id="pg-asksec" style="display:none">' +
        '<h2>2 &middot; Ask <span class="sub">POST /v1/playground/ask &mdash; the model calls recall/get as tools; the reads stay scope-gated</span></h2>' +
        '<div id="pg-asking-as" class="note" style="margin-top:4px"></div>' +
        '<div class="row" style="margin-top:8px">' +
          '<div><label for="pg-q">your question</label>' +
            '<input type="text" id="pg-q" maxlength="' + Q_MAX + '" placeholder="what&rsquo;s the renewal risk at Acme?" autocomplete="off"></div>' +
          '<div class="tight"><button class="primary" id="pg-ask">Ask</button></div>' +
        '</div>' +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight" style="min-width:260px"><label for="pg-model">model</label>' +
            '<select class="field" id="pg-model"></select></div>' +
          '<div class="tight" style="min-width:120px"><label for="pg-repeat" title="sequential re-asks of the identical request, fresh conversation each — never in parallel, never a load test">repeat</label>' +
            '<select class="field" id="pg-repeat"><option value="1" selected>1</option><option value="3">3</option><option value="5">5</option></select></div>' +
        '</div>' +
        '<div class="asof" id="pg-ask-note" style="margin-top:6px"></div>' +
        '<div class="err" id="pg-ask-err"></div>' +
        '<div id="pg-wait"></div>' +
      '</div>' +

      // ---- 3 · WHAT CAME BACK + 4 · THIS SESSION (render only on a run) --
      '<div id="pg-run"></div>' +
      '<div id="pg-session"></div>'
    );
  }

  /* --------------------------------------------------------------- wiring */
  function wire() {
    el("pg-mint").onclick = function () { V.openMint(); };
    el("pg-r-working").onchange = function () { if (this.checked) setMode("working"); };
    el("pg-r-paste").onchange = function () { if (this.checked) setMode("paste"); };
    // decode-as-you-type, 250 ms debounce (the panel_scope pattern)
    var deb = null;
    el("pg-paste").addEventListener("input", function () {
      clearTimeout(deb);
      // setMode("paste") re-reads the field and adopts it — one decode path
      deb = setTimeout(function () { setMode("paste"); }, 250);
    });
    el("pg-ask").onclick = ask;
    el("pg-q").addEventListener("keydown", function (e) { if (e.key === "Enter") ask(); });

    // a mint completed while this panel exists lands as the active scope (§3.3)
    V.onMint(function (m) {
      if (!S.mounted || !m || !m.handle) return;
      el("pg-paste").value = m.handle;
      setMode("paste");
      adoptPaste(m.handle);
    });
    // the working-handle radio appears/disappears live (§3.1)
    V.onWorkingHandle(function (h) {
      if (!S.mounted) return;
      if (S.mode === "working") {
        if (h) adopt(h, "working");
        else { S.active = null; setMode("paste"); }
      }
      renderScopeModes();
    });
    V.onTenant(function () { if (S.mounted) renderNoTenant(); });

    // expiry countdowns tick; an expiry mid-session flips the strip (state E)
    setInterval(function () {
      if (!S.mounted || S.inflight) return;
      if (S.active || V.workingHandle()) {
        renderScopeModes();
        renderActiveClaims();
      }
    }, 10000);

    // delegated CTAs (denial hero + teach states render after the fact)
    document.addEventListener("click", function (ev) {
      var t = ev.target;
      if (!t || !t.classList) return;
      if (t.classList.contains("pg-prove")) {
        // proves the LATEST RUN's boundary — the handle that produced it
        var h = (S.latest && S.latest.handle) || (S.active && S.active.handle);
        if (h) V.show("scope", { handle: h });
      }
      if (t.classList.contains("pg-goto-scope")) {
        // inspects the ACTIVE key (or just opens the inspector)
        V.show("scope", S.active ? { handle: S.active.handle } : undefined);
      }
      if (t.classList.contains("pg-diffkey")) {
        var r = el("pg-recent");
        if (r) { r.scrollIntoView({ behavior: "smooth", block: "center" }); }
        var pi = el("pg-paste");
        if (pi && !recentGet().length) pi.focus();
      }
      if (t.classList.contains("pg-goto-quar")) V.show("quarantine");
      if (t.classList.contains("pg-mint2")) V.openMint();
      if (t.classList.contains("pg-retry-status")) fetchStatus();
    });
  }

  /* ----------------------------------------------------- no-tenant teach */
  function renderNoTenant() {
    var host = el("pg-notenant");
    if (!host) return;
    if (V.tenant()) { host.innerHTML = ""; return; }
    host.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">No space selected yet</div>' +
        '<div class="et-body">Pick a space in the bar above &mdash; this screen loads itself the moment one ' +
          'is set. Pasting a scope handle below also works: a handle names its own space.</div>' +
      '</div>';
  }

  /* ===================================================================
     SCOPE ADOPTION (§3) — adopt, never mint. The playground owns no mint
     form and no principal picker; Verity.openMint() is the one ceremony.
     =================================================================== */
  function setMode(mode) {
    S.mode = mode;
    var rw = el("pg-r-working"), rp = el("pg-r-paste");
    if (rw) rw.checked = mode === "working";
    if (rp) rp.checked = mode === "paste";
    if (mode === "working") {
      var wh = V.workingHandle();
      if (wh) adopt(wh, "working");
    } else {
      var raw = (el("pg-paste").value || "").trim();
      if (raw) adoptPaste(raw);
      else { S.active = null; renderActiveClaims(); }
    }
  }

  function adoptPaste(raw) {
    V.clearErr("pg-paste-err");
    if (!raw) { if (S.mode === "paste") { S.active = null; renderActiveClaims(); } return; }
    try {
      adopt(raw, "paste");
    } catch (e) {
      // the decoder's own human message, inline (§3.2)
      S.active = null;
      renderActiveClaims();
      V.err("pg-paste-err", e);
    }
  }

  // Throws on a malformed handle (callers surface the decoder's message).
  function adopt(handle, source) {
    var claims = V.decodeHandle(handle); // pure client-side; may throw
    S.active = { handle: handle, claims: claims, source: source };
    V.clearErr("pg-paste-err");
    if (claims.tenant_id) V.setTenant(claims.tenant_id); // an id, not a secret
    ensureDirectory(claims.tenant_id).then(function () {
      renderScopeModes();
      renderActiveClaims();
      renderRecent();
    });
    renderActiveClaims();
  }

  /* -------------------------------------------- radio rows + claims strip */
  function renderScopeModes() {
    var box = el("pg-mode-working");
    if (!box) return;
    var wh = V.workingHandle();
    if (!wh) {
      box.style.display = "none";
      if (S.mode === "working") setMode("paste");
      return;
    }
    box.style.display = "";
    var claimsHtml;
    try {
      var p = V.decodeHandle(wh);
      if (isExpired(p)) {
        // an expired working handle never silently asks — paste stands (§3.1)
        claimsHtml = V.stateChip("fail", "expired") +
          ' <span class="asof">the server will refuse it &mdash; re-mint from the top bar</span>';
        if (S.mode === "working") setMode("paste");
      } else {
        var left = expiresLeft(p);
        claimsHtml =
          V.stateChip(seesNothing(p) ? "attn" : "ok",
            seesNothing(p) ? "live — but it sees nothing"
              : "live" + (left != null ? " — expires in " + V.fmtAge(left) : "")) +
          '<div style="margin-top:4px">reads as ' + principalChips(p) + "</div>";
      }
    } catch (e) {
      claimsHtml = V.stateChip("fail", "undecodable") +
        ' <span class="asof">' + esc(e.message) + "</span>";
    }
    el("pg-working-claims").innerHTML = claimsHtml;
  }

  function principalChips(p) {
    if (seesNothing(p)) {
      return V.stateChip("attn", "sees nothing — no keys on this handle") +
        ' <span class="asof">Verity fails closed: an empty &ldquo;who&rdquo; refuses; asking anyway IS the demo</span>';
    }
    return p.principals.map(pChip).join(" ") + dirHint();
  }
  function dirHint() {
    if (S.dir.map || !S.dir.error) return "";
    return ' <span class="asof">names unavailable — the token→name directory needs the admin token (session bar)</span>';
  }

  function entityLimitHtml(p) {
    return (p.entity_scope && p.entity_scope.length)
      ? V.entityBadges(p.entity_scope)
      : '<span style="color:var(--dim)">any entity — no entity limit</span>';
  }

  // The active scope's full claims strip (below the radios).
  function renderActiveClaims() {
    var host = el("pg-claims");
    if (!host) return;
    if (!S.active) { host.innerHTML = ""; renderAskingAs(); updateAskEnabled(); return; }
    var p = S.active.claims;
    var expired = isExpired(p);
    var head;
    if (expired) {
      head = V.stateChip("fail", "expired") +
        '<div class="note" style="margin-top:6px">This handle expired &mdash; the server will refuse it, and refuses it ' +
        "<em>before</em> spending any tokens. Handles expire on purpose; re-mint from the top bar &mdash; renewal never " +
        "widens anything. Runs already in the session table keep their numbers. " +
        '<button class="pg-mint2" style="padding:1px 7px;font-size:11px">Mint a fresh handle</button></div>';
    } else if (seesNothing(p)) {
      head = V.stateChip("attn", "sees nothing — no keys on this handle") +
        ' <span class="asof">Ask stays enabled &mdash; the denial is the demo</span>';
    } else {
      var left = expiresLeft(p);
      head = V.stateChip("ok", "live" + (left != null ? " — expires in " + V.fmtAge(left) : ""));
    }
    host.innerHTML =
      '<div>' + head + "</div>" +
      '<dl class="kv" style="margin-top:8px">' +
        "<dt>reads as</dt><dd>" + principalChips(p) + "</dd>" +
        "<dt>limited to</dt><dd>" + entityLimitHtml(p) + "</dd>" +
        "<dt>ceiling</dt><dd>" + V.confBadge(p.max_confidentiality) +
          ' <span class="asof">nothing classified above this can come back &mdash; no question can raise it</span></dd>' +
      "</dl>" +
      '<div style="margin-top:6px"><button class="pg-goto-scope" style="padding:1px 7px;font-size:11px">inspect &rarr; Scope Inspector</button></div>';
    renderAskingAs();
    updateAskEnabled();
  }

  // One line above the Ask box — never the raw vs_… string (§3).
  function renderAskingAs() {
    var host = el("pg-asking-as");
    if (!host) return;
    if (!S.active) {
      host.innerHTML = "no key picked yet — pick one in section 1; there is no default";
      return;
    }
    var p = S.active.claims;
    var left = expiresLeft(p);
    host.innerHTML = "asking as " + principalChips(p) +
      " · ceiling " + V.confBadge(p.max_confidentiality) +
      " · " + entityLimitHtml(p) +
      (left != null ? " · expires in " + V.fmtAge(left) : "") +
      (isExpired(p) ? " · " + V.stateChip("fail", "expired") : "");
  }

  /* ------------------------------------------------------- recent chips */
  function renderRecent() {
    var host = el("pg-recent");
    if (!host) return;
    var list = recentGet();
    if (!list.length) { host.innerHTML = ""; return; }
    var chips = list.map(function (c, i) {
      var isActive = S.active && S.active.handle === c.handle;
      return '<span class="epk-chip"' + (isActive ? ' style="outline:1px solid var(--accent)"' : "") + ">" +
        '<a class="pg-recent-chip" data-i="' + i + '" style="cursor:pointer">' + esc(c.label) + "</a>" +
        '<button type="button" class="epk-x pg-recent-x" data-i="' + i + '" aria-label="forget ' + esc(c.label) + '">&times;</button>' +
      "</span>";
    }).join(" ");
    host.innerHTML =
      '<div>recently asked as: ' + chips + "</div>" +
      '<div class="asof" style="margin-top:3px">this tab only &mdash; click to re-ask the same question as a ' +
        "different key. That two-click swap IS the boundary demo.</div>";
    host.querySelectorAll(".pg-recent-chip").forEach(function (a) {
      a.onclick = function () {
        var c = recentGet()[parseInt(a.getAttribute("data-i"), 10)];
        if (!c) return;
        el("pg-paste").value = c.handle;
        setMode("paste");
        adoptPaste(c.handle);
        var q = el("pg-q");
        if (q) q.focus();
      };
    });
    host.querySelectorAll(".pg-recent-x").forEach(function (b) {
      b.onclick = function () {
        var list2 = recentGet();
        list2.splice(parseInt(b.getAttribute("data-i"), 10), 1);
        recentSave(list2);
        renderRecent();
      };
    });
  }

  /* ===================================================================
     STATUS GATE — GET /v1/playground/status. Absence of a key is a
     STATE, not an error (§6/§7B); the model picker never invents ids.
     =================================================================== */
  function fetchStatus() {
    var host = el("pg-nokey");
    if (host && !S.status) {
      host.innerHTML = '<div class="note">' + V.stateChip("wait", "checking the server’s model key…") + "</div>";
    }
    V.api("/v1/playground/status")
      .then(function (st) { S.status = st; S.statusErr = null; renderGate(); })
      .catch(function (e) { S.status = null; S.statusErr = String((e && e.message) || e); renderGate(); });
  }

  function renderGate() {
    var host = el("pg-nokey");
    var asksec = el("pg-asksec");
    if (!host || !asksec) return;
    if (S.statusErr) {
      host.innerHTML =
        '<div class="card">' + V.stateChip("fail", "couldn’t check the playground endpoint") +
        '<div class="note" style="margin-top:6px">' + esc(S.statusErr) + "</div>" +
        '<div style="margin-top:6px"><button class="pg-retry-status">Retry</button></div></div>';
      asksec.style.display = "none";
      return;
    }
    if (!S.status) { asksec.style.display = "none"; return; }
    if (S.status.ready === false) {
      // state B — teaching empty state replaces sections 2–4; section 1 works
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">The playground needs a model key on the server</div>' +
          '<div class="et-body">This screen drives a real agent, so the server needs an Anthropic API key. Set ' +
            '<b><span class="ref">VERITY_ANTHROPIC_KEY_FILE</span></b> to the path of a file containing the key ' +
            '(for example <span class="ref">~/.verity-anthropic-key</span>, permissions <span class="ref">0600</span>) ' +
            "and restart the server. The key stays server-side &mdash; it never reaches this browser, the logs, or the " +
            "audit trail. Everything else here works now; <b>recall itself is LLM-free</b> &mdash; the key gates only " +
            "the model on top. Meanwhile: probe this scope directly in <b>Scope Inspector &rarr;</b>." +
            '<div class="ref" style="margin-top:8px">' + esc(S.status.reason || "") + "</div></div>" +
          '<div class="et-actions">' +
            '<button class="pg-retry-status">Retry</button>' +
            '<button class="pg-goto-scope">Open Scope Inspector</button>' +
          "</div>" +
        "</div>";
      asksec.style.display = "none";
      el("pg-run").innerHTML = "";
      el("pg-session").innerHTML = "";
      return;
    }
    // ready — populate the picker from the server's allowlist, nothing else
    host.innerHTML = "";
    asksec.style.display = "";
    var sel = el("pg-model");
    var models = S.status.models || [];
    if (models.length) {
      sel.innerHTML = models.map(function (m) {
        return '<option value="' + esc(m.id) + '"' + (m["default"] ? " selected" : "") + ">" +
          esc(m.label || m.id) + "</option>";
      }).join("");
      sel.disabled = false;
    } else {
      sel.innerHTML = '<option value="">the server offered no models</option>';
      sel.disabled = true;
    }
    var mt = S.status.max_turns != null ? S.status.max_turns : 8;
    el("pg-ask-note").textContent =
      "up to " + mt + " tool turns · each ask starts fresh — nothing is remembered between " +
      "questions · repeats run one after another, never in parallel";
    updateAskEnabled();
  }

  function updateAskEnabled() {
    var btn = el("pg-ask");
    if (!btn) return;
    var ready = S.status && S.status.ready !== false;
    var expired = S.active && isExpired(S.active.claims);
    // a sees-nothing handle stays askable — the denial is the demo (§3.2)
    btn.disabled = !!(S.inflight || !ready || !S.active || expired);
  }

  /* ------------------------------------------------- no-handle teach (D) */
  function renderNoHandleTeach() {
    el("pg-run").innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick who is asking first</div>' +
        '<div class="et-body">The agent reads with a scope handle &mdash; the signed key an agent reads with ' +
          "&mdash; and there is no default. An unscoped ask does not exist; Verity fails closed. Paste one above " +
          '(<span class="ref">verity-cli dev</span> prints one at bootstrap), or mint one.</div>' +
        '<div class="et-actions"><button class="primary pg-mint2">Mint a handle &rarr;</button></div>' +
      "</div>";
  }

  /* ===================================================================
     THE ASK — POST /v1/playground/ask, raw fetch (see file header for
     why), ONE performance.now() span per request, repeats sequential.
     =================================================================== */
  async function postAsk(body) {
    var t0 = performance.now();
    var res;
    try {
      res = await fetch("/v1/playground/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch (e) {
      throw new Error("/v1/playground/ask — network error: " + e.message);
    }
    var text = await res.text();
    var clientMs = performance.now() - t0; // the one browser-side number
    var json = null;
    try { json = text ? JSON.parse(text) : null; } catch (e) { /* non-JSON body */ }
    return { ok: res.ok, status: res.status, json: json, raw: text, client_ms: clientMs };
  }

  async function ask() {
    V.clearErr("pg-ask-err");
    if (S.inflight) return;
    if (!S.active) { renderNoHandleTeach(); return; }
    var p = S.active.claims;
    if (isExpired(p)) { renderActiveClaims(); updateAskEnabled(); return; }
    var q = (el("pg-q").value || "").trim();
    if (!q) return V.err("pg-ask-err", "type a question first — plain language works");
    if (q.length > Q_MAX) return V.err("pg-ask-err", "questions are capped at " + Q_MAX + " characters");
    var model = el("pg-model").value;
    if (!model) return V.err("pg-ask-err", "the server offered no models to pick from");
    var repeat = parseInt(el("pg-repeat").value, 10) || 1;

    recentPush(labelFor(p), S.active.handle);
    S.inflight = true;
    updateAskEnabled();
    var body = { scope_handle: S.active.handle, question: q, model: model };
    try {
      for (var i = 1; i <= repeat; i++) {
        startTicker(i, repeat);
        var r;
        try {
          r = await postAsk(body);
        } catch (netErr) {
          stopTicker();
          renderAskFailure(0, null, String(netErr.message || netErr));
          break;
        }
        stopTicker();
        if (!r.ok) {
          renderAskFailure(r.status, r.json, r.raw);
          if (r.status === 503) { S.status = null; fetchStatus(); } // key vanished → re-derive state B
          break; // a failed repeat stops the sequence — no spend on a broken run
        }
        recordRun(r.json, r.client_ms, q, model);
        S.latest = {
          resp: r.json, client_ms: r.client_ms, question: q, model: model,
          handle: S.active.handle, at: Date.now(),
        };
        renderLatest();
        renderSession();
      }
    } finally {
      stopTicker();
      S.inflight = false;
      updateAskEnabled();
      renderActiveClaims(); // expiry may have flipped mid-ask
    }
  }

  /* -------------------------------------------------- in-flight (state I) */
  function startTicker(i, total) {
    stopTicker();
    var t0 = performance.now();
    var host = el("pg-wait");
    function paint() {
      if (!host) return;
      var secs = ((performance.now() - t0) / 1000).toFixed(1);
      host.innerHTML =
        '<div class="note" style="margin-top:8px">' +
        V.stateChip("wait", "asking — model turns can take seconds") +
        (total > 1 ? " run " + i + " of " + total + " (sequential)" : "") +
        ' <span class="asof">elapsed in this browser: ' + secs +
        " s — the only number on this screen not measured by the server, and it says so</span></div>";
    }
    paint();
    S.tickTimer = setInterval(paint, 100);
  }
  function stopTicker() {
    if (S.tickTimer) { clearInterval(S.tickTimer); S.tickTimer = null; }
    var host = el("pg-wait");
    if (host) host.innerHTML = "";
  }

  /* --------------------------------------------------- failures (§6 / §7H) */
  function renderAskFailure(status, json, rawText) {
    var detail = (json && json.detail) || String(rawText || "").slice(0, 500) || ("HTTP " + status);
    var chip, lede;
    if (status === 401) {
      chip = V.stateChip("fail", "this key was refused — before any tokens were spent");
      lede = "The server refused the scope handle and never called the model — fail closed, no spend on a dead key.";
    } else if (status === 422) {
      chip = V.stateChip("fail", "the server refused the request");
      lede = "";
    } else if (status === 503) {
      chip = V.stateChip("fail", "no model key on this server");
      lede = "";
    } else if (status === 502 || status === 504) {
      chip = V.stateChip("fail", "the model call failed — memory was fine");
      lede = "The memory reads before the failure are shown below with their measured timings, labeled " +
        "<em>partial</em>. Verity’s read path was not involved; your handle is still good — ask again.";
    } else {
      chip = V.stateChip("fail", "the ask failed");
      lede = "";
    }
    var partial = "";
    if (json && json.partial && (json.partial.turns || json.partial.totals)) {
      partial =
        '<h3 style="margin-top:12px;font-size:12px">Measured before the failure <span class="refreshed">partial — measured work is never thrown away</span></h3>' +
        (json.partial.totals ? timingStrip(json.partial.totals, null, true) : "") +
        (json.partial.turns && json.partial.turns.length
          ? traceHtml({ turns: json.partial.turns, evidence: [], system_prompt: null })
          : "");
    }
    el("pg-run").innerHTML =
      '<div class="card">' +
        '<h2>3 &middot; What came back <span class="sub">latest attempt</span></h2>' +
        "<div>" + chip + "</div>" +
        (lede ? '<div class="note" style="margin-top:6px">' + lede + "</div>" : "") +
        '<div class="note" style="margin-top:6px">' + esc(detail) + "</div>" +
        partial +
      "</div>";
  }

  /* ===================================================================
     RUN RECORDS + SESSION TABLE (§8) — panel JS memory only; dies with
     this tab and says so. Comparable = same (claims payload, question,
     model); percentiles only at n ≥ 5 (a p95 of two samples is a small lie).
     =================================================================== */
  function bucketKey(handle, question, model) {
    // the handle's signed claims payload segment — identical claims, one bucket
    var payload = String(handle).slice(3).split(".")[0];
    return payload + " " + question + " " + model;
  }

  function recordRun(resp, clientMs, question, model) {
    var t = resp.totals || {};
    var perCall = [], perRead = [];
    (resp.turns || []).forEach(function (turn) {
      if (turn.llm_ms != null) perCall.push(turn.llm_ms);
      (turn.tool_calls || []).forEach(function (tc) {
        if (tc.storage_ms != null) perRead.push(tc.storage_ms);
      });
    });
    S.runs.push({
      bucket: bucketKey(S.active.handle, question, model),
      model: model,
      turns: (resp.turns || []).length,
      reads: t.storage_calls != null ? t.storage_calls : perRead.length,
      hits: t.visible_hits_total,
      wall: t.wall_ms,
      tin: t.input_tokens,
      tout: t.output_tokens,
      perCall: perCall,
      perRead: perRead,
      at: Date.now(),
      visibility: resp.visibility,
    });
  }

  function renderSession() {
    var host = el("pg-session");
    if (!host || !S.runs.length) return;
    var latest = S.runs[S.runs.length - 1];
    var comparable = S.runs.filter(function (r) { return r.bucket === latest.bucket; });
    var n = comparable.length;

    var pctHtml;
    if (n >= 5) {
      var reads = [], calls = [], walls = [];
      comparable.forEach(function (r) {
        reads = reads.concat(r.perRead);
        calls = calls.concat(r.perCall);
        if (r.wall != null) walls.push(r.wall);
      });
      reads.sort(function (a, b) { return a - b; });
      calls.sort(function (a, b) { return a - b; });
      walls.sort(function (a, b) { return a - b; });
      pctHtml =
        '<div class="note" style="margin-top:6px">comparable runs (same key · question · model) — <b>n = ' + n + "</b>" +
        '<div class="tablewrap" style="margin-top:6px"><table><thead><tr><th></th><th>p50</th><th>p95</th><th>of</th></tr></thead><tbody>' +
        (reads.length ? "<tr><td>memory reads (per scoped read)</td><td>" + ms1(pctl(reads, 0.5)) + "</td><td>" + ms1(pctl(reads, 0.95)) + "</td><td>" + reads.length + " reads</td></tr>" : "") +
        (calls.length ? "<tr><td>model call (per Anthropic round-trip, incl. network)</td><td>" + ms1(pctl(calls, 0.5)) + "</td><td>" + ms1(pctl(calls, 0.95)) + "</td><td>" + calls.length + " calls</td></tr>" : "") +
        (walls.length ? "<tr><td>whole answer (server total)</td><td>" + ms1(pctl(walls, 0.5)) + "</td><td>" + ms1(pctl(walls, 0.95)) + "</td><td>" + walls.length + " runs</td></tr>" : "") +
        "</tbody></table></div></div>";
    } else {
      pctHtml =
        '<div class="asof" style="margin-top:6px">' + n + " comparable run" + (n === 1 ? "" : "s") +
        " (same key · question · model) — percentiles render at n ≥ 5; a p95 of " +
        "two samples is a small lie. Raw numbers below.</div>";
    }

    var rows = S.runs.slice().reverse().map(function (r, idx) {
      var num = S.runs.length - idx;
      return "<tr" + (r.bucket === latest.bucket ? "" : ' style="opacity:.65"') + ">" +
        "<td>" + num + "</td>" +
        "<td>" + esc(r.model) + "</td>" +
        "<td>" + esc(r.turns) + "</td>" +
        "<td>" + esc(r.reads != null ? r.reads : "—") + "</td>" +
        "<td>" + esc(r.hits != null ? r.hits : "—") + "</td>" +
        "<td>" + ms1(r.wall) + "</td>" +
        "<td>" + intFmt(r.tin) + " / " + intFmt(r.tout) + "</td>" +
        "<td>" + esc(V.timeAgo(r.at)) + "</td>" +
      "</tr>";
    }).join("");

    host.innerHTML =
      '<div class="card">' +
        '<h2>4 &middot; This session <span class="sub">panel memory only — dies with this tab</span></h2>' +
        pctHtml +
        '<div class="tablewrap" style="margin-top:8px"><table><thead><tr>' +
          "<th>#</th><th>model</th><th>turns</th><th>reads</th><th>hits</th><th>server ms</th><th>in/out tok</th><th>when</th>" +
        "</tr></thead><tbody>" + rows + "</tbody></table></div>" +
        '<div class="asof" style="margin-top:6px">session-local · this hardware · model time includes ' +
          "Anthropic network · repeats sequential · dies with this tab · NOT the milestone-A benchmark</div>" +
      "</div>";
  }

  /* ===================================================================
     3 · WHAT CAME BACK — visibility-stamped rendering (§5/§7). The UI
     trusts the server's `visibility` field, never the model's prose.
     =================================================================== */
  function renderLatest() {
    var host = el("pg-run");
    if (!host || !S.latest) return;
    var run = S.latest.resp;
    var t = run.totals || {};

    var capLine = "";
    if (run.stop === "turn_cap") {
      capLine = '<div class="note" style="margin-top:6px">' +
        V.stateChip("attn", "turn cap") + " Stopped at the <b>" + (run.turns || []).length +
        "-turn cap</b>. The answer may be incomplete — the trace shows everything it did get to, measured.</div>";
    }

    var body;
    if (run.visibility === "nothing_visible") {
      body = denialHero(run);
    } else if (run.visibility === "no_reads") {
      body =
        "<div>" + V.stateChip("attn", "answered without reading") + "</div>" +
        '<div class="note" style="margin-top:6px">The model never called a tool, so nothing below is grounded ' +
          "in this scope’s memory. Treat it as the model’s own invention, or ask again.</div>" +
        answerHtml(run.answer, true);
    } else {
      var nh = t.visible_hits_total != null ? t.visible_hits_total : 0;
      body =
        "<div>" + V.stateChip("ok", "answered from " + nh +
          (nh === 1 ? " memory" : " memories") + " visible to this key") + "</div>" +
        answerHtml(run.answer, false);
    }

    host.innerHTML =
      '<div class="card">' +
        '<h2>3 &middot; What came back <span class="sub">latest run · every number measured this run — nothing estimated</span></h2>' +
        capLine +
        body +
        timingStrip(t, S.latest.client_ms, false) +
        '<h3 style="margin-top:14px;font-size:12px">What the agent did</h3>' +
        traceHtml(run) +
        evidenceBlock(run) +
      "</div>";
  }

  function answerHtml(answer, dim) {
    if (!answer) {
      return '<div class="note" style="margin-top:8px"><span style="color:var(--dim)">the model produced no ' +
        "final text — shown as absent, never invented</span></div>";
    }
    return '<div class="content" style="margin-top:8px' + (dim ? ";color:var(--dim)" : "") + '">' +
      esc(answer) + "</div>";
  }

  // §7C — THE DENIAL, the hero. Counts are the measured totals, never canned.
  // Forensic CTAs only; no widen affordance exists, not even disabled.
  function denialHero(run) {
    var t = run.totals || {};
    var searches = t.storage_calls != null ? t.storage_calls : 0;
    var modelWords = run.answer
      ? '<div class="note" style="margin-top:8px"><em>the model’s own words:</em> ' +
        '<span style="color:var(--dim)">&ldquo;' + esc(run.answer) + "&rdquo;</span></div>"
      : "";
    return (
      "<div>" + V.stateChip("attn", "nothing visible to this key") + "</div>" +
      '<div class="empty-teach sp-b" style="margin-top:8px">' +
        '<div class="et-title">Nothing visible to this key — and that’s the demo.</div>' +
        '<div class="et-body">The agent went to memory <b>' + plural(searches, "time") +
          "</b> through this handle and got <b>0 results</b>. It answered from nothing because it <em>has</em> " +
          "nothing: Verity’s read path filters by permission <b>before</b> ranking, and it fails closed — " +
          "no key, no memory, no exceptions, and no way for a clever question to widen a scope. The data may " +
          "well exist; these keys cannot see it." +
          modelWords +
          '<div class="asof" style="margin-top:8px">measured all the same: model ' + V.fmtMs(t.llm_ms) +
            " · memory reads " + ms1(t.storage_ms) + " · " + plural((run.turns || []).length, "turn") +
            " · " + intFmt(t.input_tokens) + " tok in / " + intFmt(t.output_tokens) + " out</div>" +
          '<div style="margin-top:8px">If a write you expected is invisible to <em>every</em> key, it may never ' +
            "have been indexed — check <b>Quarantine</b>.</div>" +
        "</div>" +
        '<div class="et-actions">' +
          '<button class="primary pg-prove">Prove why, item by item &rarr; Scope Inspector</button>' +
          '<button class="pg-diffkey">Ask as a different key</button>' +
          '<button class="pg-goto-quar">Check Quarantine &rsaquo;</button>' +
        "</div>" +
      "</div>"
    );
  }

  /* ---------------------------------------------- the labeled timing strip */
  function timingStrip(t, clientMs, partial) {
    if (!t) return "";
    var parts = [];
    if (t.wall_ms != null) parts.push("<b>server total</b> " + ms1(t.wall_ms));
    if (t.llm_ms != null) {
      parts.push("<b>model</b> " + ms1(t.llm_ms) +
        (t.llm_calls != null ? " across " + plural(t.llm_calls, "call") : "") +
        " (incl. network to Anthropic)");
    }
    if (t.storage_ms != null) {
      parts.push("<b>memory reads</b> " + ms1(t.storage_ms) +
        (t.storage_calls != null ? " across " + plural(t.storage_calls, "scoped read") : ""));
    }
    if (t.input_tokens != null || t.output_tokens != null) {
      parts.push("<b>" + intFmt(t.input_tokens) + " tokens in / " + intFmt(t.output_tokens) +
        " out</b> (from the API’s usage block)");
    }
    if (t.cache_read_input_tokens > 0) {
      parts.push("<b>" + intFmt(t.cache_read_input_tokens) +
        " cache-read tokens</b> (provider-side prompt caching — disclosed, not pocketed as a speedup)");
    }
    if (clientMs != null) parts.push("<b>round-trip in this browser</b> " + ms1(clientMs));
    if (!parts.length) return "";

    // the split attribution — computed from the same measured spans, never asserted
    var split = "";
    if (t.llm_ms != null && t.storage_ms != null && (t.llm_ms + t.storage_ms) > 0) {
      var mp = (t.llm_ms / (t.llm_ms + t.storage_ms)) * 100;
      split = '<div class="asof" style="margin-top:3px">model ' + mp.toFixed(1) +
        "% of the time · permission-filtered reads " + (100 - mp).toFixed(1) +
        "% — computed from the measured spans above</div>";
    }
    return (
      '<div class="note" style="margin-top:10px">' +
        (partial ? '<span class="badge b-kind">partial</span> ' : "") +
        parts.join(" · ") +
        split +
        '<div class="asof" style="margin-top:3px">every number measured this run — nothing estimated · ' +
          "session-local, this hardware · NOT the milestone-A benchmark</div>" +
      "</div>"
    );
  }

  /* --------------------------------------------------- the trace (§8) */
  function traceHtml(run) {
    var evByN = {};
    (run.evidence || []).forEach(function (e) { evByN[e.n] = e; });
    var html = "";
    // first fold: the disclosed system prompt, verbatim
    if (run.system_prompt) {
      html += '<details style="margin-top:6px"><summary style="cursor:pointer;color:var(--dim);font-size:var(--fs-sm)">' +
        "the agent’s instructions (the fixed system prompt, verbatim)</summary>" +
        '<div class="dc-meta" style="margin-top:6px;white-space:pre-wrap">' + esc(run.system_prompt) + "</div></details>";
    }
    var step = 0;
    (run.turns || []).forEach(function (turn) {
      step++;
      html += modelStep(turn, step);
      (turn.tool_calls || []).forEach(function (tc) {
        step++;
        html += toolStep(tc, step, evByN);
      });
    });
    html +=
      '<div class="asof" style="margin-top:6px">storage ms is the same in-process read the public ' +
        "POST /v1/recall performs, measured without HTTP framing.</div>" +
      '<div class="note" style="margin-top:6px">the model is instructed to answer only from these results; ' +
        "this trace is how you check it kept its word. " +
        '<button class="pg-prove" style="padding:1px 7px;font-size:11px">prove this boundary &rarr; Scope Inspector</button></div>';
    return html;
  }

  function toolVerbPhrase(calls) {
    var kinds = {};
    calls.forEach(function (c) { kinds[c.tool] = true; });
    if (kinds.search_memory && kinds.get_fact) return "use its memory tools";
    if (kinds.get_fact) return "pin an exact fact";
    return "search";
  }

  function modelStep(turn, step) {
    var u = turn.usage || {};
    var hasTools = turn.tool_calls && turn.tool_calls.length;
    var what;
    if (hasTools) {
      what = (turn.n === 1 ? "model read the question, decided to "
        : "model reviewed what came back, decided to ") + toolVerbPhrase(turn.tool_calls);
    } else if (turn.stop_reason === "end_turn") {
      what = "model wrote the answer";
    } else {
      what = "model responded (stop: " + esc(turn.stop_reason) + ")";
    }
    var cache = (u.cache_read_input_tokens > 0)
      ? " " + V.badge("cache read: " + intFmt(u.cache_read_input_tokens) + " tok", "b-kind")
      : "";
    var fold = turn.text
      ? '<details style="margin-left:22px"><summary style="cursor:pointer;color:var(--dim);font-size:var(--fs-sm)">the turn’s text · stop_reason ' +
        esc(turn.stop_reason) + '</summary><div class="dc-meta" style="margin-top:4px;white-space:pre-wrap">' +
        esc(turn.text) + "</div></details>"
      : "";
    return (
      '<div style="margin-top:6px"><span class="ref">' + step + "</span> " + esc(what) +
        (turn.llm_ms != null ? " · " + ms1(turn.llm_ms) : "") +
        (u.input_tokens != null ? " · " + intFmt(u.input_tokens) + " in / " + intFmt(u.output_tokens) + " out tok" : "") +
        cache +
      "</div>" + fold
    );
  }

  function toolStep(tc, step, evByN) {
    var head, result, fold = "";
    if (tc.tool === "search_memory") {
      var input = tc.input || {};
      head = "searched memory for “" + esc(input.text || "") + "”" +
        (input.k != null ? " (k=" + esc(input.k) + ")" : "");
      if (tc.hits > 0) {
        result = "→ " + plural(tc.hits, "result") + " came back through this key" +
          (tc.storage_ms != null ? " · " + ms1(tc.storage_ms) + " storage" : "");
        var cards = (tc.evidence_ns || []).map(function (n) {
          return evByN[n] ? evCard(evByN[n]) : "";
        }).join("");
        if (cards) {
          fold = '<details style="margin-left:22px"><summary style="cursor:pointer;color:var(--accent);font-size:var(--fs-sm)">show the ' +
            tc.hits + " result" + (tc.hits === 1 ? "" : "s") + "</summary>" + cards + "</details>";
        }
      } else {
        // a denied run's trace is a column of amber zeros — the visual story
        result = "→ " + V.stateChip("attn", "0 results — nothing visible to this key for that search") +
          (tc.storage_ms != null ? " · " + ms1(tc.storage_ms) + " storage" : "");
      }
    } else if (tc.tool === "get_fact") {
      var inp = tc.input || {};
      head = "read one fact: " + esc((inp.source || "?") + " / " + (inp.entity_id || "?") + " / " + (inp.field || "?")) +
        (inp.as_of ? " as of " + esc(inp.as_of) : "");
      if (tc.fact) {
        result = "→ found" + (tc.storage_ms != null ? " · " + ms1(tc.storage_ms) + " storage" : "");
        fold = '<details style="margin-left:22px"><summary style="cursor:pointer;color:var(--accent);font-size:var(--fs-sm)">show the fact</summary>' +
          '<div class="dc-meta" style="margin-top:4px;white-space:pre-wrap">' + esc(JSON.stringify(tc.fact, null, 2)) + "</div></details>";
      } else {
        // a missing key is a true answer, not an error (§4)
        result = "→ " + esc(tc.error || "no value for that key/time") +
          " — an honest miss, not an error" +
          (tc.storage_ms != null ? " · " + ms1(tc.storage_ms) + " storage" : "");
      }
    } else {
      head = "model asked for a tool that doesn’t exist (“" + esc(tc.tool) + "”)";
      result = "→ " + V.stateChip("fail", "refused — never executed");
    }
    return '<div style="margin-top:4px;margin-left:22px"><span class="ref">' + step + "</span> " +
      head + " " + result + "</div>" + fold;
  }

  /* --------------------------------------------- evidence (wire truth, §8) */
  function evCard(e) {
    return (
      '<div class="hit">' +
        '<div style="display:flex;gap:8px;align-items:baseline">' +
          '<span class="badge b-kind" title="evidence number — the answer cites these in [brackets]">[' + Number(e.n) + "]</span>" +
          '<div class="content" style="margin-top:0;flex:1">' + esc(e.content) + "</div>" +
        "</div>" +
        '<div style="margin-top:6px">' +
          V.kindBadge(e.kind || "content") +
          V.provenanceBadge(e.acl_provenance) +
          V.trustBadge(e.trust_tier) +
          V.entityBadges(e.entity_tags) +
          V.sampleBadge(e.entity_tags) +
        "</div>" +
        '<div class="dc-meta">' +
          (e.score != null ? "score " + Number(e.score).toFixed(3) + " (raw rank score, not a probability)" : "") +
          " · doc " + esc(e.document_id) + " · seq " + esc(e.seq) +
          (e.valid_from ? " · valid_from " + esc(V.fmtTime(e.valid_from)) : "") +
          (e.provenance != null ? " · citation→L0 episode " + esc(e.provenance) : "") +
        "</div>" +
      "</div>"
    );
  }

  function evidenceBlock(run) {
    var ev = run.evidence || [];
    if (!ev.length) return "";
    return (
      '<h3 style="margin-top:14px;font-size:12px">Evidence — what this key let through ' +
        '<span class="refreshed">the agent saw nothing else</span></h3>' +
      ev.map(evCard).join("")
    );
  }
})();
