"use strict";
/* ==========================================================================
   panel_ingest.js — Add memory (UI-ACTIONS N2)
   --------------------------------------------------------------------------
   Reads / writes:
     • GET  /v1/admin/principals?tenant_id&limit — the named directory that
       feeds the viewer picker (admin read; 401 renders honestly and falls
       back to raw tokens, never to a permissive default)
     • POST /v1/scopes — mints the WRITE PASS (jargon: scope handle) whose
       principals become the memory's visibility; actor console:ingest;
       15-minute TTL disclosed (server floor is 60 s)
     • POST /v1/episodes — paste-text path: { scope_handle, observation,
       entities[] } → { episode_id }
     • POST /v1/files — upload path: multipart scope_handle / file /
       entities (comma-sep) → { media_id, chunks_indexed }; 32 MB server
       body cap; text-like files index, others are store-only in v0.1
     • URLs are NOT fetched by the console (zero outside requests) or the
       server (no fetch endpoint, by design) — the tab writes the exact
       `verity-cli add <url> --visibility …` command instead.

   THE GATE (N2): visibility is required with no default. Adding without a
   pass sends the request anyway and surfaces the server's own 422 refusal
   VERBATIM — the teaching refusal is the point. A pass naming no viewers is
   flagged loudly: it writes memory nobody can ever read (fail-closed).

   THE LAW, applied: plain-language primary labels; refs mono-small; the
   directory autoloads once the tenant is known; every empty state teaches;
   receipts show only server-reported numbers (no fabrication); the success
   handoff sends the operator to the Scope Inspector to recall — or to a
   narrower pass to watch the boundary hold.
   ========================================================================== */
(function () {
  var V = window.Verity;

  var PASS_TTL_SECONDS = 900; // 15 min, disclosed in copy; server floor 60 s

  var data = {
    dir: [],            // [{principal, token}] from GET /v1/admin/principals
    dirState: "idle",   // idle | loading | ok | empty | unauth | fail
    dirPartial: false,  // next_after_token was non-null (directory larger)
    checkedAt: 0,
  };
  var sel = {};         // token (string) → principal string — picked viewers
  var pass = { handle: "", claims: null, how: "" };
  var view = "text";    // text | file | url
  var tenantNow = "";
  // Entity-tag picker (Verity.entityPicker, ENTITY-PICKER.md §5.1): chips are
  // the ONLY submission path — no comma-split free text rides into a POST.
  var entsPicker = null;
  var entsRestrictKey = null;

  function el(id) { return V.$(id); }
  function nowStamp() { return new Date().toTimeString().slice(0, 8); }

  /* ------------------------------------------------- humane principal bits */

  // "user:alice@corp.example" → name-first chip; kind + token stay secondary.
  function principalName(p) {
    var s = String(p || "");
    var i = s.indexOf(":");
    return i < 0 ? s : s.slice(i + 1);
  }
  function principalKind(p) {
    var s = String(p || "");
    var i = s.indexOf(":");
    var k = i < 0 ? "" : s.slice(0, i);
    if (k === "user") return "person";
    if (k === "group") return "group";
    return k || "principal";
  }

  function selectedTokens() {
    var toks = Object.keys(sel).map(Number);
    var raw = el("ing-raw") ? el("ing-raw").value.trim() : "";
    if (raw) {
      var extra = raw.split(",").map(function (s) { return s.trim(); })
        .filter(Boolean).map(Number);
      for (var i = 0; i < extra.length; i++) {
        if (Number.isInteger(extra[i]) && toks.indexOf(extra[i]) < 0) toks.push(extra[i]);
      }
    }
    toks.sort(function (a, b) { return a - b; });
    return toks;
  }
  function rawIsBad() {
    var raw = el("ing-raw") ? el("ing-raw").value.trim() : "";
    if (!raw) return false;
    return raw.split(",").map(function (s) { return s.trim(); }).filter(Boolean)
      .some(function (s) { return !Number.isInteger(Number(s)); });
  }

  /* ============================================================ register */

  V.register({
    id: "ingest",
    mount: function () {
      var host = el("ingest-mount");
      if (!host) return;
      host.innerHTML = '<div id="ing-nota"></div><div id="ing-cards"></div>';
      buildCards();
      wire();
      renderPass();
      switchView("text");
      if (!V.tenant()) renderNoTenant();
    },
    // AUTOLOAD: the viewer directory loads itself the moment a tenant is
    // known (re-runs on tenant change; deduped by the router).
    load: function (_section, tenant) {
      if (tenantNow && tenantNow !== tenant) {
        sel = {};
        if (entsPicker) entsPicker.clear(); // another tenant's tags don't carry over
        if (pass.claims && pass.claims.tenant_id !== tenant) {
          pass = { handle: "", claims: null, how: "" };
        }
      }
      tenantNow = tenant;
      if (el("ing-nota")) el("ing-nota").innerHTML = "";
      if (el("ing-cards")) el("ing-cards").style.display = "";
      renderPass();
      return refreshDir(tenant);
    },
    onShow: function () {
      var p = V.navParams();
      if (p && p.view) switchView(p.view);
    },
  });

  // A handle minted anywhere (topbar dialog, teach buttons) can serve as the
  // write pass — same post-mint handoff pattern as the entities panel.
  V.onMint(function (info) {
    if (!info || !info.handle) return;
    var claims = info.claims;
    if (!claims) { try { claims = V.decodeHandle(info.handle); } catch (e) { claims = null; } }
    pass = { handle: info.handle, claims: claims, how: "from the mint dialog" };
    renderPass();
    updateUrlCmd();
  });

  /* ============================================================ skeleton */

  function buildCards() {
    el("ing-cards").innerHTML =
      /* ---------------------------------------- step 1 · who can see it */
      '<div class="card">' +
        '<h2>1 · Who can see this? <span class="sub">GET /v1/admin/principals · POST /v1/scopes</span></h2>' +
        '<div class="note" style="margin-top:0">Everything you add is written under a <b>write pass</b> — a short-lived signed key naming exactly who may recall it later. ' +
          "No pass means no audience, and Verity <b>refuses rather than guesses</b>. There is no “everyone” option, here or anywhere.</div>" +
        '<div id="ing-pass-line" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:10px 0 4px"></div>' +
        '<div id="ing-pass-meta" class="dc-meta" style="margin-top:2px"></div>' +
        '<div style="margin-top:10px"><label for="ing-filter">pick viewers — people &amp; groups on record for this tenant</label>' +
          '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
            '<input type="text" id="ing-filter" placeholder="filter names…" spellcheck="false" style="max-width:280px">' +
            '<span class="asof" id="ing-dir-asof"></span>' +
            '<span class="spacer" style="flex:1"></span>' +
            '<button id="ing-dir-refresh">Refresh names</button>' +
          "</div>" +
          '<div id="ing-dir" style="margin-top:6px;max-height:190px;overflow:auto;border:1px solid var(--border);border-radius:var(--r-sm);padding:6px 8px"></div>' +
          '<div id="ing-dir-note" class="asof" style="display:block;margin-top:4px"></div>' +
        "</div>" +
        '<div class="row" style="margin-top:10px">' +
          '<div><label for="ing-raw">or raw principal tokens <span style="font-weight:400">(dev mode; comma-separated, e.g. 1, 11)</span></label>' +
            '<input type="text" id="ing-raw" placeholder="e.g. 1" spellcheck="false"></div>' +
          '<div class="tight"><button class="primary" id="ing-mint">Create write pass</button></div>' +
        "</div>" +
        '<div class="row" style="margin-top:10px">' +
          '<div><label for="ing-paste">or paste a scope handle you already hold</label>' +
            '<input type="text" id="ing-paste" placeholder="vs_…" spellcheck="false"></div>' +
          '<div class="tight"><button id="ing-use">Use this handle</button></div>' +
        "</div>" +
        '<div class="err" id="ing-pass-err"></div>' +
        '<div class="note">Write passes expire after <b>15 minutes</b> here (the server enforces a 60&nbsp;s minimum) and are never stored by the console. ' +
          "A pass naming <b>no viewers</b> still works — and writes memory <b>nobody can ever read</b>. That is fail-closed working, not a bug.</div>" +
      "</div>" +

      /* ---------------------------------------------- step 2 · the memory */
      '<div class="card">' +
        '<h2>2 · What to add <span class="sub">POST /v1/episodes · POST /v1/files</span></h2>' +
        '<div class="toolbar" style="margin-top:2px">' +
          '<span class="seg">' +
            '<button id="ing-tab-text" class="on">Paste text</button>' +
            '<button id="ing-tab-file">Upload a file</button>' +
            '<button id="ing-tab-url">From a URL</button>' +
          "</span>" +
          '<span class="spacer"></span>' +
          '<span id="ing-add-state"></span>' +
        "</div>" +

        '<div id="ing-view-text">' +
          '<label for="ing-text">the note itself — stored verbatim, indexed for recall</label>' +
          '<textarea id="ing-text" style="min-height:96px" placeholder="e.g. Acme’s CTO confirmed the pilot starts in August; budget owner is J. Reyes."></textarea>' +
        "</div>" +

        '<div id="ing-view-file" hidden>' +
          '<label for="ing-file">choose a file</label>' +
          '<input type="file" id="ing-file" style="display:block;color:var(--dim)">' +
          '<div class="note">Text-like files (<span class="mono">.txt .md .json</span>, any <span class="mono">text/*</span>) are chunked and indexed for recall. ' +
            "Other types are <b>stored but not searchable</b> in v0.1 — the receipt will say which happened. Server caps uploads at <b>32&nbsp;MB</b>.</div>" +
        "</div>" +

        '<div id="ing-view-url" hidden>' +
          '<div class="note" style="margin-top:0">The console makes <b>zero outside requests</b>, and the server has no fetch-a-URL endpoint by design — ' +
            "the download happens on <b>your machine</b>, where you can see exactly what is being ingested. This tab writes the command for you:</div>" +
          '<label for="ing-url">web address</label>' +
          '<input type="text" id="ing-url" placeholder="https://example.com/notes.md" spellcheck="false">' +
          '<label for="ing-url-cmd" style="margin-top:8px">run this where verity-cli lives</label>' +
          '<textarea id="ing-url-cmd" readonly class="mono" style="min-height:58px"></textarea>' +
          '<div class="actions" style="justify-content:flex-start;margin-top:6px"><button id="ing-url-copy">Copy CLI command</button></div>' +
          '<div class="dc-meta">verity-cli add mints its own write pass over exactly your --visibility tokens (same rule as this screen; it refuses without them) · URL downloads cap at 2 MB · agents do the same via the MCP tool memory_ingest_url</div>' +
        "</div>" +

        '<div id="ing-ents-wrap" style="margin-top:10px">' +
          '<label>which customer or account is this about? <span style="font-weight:400">(optional)</span></label>' +
          '<div id="ing-ents"></div>' +
        "</div>" +

        '<div class="actions" style="justify-content:flex-start;margin-top:12px">' +
          '<button class="primary" id="ing-add">Add to memory</button>' +
        "</div>" +
        '<div class="err" id="ing-add-err"></div>' +
        '<div id="ing-add-teach"></div>' +
        '<div id="ing-receipt"></div>' +
      "</div>";
  }

  function wire() {
    el("ing-dir-refresh").onclick = function () { V.reload("ingest"); };
    el("ing-filter").oninput = function () { renderDirList(); };
    el("ing-dir").addEventListener("change", function (e) {
      var t = e.target;
      if (!t || t.type !== "checkbox") return;
      if (t.checked) sel[t.getAttribute("data-tok")] = t.getAttribute("data-principal");
      else delete sel[t.getAttribute("data-tok")];
      updateMintLabel();
      updateUrlCmd();
    });
    el("ing-raw").oninput = function () { updateMintLabel(); updateUrlCmd(); };
    el("ing-mint").onclick = mintPass;
    el("ing-use").onclick = usePastedHandle;
    el("ing-tab-text").onclick = function () { switchView("text"); };
    el("ing-tab-file").onclick = function () { switchView("file"); };
    el("ing-tab-url").onclick = function () { switchView("url"); };
    el("ing-url").oninput = updateUrlCmd;
    el("ing-url-copy").onclick = function () {
      var ta = el("ing-url-cmd");
      ta.select();
      try { navigator.clipboard.writeText(ta.value); } catch (e) { document.execCommand("copy"); }
      el("ing-url-copy").textContent = "Copied";
      setTimeout(function () { var b = el("ing-url-copy"); if (b) b.textContent = "Copy CLI command"; }, 1500);
    };
    el("ing-add").onclick = addMemory;
  }

  function renderNoTenant() {
    if (el("ing-cards")) el("ing-cards").style.display = "none";
    el("ing-nota").innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a tenant to start adding memory</div>' +
        '<div class="et-body">Paste a tenant id in the session bar above (<span class="mono">verity-cli dev</span> prints one), ' +
          "or mint a scope handle — the console adopts its tenant automatically and this screen loads itself.</div>" +
        '<div class="et-actions"><button class="primary" id="ing-nota-mint">Mint a scope handle</button></div>' +
      "</div>";
    el("ing-nota-mint").onclick = function () { V.openMint(); };
  }

  /* ===================================================== viewer directory */

  async function refreshDir(tenant) {
    data.dirState = "loading";
    renderDirList();
    V.clearErr("ing-pass-err");
    try {
      var res = await V.api(
        "/v1/admin/principals?tenant_id=" + encodeURIComponent(tenant) + "&limit=1000",
        { admin: true }
      );
      data.dir = (res && res.principals) || [];
      data.dirPartial = !!(res && res.next_after_token != null);
      data.dirState = data.dir.length ? "ok" : "empty";
      data.checkedAt = Date.now();
    } catch (e) {
      if (/HTTP 401/.test(String(e.message))) data.dirState = "unauth";
      else { data.dirState = "fail"; V.err("ing-pass-err", e); }
    }
    renderDirList();
  }

  function renderDirList() {
    var host = el("ing-dir");
    if (!host) return;
    var note = el("ing-dir-note");
    var asof = el("ing-dir-asof");
    asof.textContent = data.checkedAt ? "directory checked " + new Date(data.checkedAt).toTimeString().slice(0, 8) : "";
    note.textContent = "";

    if (data.dirState === "loading" || data.dirState === "idle") {
      host.innerHTML = V.stateChip("wait", "loading names…");
      return;
    }
    if (data.dirState === "unauth") {
      host.innerHTML =
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip("attn", "admin token required") +
          '<span style="color:var(--dim);font-size:var(--fs-sm)">Listing names is an admin read. Paste an admin token in the session bar to see them — or use raw principal tokens (dev mode) below. There is no permissive fallback.</span>' +
        "</div>";
      return;
    }
    if (data.dirState === "fail") {
      host.innerHTML = V.stateChip("fail", "directory read failed");
      return;
    }
    if (data.dirState === "empty") {
      host.innerHTML =
        '<div class="empty-teach sp-a" style="margin:2px 0">' +
          '<div class="et-title">No people or groups on record yet</div>' +
          '<div class="et-body">This tenant’s directory is empty — an empty list is an honest answer, not an error. ' +
            "Create people and groups in <b>People &amp; groups</b>, or type raw principal tokens (dev mode) below.</div>" +
          '<div class="et-actions"><button id="ing-open-principals">Open People &amp; groups</button></div>' +
        "</div>";
      var b = el("ing-open-principals");
      if (b) b.onclick = function () { V.show("principals"); };
      return;
    }

    var q = (el("ing-filter").value || "").trim().toLowerCase();
    var rows = data.dir.filter(function (r) {
      return !q || String(r.principal).toLowerCase().indexOf(q) >= 0;
    });
    if (!rows.length) {
      host.innerHTML = '<span class="asof">no names match “' + esc(q) + '” — ' + data.dir.length + " on record</span>";
    } else {
      host.innerHTML = rows.map(function (r) {
        var tok = String(r.token);
        var checked = Object.prototype.hasOwnProperty.call(sel, tok) ? " checked" : "";
        return '<label class="checkline" style="display:flex;margin:3px 0;font-size:var(--fs-sm)">' +
          '<input type="checkbox" data-tok="' + esc(tok) + '" data-principal="' + esc(r.principal) + '"' + checked + ">" +
          "<b style=\"color:var(--text)\">" + esc(principalName(r.principal)) + "</b>" +
          '<span style="color:var(--dim)">· ' + esc(principalKind(r.principal)) + "</span>" +
          '<span class="ref">' + esc(r.principal) + " · token " + esc(tok) + "</span>" +
        "</label>";
      }).join("");
    }
    if (data.dirPartial) {
      note.textContent = "showing the first 1000 names — the directory is larger; narrow with the filter or use raw tokens.";
    }
    updateMintLabel();
  }

  function updateMintLabel() {
    var btn = el("ing-mint");
    if (!btn) return;
    var n = selectedTokens().length;
    btn.textContent = n ? "Create write pass (" + n + " viewer" + (n === 1 ? "" : "s") + ")" : "Create write pass";
  }

  /* ========================================================= write pass */

  async function mintPass() {
    V.clearErr("ing-pass-err");
    if (!tenantNow) { V.err("ing-pass-err", new Error("no tenant set — paste one in the session bar first")); return; }
    if (rawIsBad()) { V.err("ing-pass-err", new Error("raw principal tokens must be integers, comma-separated — e.g. 1, 11")); return; }
    var toks = selectedTokens();
    if (!toks.length) {
      // The teaching refusal, client-side edition: we will not mint a
      // sees-nothing pass by accident. (Adding with NO pass still reaches
      // the server and surfaces its 422 verbatim — that path stays open.)
      V.err("ing-pass-err", new Error(
        "no viewers selected — Verity refuses to guess an audience. Pick at least one name (or a raw token). " +
        "If you add without any pass, the server will refuse with a 422: that refusal is fail-closed working."
      ));
      return;
    }
    var btn = el("ing-mint");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/scopes", {
        json: {
          tenant_id: tenantNow,
          principals: toks,
          ttl_seconds: PASS_TTL_SECONDS,
          actor_azp: "console:ingest",
        },
      });
      var handle = res && res.scope_handle;
      if (!handle) throw new Error("mint returned no scope_handle");
      var claims = null;
      try { claims = V.decodeHandle(handle); } catch (e) { /* still usable */ }
      pass = { handle: handle, claims: claims, how: "minted here" };
      renderPass();
      updateUrlCmd();
    } catch (e) {
      V.err("ing-pass-err", e); // server refusals verbatim
    } finally {
      btn.disabled = false;
    }
  }

  function usePastedHandle() {
    V.clearErr("ing-pass-err");
    var h = el("ing-paste").value.trim();
    if (!h) { V.err("ing-pass-err", new Error("paste a vs_… scope handle first")); return; }
    var claims = null;
    try { claims = V.decodeHandle(h); }
    catch (e) { V.err("ing-pass-err", e); return; }
    pass = { handle: h, claims: claims, how: "pasted" };
    el("ing-paste").value = "";
    renderPass();
    updateUrlCmd();
  }

  function passViewerCount() {
    return pass.claims && pass.claims.principals ? pass.claims.principals.length : null;
  }
  function passExpired() {
    if (!pass.claims || !pass.claims.expires_at) return false;
    var t = Date.parse(pass.claims.expires_at);
    return isFinite(t) && t < Date.now();
  }

  function renderPass() {
    var line = el("ing-pass-line");
    var meta = el("ing-pass-meta");
    if (!line) return;
    if (!pass.handle) {
      line.innerHTML = V.stateChip("off", "no write pass yet") +
        '<span style="color:var(--dim);font-size:var(--fs-sm)">pick viewers below, then create a pass — it becomes the memory’s audience</span>';
      meta.textContent = "";
      syncEntsPicker();
      return;
    }
    var n = passViewerCount();
    var bits = [];
    if (passExpired()) {
      bits.push(V.stateChip("attn", "pass expired"));
      bits.push('<span style="color:var(--dim);font-size:var(--fs-sm)">this pass has expired — writes under it will be refused; create a new one</span>');
    } else if (n === 0) {
      bits.push(V.stateChip("attn", "pass sees nothing"));
      bits.push('<span style="color:var(--dim);font-size:var(--fs-sm)">this pass names <b>no viewers</b> — anything written under it is stored but can never be read by anyone. Pick viewers and mint again.</span>');
    } else if (pass.claims && pass.claims.tenant_id && tenantNow && pass.claims.tenant_id !== tenantNow) {
      bits.push(V.stateChip("attn", "different tenant"));
      bits.push('<span style="color:var(--dim);font-size:var(--fs-sm)">this pass belongs to another tenant — writes will land there, not here</span>');
    } else {
      bits.push(V.stateChip("ok", "write pass ready"));
      bits.push('<span style="color:var(--dim);font-size:var(--fs-sm)">' +
        (n != null ? "visible to <b>" + n + " viewer" + (n === 1 ? "" : "s") + "</b>" : "viewers unreadable from the handle") +
        " · " + esc(pass.how) + "</span>");
    }
    line.innerHTML = bits.join("");
    var metaBits = [];
    if (pass.claims) {
      if (pass.claims.principals) metaBits.push("principals [" + pass.claims.principals.join(", ") + "]");
      if (pass.claims.max_confidentiality) metaBits.push("ceiling " + pass.claims.max_confidentiality);
      if (pass.claims.entity_scope && pass.claims.entity_scope.length) metaBits.push("entity-bound (" + pass.claims.entity_scope.length + ")");
      if (pass.claims.expires_at) metaBits.push("expires " + V.fmtTime(pass.claims.expires_at));
    }
    var shown = pass.handle.length > 34 ? pass.handle.slice(0, 30) + "…" : pass.handle;
    meta.innerHTML = "scope_handle " + esc(shown) + (metaBits.length ? " · " + esc(metaBits.join(" · ")) : "");
    syncEntsPicker();
  }

  // ENTITY-PICKER.md §5.1: mode "tags" (tagging is how entities are born —
  // emptyBehavior "teach"), and when the write pass is entity-bound the picker
  // is rebuilt with restrictTo = the pass's entity set, so outside tags are
  // refused inline — the same subset rule the server enforces on write.
  function syncEntsPicker() {
    var mount = el("ing-ents");
    if (!mount) return;
    var restrict = (pass.claims && pass.claims.entity_scope && pass.claims.entity_scope.length)
      ? pass.claims.entity_scope.slice() : null;
    var key = restrict ? restrict.join("\u0000") : "";
    if (entsPicker && key === entsRestrictKey) return;
    entsRestrictKey = key;
    var keep = entsPicker ? entsPicker.value() : [];
    if (entsPicker) { entsPicker.destroy(); entsPicker = null; }
    mount.innerHTML = "";
    var opts = {
      mode: "tags",
      multiple: true,
      allowNew: true, // forced false by the component when restrictTo is set
      emptyBehavior: "teach",
      placeholder: "account:acme",
      explainer: restrict
        ? "your write pass is entity-bound — tags must stay inside its limit; anything outside is refused here, exactly as the server would refuse it."
        : "tags decide which entity views can find this memory. Known tags are suggested with counts; a new tag creates that entity the moment this lands.",
      // Chips outside a newly-bound pass are dropped, not smuggled: the
      // server would refuse them anyway (fail-closed, same rule).
      prefill: restrict ? keep.filter(function (t) { return restrict.indexOf(t) >= 0; }) : keep,
      tenantId: function () { return tenantNow || V.tenant(); },
      onChange: function () { updateUrlCmd(); },
    };
    if (restrict) opts.restrictTo = restrict;
    entsPicker = V.entityPicker(mount, opts);
    updateUrlCmd();
  }

  /* ============================================================== views */

  function switchView(v) {
    if (v !== "text" && v !== "file" && v !== "url") return;
    view = v;
    if (!el("ing-tab-text")) return;
    el("ing-tab-text").className = v === "text" ? "on" : "";
    el("ing-tab-file").className = v === "file" ? "on" : "";
    el("ing-tab-url").className = v === "url" ? "on" : "";
    el("ing-view-text").hidden = v !== "text";
    el("ing-view-file").hidden = v !== "file";
    el("ing-view-url").hidden = v !== "url";
    var add = el("ing-add");
    add.style.display = v === "url" ? "none" : "";
    add.textContent = v === "file" ? "Add file to memory" : "Add to memory";
    if (v === "url") updateUrlCmd();
  }

  // The cardinal rule (ENTITY-PICKER.md §2.1): value() is the ONLY submission
  // path — committed chips, never in-progress typed text, never a comma split.
  function parsedEnts() {
    return entsPicker ? entsPicker.value() : [];
  }

  function updateUrlCmd() {
    var out = el("ing-url-cmd");
    if (!out) return;
    var url = (el("ing-url") ? el("ing-url").value.trim() : "") || "<url>";
    var toks = selectedTokens();
    var vis = toks.length ? toks.join(",") : "<tokens>";
    var cmd = 'verity-cli add "' + url.replace(/"/g, "") + '" --visibility ' + vis;
    parsedEnts().forEach(function (e) { cmd += " --entity " + e; });
    if (!toks.length) cmd += "   # --visibility is REQUIRED — the CLI refuses without it";
    out.value = cmd;
  }

  /* ================================================================ add */

  async function addMemory() {
    V.clearErr("ing-add-err");
    el("ing-add-teach").innerHTML = "";
    var startedWithoutPass = !pass.handle;

    if (view === "text") {
      var text = el("ing-text").value;
      if (!text.trim()) { V.err("ing-add-err", new Error("nothing to add — the note is empty")); return; }
    } else if (view === "file") {
      if (!el("ing-file").files || !el("ing-file").files.length) {
        V.err("ing-add-err", new Error("choose a file first")); return;
      }
    } else { return; }

    var btn = el("ing-add");
    btn.disabled = true;
    el("ing-add-state").innerHTML = V.stateChip("wait", "writing…");
    try {
      var res, receipt;
      if (view === "text") {
        // Omitting scope_handle on purpose when there is no pass: the
        // server's own 422 refusal is the teaching moment (N2 gate).
        var body = { observation: el("ing-text").value, entities: parsedEnts() };
        if (pass.handle) body.scope_handle = pass.handle;
        res = await V.api("/v1/episodes", { json: body });
        receipt = {
          kind: "text",
          idLabel: "episode",
          id: res && res.episode_id,
          line: "Your note is in memory and indexed for recall.",
          endpoint: "POST /v1/episodes",
        };
      } else {
        var fd = new FormData();
        if (pass.handle) fd.append("scope_handle", pass.handle);
        var ents = parsedEnts();
        if (ents.length) fd.append("entities", ents.join(","));
        fd.append("file", el("ing-file").files[0]);
        res = await V.api("/v1/files", { method: "POST", body: fd });
        var chunks = res ? Number(res.chunks_indexed) : 0;
        receipt = {
          kind: "file",
          idLabel: "media",
          id: res && res.media_id,
          chunks: chunks,
          filename: el("ing-file").files[0].name,
          line: chunks > 0
            ? "File stored — <b>" + chunks + " chunk" + (chunks === 1 ? "" : "s") + "</b> indexed for recall."
            : "File stored — <b>0 chunks indexed</b>: this file type is store-only in v0.1 (not searchable).",
          endpoint: "POST /v1/files",
        };
      }
      el("ing-add-state").innerHTML = V.stateChip("ok", "written");
      renderReceipt(receipt);
      // Born-by-usage, made visible: a new tag committed above now exists —
      // re-fetch the directory so it appears with its count immediately.
      if (entsPicker) entsPicker.refresh();
      if (view === "text") el("ing-text").value = "";
      else el("ing-file").value = "";
    } catch (e) {
      el("ing-add-state").innerHTML = V.stateChip("fail");
      V.err("ing-add-err", e); // server refusal, verbatim
      if (startedWithoutPass && /HTTP 4/.test(String(e.message))) {
        el("ing-add-teach").innerHTML =
          '<div class="note">That refusal is the design: <b>no audience, no write</b>. Verity never picks a default. ' +
          "Create a write pass in step 1 and try again.</div>";
      }
    } finally {
      btn.disabled = false;
    }
  }

  /* ============================================================= receipt */

  function renderReceipt(r) {
    var n = passViewerCount();
    var viewers = n == null
      ? "the viewers on your pass"
      : (n === 0
        ? "<b>no one</b> — the pass named no viewers (fail-closed: stored, never readable)"
        : "<b>" + n + " viewer" + (n === 1 ? "" : "s") + "</b>");
    var names = Object.keys(sel).map(function (k) { return sel[k]; });
    var nameChips = names.slice(0, 4).map(function (p) {
      return V.entityChip(principalName(p), principalKind(p));
    }).join(" ") + (names.length > 4 ? ' <span class="asof">+' + (names.length - 4) + " more</span>" : "");
    var handleForProbe = pass.handle;
    var stateChip = (r.kind === "file" && r.chunks === 0)
      ? V.stateChip("attn", "stored, not searchable")
      : V.stateChip("ok", "in memory");

    el("ing-receipt").innerHTML =
      '<div class="card" style="margin-top:12px;margin-bottom:0">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          stateChip +
          '<span class="asof">written ' + nowStamp() + "</span>" +
        "</div>" +
        '<div style="margin-top:8px">' + r.line + " Readable by " + viewers + "." +
          (names.length ? '<div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">' + nameChips + "</div>" : "") +
        "</div>" +
        '<div class="dc-meta" style="margin-top:8px">' + esc(r.endpoint) + " · " + esc(r.idLabel) + " " +
          (r.id != null ? '<span class="ref">' + esc(String(r.id)) + "</span>" : "—") +
          (r.filename ? ' · <span class="ref">' + esc(r.filename) + "</span>" : "") +
          " · visibility inherited from the write pass" +
        "</div>" +
        '<div class="actions" style="justify-content:flex-start;margin-top:10px">' +
          '<button class="good" id="ing-probe">Recall it now — open Scope Inspector</button>' +
          '<button id="ing-narrow">Test the boundary — mint a narrower pass</button>' +
          '<button id="ing-again">Add another</button>' +
        "</div>" +
        '<div class="asof" style="display:block;margin-top:6px">The interesting part is the boundary: recall this under a pass that should NOT see it, and watch Verity return nothing — an explained zero, not a bug.</div>' +
      "</div>";

    el("ing-probe").onclick = function () {
      if (handleForProbe) V.show("scope", { handle: handleForProbe });
      else V.show("scope");
    };
    el("ing-narrow").onclick = function () { V.openMint({ tenant: tenantNow }); };
    el("ing-again").onclick = function () {
      el("ing-receipt").innerHTML = "";
      el("ing-add-state").innerHTML = "";
      var t = el(view === "text" ? "ing-text" : view === "file" ? "ing-file" : "ing-url");
      if (t) t.focus();
    };
  }
})();
