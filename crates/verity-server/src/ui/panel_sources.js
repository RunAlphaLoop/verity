"use strict";
/* ==========================================================================
   panel_sources.js — Sources & Freshness (v2 rebuild · UN-SEAMED, N4)
   --------------------------------------------------------------------------
   Verbs (all live, none faked):
     • mint webhook   POST /v1/webhooks            — show-once secret URL
     • revoke webhook DELETE /v1/webhooks/{id}     — typed confirm (REVOKE)
     • install draft  POST /v1/manifests           — draft only, never runs
     • activate       POST /v1/manifests/{id}/activate — THE human gate:
                      separate step, typed confirm (ACTIVATE), approver name
                      required + recorded in audit_log by the server.
   Reads autoload when the tenant is known (LAW #3 — no cold Load button):
     connector-status · slo/freshness · backfill · manifests, allSettled so
     one failure never blanks the screen. GET /v1/admin/principals feeds the
     who-can-see picker in the connect dialog (names, not bare ints).

   Fail-closed gates kept: empty visibility on mint → the server's own 422
   refusal, surfaced verbatim (no client-side permissive default); the raw
   webhook URL is shown ONCE and never re-fetched (only its hash persists);
   activation is never bundled into install; no "index it anyway" anywhere.

   Honesty: percentiles are real samples over the stated window on THIS
   deployment (labeled not-the-benchmark); the alert threshold is
   operator-set and labeled so; heartbeat rows never get a guessed lane;
   client-side "waiting for first delivery" rows are labeled client-side.
   ========================================================================== */
(function () {
  var V = window.Verity;

  // Liveness thresholds (SPEC §5): <15m fresh · <24h quiet · beyond = cold.
  var FRESH_MS = 15 * 60 * 1000;
  var STALE_MS = 24 * 60 * 60 * 1000;

  /* ------------------------------------------------------------ state */

  var data = {
    status: [],     // connector heartbeats
    fresh: [],      // freshness percentiles
    backfill: [],   // latest catch-up run per source
    manifests: [],  // draft/active blueprints
    errs: [],       // per-read load failures (rendered, never hidden)
    loadedAt: 0,
  };
  // Client-side only: sources minted this session that have not yet posted a
  // heartbeat or delivery. Labeled as client-side in the table — honest.
  var pendingLocal = [];
  var tenantNow = "";
  var pendingActivate = null; // { id, name, laneWords, ready }
  // Entity-scope picker for the mint dialog (ENTITY-PICKER.md §5.2): scope
  // mode, hidden by the Emptiness Law at zero entities. Highest blast radius
  // in the console — a webhook's entity limit binds standing infrastructure
  // that cannot be listed or edited afterward; only revoked and re-minted.
  var mintEntPicker = null;

  function el(id) { return V.$(id); }

  // Starter manifest for the install dialog: a trimmed, commented, VALID
  // manifest derived from registry/manifests/linear.yaml (one entity, every
  // required part). Installing it still only creates a draft — the human
  // activate gate is unchanged.
  var LINEAR_EXAMPLE = `# validate offline: cargo run -p verity-manifest --bin manifest-test -- <file>
# Trimmed from registry/manifests/linear.yaml — one entity, the parts every
# manifest needs. Installing stores a DRAFT; a named human activates it.

manifest_version: 1

source:
  name: linear
  # Tier B: webhooks + API under your key, but no per-item ACL API —
  # container approximation only (declared honestly in acl_policy below).
  tier: B
  auth:
    # Secrets are referenced by name and read from the environment, never
    # pasted inline: secret://linear-service-key resolves to the
    # VERITY_SECRET_LINEAR_SERVICE_KEY env var on the server.
    ref: secret://linear-service-key
    shape: static_key
  webhook:
    # Deliveries are signature-verified before anything is stored.
    signature:
      scheme: hmac_sha256          # hex HMAC-SHA256 of the raw request body
      header: Linear-Signature
      secret_ref: secret://linear-webhook-secret

entities:
  - type: issue
    route:
      # Which incoming payloads this entity claims; anything unrouted
      # quarantines (fail closed, never mis-filed).
      when: "type = 'Issue' and action in ['create','update']"
      operation: upsert
    primary_key: "data.id"         # which field is the ID — updates replace, never duplicate
    valid_from: "data.updatedAt"   # which timestamp is the event time (bi-temporal)
    map:                           # which fields become queryable facts
      identifier: "data.identifier"
      title: "data.title"
      state: "data.state.name"
      team: "data.team.key"

# Who may see each item. This is the human-gated block: an admin reviews
# exactly this and approves it in the separate activate step.
acl_policy:
  mode: map
  identity_namespace: source_native_id
  principals: "organizationId"
  approximation: true
  note: >-
    Linear exposes no per-issue ACL API (Tier B). Workspace membership
    (organizationId) approximates visibility; private-team boundaries are
    NOT reconstructed.
`;

  /* ------------------------------------------------------------ helpers */

  function ageMs(iso) {
    if (!iso) return null;
    var t = new Date(iso).getTime();
    return isNaN(t) ? null : Date.now() - t;
  }

  // Coarse, honest age label ("2m ago"), never a fake-precise stamp.
  function humanAge(ms) {
    if (ms == null) return "—";
    if (ms < 0) ms = 0;
    return V.fmtAge(ms / 1000) + " ago";
  }

  // One plain-words liveness verdict per source (the ten-second read).
  function liveness(evAge, hbAge, bfError) {
    if (bfError) {
      return { chip: V.stateChip("fail"), text: "catch-up import failed — see notes" };
    }
    var a = evAge != null ? evAge : hbAge;
    if (a == null) {
      // Honest fallback: a source that reports no event time never shows
      // fake-fresh green.
      return { chip: V.stateChip("off", "age unknown"), text: "no event time reported yet" };
    }
    if (a < FRESH_MS) {
      return { chip: V.stateChip("ok", "fresh"), text: "fresh " + humanAge(a) + " · syncing normally" };
    }
    if (a < STALE_MS) {
      return { chip: V.stateChip("wait", "quiet"), text: "quiet — last new data " + humanAge(a) };
    }
    return { chip: V.stateChip("attn", "cold"), text: "cold — no new data for " + V.fmtAge(a / 1000) };
  }

  // Manifest permission lane, in plain words. acl_mode is real server data
  // (map | static | quarantine); a manifest that no longer parses is null.
  function laneWords(aclMode) {
    var m = String(aclMode || "").toLowerCase();
    if (m === "map") return "source permissions copied exactly";
    if (m === "static") return "an admin chose who can see it";
    if (m === "quarantine") return "no permission mapping — everything it sends is quarantined";
    return "manifest unreadable — cannot state a lane";
  }

  function fmtCount(n) { return n == null ? "—" : String(n); }

  // Operator-set alert threshold (ms) — display highlighting only.
  function targetMs() {
    var f = el("src-target");
    if (!f) return null;
    var v = parseInt(f.value, 10);
    return isNaN(v) || v < 0 ? null : v;
  }

  function windowHours() {
    var f = el("src-window");
    var v = f ? parseInt(f.value, 10) : 24;
    return Math.max(1, Math.min(2160, isNaN(v) ? 24 : v));
  }

  function pctCell(ms, tgt) {
    if (ms == null) return '<span class="ref">—</span>';
    var txt = V.fmtMs(ms);
    return (tgt != null && ms > tgt)
      ? V.badge(txt + " · over your target", "b-conf-3")
      : V.esc(txt);
  }

  function receipt(kind, html) {
    el("src-receipt").innerHTML =
      '<div class="card" style="border-left:3px solid var(--state-' +
        (kind === "ok" ? "ok" : "attn") + ')">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip(kind) + "<span>" + html + "</span>" +
          '<span class="spacer" style="flex:1"></span>' +
          '<button id="src-receipt-x">Dismiss</button>' +
        "</div></div>";
    el("src-receipt-x").onclick = function () { el("src-receipt").innerHTML = ""; };
  }

  function hint401(errs) {
    return errs.some(function (m) { return /HTTP 401/.test(m); })
      ? '<div class="note"><em>admin token required</em> — this deployment enforces one; set it in the session bar above (kept in this tab only).</div>'
      : "";
  }

  /* =========================================================== register */

  V.register({
    id: "sources",

    mount: function () {
      var host = el("sources-mount");
      if (!host) return;
      host.innerHTML =
        /* ---- toolbar ---- */
        '<div class="toolbar">' +
          '<span id="src-state"></span>' +
          '<span class="asof" id="src-asof"></span>' +
          '<span class="spacer"></span>' +
          '<button id="src-refresh">Refresh</button>' +
          '<button id="src-revoke-open" title="DELETE /v1/webhooks/{id} — the URL stops resolving immediately">Shut off a source&hellip;</button>' +
          '<button id="src-manifest-open" title="POST /v1/manifests — installs as a DRAFT; a separate human approval activates it">Install a manifest&hellip;</button>' +
          '<button class="primary" id="src-connect-open" title="POST /v1/webhooks — mints a private URL any system can POST JSON to">Connect a source</button>' +
        "</div>" +
        '<div class="err" id="src-err"></div>' +
        '<div id="src-hint"></div>' +
        '<div id="src-receipt"></div>' +

        /* ---- source health ---- */
        '<div class="card">' +
          '<h2>Your sources <span class="sub">GET /v1/admin/connector-status · /v1/admin/backfill</span></h2>' +
          '<div id="src-health"></div>' +
        "</div>" +

        /* ---- manifests ---- */
        '<div class="card">' +
          '<h2>Manifests — how each source&rsquo;s permissions map in <span class="sub">GET /v1/manifests</span></h2>' +
          '<div class="note" style="margin-top:0"><b>When you need one:</b> free-text in → a plain webhook (zero config). Structured records (tickets, deals, invoices) you want queryable field-by-field with permissions → a manifest. ' +
            "It is the recipe that tells Verity, per event: which field is the ID (so updates replace instead of duplicate), which fields become facts, which timestamp is the event time, and who may see each item — YAML because connectors are config you can review, diff, and approve. " +
            "Two lanes, labeled, never blurred: <b>mirrored</b> = the source&rsquo;s own permission lists are copied exactly; <b>assigned</b> = an admin chose who can see it. " +
            "Installing creates a <b>draft that never runs</b> — a named human must approve it in a separate step, and that approval is written to the audit log.</div>" +
          '<div id="src-manifests"></div>' +
        "</div>" +

        /* ---- freshness ---- */
        '<div class="card">' +
          '<h2>Ingest freshness — how fast new data becomes searchable <span class="sub">GET /v1/slo/freshness</span></h2>' +
          '<div class="row" style="margin-top:0">' +
            '<div class="tight"><label for="src-window">measured over the last (hours)</label>' +
              '<input type="number" id="src-window" value="24" min="1" max="2160" style="width:110px"></div>' +
            '<div class="tight"><label for="src-target">alert me over (ms) <span style="font-weight:400">— your setting, not a server SLO</span></label>' +
              '<input type="number" id="src-target" value="900000" min="0" step="1000" style="width:130px" ' +
              'title="Set in this console for display highlighting only. The server enforces no SLO here; a red chip means a REAL measured percentile exceeded the number you typed."></div>' +
          "</div>" +
          '<div id="src-fresh"></div>' +
        "</div>" +

        /* ---- backfill ---- */
        '<div class="card">' +
          '<h2>Catch-up imports <span class="sub">backfill · latest run per source</span></h2>' +
          '<div class="note" style="margin-top:0">A catch-up import replays a source&rsquo;s history into Verity. A bar is exact only when the total is known; ' +
            "a striped track means the total is genuinely unknown — never a fabricated percentage. A time-left estimate appears only for a running job with real forward progress.</div>" +
          '<div id="src-back"></div>' +
        "</div>" +

        /* ================= dialogs ================= */

        /* ---- connect a source (mint webhook) ---- */
        '<div class="dialog-backdrop" id="src-mint-dialog"><div class="dialog" style="max-width:640px">' +
          "<h3>Connect a source</h3>" +
          '<div class="note" style="margin-top:0">Verity mints a <b>private URL</b>; anything that can POST JSON to it becomes a memory source — no code on the sender side. ' +
            "Everything it writes is stamped with the visibility you pick here. There is no default: <b>if nobody is picked, the server refuses to mint</b> — a source whose writes nobody could ever read is refused, not silently created.</div>" +
          '<div style="margin-top:12px"><label for="src-mint-name">source name <span style="font-weight:400">— becomes the source label on every record it writes</span></label>' +
            '<input type="text" id="src-mint-name" placeholder="e.g. hubspot" autocomplete="off" spellcheck="false"></div>' +
          '<div style="margin-top:10px"><label>who can see what it writes</label>' +
            '<div id="src-mint-principals" style="max-height:150px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 10px"></div>' +
          "</div>" +
          '<div style="margin-top:8px"><label for="src-mint-raw">raw principal tokens <span style="font-weight:400">(dev mode; comma-separated ints — added to any picks above)</span></label>' +
            '<input type="text" id="src-mint-raw" placeholder="e.g. 11, 1001" autocomplete="off" spellcheck="false"></div>' +
          '<div class="row" style="margin-top:10px">' +
            '<div><label>limit to entities <span style="font-weight:400">(optional)</span></label>' +
              '<div id="src-mint-entities"></div></div>' +
            '<div class="tight" style="min-width:170px"><label for="src-mint-conf">confidentiality ceiling</label>' +
              // No preselection — the ceiling is an explicit choice, same
              // no-default stance as every other dialog (audit advisory fix).
              '<select class="field" id="src-mint-conf">' +
                '<option value="" selected disabled>choose…</option>' +
                '<option value="Public">public</option>' +
                '<option value="Internal">internal</option>' +
                '<option value="Confidential">confidential</option>' +
                '<option value="Restricted">restricted</option>' +
              "</select></div>" +
          "</div>" +
          '<div style="margin-top:10px"><label for="src-mint-manifest">route payloads through a manifest <span style="font-weight:400">(optional)</span></label>' +
            '<select class="field" id="src-mint-manifest"><option value="">no — plain JSON shape</option></select>' +
            '<div class="note">Binding a <b>draft</b> is allowed — every payload quarantines until a human approves the manifest. Fail closed, never mis-filed.</div>' +
          "</div>" +
          '<div class="err" id="src-mint-err"></div>' +
          '<div id="src-mint-result"></div>' +
          '<div class="actions">' +
            '<button id="src-mint-cancel">Close</button>' +
            '<button class="primary" id="src-mint-go">Mint the URL</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- shut off (revoke webhook) ---- */
        '<div class="dialog-backdrop" id="src-revoke-dialog"><div class="dialog" style="max-width:560px">' +
          "<h3>Shut off a source</h3>" +
          '<div class="note" style="margin-top:0">Revoking kills the private URL <b>immediately</b> — deliveries stop and the URL can never be revived. ' +
            "Nothing already ingested is deleted (history is invalidated elsewhere, never erased here). " +
            "You need the <b>webhook id</b> from when the source was minted — the console cannot list webhooks yet (<code>GET /v1/webhooks</code> is on the roadmap).</div>" +
          '<div style="margin-top:12px"><label for="src-revoke-id">webhook id</label>' +
            '<input type="text" id="src-revoke-id" placeholder="the uuid shown when you minted it" autocomplete="off" spellcheck="false"></div>' +
          '<div style="margin-top:10px"><label for="src-revoke-word">this is permanent — type <b>REVOKE</b> to continue</label>' +
            '<input type="text" id="src-revoke-word" autocomplete="off" spellcheck="false"></div>' +
          '<div class="err" id="src-revoke-err"></div>' +
          '<div class="actions">' +
            '<button id="src-revoke-cancel">Cancel</button>' +
            '<button class="danger" id="src-revoke-go" disabled>Shut it off</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- install manifest (draft) ---- */
        '<div class="dialog-backdrop" id="src-manifest-dialog"><div class="dialog" style="max-width:640px">' +
          "<h3>Install a manifest (draft)</h3>" +
          '<div class="note" style="margin-top:0"><b>When you need one:</b> free-text in → a plain webhook (zero config). Structured records (tickets, deals, invoices) you want queryable field-by-field with permissions → a manifest. ' +
            "It is the recipe that tells Verity, per event: which field is the ID (so updates replace instead of duplicate), which fields become facts, which timestamp is the event time, and who may see each item — YAML because connectors are config you can review, diff, and approve.</div>" +
          '<div class="note">Paste (or start from the example below) — it is validated and stored as a <b>draft — it never runs</b> until a named human approves it in the separate activate step. ' +
            "Re-installing an existing name replaces its YAML and <b>demotes it back to draft</b>: every change re-crosses the human gate.</div>" +
          '<div style="margin-top:12px"><label for="src-manifest-yaml">manifest YAML</label>' +
            '<div style="margin:4px 0 6px"><button id="src-manifest-example" title="fills the box with a trimmed, commented Linear manifest — edit freely; nothing is sent until you click Install, and even then it is only a draft">Start from the Linear example</button></div>' +
            '<textarea id="src-manifest-yaml" style="min-height:180px" placeholder="source:&#10;  name: hubspot&#10;  &hellip;" spellcheck="false"></textarea></div>' +
          '<div class="err" id="src-manifest-err"></div>' +
          '<div id="src-manifest-result"></div>' +
          '<div class="actions">' +
            '<button id="src-manifest-cancel">Close</button>' +
            '<button class="primary" id="src-manifest-go">Install as draft</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- activate manifest (THE human gate) ---- */
        '<div class="dialog-backdrop" id="src-activate-dialog"><div class="dialog" style="max-width:600px">' +
          '<h3 id="src-activate-title">Approve &amp; activate</h3>' +
          '<div id="src-activate-summary"></div>' +
          '<div class="note">This is the product&rsquo;s mandated <b>human approval</b>: you are vouching that this manifest&rsquo;s permission mapping is correct. ' +
            "Your name is stored on the manifest and written to the <b>audit log</b>. The server re-checks the permission policy and will refuse a manifest whose policy is absent or violates its declared tier — that refusal appears here verbatim.</div>" +
          '<div style="margin-top:12px"><label for="src-activate-who">your name — recorded as the approver</label>' +
            '<input type="text" id="src-activate-who" placeholder="e.g. jane@corp.example" autocomplete="off" spellcheck="false"></div>' +
          '<div style="margin-top:10px"><label for="src-activate-word">type <b>ACTIVATE</b> to continue</label>' +
            '<input type="text" id="src-activate-word" autocomplete="off" spellcheck="false"></div>' +
          '<div class="err" id="src-activate-err"></div>' +
          '<div class="actions">' +
            '<button id="src-activate-cancel">Cancel</button>' +
            '<button class="good" id="src-activate-go" disabled>Approve &amp; activate</button>' +
          "</div>" +
        "</div></div>";

      /* ---- wiring ---- */
      el("src-refresh").onclick = function () { V.reload("sources"); };
      el("src-connect-open").onclick = function () { openMintDialog(""); };
      el("src-mint-cancel").onclick = function () { V.dialog("src-mint-dialog").close(); };
      el("src-mint-go").onclick = mintWebhook;

      el("src-revoke-open").onclick = openRevokeDialog;
      el("src-revoke-cancel").onclick = function () { V.dialog("src-revoke-dialog").close(); };
      el("src-revoke-go").onclick = revokeWebhook;
      el("src-revoke-word").oninput = reflectRevokeTyped;
      el("src-revoke-id").oninput = reflectRevokeTyped;

      el("src-manifest-open").onclick = openManifestDialog;
      el("src-manifest-cancel").onclick = function () { V.dialog("src-manifest-dialog").close(); };
      el("src-manifest-go").onclick = installManifest;
      el("src-manifest-example").onclick = function () {
        el("src-manifest-yaml").value = LINEAR_EXAMPLE;
        V.clearErr("src-manifest-err");
      };

      el("src-activate-cancel").onclick = function () { V.dialog("src-activate-dialog").close(); };
      el("src-activate-go").onclick = activateManifest;
      el("src-activate-word").oninput = reflectActivateTyped;
      el("src-activate-who").oninput = reflectActivateTyped;

      el("src-window").addEventListener("change", function () { V.reload("sources"); });
      el("src-target").addEventListener("input", renderFreshness);

      if (!V.tenant()) renderNoTenant();
    },

    /* v2 AUTOLOAD — the router runs this when the tenant is known. */
    load: function (_section, tenant) { return refresh(tenant); },

    onShow: function () {
      var p = V.navParams();
      if (p && p.view === "connect" && V.tenant()) openMintDialog("");
      if (!V.tenant()) renderNoTenant();
    },
  });

  /* =========================================================== loading */

  function renderNoTenant() {
    el("src-state").innerHTML = V.stateChip("off", "no tenant");
    el("src-health").innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a tenant to see its sources</div>' +
        '<div class="et-body">Paste a tenant id in the session bar above, or mint a scope handle — the tenant fills in automatically and this screen loads itself.</div>' +
        '<div class="et-actions"><button class="primary" id="src-teach-mint">Mint a scope handle</button></div>' +
      "</div>";
    el("src-manifests").innerHTML = "";
    el("src-fresh").innerHTML = "";
    el("src-back").innerHTML = "";
    el("src-teach-mint").onclick = function () { V.openMint(); };
  }

  async function refresh(tenant) {
    tenantNow = tenant;
    V.clearErr("src-err");
    el("src-hint").innerHTML = "";
    el("src-state").innerHTML = V.stateChip("wait", "loading");
    var q = "tenant_id=" + encodeURIComponent(tenant);
    var results = await Promise.allSettled([
      V.api("/v1/admin/connector-status?" + q, { admin: true }),
      V.api("/v1/slo/freshness?" + q + "&window_hours=" + windowHours(), { admin: true }),
      V.api("/v1/admin/backfill?" + q, { admin: true }),
      V.api("/v1/manifests?" + q, { admin: true }),
    ]);
    var keys = ["status", "fresh", "backfill", "manifests"];
    data.errs = [];
    results.forEach(function (r, i) {
      if (r.status === "fulfilled") data[keys[i]] = Array.isArray(r.value) ? r.value : [];
      else { data[keys[i]] = []; data.errs.push(r.reason && r.reason.message ? r.reason.message : String(r.reason)); }
    });
    data.loadedAt = Date.now();
    renderAll();
  }

  function needsYou() {
    // The rail-pill count — derived from the SAME rows this panel renders:
    // drafts awaiting the human gate + failed catch-up runs. (Threshold
    // breaches are excluded on purpose: the threshold is a client-side knob.)
    var drafts = data.manifests.filter(function (m) { return m.status === "draft"; }).length;
    var failed = data.backfill.filter(function (b) { return String(b.state).toLowerCase() === "failed"; }).length;
    return drafts + failed;
  }

  function renderAll() {
    var needs = needsYou();
    V.setCount("sources", needs);
    var anything = data.status.length || data.fresh.length || data.backfill.length ||
                   data.manifests.length || pendingLocal.length;
    if (data.errs.length) {
      el("src-state").innerHTML = V.stateChip("fail", "couldn't load");
      V.err("src-err", new Error(data.errs.join("  |  ")));
      el("src-hint").innerHTML = hint401(data.errs);
    } else if (needs) {
      el("src-state").innerHTML = V.stateChip("attn", needs + " need" + (needs === 1 ? "s" : "") + " you");
    } else if (!anything) {
      el("src-state").innerHTML = V.stateChip("off", "nothing connected");
    } else {
      el("src-state").innerHTML = V.stateChip("ok", "syncing normally");
    }
    el("src-asof").textContent = "checked " + new Date().toTimeString().slice(0, 8);
    renderHealth();
    renderManifests();
    renderFreshness();
    renderBackfill();
  }

  /* =========================================================== health */

  function renderHealth() {
    var host = el("src-health");
    var freshBy = {};
    data.fresh.forEach(function (f) { freshBy[f.source] = f; });
    var backBy = {};
    data.backfill.forEach(function (b) { backBy[b.source] = b; });
    var hbBy = {};
    data.status.forEach(function (s) { hbBy[s.source] = s; });

    // Union of every source any endpoint knows about + this session's mints —
    // kills the old "no connectors" vs live-freshness self-contradiction.
    var names = {};
    data.status.forEach(function (s) { names[s.source] = 1; });
    data.fresh.forEach(function (f) { names[f.source] = 1; });
    data.backfill.forEach(function (b) { names[b.source] = 1; });
    pendingLocal.forEach(function (p) { if (!names[p.source]) names[p.source] = 2; });
    var sources = Object.keys(names).sort();

    if (!sources.length) {
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">No sources connected yet</div>' +
          '<div class="et-body">Verity ingests through minted <b>private URLs</b> (any system that can POST JSON) and manifest-driven connectors. ' +
            "Connect your first source — you get a copyable URL and a curl line to send the first payload with. An empty inventory is a real state, not an error.</div>" +
          '<div class="et-actions">' +
            '<button class="primary" id="src-teach-connect">Connect a source</button>' +
            '<button id="src-teach-manifest">Install a manifest</button>' +
          "</div>" +
        "</div>";
      el("src-teach-connect").onclick = function () { openMintDialog(""); };
      el("src-teach-manifest").onclick = openManifestDialog;
      return;
    }

    var body = sources.map(function (name) {
      var hb = hbBy[name];
      var fr = freshBy[name];
      var bf = backBy[name];
      var mintedOnly = names[name] === 2;
      var evAge = hb ? ageMs(hb.last_event_at) : null;
      var hbAge = hb ? ageMs(hb.updated_at) : null;
      var bfError = bf && bf.error ? bf.error : null;

      var stateCell, liveText;
      if (mintedOnly) {
        stateCell = V.stateChip("wait", "waiting for first delivery");
        liveText = "minted this session — nothing has arrived yet";
      } else {
        var lv = liveness(evAge, hbAge, bfError);
        stateCell = lv.chip;
        liveText = lv.text;
      }

      var searchable = fr && fr.p50_ms != null
        ? "typically searchable in <b>" + V.esc(V.fmtMs(fr.p50_ms)) + "</b>"
        : '<span class="ref">not measured in this window</span>';

      var notes = [];
      if (mintedOnly) {
        notes.push('<span class="ref">client-side row — shown here until the first payload or heartbeat arrives; refresh to re-check</span>');
      }
      if (!hb && fr && !mintedOnly) {
        notes.push('<span class="ref">alive per freshness; no heartbeat yet (connectors push those) — a telemetry gap, not a dead source</span>');
      }
      if (bfError) {
        notes.push(V.badge("catch-up failed", "b-conf-3") + ' <span class="note" style="margin-top:0">' + V.esc(bfError) + "</span>");
      }
      if (hb && hb.cursor) {
        notes.push('<span class="ref" title="opaque connector checkpoint — display only">checkpoint ' + V.esc(hb.cursor) + "</span>");
      }

      return "<tr>" +
        "<td><b>" + V.esc(name) + "</b>" +
          (mintedOnly && pendingLocal.some(function (p) { return p.source === name; })
            ? '<div class="ref">id ' + V.esc((pendingLocal.filter(function (p) { return p.source === name; })[0] || {}).webhook_id || "") + "</div>"
            : "") + "</td>" +
        "<td>" + stateCell + "</td>" +
        "<td>" + V.esc(liveText) + "</td>" +
        "<td>" + searchable + "</td>" +
        '<td class="num">' + fmtCount(hb ? hb.items_synced : null) + "</td>" +
        "<td>" + (notes.length ? notes.join("<br>") : '<span class="ref">—</span>') + "</td>" +
      "</tr>";
    }).join("");

    host.innerHTML =
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>source</th><th>state</th><th>what's happening</th>" +
        "<th>new data becomes searchable</th>" +
        '<th class="num">items synced</th><th>notes</th>' +
      "</tr></thead><tbody>" + body + "</tbody></table></div>" +
      '<div class="note">Heartbeat rows carry no permission lane or tier — the heartbeat does not report one, and this screen never guesses ' +
        "(a mislabeled lane is worse than an admitted unknown). Lanes are real, and explained, on the manifests below.</div>";
  }

  /* =========================================================== manifests */

  function renderManifests() {
    var host = el("src-manifests");
    var rows = data.manifests;
    if (!rows.length) {
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">No manifests installed</div>' +
          '<div class="et-body">Free-text in → a plain webhook (zero config). Structured records (tickets, deals, invoices) you want queryable field-by-field with permissions → a manifest: ' +
            "the recipe that tells Verity, per event, which field is the ID (so updates replace instead of duplicate), which fields become facts, which timestamp is the event time, and who may see each item. " +
            "Installing one creates a draft that never runs; a named human approves it in a separate step, on the record.</div>" +
          '<div class="et-actions"><button class="primary" id="src-m-teach">Install a manifest</button></div>' +
        "</div>";
      el("src-m-teach").onclick = openManifestDialog;
      return;
    }

    var drafts = rows.filter(function (m) { return m.status === "draft"; }).length;
    var body = rows.map(function (m, i) {
      var active = m.status === "active";
      var chip = active
        ? V.stateChip("ok", "active")
        : V.stateChip("attn", "awaiting your approval");
      var approver = active && m.approved_by
        ? "approved by <b>" + V.esc(m.approved_by) + "</b>"
        : (active ? '<span class="ref">approver not recorded</span>' : '<span class="ref">draft — never runs until approved</span>');
      var actions = active
        ? '<button class="src-m-use" data-i="' + i + '" title="opens the connect dialog with this manifest pre-selected">Connect a source with it</button>'
        : '<button class="good src-m-activate" data-i="' + i + '">Approve &amp; activate&hellip;</button>';
      return "<tr>" +
        "<td><b>" + V.esc(m.name) + "</b><div class=\"ref\">" + V.esc(m.manifest_id) + "</div></td>" +
        "<td>" + chip + "</td>" +
        "<td>" + V.esc(laneWords(m.acl_mode)) +
          '<div class="ref">acl_mode: ' + V.esc(m.acl_mode == null ? "unparsed" : m.acl_mode) +
          " · tier " + V.esc(m.tier == null ? "unstated" : m.tier) + "</div></td>" +
        "<td>" + approver + "</td>" +
        '<td><span class="ref" title="last change">' + V.esc(V.fmtTime(m.updated_at)) + "</span></td>" +
        "<td>" + actions + "</td>" +
      "</tr>";
    }).join("");

    host.innerHTML =
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>manifest</th><th>state</th><th>who can see its writes</th>" +
        "<th>approval</th><th>updated</th><th></th>" +
      "</tr></thead><tbody>" + body + "</tbody></table></div>" +
      (drafts ? "" :
        '<div class="note">Every installed manifest has crossed the human gate — nothing here runs unapproved.</div>');

    Array.prototype.forEach.call(host.querySelectorAll(".src-m-activate"), function (btn) {
      btn.onclick = function () { openActivateDialog(rows[Number(btn.getAttribute("data-i"))]); };
    });
    Array.prototype.forEach.call(host.querySelectorAll(".src-m-use"), function (btn) {
      btn.onclick = function () { openMintDialog(rows[Number(btn.getAttribute("data-i"))].manifest_id); };
    });
  }

  /* =========================================================== freshness */

  function renderFreshness() {
    var host = el("src-fresh");
    if (!host) return;
    var rows = data.fresh;
    var tgt = targetMs();
    if (!rows.length) {
      host.innerHTML =
        '<div class="empty">No freshness samples in the last ' + windowHours() +
        " hours. Nothing measured means no number — this screen shows the empty state rather than a fabricated percentile. " +
        "Samples appear automatically as soon as a source delivers data.</div>";
      return;
    }
    var body = rows.map(function (r) {
      var breach = tgt != null && r.p95_ms != null && r.p95_ms > tgt;
      // Honesty at tiny sample counts: below 10 samples a "percentile" is
      // not a distribution — say so, dimly, without hiding the row.
      var samplesCell = fmtCount(r.samples);
      if (r.samples != null && r.samples > 0 && r.samples < 10) {
        samplesCell += '<div class="ref">' + (r.samples === 1
          ? "1 sample — one measurement, not a distribution"
          : r.samples + " samples — at this count percentiles are just min/max") + "</div>";
      }
      return "<tr" + (breach ? ' class="flag"' : "") + ">" +
        "<td><b>" + V.esc(r.source) + "</b></td>" +
        '<td class="num">' + samplesCell + "</td>" +
        '<td class="num">' + pctCell(r.p50_ms, tgt) + "</td>" +
        '<td class="num">' + pctCell(r.p95_ms, tgt) + "</td>" +
        '<td class="num">' + pctCell(r.p99_ms, tgt) + "</td>" +
      "</tr>";
    }).join("");
    host.innerHTML =
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>source</th>" +
        '<th class="num">samples</th>' +
        '<th class="num">typical <span style="text-transform:none">(p50)</span></th>' +
        '<th class="num">slow <span style="text-transform:none">(p95)</span></th>' +
        '<th class="num">worst seen <span style="text-transform:none">(p99)</span></th>' +
      "</tr></thead><tbody>" + body + "</tbody></table></div>" +
      '<div class="note">Every number is computed from real samples on <b>this deployment</b> over the last ' + windowHours() +
      " hours — session-local measurements, <em>not the published benchmark</em>. A red row means a real p95 exceeded " +
      (tgt != null ? "your " + V.esc(V.fmtMs(tgt)) + " threshold" : "your threshold (unset)") +
      " — a console display setting, not a server-enforced SLO.</div>";
  }

  /* =========================================================== backfill */

  function backfillChip(state) {
    var s = String(state || "").toLowerCase();
    if (s === "running") return V.stateChip("wait", "running");
    if (s === "completed") return V.stateChip("ok", "completed");
    if (s === "failed") return V.stateChip("fail", "failed");
    if (s === "paused") return V.stateChip("off", "paused");
    return V.stateChip("off", s || "—");
  }

  function progressCell(run) {
    var state = String(run.state || "").toLowerCase();
    var total = run.total;
    var processed = run.processed || 0;
    if (total != null && total > 0) {
      var pct = Math.max(0, Math.min(100, (processed / total) * 100));
      var cls = (state === "completed" || state === "failed" || state === "paused") ? " " + state : "";
      return '<div class="bar' + cls + '"><i style="width:' + pct.toFixed(1) + '%"></i></div>' +
        '<span class="pct">' + pct.toFixed(1) + "% · " + V.esc(processed) + " / " + V.esc(total) + "</span>";
    }
    // No total → NEVER fabricate a percentage.
    return '<div class="bar indet"></div>' +
      '<span class="pct">' + V.esc(processed) + " done · total unknown</span>";
  }

  function etaCell(run) {
    var state = String(run.state || "").toLowerCase();
    var total = run.total, processed = run.processed || 0;
    if (state !== "running" || total == null || total <= 0 || processed <= 0 || processed >= total) {
      return '<span class="ref" title="a time-left estimate is shown only for a running job with a known total and forward progress">—</span>';
    }
    var elapsed = new Date(run.updated_at).getTime() - new Date(run.started_at).getTime();
    if (!(elapsed > 0)) return '<span class="ref">—</span>';
    var rate = processed / elapsed;
    if (!(rate > 0)) return '<span class="ref">—</span>';
    return '<span title="projected from processed/elapsed at the last heartbeat, as-of ' +
      V.esc(V.fmtTime(run.updated_at)) + '">~' + V.esc(V.fmtMs((total - processed) / rate)) + " left</span>";
  }

  function renderBackfill() {
    var host = el("src-back");
    var rows = data.backfill;
    if (!rows.length) {
      host.innerHTML =
        '<div class="empty">No catch-up imports have run for this tenant. Connectors report them as they replay history — nothing to show is a real state, not an error.</div>';
      return;
    }
    var body = rows.map(function (r) {
      return "<tr>" +
        "<td><b>" + V.esc(r.source) + "</b></td>" +
        "<td>" + backfillChip(r.state) + "</td>" +
        '<td style="min-width:180px">' + progressCell(r) + "</td>" +
        "<td>" + etaCell(r) + "</td>" +
        "<td>" + (r.error
          ? V.badge("error", "b-conf-3") + ' <span class="note" style="margin-top:0">' + V.esc(r.error) + "</span>"
          : '<span class="ref">—</span>') + "</td>" +
        '<td><span class="ref">' + V.esc(V.fmtTime(r.updated_at)) + "</span></td>" +
      "</tr>";
    }).join("");
    host.innerHTML =
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>source</th><th>state</th><th>progress</th><th>time left</th><th>error</th><th>updated</th>" +
      "</tr></thead><tbody>" + body + "</tbody></table></div>";
  }

  /* ================================================= connect (mint) flow */

  async function openMintDialog(manifestId) {
    if (!tenantNow) { V.openMint(); return; }
    V.clearErr("src-mint-err");
    el("src-mint-result").innerHTML = "";
    el("src-mint-go").disabled = false;

    // Manifest binding options from the SAME list the panel renders.
    var sel = el("src-mint-manifest");
    sel.innerHTML = '<option value="">no — plain JSON shape</option>' +
      data.manifests.map(function (m) {
        return '<option value="' + V.esc(m.manifest_id) + '">' +
          V.esc(m.name) + (m.status === "active" ? " (active)" : " (draft — quarantines until approved)") +
        "</option>";
      }).join("");
    if (manifestId) sel.value = manifestId;

    V.dialog("src-mint-dialog").open();

    // Entity-scope picker: emptyBehavior "hide" needs total_distinct before
    // first paint, so prime the shared directory cache at dialog-open (one
    // cheap admin GET — ENTITY-PICKER.md §2.2/§3). A fetch failure is the
    // picker's problem: it degrades to lint-only free entry with an honest
    // note, never a hidden field and never a fabricated count.
    try { await V.entityDirectory(tenantNow, {}); } catch (e) { /* degraded mode renders */ }
    if (!mintEntPicker) {
      mintEntPicker = V.entityPicker(el("src-mint-entities"), {
        mode: "scope",
        multiple: true,
        allowNew: true,
        emptyBehavior: "hide",
        placeholder: "account:acme",
        explainer: "every future payload from this source will be limited to these entities — for the life of the webhook. There is no edit later; only revoke and re-mint.",
        tenantId: function () { return tenantNow || V.tenant(); },
      });
    } else {
      mintEntPicker.clear();     // each mint starts from an explicit, empty limit
      mintEntPicker.refresh();
    }

    // Who-can-see picker: names from the principal directory, not bare ints.
    var box = el("src-mint-principals");
    box.innerHTML = '<span class="ref">loading the principal directory&hellip;</span>';
    try {
      var res = await V.api(
        "/v1/admin/principals?tenant_id=" + encodeURIComponent(tenantNow) + "&limit=1000",
        { admin: true });
      var list = (res && res.principals) || [];
      if (!list.length) {
        box.innerHTML = '<span class="ref">the principal directory is empty for this tenant — ' +
          "add people on the People &amp; groups screen, or use raw tokens below (dev mode)</span>";
      } else {
        box.innerHTML = list.map(function (p) {
          return '<label class="checkline" style="display:flex;margin:2px 0">' +
            '<input type="checkbox" class="src-mint-p" value="' + Number(p.token) + '"> ' +
            "<b>" + V.esc(p.principal) + "</b>" +
            '<span class="ref" style="margin-left:auto">#' + Number(p.token) + "</span>" +
          "</label>";
        }).join("");
      }
    } catch (e) {
      box.innerHTML = '<span class="ref">could not read the principal directory (' +
        V.esc((e && e.message) || e) + ") — enter raw tokens below</span>";
    }
  }

  async function mintWebhook() {
    V.clearErr("src-mint-err");
    var name = el("src-mint-name").value.trim();
    if (!name) {
      V.err("src-mint-err", new Error("give the source a name — it becomes the source label on every record it writes"));
      return;
    }
    var tokens = [];
    Array.prototype.forEach.call(document.querySelectorAll(".src-mint-p:checked"), function (cb) {
      tokens.push(Number(cb.value));
    });
    var raw = el("src-mint-raw").value.trim();
    if (raw) {
      var parsed = raw.split(",").map(function (s) { return s.trim(); }).filter(Boolean).map(Number);
      if (parsed.some(function (n) { return !Number.isInteger(n); })) {
        V.err("src-mint-err", new Error("raw principal tokens must be integers (comma-separated), e.g. 11, 1001"));
        return;
      }
      parsed.forEach(function (n) { if (tokens.indexOf(n) < 0) tokens.push(n); });
    }
    // No client-side default if empty: the server's 422 refusal IS the
    // teaching moment (fail closed — omission refuses), surfaced verbatim.
    var conf = el("src-mint-conf").value;
    if (!conf) {
      V.err("src-mint-err", new Error(
        "Choose a confidentiality ceiling — there is no default. " +
        "It caps how sensitive the memories this webhook writes can be."));
      return;
    }
    var body = {
      tenant_id: tenantNow,
      name: name,
      visibility: tokens,
      confidentiality: conf,
    };
    // Chips are the only submission path (ENTITY-PICKER.md §2.1). Empty
    // picker ⇒ field omitted — unbound, exactly as the bare input submitted
    // (fail-closed shape untouched: entity scope narrows, never grants).
    var ents = mintEntPicker ? mintEntPicker.value() : [];
    if (ents.length) body.entity_scope = ents;
    var mid = el("src-mint-manifest").value;
    if (mid) body.manifest_id = mid;

    var btn = el("src-mint-go");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/webhooks", { json: body, admin: true });
      var url = location.origin + res.url;
      var curl = "curl -X POST " + url + " \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"content\":\"Hello from " + name.replace(/'/g, "") + "\"}'";
      el("src-mint-result").innerHTML =
        '<div class="card" style="margin-top:12px;margin-bottom:0">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            V.stateChip("ok", "source connected") +
            '<span class="asof">secret URL — shown ONCE; Verity keeps only a fingerprint and can never show it again</span>' +
          "</div>" +
          '<textarea id="src-mint-url" readonly style="margin-top:8px;min-height:52px">' + V.esc(url) + "</textarea>" +
          '<div class="actions" style="justify-content:flex-start;margin-top:8px">' +
            '<button class="primary" id="src-mint-copy">Copy the URL</button>' +
            '<button id="src-mint-copy-curl">Copy a test curl</button>' +
          "</div>" +
          '<pre style="margin-top:8px;padding:8px 10px;border:1px solid var(--border);border-radius:var(--r-sm);overflow-x:auto;font-size:11.5px">' + V.esc(curl) + "</pre>" +
          '<div class="note">Save the webhook id ' + V.refSpan(res.webhook_id) +
            " — shutting this source off later needs it (the console cannot list webhooks yet). " +
            "The source appears in the table as <b>waiting for first delivery</b> until the first payload lands.</div>" +
        "</div>";
      el("src-mint-copy").onclick = function () {
        el("src-mint-url").select();
        try { navigator.clipboard.writeText(url); } catch (e) { document.execCommand("copy"); }
        el("src-mint-copy").textContent = "Copied";
      };
      el("src-mint-copy-curl").onclick = function () {
        try { navigator.clipboard.writeText(curl); } catch (e) { /* selection fallback below */ }
        el("src-mint-copy-curl").textContent = "Copied";
      };
      pendingLocal.push({ source: "webhook:" + name, webhook_id: res.webhook_id, mintedAt: Date.now() });
      renderHealth();
    } catch (e) {
      // Server refusals (empty visibility, unknown manifest) verbatim — the
      // refusal is the product speaking, not an error to soften.
      V.err("src-mint-err", e);
    } finally {
      btn.disabled = false;
    }
  }

  /* ================================================= revoke flow */

  function openRevokeDialog() {
    V.clearErr("src-revoke-err");
    el("src-revoke-id").value = "";
    el("src-revoke-word").value = "";
    el("src-revoke-go").disabled = true;
    V.dialog("src-revoke-dialog").open();
  }

  function reflectRevokeTyped() {
    el("src-revoke-go").disabled = !(
      el("src-revoke-word").value.trim() === "REVOKE" && el("src-revoke-id").value.trim()
    );
  }

  async function revokeWebhook() {
    V.clearErr("src-revoke-err");
    var id = el("src-revoke-id").value.trim();
    var btn = el("src-revoke-go");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/webhooks/" + encodeURIComponent(id), { method: "DELETE", admin: true });
      V.dialog("src-revoke-dialog").close();
      if (res && res.revoked) {
        receipt("ok", "Source shut off — the URL stopped resolving the moment you clicked. Already-ingested history is untouched (invalidate, never erase).");
      } else {
        receipt("attn", "Nothing was revoked — that id is unknown or was already shut off. An honest no-op, not a failure.");
      }
      pendingLocal = pendingLocal.filter(function (p) { return p.webhook_id !== id; });
      V.reload("sources");
    } catch (e) {
      V.err("src-revoke-err", e);
      btn.disabled = false;
    }
  }

  /* ================================================= manifest flows */

  function openManifestDialog() {
    V.clearErr("src-manifest-err");
    el("src-manifest-result").innerHTML = "";
    V.dialog("src-manifest-dialog").open();
  }

  async function installManifest() {
    V.clearErr("src-manifest-err");
    el("src-manifest-result").innerHTML = "";
    var yaml = el("src-manifest-yaml").value;
    if (!yaml.trim()) {
      V.err("src-manifest-err", new Error("paste the manifest YAML — the server validates it before anything is stored"));
      return;
    }
    var btn = el("src-manifest-go");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/manifests", { json: { tenant_id: tenantNow, yaml: yaml }, admin: true });
      var ready = res.activation_ready === true;
      el("src-manifest-result").innerHTML =
        '<div class="card" style="margin-top:12px;margin-bottom:0">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            V.stateChip("ok", "installed as a draft") +
            (ready
              ? V.stateChip("attn", "awaiting a human approval")
              : V.stateChip("attn", "not yet activatable")) +
          "</div>" +
          '<div class="note"><b>' + V.esc(res.name) + "</b> " + V.refSpan(res.manifest_id) +
            " — permission lane: " + V.esc(laneWords(res.acl_mode)) + ". " +
            (ready
              ? "It never runs until a named person approves it — the button is in the manifests table."
              : "The server pre-checked the gate and would refuse activation: <b>" +
                V.esc((res.activation_ready && res.activation_ready.refused) || "reason not stated") +
                "</b> — fix the YAML and re-install.") +
          "</div>" +
        "</div>";
      V.reload("sources");
    } catch (e) {
      // Validation refusals (bad YAML, schema violations) verbatim.
      V.err("src-manifest-err", e);
    } finally {
      btn.disabled = false;
    }
  }

  function openActivateDialog(m) {
    pendingActivate = m;
    V.clearErr("src-activate-err");
    el("src-activate-title").textContent = "Approve & activate “" + m.name + "”";
    el("src-activate-summary").innerHTML =
      '<div class="dc-evidence" style="margin-top:0"><b>What you are approving:</b> payloads from <b>' +
        V.esc(m.name) + "</b> will be indexed with the lane <b>" + V.esc(laneWords(m.acl_mode)) + "</b>." +
        '<div class="dc-meta" style="margin-top:6px">' + V.esc(m.manifest_id) +
        " · acl_mode: " + V.esc(m.acl_mode == null ? "unparsed" : m.acl_mode) +
        " · tier " + V.esc(m.tier == null ? "unstated" : m.tier) + "</div></div>";
    el("src-activate-who").value = "";
    el("src-activate-word").value = "";
    el("src-activate-go").disabled = true;
    V.dialog("src-activate-dialog").open();
  }

  function reflectActivateTyped() {
    el("src-activate-go").disabled = !(
      el("src-activate-word").value.trim() === "ACTIVATE" && el("src-activate-who").value.trim()
    );
  }

  async function activateManifest() {
    if (!pendingActivate) return;
    V.clearErr("src-activate-err");
    var who = el("src-activate-who").value.trim();
    var btn = el("src-activate-go");
    btn.disabled = true;
    try {
      var res = await V.api(
        "/v1/manifests/" + encodeURIComponent(pendingActivate.id || pendingActivate.manifest_id) + "/activate",
        { json: { tenant_id: tenantNow, approved_by: who }, admin: true });
      V.dialog("src-activate-dialog").close();
      receipt("ok",
        "<b>" + V.esc(res.name) + "</b> is live — approved by <b>" + V.esc(res.approved_by) +
        "</b>, recorded in the audit log. Payloads it maps start indexing on the next delivery.");
      V.reload("sources");
    } catch (e) {
      // The gate's refusal (absent acl_policy, tier violation) verbatim —
      // an approval the server won't take is a fact, not a UI failure.
      V.err("src-activate-err", e);
      btn.disabled = false;
    }
  }
})();
