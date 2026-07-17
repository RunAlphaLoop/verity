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
     connector-status · slo/freshness · backfill · manifests · folders ·
     admin/connectors (per-source connect readiness), allSettled so one
     failure never blanks the screen. GET /v1/admin/principals feeds the
     who-can-see picker in the connect dialog (names, not bare ints).

   Connect section (Phase 2): the zero-credential local-folder watch stays the
   fastest start, and each eligible source row now carries an "Add / rotate
   credential" control (POST /v1/admin/connectors/{source}/credential, gated by
   SecretIntakeAuth — bearer via Authorization header + same-origin Origin/CSRF,
   NEVER a cookie, 401 with no dev-open branch when VERITY_ADMIN_TOKEN is unset).
   The dialog is source-branched: tier-C (HubSpot/Salesforce) takes a masked
   bearer + the MANDATORY visibility picker (empty refused client-side AND by
   the server) + a live Test (HubSpot /crm/v3/owners); Google (Drive/Gmail/
   Directory) takes an SA-key PATH + subject (required gmail/gdirectory) + a
   STRUCTURAL SA-JSON Test (honestly labeled not-a-live-auth-test). The pasted
   token is NEVER echoed, NEVER kept in the DOM/JS after the request resolves,
   and the response echoes ONLY the salted-HMAC fingerprint. Backfill triggering
   is still Phase 3 — the per-source hint stays honest, never a button that 404s.
   The connectors row credential field flips from the Phase-1 observed state to
   tracked { kind, fingerprint } once a credential is stored.

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
    folders: [],    // watched local folders (live status per watch)
    connectors: [], // per-source connect readiness (Phase-1 read plane)
    connectorsAsOf: null, // the server's checked_at for those probes
    errs: [],       // per-read load failures (rendered, never hidden)
    loadedAt: 0,
  };
  // The who-can-see-it picker inside the Watch-a-folder dialog. Reused across
  // opens (destroyed/rebuilt each open so a stale tenant's names never linger).
  var folderViewersPicker = null;
  var pendingFolderStop = null; // { folder_id, source, path } for the stop dialog
  // Folder-onboarding fix: the register body held between the pre-flight preview
  // and the big-folder confirm (the actual register runs only on confirm — or
  // immediately when the count is below the threshold).
  var pendingFolderRegister = null; // { body, viewerNames, path, count }
  // Live INITIAL-SCAN tracking, keyed by folder_id (folder scans are keyed on a
  // server-minted run_id, but a folder can only have one in-flight scan at a
  // time, so folder_id is the stable UI key). Each entry owns ONE setInterval
  // whose handle lives here so it is cleared on terminal state, on Stop, on
  // tenant switch, and on panel teardown — no leaked polling.
  var folderScans = {}; // folder_id -> { run_id, folder_id, source, path, run, err, done, stopped, poll }
  // Above EITHER of these the UI requires an explicit big-folder confirm before
  // starting the scan (mirrors the server's own bounded pre-flight guard).
  var BIG_FOLDER_FILES = 200;
  var BIG_FOLDER_BYTES = 100 * 1024 * 1024; // 100 MB
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
  // Phase-2 credential dialog: the source being credentialed this open, its
  // credential class ("tierc" | "google"), whether a credential is already
  // stored (=> the flow is a rotate, not a first add), and the who-can-see
  // picker for tier-C (rebuilt each open so a stale tenant never lingers).
  var pendingCred = null; // { source, label, kind, cls, subjectRequired, rotate }
  var credViewersPicker = null;
  // Phase-3 backfill: the (source, label) being confirmed this open, and the
  // live runs triggered this session keyed by source. Each active run owns ONE
  // setInterval; the handle lives here so it is cleared on terminal state, on
  // panel teardown, and before a same-source re-trigger — no leaked polling.
  var pendingBackfill = null; // { source, label }
  var backfillRuns = {};      // source -> { run_id, source, label, poll, run, err, done }
  // Phase-4 continuous sync: the (source, label) being toggled this open. The
  // toggle is a stateless pair of POSTs + a reload — it owns NO setInterval, so
  // there is no leaked-interval concern here (the row's own sync state, polled
  // by the panel's normal reads, is the single source of truth).
  var pendingSync = null; // { source, label, kind }

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
  function liveness(evAge, hbAge, bfError, hasFresh) {
    if (bfError) {
      return { chip: V.stateChip("fail"), text: "catch-up import failed — see notes" };
    }
    var a = evAge != null ? evAge : hbAge;
    if (a == null) {
      if (hasFresh) {
        // Live freshness samples prove data is flowing — the missing
        // heartbeat is a telemetry gap (called out in notes), not a dead source.
        return {
          chip: V.stateChip("ok", "delivering"),
          text: "data is arriving and becoming searchable — the source hasn't sent a status report yet",
        };
      }
      // "age unknown" is reserved for a source with neither a heartbeat nor
      // freshness samples — never shows fake-fresh green.
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

  // Human byte size for the big-folder confirm ("16.0 GB"). Never fabricated —
  // fed only from the server's real (bounded) pre-flight byte count.
  function fmtBytes(n) {
    if (n == null) return "—";
    var b = Number(n);
    if (!(b >= 0)) return "—";
    if (b < 1024) return b + " B";
    var u = ["KB", "MB", "GB", "TB"], i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return (b < 10 ? b.toFixed(1) : Math.round(b)) + " " + u[i];
  }

  // Operator-set alert threshold (ms) — display highlighting only.
  function targetMs() {
    var f = el("src-target");
    if (!f) return null;
    var v = parseInt(f.value, 10);
    return isNaN(v) || v < 0 ? null : v;
  }

  // Friendly threshold unit — ONE formatter feeds both the input-side echo
  // and the freshness footer, so the two can never disagree on units again.
  function fmtThreshold(ms) {
    if (ms == null) return null;
    if (ms < 1000) return Math.round(ms) + " ms";
    if (ms < 60000) { var s = ms / 1000; return (s % 1 ? s.toFixed(1) : s) + " s"; }
    if (ms < 3600000) { var m = ms / 60000; return (m % 1 ? m.toFixed(1) : m) + " min"; }
    var h = ms / 3600000;
    return (h % 1 ? h.toFixed(1) : h) + " h";
  }

  // Live conversion beside the ms input, e.g. "900000 ms = 15 min".
  function reflectTarget() {
    var echo = el("src-target-echo");
    if (!echo) return;
    var t = targetMs();
    echo.textContent = t == null ? "no threshold set — rows are never flagged"
      : t < 1000 ? "" // sub-second ms needs no conversion
      : t + " ms = " + fmtThreshold(t);
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
          '<button id="src-folder-open" title="POST /v1/admin/folders — Verity watches a folder on this machine; files you drop in become memory">Watch a local folder&hellip;</button>' +
          '<button class="primary" id="src-connect-open" title="POST /v1/webhooks — mints a private URL any system can POST JSON to">Connect a source</button>' +
        "</div>" +
        '<div class="err" id="src-err"></div>' +
        '<div id="src-hint"></div>' +
        '<div id="src-receipt"></div>' +

        /* ---- fastest start: the zero-credential folder watch ---- */
        '<div class="card">' +
          '<h2>Fastest start: watch a local folder &mdash; no credential <span class="sub api-crumb">GET /v1/admin/folders</span></h2>' +
          '<div class="note" style="margin-top:0"><b>Point Verity at a folder on this machine and drop files in — each one becomes memory you can query.</b> ' +
            "Verity runs on this computer, so it can watch a folder here directly (your browser can&rsquo;t) &mdash; no credential, no connector setup. " +
            "Word docs, spreadsheets, slide decks, PDFs and plain text are read automatically; a file it can&rsquo;t read is still recorded, with the reason shown, never dropped silently. " +
            "You choose <b>who can see</b> the files in a folder when you add it &mdash; there is no default: a folder nobody could ever read is refused, not silently created.</div>" +
          '<div id="src-folders"></div>' +
        "</div>" +

        /* ---- connect a source: per-source readiness (Phase-1 read) ---- */
        '<div class="card">' +
          '<h2>Connect a source <span class="sub api-crumb">GET /v1/admin/connectors</span></h2>' +
          '<div class="note" style="margin-top:0"><b>Every source family Verity can ingest from, with exactly what this server can truthfully see about each.</b> ' +
            "Prerequisite checks are probed, never guessed; a worker chip is <b>server-authoritative</b> only when this server owns the process, otherwise it is <b>observed</b> from heartbeats. " +
            "You can now <b>add or rotate a credential</b> per source: CRM bearers are <b>encrypted at rest</b> under this space&rsquo;s key and the console keeps only a fingerprint &mdash; never the token; Google connectors store only the <b>path</b> to a service-account key file, never its contents. " +
            "Secret entry needs an admin token (it is refused unauthenticated). " +
            "<b>Continuous sync</b> (gdrive/gmail/hubspot) polls a source on an interval and writes memory until you turn it off &mdash; enabled only when a credential resolves, off by default; gdirectory&rsquo;s toggle maps to the directory plane. " +
            "The one zero-credential path is the local folder above.</div>" +
          // Live backfill strips (Phase 3): one per (source, run_id) triggered
          // this session. Rendered by the poller, NOT by the table re-render, so
          // an auto-refresh never wipes a run in flight.
          '<div id="src-backfill-live"></div>' +
          '<div id="src-connect"></div>' +
        "</div>" +

        /* ---- source health ---- */
        '<div class="card">' +
          '<h2>Your sources <span class="sub api-crumb">GET /v1/admin/connector-status · /v1/admin/backfill</span></h2>' +
          '<div id="src-health"></div>' +
        "</div>" +

        /* ---- manifests ---- */
        '<div class="card">' +
          '<h2>Manifests — how each source&rsquo;s permissions map in <span class="sub api-crumb">GET /v1/manifests</span></h2>' +
          '<div class="note" style="margin-top:0"><b>When you need one:</b> free-text in → a plain webhook (zero config). Structured records (tickets, deals, invoices) you want queryable field-by-field with permissions → a manifest. ' +
            "It is the recipe that tells Verity, per event: which field is the ID (so updates replace instead of duplicate), which fields become facts, which timestamp is the event time, and who may see each item — YAML because connectors are config you can review, diff, and approve. " +
            "Two lanes, labeled, never blurred: <b>mirrored</b> = the source&rsquo;s own permission lists are copied exactly; <b>assigned</b> = an admin chose who can see it. " +
            "Installing creates a <b>draft that never runs</b> — a named human must approve it in a separate step, and that approval is written to the audit log.</div>" +
          '<div id="src-manifests"></div>' +
        "</div>" +

        /* ---- freshness ---- */
        '<div class="card">' +
          '<h2>Ingest freshness — how fast new data becomes searchable <span class="sub api-crumb">GET /v1/slo/freshness</span></h2>' +
          '<div class="row" style="margin-top:0">' +
            '<div class="tight"><label for="src-window">measured over the last (hours)</label>' +
              '<input type="number" id="src-window" value="24" min="1" max="2160" style="width:110px"></div>' +
            '<div class="tight"><label for="src-target">alert me over (ms) <span style="font-weight:400">— your setting, not a server SLO</span></label>' +
              '<input type="number" id="src-target" value="900000" min="0" step="1000" style="width:130px" ' +
              'title="Set in this console for display highlighting only. The server enforces no SLO here; a red chip means a REAL measured percentile exceeded the number you typed.">' +
              '<div class="ref" id="src-target-echo"></div></div>' +
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
            '<div class="tight" style="min-width:170px"><label for="src-mint-conf">confidentiality ceiling <span style="font-weight:400">— the widest visibility this source may ever grant</span></label>' +
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
            "You need the <b>webhook id</b> from when the source was minted — the console cannot list webhooks yet, so keep it from the connect step.<span class=\"api-crumb\"> · listing them (GET /v1/webhooks) is on the roadmap</span></div>" +
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
          /* the what-is-a-manifest explainer lives ONCE, on the card intro */
          '<div class="note" style="margin-top:0">Paste (or start from the example below) — it is validated and stored as a <b>draft — it never runs</b> until a named human approves it in the separate activate step. ' +
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

        /* ---- watch a local folder ---- */
        '<div class="dialog-backdrop" id="src-folder-dialog"><div class="dialog" style="max-width:640px">' +
          "<h3>Watch a local folder</h3>" +
          '<div class="note" style="margin-top:0">Verity watches this folder on the machine it runs on. ' +
            "Every file you drop in is read and stored as memory, stamped with the visibility you choose below; " +
            "edit a file and the new version replaces the old. Hidden and half-written files (names starting with a dot, <span class=\"ref\">.tmp</span>, <span class=\"ref\">.swp</span>, editor backups) are skipped, and very large files are skipped with a note &mdash; nothing is ever indexed without a visibility you set.</div>" +
          '<div style="margin-top:12px"><label for="src-folder-path">folder on this machine <span style="font-weight:400">— an absolute path the server can reach</span></label>' +
            '<input type="text" id="src-folder-path" value="./verity-inbox" placeholder="./verity-inbox" autocomplete="off" spellcheck="false"></div>' +
          '<div class="note" style="margin-top:6px">Not sure? Leave <span class="ref">./verity-inbox</span> &mdash; Verity creates it beside the server if it doesn&rsquo;t exist, and you can drop files straight in. ' +
            "The path is where the server looks, not where your browser looks.</div>" +
          '<div style="margin-top:12px"><label>who can see the files in this folder <span style="font-weight:400">— pick the keys; there is no default</span></label>' +
            '<div id="src-folder-viewers" style="margin-top:6px"></div>' +
            '<div class="note" style="margin-top:6px">Every file this folder ingests is shared with exactly these keys &mdash; nothing wider. ' +
              'Leave it empty and Verity refuses to watch the folder, the same fail-closed rule every other write follows.<span class="api-crumb"> (GET /v1/admin/principals)</span></div>' +
          "</div>" +
          '<div class="row" style="margin-top:12px">' +
            '<div class="tight" style="min-width:200px"><label for="src-folder-conf">most sensitive these files may be <span style="font-weight:400">— the ceiling for this folder</span></label>' +
              '<select class="field" id="src-folder-conf">' +
                '<option value="" selected disabled>choose…</option>' +
                '<option value="Public">public</option>' +
                '<option value="Internal">internal</option>' +
                '<option value="Confidential">confidential</option>' +
                '<option value="Restricted">restricted</option>' +
              "</select></div>" +
          "</div>" +
          '<div class="err" id="src-folder-err"></div>' +
          '<div id="src-folder-result"></div>' +
          '<div class="actions">' +
            '<button id="src-folder-cancel">Close</button>' +
            '<button class="primary" id="src-folder-go">Start watching</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- stop watching a folder (typed confirm) ---- */
        '<div class="dialog-backdrop" id="src-folder-stop-dialog"><div class="dialog" style="max-width:560px">' +
          "<h3>Stop watching this folder</h3>" +
          '<div id="src-folder-stop-summary"></div>' +
          '<div class="note">Verity stops watching immediately &mdash; new files you drop in will no longer become memory. ' +
            "Files already ingested stay searchable (history is invalidated elsewhere, never erased here).</div>" +
          '<div style="margin-top:10px"><label for="src-folder-stop-word">type <b>STOP</b> to continue</label>' +
            '<input type="text" id="src-folder-stop-word" autocomplete="off" spellcheck="false"></div>' +
          '<div class="err" id="src-folder-stop-err"></div>' +
          '<div class="actions">' +
            '<button id="src-folder-stop-cancel">Cancel</button>' +
            '<button class="danger" id="src-folder-stop-go" disabled>Stop watching</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- big-folder pre-flight confirm (folder-onboarding fix) ---- */
        '<div class="dialog-backdrop" id="src-folder-big-dialog"><div class="dialog" style="max-width:600px">' +
          "<h3>This is a big folder</h3>" +
          '<div id="src-folder-big-summary"></div>' +
          '<div class="note" style="margin-top:0">Verity will <b>read and store the contents of these files as memory</b>, ' +
            "shared with exactly the keys you picked. It reads them in the background &mdash; you can watch progress and stop the scan at any point (already-read files stay). " +
            "The count above is a bounded pre-flight estimate; a <span class=\"ref\">&ge;</span> prefix means the real folder is bigger than we stopped counting.</div>" +
          '<div class="err" id="src-folder-big-err"></div>' +
          '<div class="actions">' +
            '<button id="src-folder-big-cancel">Cancel</button>' +
            '<button class="danger" id="src-folder-big-go">Read &amp; store these files</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- add / rotate a credential (Phase 2, source-branched) ---- */
        '<div class="dialog-backdrop" id="src-cred-dialog"><div class="dialog" style="max-width:640px">' +
          '<h3 id="src-cred-title">Add a credential</h3>' +
          '<div id="src-cred-summary"></div>' +
          // DEV teaching banner: shown only after a 401 proves the secret-write
          // surface is unauthenticated on this deployment (VERITY_ADMIN_TOKEN unset).
          '<div class="note" id="src-cred-dev" style="display:none;margin-top:10px"></div>' +

          /* ---- tier-C branch: HubSpot / Salesforce ---- */
          '<div id="src-cred-tierc" style="display:none">' +
            '<div class="note" style="margin-top:0">Paste the API bearer token for this CRM. ' +
              "It is <b>encrypted at rest</b> under this space&rsquo;s key the moment it is stored &mdash; the server keeps only a <b>fingerprint</b>, " +
              "never the token, and this console clears it from the page as soon as the request resolves. " +
              "You must also choose <b>who can see</b> the records this credential ingests: there is no default &mdash; an empty pick is refused here and by the server.</div>" +
            '<div style="margin-top:12px"><label for="src-cred-token">API token <span style="font-weight:400">— masked; never echoed back, never kept after Save</span></label>' +
              '<input type="password" id="src-cred-token" placeholder="paste the bearer token" autocomplete="off" spellcheck="false"></div>' +
            '<div style="margin-top:10px"><label>who can see what this credential ingests <span style="font-weight:400">— pick the keys; there is no default</span></label>' +
              '<div id="src-cred-viewers" style="margin-top:6px"></div>' +
              '<div class="note" style="margin-top:6px">These are the keys the records this credential ingests will be shared with once ingestion runs. ' +
                "It is required and checked now (an empty pick is refused, here and by the server), but connector ingestion isn&rsquo;t wired to it yet &mdash; that lands in a later phase, so nothing is ingested under it today. " +
                'Leave it empty and the store is refused, the same fail-closed rule every other write follows.<span class="api-crumb"> (GET /v1/admin/principals)</span></div>' +
            "</div>" +
          "</div>" +

          /* ---- Google branch: Drive / Gmail / Directory ---- */
          '<div id="src-cred-google" style="display:none">' +
            '<div class="note" style="margin-top:0">Google connectors authenticate with a <b>service-account key file</b>. ' +
              "This console stores only the <b>path</b> to that file on the machine the connector runs on &mdash; never the key contents. " +
              "The path is checked structurally (is it a readable SA-JSON with a client_email and private_key); that is <b>not a live auth test</b>.</div>" +
            '<div style="margin-top:12px"><label for="src-cred-path">service-account key path <span style="font-weight:400">— an absolute path the connector can read</span></label>' +
              '<input type="text" id="src-cred-path" placeholder="/etc/verity/sa-key.json" autocomplete="off" spellcheck="false"></div>' +
            '<div id="src-cred-subject-wrap" style="margin-top:10px;display:none"><label for="src-cred-subject">impersonation subject <span style="font-weight:400">— a Workspace admin address for domain-wide delegation</span></label>' +
              '<input type="text" id="src-cred-subject" placeholder="admin@corp.example" autocomplete="off" spellcheck="false">' +
              '<div class="note" style="margin-top:6px">Gmail and the directory read as a specific user &mdash; this subject is who. Required for these two; the server refuses without it.</div>' +
            "</div>" +
          "</div>" +

          '<div class="err" id="src-cred-err"></div>' +
          '<div id="src-cred-test-result"></div>' +
          '<div id="src-cred-result"></div>' +
          '<div class="actions">' +
            '<button id="src-cred-cancel">Close</button>' +
            '<button class="danger" id="src-cred-revoke" style="display:none">Remove credential</button>' +
            '<button id="src-cred-test">Test credential</button>' +
            '<button class="primary" id="src-cred-go">Save</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- run backfill (typed-tenant-NAME confirm · Phase 3) ---- */
        '<div class="dialog-backdrop" id="src-backfill-dialog"><div class="dialog" style="max-width:600px">' +
          '<h3 id="src-backfill-title">Run a catch-up import</h3>' +
          '<div id="src-backfill-summary"></div>' +
          '<div class="note" style="margin-top:0">This <b>replays this source&rsquo;s history</b> into Verity and writes <b>real memory</b> &mdash; ' +
            "a bi-temporal write that is invalidated later, never un-written. It runs as a one-shot full crawl on the server. " +
            "What it ingests is <b>not queryable the instant the bar turns green</b>: each item still has to resolve into entities behind the resolve debounce, so give it a moment after the crawl drains before you query or point an agent at it.</div>" +
          '<div style="margin-top:12px"><label for="src-backfill-word">to confirm this write, type the space name <b id="src-backfill-name"></b> exactly</label>' +
            '<input type="text" id="src-backfill-word" autocomplete="off" spellcheck="false"></div>' +
          '<div class="err" id="src-backfill-err"></div>' +
          '<div class="actions">' +
            '<button id="src-backfill-cancel">Cancel</button>' +
            '<button class="danger" id="src-backfill-go" disabled>Run backfill</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- turn ON continuous sync (cost-confirm · Phase 4) ---- */
        '<div class="dialog-backdrop" id="src-sync-dialog"><div class="dialog" style="max-width:600px">' +
          '<h3 id="src-sync-title">Turn on continuous sync</h3>' +
          '<div id="src-sync-summary"></div>' +
          '<div class="note" id="src-sync-blurb" style="margin-top:0"></div>' +
          '<div class="note" style="margin-top:8px"><b>This runs indefinitely until you turn it off.</b> ' +
            "Each cycle is a short incremental poll that advances the source&rsquo;s cursor and writes real memory &mdash; " +
            "the credential is resolved fresh per cycle, never left decrypted on disk between polls.</div>" +
          '<div style="margin-top:12px"><label for="src-sync-interval">poll every (seconds) <span style="font-weight:400">&mdash; how often Verity checks the source; minimum 60</span></label>' +
            '<input type="number" id="src-sync-interval" value="300" min="60" step="60" style="width:130px">' +
            '<div class="ref" id="src-sync-interval-echo"></div></div>' +
          '<div class="err" id="src-sync-err"></div>' +
          '<div class="actions">' +
            '<button id="src-sync-cancel">Cancel</button>' +
            '<button class="primary" id="src-sync-go">Start continuous sync</button>' +
          "</div>" +
        "</div></div>" +

        /* ---- turn OFF continuous sync (confirm · Phase 4) ---- */
        '<div class="dialog-backdrop" id="src-sync-off-dialog"><div class="dialog" style="max-width:560px">' +
          '<h3 id="src-sync-off-title">Turn off continuous sync</h3>' +
          '<div id="src-sync-off-summary"></div>' +
          '<div class="note" style="margin-top:0">Verity stops polling this source &mdash; no more automatic cycles. ' +
            "Any cycle already in flight finishes; nothing already ingested is removed (invalidate elsewhere, never erased here). " +
            "You can turn it back on anytime.<span class=\"api-crumb\"> POST /v1/admin/connectors/{source}/sync {enabled:false}</span></div>" +
          '<div class="err" id="src-sync-off-err"></div>' +
          '<div class="actions">' +
            '<button id="src-sync-off-cancel">Cancel</button>' +
            '<button class="danger" id="src-sync-off-go">Turn it off</button>' +
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

      el("src-folder-open").onclick = openFolderDialog;
      el("src-folder-cancel").onclick = function () { V.dialog("src-folder-dialog").close(); };
      el("src-folder-go").onclick = addFolder;
      el("src-folder-stop-cancel").onclick = function () { V.dialog("src-folder-stop-dialog").close(); };
      el("src-folder-stop-go").onclick = stopFolder;
      el("src-folder-stop-word").oninput = reflectFolderStopTyped;
      el("src-folder-big-cancel").onclick = function () { pendingFolderRegister = null; V.dialog("src-folder-big-dialog").close(); };
      el("src-folder-big-go").onclick = confirmBigFolder;

      el("src-cred-cancel").onclick = closeCredDialog;
      el("src-cred-test").onclick = testCredential;
      el("src-cred-go").onclick = saveCredential;
      el("src-cred-revoke").onclick = revokeCredential;

      el("src-backfill-cancel").onclick = function () { V.dialog("src-backfill-dialog").close(); };
      el("src-backfill-go").onclick = runBackfill;
      el("src-backfill-word").oninput = reflectBackfillTyped;

      el("src-sync-cancel").onclick = function () { V.dialog("src-sync-dialog").close(); };
      el("src-sync-go").onclick = enableSync;
      el("src-sync-interval").oninput = reflectSyncInterval;
      el("src-sync-off-cancel").onclick = function () { V.dialog("src-sync-off-dialog").close(); };
      el("src-sync-off-go").onclick = disableSync;

      el("src-activate-cancel").onclick = function () { V.dialog("src-activate-dialog").close(); };
      el("src-activate-go").onclick = activateManifest;
      el("src-activate-word").oninput = reflectActivateTyped;
      el("src-activate-who").oninput = reflectActivateTyped;

      el("src-window").addEventListener("change", function () { V.reload("sources"); });
      el("src-target").addEventListener("input", function () { reflectTarget(); renderFreshness(); });
      reflectTarget();

      if (!V.tenant()) renderNoTenant();
    },

    /* v2 AUTOLOAD — the router runs this when the tenant is known. */
    load: function (_section, tenant) { return refresh(tenant); },

    onShow: function () {
      var p = V.navParams();
      if (p && p.view === "connect" && V.tenant()) openMintDialog("");
      if (p && p.view === "folder" && V.tenant()) openFolderDialog();
      if (!V.tenant()) renderNoTenant();
    },
  });

  /* =========================================================== loading */

  function renderNoTenant() {
    // No space selected: tear down every live poll and drop the strips so no
    // interval outlives a screen that can't own a run (leaked-interval guard).
    stopAllBackfillPolls();
    backfillRuns = {};
    stopAllFolderScanPolls();
    folderScans = {};
    var live = el("src-backfill-live");
    if (live) live.innerHTML = "";
    el("src-state").innerHTML = V.stateChip("off", "no space");
    el("src-health").innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a space (tenant) to see its sources</div>' +
        '<div class="et-body">Paste a space id in the session bar above, or mint a scope handle (the signed key an agent reads with) — the space fills in automatically and this screen loads itself.</div>' +
        '<div class="et-actions"><button class="primary" id="src-teach-mint">Mint a scope handle</button></div>' +
      "</div>";
    el("src-folders").innerHTML = "";
    el("src-connect").innerHTML = "";
    el("src-manifests").innerHTML = "";
    el("src-fresh").innerHTML = "";
    el("src-back").innerHTML = "";
    el("src-teach-mint").onclick = function () { V.openMint(); };
  }

  async function refresh(tenant) {
    // A space switch orphans any in-flight strips (a run belongs to the space it
    // was triggered in) — tear their polls down before adopting the new tenant.
    if (tenantNow && tenant !== tenantNow) {
      stopAllBackfillPolls();
      backfillRuns = {};
      stopAllFolderScanPolls();
      folderScans = {};
      var live = el("src-backfill-live");
      if (live) live.innerHTML = "";
    }
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
      V.api("/v1/admin/folders?" + q, { admin: true }),
      V.api("/v1/admin/connectors?" + q, { admin: true }),
    ]);
    var keys = ["status", "fresh", "backfill", "manifests", "folders", "connectors"];
    data.errs = [];
    results.forEach(function (r, i) {
      if (r.status === "fulfilled") {
        // /v1/admin/folders returns { folders: [...] } and /v1/admin/connectors
        // returns { connectors: [...], checked_at }; the rest return arrays.
        var v = r.value;
        if (keys[i] === "folders") data.folders = (v && Array.isArray(v.folders)) ? v.folders : (Array.isArray(v) ? v : []);
        else if (keys[i] === "connectors") {
          data.connectors = (v && Array.isArray(v.connectors)) ? v.connectors : [];
          data.connectorsAsOf = (v && v.checked_at) || null;
        }
        else data[keys[i]] = Array.isArray(v) ? v : [];
      } else {
        data[keys[i]] = [];
        if (keys[i] === "connectors") data.connectorsAsOf = null;
        data.errs.push(r.reason && r.reason.message ? r.reason.message : String(r.reason));
      }
    });
    data.loadedAt = Date.now();
    renderAll();
  }

  function needsYou() {
    // The rail-pill count — derived from the SAME rows this panel renders:
    // drafts awaiting the human gate + failed catch-up runs + watched folders
    // that reported a problem. (Threshold breaches are excluded on purpose:
    // the threshold is a client-side knob.)
    var drafts = data.manifests.filter(function (m) { return m.status === "draft"; }).length;
    var failed = data.backfill.filter(function (b) { return String(b.state).toLowerCase() === "failed"; }).length;
    var folderProblems = data.folders.filter(function (f) { return !!f.last_error; }).length;
    // Connect readiness: only a configured-then-broken credential path counts
    // (the one attn chip that table renders); a never-configured source is a
    // setup state, not an incident.
    var credBroken = data.connectors.filter(function (c) { return credState(c).state === "path-missing"; }).length;
    return drafts + failed + folderProblems + credBroken;
  }

  function renderAll() {
    var needs = needsYou();
    V.setCount("sources", needs);
    var anything = data.status.length || data.fresh.length || data.backfill.length ||
                   data.manifests.length || data.folders.length || pendingLocal.length;
    if (data.errs.length) {
      el("src-state").innerHTML = V.stateChip("fail", "couldn't load");
      // Four reads failing the same way is ONE problem — dedupe before showing.
      var uniq = data.errs.filter(function (m, i) { return data.errs.indexOf(m) === i; });
      if (uniq.some(function (m) { return /HTTP 400/.test(m) && /UUID parsing failed/.test(m); })) {
        var ebox = el("src-err");
        ebox.innerHTML = "This space id isn't valid — Verity space ids are UUIDs " +
          "(they look like 019f53b8-…). Pick a real space in the session bar above." +
          '<div class="ref" style="margin-top:4px">' + V.esc(uniq.join("\n")) + "</div>";
        ebox.classList.add("on");
      } else {
        V.err("src-err", new Error(uniq.join("  |  ")));
      }
      el("src-hint").innerHTML = hint401(data.errs);
    } else if (needs) {
      el("src-state").innerHTML = V.stateChip("attn", needs + " need" + (needs === 1 ? "s" : "") + " you");
    } else if (!anything) {
      el("src-state").innerHTML = V.stateChip("off", "nothing connected");
    } else {
      el("src-state").innerHTML = V.stateChip("ok", "syncing normally");
    }
    el("src-asof").textContent = "checked " + new Date().toTimeString().slice(0, 8);
    renderFolders();
    renderConnectors();
    renderBackfillLive();
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
      var bfState = bf ? String(bf.state || "").toLowerCase() : "";
      // Belt-and-suspenders for the best-effort reconcile: a completed row still
      // carrying the raw degrade token in `error` means the reap's reconcile to
      // degraded_acl didn't land (transient DB fault) — treat it as degraded so a
      // coarsened crawl never paints a clean green success.
      if (bfState === "completed" && bf.error === "verity.backfill.degraded_acl") bfState = "degraded_acl";
      // A degraded_acl run is NOT a failure — it completed the full crawl but had
      // to coarsen owner/team ACLs to the admin-assigned visibility. Its `error`
      // column carries that honest note, so treat it as a failure ONLY when the
      // state is actually failed (never paint a clean degraded run red).
      var bfError = bf && bf.error && bfState === "failed" ? bf.error : null;
      var bfDegraded = bfState === "degraded_acl";
      var bfDegradedNote = bfDegraded && bf.error ? bf.error : null;

      var stateCell, liveText;
      if (mintedOnly) {
        stateCell = V.stateChip("wait", "waiting for first delivery");
        liveText = "minted this session — nothing has arrived yet";
      } else {
        var lv = liveness(evAge, hbAge, bfError, !!(fr && (fr.samples || fr.p50_ms != null)));
        stateCell = lv.chip;
        liveText = lv.text;
      }

      var searchable = fr && fr.p50_ms != null
        ? "typically searchable in <b>" + V.esc(V.fmtMs(fr.p50_ms)) + "</b>"
        : '<span class="ref">not measured in this window</span>';

      var notes = [];
      // Prose notes get word-break:normal inline — .ref's break-all is for
      // raw ids and would split words mid-word here (core.css stays frozen).
      var proseRef = '<span class="ref" style="word-break:normal;overflow-wrap:break-word">';
      if (mintedOnly) {
        notes.push(proseRef + 'client-side row — shown here until the first payload or heartbeat arrives; refresh to re-check</span>');
      }
      if (!hb && fr && !mintedOnly) {
        notes.push(proseRef + 'no status report from this source yet — freshness is measured from the data itself</span>');
      }
      if (bfError) {
        notes.push(V.badge("catch-up failed", "b-conf-3") + ' <span class="note" style="margin-top:0">' + V.esc(bfError) + "</span>");
      }
      if (bfDegraded) {
        // Honest, non-red: the crawl delivered every record but the fine-grained
        // owner/team ACLs were unavailable, so records use the admin-assigned
        // visibility policy. Never a silent success.
        notes.push(V.badge("ACLs coarsened", "b-conf-2") +
          ' <span class="note" style="margin-top:0">owner/team ACLs unavailable — using the admin-assigned visibility policy' +
          (bfDegradedNote ? " (" + V.esc(bfDegradedNote) + ")" : "") + "</span>");
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
        // overflow-wrap keeps long notes wrapping at word boundaries — never
        // mid-word (word-break:normal beats any inherited break-all).
        '<td style="overflow-wrap:break-word;word-break:normal;max-width:340px">' +
          (notes.length ? notes.join("<br>") : '<span class="ref">—</span>') + "</td>" +
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

  /* =========================================================== folders */

  // One plain-words liveness line for a watched folder. status is real server
  // state ("running" | "stopped"); a folder that reported an error surfaces it
  // verbatim (fail-visible), never a fake green.
  function folderChip(f) {
    if (f.last_error) return V.stateChip("fail", "problem");
    var s = String(f.status || "").toLowerCase();
    if (s === "stopped") return V.stateChip("off", "stopped");
    if (s === "running") return V.stateChip("ok", "watching");
    // Unknown/absent status: say so, never guess a green.
    return V.stateChip("wait", s || "starting");
  }

  function renderFolders() {
    var host = el("src-folders");
    if (!host) return;
    var rows = data.folders;
    if (!rows.length) {
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">No folders watched yet</div>' +
          '<div class="et-body">Pick a folder on this machine and Verity turns everything you drop in it into memory &mdash; ' +
            "the fastest way to get your own files in. You choose who can see them when you add the folder; there is no default. " +
            "An empty list is a real state, not an error.</div>" +
          '<div class="et-actions"><button class="primary" id="src-folder-teach">Watch a local folder</button></div>' +
        "</div>";
      var b = el("src-folder-teach");
      if (b) b.onclick = openFolderDialog;
      return;
    }

    var body = rows.map(function (f, i) {
      var evAge = ageMs(f.last_event_at);
      var lastChange = evAge != null ? humanAge(evAge)
        : '<span class="ref">no file yet</span>';
      var files = f.files_ingested != null ? f.files_ingested
        : (f.items_synced != null ? f.items_synced : null);
      var notes = [];
      var proseRef = '<span class="ref" style="word-break:normal;overflow-wrap:break-word">';
      if (f.last_error) {
        notes.push(V.badge("problem", "b-conf-3") + ' <span class="note" style="margin-top:0">' + V.esc(f.last_error) + "</span>");
      }
      if (String(f.status || "").toLowerCase() === "running" && files === 0 && evAge == null) {
        notes.push(proseRef + "watching &mdash; drop a file into this folder and it appears here on the next check</span>");
      }
      if (f.confidentiality) {
        notes.push('<span class="ref">ceiling: ' + V.esc(String(f.confidentiality).toLowerCase()) + "</span>");
      }
      var stopBtn = String(f.status || "").toLowerCase() === "stopped"
        ? '<span class="ref">stopped</span>'
        : '<button class="danger src-folder-stop" data-i="' + i + '">Stop&hellip;</button>';
      // A live initial-scan strip (folder-onboarding fix): when this folder has
      // a background scan tracked this session, it renders in a full-width row
      // below, keyed on the folder_id — the same strip the dialog shows.
      var fid = f.folder_id != null ? String(f.folder_id) : (f.id != null ? String(f.id) : "");
      var scanRow = (fid && folderScans[fid])
        ? '<tr class="src-folder-scan-holder"><td colspan="6" style="padding-top:0">' +
            '<div id="src-folder-scan-row-' + V.esc(fid) + '"></div></td></tr>'
        : "";
      return "<tr>" +
        '<td><b>' + V.esc(f.path || "(path not reported)") + "</b>" +
          (f.source ? '<div class="ref">' + V.esc(f.source) + "</div>" : "") + "</td>" +
        "<td>" + folderChip(f) + "</td>" +
        '<td class="num">' + fmtCount(files) + "</td>" +
        "<td>" + lastChange + "</td>" +
        '<td style="overflow-wrap:break-word;word-break:normal;max-width:320px">' +
          (notes.length ? notes.join("<br>") : '<span class="ref">&mdash;</span>') + "</td>" +
        "<td>" + stopBtn + "</td>" +
      "</tr>" + scanRow;
    }).join("");

    host.innerHTML =
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>folder on this machine</th><th>state</th>" +
        '<th class="num">files ingested</th><th>last change</th><th>notes</th><th></th>' +
      "</tr></thead><tbody>" + body + "</tbody></table></div>" +
      '<div class="note">Each watched folder also appears in <b>Your sources</b> below as ' +
        '<span class="ref">folder:&lt;name&gt;</span>, with the same freshness numbers as every other source &mdash; ' +
        "so &ldquo;how fast a dropped file becomes searchable&rdquo; is measured, not asserted.</div>";

    Array.prototype.forEach.call(host.querySelectorAll(".src-folder-stop"), function (btn) {
      btn.onclick = function () { openFolderStopDialog(rows[Number(btn.getAttribute("data-i"))]); };
    });

    // Paint any live initial-scan strips into their freshly-rendered row mounts
    // (renderFolders just replaced the DOM, so the row div is empty until now).
    Object.keys(folderScans).forEach(function (k) { renderFolderScan(k); });
  }

  /* ================================================ connect readiness */

  // Honest credential chip straight from the server's closed vocabulary. The
  // server never reads credential contents, so no chip here ever claims
  // "valid" — and CRM/Drive/Gmail credentials live in the connector CLI's
  // env, invisible to the server: reported "untracked", never guessed.
  // Normalize the credential field across Phase-1 (a bare string) and Phase-2
  // (an object: {state:"tracked",kind,fingerprint,updated_at} when a credential
  // is stored, else {state:<phase-1 word>}). Returns {state, kind, fingerprint,
  // updated_at} so every reader speaks one shape.
  function credState(c) {
    var cr = c.credential;
    if (cr && typeof cr === "object") {
      return {
        state: String(cr.state || ""),
        kind: cr.kind || null,
        fingerprint: cr.fingerprint || null,
        updated_at: cr.updated_at || null,
      };
    }
    return { state: String(cr || ""), kind: null, fingerprint: null, updated_at: null };
  }

  function connCredCell(c) {
    var cs = credState(c);
    var v = cs.state;
    var proseRef = '<span class="ref" style="word-break:normal;overflow-wrap:break-word">';
    if (v === "tracked") {
      // A credential is stored: show its kind + the salted-HMAC fingerprint —
      // NEVER a raw last-4 and never the secret. The token itself is unknowable
      // here (the server never returns it), so no chip claims "valid".
      return V.stateChip("ok", "stored") +
        '<div class="ref" style="word-break:normal;overflow-wrap:break-word">' +
          (cs.kind === "path" ? "SA-key path" : "bearer") +
          (cs.fingerprint ? " · " + V.esc(cs.fingerprint) : "") +
          (cs.updated_at ? " · " + V.esc(V.fmtTime(cs.updated_at)) : "") +
        "</div>";
    }
    if (v === "not-required") return V.stateChip("ok", "none needed");
    if (v === "untracked") {
      return V.stateChip("off", "none stored") +
        "<div>" + proseRef + "no credential stored here yet &mdash; add one with the button, or leave it in the connector CLI&rsquo;s env</span></div>";
    }
    if (v === "path-configured") {
      return V.stateChip("ok", "key path present") +
        "<div>" + proseRef + "path checked only &mdash; present does not mean valid</span></div>";
    }
    if (v === "path-missing") return V.stateChip("attn", "key path missing");
    if (v === "unset") return V.stateChip("off", "not set");
    // An unrecognized value is shown as-is, dimly — never mapped to a green.
    return V.stateChip("off", v || "—");
  }

  // Two-tier worker verdict, the server's own vocabulary: "on" exists only
  // with authority "server" (an owned live process); a recent heartbeat is
  // "unknown" — recent activity does NOT prove a worker is running now.
  function connWorkerCell(c) {
    var w = c.worker || {};
    var chip = w.status === "on" ? V.stateChip("ok", "running")
      : w.status === "unknown" ? V.stateChip("wait", "unknown")
      : V.stateChip("off", "off");
    var words = w.authority === "server" ? "server-authoritative"
      : w.authority === "observed"
        ? (w.status === "unknown"
            ? "heartbeat under 2 min ago &mdash; may have just finished, or be running elsewhere"
            : "observed from heartbeats")
        : "never seen for this space";
    return chip + '<div class="ref" style="word-break:normal;overflow-wrap:break-word">' + words + "</div>";
  }

  // The action cell obeys the no-dead-button rule: the live controls are the
  // zero-credential folder watch, the Phase-2 credential dialog, and — Phase 3 —
  // "Run backfill", ENABLED only when the server's own backfill.available is true
  // (gdrive/gmail with a resolvable credential). When it is false the honest
  // disabled state shows backfill.hint VERBATIM — never a button that would 4xx.
  // Which sources take a UI-entered credential (Phase 2). folder is
  // zero-credential; everything else in the registry does. Mirrors the server's
  // credential_class (folder => None, the rest => TierC/Google).
  function credEligible(source) { return source !== "folder"; }

  // The backfill portion of the action cell (Phase 3). available => an enabled
  // control that opens the typed-tenant-NAME confirm; else the server's hint
  // verbatim as an honest disabled state (a dimmed, non-clickable button so the
  // affordance reads the same, but it never fires). Never rendered for folder.
  function connBackfillControl(c) {
    var proseRef = '<span class="ref" style="word-break:normal;overflow-wrap:break-word">';
    var bf = c.backfill || {};
    var hint = bf.hint || "";
    if (bf.available) {
      return '<button class="primary src-conn-backfill" data-src="' + V.esc(c.source) + '" ' +
        'title="POST /v1/admin/connectors/' + V.esc(c.source) + '/backfill — replays this source’s history into real memory">' +
        "Run backfill&hellip;</button>" +
        (hint ? "<br>" + proseRef + V.esc(hint) + "</span>" : "");
    }
    // Honest disabled state — the hint says exactly why, and there is no live
    // button to click (fail-visible, never a dead trigger).
    return '<button class="src-conn-backfill-off" disabled title="backfill is not available for this source yet">Run backfill&hellip;</button>' +
      (hint ? "<br>" + proseRef + V.esc(hint) + "</span>" : "");
  }

  function connActionCell(c) {
    var proseRef = '<span class="ref" style="word-break:normal;overflow-wrap:break-word">';
    if (c.source === "folder") {
      return '<button class="primary src-conn-folder" title="POST /v1/admin/folders — the same watch-a-folder dialog as the card above">Watch a folder&hellip;</button>';
    }
    var parts = [];
    var failing = (c.prereqs || []).filter(function (q) { return !q.ok; });
    if (failing.length) {
      parts.push(failing.map(function (q) {
        return V.badge("missing: " + String(q.name || ""), "b-conf-3") +
          "<br>" + proseRef + V.esc(String(q.hint || "")) + "</span>";
      }).join("<br>"));
    } else {
      // gdrive/gmail/hubspot carry the Run-backfill control (enabled when the
      // server reports backfill.available, else the honest disabled state with
      // the exact hint). Every other source keeps its plain backfill note.
      if (c.backfill && (c.backfill.available ||
        String(c.source) === "gdrive" || String(c.source) === "gmail" ||
        String(c.source) === "hubspot")) {
        parts.push(connBackfillControl(c));
      } else {
        var hint = c.backfill && c.backfill.hint;
        if (hint) parts.push(proseRef + V.esc(hint) + "</span>");
      }
    }
    // Phase-2 credential control: add if none stored, rotate if one is. Rows
    // carry the source in data-src so the handler re-reads the fresh row.
    if (credEligible(c.source)) {
      var rotate = credState(c).state === "tracked";
      parts.push('<button class="src-conn-cred" data-src="' + V.esc(c.source) + '" ' +
        'title="POST /v1/admin/connectors/' + V.esc(c.source) + '/credential — encrypted at rest; the server keeps only a fingerprint">' +
        (rotate ? "Rotate credential&hellip;" : "Add credential&hellip;") + "</button>");
    }
    return parts.length ? parts.join("<br>") : '<span class="ref">—</span>';
  }

  function renderConnectors() {
    var host = el("src-connect");
    if (!host) return;
    var rows = data.connectors;
    if (!rows.length) {
      // The endpoint always answers with every source family — an empty list
      // here means the read itself failed (surfaced in the error strip at the
      // top), not "no connectors". Say so; never paint a fabricated table.
      host.innerHTML =
        '<div class="empty">Couldn&rsquo;t read connector readiness &mdash; see the error above. ' +
        "Nothing on this table is ever guessed, so there is nothing honest to show without the read.</div>";
      return;
    }
    var body = rows.map(function (c) {
      var hbCell = c.last_heartbeat
        ? '<span title="' + V.esc(V.fmtTime(c.last_heartbeat)) + '">' + humanAge(ageMs(c.last_heartbeat)) + "</span>"
        : '<span class="ref">never</span>';
      return "<tr>" +
        "<td><b>" + V.esc(c.label || c.source) + "</b>" +
          '<div class="ref">' + V.esc(c.source) + (c.kind ? " · " + V.esc(c.kind) : "") + "</div></td>" +
        "<td>" + connCredCell(c) + "</td>" +
        "<td>" + connWorkerCell(c) + "</td>" +
        "<td>" + hbCell + "</td>" +
        '<td style="overflow-wrap:break-word;word-break:normal;max-width:300px">' + connSyncCell(c) + "</td>" +
        '<td style="overflow-wrap:break-word;word-break:normal;max-width:360px">' + connActionCell(c) + "</td>" +
      "</tr>";
    }).join("");
    host.innerHTML =
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>source</th><th>credential</th><th>worker</th><th>last status report</th><th>continuous sync</th><th>next step</th>" +
      "</tr></thead><tbody>" + body + "</tbody></table></div>" +
      '<div class="note">Readiness checked ' +
        (data.connectorsAsOf ? "at " + V.esc(V.fmtTime(data.connectorsAsOf)) : "&mdash;") +
        " on the server. Prereq checks are existence probes &mdash; the server never reads a credential&rsquo;s contents, " +
        "so &ldquo;present&rdquo; never means &ldquo;valid&rdquo;.</div>";
    Array.prototype.forEach.call(host.querySelectorAll(".src-conn-folder"), function (btn) {
      btn.onclick = openFolderDialog;
    });
    Array.prototype.forEach.call(host.querySelectorAll(".src-conn-cred"), function (btn) {
      btn.onclick = function () {
        var src = btn.getAttribute("data-src");
        var row = data.connectors.filter(function (x) { return x.source === src; })[0];
        if (row) openCredDialog(row);
      };
    });
    Array.prototype.forEach.call(host.querySelectorAll(".src-conn-backfill"), function (btn) {
      btn.onclick = function () {
        var src = btn.getAttribute("data-src");
        var row = data.connectors.filter(function (x) { return x.source === src; })[0];
        if (row) openBackfillDialog(row);
      };
    });
    Array.prototype.forEach.call(host.querySelectorAll(".src-conn-sync-on"), function (btn) {
      btn.onclick = function () {
        var src = btn.getAttribute("data-src");
        var row = data.connectors.filter(function (x) { return x.source === src; })[0];
        if (row) openSyncDialog(row);
      };
    });
    Array.prototype.forEach.call(host.querySelectorAll(".src-conn-sync-off"), function (btn) {
      btn.onclick = function () {
        var src = btn.getAttribute("data-src");
        var row = data.connectors.filter(function (x) { return x.source === src; })[0];
        if (row) openSyncOffDialog(row);
      };
    });
    Array.prototype.forEach.call(host.querySelectorAll(".src-conn-sync-dir"), function (btn) {
      btn.onclick = function () {
        var on = btn.getAttribute("data-on") === "1";
        toggleDirectorySync(on);
      };
    });
  }

  /* ========================================= continuous sync (Phase 4) */

  // The continuous-sync cell for one connector row. The model: a per-(tenant,
  // source) SCHEDULER that fires a short incremental --once poll on an interval,
  // durable in sync_schedules + re-armed on boot. Sources & their toggle:
  //   • gdrive/gmail/hubspot — a native schedule. The toggle is ENABLED only when
  //     the server reports backfill.available (a resolvable credential + hubspot
  //     visibility + gmail subject); otherwise an HONEST disabled state showing
  //     the exact precondition hint (never a dead toggle that would 422).
  //   • gdirectory — no connector schedule; its continuous sync IS the directory
  //     plane, so its toggle maps to the directory worker start/stop (reused),
  //     keyed off the row's own worker chip for the current on/off state.
  //   • folder/salesforce — not applicable; the server's sync.hint verbatim.
  // The live state ("syncing every 5m · last synced 2m ago" / "off") comes
  // straight from the row's sync:{enabled,interval_secs,last_run_at}. After a
  // toggle the panel reloads, so the row re-reads its own truth — no dead state.
  function connSyncCell(c) {
    var proseRef = '<span class="ref" style="word-break:normal;overflow-wrap:break-word">';
    var sync = c.sync || {};

    // gdirectory: map to the directory plane. The row's worker chip is the live
    // on/off truth (status "on" => an owned live directory child).
    if (c.source === "gdirectory") {
      var w = c.worker || {};
      var running = w.status === "on";
      var dirState = running
        ? V.stateChip("ok", "syncing") +
            '<div class="ref" style="word-break:normal;overflow-wrap:break-word">directory worker reconciling on a loop</div>'
        : V.stateChip("off", "off");
      var dirBtn = running
        ? '<button class="danger src-conn-sync-dir" data-on="1" title="POST /v1/admin/planes/directory/stop">Sync (continuous): on &mdash; turn off</button>'
        : '<button class="src-conn-sync-dir" data-on="0" title="POST /v1/admin/planes/directory/start — gdirectory’s continuous sync is the directory plane">Sync (continuous)&hellip;</button>';
      return dirState + '<div style="margin-top:6px">' + dirBtn + "</div>" +
        "<div>" + proseRef + "continuous sync for the directory is the directory plane, not a poll schedule</span></div>";
    }

    // folder / salesforce (sync.eligible === false): honest not-applicable, the
    // server's own hint verbatim. No toggle — there is nothing to arm.
    if (!sync.eligible) {
      return V.stateChip("off", "not applicable") +
        (sync.hint ? "<div>" + proseRef + V.esc(sync.hint) + "</span></div>" : "");
    }

    // gdrive / gmail / hubspot: a native schedule. When enabled, show the live
    // cadence + last-sync + a turn-off control. When off, a Sync toggle that
    // opens the cost-confirm — ENABLED only when a credential is resolvable
    // (backfill.available), else the honest disabled state with the reason.
    if (sync.enabled) {
      var every = sync.interval_secs != null
        ? "syncing every " + V.esc(V.fmtAge(sync.interval_secs))
        : "syncing";
      var last = sync.last_run_at
        ? " &middot; last synced " + V.esc(humanAge(ageMs(sync.last_run_at)))
        : " &middot; no cycle has run yet";
      return V.stateChip("ok", "on") +
        '<div class="ref" style="word-break:normal;overflow-wrap:break-word">' + every + last + "</div>" +
        '<div style="margin-top:6px"><button class="danger src-conn-sync-off" data-src="' + V.esc(c.source) + '" ' +
          'title="POST /v1/admin/connectors/' + V.esc(c.source) + '/sync {enabled:false}">Sync (continuous): on &mdash; turn off</button></div>';
    }

    // Off. The toggle is enabled only when the credential resolves.
    var bf = c.backfill || {};
    if (bf.available) {
      return V.stateChip("off", "off") +
        '<div style="margin-top:6px"><button class="src-conn-sync-on" data-src="' + V.esc(c.source) + '" ' +
          'title="POST /v1/admin/connectors/' + V.esc(c.source) + '/sync — polls the source on an interval and writes memory until turned off">' +
          "Sync (continuous)&hellip;</button></div>";
    }
    // No resolvable credential: an honest disabled toggle (dimmed, non-firing),
    // the exact precondition hint from the server — never a toggle that 422s.
    return V.stateChip("off", "off") +
      '<div style="margin-top:6px"><button class="src-conn-sync-on-off" disabled ' +
        'title="add a credential first — continuous sync needs a resolvable credential">Sync (continuous)&hellip;</button></div>' +
      (bf.hint ? "<div>" + proseRef + V.esc(bf.hint) + "</span></div>" : "");
  }

  function reflectSyncInterval() {
    var echo = el("src-sync-interval-echo");
    if (!echo) return;
    var v = parseInt(el("src-sync-interval").value, 10);
    if (isNaN(v)) { echo.textContent = ""; return; }
    if (v < 60) { echo.textContent = "below the 60s floor — continuous sync won't hammer a source; use 60s or more"; return; }
    echo.textContent = "polls every " + V.fmtAge(v);
  }

  function openSyncDialog(row) {
    if (!tenantNow) { V.openMint(); return; }
    // Re-check the precondition so a stale row can never open a doomed confirm.
    if (!(row && row.backfill && row.backfill.available)) return;
    pendingSync = { source: row.source, label: row.label || row.source, kind: row.kind || null };
    V.clearErr("src-sync-err");
    el("src-sync-title").textContent = "Turn on continuous sync for " + pendingSync.label;
    el("src-sync-summary").innerHTML =
      '<div class="dc-evidence" style="margin-top:0"><b>' + V.esc(pendingSync.label) + "</b>" +
        '<div class="dc-meta" style="margin-top:6px">' + V.esc(pendingSync.source) +
        (pendingSync.kind ? " · " + V.esc(pendingSync.kind) : "") +
        " &middot; space " + V.esc(confirmToken()) + "</div></div>";
    el("src-sync-blurb").innerHTML =
      "Verity will poll <b>" + V.esc(pendingSync.label) + "</b> every <b id=\"src-sync-blurb-interval\">5m</b> " +
      "and write memory continuously until you turn this off.";
    el("src-sync-interval").value = "300";
    reflectSyncInterval();
    syncBlurbInterval();
    el("src-sync-interval").oninput = function () { reflectSyncInterval(); syncBlurbInterval(); };
    el("src-sync-go").disabled = false;
    V.dialog("src-sync-dialog").open();
  }

  // Keep the plain-words "every N" in the cost blurb in step with the input.
  function syncBlurbInterval() {
    var span = el("src-sync-blurb-interval");
    if (!span) return;
    var v = parseInt(el("src-sync-interval").value, 10);
    span.textContent = (isNaN(v) || v < 60) ? "5m" : V.fmtAge(v);
  }

  async function enableSync() {
    if (!pendingSync) return;
    V.clearErr("src-sync-err");
    var v = parseInt(el("src-sync-interval").value, 10);
    if (isNaN(v) || v < 60) {
      // Mirror the server's own 60s floor client-side — a sub-floor value is a
      // clean refusal here (and the server 422s it too), never a silent clamp.
      V.err("src-sync-err", new Error(
        "poll interval must be at least 60 seconds — continuous sync must never hammer a source API."));
      return;
    }
    var source = pendingSync.source;
    var btn = el("src-sync-go");
    btn.disabled = true;
    try {
      var res = await V.api(
        "/v1/admin/connectors/" + encodeURIComponent(source) + "/sync",
        { json: { tenant_id: tenantNow, enabled: true, interval_secs: v }, admin: true });
      V.dialog("src-sync-dialog").close();
      pendingSync = null;
      var every = res && res.interval_secs != null ? V.fmtAge(res.interval_secs) : "the chosen interval";
      var warn = res && res.warning
        ? " " + V.badge("double-poll", "b-conf-3") + " " + V.esc(res.warning)
        : "";
      receipt("ok",
        "Continuous sync is <b>on</b> for <b>" + V.esc(source) + "</b> &mdash; Verity polls it every <b>" +
        V.esc(every) + "</b> and writes memory until you turn it off." + warn);
      V.reload("sources");
    } catch (e) {
      // Server refusals verbatim — 422 (sub-floor interval / unresolvable
      // credential / missing hubspot visibility / gmail subject), 404 (unknown
      // tenant/source), 409 (busy). The refusal is the product speaking.
      V.err("src-sync-err", e);
      btn.disabled = false;
    }
  }

  function openSyncOffDialog(row) {
    if (!tenantNow) { V.openMint(); return; }
    pendingSync = { source: row.source, label: row.label || row.source, kind: row.kind || null };
    V.clearErr("src-sync-off-err");
    el("src-sync-off-title").textContent = "Turn off continuous sync for " + pendingSync.label;
    el("src-sync-off-summary").innerHTML =
      '<div class="dc-evidence" style="margin-top:0"><b>' + V.esc(pendingSync.label) + "</b>" +
        '<div class="dc-meta" style="margin-top:6px">' + V.esc(pendingSync.source) + "</div></div>";
    V.dialog("src-sync-off-dialog").open();
  }

  async function disableSync() {
    if (!pendingSync) return;
    V.clearErr("src-sync-off-err");
    var source = pendingSync.source;
    var btn = el("src-sync-off-go");
    btn.disabled = true;
    try {
      await V.api(
        "/v1/admin/connectors/" + encodeURIComponent(source) + "/sync",
        { json: { tenant_id: tenantNow, enabled: false }, admin: true });
      V.dialog("src-sync-off-dialog").close();
      pendingSync = null;
      receipt("ok",
        "Continuous sync is <b>off</b> for <b>" + V.esc(source) + "</b> &mdash; no more automatic polls. " +
        "Any cycle already in flight finishes; nothing already ingested is removed.");
      V.reload("sources");
    } catch (e) {
      V.err("src-sync-off-err", e);
      btn.disabled = false;
    }
  }

  // gdirectory's Sync toggle maps to the existing directory plane (reused, never
  // duplicated). on=true means it is currently running => stop; else start.
  async function toggleDirectorySync(on) {
    if (!tenantNow) { V.openMint(); return; }
    var path = on ? "stop" : "start";
    try {
      var res = await V.api("/v1/admin/planes/directory/" + path,
        { json: { tenant_id: tenantNow }, admin: true });
      if (on) {
        if (res && res.stopped === false) {
          // The stop endpoint returns 200 {stopped:false, note:...} when THIS
          // console doesn't own the worker (it was started elsewhere, e.g.
          // verity-cli dev --directory). Surfacing a flat "stopped" success here
          // would be a dishonest receipt on a control that was a no-op — show the
          // server's honest note instead. Mirrors the start-path already_running.
          receipt("attn", V.esc(res.note || "Nothing to stop — this console doesn't own the directory worker."));
        } else {
          receipt("ok", "Directory sync <b>stopped</b> &mdash; the directory worker is no longer reconciling.");
        }
      } else if (res && res.already_running) {
        receipt("attn", "Directory sync was <b>already running</b> &mdash; an honest no-op, not a failure.");
      } else {
        receipt("ok", "Directory sync <b>started</b> &mdash; the directory worker reconciles the full directory on a loop until stopped.");
      }
      V.reload("sources");
    } catch (e) {
      // The directory plane's own refusal verbatim — 422 (missing repo/venv),
      // 503 (missing SA key / subject / spawn), each with the exact fix.
      receipt("attn", "Couldn&rsquo;t toggle directory sync: " + V.esc((e && e.message) || String(e)));
    }
  }

  /* ================================================= watch-folder flow */

  async function openFolderDialog() {
    if (!tenantNow) { V.openMint(); return; }
    V.clearErr("src-folder-err");
    el("src-folder-result").innerHTML = "";
    el("src-folder-go").disabled = false;
    pendingFolderRegister = null;
    if (!el("src-folder-path").value.trim()) el("src-folder-path").value = "./verity-inbox";
    el("src-folder-conf").value = "";
    V.dialog("src-folder-dialog").open();

    // Who-can-see-it: the SAME named picker the manifest wizard uses — pick
    // keys from the directory, never raw tokens, never a default (LAW: fail
    // closed). Rebuilt each open so a prior tenant's names never linger.
    var mount = el("src-folder-viewers");
    if (folderViewersPicker) { folderViewersPicker.destroy(); folderViewersPicker = null; }
    folderViewersPicker = V.principalPicker(mount, {
      tenantId: function () { return tenantNow || V.tenant(); },
      placeholder: "filter people & groups",
      emptyTitle: "No people or groups on record yet",
      emptyBody: "Add people or groups to this space first, then pick who can see this folder's files.",
      emptyAction: "Open People & groups",
      onOpenDirectory: function () { V.show("principals"); },
    });
    folderViewersPicker.load(tenantNow);
  }

  // Start watching, in three honest steps (folder-onboarding fix):
  //   1. hit GET /v1/admin/folders/preview for a BOUNDED file/byte count;
  //   2. above a threshold, require an explicit big-folder confirm — otherwise
  //      register straight away;
  //   3. POST /v1/admin/folders (returns FAST with a run_id) and start the live
  //      progress strip keyed on that run_id.
  // The register no longer blocks on ingesting every existing file — that scan
  // runs in the background on the server; here we only kick it off and watch it.
  async function addFolder() {
    V.clearErr("src-folder-err");
    el("src-folder-result").innerHTML = "";
    var path = el("src-folder-path").value.trim();
    if (!path) {
      V.err("src-folder-err", new Error("give a folder path on this machine — e.g. ./verity-inbox"));
      return;
    }
    // No client-side default: an empty pick is refused right here, mirroring
    // the server's own fail-closed refusal (never a permissive default).
    var viewers = folderViewersPicker ? folderViewersPicker.value() : [];
    if (!viewers.length) {
      V.err("src-folder-err", new Error(
        "Pick who can see this folder's files — there is no default. " +
        "A folder whose files nobody could ever read is refused, not silently watched."));
      return;
    }
    var conf = el("src-folder-conf").value;
    if (!conf) {
      V.err("src-folder-err", new Error(
        "Choose how sensitive these files may be — there is no default. " +
        "It caps the visibility any file in this folder can carry."));
      return;
    }
    var body = {
      tenant_id: tenantNow,
      path: path,
      visibility: viewers.map(function (v) { return v.token; }),
      confidentiality: conf,
    };
    var viewerNames = viewers.map(function (v) { return v.principal; }).join(", ");
    pendingFolderRegister = { body: body, viewerNames: viewerNames, path: path, count: null };

    var btn = el("src-folder-go");
    btn.disabled = true;
    try {
      // Bounded pre-flight count so a huge tree can't be silently ingested — and
      // so the count itself never hangs (the server caps the walk). A preview
      // failure (unreadable path / path-is-file) is a real refusal, surfaced
      // verbatim; we do NOT register a folder the server can't read.
      var pre = await V.api(
        "/v1/admin/folders/preview?tenant_id=" + encodeURIComponent(tenantNow) +
          "&path=" + encodeURIComponent(path),
        { admin: true });
      pendingFolderRegister.count = pre;
      var files = pre && pre.files != null ? Number(pre.files) : 0;
      var bytes = pre && pre.bytes != null ? Number(pre.bytes) : 0;
      var big = files > BIG_FOLDER_FILES || bytes > BIG_FOLDER_BYTES ||
        (pre && pre.capped); // capped => at least the cap; treat as big
      if (big) {
        // Hand off to the explicit confirm — the register runs only on confirm.
        openBigFolderConfirm(pre);
        btn.disabled = false;
        return;
      }
      // Below threshold: proceed straight to a fast register + live strip.
      await registerFolder();
      // Re-enable so another folder can be added without reopening — the just-
      // registered scan lives on independently in its own strip.
      btn.disabled = false;
    } catch (e) {
      // Server refusals (empty visibility, unreadable path) surface verbatim —
      // the refusal is the product speaking, not an error to soften.
      V.err("src-folder-err", e);
      btn.disabled = false;
    }
  }

  // The big-folder confirm: an EXPLICIT "this folder has ~N files (X) — Verity
  // will read and store their contents as memory; continue?" gate. The register
  // fires only when the operator confirms here.
  function openBigFolderConfirm(count) {
    V.clearErr("src-folder-big-err");
    var files = count && count.files != null ? Number(count.files) : 0;
    var bytes = count && count.bytes != null ? Number(count.bytes) : 0;
    var ge = count && count.capped ? "&ge;&thinsp;" : "~";
    el("src-folder-big-summary").innerHTML =
      '<div class="dc-evidence" style="margin-top:0"><b>' +
        V.esc((pendingFolderRegister && pendingFolderRegister.path) || "this folder") + "</b>" +
        ' has ' + ge + "<b>" + V.esc(files) + "</b> file" + (files === 1 ? "" : "s") +
        " (" + ge + "<b>" + V.esc(fmtBytes(bytes)) + "</b>)." +
      "</div>";
    el("src-folder-big-go").disabled = false;
    V.dialog("src-folder-big-dialog").open();
  }

  async function confirmBigFolder() {
    if (!pendingFolderRegister) { V.dialog("src-folder-big-dialog").close(); return; }
    V.clearErr("src-folder-big-err");
    var btn = el("src-folder-big-go");
    btn.disabled = true;
    try {
      // The operator has confirmed the big folder — carry the explicit ack the
      // server's own big-folder guard requires (below threshold this field is
      // never set, so the guard only ever waves through a small folder silently).
      pendingFolderRegister.body.acknowledge_large = true;
      await registerFolder();
      V.dialog("src-folder-big-dialog").close();
    } catch (e) {
      V.err("src-folder-big-err", e);
      btn.disabled = false;
    }
  }

  // POST /v1/admin/folders — returns FAST with a server-minted run_id for the
  // background initial scan. Renders the live strip in the dialog result and
  // begins polling GET /v1/admin/backfill on that run_id. Throws on a server
  // refusal so the caller can surface it in the right error slot.
  async function registerFolder() {
    if (!pendingFolderRegister) return;
    var reg = pendingFolderRegister;
    var res = await V.api("/v1/admin/folders", { json: reg.body, admin: true });
    var source = (res && res.source) || "folder:…";
    var folderId = res && res.folder_id;
    el("src-folder-result").innerHTML =
      '<div class="card" style="margin-top:12px;margin-bottom:0">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          V.stateChip("ok", "watching") +
          '<span class="asof">' + V.esc((res && res.path) || reg.path) + "</span>" +
        "</div>" +
        '<div class="note" style="margin-top:8px"><b>Watching this folder.</b> ' +
          "Existing files are being read in the background now; new files you drop in become memory too. " +
          "Everything is shared with <b>" + V.esc(reg.viewerNames) + "</b> and nobody wider. " +
          "The folder appears in <b>Your sources</b> as " +
          '<span class="ref">' + V.esc(source) + "</span>." +
          ((res && res.created) ? " Verity created the folder for you." : "") + "</div>" +
        // The live initial-scan strip renders here, keyed on the run_id.
        '<div id="src-folder-scan-' + V.esc(String(folderId)) + '"></div>' +
      "</div>";
    // Track the background initial scan (only when the server minted a run_id;
    // an already-existing re-register still returns one).
    if (folderId && res && res.run_id) {
      startFolderScanTracking(folderId, source, reg.path, res.run_id);
    }
    pendingFolderRegister = null;
    V.reload("sources");
  }

  function openFolderStopDialog(f) {
    pendingFolderStop = f;
    V.clearErr("src-folder-stop-err");
    el("src-folder-stop-summary").innerHTML =
      '<div class="dc-evidence" style="margin-top:0"><b>Stop watching:</b> <b>' +
        V.esc(f.path || "(folder)") + "</b>" +
        (f.source ? '<div class="dc-meta" style="margin-top:6px">' + V.esc(f.source) + "</div>" : "") +
      "</div>";
    el("src-folder-stop-word").value = "";
    el("src-folder-stop-go").disabled = true;
    V.dialog("src-folder-stop-dialog").open();
  }

  function reflectFolderStopTyped() {
    el("src-folder-stop-go").disabled = el("src-folder-stop-word").value.trim() !== "STOP";
  }

  async function stopFolder() {
    if (!pendingFolderStop) return;
    V.clearErr("src-folder-stop-err");
    var id = pendingFolderStop.folder_id || pendingFolderStop.id;
    var btn = el("src-folder-stop-go");
    btn.disabled = true;
    try {
      var res = await V.api("/v1/admin/folders/" + encodeURIComponent(id), { method: "DELETE", admin: true });
      V.dialog("src-folder-stop-dialog").close();
      if (res && (res.stopped || res.removed || res.deleted)) {
        receipt("ok", "Stopped watching that folder — new files dropped in will no longer become memory. Files already ingested stay searchable (invalidate, never erase).");
      } else {
        receipt("attn", "Nothing was stopped — that folder is unknown or was already stopped. An honest no-op, not a failure.");
      }
      V.reload("sources");
    } catch (e) {
      V.err("src-folder-stop-err", e);
      btn.disabled = false;
    }
  }

  /* ==================================== folder initial-scan live tracking */

  // Begin (or restart) live tracking for one folder's background initial scan,
  // keyed on the server-minted run_id. Clears any prior poll for the same
  // folder first so a re-register never leaks an interval.
  function startFolderScanTracking(folderId, source, path, runId) {
    var key = String(folderId);
    stopFolderScanPoll(key);
    folderScans[key] = {
      run_id: runId || null,
      folder_id: folderId,
      source: source,
      path: path,
      run: null,      // the matched GET row, once it lands
      err: null,      // a poll error, surfaced (never hidden)
      done: false,    // terminal (completed/failed/degraded_acl/paused) reached
      stopped: false, // the operator cancelled the scan (terminal "paused")
      poll: null,
    };
    renderFolderScan(key);
    pollFolderScanOnce(key);
    folderScans[key].poll = setInterval(function () { pollFolderScanOnce(key); }, 2000);
  }

  function stopFolderScanPoll(key) {
    var r = folderScans[key];
    if (r && r.poll) { clearInterval(r.poll); r.poll = null; }
  }

  // Clear every live folder-scan poll — called on panel teardown / no-tenant /
  // tenant switch so no interval outlives the screen (leaked-interval guard).
  function stopAllFolderScanPolls() {
    Object.keys(folderScans).forEach(function (k) { stopFolderScanPoll(k); });
  }

  // A folder scan is terminal on the same completed/failed/degraded_acl the
  // backfill strip uses, PLUS "paused" — the honest terminal an operator Stop
  // lands as (already-ingested files retained).
  function isFolderScanTerminal(state) {
    var s = String(state || "").toLowerCase();
    return s === "completed" || s === "failed" || s === "degraded_acl" || s === "paused";
  }

  async function pollFolderScanOnce(key) {
    var r = folderScans[key];
    if (!r) return;
    try {
      var rows = await V.api(
        "/v1/admin/backfill?tenant_id=" + encodeURIComponent(tenantNow),
        { admin: true });
      var list = Array.isArray(rows) ? rows : [];
      // Match on the SERVER-MINTED run_id so a different run never bleeds its
      // telemetry into this strip.
      var match = r.run_id
        ? list.filter(function (x) { return x.run_id === r.run_id; })[0]
        : null;
      r.err = null;
      if (match) {
        r.run = match;
        if (isFolderScanTerminal(match.state)) {
          r.done = true;
          if (String(match.state).toLowerCase() === "paused") r.stopped = true;
          stopFolderScanPoll(key);
          // Refresh so Your sources reflects the finished scan (file count, etc.).
          V.reload("sources");
        }
      }
      // No match yet: the scan may not have posted its first progress row. Keep
      // polling; the strip shows "starting" until the run_id appears.
    } catch (e) {
      r.err = (e && e.message) || String(e);
    }
    renderFolderScan(key);
  }

  // The live progress strip for one folder's initial scan. Reuses the backfill
  // strip idiom: exact bar when total is known, honest indeterminate + processed
  // count otherwise, a Stop control while running, and a Dismiss once terminal.
  // Rendered into BOTH the dialog result (id "src-folder-scan-<id>") and the Your
  // sources folder row (id "src-folder-scan-row-<id>") when either exists.
  function renderFolderScan(key) {
    var r = folderScans[key];
    if (!r) return;
    var html = r ? folderScanStripHtml(r) : "";
    ["src-folder-scan-" + key, "src-folder-scan-row-" + key].forEach(function (id) {
      var host = document.getElementById(id);
      if (host) {
        host.innerHTML = html;
        wireFolderScanStrip(host, key);
      }
    });
  }

  function folderScanStripHtml(r) {
    var run = r.run;
    var state = run ? String(run.state || "").toLowerCase() : "starting";
    var processed = run ? (run.processed || 0) : 0;
    var skipped = run ? (run.skipped || 0) : 0;
    var total = run ? run.total : null;

    var line, chip;
    if (r.err) {
      chip = V.stateChip("attn", "can't read progress");
      line = '<span class="pct">' + V.esc(r.err) + "</span>";
    } else if (!run) {
      chip = V.stateChip("wait", "starting");
      line = '<div class="bar indet"></div><span class="pct">reading existing files &mdash; waiting for the first progress report</span>';
    } else if (state === "completed") {
      chip = V.stateChip("ok", "watching");
      line = '<div class="bar completed"><i style="width:100%"></i></div>' +
        '<span class="pct">' + V.esc(processed) + " file" + (processed === 1 ? "" : "s") +
        " ingested" + (skipped ? " · " + V.esc(skipped) + " skipped" : "") + "</span>";
    } else if (state === "paused") {
      chip = V.stateChip("off", "scan stopped");
      line = '<div class="bar paused"><i style="width:100%"></i></div>' +
        '<span class="pct">stopped after ' + V.esc(processed) + " file" + (processed === 1 ? "" : "s") +
        " ingested" + (skipped ? " · " + V.esc(skipped) + " skipped" : "") + "</span>";
    } else if (state === "failed") {
      chip = V.stateChip("fail", "scan failed");
      line = '<span class="pct">' + V.esc(processed) + " ingested before the scan failed" +
        (skipped ? " · " + V.esc(skipped) + " skipped" : "") + "</span>";
    } else if (state === "degraded_acl") {
      chip = V.stateChip("attn", "watching · ACLs coarsened");
      line = '<div class="bar completed"><i style="width:100%"></i></div>' +
        '<span class="pct">' + V.esc(processed) + " ingested" +
        (skipped ? " · " + V.esc(skipped) + " skipped" : "") + "</span>";
    } else {
      // running: "watching · N / M files · K skipped".
      chip = V.stateChip("wait", "scanning");
      if (total != null && total > 0) {
        var pct = Math.max(0, Math.min(100, (processed / total) * 100));
        line = '<div class="bar"><i style="width:' + pct.toFixed(1) + '%"></i></div>' +
          '<span class="pct">watching &middot; ' + V.esc(processed) + " / " + V.esc(total) + " files" +
          (skipped ? " · " + V.esc(skipped) + " skipped" : "") + "</span>";
      } else {
        line = '<div class="bar indet"></div>' +
          '<span class="pct">watching &middot; ' + V.esc(processed) + " files" +
          (skipped ? " · " + V.esc(skipped) + " skipped" : "") + " read so far</span>";
      }
    }

    var tail;
    if (state === "completed" || state === "degraded_acl") {
      tail = '<div class="note" style="margin-top:8px">Watching &mdash; ' + V.esc(processed) +
        " file" + (processed === 1 ? "" : "s") + " ingested; drop new files in and they become memory." +
        (state === "degraded_acl" && run && run.error ? " (" + V.esc(run.error) + ")" : "") + "</div>";
    } else if (state === "paused") {
      tail = '<div class="note" style="margin-top:8px">Initial scan stopped &mdash; already-read files stay searchable, and Verity keeps watching for <b>new</b> files you drop in.</div>';
    } else if (state === "failed") {
      tail = '<div class="note" style="margin-top:8px">' + V.badge("scan failed", "b-conf-3") + " " +
        (run && run.error ? '<span class="note" style="margin-top:0">' + V.esc(run.error) + "</span>" : "the initial scan exited abnormally — see the server log.") + "</div>";
    } else if (!r.err) {
      tail = '<div class="note" style="margin-top:8px">Reading existing files &mdash; this strip updates live and stops on its own when the scan drains. New files are watched regardless.</div>';
    } else {
      tail = "";
    }

    // A Stop control while the scan is in flight; a Dismiss once terminal.
    var controls = "";
    if (!r.done) {
      controls = '<div class="actions" style="justify-content:flex-start;margin-top:8px">' +
        '<button class="danger src-folder-scan-stop" data-key="' + V.esc(String(r.folder_id)) + '">Stop scan</button>' +
        "</div>";
    } else {
      controls = '<div class="actions" style="justify-content:flex-start;margin-top:8px">' +
        '<button class="src-folder-scan-dismiss" data-key="' + V.esc(String(r.folder_id)) + '">Dismiss</button>' +
        "</div>";
    }

    return '<div style="margin-top:8px">' +
      '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
        chip +
        '<span class="ref" style="margin-left:auto">' +
          (r.run_id ? "scan " + V.esc(r.run_id) : "run id pending") + "</span>" +
      "</div>" +
      '<div style="min-width:180px;margin-top:8px">' + line + "</div>" +
      tail + controls +
    "</div>";
  }

  function wireFolderScanStrip(host, key) {
    Array.prototype.forEach.call(host.querySelectorAll(".src-folder-scan-stop"), function (btn) {
      btn.onclick = function () { stopFolderScan(key); };
    });
    Array.prototype.forEach.call(host.querySelectorAll(".src-folder-scan-dismiss"), function (btn) {
      btn.onclick = function () {
        stopFolderScanPoll(key);
        delete folderScans[key];
        renderFolders();
        var dlgHost = document.getElementById("src-folder-scan-" + key);
        if (dlgHost) dlgHost.innerHTML = "";
      };
    });
  }

  // Cooperatively cancel an in-flight initial scan (POST
  // /v1/admin/folders/scan/stop). Already-ingested files stay; the OS watch for
  // NEW files is unaffected. The strip flips to the honest "paused" terminal on
  // the next poll (or immediately if the server reports the run_id back).
  async function stopFolderScan(key) {
    var r = folderScans[key];
    if (!r) return;
    var btns = document.querySelectorAll('.src-folder-scan-stop[data-key="' + key + '"]');
    Array.prototype.forEach.call(btns, function (b) { b.disabled = true; });
    try {
      await V.api("/v1/admin/folders/scan/stop", {
        json: { tenant_id: tenantNow, folder_id: r.folder_id },
        admin: true,
      });
      // The task writes its own terminal "paused" row; poll once now so the
      // strip flips promptly instead of waiting the full interval.
      await pollFolderScanOnce(key);
    } catch (e) {
      r.err = (e && e.message) || String(e);
      renderFolderScan(key);
      Array.prototype.forEach.call(btns, function (b) { b.disabled = false; });
    }
  }

  /* ============================================ credential (Phase 2) flow */

  // The secret-write surface is SecretIntakeAuth-gated: an unset
  // VERITY_ADMIN_TOKEN => 401 with NO dev-open branch (unlike the dev-open admin
  // GETs). This exact message is the honest capability signal.
  var SECRET_401 = /VERITY_ADMIN_TOKEN|secret intake requires|no dev-open/i;
  var DEV_TEACH =
    "set VERITY_ADMIN_TOKEN — secret entry is refused unauthenticated; " +
    "Google path-only and the local-folder card need no token.";

  function credClassOf(source) {
    if (source === "hubspot" || source === "salesforce") return "tierc";
    if (source === "gdrive" || source === "gmail" || source === "gdirectory") return "google";
    return "none";
  }
  function credSubjectRequired(source) { return source === "gmail" || source === "gdirectory"; }

  // Wipe every trace of the pasted secret from the DOM + JS state. Called after
  // a resolved save AND on close/cancel — the token must never linger.
  function clearCredSecrets() {
    var t = el("src-cred-token");
    if (t) t.value = "";
    var p = el("src-cred-path");
    if (p) p.value = "";
    var s = el("src-cred-subject");
    if (s) s.value = "";
  }

  function closeCredDialog() {
    clearCredSecrets();
    if (credViewersPicker) { credViewersPicker.destroy(); credViewersPicker = null; }
    pendingCred = null;
    V.dialog("src-cred-dialog").close();
  }

  function setCredDevBlocked(blocked) {
    var box = el("src-cred-dev");
    var tokenField = el("src-cred-token");
    if (blocked) {
      box.style.display = "";
      box.innerHTML = "<em>" + V.esc(DEV_TEACH) + "</em>";
      // tier-C token paste is the one field that ALWAYS needs the token — 401s
      // unauthenticated. Disable it and the Save so no secret is typed in vain.
      if (tokenField) { tokenField.disabled = true; tokenField.value = ""; tokenField.placeholder = "disabled — secret entry is refused unauthenticated"; }
      if (pendingCred && pendingCred.cls === "tierc") el("src-cred-go").disabled = true;
    } else {
      box.style.display = "none";
      box.innerHTML = "";
      if (tokenField) { tokenField.disabled = false; tokenField.placeholder = "paste the bearer token"; }
      el("src-cred-go").disabled = false;
    }
  }

  async function openCredDialog(row) {
    if (!tenantNow) { V.openMint(); return; }
    var source = row.source;
    var cls = credClassOf(source);
    if (cls === "none") return; // folder / unknown — never eligible
    var rotate = credState(row).state === "tracked";
    pendingCred = {
      source: source,
      label: row.label || source,
      kind: row.kind || null,
      cls: cls,
      subjectRequired: credSubjectRequired(source),
      rotate: rotate,
    };

    V.clearErr("src-cred-err");
    el("src-cred-test-result").innerHTML = "";
    el("src-cred-result").innerHTML = "";
    clearCredSecrets();
    setCredDevBlocked(false);
    el("src-cred-go").disabled = false;

    el("src-cred-title").textContent =
      (rotate ? "Rotate the credential for " : "Add a credential for ") + pendingCred.label;
    el("src-cred-summary").innerHTML =
      '<div class="dc-evidence" style="margin-top:0"><b>' + V.esc(pendingCred.label) + "</b>" +
        '<div class="dc-meta" style="margin-top:6px">' + V.esc(source) +
        (pendingCred.kind ? " · " + V.esc(pendingCred.kind) : "") +
        (rotate ? " · a credential is already stored — saving replaces it (rotate)" : "") +
        "</div></div>";

    // Remove is offered only when a credential is already stored (rotate mode);
    // there is nothing to revoke on a first add.
    el("src-cred-revoke").style.display = rotate ? "" : "none";

    // Branch the body. Only one of the two panels is ever visible.
    el("src-cred-tierc").style.display = cls === "tierc" ? "" : "none";
    el("src-cred-google").style.display = cls === "google" ? "" : "none";
    el("src-cred-subject-wrap").style.display =
      (cls === "google" && pendingCred.subjectRequired) ? "" : "none";

    V.dialog("src-cred-dialog").open();

    // tier-C: the MANDATORY visibility picker — the same named directory picker
    // every other write uses. Rebuilt each open (fail-closed: no default, empty
    // refused here and by the server).
    if (cls === "tierc") {
      if (credViewersPicker) { credViewersPicker.destroy(); credViewersPicker = null; }
      credViewersPicker = V.principalPicker(el("src-cred-viewers"), {
        tenantId: function () { return tenantNow || V.tenant(); },
        placeholder: "filter people & groups",
        emptyTitle: "No people or groups on record yet",
        emptyBody: "Add people or groups to this space first, then pick who can see this connector's records.",
        emptyAction: "Open People & groups",
        onOpenDirectory: function () { V.show("principals"); },
      });
      credViewersPicker.load(tenantNow);
    } else if (credViewersPicker) {
      credViewersPicker.destroy();
      credViewersPicker = null;
    }

    // Capability probe: the credential/test surface is SecretIntakeAuth-gated
    // with NO side effects (it never stores). A 401 here proves the server has
    // no VERITY_ADMIN_TOKEN — disable the token paste + teach, gracefully.
    try {
      await V.api(
        "/v1/admin/connectors/" + encodeURIComponent(source) +
          "/credential/test?tenant_id=" + encodeURIComponent(tenantNow),
        { json: {}, admin: true });
    } catch (e) {
      var m = (e && e.message) || "";
      if (/HTTP 401/.test(m) && SECRET_401.test(m)) setCredDevBlocked(true);
      // Any other error (403 Origin, 404, network) is surfaced by the real
      // Test/Save actions, not pre-emptively here.
    }
  }

  // Build the source-branched request body, enforcing the fail-closed
  // client-side gates (empty visibility / token / path / subject refused here,
  // mirroring the server's own 422). Returns { body } or throws a teaching Error.
  function buildCredBody(includeToken) {
    if (!pendingCred) throw new Error("no source selected");
    if (pendingCred.cls === "tierc") {
      var body = {};
      if (includeToken) {
        var token = el("src-cred-token").value;
        if (!token.trim()) {
          throw new Error("paste the API token — it is encrypted at rest and never echoed back.");
        }
        body.token = token;
      }
      // The MANDATORY visibility set: no default, empty refused client-side.
      var viewers = credViewersPicker ? credViewersPicker.value() : [];
      if (includeToken && !viewers.length) {
        throw new Error(
          "Pick who can see what this credential ingests — there is no default. " +
          "An empty visibility set is refused here and by the server (fail closed).");
      }
      if (viewers.length) body.visibility = viewers.map(function (v) { return v.token; });
      return { body: body, viewers: viewers };
    }
    // Google
    var gbody = {};
    var path = el("src-cred-path").value.trim();
    if (!path) throw new Error("give the service-account key path — an absolute path the connector can read.");
    gbody.path = path;
    if (pendingCred.subjectRequired) {
      var subject = el("src-cred-subject").value.trim();
      if (!subject) {
        throw new Error(
          "give the impersonation subject — Gmail and the directory read as a specific " +
          "Workspace user, and the server refuses without it.");
      }
      gbody.subject = subject;
    } else {
      var optSub = el("src-cred-subject").value.trim();
      if (optSub) gbody.subject = optSub;
    }
    return { body: gbody, viewers: [] };
  }

  async function testCredential() {
    if (!pendingCred) return;
    V.clearErr("src-cred-err");
    el("src-cred-test-result").innerHTML = "";
    // Test does NOT require the visibility set — only the secret material to
    // probe with (tier-C token / Google path). Build with includeToken but
    // tolerate a missing visibility (the store gate, not the test gate).
    var body;
    try {
      if (pendingCred.cls === "tierc") {
        var token = el("src-cred-token").value;
        if (!token.trim()) {
          throw new Error("paste the API token to test it against the live provider.");
        }
        body = { token: token };
      } else {
        var path = el("src-cred-path").value.trim();
        if (!path) throw new Error("give the service-account key path to check it structurally.");
        body = { path: path };
      }
    } catch (e) {
      V.err("src-cred-err", e);
      return;
    }
    var btn = el("src-cred-test");
    btn.disabled = true;
    try {
      var res = await V.api(
        "/v1/admin/connectors/" + encodeURIComponent(pendingCred.source) +
          "/credential/test?tenant_id=" + encodeURIComponent(tenantNow),
        { json: body, admin: true });
      var ok = !!(res && res.ok);
      var kind = (res && res.kind) || (pendingCred.cls === "tierc" ? "live" : "structural");
      var status = res && res.status != null ? " · HTTP " + V.esc(res.status) : "";
      var label = kind === "live" ? "live check" : "structural check — not a live auth test";
      el("src-cred-test-result").innerHTML =
        '<div class="card" style="margin-top:10px;margin-bottom:0">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            (ok ? V.stateChip("ok", "reachable") : V.stateChip("attn", "not usable")) +
            '<span class="asof">' + V.esc(label) + status + "</span>" +
          "</div>" +
          '<div class="note" style="margin-top:8px">' + V.esc((res && res.detail) || "no detail returned") + "</div>" +
        "</div>";
    } catch (e) {
      var m = (e && e.message) || "";
      if (/HTTP 401/.test(m) && SECRET_401.test(m)) setCredDevBlocked(true);
      V.err("src-cred-err", e);
    } finally {
      btn.disabled = false;
    }
  }

  async function saveCredential() {
    if (!pendingCred) return;
    V.clearErr("src-cred-err");
    el("src-cred-result").innerHTML = "";
    var built;
    try {
      built = buildCredBody(true);
    } catch (e) {
      V.err("src-cred-err", e);
      return;
    }
    var source = pendingCred.source;
    var rotate = pendingCred.rotate;
    var viewerNames = (built.viewers || []).map(function (v) { return v.principal; }).join(", ");
    var btn = el("src-cred-go");
    btn.disabled = true;
    try {
      var res = await V.api(
        "/v1/admin/connectors/" + encodeURIComponent(source) + "/credential",
        { json: built.body, admin: true });
      // NEVER keep the token: clear the input the instant the request resolves,
      // and show ONLY the returned fingerprint (no last-4, no raw hash oracle).
      clearCredSecrets();
      el("src-cred-result").innerHTML =
        '<div class="card" style="margin-top:12px;margin-bottom:0">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            V.stateChip("ok", rotate ? "credential rotated" : "credential stored") +
            '<span class="asof">the token is never kept — this console holds only the fingerprint below</span>' +
          "</div>" +
          '<div class="note" style="margin-top:8px">' +
            (res && res.kind === "path" ? "SA-key path recorded" : "bearer stored, encrypted at rest") +
            (res && res.fingerprint ? " · fingerprint " + V.refSpan(res.fingerprint) : "") +
            (viewerNames ? ". You picked <b>" + V.esc(viewerNames) + "</b> as who should see records it ingests; that scope was validated but connector ingestion isn&rsquo;t wired to it yet (a later phase), so nothing is ingested or shared under it today." : "") +
          "</div>" +
        "</div>";
      V.reload("sources");
    } catch (e) {
      // Server refusals surface verbatim: 401 (VERITY_ADMIN_TOKEN unset), 403
      // (cross-origin), 409 (env-vs-UI precedence), 422 (empty/KEK-refuse).
      var m = (e && e.message) || "";
      if (/HTTP 401/.test(m) && SECRET_401.test(m)) setCredDevBlocked(true);
      V.err("src-cred-err", e);
    } finally {
      // Re-enable Save unless the dev block already latched it off for tier-C
      // (an unauthenticated token paste can never succeed — keep it disabled).
      var devLatched = pendingCred && pendingCred.cls === "tierc" &&
        el("src-cred-token").disabled;
      if (!devLatched) btn.disabled = false;
    }
  }

  async function revokeCredential() {
    if (!pendingCred) return;
    V.clearErr("src-cred-err");
    el("src-cred-result").innerHTML = "";
    var source = pendingCred.source;
    var btn = el("src-cred-revoke");
    btn.disabled = true;
    try {
      var res = await V.api(
        "/v1/admin/connectors/" + encodeURIComponent(source) + "/credential",
        { method: "DELETE", admin: true });
      var removed = !!(res && res.revoked);
      el("src-cred-result").innerHTML =
        '<div class="card" style="margin-top:12px;margin-bottom:0">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            (removed ? V.stateChip("ok", "credential removed") : V.stateChip("attn", "nothing to remove")) +
            '<span class="asof">' +
              (removed
                ? "the stored credential was deleted &mdash; the row falls back to its observed state"
                : "no credential was stored for this source &mdash; an honest no-op, not a failure") +
            "</span>" +
          "</div></div>";
      // The row's chip is refreshed from the connectors endpoint on reload.
      V.reload("sources");
      // A removed credential means the next open is an add, not a rotate.
      if (removed && pendingCred) { pendingCred.rotate = false; el("src-cred-revoke").style.display = "none"; }
    } catch (e) {
      var m = (e && e.message) || "";
      if (/HTTP 401/.test(m) && SECRET_401.test(m)) setCredDevBlocked(true);
      V.err("src-cred-err", e);
    } finally {
      btn.disabled = false;
    }
  }

  /* ============================================ backfill (Phase 3) flow */

  // The tenant NAME the confirm re-affirms. tenantName() resolves it from the
  // directory; when absent (a real id not on the truncated page) we fall back to
  // the id itself so the typed-confirm still has an exact token to match — never
  // an empty string that would let a blank confirm through.
  function confirmToken() {
    var n = V.tenantName(tenantNow);
    return (n && n.trim()) ? n : tenantNow;
  }

  function openBackfillDialog(row) {
    if (!tenantNow) { V.openMint(); return; }
    // Only gdrive/gmail with an available backfill reach an enabled button, but
    // re-check here so a stale row can never open a doomed confirm.
    if (!(row && row.backfill && row.backfill.available)) return;
    pendingBackfill = { source: row.source, label: row.label || row.source };
    V.clearErr("src-backfill-err");
    var token = confirmToken();
    el("src-backfill-title").textContent = "Run a catch-up import for " + pendingBackfill.label;
    el("src-backfill-summary").innerHTML =
      '<div class="dc-evidence" style="margin-top:0"><b>What you are running:</b> a full-crawl replay of <b>' +
        V.esc(pendingBackfill.label) + "</b>&rsquo;s history into this space." +
        '<div class="dc-meta" style="margin-top:6px">' + V.esc(pendingBackfill.source) +
        " &middot; space " + V.esc(token) + "</div></div>";
    el("src-backfill-name").textContent = token;
    el("src-backfill-word").value = "";
    el("src-backfill-go").disabled = true;
    V.dialog("src-backfill-dialog").open();
  }

  function reflectBackfillTyped() {
    el("src-backfill-go").disabled =
      el("src-backfill-word").value.trim() !== confirmToken();
  }

  async function runBackfill() {
    if (!pendingBackfill) return;
    V.clearErr("src-backfill-err");
    var source = pendingBackfill.source;
    var label = pendingBackfill.label;
    var btn = el("src-backfill-go");
    btn.disabled = true;
    try {
      // No request body — the endpoint is admin-gated with the identity in the
      // query string; POST is explicit since opts.json is absent (default GET).
      var res = await V.api(
        "/v1/admin/connectors/" + encodeURIComponent(source) +
          "/backfill?tenant_id=" + encodeURIComponent(tenantNow),
        { method: "POST", admin: true });
      V.dialog("src-backfill-dialog").close();
      pendingBackfill = null;
      // Server-minted run_id — the poll keys on THIS run so it never renders
      // another run's telemetry.
      startBackfillTracking(source, label, res && res.run_id, res && res.pid);
    } catch (e) {
      // Server refusals verbatim — 409 (already running / source busy under
      // another tenant), 422 (not wired / no key / no subject), 503 (spawn).
      V.err("src-backfill-err", e);
      btn.disabled = false;
    }
  }

  // Begin (or restart) live tracking for one (source, run_id). Clears any prior
  // poll for the same source first so a re-trigger never leaks an interval.
  function startBackfillTracking(source, label, runId, pid) {
    stopBackfillPoll(source);
    backfillRuns[source] = {
      run_id: runId || null,
      source: source,
      label: label,
      pid: pid || null,
      run: null,       // the matched GET row, once it lands
      err: null,       // a poll error, surfaced (never hidden)
      done: false,     // terminal (completed/failed) reached
      poll: null,
    };
    renderBackfillLive();
    pollBackfillOnce(source);
    backfillRuns[source].poll = setInterval(function () { pollBackfillOnce(source); }, 2000);
  }

  function stopBackfillPoll(source) {
    var r = backfillRuns[source];
    if (r && r.poll) { clearInterval(r.poll); r.poll = null; }
  }

  // Clear every live poll — called on panel teardown / no-tenant so no interval
  // outlives the screen (the leaked-interval guard).
  function stopAllBackfillPolls() {
    Object.keys(backfillRuns).forEach(function (s) { stopBackfillPoll(s); });
  }

  function isTerminal(state) {
    var s = String(state || "").toLowerCase();
    // degraded_acl is a TERMINAL state (a completed-but-coarsened crawl), so the
    // live poll stops on it just like completed/failed — never an eternal spin.
    return s === "completed" || s === "failed" || s === "degraded_acl";
  }

  async function pollBackfillOnce(source) {
    var r = backfillRuns[source];
    if (!r) return;
    try {
      var rows = await V.api(
        "/v1/admin/backfill?tenant_id=" + encodeURIComponent(tenantNow),
        { admin: true });
      var list = Array.isArray(rows) ? rows : [];
      // Match on the SERVER-MINTED run_id — NOT just the source — so a different
      // run for the same source never bleeds its telemetry into this strip.
      var match = r.run_id
        ? list.filter(function (x) { return x.run_id === r.run_id; })[0]
        : null;
      r.err = null;
      if (match) {
        r.run = match;
        if (isTerminal(match.state)) {
          r.done = true;
          stopBackfillPoll(source);
          // The terminal state is authoritative because the server's child-exit
          // reap reconciles backfill_run (completed on exit 0; failed + code +
          // log tail otherwise) — so a SIGKILL/OOM/dropped-telemetry child still
          // resolves here instead of hanging. Refresh the panel so the connectors
          // table + catch-up table reflect the finished run.
          V.reload("sources");
        }
      }
      // No match yet: the child may not have posted its first progress row. Keep
      // polling; the strip shows "starting" until the run_id appears.
    } catch (e) {
      r.err = (e && e.message) || String(e);
    }
    renderBackfillLive();
  }

  // Render the live strips from backfillRuns — driven by the poller, never wiped
  // by a table re-render. Exact bar when total is known; honest indeterminate +
  // processed count otherwise. On completion: "ingested — becoming queryable
  // (~resolve debounce)", NOT "done, query now".
  function renderBackfillLive() {
    var host = el("src-backfill-live");
    if (!host) return;
    var sources = Object.keys(backfillRuns);
    if (!sources.length) { host.innerHTML = ""; return; }
    host.innerHTML = sources.map(function (s) {
      var r = backfillRuns[s];
      var run = r.run;
      var state = run ? String(run.state || "").toLowerCase() : "starting";
      var chip, progress, tail;

      // Belt-and-suspenders for the best-effort reconcile: if the reap's
      // reconcile_terminal DB write failed (transient fault / pool exhaustion),
      // the last persisted row is the connector-posted state='completed' carrying
      // the raw degrade token in error. Treat that as degraded, NEVER a silent
      // green success — a coarsened crawl must never read as clean-completed.
      // Derived BEFORE the chip so the chip is amber (not green) too.
      var degradeToken = "verity.backfill.degraded_acl";
      if (state === "completed" && run && run.error === degradeToken) state = "degraded_acl";

      if (r.err) {
        chip = V.stateChip("attn", "can't read progress");
        progress = '<span class="pct">' + V.esc(r.err) + "</span>";
      } else if (!run) {
        chip = V.stateChip("wait", "starting");
        progress = '<div class="bar indet"></div><span class="pct">spawned' +
          (r.pid ? " (pid " + V.esc(r.pid) + ")" : "") + " &mdash; waiting for the first progress report</span>";
      } else {
        chip = backfillChip(state);
        progress = progressCell(run);
      }

      if (state === "completed") {
        // HONESTY: the green bar means the crawl DRAINED, not that the data is
        // queryable. Entities still resolve async behind the resolve debounce —
        // the CTA gates on that, never on the bar.
        tail = '<div class="note" style="margin-top:8px">' +
          V.stateChip("ok", "ingested") +
          " &mdash; <b>becoming queryable</b> (~resolve debounce). The crawl drained; each item is still resolving into entities, " +
          "so give it a moment before you query this source or point an agent at it.</div>";
      } else if (state === "failed") {
        tail = '<div class="note" style="margin-top:8px">' + V.badge("failed", "b-conf-3") + " " +
          (run && run.error
            ? '<span class="note" style="margin-top:0">' + V.esc(run.error) + "</span>"
            : "the backfill exited non-zero — see the connector log on the server (ingest/" + V.esc(s) + ".log).") +
          "</div>";
      } else if (state === "degraded_acl") {
        // HONEST, non-red: the crawl drained every record, but the connector's
        // HubSpot app lacked the owners-read scope, so owner/team ACLs were
        // coarsened to the admin-assigned visibility policy. Never a silent
        // success — the operator sees exactly what was (and wasn't) applied.
        tail = '<div class="note" style="margin-top:8px">' +
          V.stateChip("attn", "ingested · ACLs coarsened") +
          ' &mdash; <b>owner/team ACLs unavailable</b> — every record used the admin-assigned ' +
          "visibility policy" +
          (run && run.error ? " (" + V.esc(run.error) + ")" : "") +
          ". The crawl drained; grant the HubSpot owners-read scope and re-run for fine-grained ACLs.</div>";
      } else if (!r.err) {
        tail = '<div class="note" style="margin-top:8px">Replaying history &mdash; this strip updates live and stops on its own when the crawl drains.</div>';
      } else {
        tail = "";
      }

      return '<div class="card" style="margin-top:12px;margin-bottom:0">' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          chip +
          "<b>" + V.esc(r.label) + "</b>" +
          '<span class="ref" style="margin-left:auto">' +
            (r.run_id ? "run " + V.esc(r.run_id) : "run id pending") + "</span>" +
        "</div>" +
        '<div style="min-width:180px;margin-top:8px">' + progress + "</div>" +
        tail +
        (r.done
          ? '<div class="actions" style="justify-content:flex-start;margin-top:8px">' +
              '<button class="src-backfill-dismiss" data-src="' + V.esc(s) + '">Dismiss</button>' +
            "</div>"
          : "") +
      "</div>";
    }).join("");

    Array.prototype.forEach.call(host.querySelectorAll(".src-backfill-dismiss"), function (btn) {
      btn.onclick = function () {
        var s = btn.getAttribute("data-src");
        stopBackfillPoll(s);
        delete backfillRuns[s];
        renderBackfillLive();
      };
    });
  }

  /* =========================================================== manifests */

  function renderManifests() {
    var host = el("src-manifests");
    var rows = data.manifests;
    if (!rows.length) {
      host.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">No manifests installed</div>' +
          '<div class="et-body">None yet. If a source sends structured records you want queryable field-by-field ' +
            "with the right permissions, install one — what a manifest is and does is explained above. " +
            "Installing only creates a draft; nothing runs until a named person approves it.</div>" +
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
      (tgt != null ? "your threshold of " + V.esc(fmtThreshold(tgt)) : "your threshold (unset)") +
      " — a console display setting, not a server-enforced SLO.</div>";
  }

  /* =========================================================== backfill */

  function backfillChip(state) {
    var s = String(state || "").toLowerCase();
    if (s === "running") return V.stateChip("wait", "running");
    if (s === "completed") return V.stateChip("ok", "completed");
    if (s === "failed") return V.stateChip("fail", "failed");
    // A completed-but-coarsened crawl: amber, never green (honest, not failed).
    if (s === "degraded_acl") return V.stateChip("attn", "ACLs coarsened");
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
        '<div class="empty">No catch-up imports have run for this space. Connectors report them as they replay history — nothing to show is a real state, not an error.</div>';
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
    box.innerHTML = '<span class="ref">loading the directory of people &amp; groups&hellip;</span>';
    try {
      var res = await V.api(
        "/v1/admin/principals?tenant_id=" + encodeURIComponent(tenantNow) + "&limit=1000",
        { admin: true });
      var list = (res && res.principals) || [];
      if (!list.length) {
        box.innerHTML = '<span class="ref">the directory of people &amp; groups is empty for this space — ' +
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
      box.innerHTML = '<span class="ref">could not read the directory of people &amp; groups (' +
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
