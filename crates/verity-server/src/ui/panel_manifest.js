"use strict";
/* ==========================================================================
   panel_manifest.js — Add a source (the manifest wizard)
   --------------------------------------------------------------------------
   Turns ONE real webhook/CDC message into scoped Verity memory. The author
   never types the manifest schema, the field-extraction expression language,
   or the permission model by hand: they PASTE a real payload and CLICK its
   values. A click can only emit a valid dot-path expression; the live preview
   is the debugger; watching quarantine on your OWN sample is the safety lesson.

   Reads / writes (all admin-gated):
     • POST /v1/manifests/dry-run { tenant_id, manifest_yaml, sample_payload }
       — THE live preview backend. Pure Manifest::from_yaml + runtime::apply()
       under a pinned fixture clock; NEVER persists (safe on every click). We
       re-fetch it after EVERY change from step 2 onward (see previewFetch()).
       200 → { outcome:"writes", source, writes[], acl } (writes[] is
       EntityWrites::to_json verbatim: {entity_type, entity_id, valid_from,
       fields} — NO content key) OR { outcome:"quarantine", reason }.
       422 → { error } = from_yaml's verbatim message; we map it to the step.
     • POST /v1/manifests { tenant_id, yaml } — Save as draft (full server
       validation, stores a DRAFT row, echoes an activation-readiness preview).
       A quarantine/absent-ACL draft saves fine; it just can't activate.

   Activation is a SEPARATE, explicit, admin-approved, audit-logged act
   (POST /v1/manifests/{id}/activate) — handed off to Sources & freshness. The
   wizard NEVER auto-activates.

   THE HUMAN GATE (step 4): the ACL block is the one choice we can't make. No
   radio carries `checked`; the build throws until an explicit choice is made;
   before step 4 the dry-run has no acl_policy, so apply() itself quarantines
   and the preview shows a held message (honest fail-closed), never a guessed
   audience. Tier (A/B/C) is INFERRED from a plain-language answer and written
   into source.tier so activation_check() passes — the author never reads the
   words "Tier A/B/C".

   THE LAW: plain language (no "JSONata"/"Tier"/"ReBAC"/"principal"/"manifest"
   in visible copy — glossed on first use where unavoidable); every number
   labeled; empty states teach; nothing fabricated (preview is real apply()
   output, quarantine reasons verbatim); endpoints in .api-crumb spans behind
   the off-by-default toggle, sentences complete without them.

   OWNS: this file + panel_manifest.html. Reuses frozen theme/core classes and
   Verity.* helpers (api, esc, refSpan, principalPicker, dialog, toasts).
   ========================================================================== */
(function () {
  var V = window.Verity;

  // Runtime bounds we mirror client-side so we never advance a payload the
  // engine would reject on sight (SPEC §5e.3 bounded engine).
  var MAX_PAYLOAD_DEPTH = 64;   // MAX_PAYLOAD_DEPTH
  var MAX_MAP_FIELDS = 64;      // MAX_MAP_FIELDS

  // The wizard's whole editable state. `acl_policy` is deliberately absent
  // until step 4 — the auto-draft path is FORBIDDEN from emitting it.
  var st = null;
  var tenantNow = "";
  var previewSeq = 0;           // stale-response guard across rapid dry-runs
  var lastPreview = null;       // last dry-run result (or null)
  var lastPreviewErr = null;    // last dry-run 422 { error, step } (or null)
  var aclPicker = null;         // Verity.principalPicker for the static case

  function el(id) { return V.$(id); }
  function esc(s) { return V.esc(s); }

  /* --------------------------------------------------------- scoped styles */
  // Injected ONCE. Uses only frozen theme tokens (var(--…)); scoped under
  // #panel-manifest so nothing leaks into other panels. Class names are all
  // mf-* to avoid collision with the frozen core classes.
  var _stylesDone = false;
  function injectStyles() {
    if (_stylesDone) return;
    _stylesDone = true;
    var css =
      "#panel-manifest .mf-crumb{cursor:pointer;color:var(--dim);font-size:var(--fs-sm);padding:2px 4px;border-radius:var(--r-sm)}" +
      "#panel-manifest .mf-crumb.on{color:var(--accent);font-weight:600}" +
      "#panel-manifest .mf-crumb.off{color:var(--faint);cursor:default}" +
      "#panel-manifest .mf-crumb-sep{color:var(--faint)}" +
      "#panel-manifest .mf-sumrow{margin-bottom:6px}" +
      "#panel-manifest .mf-sumlabel{display:inline-block;min-width:96px;color:var(--dim);font-size:var(--fs-sm)}" +
      "#panel-manifest .mf-node{display:flex;align-items:center;gap:8px;padding:3px 0;flex-wrap:wrap}" +
      "#panel-manifest .mf-nodepath{min-width:0}" +
      "#panel-manifest .mf-treeval{color:var(--text);font-family:var(--mono);font-size:var(--fs-sm)}" +
      "#panel-manifest .mf-treekind{color:var(--faint);font-size:var(--fs-xs)}" +
      "#panel-manifest .mf-affor{display:inline-flex;gap:4px;flex-wrap:wrap;margin-left:auto}" +
      "#panel-manifest .mf-treebtn{padding:1px 7px;font-size:var(--fs-xs)}" +
      "#panel-manifest .mf-x{cursor:pointer;color:var(--faint);padding:0 4px;font-weight:700}" +
      "#panel-manifest .mf-x:hover{color:var(--amber)}" +
      "#panel-manifest .mf-and{color:var(--dim);font-size:var(--fs-sm);min-width:26px}" +
      "#panel-manifest .mf-inchip{display:inline-flex;align-items:center;gap:2px}" +
      "#panel-manifest .mf-aclopt{display:flex;gap:10px;align-items:flex-start;padding:10px 12px;border:1px solid var(--border);border-radius:var(--r-sm);margin-bottom:8px;cursor:pointer}" +
      "#panel-manifest .mf-aclopt.on{border-color:var(--accent);background:var(--accent-soft)}" +
      "#panel-manifest .mf-aclopt input{margin-top:3px}" +
      "#panel-manifest .mf-aclopt-body{flex:1}" +
      "#panel-manifest .mf-band{padding:6px 10px;border-radius:var(--r-sm);font-size:var(--fs-sm);border:1px solid}" +
      "#panel-manifest .mf-band-ok{color:var(--green);border-color:var(--green-line);background:var(--green-soft)}" +
      "#panel-manifest .mf-band-warn{color:var(--amber);border-color:var(--amber-line);background:var(--amber-soft)}" +
      "#panel-manifest .mf-band-hold{color:var(--amber);border-color:var(--amber-line);background:var(--amber-soft)}" +
      "#panel-manifest .mf-yaml{background:var(--panel);border:1px solid var(--border);border-radius:var(--r-sm);padding:10px;overflow-x:auto;font-size:var(--fs-sm);white-space:pre;font-family:var(--mono)}";
    var s = document.createElement("style");
    s.textContent = css;
    document.head.appendChild(s);
  }

  /* ---------------------------------------------------------- fresh state */

  function freshState() {
    return {
      step: 1,               // 1..5
      sourceName: "",
      payloadText: "",
      payload: null,         // parsed JSON (object) once "Read the shape" runs
      // route: a list of {path, op, value|values} joined by "and"
      routeConds: [],
      // entity mapping
      primaryKey: "",        // dot-path
      validFrom: "",         // dot-path OR the literal "$now()"
      map: [],               // [{field, path}]
      content: "",           // dot-path to a string leaf, or ""
      // ACL — the human gate. chosen stays false until an explicit choice.
      acl: {
        chosen: false,
        choice: "",          // "" | "mirror" | "rough" | "fixed" | "hold"
        principalsPath: "",  // for mirror/rough
        namespace: "",       // "email" | "source_native_id" | "verity_group"
        note: "",            // for rough (required, non-empty)
        staticViewers: [],   // for fixed: [{principal, token}]
      },
    };
  }

  /* =========================================================== register */

  V.register({
    id: "manifest",
    mount: function () {
      var host = el("mf-mount");
      if (!host) return;
      injectStyles();
      st = freshState();
      host.innerHTML =
        '<div id="mf-rail"></div>' +
        '<div id="mf-layout" style="display:flex;gap:18px;align-items:flex-start">' +
          '<div id="mf-steps" style="flex:1;min-width:0"></div>' +
          '<div id="mf-preview" style="flex:0 0 340px;max-width:340px"></div>' +
        '</div>';
      render();
      if (!V.tenant()) renderNoTenant();
    },
    load: function (_section, tenant) {
      if (tenantNow && tenantNow !== tenant) {
        // another space's payload/viewers do not carry over — start clean
        st = freshState();
        if (aclPicker) { aclPicker.destroy(); aclPicker = null; }
        lastPreview = null; lastPreviewErr = null;
      }
      tenantNow = tenant;
      render();
    },
  });

  /* =============================================================== render */

  function render() {
    renderRail();
    renderStep();
    renderPreview();
  }

  function renderNoTenant() {
    var host = el("mf-mount");
    if (!host) return;
    host.innerHTML =
      '<div class="empty-teach">' +
        '<div class="et-title">Pick a space first</div>' +
        '<div class="et-body">A source belongs to a <b>space</b> (the company that owns this memory). ' +
          'Pick or paste a space id<span class="api-crumb"> (tenant id)</span> in the session bar above, then come back to add a source.</div>' +
      "</div>";
  }

  /* ------------------------------------------------------------ the rail */

  var STEP_LABELS = [
    "① Payload",
    "② Route",
    "③ Fields",
    "④ Who can see it",
    "⑤ Review & test",
  ];

  function renderRail() {
    var r = el("mf-rail");
    if (!r) return;
    var parts = [];
    for (var i = 0; i < STEP_LABELS.length; i++) {
      var n = i + 1;
      var reachable = canReach(n);
      var cls = "mf-crumb" + (st.step === n ? " on" : "") + (reachable ? "" : " off");
      parts.push('<span class="' + cls + '" data-step="' + n + '">' + esc(STEP_LABELS[i]) + "</span>");
    }
    r.innerHTML =
      '<div class="toolbar" style="margin-bottom:14px">' +
        '<div class="mf-crumbrail" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">' +
          parts.join('<span class="mf-crumb-sep">·</span>') +
        "</div>" +
      "</div>";
    // rail clicks jump only to reachable steps
    r.querySelectorAll(".mf-crumb").forEach(function (c) {
      c.addEventListener("click", function () {
        var n = Number(c.getAttribute("data-step"));
        if (canReach(n)) { st.step = n; render(); }
      });
    });
  }

  // A step is reachable once the ones before it are satisfied enough to be
  // honest. The ACL gate (step 4 -> 5) is the strict one.
  function canReach(n) {
    if (n <= 1) return true;
    if (!st.payload) return false;               // need a parsed payload
    if (n === 2) return true;
    if (n === 3) return true;                     // an empty route (match-all) is valid
    if (n === 4) return !!st.primaryKey;         // need a stable id to map at all
    if (n === 5) return !!st.primaryKey && st.acl.chosen && aclStepValid(); // the human gate
    return false;
  }

  function renderStep() {
    var host = el("mf-steps");
    if (!host) return;
    if (st.step === 1) return stepPayload(host);
    if (st.step === 2) return stepRoute(host);
    if (st.step === 3) return stepFields(host);
    if (st.step === 4) return stepAcl(host);
    if (st.step === 5) return stepReview(host);
  }

  /* ==================================================== STEP 1 · payload */

  function stepPayload(host) {
    host.innerHTML =
      '<div class="card">' +
        '<h2>① Paste one real message <span class="sub">from your source</span></h2>' +
        '<div class="note" style="margin-top:0">Copy one real message your source sends &mdash; a webhook body, a database row. ' +
          'We read its shape to help you map it. <b>We never send it anywhere and never store it.</b></div>' +

        '<div class="row" style="margin-top:12px">' +
          '<div><label for="mf-source">Source name</label>' +
            '<input type="text" id="mf-source" placeholder="e.g. linear" spellcheck="false" value="' + esc(st.sourceName) + '">' +
            '<div class="err" id="mf-source-err"></div></div>' +
        "</div>" +

        '<div style="margin-top:12px">' +
          '<label for="mf-payload">One real message <span style="font-weight:400">(JSON)</span></label>' +
          '<textarea id="mf-payload" style="min-height:180px;font-family:var(--mono);font-size:var(--fs-sm)" ' +
            'placeholder=\'{ "type": "Issue", "action": "update", "data": { "id": "iss_1", "title": "Fix the webhook" } }\'>' + esc(st.payloadText) + "</textarea>" +
          '<div id="mf-payload-receipt" class="note" style="margin-top:6px"></div>' +
          '<div class="err" id="mf-payload-err"></div>' +
        "</div>" +

        '<div class="toolbar" style="margin-top:12px">' +
          '<button class="primary" id="mf-read-shape">Read the shape →</button>' +
          '<span class="spacer"></span>' +
        "</div>" +

        // empty-state teach: no message handy
        (st.payloadText ? "" :
          '<div class="empty-teach" style="margin-top:12px">' +
            '<div class="et-title">No message handy?</div>' +
            '<div class="et-body">Send one event to a minted webhook, then copy it from what quarantine captured.' +
              '<span class="api-crumb"> (GET /v1/quarantine)</span></div>' +
          "</div>") +

        // optional graft: worked examples (acl_policy omitted on purpose)
        '<div style="margin-top:14px">' +
          '<div class="note" style="margin-top:0">Start from a worked example <span style="font-weight:400">(we leave &ldquo;who can see it&rdquo; for you)</span>:</div>' +
          '<div class="toolbar" style="margin-top:4px">' +
            '<button id="mf-ex-linear">Linear issues</button>' +
            '<button id="mf-ex-github">GitHub issues</button>' +
            '<button id="mf-ex-webhook">Generic webhook</button>' +
          "</div>" +
        "</div>" +
      "</div>";

    var src = el("mf-source");
    src.addEventListener("input", function () {
      st.sourceName = src.value;
      validateSourceName();
    });
    var pay = el("mf-payload");
    pay.addEventListener("input", function () {
      st.payloadText = pay.value;
      validatePayload(false);
    });
    el("mf-read-shape").addEventListener("click", readShape);
    el("mf-ex-linear").addEventListener("click", function () { loadExample("linear"); });
    el("mf-ex-github").addEventListener("click", function () { loadExample("github"); });
    el("mf-ex-webhook").addEventListener("click", function () { loadExample("webhook"); });

    validateSourceName();
    if (st.payloadText) validatePayload(false);
  }

  // schema.rs: source.name matches ^[a-z0-9_-]+$, non-empty.
  function validateSourceName() {
    var e = el("mf-source-err");
    if (!e) return true;
    var v = st.sourceName.trim();
    if (!v) { V.clearErr(e); return false; }
    if (!/^[a-z0-9_-]+$/.test(v)) {
      e.textContent = "lowercase letters, numbers, _ or - only.";
      e.classList.add("on");
      return false;
    }
    V.clearErr(e);
    return true;
  }

  function valueDepth(v) {
    if (v === null || typeof v !== "object") return 0;
    var max = 0;
    if (Array.isArray(v)) {
      for (var i = 0; i < v.length; i++) max = Math.max(max, valueDepth(v[i]));
    } else {
      for (var k in v) if (Object.prototype.hasOwnProperty.call(v, k)) max = Math.max(max, valueDepth(v[k]));
    }
    return 1 + max;
  }

  // Client-side ONLY here: JSON.parse succeeds AND depth <= 64. Returns the
  // parsed value (or null). `advancing` gates the block on "Read the shape".
  function validatePayload(advancing) {
    var e = el("mf-payload-err");
    var receipt = el("mf-payload-receipt");
    var txt = st.payloadText.trim();
    if (!txt) {
      if (e) V.clearErr(e);
      if (receipt) receipt.textContent = "";
      return null;
    }
    var parsed;
    try {
      parsed = JSON.parse(txt);
    } catch (err) {
      if (e) { e.textContent = "That isn’t valid JSON — " + err.message + "."; e.classList.add("on"); }
      if (receipt) receipt.textContent = "";
      return null;
    }
    var depth = valueDepth(parsed);
    if (depth > MAX_PAYLOAD_DEPTH) {
      if (e) {
        e.textContent = "This message nests deeper than Verity accepts (depth " + depth +
          ", cap " + MAX_PAYLOAD_DEPTH + ") — it would be held on sight.";
        e.classList.add("on");
      }
      if (receipt) receipt.textContent = "";
      return null;
    }
    if (e) V.clearErr(e);
    if (receipt) {
      var topKeys = (parsed && typeof parsed === "object" && !Array.isArray(parsed))
        ? Object.keys(parsed).length
        : (Array.isArray(parsed) ? parsed.length : 0);
      var kind = Array.isArray(parsed) ? "top-level items" : "top-level keys";
      receipt.innerHTML = "✓ Valid JSON · " + topKeys + " " + kind +
        " · nesting depth " + depth + " (cap " + MAX_PAYLOAD_DEPTH + ").";
    }
    return parsed;
  }

  function readShape() {
    if (!validateSourceName()) {
      var se = el("mf-source-err");
      if (se && !st.sourceName.trim()) { se.textContent = "Give the source a name first."; se.classList.add("on"); }
      return;
    }
    var parsed = validatePayload(true);
    if (parsed === null) return; // block; error already shown
    st.payload = parsed;
    st.step = 2;
    render();
  }

  /* ----------------------------------------------------- worked examples */
  // Net-new client-side starter blobs. They ship with acl_policy OMITTED —
  // the human still decides who can see it in step 4.
  function loadExample(which) {
    var ex = EXAMPLES[which];
    if (!ex) return;
    st = freshState();
    st.sourceName = ex.source;
    st.payloadText = JSON.stringify(ex.payload, null, 2);
    st.payload = ex.payload;
    st.routeConds = ex.routeConds || [];
    st.primaryKey = ex.primaryKey || "";
    st.validFrom = ex.validFrom || "";
    st.map = ex.map || [];
    st.content = ex.content || "";
    // acl intentionally left un-chosen.
    st.step = 2;
    render();
  }

  var EXAMPLES = {
    linear: {
      source: "linear",
      payload: { type: "Issue", action: "update", data: { id: "iss_1", title: "Fix the webhook", updatedAt: "2026-07-01T12:00:00.000Z", state: { name: "In Progress" }, team: { id: "team_9", members: [{ id: "u1" }, { id: "u2" }] } } },
      routeConds: [{ path: "type", op: "=", value: "Issue" }, { path: "action", op: "in", values: ["create", "update"] }],
      primaryKey: "data.id",
      validFrom: "data.updatedAt",
      map: [{ field: "title", path: "data.title" }, { field: "state", path: "data.state.name" }],
      content: "",
    },
    github: {
      source: "github",
      payload: { action: "opened", issue: { id: 42, title: "Crash on start", updated_at: "2026-07-01T12:00:00Z", user: { login: "octocat" }, body: "It crashes." } },
      routeConds: [{ path: "action", op: "in", values: ["opened", "edited"] }],
      primaryKey: "issue.id",
      validFrom: "issue.updated_at",
      map: [{ field: "title", path: "issue.title" }],
      content: "issue.body",
    },
    webhook: {
      source: "generic",
      payload: { event: "record.updated", record: { id: "rec_1", name: "Acme", updated: "2026-07-01T12:00:00Z" } },
      routeConds: [{ path: "event", op: "=", value: "record.updated" }],
      primaryKey: "record.id",
      validFrom: "record.updated",
      map: [{ field: "name", path: "record.name" }],
      content: "",
    },
  };

  /* ====================================================== payload walking */

  // Walk the parsed payload into flat nodes: { path, value, kind }.
  // kind: "leaf" (scalar), "object", "array". Arrays of objects emit a
  // synthetic "[]" descent so a click yields data.team.members[].id.
  function walkPayload() {
    var nodes = [];
    function scalarKind(v) {
      if (v === null) return "null";
      if (typeof v === "string") return "string";
      if (typeof v === "number") return "number";
      if (typeof v === "boolean") return "bool";
      return "";
    }
    function descend(v, path, depth) {
      if (depth > MAX_PAYLOAD_DEPTH) return;
      if (Array.isArray(v)) {
        nodes.push({ path: path, value: v, kind: "array", len: v.length });
        // descend into the FIRST object element with a "[]" path so members[].id works
        var firstObj = v.find(function (x) { return x && typeof x === "object" && !Array.isArray(x); });
        if (firstObj) descend(firstObj, path + "[]", depth + 1);
        return;
      }
      if (v && typeof v === "object") {
        if (path) nodes.push({ path: path, value: v, kind: "object", len: Object.keys(v).length });
        Object.keys(v).forEach(function (k) {
          descend(v[k], path ? path + "." + k : k, depth + 1);
        });
        return;
      }
      nodes.push({ path: path, value: v, kind: "leaf", scalar: scalarKind(v) });
    }
    descend(st.payload, "", 0);
    return nodes.filter(function (n) { return n.path; });
  }

  function nodeByPath(path) {
    return walkPayload().find(function (n) { return n.path === path; });
  }

  function looksTimestamp(v) {
    if (typeof v === "number") return v > 1e11; // epoch ms heuristic
    if (typeof v !== "string") return false;
    // RFC3339-ish
    return /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(v);
  }

  function shortVal(v) {
    if (v === null) return "null";
    if (typeof v === "string") return '"' + (v.length > 40 ? v.slice(0, 40) + "…" : v) + '"';
    if (typeof v === "object") return Array.isArray(v) ? "[" + v.length + " items]" : "{…}";
    return String(v);
  }

  /* ======================================================= STEP 2 · route */

  var OPS = [
    { op: "=", label: "is" },
    { op: "!=", label: "is not" },
    { op: "in", label: "is one of" },
  ];

  function stepRoute(host) {
    var scalarNodes = walkPayload().filter(function (n) { return n.kind === "leaf"; });
    host.innerHTML =
      '<div class="card">' +
        '<h2>② Which messages does this handle?</h2>' +
        '<div class="note" style="margin-top:0">We&rsquo;ll only act on messages that match. Build the rule by clicking values from your message &mdash; <b>no typing</b>. Rows are joined by <b>and</b>.</div>' +

        '<div id="mf-route-conds" style="margin-top:12px"></div>' +

        '<div class="toolbar" style="margin-top:10px">' +
          '<select id="mf-route-add" class="field" style="max-width:280px">' +
            '<option value="">+ add a condition on a value…</option>' +
            scalarNodes.map(function (n) {
              return '<option value="' + esc(n.path) + '">' + esc(n.path) + " = " + esc(shortVal(n.value)) + "</option>";
            }).join("") +
          "</select>" +
        "</div>" +

        '<div id="mf-route-match" style="margin-top:10px"></div>' +
        '<div id="mf-route-rule" class="api-crumb-block" style="margin-top:10px"></div>' +

        navRow(2) +
      "</div>";

    renderRouteConds();
    el("mf-route-add").addEventListener("change", function () {
      var p = this.value;
      if (!p) return;
      var n = nodeByPath(p);
      st.routeConds.push({ path: p, op: "=", value: n ? n.value : "" });
      this.value = "";
      renderRouteConds();
      renderRuleCrumb();
      renderPreview();
    });
    renderRuleCrumb();
    wireNav(2);
  }

  function renderRouteConds() {
    var host = el("mf-route-conds");
    if (!host) return;
    if (st.routeConds.length === 0) {
      host.innerHTML = '<div class="note" style="margin-top:0">No conditions yet — every message would be handled. Add a condition to narrow it.</div>';
      return;
    }
    host.innerHTML = st.routeConds.map(function (c, i) {
      var n = nodeByPath(c.path);
      var opts = OPS.map(function (o) {
        return '<option value="' + o.op + '"' + (c.op === o.op ? " selected" : "") + ">" + esc(o.label) + "</option>";
      }).join("");
      var valCtl;
      if (c.op === "in") {
        var chosen = c.values || [];
        valCtl = '<span class="mf-inlist" data-i="' + i + '">' +
          chosen.map(function (v, j) {
            return '<span class="chip mf-inchip" data-i="' + i + '" data-j="' + j + '">' + esc(String(v)) +
              ' <span class="mf-x" data-i="' + i + '" data-j="' + j + '">×</span></span>';
          }).join("") +
          '<input type="text" class="mf-inadd" data-i="' + i + '" placeholder="type a value + Enter" style="width:150px;display:inline-block">' +
          "</span>";
      } else {
        var observed = n && n.kind === "leaf" ? [n.value] : [];
        valCtl = '<select class="mf-condval field" data-i="' + i + '" style="max-width:200px">' +
          observed.map(function (v) {
            return '<option value="' + esc(String(v)) + '"' + (String(c.value) === String(v) ? " selected" : "") + ">" + esc(shortVal(v)) + "</option>";
          }).join("") +
          "</select>";
      }
      return '<div class="mf-cond" style="display:flex;gap:8px;align-items:center;margin-bottom:6px;flex-wrap:wrap">' +
        (i > 0 ? '<span class="mf-and">and</span>' : "<span class=\"mf-and\" style=\"visibility:hidden\">and</span>") +
        '<span class="ref">' + esc(c.path) + "</span>" +
        '<select class="mf-condop field" data-i="' + i + '" style="max-width:120px">' + opts + "</select>" +
        valCtl +
        '<span class="mf-x mf-cond-del" data-i="' + i + '" title="remove">×</span>' +
      "</div>";
    }).join("");

    host.querySelectorAll(".mf-condop").forEach(function (s) {
      s.addEventListener("change", function () {
        var i = Number(s.getAttribute("data-i"));
        st.routeConds[i].op = s.value;
        if (s.value === "in" && !st.routeConds[i].values) {
          st.routeConds[i].values = st.routeConds[i].value != null ? [st.routeConds[i].value] : [];
        }
        renderRouteConds(); renderRuleCrumb(); renderPreview();
      });
    });
    host.querySelectorAll(".mf-condval").forEach(function (s) {
      s.addEventListener("change", function () {
        var i = Number(s.getAttribute("data-i"));
        st.routeConds[i].value = s.value;
        renderRuleCrumb(); renderPreview();
      });
    });
    host.querySelectorAll(".mf-inadd").forEach(function (inp) {
      inp.addEventListener("keydown", function (e) {
        if (e.key !== "Enter") return;
        e.preventDefault();
        var i = Number(inp.getAttribute("data-i"));
        var v = inp.value.trim();
        if (!v) return;
        st.routeConds[i].values = (st.routeConds[i].values || []).concat([v]);
        renderRouteConds(); renderRuleCrumb(); renderPreview();
        var again = el("mf-route-conds").querySelector('.mf-inadd[data-i="' + i + '"]');
        if (again) again.focus();
      });
    });
    host.querySelectorAll(".mf-inchip .mf-x").forEach(function (x) {
      x.addEventListener("click", function () {
        var i = Number(x.getAttribute("data-i")), j = Number(x.getAttribute("data-j"));
        st.routeConds[i].values.splice(j, 1);
        renderRouteConds(); renderRuleCrumb(); renderPreview();
      });
    });
    host.querySelectorAll(".mf-cond-del").forEach(function (x) {
      x.addEventListener("click", function () {
        var i = Number(x.getAttribute("data-i"));
        st.routeConds.splice(i, 1);
        renderRouteConds(); renderRuleCrumb(); renderPreview();
      });
    });
  }

  // Build the predicate.rs `when` string. Grammar: <path> <op> <val>, joined
  // by `and`; `in` takes a bracketed list. String values are single-quoted.
  function routeWhen() {
    if (st.routeConds.length === 0) return "";
    return st.routeConds.map(function (c) {
      if (c.op === "in") {
        var list = (c.values || []).map(quoteLit).join(", ");
        return c.path + " in [" + list + "]";
      }
      return c.path + " " + c.op + " " + quoteLit(c.value);
    }).join(" and ");
  }

  function quoteLit(v) {
    if (typeof v === "number" || typeof v === "boolean") return String(v);
    var s = String(v);
    if (/^-?\d+(\.\d+)?$/.test(s)) return s;
    if (s === "true" || s === "false") return s;
    return "'" + s.replace(/'/g, "\\'") + "'";
  }

  function renderRuleCrumb() {
    var host = el("mf-route-rule");
    if (!host) return;
    var w = routeWhen();
    host.innerHTML = w
      ? "rule: <span class=\"ref\">" + esc(w) + "</span>"
      : "rule: <span class=\"ref\">(match every message)</span>";
  }

  /* ====================================================== STEP 3 · fields */

  function stepFields(host) {
    host.innerHTML =
      '<div class="card">' +
        '<h2>③ What should Verity remember?</h2>' +
        '<div class="note" style="margin-top:0">Click values in your message to map them. ' +
          'Pick one value as the <b>stable ID</b> (so updates land on the same record), an <b>event time</b>, and any fields to keep. ' +
          'A long text value can become the record&rsquo;s <b>free text</b>.</div>' +

        '<div id="mf-map-summary" style="margin-top:12px"></div>' +

        '<div class="mf-tree" style="margin-top:12px;border:1px solid var(--border);border-radius:var(--r-sm);padding:10px 12px;max-height:360px;overflow:auto"></div>' +

        '<div class="err" id="mf-fields-err" style="margin-top:8px"></div>' +

        navRow(3) +
      "</div>";
    renderMapSummary();
    renderTree(host.querySelector(".mf-tree"));
    wireNav(3);
  }

  function renderMapSummary() {
    var host = el("mf-map-summary");
    if (!host) return;
    var rows = [];
    rows.push(chipLine("Stable ID", st.primaryKey ? st.primaryKey : null, "pick a value below", "pk"));
    rows.push(eventTimeRow());
    var mapTxt = st.map.length
      ? st.map.map(function (m, i) {
          return "<b>" + esc(m.field) + "</b> ← " + V.refSpan(m.path) +
            ' <span class="mf-x" data-mapi="' + i + '" title="remove">×</span>';
        }).join(" · ")
      : null;
    rows.push('<div class="mf-sumrow"><span class="mf-sumlabel">Fields</span> ' +
      (mapTxt || '<span class="note" style="margin:0">nothing kept yet — click <b>+field</b> on a value</span>') +
      (st.map.length ? '  <span class="asof">(' + st.map.length + " of " + MAX_MAP_FIELDS + " max)</span>" : "") + "</div>");
    rows.push('<div class="mf-sumrow"><span class="mf-sumlabel">Free text</span> ' +
      (st.content ? V.refSpan(st.content) + ' <span class="mf-x" id="mf-clear-content" title="unset">×</span>'
        : '<span class="note" style="margin:0">none — optional</span>') + "</div>");
    host.innerHTML = rows.join("");
    var cc = el("mf-clear-content");
    if (cc) cc.addEventListener("click", function () { st.content = ""; renderMapSummary(); renderPreview(); });
    var now = el("mf-now");
    if (now) now.addEventListener("click", function () { st.validFrom = "$now()"; renderMapSummary(); renderPreview(); });
    // per-field remove
    host.querySelectorAll(".mf-x[data-mapi]").forEach(function (x) {
      x.addEventListener("click", function () {
        var i = Number(x.getAttribute("data-mapi"));
        st.map.splice(i, 1);
        renderMapSummary(); renderPreview();
      });
    });
    // clear pk / event time
    host.querySelectorAll(".mf-x[data-clear]").forEach(function (x) {
      x.addEventListener("click", function () {
        var k = x.getAttribute("data-clear");
        if (k === "pk") st.primaryKey = "";
        else if (k === "vf") st.validFrom = "";
        renderMapSummary(); renderPreview();
      });
    });
  }

  function chipLine(label, valuePath, hint, kind) {
    if (valuePath) {
      return '<div class="mf-sumrow"><span class="mf-sumlabel">' + esc(label) + "</span> " +
        V.refSpan(valuePath) + ' <span class="mf-x" data-clear="' + kind + '" title="unset">×</span></div>';
    }
    return '<div class="mf-sumrow"><span class="mf-sumlabel">' + esc(label) + '</span> <span class="note" style="margin:0">' + esc(hint) + "</span></div>";
  }

  // Event time is special: it can be a clicked value OR the built-in $now().
  function eventTimeRow() {
    var v = st.validFrom;
    var shown = v
      ? (v === "$now()"
          ? '<span class="ref">when the message arrives</span>'
          : V.refSpan(v)) +
        ' <span class="mf-x" data-clear="vf" title="unset">×</span>'
      : '<span class="note" style="margin:0">pick a date/time value below, or</span> ' +
        '<button id="mf-now" style="padding:1px 8px;font-size:var(--fs-xs)">use “when it arrives”</button>';
    return '<div class="mf-sumrow"><span class="mf-sumlabel">Event time</span> ' + shown + "</div>";
  }

  function renderTree(treeEl) {
    var nodes = walkPayload();
    treeEl.innerHTML = nodes.map(function (n) {
      var indent = (n.path.split(/\.|\[\]/).length - 1) * 14;
      var affor = "";
      if (n.kind === "leaf") {
        affor += treeBtn("field", n.path, "+field");
        affor += treeBtn("pk", n.path, "pk");
        if (looksTimestamp(n.value)) affor += treeBtn("vf", n.path, "event time");
        if (n.scalar === "string") affor += treeBtn("content", n.path, "as content");
      }
      // ACL candidate shortcut on *.id / members[].id nodes
      if (/(^|\.)id$/.test(n.path) || /\[\]\.id$/.test(n.path)) {
        affor += treeBtn("acl", n.path, "who can see it →");
      }
      var valStr = n.kind === "leaf"
        ? '<span class="mf-treeval">' + esc(shortVal(n.value)) + "</span>"
        : '<span class="mf-treekind">' + (n.kind === "array" ? "[" + n.len + " items]" : "{" + n.len + " keys}") + "</span>";
      return '<div class="mf-node" style="padding-left:' + indent + 'px">' +
        '<span class="ref mf-nodepath">' + esc(lastSeg(n.path)) + "</span> " + valStr +
        '<span class="mf-affor">' + affor + "</span>" +
      "</div>";
    }).join("");

    treeEl.querySelectorAll(".mf-treebtn").forEach(function (b) {
      b.addEventListener("click", function () {
        var kind = b.getAttribute("data-kind"), path = b.getAttribute("data-path");
        onTreeAction(kind, path);
      });
    });
    // add $now() one-click for event time
    // (rendered as part of the event-time summary hint below the tree)
  }

  function treeBtn(kind, path, label) {
    return '<button class="mf-treebtn" data-kind="' + kind + '" data-path="' + esc(path) + '">' + esc(label) + "</button>";
  }
  function lastSeg(path) {
    var parts = path.split(".");
    return parts[parts.length - 1];
  }

  function onTreeAction(kind, path) {
    if (kind === "pk") { st.primaryKey = path; }
    else if (kind === "vf") { st.validFrom = path; }
    else if (kind === "content") { st.content = path; }
    else if (kind === "field") {
      if (st.map.length >= MAX_MAP_FIELDS) {
        var fe = el("mf-fields-err");
        if (fe) { fe.textContent = "That’s the most fields Verity keeps per record (" + MAX_MAP_FIELDS + " max). Remove one to add another."; fe.classList.add("on"); }
        return;
      }
      var field = lastSeg(path);
      if (st.map.some(function (m) { return m.path === path; })) return;
      st.map.push({ field: field, path: path });
    } else if (kind === "acl") {
      // jump to step 4 with this node as a candidate (never pre-select)
      st.acl._candidatePath = path;
      st.step = 4;
      render();
      return;
    }
    renderMapSummary();
    renderPreview();
    // rewire summary × handlers (delegated)
    var host = el("mf-map-summary");
    if (host) host.querySelectorAll(".mf-x[data-clear]").forEach(function (x) {
      x.addEventListener("click", function () {
        var k = x.getAttribute("data-clear");
        if (k === "pk") st.primaryKey = "";
        else if (k === "vf") st.validFrom = "";
        renderMapSummary(); renderPreview();
      });
    });
  }

  /* ========================================================= STEP 4 · ACL */
  // THE HUMAN GATE. No pre-selection. The build throws until acl.chosen.

  var ACL_CHOICES = [
    {
      key: "mirror",
      title: "The message already names who — mirror it exactly",
      body: "The message lists the exact people who should see this (their emails or IDs). We copy that, unchanged.",
      tier: "A",
    },
    {
      key: "rough",
      title: "The message names a rough audience — use it, marked approximate",
      body: "The message names a team or workspace, not the exact people. We use it and mark it approximate, and you say why.",
      tier: "B",
    },
    {
      key: "fixed",
      title: "I’ll pick a fixed set of people myself",
      body: "The message doesn’t say who should see this. You choose a fixed set of people or groups by name.",
      tier: "C",
    },
    {
      key: "hold",
      title: "Hold everything for now",
      body: "Not sure yet? Every message from this source is held (quarantined) until you decide. Safe by default.",
      tier: null,
    },
  ];

  function stepAcl(host) {
    host.innerHTML =
      '<div class="card">' +
        '<h2>④ Who can see it?</h2>' +
        '<div class="mf-gate-banner" style="background:var(--amber-soft);border:1px solid var(--amber-line);color:var(--amber);' +
          'border-radius:var(--r-sm);padding:var(--sp-2) var(--sp-3);margin-bottom:var(--sp-4);font-size:12px;line-height:1.5">' +
          'This is the <b style="color:var(--text);font-weight:600">one choice we can’t make for you</b>. A wrong answer here leaks private data into shared memory &mdash; ' +
          'so nothing is pre-picked, and until you choose, <b style="color:var(--text);font-weight:600">every message from this source is held</b>.' +
        "</div>" +

        (st.acl._candidatePath
          ? '<div class="note" style="margin-top:0">You came from <span class="ref">' + esc(st.acl._candidatePath) + '</span> &mdash; if you mirror or use the message’s audience, that’s a good path to point at. It is <b>only a suggestion</b>; nothing is selected.</div>'
          : "") +

        '<div id="mf-acl-choices" style="margin-top:12px"></div>' +
        '<div id="mf-acl-detail" style="margin-top:12px"></div>' +
        '<div class="err" id="mf-acl-err" style="margin-top:8px"></div>' +

        navRow(4) +
      "</div>";

    renderAclChoices();
    renderAclDetail();
    wireNav(4);
  }

  function renderAclChoices() {
    var host = el("mf-acl-choices");
    if (!host) return;
    host.innerHTML = ACL_CHOICES.map(function (c) {
      var on = st.acl.choice === c.key;
      // NO radio carries `checked`; selection is an explicit click.
      return '<label class="mf-aclopt' + (on ? " on" : "") + '" data-key="' + c.key + '">' +
        '<input type="radio" name="mf-acl" value="' + c.key + '"' + (on ? " checked" : "") + '>' +
        '<span class="mf-aclopt-body"><b>' + esc(c.title) + "</b>" +
          '<span class="note" style="margin-top:2px;display:block">' + esc(c.body) + "</span></span>" +
      "</label>";
    }).join("");
    host.querySelectorAll('input[name="mf-acl"]').forEach(function (r) {
      r.addEventListener("change", function () {
        st.acl.chosen = true;
        st.acl.choice = r.value;
        renderAclChoices();
        renderAclDetail();
        validateAclInline();
        renderPreview();
      });
    });
  }

  function nsSelect() {
    var opts = [
      { v: "", label: "— how are people named? —" },
      { v: "email", label: "these are email addresses" },
      { v: "source_native_id", label: "this source’s own IDs" },
      { v: "verity_group", label: "group names you use in Verity" },
    ];
    return '<select id="mf-acl-ns" class="field" style="max-width:280px">' +
      opts.map(function (o) {
        return '<option value="' + o.v + '"' + (st.acl.namespace === o.v ? " selected" : "") + ">" + esc(o.label) + "</option>";
      }).join("") + "</select>";
  }

  // candidate paths for the principals picker: *.id / members[].id nodes
  function aclCandidatePaths() {
    return walkPayload().filter(function (n) {
      return /(^|\.)id$/.test(n.path) || /\[\]\.id$/.test(n.path) ||
        /members\b/.test(n.path) || /(^|\.)team\b/.test(n.path);
    }).map(function (n) { return n.path; });
  }

  function renderAclDetail() {
    var host = el("mf-acl-detail");
    if (!host) return;
    var c = st.acl.choice;
    if (!c) { host.innerHTML = '<div class="note" style="margin:0">Pick one above to continue. Nothing is selected for you.</div>'; return; }

    if (c === "hold") {
      host.innerHTML = '<div class="note" style="margin:0">Every message from this source will be <b>held</b> until an admin adds a rule later. This is always a valid, safe choice.</div>';
      return;
    }

    if (c === "mirror" || c === "rough") {
      var cands = aclCandidatePaths();
      var candOpts = ['<option value="">— point at the value that names who —</option>']
        .concat(cands.map(function (p) {
          return '<option value="' + esc(p) + '"' + (st.acl.principalsPath === p ? " selected" : "") + ">" + esc(p) + "</option>";
        })).join("");
      host.innerHTML =
        '<div><label for="mf-acl-principals">Which value names who can see it?</label>' +
          '<select id="mf-acl-principals" class="field" style="max-width:320px">' + candOpts + "</select>" +
          '<div class="note" style="margin-top:2px">Click a value with people’s IDs or emails' +
            (c === "rough" ? " (a team or its members)" : "") + ". These are suggestions from your message; nothing is picked for you.</div>" +
        "</div>" +
        '<div style="margin-top:10px"><label for="mf-acl-ns">How are those named?</label>' + nsSelect() + "</div>" +
        (c === "rough"
          ? '<div style="margin-top:10px"><label for="mf-acl-note">Why is this only approximate? <span style="font-weight:400">(an admin reads this before approving)</span></label>' +
              '<textarea id="mf-acl-note" style="min-height:60px" placeholder="e.g. Team membership stands in for who can see each issue.">' + esc(st.acl.note) + "</textarea></div>"
          : "");
      var pp = el("mf-acl-principals");
      pp.addEventListener("change", function () { st.acl.principalsPath = pp.value; validateAclInline(); renderPreview(); });
      var ns = el("mf-acl-ns");
      ns.addEventListener("change", function () { st.acl.namespace = ns.value; validateAclInline(); renderPreview(); });
      var note = el("mf-acl-note");
      if (note) note.addEventListener("input", function () { st.acl.note = note.value; validateAclInline(); renderPreview(); });
      // The candidate node that got us here is OFFERED in the dropdown but is
      // never auto-selected — suggesting is not deciding.
      return;
    }

    if (c === "fixed") {
      host.innerHTML =
        '<div><label>Pick who can see it — people &amp; groups on record for this space</label>' +
          '<div id="mf-acl-picker" style="margin-top:6px"></div>' +
        "</div>" +
        '<div class="note" style="margin-top:8px">You pick the exact keys from the named directory — you never type raw tokens.<span class="api-crumb"> (GET /v1/admin/principals)</span></div>';
      var mount = el("mf-acl-picker");
      if (aclPicker) { aclPicker.destroy(); aclPicker = null; }
      aclPicker = V.principalPicker(mount, {
        tenantId: function () { return V.tenant(); },
        placeholder: "filter people & groups",
        emptyTitle: "No people or groups on record yet",
        emptyBody: "Add people or groups to this space first, then pick from them here.",
        emptyAction: "Open People & groups",
        onOpenDirectory: function () { V.show("principals"); },
        onChange: function (sel) { st.acl.staticViewers = sel; validateAclInline(); renderPreview(); },
      });
      aclPicker.set(st.acl.staticViewers || []);
      aclPicker.load(V.tenant());
      return;
    }
  }

  // Inline enforcement mirroring activation_check, BEFORE Next. Returns true
  // when the ACL step is valid for the current choice.
  function aclStepValid() {
    var a = st.acl;
    if (!a.chosen) return false;
    if (a.choice === "hold") return true;
    if (a.choice === "mirror") return !!a.principalsPath && !!a.namespace;
    if (a.choice === "rough") return !!a.principalsPath && !!a.namespace && !!a.note.trim();
    if (a.choice === "fixed") return (a.staticViewers || []).length > 0;
    return false;
  }

  function validateAclInline() {
    var e = el("mf-acl-err");
    if (!e) return;
    var a = st.acl;
    var msg = "";
    if (a.choice === "mirror") {
      if (!a.principalsPath) msg = "Point at the value in your message that names who can see it.";
      else if (!a.namespace) msg = "Say how those people are named (emails, source IDs, or group names).";
    } else if (a.choice === "rough") {
      if (!a.principalsPath) msg = "Point at the value that names the rough audience (a team or its members).";
      else if (!a.namespace) msg = "Say how those are named.";
      else if (!a.note.trim()) msg = "Say what makes this approximate — an admin reads this when they approve.";
    } else if (a.choice === "fixed") {
      if ((a.staticViewers || []).length === 0) msg = "Pick at least one key — a fixed audience can’t be empty.";
    }
    if (msg) { e.textContent = msg; e.classList.add("on"); }
    else V.clearErr(e);
    // reflect on the nav Next button
    var next = el("mf-next-4");
    if (next) next.disabled = !aclStepValid();
  }

  /* ================================================ manifest assembly */

  // Verity.manifest.build(state) — serialize the structured draft to YAML.
  // THROWS if the ACL step is not an explicit human choice: the preview,
  // download, and upload literally cannot be produced from an un-chosen ACL.
  function buildYaml() {
    if (!st.acl.chosen) {
      throw new Error("acl_policy is a human choice — the wizard cannot produce a manifest until step 4 is answered");
    }
    return assembleYaml(true);
  }

  // assembleYaml(withAcl): when withAcl is false, acl_policy is OMITTED — used
  // for the pre-step-4 preview, where apply() honestly quarantines on absent
  // acl_policy (fail-closed shown early, never a fabricated audience).
  function assembleYaml(withAcl) {
    var L = [];
    L.push("manifest_version: 1");
    L.push("source:");
    L.push("  name: " + yStr(st.sourceName || "source"));
    var tier = withAcl ? inferredTier() : null;
    if (tier) L.push("  tier: " + tier);
    L.push("entities:");
    L.push("  - type: " + yStr(entityType()));
    L.push("    route:");
    var when = routeWhen();
    L.push("      when: " + yStr(when || "true"));
    L.push("    primary_key: " + yStr(st.primaryKey || ""));
    if (st.validFrom) L.push("    valid_from: " + yStr(st.validFrom));
    if (st.map.length) {
      L.push("    map:");
      st.map.forEach(function (m) { L.push("      " + yKey(m.field) + ": " + yStr(m.path)); });
    } else {
      L.push("    map: {}");
    }
    if (st.content) L.push("    content: " + yStr(st.content));

    if (withAcl && st.acl.choice && st.acl.choice !== "hold") {
      L.push("acl_policy:");
      if (st.acl.choice === "mirror") {
        L.push("  mode: map");
        L.push("  identity_namespace: " + st.acl.namespace);
        L.push("  principals: " + yStr(st.acl.principalsPath));
        L.push("  approximation: false");
      } else if (st.acl.choice === "rough") {
        L.push("  mode: map");
        L.push("  identity_namespace: " + st.acl.namespace);
        L.push("  principals: " + yStr(st.acl.principalsPath));
        L.push("  approximation: true");
        L.push("  note: " + yStr(st.acl.note.trim()));
      } else if (st.acl.choice === "fixed") {
        L.push("  mode: static");
        L.push("  static_visibility:");
        (st.acl.staticViewers || []).forEach(function (p) {
          L.push("    - " + yStr(p.principal || String(p.token)));
        });
      }
    }
    // choice === "hold" (or withAcl false): acl_policy omitted → quarantine.
    return L.join("\n") + "\n";
  }

  function inferredTier() {
    if (st.acl.choice === "mirror") return "A";
    if (st.acl.choice === "rough") return "B";
    if (st.acl.choice === "fixed") return "C";
    return null; // hold — no tier
  }

  function entityType() {
    // a friendly default entity type from the source name
    return (st.sourceName || "record").replace(/[^a-z0-9_]/g, "_") || "record";
  }

  function yStr(s) {
    s = String(s);
    // always quote to be safe with special chars in JSONata/paths
    return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }
  function yKey(s) {
    // map keys: bare if simple, else quoted
    return /^[A-Za-z_][A-Za-z0-9_]*$/.test(s) ? s : yStr(s);
  }

  /* ============================================== dry-run / live preview */

  // The preview re-fetches here. It fires from step 2 on, after EVERY change
  // (renderPreview → previewFetch). Before step 4 the request carries NO
  // acl_policy, so apply() itself quarantines (honest fail-closed).
  function renderPreview() {
    var host = el("mf-preview");
    if (!host) return;
    if (st.step < 2 || !st.payload) { host.innerHTML = ""; return; }
    // header + a "checking…" line; the fetch fills the body
    host.innerHTML =
      '<div class="card" style="position:sticky;top:12px">' +
        '<h2 style="font-size:var(--fs-md)">Live preview</h2>' +
        '<div class="note" style="margin-top:0">What this exact message becomes — real output from Verity’s engine, run on a pinned clock so it’s repeatable.<span class="api-crumb"> (POST /v1/manifests/dry-run)</span></div>' +
        '<div id="mf-preview-body" style="margin-top:10px"><span class="asof">checking…</span></div>' +
      "</div>";
    previewFetch();
  }

  var previewDebounce = null;
  function previewFetch() {
    if (previewDebounce) clearTimeout(previewDebounce);
    previewDebounce = setTimeout(doPreviewFetch, 180);
  }

  function doPreviewFetch() {
    var seq = ++previewSeq;
    var withAcl = st.step >= 4 && st.acl.chosen && st.acl.choice !== "hold" && aclStepValid();
    var yaml;
    try {
      yaml = assembleYaml(withAcl);
    } catch (e) {
      renderPreviewBody({ localErr: e.message });
      return;
    }
    var body = { tenant_id: V.tenant(), manifest_yaml: yaml, sample_payload: st.payload };
    V.api("/v1/manifests/dry-run", { json: body, admin: true })
      .then(function (res) {
        if (seq !== previewSeq) return; // stale
        lastPreview = res; lastPreviewErr = null;
        renderPreviewBody({ res: res });
      })
      .catch(function (e) {
        if (seq !== previewSeq) return;
        // 422 → from_yaml verbatim, mapped to a step. Other errors surface raw.
        var m = String(e.message || e);
        var parsed = extract422(m);
        lastPreview = null; lastPreviewErr = parsed;
        renderPreviewBody({ err: m, parsed: parsed });
      });
  }

  // Pull the { error } body out of api()'s "path — HTTP 422: {json}" message.
  function extract422(msg) {
    var m = /HTTP 422:\s*(\{[\s\S]*\})/.exec(msg);
    if (!m) return null;
    try {
      var j = JSON.parse(m[1]);
      return { error: j.error || m[1], step: mapErrToStep(j.error || "") };
    } catch (e) { return { error: m[1], step: null }; }
  }

  function mapErrToStep(errStr) {
    var s = errStr.toLowerCase();
    if (s.indexOf("acl_policy") >= 0 || s.indexOf("identity_namespace") >= 0 || s.indexOf("principals") >= 0) return 4;
    if (s.indexOf("route") >= 0 || s.indexOf("when") >= 0 || s.indexOf("predicate") >= 0) return 2;
    if (s.indexOf("map.") >= 0 || s.indexOf("primary_key") >= 0 || s.indexOf("valid_from") >= 0 || s.indexOf("path") >= 0) return 3;
    return null;
  }

  function renderPreviewBody(o) {
    refreshRouteMatch();
    var host = el("mf-preview-body");
    if (!host) return;

    if (o.localErr) {
      host.innerHTML = '<div class="note" style="margin:0">' + esc(o.localErr) + "</div>";
      return;
    }

    if (o.err) {
      // 422 during authoring — map to the offending step
      var p = o.parsed;
      var line = p ? p.error : o.err;
      host.innerHTML =
        '<div class="mf-band mf-band-warn">The manifest doesn’t parse yet.</div>' +
        '<div class="note" style="margin-top:6px">' + esc(line) + "</div>" +
        (p && p.step ? '<button style="margin-top:8px" id="mf-fix-parse">Fix in step ' + p.step + " →</button>" : "");
      var fx = el("mf-fix-parse");
      if (fx && p && p.step) fx.addEventListener("click", function () { st.step = p.step; render(); });
      return;
    }

    var res = o.res;
    if (!res) { host.innerHTML = '<span class="asof">no preview</span>'; return; }

    if (res.outcome === "quarantine") {
      renderQuarantinePreview(host, res.reason);
      return;
    }
    // writes
    renderWritesPreview(host, res);
  }

  // Live "does this sample match?" line on the route step, driven by the same
  // dry-run round-trip as the preview pane.
  function refreshRouteMatch() {
    var m = el("mf-route-match");
    if (!m) return; // not on the route step
    if (lastPreview && lastPreview.outcome === "quarantine" &&
        /no entity route matched/.test(lastPreview.reason || "")) {
      m.innerHTML = '<div class="mf-band mf-band-warn">This sample would NOT be handled — is this the right rule?</div>';
    } else if (lastPreview) {
      // any non-route-miss outcome means the route matched (mapping/ACL come next)
      m.innerHTML = '<div class="mf-band mf-band-ok">✓ This sample matches — it would be handled.</div>';
    } else {
      m.innerHTML = "";
    }
  }

  // Quarantine as a first-class TEACHING card, not a red error. Reason shown
  // verbatim (in .api-crumb when API details on) + plain gloss + a fix pivot.
  function renderQuarantinePreview(host, reason) {
    reason = reason || "";
    var g = glossQuarantine(reason);
    // The absent-ACL reason before step 4 is the EXPECTED teach state.
    var preAcl = /acl_policy absent/.test(reason);
    host.innerHTML =
      '<div class="mf-band ' + (preAcl ? "mf-band-warn" : "mf-band-hold") + '">' +
        (preAcl ? "⚠ Who could see it: not decided yet" : "This message would be held") +
      "</div>" +
      '<div class="note" style="margin-top:6px">' + esc(g.plain) + "</div>" +
      '<div class="api-crumb-block" style="margin-top:6px">reason: <span class="ref">' + esc(reason) + "</span></div>" +
      (g.step ? '<button style="margin-top:8px" data-fixstep="' + g.step + '">' + esc(g.fix) + "</button>" : "");
    var b = host.querySelector("button[data-fixstep]");
    if (b) b.addEventListener("click", function () {
      st.step = Number(b.getAttribute("data-fixstep")); render();
    });
  }

  // Map the runtime's verbatim reason substring → plain gloss + fix pivot.
  function glossQuarantine(reason) {
    var r = reason;
    if (/acl_policy absent/.test(r)) {
      return { plain: "You haven’t chosen who can see this yet, so every message is held until you do.", step: 4, fix: "Choose who can see it →" };
    }
    if (/no entity route matched/.test(r)) {
      return { plain: "None of your route rules match this message.", step: 2, fix: "Fix the rule →" };
    }
    if (/primary_key/.test(r)) {
      return { plain: "We can’t find a stable ID in this message.", step: 3, fix: "Pick a stable ID →" };
    }
    var mMap = /map\.([A-Za-z0-9_]+)/.exec(r);
    if (mMap) {
      return { plain: "The field “" + mMap[1] + "” isn’t in this message.", step: 3, fix: "Fix fields →" };
    }
    if (/valid_from/.test(r)) {
      return { plain: "That value isn’t a date/time Verity can read.", step: 3, fix: "Re-pick the event time →" };
    }
    if (/acl principal extraction/.test(r) || /matched nothing/.test(r)) {
      return { plain: "No one to grant visibility to was found at that value.", step: 4, fix: "Fix who can see it →" };
    }
    if (/nesting exceeds|output exceeds|value cap|byte cap/.test(r)) {
      return { plain: "This message is past one of Verity’s size limits (the number is in the reason).", step: null, fix: "" };
    }
    return { plain: "Verity held this message rather than mis-file it.", step: null, fix: "" };
  }

  function renderWritesPreview(host, res) {
    var w = (res.writes && res.writes[0]) || null;
    var acl = res.acl || null;
    var parts = [];
    parts.push('<div class="mf-band mf-band-ok">Ready — this message becomes memory</div>');

    if (w) {
      var fieldKeys = w.fields ? Object.keys(w.fields).sort() : [];
      parts.push('<div class="kv" style="margin-top:8px">' +
        "<dt>record</dt><dd>" + esc(w.entity_type) + ":" + esc(w.entity_id) + "</dd>" +
        "<dt>event time</dt><dd>" + esc(w.valid_from || "—") + "</dd>" +
        "</div>");
      // Only the "$now()" builtin is clock-derived; a payload timestamp is the
      // message's real value. Label honestly, per THE LAW (nothing fabricated).
      if (st.validFrom === "$now()") {
        parts.push('<div class="asof" style="margin-top:2px">event time is pinned for a repeatable preview</div>');
      }
      if (fieldKeys.length) {
        parts.push('<div style="margin-top:8px"><b>' + fieldKeys.length + " field" + (fieldKeys.length === 1 ? "" : "s") + " kept</b></div>");
        parts.push('<div class="tablewrap"><table><tbody>' +
          fieldKeys.map(function (k) {
            return "<tr><td class=\"ref\">" + esc(k) + "</td><td>" + esc(String(w.fields[k])) + "</td></tr>";
          }).join("") +
          "</tbody></table></div>");
      }
      // free text from the client draft (to_json does NOT emit content — we
      // render it from what WE mapped, honestly labeled).
      if (st.content) {
        var cv = readPath(st.payload, st.content);
        if (cv != null) {
          parts.push('<div style="margin-top:8px"><b>free text</b><div class="note" style="margin-top:2px">' +
            esc(String(cv).slice(0, 200)) + (String(cv).length > 200 ? "…" : "") + "</div></div>");
        }
      }
    }

    // Who could see it — from the real AclEnvelope, or the pre-step-4 hold.
    parts.push('<div style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px">');
    parts.push('<div style="font-weight:600;margin-bottom:4px">Who could see it</div>');
    if (acl) {
      parts.push(aclEnvelopeHtml(acl));
    } else {
      parts.push('<div class="mf-band mf-band-warn">⚠ Not decided yet — this message would be held (quarantined) until you choose in step ④.</div>');
    }
    parts.push("</div>");

    host.innerHTML = parts.join("");
  }

  function aclEnvelopeHtml(acl) {
    var prov = acl.acl_provenance;
    var principals = acl.principals;
    if (acl.mode === "map") {
      if (prov === "approximated") {
        return '<div><span class="badge b-approximated">approximate</span> <span class="note" style="margin:0">team membership stands in for who can see this</span></div>' +
          principalListHtml(principals);
      }
      return '<div><span class="badge b-mirrored">mirrored</span> <span class="note" style="margin:0">exact — mirrors the source’s real permissions</span></div>' +
        principalListHtml(principals);
    }
    if (acl.mode === "static") {
      if (principals && principals.length) {
        return '<div><span class="note" style="margin:0">a fixed set you chose:</span></div>' + principalListHtml(principals);
      }
      return '<div class="note" style="margin:0">whoever the webhook URL is minted for.</div>';
    }
    return '<div class="note" style="margin:0">held — no one, until an admin adds a rule.</div>';
  }

  function principalListHtml(principals) {
    if (!principals || !principals.length) return '<div class="note" style="margin:2px 0 0">— no one matched</div>';
    return '<div style="margin-top:4px">' +
      principals.map(function (p) { return '<span class="chip" style="margin:2px 4px 2px 0">' + esc(p) + "</span>"; }).join("") +
      '</div><div class="asof">' + principals.length + " key" + (principals.length === 1 ? "" : "s") + " named</div>";
  }

  // minimal client-side path reader for content preview (dot + [] arrays)
  function readPath(obj, path) {
    var parts = path.split(".");
    var cur = obj;
    for (var i = 0; i < parts.length; i++) {
      var seg = parts[i];
      if (seg.endsWith("[]")) {
        var base = seg.slice(0, -2);
        cur = cur && cur[base];
        if (!Array.isArray(cur)) return null;
        cur = cur[0];
      } else {
        if (cur == null) return null;
        cur = cur[seg];
      }
    }
    return cur;
  }

  /* ==================================================== STEP 5 · review */

  function stepReview(host) {
    var yaml;
    try { yaml = buildYaml(); } catch (e) { yaml = null; }
    host.innerHTML =
      '<div class="card">' +
        '<h2>⑤ Review, test, save as draft</h2>' +
        '<div class="note" style="margin-top:0">Here’s what you built, in plain language. The full manifest is below the &ldquo;show API details&rdquo; toggle.</div>' +

        '<div id="mf-review-summary" style="margin-top:10px"></div>' +

        '<div id="mf-test-line" style="margin-top:12px"></div>' +

        '<div class="api-crumb-block" style="margin-top:12px">' +
          '<label>the manifest (YAML)</label>' +
          '<pre class="mf-yaml">' + esc(yaml || "(cannot build — finish step ④)") + "</pre>" +
        "</div>" +

        '<div class="toolbar" style="margin-top:14px">' +
          '<button id="mf-download">Download test bundle</button>' +
          '<button class="primary" id="mf-save-draft">Save as draft</button>' +
          '<span class="spacer"></span>' +
        "</div>" +
        '<div class="err" id="mf-review-err" style="margin-top:8px"></div>' +
        '<div id="mf-save-receipt" style="margin-top:10px"></div>' +

        '<div class="note" style="margin-top:12px">Saving stores a <b>draft</b> — it is not live. Turning a source on is a separate step an admin approves, with the reason recorded.<span class="api-crumb"> (POST /v1/manifests then POST /v1/manifests/{id}/activate)</span></div>' +

        navRow(5) +
      "</div>";

    renderReviewSummary();
    renderTestLine();
    wireNav(5);
    el("mf-download").addEventListener("click", downloadBundle);
    el("mf-save-draft").addEventListener("click", saveDraft);
  }

  function renderReviewSummary() {
    var host = el("mf-review-summary");
    if (!host) return;
    var whenTxt = st.routeConds.length
      ? "messages where " + st.routeConds.map(condPlain).join(" and ")
      : "every message";
    var aclPlain = aclChoicePlain();
    host.innerHTML =
      '<div class="kv">' +
        "<dt>Source</dt><dd>" + esc(st.sourceName) + "</dd>" +
        "<dt>Handles</dt><dd style=\"font-family:inherit\">" + esc(whenTxt) + "</dd>" +
        "<dt>Stable ID</dt><dd>" + esc(st.primaryKey || "—") + "</dd>" +
        (st.validFrom ? "<dt>Event time</dt><dd>" + esc(st.validFrom) + "</dd>" : "") +
        "<dt>Fields kept</dt><dd style=\"font-family:inherit\">" + (st.map.length ? st.map.map(function (m) { return m.field; }).join(", ") : "—") + "</dd>" +
        (st.content ? "<dt>Free text</dt><dd>" + esc(st.content) + "</dd>" : "") +
        "<dt>Who can see it</dt><dd style=\"font-family:inherit\">" + esc(aclPlain) + "</dd>" +
      "</div>";
  }

  function condPlain(c) {
    if (c.op === "in") return c.path + " is one of " + (c.values || []).join(", ");
    return c.path + " " + (c.op === "!=" ? "is not" : "is") + " " + c.value;
  }

  function aclChoicePlain() {
    var c = st.acl.choice;
    if (c === "mirror") return "mirror exactly who the message names";
    if (c === "rough") return "the rough audience the message names (approximate)";
    if (c === "fixed") return "a fixed set of " + (st.acl.staticViewers || []).length + " you picked";
    if (c === "hold") return "held for now — nothing is visible until an admin adds a rule";
    return "— not chosen";
  }

  // Run the sample through the manifest via dry-run under the pinned clock and
  // report labeled numbers. This IS the golden the fixture bundle ships.
  function renderTestLine() {
    var host = el("mf-test-line");
    if (!host) return;
    host.innerHTML = '<span class="asof">testing this message…</span>';
    var yaml;
    try { yaml = buildYaml(); } catch (e) { host.innerHTML = '<div class="note" style="margin:0">' + esc(e.message) + "</div>"; return; }
    V.api("/v1/manifests/dry-run", { json: { tenant_id: V.tenant(), manifest_yaml: yaml, sample_payload: st.payload }, admin: true })
      .then(function (res) {
        lastPreview = res; lastPreviewErr = null;
        if (res.outcome === "quarantine") {
          var g = glossQuarantine(res.reason || "");
          host.innerHTML = '<div class="mf-band mf-band-hold">This message would be held.</div>' +
            '<div class="note" style="margin-top:4px">' + esc(g.plain) + "</div>";
          return;
        }
        var w = (res.writes && res.writes[0]) || {};
        var nFields = w.fields ? Object.keys(w.fields).length : 0;
        var nKeys = (res.acl && res.acl.principals) ? res.acl.principals.length : 0;
        var visTxt = res.acl
          ? (res.acl.mode === "static" && !nKeys ? "visible to whoever the webhook is minted for"
            : "visible to " + nKeys + " key" + (nKeys === 1 ? "" : "s"))
          : "held";
        host.innerHTML =
          '<div class="mf-band mf-band-ok">✓ produced ' + (res.writes ? res.writes.length : 0) + " record" +
            ((res.writes && res.writes.length === 1) ? "" : "s") + ", " + nFields + " field" + (nFields === 1 ? "" : "s") +
            ", " + esc(visTxt) + " — as shown in the preview.</div>" +
          '<div class="note" style="margin-top:4px">This test ships with the manifest, so a future edit that changes what this message becomes fails loudly.</div>';
      })
      .catch(function (e) {
        var m = String(e.message || e);
        var parsed = extract422(m);
        host.innerHTML = '<div class="mf-band mf-band-warn">The manifest doesn’t parse.</div>' +
          '<div class="note" style="margin-top:4px">' + esc(parsed ? parsed.error : m) + "</div>";
      });
  }

  /* -------------------------------------------------- fixture bundle download */
  // Assembles { manifest.yaml, fixtures/<src>_sample.json, _facts.json, _acl.json }
  // from the REAL dry-run output (a deterministic golden under fixture_clock).
  // v0: a DOWNLOAD, not a server-persisted artifact (no sidecar-file plane yet).
  function downloadBundle() {
    var errEl = el("mf-review-err");
    V.clearErr(errEl);
    var yaml;
    try { yaml = buildYaml(); } catch (e) { V.err(errEl, e); return; }
    var src = st.sourceName || "source";
    V.api("/v1/manifests/dry-run", { json: { tenant_id: V.tenant(), manifest_yaml: yaml, sample_payload: st.payload }, admin: true })
      .then(function (res) {
        var files = {};
        // The YAML gains a fixtures: block pointing at the relative sidecars.
        var fxYaml = yaml + fixturesBlock(src, res);
        files["manifest.yaml"] = fxYaml;
        files["fixtures/" + src + "_sample.json"] = JSON.stringify(st.payload, null, 2);
        if (res.outcome === "writes") {
          files["fixtures/" + src + "_facts.json"] = JSON.stringify(res.writes || [], null, 2);
          if (res.acl) files["fixtures/" + src + "_acl.json"] = JSON.stringify([res.acl], null, 2);
        }
        downloadTextBundle(src + "-manifest-bundle", files);
      })
      .catch(function (e) { V.err(errEl, e); });
  }

  function fixturesBlock(src, res) {
    var L = ["", "fixtures:"];
    L.push("  - input: " + JSON.stringify("fixtures/" + src + "_sample.json"));
    L.push("    expect:");
    if (res.outcome === "writes") {
      L.push("      facts: " + JSON.stringify("fixtures/" + src + "_facts.json"));
      if (res.acl) L.push("      acl_envelopes: " + JSON.stringify("fixtures/" + src + "_acl.json"));
    } else {
      L.push("      quarantined: true");
      // a stable substring of the real reason
      var sub = stableReasonSubstring(res.reason || "");
      if (sub) L.push("      reason_contains: " + JSON.stringify(sub));
    }
    return "\n" + L.join("\n") + "\n";
  }

  function stableReasonSubstring(reason) {
    var mMap = /map\.[A-Za-z0-9_]+/.exec(reason);
    if (mMap) return mMap[0];
    if (/no entity route matched/.test(reason)) return "no entity route matched";
    if (/primary_key/.test(reason)) return "primary_key";
    if (/valid_from/.test(reason)) return "valid_from";
    if (/acl_policy absent/.test(reason)) return "acl_policy absent";
    return reason.slice(0, 40);
  }

  // Download several text files as one .txt manifest-of-files (no zip lib
  // available client-side; we emit a single readable bundle the user unpacks,
  // plus each file individually so `verity manifest test` can consume them).
  function downloadTextBundle(name, files) {
    // Emit each file as its own download (browsers allow sequential blobs).
    Object.keys(files).forEach(function (rel, idx) {
      var safe = rel.replace(/\//g, "__");
      setTimeout(function () {
        var blob = new Blob([files[rel]], { type: "text/plain" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = name + "." + safe;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      }, idx * 120);
    });
  }

  /* -------------------------------------------------------- save as draft */

  function saveDraft() {
    var errEl = el("mf-review-err");
    var receipt = el("mf-save-receipt");
    V.clearErr(errEl);
    receipt.innerHTML = "";
    var yaml;
    try { yaml = buildYaml(); } catch (e) { V.err(errEl, e); return; }
    var btn = el("mf-save-draft");
    btn.disabled = true;
    btn.textContent = "Saving…";
    V.api("/v1/manifests", { json: { tenant_id: V.tenant(), yaml: yaml }, admin: true })
      .then(function (res) {
        btn.disabled = false;
        btn.textContent = "Save as draft";
        renderSaveReceipt(receipt, res);
      })
      .catch(function (e) {
        btn.disabled = false;
        btn.textContent = "Save as draft";
        // a validation failure maps back to the offending step
        var m = String(e.message || e);
        var parsed = extract422(m);
        if (parsed && parsed.step) {
          V.err(errEl, new Error(parsed.error + " — fix it in step " + parsed.step + "."));
          receipt.innerHTML = '<button id="mf-goto-err">Go to step ' + parsed.step + " →</button>";
          var g = el("mf-goto-err");
          if (g) g.addEventListener("click", function () { st.step = parsed.step; render(); });
        } else {
          V.err(errEl, new Error(parsed ? parsed.error : m));
        }
      });
  }

  function renderSaveReceipt(receipt, res) {
    var id = res && (res.manifest_id || res.id) ? (res.manifest_id || res.id) : null;
    var ready = res && (res.activation_ready === true || (res.activation && res.activation.ready === true));
    receipt.innerHTML =
      '<div class="mf-band mf-band-ok">✓ Saved as a draft — not live yet.</div>' +
      (id ? '<div class="api-crumb-block" style="margin-top:4px">manifest id: ' + V.refSpan(id) + "</div>" : "") +
      '<div class="note" style="margin-top:6px">' +
        (st.acl.choice === "hold"
          ? "This draft holds every message until an admin adds a rule. It saved fine — it just can’t be turned on until then."
          : (ready
            ? "This draft is ready for an admin to turn on. Turning it on is a separate, approved step."
            : "Turning this source on is a separate step an admin approves.")) +
      "</div>" +
      '<div class="toolbar" style="margin-top:8px">' +
        '<button id="mf-goto-sources">Go turn it on in Sources →</button>' +
        '<button id="mf-new-source">Add another source</button>' +
      "</div>";
    var gs = el("mf-goto-sources");
    if (gs) gs.addEventListener("click", function () { V.show("sources"); });
    var ns = el("mf-new-source");
    if (ns) ns.addEventListener("click", function () {
      st = freshState();
      if (aclPicker) { aclPicker.destroy(); aclPicker = null; }
      render();
    });
  }

  /* ============================================================ nav row */

  function navRow(n) {
    var back = n > 1 ? '<button id="mf-back-' + n + '">← Back</button>' : "";
    var next = "";
    if (n < 5) {
      next = '<button class="primary" id="mf-next-' + n + '">Next →</button>';
    }
    return '<div class="toolbar" style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">' +
      back + '<span class="spacer"></span>' + next + "</div>";
  }

  function wireNav(n) {
    var back = el("mf-back-" + n);
    if (back) back.addEventListener("click", function () { st.step = n - 1; render(); });
    var next = el("mf-next-" + n);
    if (next) {
      next.addEventListener("click", function () {
        if (!stepGate(n)) return;
        st.step = n + 1;
        render();
      });
      // reflect gate state immediately for the ACL step
      if (n === 4) next.disabled = !aclStepValid();
    }
  }

  // Per-step gate before advancing. Returns true if OK; shows a message if not.
  function stepGate(n) {
    if (n === 3) {
      if (!st.primaryKey) {
        var fe = el("mf-fields-err");
        if (fe) { fe.textContent = "Pick a stable ID first — without it, updates can’t land on the same record."; fe.classList.add("on"); }
        return false;
      }
      return true;
    }
    if (n === 4) {
      validateAclInline();
      return aclStepValid();
    }
    return true;
  }
})();
