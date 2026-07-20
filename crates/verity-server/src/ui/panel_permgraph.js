"use strict";
/* ==========================================================================
   panel_permgraph.js — Permission graph (admin/operator plane)
   --------------------------------------------------------------------------
   Two modes, one panel. All reads are admin-bearer ({admin:true}) against the
   ADMIN plane only — this file never touches the read path.

   Mode A · "What does a person see?"   GET /v1/admin/access/subject
     → closure graph (inline SVG) + corpus breakdown bars + grant-confidence
       bar + paginated METADATA-ONLY document list. Click a document row →
       GET /v1/admin/access/object?document_id=… and light the granting
       group/user nodes + path edges in the graph (the "why").

   Mode B · "Who can see this?"          GET /v1/admin/access/object
     → visibility tokens → principals → reachable users WITH the granting
       group path (the "why"), same inline-SVG closure. document_id / source /
       entity selectors; source/entity may come back "approximate" or be
       refused above the corpus ceiling — surfaced honestly.

   CSP: rendered as HTML strings inside the nonced panel script block. Inline
   SVG is CSP-legal markup (default-src 'self' does not gate it); widths use
   inline style="" (style-src 'unsafe-inline'). ZERO external libs, ZERO
   external-source script tags, ZERO inline on* handlers; every click is wired through the
   delegated wire(host, sel, fn) + data-* pattern, exactly like
   panel_principals.js. Layout is a deterministic layered pass; no lib.

   Fail-closed + honest: 401 → "admin token required" teach; 503 → "ReBAC
   unconfigured" teach; unresolvable subject → empty everything, said out
   loud; approximate/truncated flags always shown, never hidden.
   ========================================================================== */
(function () {
  var V = window.Verity;

  /* Per-mode UI state. `data` holds the last subject response so the doc
     panel, graph, and highlight all read the ONE server answer. */
  var mode = "subject"; // "subject" | "object"
  var tenantNow = "";
  var subj = {
    subject: "",
    max_conf: 3,
    resp: null,        // last /access/subject response
    docs: [],          // accumulated document rows (paginated)
    nextAfter: null,
    loading: false,
    highlightNodes: {},// id → true, set by a doc's why-path
    activeDoc: "",     // document_id whose why-path is lit
  };
  var obj = {
    selKind: "document_id", // document_id | source | entity
    selValue: "",
    resp: null,        // last /access/object response
    loading: false,
  };

  function el(id) { return V.$(id); }

  /* Delegated click wiring — reads data-* for args. No inline on* (CSP). */
  function wire(host, sel, fn) {
    if (!host) return;
    var nodes = host.querySelectorAll(sel);
    for (var i = 0; i < nodes.length; i++) {
      (function (n) { n.onclick = function () { fn(n); }; })(nodes[i]);
    }
  }

  /* "user:alice@x" → {kind:"user", name:"alice@x"}; "group:eng" → group. */
  function classify(principal) {
    var s = String(principal || "");
    if (s.indexOf("user:") === 0) return { kind: "user", name: s.slice(5) };
    if (s.indexOf("group:") === 0) return { kind: "group", name: s.slice(6) };
    return { kind: "other", name: s };
  }
  function pct(n, total) {
    if (!total || total <= 0) return 0;
    var p = (Number(n) / Number(total)) * 100;
    if (p > 0 && p < 0.5) return 0.5; // keep a sliver visible for non-zero
    return Math.min(100, p);
  }
  function num(n) { return Number(n || 0).toLocaleString(); }

  /* =========================================================== register */
  V.register({
    id: "permgraph",
    mount: mount,
    load: function (_section, tenant) { return onTenant(tenant); },
    onShow: function () { if (!V.tenant()) renderNoTenant(); },
  });

  /* =========================================================== mount */
  function mount() {
    var host = el("permgraph-mount");
    if (!host) return;
    host.innerHTML =
      '<div class="toolbar">' +
        '<span class="seg" id="pg-seg">' +
          '<button id="pg-mode-subject" class="on" ' +
            'title="GET /v1/admin/access/subject — the identity closure + the corpus this subject is authorized to reach">What does a person see?</button>' +
          '<button id="pg-mode-object" ' +
            'title="GET /v1/admin/access/object — who can reach a document/source/entity, and the granting group path">Who can see this?</button>' +
        "</span>" +
        '<span class="spacer"></span>' +
        '<span class="asof" id="pg-asof"></span>' +
      "</div>" +
      '<div class="err" id="pg-err"></div>' +
      '<div id="pg-hint"></div>' +
      '<div id="pg-controls"></div>' +
      '<div id="pg-out"></div>';

    if (!V.tenant()) { renderNoTenant(); return; }
    renderControls();
  }

  /* =========================================================== no-tenant */
  function renderNoTenant() {
    var out = el("pg-out");
    if (!out) return;
    var ctl = el("pg-controls"); if (ctl) ctl.innerHTML = "";
    var asof = el("pg-asof"); if (asof) asof.textContent = "";
    out.innerHTML =
      '<div class="empty-teach sp-a">' +
        '<div class="et-title">Pick a space to explore its permission graph</div>' +
        '<div class="et-body">Paste a space&rsquo;s <span class="ref">tenant_id</span> in the session bar above, or mint a scope handle — ' +
          "the space fills in automatically and this screen loads itself. The permission graph is a <b>god-view</b> over org structure and access, so it is admin-only.</div>" +
        '<div class="et-actions"><button class="primary" id="pg-teach-mint">Mint a scope handle</button></div>' +
      "</div>";
    var b = el("pg-teach-mint");
    if (b) b.onclick = function () { V.openMint(); };
  }

  /* =========================================================== tenant change */
  function onTenant(tenant) {
    tenantNow = tenant;
    // reset both modes' cached answers — permission truth is per-space
    subj.resp = null; subj.docs = []; subj.nextAfter = null;
    subj.highlightNodes = {}; subj.activeDoc = "";
    obj.resp = null;
    renderControls();
    // Autoload only if the operator has already named a subject/object.
    if (mode === "subject" && subj.subject) return runSubject();
    if (mode === "object" && obj.selValue) return runObject();
    renderIdle();
  }

  function setMode(m) {
    if (mode === m) return;
    mode = m;
    el("pg-mode-subject").className = m === "subject" ? "on" : "";
    el("pg-mode-object").className = m === "object" ? "on" : "";
    V.clearErr("pg-err");
    el("pg-hint").innerHTML = "";
    renderControls();
    if (m === "subject" && subj.resp) renderSubject();
    else if (m === "object" && obj.resp) renderObject();
    else renderIdle();
  }

  /* =========================================================== controls */
  function renderControls() {
    var ctl = el("pg-controls");
    if (!ctl) return;
    if (mode === "subject") {
      ctl.innerHTML =
        '<div class="card"><div class="row">' +
          '<div><label for="pg-subject">person or group (subject)</label>' +
            '<input type="text" id="pg-subject" list="pg-subject-list" ' +
              'placeholder="alice@corp.example  ·  or group:eng" autocomplete="off" spellcheck="false" ' +
              'value="' + V.esc(subj.subject ? classify(subj.subject).name : "") + '"></div>' +
          '<div><label for="pg-maxconf">at confidentiality up to</label>' +
            '<select id="pg-maxconf" class="field">' +
              optConf(0) + optConf(1) + optConf(2) + optConf(3) +
            "</select></div>" +
        "</div>" +
        '<datalist id="pg-subject-list"></datalist>' +
        '<div class="note" style="margin-top:8px">A bare name becomes <span class="ref">user:&lt;name&gt;</span>; type <span class="ref">group:&lt;name&gt;</span> to ask about a group. ' +
          'The corpus shown is exactly what a real read would be pre-filtered to for this subject — after any in-window revocations are subtracted.' +
          '<span class="api-crumb"> · GET /v1/admin/access/subject</span></div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:10px">' +
          '<button class="primary" id="pg-run-subject">See what they can reach</button>' +
        "</div></div>";
      var mc = el("pg-maxconf"); if (mc) mc.value = String(subj.max_conf);
      el("pg-run-subject").onclick = submitSubject;
      var si = el("pg-subject");
      si.onkeydown = function (e) { if (e.key === "Enter") submitSubject(); };
      populateSubjectList();
    } else {
      ctl.innerHTML =
        '<div class="card"><div class="row">' +
          '<div><label for="pg-objkind">look up by</label>' +
            '<select id="pg-objkind" class="field">' +
              '<option value="document_id">a document</option>' +
              '<option value="source">a whole source</option>' +
              '<option value="entity">an entity tag</option>' +
            "</select></div>" +
          '<div><label for="pg-objval" id="pg-objval-label">document id</label>' +
            '<input type="text" id="pg-objval" placeholder="d/abc123" autocomplete="off" spellcheck="false" ' +
              'value="' + V.esc(obj.selValue) + '"></div>' +
        "</div>" +
        '<div class="note" style="margin-top:8px" id="pg-obj-note">Decodes the object&rsquo;s materialized visibility tokens, resolves them to people and groups, then fans out to <b>every reachable person</b> with the granting group path.' +
          '<span class="api-crumb"> · GET /v1/admin/access/object</span></div>' +
        '<div class="actions" style="justify-content:flex-start;margin-top:10px">' +
          '<button class="primary" id="pg-run-object">See who can reach it</button>' +
        "</div></div>";
      var ok = el("pg-objkind");
      ok.value = obj.selKind;
      ok.onchange = function () { obj.selKind = ok.value; reflectObjKind(); };
      el("pg-run-object").onclick = submitObject;
      var ov = el("pg-objval");
      ov.onkeydown = function (e) { if (e.key === "Enter") submitObject(); };
      reflectObjKind();
    }
  }

  function optConf(i) {
    var names = ["public (0)", "internal (1)", "confidential (2)", "restricted (3)"];
    return '<option value="' + i + '">' + names[i] + " and below</option>";
  }

  function reflectObjKind() {
    var lbl = el("pg-objval-label"), inp = el("pg-objval"), note = el("pg-obj-note");
    if (!lbl || !inp) return;
    if (obj.selKind === "document_id") {
      lbl.textContent = "document id"; inp.placeholder = "d/abc123";
      if (note) note.innerHTML = "Decodes the document&rsquo;s materialized visibility tokens, resolves them to people and groups, then fans out to <b>every reachable person</b> with the granting group path.<span class=\"api-crumb\"> · GET /v1/admin/access/object</span>";
    } else if (obj.selKind === "source") {
      lbl.textContent = "source"; inp.placeholder = "gdrive";
      if (note) note.innerHTML = "<b>Whole-source</b> lookup is a full scan of every live chunk from that source — it may return <b>approximate</b> results or be refused above the corpus ceiling until a supporting index exists. Answers are honest either way.<span class=\"api-crumb\"> · GET /v1/admin/access/object?source=…</span>";
    } else {
      lbl.textContent = "entity tag"; inp.placeholder = "acme-corp";
      if (note) note.innerHTML = "<b>Entity-tag</b> lookup scans every live chunk carrying the tag; it may return <b>approximate</b> results or be refused above the corpus ceiling. Answers are honest either way.<span class=\"api-crumb\"> · GET /v1/admin/access/object?entity=…</span>";
    }
  }

  /* Datalist assist for the subject box — reuses the principals directory. */
  function populateSubjectList() {
    var dl = el("pg-subject-list");
    if (!dl || !tenantNow) return;
    V.api("/v1/admin/principals?tenant_id=" + encodeURIComponent(tenantNow) + "&after_token=0&limit=1000", { admin: true })
      .then(function (res) {
        var rows = (res && res.principals) || [];
        dl.innerHTML = rows.map(function (r) {
          var c = classify(r.principal);
          return '<option value="' + V.esc(c.kind === "group" ? "group:" + c.name : c.name) + '">';
        }).join("");
      })
      .catch(function () { /* assist only — silent, the box still works */ });
  }

  /* =========================================================== idle */
  function renderIdle() {
    var out = el("pg-out");
    if (!out) return;
    var asof = el("pg-asof"); if (asof) asof.textContent = "";
    if (mode === "subject") {
      out.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Name a person or group</div>' +
          '<div class="et-body">Enter who you want to inspect above, then <b>See what they can reach</b>. ' +
            "You&rsquo;ll get their group closure as a graph, the corpus they can reach broken down by source, " +
            "confidentiality and permission-provenance, and a paginated, metadata-only list of the documents themselves — " +
            "click any document to light up <b>why</b> they can see it.</div>" +
        "</div>";
    } else {
      out.innerHTML =
        '<div class="empty-teach sp-a">' +
          '<div class="et-title">Name an object</div>' +
          '<div class="et-body">Enter a document id, a source, or an entity tag above, then <b>See who can reach it</b>. ' +
            "You&rsquo;ll get its visibility tokens resolved to people and groups, and every reachable person with the " +
            "granting group path that explains the access.</div>" +
        "</div>";
    }
  }

  /* =========================================================== subject flow */
  function submitSubject() {
    var raw = String((el("pg-subject") || {}).value || "").trim();
    if (!raw) {
      V.err("pg-err", new Error("name a person or group first — nothing is assumed"));
      return;
    }
    subj.subject = raw.indexOf(":") >= 0 ? raw : "user:" + raw;
    subj.max_conf = Number((el("pg-maxconf") || {}).value || 3);
    subj.docs = []; subj.nextAfter = null;
    subj.highlightNodes = {}; subj.activeDoc = "";
    runSubject();
  }

  function subjectUrl(after) {
    var u = "/v1/admin/access/subject?tenant_id=" + encodeURIComponent(tenantNow) +
      "&subject=" + encodeURIComponent(subj.subject) +
      "&max_confidentiality=" + encodeURIComponent(subj.max_conf) +
      "&docs_limit=50";
    if (after) u += "&docs_after=" + encodeURIComponent(after);
    return u;
  }

  async function runSubject() {
    if (!tenantNow || !subj.subject) { renderIdle(); return; }
    subj.loading = true;
    V.clearErr("pg-err");
    el("pg-hint").innerHTML = "";
    el("pg-out").innerHTML = '<div class="note">' + V.stateChip("wait", "reading") +
      " asking the permission engine what <b>" + V.esc(classify(subj.subject).name) + "</b> can reach&hellip;</div>";
    try {
      var res = await V.api(subjectUrl(null), { admin: true });
      if (tenantNow !== res.tenant_id && res.tenant_id) { /* space moved mid-flight */ }
      subj.resp = res || {};
      subj.docs = ((res && res.documents && res.documents.items) || []).slice();
      subj.nextAfter = (res && res.documents && res.documents.next_after) || null;
      subj.loading = false;
      renderSubject();
    } catch (e) {
      subj.loading = false;
      teachError(e);
    }
  }

  async function loadMoreDocs(btn) {
    if (!subj.nextAfter) return;
    btn.disabled = true;
    try {
      var res = await V.api(subjectUrl(subj.nextAfter), { admin: true });
      var items = (res && res.documents && res.documents.items) || [];
      subj.docs = subj.docs.concat(items);
      subj.nextAfter = (res && res.documents && res.documents.next_after) || null;
      renderSubject();
    } catch (e) {
      V.err("pg-err", e);
      btn.disabled = false;
    }
  }

  function renderSubject() {
    var out = el("pg-out");
    if (!out) return;
    var r = subj.resp || {};
    el("pg-asof").textContent = "read " + new Date().toTimeString().slice(0, 8);

    if (r.subject_resolved === false) {
      out.innerHTML =
        '<div class="card" style="border-left:3px solid var(--state-attn)">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            V.stateChip("attn", "not on record") +
            "<b>" + V.esc(classify(subj.subject).name) + "</b>" +
            '<span style="color:var(--dim)">could not be resolved to any principal</span>' +
          "</div>" +
          '<div class="note">Fail-closed: an unresolvable subject sees <b>nothing</b>. There is no token set, ' +
            "so the corpus and document list are empty — this is a real answer, not an error. Check the name against " +
            "<b>People &amp; groups</b>.</div>" +
        "</div>";
      V.setCount("permgraph", 0, "docs visible");
      return;
    }

    var corpus = r.corpus || {};
    var total = corpus.total || { chunks: 0, docs: 0 };
    var flags = r.flags || {};
    V.setCount("permgraph", total.docs || 0, "docs visible to this subject");

    var html = "";

    /* -------- flags banner (honesty first) -------- */
    var banners = [];
    if (flags.approximate_counts) {
      banners.push('<span class="pg-flag" title="a company-wide token set made the aggregate scan hit its statement-timeout — counts are a lower bound, not ground truth">&#9888; approximate counts</span>');
    }
    if (flags.closure_truncated) {
      banners.push('<span class="pg-flag" title="the identity closure was capped for rendering — some ancestor groups are collapsed">&#9888; closure truncated</span>');
    }
    if (flags.revocation_window_active) {
      banners.push('<span class="pg-flag" title="an in-window revocation touched this token set; parity with a concurrent read holds only at the same read-instant">&#9888; revocation window active</span>');
    }

    /* -------- header line -------- */
    html += '<div class="card"><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
      V.stateChip("ok", "authorized view") +
      "<b>" + V.esc(classify(subj.subject).name) + "</b>" +
      '<span style="color:var(--dim)">can reach</span>' +
      "<b>" + num(total.docs) + "</b><span style=\"color:var(--dim)\">documents · " + num(total.chunks) + " chunks</span>" +
      banners.join(" ") +
      "</div>" +
      '<div class="note" style="margin-top:4px">Tokens: ' +
        ((r.tokens || []).length
          ? (r.tokens || []).map(function (t) { return '<span class="ref">#' + V.esc(String(t)) + "</span>"; }).join(" ")
          : '<span class="ref">none — nothing is visible</span>') +
      "</div></div>";

    /* -------- two columns: graph | breakdown -------- */
    html += '<div class="pg-cols">';

    /* left: closure graph */
    html += '<div class="card"><h2>Identity closure <span class="sub">who this subject is, through the groups they hold</span></h2>' +
      '<div class="pg-graphwrap" id="pg-graph">' + renderClosureSvg(r.closure || {}, subj.highlightNodes) + "</div>" +
      '<div class="note" style="margin-top:6px">Green highlight shows <b>why</b> a clicked document is visible — the granting group/user path. Click a document below to light it.</div>' +
      "</div>";

    /* right: corpus breakdown + grant confidence */
    html += '<div>' + renderBreakdown(corpus) + renderGrantConfidence(r.grant_confidence || {}) + "</div>";

    html += "</div>"; // pg-cols

    /* -------- documents (metadata only) -------- */
    html += renderDocs();

    out.innerHTML = html;

    // wire node clicks (filter docs granted via that node — best-effort visual)
    wire(el("pg-graph"), ".pg-node", function (n) {
      var id = n.getAttribute("data-node") || "";
      // clicking a node clears any active doc highlight and re-lights just it
      subj.activeDoc = "";
      subj.highlightNodes = {}; subj.highlightNodes[id] = true;
      refreshGraphHighlight();
      markActiveDocRow("");
    });
    // wire doc rows → why-highlight (Endpoint 2)
    wire(el("pg-out"), "tr.pg-docrow", function (row) {
      whyForDoc(row.getAttribute("data-doc") || "");
    });
    var more = el("pg-more");
    if (more) more.onclick = function () { loadMoreDocs(more); };
  }

  /* -------- corpus breakdown bars -------- */
  function renderBreakdown(corpus) {
    var total = (corpus.total && corpus.total.chunks) || 0;
    var html = '<div class="card"><h2>Corpus breakdown <span class="sub">counts only — never document contents</span></h2>';

    // by source
    html += '<div class="note" style="margin:0 0 4px"><b>By source</b></div>';
    var bySrc = (corpus.by_source || []).slice().sort(function (a, b) { return (b.chunks || 0) - (a.chunks || 0); });
    if (!bySrc.length) html += '<div class="note">no visible chunks</div>';
    bySrc.forEach(function (s) {
      html += breakRow(s.source || "(none)", "pg-fill-src", s.chunks, s.docs, total);
    });

    // by confidentiality
    var confNames = ["public", "internal", "confidential", "restricted"];
    html += '<div class="note" style="margin:12px 0 4px"><b>By confidentiality</b></div>';
    var byConf = (corpus.by_confidentiality || []).slice().sort(function (a, b) { return (a.level || 0) - (b.level || 0); });
    if (!byConf.length) html += '<div class="note">no visible chunks</div>';
    byConf.forEach(function (c) {
      var lvl = Number(c.level || 0);
      html += breakRow(confNames[lvl] + " (" + lvl + ")", "pg-fill-conf-" + lvl, c.chunks, c.docs, total);
    });

    // by provenance
    html += '<div class="note" style="margin:12px 0 4px"><b>By permission-provenance</b> — how much to trust each grant</div>';
    var byProv = (corpus.by_provenance || []).slice().sort(function (a, b) { return (b.chunks || 0) - (a.chunks || 0); });
    if (!byProv.length) html += '<div class="note">no visible chunks</div>';
    byProv.forEach(function (p) {
      var name = String(p.provenance || "admin-assigned").toLowerCase();
      var cls = ["mirrored", "approximated", "admin-assigned", "quarantined"].indexOf(name) >= 0
        ? "pg-fill-" + name : "pg-fill-admin-assigned";
      html += breakRow(name, cls, p.chunks, p.docs, total);
    });

    html += "</div>";
    return html;
  }

  function breakRow(label, fillCls, chunks, docs, total) {
    var w = pct(chunks, total);
    return '<div class="pg-breakrow">' +
      '<span class="pg-breaklabel">' + V.esc(label) + "</span>" +
      '<span class="pg-breakbar"><i class="' + fillCls + '" style="width:' + w.toFixed(1) + '%"></i></span>' +
      '<span class="pg-breakcount">' + num(chunks) + " chk · " + num(docs) + " doc</span>" +
      "</div>";
  }

  /* -------- grant-confidence: one segmented bar over the four lanes -------- */
  function renderGrantConfidence(gc) {
    var lanes = ["mirrored", "approximated", "admin-assigned", "quarantined"];
    var segs = "", legend = "";
    var any = false;
    lanes.forEach(function (name) {
      var frac = Number(gc[name] || 0);
      if (frac > 0) any = true;
      var wpct = (frac * 100);
      segs += '<span class="pg-fill-' + name + '" style="width:' + wpct.toFixed(1) + '%" ' +
        'title="' + V.esc(name + ": " + (wpct).toFixed(1) + "%") + '"></span>';
      legend += '<span style="margin-right:12px;font-size:var(--fs-sm);color:var(--dim)">' +
        '<span class="pg-swatch pg-fill-' + name + '"></span>' + V.esc(name) + " " + (wpct).toFixed(0) + "%</span>";
    });
    var basis = gc.basis || "chunks";
    return '<div class="card"><h2>Grant confidence <span class="sub">provenance mix over ' + V.esc(String(basis)) + '</span></h2>' +
      (any
        ? '<div class="pg-conf">' + segs + "</div><div style=\"margin-top:8px\">" + legend + "</div>"
        : '<div class="note">no grants to weigh</div>') +
      '<div class="note" style="margin-top:8px"><b>mirrored</b> is the source&rsquo;s own permission list copied exactly (highest confidence); ' +
        "<b>approximated</b> was inferred from a container; <b>admin-assigned</b> was set by hand; " +
        "<b>quarantined</b> had no mapping and is held out of the index (lowest).</div>" +
      "</div>";
  }

  /* -------- documents table (metadata only) -------- */
  function renderDocs() {
    var confNames = ["public", "internal", "confidential", "restricted"];
    var html = '<div class="card"><h2>Documents <span class="sub">metadata only — never contents (page-local rollup)</span></h2>';
    if (!subj.docs.length) {
      html += '<div class="note">No documents in this subject&rsquo;s authorized set' +
        (subj.max_conf < 3 ? " at confidentiality " + subj.max_conf + " and below" : "") +
        " — a valid answer, not an error.</div></div>";
      return html;
    }
    html += '<div class="note" style="margin-top:0">Per-document chunk counts and confidentiality here are <b>page-local</b> ' +
      "(a document&rsquo;s chunks can span pages); the authoritative totals are the corpus breakdown above. " +
      "Click a row to see <b>why</b> it&rsquo;s visible.</div>" +
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>document</th><th>source</th><th>confidentiality</th><th class=\"num\">chunks (page)</th><th>last seen</th>" +
      "</tr></thead><tbody>" +
      subj.docs.map(function (d) {
        var did = d.document_id || "";
        var active = did === subj.activeDoc ? " pg-active" : "";
        return '<tr class="pg-docrow' + active + '" data-doc="' + V.esc(did) + '" ' +
            'title="who can see this? — GET /v1/admin/access/object?document_id=…">' +
          "<td><b>" + V.esc(did) + "</b></td>" +
          "<td>" + V.esc(d.source || "—") + "</td>" +
          "<td>" + V.confBadge(Number(d.min_confidentiality || 0)) + "</td>" +
          '<td class="num">' + num(d.n_chunks) + "</td>" +
          "<td><span class=\"ref\">" + V.esc(d.last_seen ? V.fmtTime(d.last_seen) : "—") + "</span></td>" +
        "</tr>";
      }).join("") +
      "</tbody></table></div>";
    if (subj.nextAfter) {
      html += '<div class="note" style="margin-top:8px">Showing the first ' + subj.docs.length +
        " documents in recency order — <b>more may exist</b>. " +
        '<button id="pg-more">Load more</button></div>';
    }
    html += "</div>";
    return html;
  }

  /* -------- click a doc → why-path (Endpoint 2) -------- */
  async function whyForDoc(documentId) {
    if (!documentId || !tenantNow) return;
    subj.activeDoc = documentId;
    markActiveDocRow(documentId);
    var graph = el("pg-graph");
    try {
      var res = await V.api(
        "/v1/admin/access/object?tenant_id=" + encodeURIComponent(tenantNow) +
        "&document_id=" + encodeURIComponent(documentId),
        { admin: true }
      );
      // The granting nodes are: the object's principals (tokens on the doc)
      // plus every group on the reachable-users' `via` paths. Any of these
      // present in the closure graph light up.
      var lit = {};
      (res.principals || []).forEach(function (p) { if (p.principal) lit[p.principal] = true; });
      (res.reachable_users || []).forEach(function (u) {
        if (u.user) lit[u.user] = true;
        (u.via || []).forEach(function (path) {
          (path || []).forEach(function (g) { lit[g] = true; });
        });
      });
      // Always light the subject itself if it's a reachable user.
      lit[subj.subject] = lit[subj.subject] || false;
      subj.highlightNodes = lit;
      refreshGraphHighlight();
    } catch (e) {
      if (graph) {
        var msg = String((e && e.message) || e);
        // Non-fatal: keep the panel; show the why-lookup failure inline.
        V.err("pg-err", new Error("why-path for " + documentId + ": " + msg));
      }
    }
  }

  function markActiveDocRow(documentId) {
    var out = el("pg-out");
    if (!out) return;
    var rows = out.querySelectorAll("tr.pg-docrow");
    for (var i = 0; i < rows.length; i++) {
      var did = rows[i].getAttribute("data-doc") || "";
      rows[i].className = "pg-docrow" + (did && did === documentId ? " pg-active" : "");
    }
  }

  /* Recompute .pg-highlight classes on the live SVG without a full re-render. */
  function refreshGraphHighlight() {
    var graph = el("pg-graph");
    if (!graph) return;
    var nodes = graph.querySelectorAll(".pg-node");
    for (var i = 0; i < nodes.length; i++) {
      var id = nodes[i].getAttribute("data-node") || "";
      var on = !!subj.highlightNodes[id];
      nodes[i].setAttribute("class", nodes[i].getAttribute("class").replace(/ ?pg-highlight/g, "") + (on ? " pg-highlight" : ""));
    }
    var edges = graph.querySelectorAll(".pg-edge");
    for (var j = 0; j < edges.length; j++) {
      var f = edges[j].getAttribute("data-from") || "";
      var t = edges[j].getAttribute("data-to") || "";
      var lit = subj.highlightNodes[f] && subj.highlightNodes[t];
      edges[j].setAttribute("class", "pg-edge" + (lit ? " pg-highlight" : ""));
    }
  }

  /* =========================================================== object flow */
  function submitObject() {
    var v = String((el("pg-objval") || {}).value || "").trim();
    if (!v) {
      V.err("pg-err", new Error("name the object first — a document id, a source, or an entity tag"));
      return;
    }
    obj.selKind = (el("pg-objkind") || {}).value || "document_id";
    obj.selValue = v;
    runObject();
  }

  async function runObject() {
    if (!tenantNow || !obj.selValue) { renderIdle(); return; }
    obj.loading = true;
    V.clearErr("pg-err");
    el("pg-hint").innerHTML = "";
    el("pg-out").innerHTML = '<div class="note">' + V.stateChip("wait", "reading") +
      " decoding who can reach <b>" + V.esc(obj.selValue) + "</b>&hellip;</div>";
    try {
      var url = "/v1/admin/access/object?tenant_id=" + encodeURIComponent(tenantNow) +
        "&" + encodeURIComponent(obj.selKind) + "=" + encodeURIComponent(obj.selValue) +
        "&users_limit=1000";
      var res = await V.api(url, { admin: true });
      obj.resp = res || {};
      obj.loading = false;
      renderObject();
    } catch (e) {
      obj.loading = false;
      teachError(e);
    }
  }

  function renderObject() {
    var out = el("pg-out");
    if (!out) return;
    var r = obj.resp || {};
    el("pg-asof").textContent = "read " + new Date().toTimeString().slice(0, 8);

    var flags = r.flags || {};
    var users = r.reachable_users || [];
    V.setCount("permgraph", users.length, "people who can reach this object");

    // Render the SVG up front so its render-truncation count (obj.svgUserTrunc)
    // is known before we assemble the banners.
    var objSvg = renderObjectSvg(r);

    var banners = [];
    if (flags.approximate) {
      banners.push('<span class="pg-flag" title="the source/entity decode scan hit its statement-timeout — this is a partial answer, not ground truth">&#9888; approximate</span>');
    }
    if (flags.fanout_truncated) {
      banners.push('<span class="pg-flag" title="a company-wide group blew past the reachable-user cap — more people can reach this than are listed">&#9888; fan-out truncated</span>');
    }
    if (obj.svgUserTrunc > 0) {
      banners.push('<span class="pg-flag" title="the graph draws the first ' + OBJECT_USER_CAP + ' reachable people and collapses the rest into a &quot;+K more&quot; node — the full list is in the reachable-people table below">&#9888; graph shows ' + OBJECT_USER_CAP + ' of ' + num(users.length) + '</span>');
    }

    var okind = (r.object && r.object.kind) || obj.selKind;
    var oid = (r.object && r.object.id) || obj.selValue;

    var html = "";
    html += '<div class="card"><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
      V.stateChip("ok", "reverse view") +
      '<span style="color:var(--dim)">' + V.esc(okind) + "</span>" +
      "<b>" + V.esc(oid) + "</b>" +
      '<span style="color:var(--dim)">is reachable by</span>' +
      "<b>" + num(users.length) + "</b><span style=\"color:var(--dim)\">" + (users.length === 1 ? "person" : "people") + "</span>" +
      banners.join(" ") +
      "</div>" +
      '<div class="note" style="margin-top:4px">' +
        (r.confidentiality != null ? V.confBadge(Number(r.confidentiality)) + " " : "") +
        provChips(r.provenance) +
        '  ·  visibility tokens: ' +
        ((r.visibility_tokens || []).length
          ? (r.visibility_tokens || []).map(function (t) { return '<span class="ref">#' + V.esc(String(t)) + "</span>"; }).join(" ")
          : '<span class="ref">none — invisible to everyone</span>') +
      "</div></div>";

    html += '<div class="pg-cols">';

    // left: reverse closure (principals + reachable users as a graph)
    html += '<div class="card"><h2>Who reaches it <span class="sub">visibility tokens → principals → reachable people</span></h2>' +
      '<div class="pg-graphwrap">' + objSvg + "</div></div>";

    // right: principals list + reachable users with via-path
    html += '<div>';
    html += '<div class="card"><h2>Principals on the object <span class="sub">tokens resolved to names</span></h2>';
    var principals = r.principals || [];
    if (!principals.length) html += '<div class="note">no principals hold a token on this object — it is invisible</div>';
    else {
      html += '<div class="tablewrap"><table><thead><tr><th>principal</th><th>kind</th><th class="num">token</th></tr></thead><tbody>' +
        principals.map(function (p) {
          var c = classify(p.principal);
          return "<tr><td><b>" + V.esc(c.name) + "</b></td><td>" + V.esc(p.kind || c.kind) +
            '</td><td class="num"><span class="ref">#' + V.esc(String(p.token)) + "</span></td></tr>";
        }).join("") +
        "</tbody></table></div>";
    }
    html += "</div>";

    html += '<div class="card"><h2>Reachable people <span class="sub">every person + the granting group path (the why)</span></h2>';
    if (!users.length) html += '<div class="note">nobody can reach this object — a valid answer, not an error</div>';
    else {
      html += '<div class="tablewrap"><table><thead><tr><th>person</th><th>via (granting path)</th><th>direct</th></tr></thead><tbody>' +
        users.map(function (u) {
          var c = classify(u.user);
          return "<tr><td><b>" + V.esc(c.name) + "</b></td>" +
            "<td>" + viaHtml(u.via, c.name) + "</td>" +
            "<td>" + (u.direct ? V.stateChip("ok", "direct") : '<span class="ref">via group</span>') + "</td></tr>";
        }).join("") +
        "</tbody></table></div>";
      if (r.reachable_users_next_after) {
        html += '<div class="note" style="margin-top:8px">More people may exist beyond this page.</div>';
      }
    }
    html += "</div>";
    html += "</div>"; // right col
    html += "</div>"; // pg-cols

    out.innerHTML = html;
  }

  function provChips(prov) {
    if (prov == null) return "";
    var arr = Array.isArray(prov) ? prov : [prov];
    return arr.map(function (p) { return V.provenanceBadge(p); }).join(" ");
  }

  function viaHtml(via, userName) {
    via = via || [];
    if (!via.length) return '<span class="ref">direct grant — no group</span>';
    return via.map(function (path) {
      var steps = (path || []).map(function (g) { return V.esc(classify(g).name); });
      // render as user → group → group
      return '<span class="pg-via">' + V.esc(userName) +
        steps.map(function (s) { return '<span class="pg-arrow">&rarr;</span>' + s; }).join("") +
        "</span>";
    }).join('<br>');
  }

  /* =========================================================== SVG layout */
  /* A deterministic layered layout — NO layout library. Nodes are placed in
     columns by depth; a user subject sits at the left, its groups fan to the
     right by ancestor_depth. Each node carries data-node for wire()/highlight;
     each edge carries data-from/data-to so highlight can light a whole path. */
  var NODE_W = 150, NODE_H = 40, COL_GAP = 70, ROW_GAP = 16, PAD = 16;
  // Max reachable-user nodes drawn in the object-mode SVG before collapsing the
  // rest into a "+K more" node (the tabular reachable-people list stays complete).
  var OBJECT_USER_CAP = 60;

  function renderClosureSvg(closure, highlight) {
    var nodes = closure.nodes || [];
    var edges = closure.edges || [];
    if (!nodes.length) {
      return '<div class="note" style="padding:16px">No closure to draw — this subject holds no groups.</div>';
    }
    // depth: users at col 0; groups by ancestor_depth (default increasing).
    var byId = {};
    nodes.forEach(function (n) { byId[n.id] = n; });
    var cols = {};
    nodes.forEach(function (n) {
      var d = n.kind === "user" ? 0 : (Number(n.ancestor_depth != null ? n.ancestor_depth : 0) + 1);
      (cols[d] = cols[d] || []).push(n);
    });
    return layoutSvg(cols, nodes, edges, byId, highlight || {});
  }

  /* Object mode: col0 = the object, col1 = principals (tokens), col2 =
     reachable users. Build a synthetic node/edge set and reuse layoutSvg. */
  function renderObjectSvg(r) {
    var oid = (r.object && r.object.id) || obj.selValue;
    var nodes = [{ id: "__object__", kind: "object", label: oid, token: null }];
    var edges = [];
    (r.principals || []).forEach(function (p) {
      nodes.push({ id: p.principal, kind: p.kind === "user" ? "user" : "group", label: classify(p.principal).name, token: p.token });
      edges.push({ from: "__object__", to: p.principal, relation: "token" });
    });
    // Client-side render cap, mirroring the server-side CLOSURE_NODE_CAP: a
    // company-wide group can return up to users_limit (~1000) reachable users;
    // rendering one node per user produces a ~1000-node / ~56000px-tall SVG that
    // janks the tab. Render the first OBJECT_USER_CAP and collapse the rest into
    // a single "+K more" node — the authoritative list is the reachable-people
    // table below. The truncation is surfaced as a graph banner (see renderObject).
    var allUsers = r.reachable_users || [];
    obj.svgUserTrunc = Math.max(0, allUsers.length - OBJECT_USER_CAP);
    var shownUsers = obj.svgUserTrunc > 0 ? allUsers.slice(0, OBJECT_USER_CAP) : allUsers;
    var seenUser = {};
    shownUsers.forEach(function (u) {
      if (!seenUser[u.user]) {
        seenUser[u.user] = true;
        nodes.push({ id: u.user, kind: "user", label: classify(u.user).name, token: null });
      }
      // edge from each granting group (or the object, if direct) to the user
      var paths = u.via || [];
      if (!paths.length) edges.push({ from: "__object__", to: u.user, relation: "direct" });
      paths.forEach(function (path) {
        var g0 = (path && path.length) ? path[0] : null;
        edges.push({ from: g0 || "__object__", to: u.user, relation: "member" });
      });
    });
    if (obj.svgUserTrunc > 0) {
      var moreId = "__more_users__";
      nodes.push({ id: moreId, kind: "more", label: "+" + obj.svgUserTrunc + " more", token: null });
      seenUser[moreId] = true;
      edges.push({ from: "__object__", to: moreId, relation: "member" });
    }
    var byId = {};
    nodes.forEach(function (n) { byId[n.id] = n; });
    var cols = { 0: [], 1: [], 2: [] };
    nodes.forEach(function (n) {
      if (n.id === "__object__") cols[0].push(n);
      else if (n.kind === "user" && seenUser[n.id]) cols[2].push(n);
      else cols[1].push(n);
    });
    // A user that is ALSO a principal on the object appears in col1; keep it there.
    return layoutSvg(cols, nodes, edges, byId, {});
  }

  function layoutSvg(cols, nodes, edges, byId, highlight) {
    var colKeys = Object.keys(cols).map(Number).sort(function (a, b) { return a - b; });
    var pos = {}; // id → {x,y}
    var maxRows = 0;
    colKeys.forEach(function (ck, ci) {
      var colNodes = cols[ck];
      colNodes.forEach(function (n, ri) {
        pos[n.id] = {
          x: PAD + ci * (NODE_W + COL_GAP),
          y: PAD + ri * (NODE_H + ROW_GAP),
        };
      });
      if (colNodes.length > maxRows) maxRows = colNodes.length;
    });
    var width = PAD * 2 + colKeys.length * NODE_W + (colKeys.length - 1) * COL_GAP;
    var height = PAD * 2 + maxRows * NODE_H + (maxRows - 1) * ROW_GAP;
    if (height < NODE_H + PAD * 2) height = NODE_H + PAD * 2;

    var svg = '<svg class="pg-svg" viewBox="0 0 ' + width + " " + height +
      '" width="' + width + '" height="' + height + '" xmlns="http://www.w3.org/2000/svg">';

    // edges first (behind nodes)
    edges.forEach(function (e) {
      var a = pos[e.from], b = pos[e.to];
      if (!a || !b) return;
      var x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2;
      var x2 = b.x, y2 = b.y + NODE_H / 2;
      var mx = (x1 + x2) / 2;
      var lit = highlight[e.from] && highlight[e.to];
      svg += '<path class="pg-edge' + (lit ? " pg-highlight" : "") + '" ' +
        'data-from="' + V.esc(e.from) + '" data-to="' + V.esc(e.to) + '" ' +
        'd="M' + x1 + " " + y1 + " C" + mx + " " + y1 + " " + mx + " " + y2 + " " + x2 + " " + y2 + '" />';
    });

    // nodes
    nodes.forEach(function (n) {
      var p = pos[n.id];
      if (!p) return;
      var kindCls = n.kind === "user" ? "pg-user" : n.kind === "group" ? "pg-group" : "pg-object";
      var hi = highlight[n.id] ? " pg-highlight" : "";
      var label = n.label || classify(n.id).name || n.id;
      var sub = n.token != null ? "#" + n.token : (n.kind === "object" ? "object" : n.kind);
      svg += '<g class="pg-node ' + kindCls + hi + '" data-node="' + V.esc(n.id) + '">' +
        '<rect x="' + p.x + '" y="' + p.y + '" width="' + NODE_W + '" height="' + NODE_H + '"></rect>' +
        '<text x="' + (p.x + 10) + '" y="' + (p.y + 17) + '">' + V.esc(truncLabel(label)) + "</text>" +
        '<text class="pg-sub" x="' + (p.x + 10) + '" y="' + (p.y + 31) + '">' + V.esc(sub) + "</text>" +
        "</g>";
    });

    svg += "</svg>";
    return svg;
  }

  function truncLabel(s) {
    s = String(s || "");
    return s.length > 20 ? s.slice(0, 19) + "…" : s;
  }

  /* =========================================================== errors */
  function teachError(e) {
    var out = el("pg-out");
    var msg = String((e && e.message) || e);
    var is401 = /HTTP 401/.test(msg);
    var is503 = /HTTP 503/.test(msg);
    var is422 = /HTTP 422/.test(msg);
    V.err("pg-err", e);
    var hint = "";
    if (is401) {
      hint = '<div class="note">The permission graph is a <b>god-view</b> over org structure and access, so it is admin-only. ' +
        "Set the admin token in the session bar above — it is kept in this tab only and never stored.</div>";
    } else if (is503) {
      hint = '<div class="note">Resolving the identity closure needs the relationship-based permissions engine (ReBAC) running. ' +
        "Without it the server refuses rather than guessing, and its refusal is shown above as-is. Point the server at a ReBAC engine and try again.</div>";
    } else if (is422) {
      hint = '<div class="note">This whole-source / entity lookup is above the corpus-size ceiling — it would be an unbounded full scan. ' +
        "Look up a specific <b>document id</b> instead (always exempt), or add the supporting index first.</div>";
    }
    el("pg-hint").innerHTML = hint;
    if (out) out.innerHTML = "";
    if (is401 || is503) {
      var asof = el("pg-asof"); if (asof) asof.textContent = "";
    }
  }
})();
