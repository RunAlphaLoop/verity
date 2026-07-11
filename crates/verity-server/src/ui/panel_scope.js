"use strict";
/* ==========================================================================
   panel_scope.js — Screen 1 · Scope Inspector  (TA.1 · the crown jewel)
   --------------------------------------------------------------------------
   Read-path purity: the ONLY network calls are pure reads through Verity.api()
   to endpoints that already exist — POST /v1/recall, GET /v1/briefs/{entity},
   GET /v1/activity. Handle decode is client-side (Verity.decodeHandle). No LLM
   call, no live-ReBAC call, no permissive-fallback affordance anywhere.

   THE HONESTY ENCODING per hit:
     • ACL provenance  → solid provenance badge (mirrored/approximated/…)
     • confidentiality → 4-level conf badge (derived from the handle ceiling
       when the hit itself carries no class — labeled as a ceiling, not a claim)
     • trust tier      → Tier-1 solid vs observation dim
     • tag_derivation  → SOLID (provenance/deterministic) vs DASHED (inferred/
       probabilistic). The wire RecallHit has no `tag_derivation` field, so we
       derive it HONESTLY from trust_tier: authoritative ⇒ provenance (a
       deterministic, source-fidelity tag); observation ⇒ inferred (a
       model-/agent-derived tag). This mapping is disclosed in the legend.
     • bi-temporal     → valid_from (+ is_stale/superseded when the payload
       actually carries them; never fabricated)
     • citation → L0   → provenance episode id (+ Copy document_id)
   ========================================================================== */
(function () {
  // Session state for this panel (kept local; never global).
  var S = {
    handle: null, // the raw vs_… string last successfully decoded
    claims: null, // decoded payload object
    probes: { recall: null, brief: null, activity: null }, // last results (for export)
    lat: [], // session-local recall latencies (ms), for p50/p95/p99
  };

  Verity.register({
    id: "scope",
    mount: function (section) {
      var el = Verity.$("scope-mount");
      if (!el) return;
      el.innerHTML = layout();
      wire();
    },
  });

  /* ------------------------------------------------------------- layout */
  function layout() {
    return (
      // ---- 1. handle intake + decode -----------------------------------
      '<div class="card">' +
        '<h2>Handle intake <span class="sub">client-side decode — the payload is signed, not secret</span></h2>' +
        '<div class="row">' +
          '<div><label for="sc-handle">scope handle (vs_&hellip;)</label>' +
            '<textarea id="sc-handle" spellcheck="false" placeholder="vs_eyJ0ZW5hbnRfaWQiOi4uLn0.c2ln&hellip;"></textarea></div>' +
          '<div class="tight"><button class="primary" id="sc-decode">Decode</button></div>' +
          '<div class="tight"><button id="sc-copy-handle" disabled>Copy handle</button></div>' +
        '</div>' +
        '<div class="err" id="sc-decode-err"></div>' +
        '<div class="note">The payload segment is base64url &mdash; <em>signed, not secret</em>: anyone holding a handle can read its scope; only the server-side HMAC makes it usable. Decoding happens entirely in your browser (zero server call).</div>' +
        '<dl class="kv" id="sc-claims" style="display:none"></dl>' +
      '</div>' +

      // ---- 2. probes through the handle --------------------------------
      '<div class="card" id="sc-probes" style="display:none">' +
        '<h2>Probes through this handle <span class="sub">pure reads — recall · brief · activity</span></h2>' +
        '<div id="sc-legend" class="note"></div>' +

        // recall
        '<h3 style="margin-top:14px;font-size:12px">&#9656; recall <span class="refreshed">POST /v1/recall</span></h3>' +
        '<div class="row">' +
          '<div><label for="sc-q">query text</label><input type="text" id="sc-q" placeholder="renewal risk at acme"></div>' +
          '<div class="tight" style="width:64px"><label for="sc-k">k</label><input type="number" id="sc-k" value="8" min="1" max="100" style="width:64px"></div>' +
          '<div class="tight" style="width:72px"><label for="sc-runs">runs</label><input type="number" id="sc-runs" value="1" min="1" max="50" style="width:72px" title="repeat the identical call N times for a session-local p50/p95/p99"></div>' +
          '<div class="tight"><button id="sc-recall">Run recall</button></div>' +
        '</div>' +
        '<div class="err" id="sc-recall-err"></div>' +
        '<div id="sc-lat"></div>' +
        '<div id="sc-recall-out"></div>' +
        '<div id="sc-trace"></div>' +

        // brief
        '<h3 style="margin-top:16px;font-size:12px">&#9656; entity brief <span class="refreshed">GET /v1/briefs/{entity}</span></h3>' +
        '<div class="row">' +
          '<div><label for="sc-brief-e">entity</label><input type="text" id="sc-brief-e" placeholder="account:acme"></div>' +
          '<div class="tight"><button id="sc-brief">Load brief</button></div>' +
        '</div>' +
        '<div class="err" id="sc-brief-err"></div>' +
        '<div id="sc-brief-out"></div>' +

        // activity
        '<h3 style="margin-top:16px;font-size:12px">&#9656; activity timeline <span class="refreshed">GET /v1/activity</span></h3>' +
        '<div class="row">' +
          '<div><label for="sc-act-e">entity</label><input type="text" id="sc-act-e" placeholder="account:acme"></div>' +
          '<div class="tight"><button id="sc-act">Load activity</button></div>' +
        '</div>' +
        '<div class="err" id="sc-act-err"></div>' +
        '<div id="sc-act-out"></div>' +

        // export
        '<div class="row" style="margin-top:16px">' +
          '<div class="tight"><button class="primary" id="sc-export">Export boundary as evidence</button></div>' +
          '<div class="note" style="flex:1">A self-contained snapshot &mdash; decoded claims + probe results + boundary trace + timestamp + build hash &mdash; with no external references. <em>This is the reviewer\'s deliverable.</em></div>' +
        '</div>' +

        // ---- v0.2: derive a NEW handle from this one (narrow-only) --------
        '<h3 style="margin-top:18px;font-size:12px">&#9656; derive a handle <span class="refreshed">POST /v1/scopes</span></h3>' +
        '<div class="note">Minting only ever <em>narrows</em>. You cannot raise the confidentiality ceiling or add an entity or a principal this handle does not already carry &mdash; the controls simply do not offer it. Purpose may clamp further; the server is the final authority.</div>' +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><button id="sc-open">Open narrower scope&hellip;</button></div>' +
          '<div class="tight"><button id="sc-renew" disabled title="Renew re-mints the same claims with a fresh TTL — only offered once the current handle is EXPIRED.">Renew (re-mint identical claims)</button></div>' +
          '<div class="note" id="sc-mint-hint" style="flex:1"></div>' +
        '</div>' +
        '<div class="err" id="sc-mint-err"></div>' +
        '<div id="sc-mint-out"></div>' +
      '</div>' +

      // ---- v0.2 mint dialog (narrow-only, no widen affordance) ------------
      mintDialogHtml()
    );
  }

  /* --------------------------------------------- v0.2 mint dialog markup */
  // The dialog is rendered ONCE; its option sets are (re)built from the
  // current decoded handle each time it opens, so no control can ever offer a
  // value broader than the source handle. There is no "widen" affordance by
  // construction — not a disabled one, simply absent.
  function mintDialogHtml() {
    return (
      '<div class="dialog-backdrop" id="sc-mint-dialog">' +
        '<div class="dialog" style="max-width:640px">' +
          '<h3>Open a narrower scope</h3>' +
          '<div class="note">Derives a fresh <code>vs_&hellip;</code> handle from the one you decoded. Every field below can only <b>tighten</b> the source handle. Principals are carried verbatim (you cannot grant powers this handle lacks); to widen anything you would mint from a broader source handle you already hold.</div>' +

          // principals — read-only, carried verbatim
          '<div class="card" style="margin-top:10px">' +
            '<div class="note" style="margin-bottom:6px"><b>principals</b> &mdash; carried verbatim from the source handle (not editable; minting cannot add a principal):</div>' +
            '<div id="sc-mint-principals"></div>' +
          '</div>' +

          // confidentiality ceiling — options capped at the source ceiling
          '<div class="tight" style="margin-top:10px">' +
            '<label for="sc-mint-conf">confidentiality ceiling <span class="note">(cannot exceed the source handle\'s ceiling)</span></label>' +
            '<select class="field" id="sc-mint-conf"></select>' +
          '</div>' +

          // entity scope — subset of the source entity_scope (or narrow an
          // unbound handle by binding it to specific entities)
          '<div class="card" style="margin-top:10px">' +
            '<div class="note" style="margin-bottom:6px"><b>entity_scope</b> &mdash; <span id="sc-mint-entity-note"></span></div>' +
            '<div id="sc-mint-entities"></div>' +
          '</div>' +

          // purpose — optional; further clamps server-side
          '<div class="tight" style="margin-top:10px">' +
            '<label for="sc-mint-purpose">purpose <span class="note">(optional &mdash; may clamp the ceiling and/or require an entity binding; unknown purposes are rejected by the server)</span></label>' +
            '<input type="text" id="sc-mint-purpose" class="field" list="sc-mint-purpose-list" placeholder="e.g. support_conversation" autocomplete="off">' +
            '<datalist id="sc-mint-purpose-list">' +
              '<option value="support_conversation">' +
              '<option value="sales_negotiation">' +
              '<option value="marketing">' +
              '<option value="analytics">' +
              '<option value="audit">' +
            '</datalist>' +
            '<div class="note" style="margin-top:4px">Suggestions are the shipped default pack; a deployment may configure others. The purpose ceiling is <em>min</em>&rsquo;d with your selection &mdash; it can only lower it.</div>' +
          '</div>' +

          // TTL
          '<div class="tight" style="margin-top:10px">' +
            '<label for="sc-mint-ttl">TTL <span class="note">(seconds until the new handle expires)</span></label>' +
            '<input type="number" id="sc-mint-ttl" class="field" min="1" step="1" value="3600">' +
          '</div>' +

          '<div class="err" id="sc-mint-dlg-err"></div>' +
          '<div class="actions">' +
            '<button class="primary" id="sc-mint-confirm">Mint narrower handle</button>' +
            '<button id="sc-mint-cancel">Cancel</button>' +
          '</div>' +
        '</div>' +
      '</div>'
    );
  }

  /* --------------------------------------------------------------- wiring */
  function wire() {
    Verity.$("sc-decode").onclick = onDecode;
    Verity.$("sc-copy-handle").onclick = function () {
      if (S.handle) copy(S.handle, this, "Copy handle");
    };
    Verity.$("sc-recall").onclick = onRecall;
    Verity.$("sc-brief").onclick = onBrief;
    Verity.$("sc-act").onclick = onActivity;
    Verity.$("sc-export").onclick = onExport;
    // v0.2 — derive-a-handle actions
    Verity.$("sc-open").onclick = openMintDialog;
    Verity.$("sc-renew").onclick = onRenew;
    var mintDlg = Verity.dialog("sc-mint-dialog");
    Verity.$("sc-mint-cancel").onclick = function () { mintDlg.close(); };
    Verity.$("sc-mint-confirm").onclick = onMintConfirm;
  }

  /* --------------------------------------------------- 1. decode + claims */
  function onDecode() {
    Verity.clearErr("sc-decode-err");
    var raw = (Verity.$("sc-handle").value || "").trim();
    try {
      var p = Verity.decodeHandle(raw);
      S.handle = raw;
      S.claims = p;
      S.probes = { recall: null, brief: null, activity: null };
      S.lat = [];
      renderClaims(p);
      // reset probe + mint outputs on a fresh decode
      ["sc-lat", "sc-recall-out", "sc-trace", "sc-brief-out", "sc-act-out", "sc-mint-out"].forEach(function (id) {
        var n = Verity.$(id); if (n) n.innerHTML = "";
      });
      Verity.clearErr("sc-mint-err");
      updateDeriveControls(p);
      Verity.$("sc-copy-handle").disabled = false;
      // Probes render even for an empty-principal handle so a reviewer can DEMONSTRATE
      // fail-closed (a recall through it returns 0 hits with the Explain-zero reason).
      Verity.$("sc-probes").style.display = "block";
      // auto-fill tenant (shared state) + entity probes from the handle
      if (p.tenant_id) Verity.setTenant(p.tenant_id);
      var firstEntity = (p.entity_scope && p.entity_scope.length) ? p.entity_scope[0] : "";
      if (firstEntity) {
        if (!Verity.$("sc-brief-e").value) Verity.$("sc-brief-e").value = firstEntity;
        if (!Verity.$("sc-act-e").value) Verity.$("sc-act-e").value = firstEntity;
      }
      renderLegend();
    } catch (e) {
      S.handle = null; S.claims = null;
      Verity.$("sc-claims").style.display = "none";
      Verity.$("sc-probes").style.display = "none";
      Verity.$("sc-copy-handle").disabled = true;
      updateDeriveControls(null);
      Verity.err("sc-decode-err", e);
    }
  }

  function renderClaims(p) {
    var dl = Verity.$("sc-claims");
    dl.innerHTML =
      row("tenant_id", esc(p.tenant_id != null ? p.tenant_id : "—")) +
      row("principals (tokens)", principalsHtml(p)) +
      row("entity_scope", entityScopeHtml(p)) +
      row("max_confidentiality", Verity.confBadge(p.max_confidentiality)) +
      row("actor (sub · azp)", esc((p.actor_sub || "—") + " · " + (p.actor_azp || "—"))) +
      row("subject", esc(p.subject || "— (principals were caller-supplied at mint)")) +
      row("retrievable_classes", retrievableHtml(p)) +
      row("purpose-policy version", purposeHtml(p)) +
      row("expires_at", expiresHtml(p));
    dl.style.display = "grid";
  }

  function row(dt, ddHtml) { return "<dt>" + esc(dt) + "</dt><dd>" + ddHtml + "</dd>"; }

  // Fail-closed empty principal set — verbatim copy from today's /ui.
  function principalsHtml(p) {
    if (!p.principals || !p.principals.length) {
      return '<span class="expired">&#8709; — this handle sees nothing (fail closed).</span>';
    }
    return p.principals.map(function (t) {
      // A principal that is an email string is an email-mapped identity: a
      // TRUST DOWNGRADE (SPEC §6b) — flag it distinctly + "why weaker" note.
      var isEmail = typeof t === "string" && /@/.test(t);
      var chip = '<span class="badge b-kind">#' + esc(t) + "</span>";
      if (isEmail) {
        chip += ' <span class="badge b-downgrade" title="Email-mapped principals are weaker than ReBAC subject resolution: membership is a point-in-time string match, not a live group-graph resolution, so a revoked email can lag one read behind. Prefer a resolved user:<id> subject.">trust downgrade</span>';
      }
      return chip;
    }).join(" ");
  }

  function entityScopeHtml(p) {
    if (p.entity_scope && p.entity_scope.length) return Verity.entityBadges(p.entity_scope);
    return '<span style="color:var(--dim)">unbound (no entity restriction on this handle)</span>';
  }

  // retrievable_classes / purpose-policy version are rendered when the handle
  // actually carries them — never fabricated when the payload omits them.
  function retrievableHtml(p) {
    var v = p.retrievable_classes || p.retrievable || null;
    if (Array.isArray(v) && v.length) {
      return v.map(function (c) { return Verity.kindBadge(c); }).join(" ");
    }
    return '<span style="color:var(--dim)">not encoded in this handle (server applies its default class set)</span>';
  }
  function purposeHtml(p) {
    var v = p.purpose_policy_version || p.policy_version || p.purpose_version || p.purpose || null;
    if (v != null && v !== "") return Verity.kindBadge(String(v));
    return '<span style="color:var(--dim)">not encoded in this handle</span>';
  }

  function expiresHtml(p) {
    if (!p.expires_at) return '<span style="color:var(--dim)">—</span>';
    var left = new Date(p.expires_at).getTime() - Date.now();
    var when = esc(Verity.fmtTime(p.expires_at));
    if (left > 0) {
      return when + ' <span class="live">(' + Math.round(left / 1000) + "s left)</span>";
    }
    return when + ' <span class="expired">(EXPIRED — the server will reject this handle)</span>';
  }

  function renderLegend() {
    Verity.$("sc-legend").innerHTML =
      "Per-hit honesty encoding: " +
      Verity.tagDerivationBadge("provenance") + " deterministic, source-fidelity tag &nbsp; · &nbsp; " +
      Verity.tagDerivationBadge("inferred") + " probabilistic / model-derived tag. " +
      "<em>tag_derivation is derived from trust tier</em> (authoritative &rarr; provenance, observation &rarr; inferred), the deterministic signal the wire carries. " +
      "Confidentiality shown per hit is <em>the handle's ceiling</em> (" + confName(S.claims && S.claims.max_confidentiality) +
      "), not a per-chunk re-classification.";
  }

  /* --------------------------------------------------- 2a. recall probe */
  async function onRecall() {
    Verity.clearErr("sc-recall-err");
    Verity.$("sc-recall-out").innerHTML = "";
    Verity.$("sc-trace").innerHTML = "";
    Verity.$("sc-lat").innerHTML = "";
    if (!S.handle) return Verity.err("sc-recall-err", "decode a scope handle first");

    var k = clampInt(Verity.$("sc-k").value, 1, 100, 8);
    var runs = clampInt(Verity.$("sc-runs").value, 1, 50, 1);
    var q = Verity.$("sc-q").value || null;
    var body = { scope_handle: S.handle, text: q, k: k };

    try {
      var hits = null;
      var lat = [];
      for (var i = 0; i < runs; i++) {
        var t0 = performance.now();
        hits = await Verity.api("/v1/recall", { json: body });
        lat.push(performance.now() - t0);
      }
      S.lat = lat;
      S.probes.recall = { query: q, k: k, runs: runs, hits: hits, latency_ms: lat };
      renderLatency(lat);
      if (hits && hits.length) {
        Verity.$("sc-recall-out").innerHTML = hits.map(hitCard).join("");
        renderTrace(hits, body);
      } else {
        Verity.$("sc-recall-out").innerHTML = explainZero(body);
      }
    } catch (e) {
      Verity.err("sc-recall-err", e);
    }
  }

  // Honest session-local latency — NEVER confused with the milestone-A bench.
  function renderLatency(lat) {
    if (!lat || !lat.length) return;
    var sorted = lat.slice().sort(function (a, b) { return a - b; });
    var p = function (q) { return sorted[Math.min(sorted.length - 1, Math.floor(q * (sorted.length - 1) + 0.5))]; };
    var enc = detectEncoderNote();
    Verity.$("sc-lat").innerHTML =
      '<div class="note" style="margin-top:8px">' +
      "session-local latency &mdash; " +
      "<b>p50</b> " + Verity.fmtMs(p(0.5)) + " · <b>p95</b> " + Verity.fmtMs(p(0.95)) + " · <b>p99</b> " + Verity.fmtMs(p(0.99)) +
      " &nbsp;<span class='badge b-kind'>" + lat.length + " run" + (lat.length === 1 ? "" : "s") + "</span>" +
      '<br><em>session-local · ' + lat.length + " run" + (lat.length === 1 ? "" : "s") + " · your hardware · round-trip incl. network — NOT the milestone-A benchmark.</em>" +
      " Config: " + enc +
      "</div>";
  }
  function detectEncoderNote() {
    // We measure the full round-trip from the browser; whether the dense leg
    // used the local encoder or excluded a remote embedder is a server config
    // we cannot observe from here — state that honestly rather than guess.
    return "full client round-trip (browser&rarr;server&rarr;browser); the server-side encoder config (local-encoder vs remote-embedder-excluded) is not observable from the read path.";
  }

  /* --------------------------------------- boundary trace (payload-derived) */
  function renderTrace(hits, body) {
    var lines = [];
    var ceil = S.claims ? S.claims.max_confidentiality : null;
    lines.push("Returned <b>" + hits.length + "</b> hit" + (hits.length === 1 ? "" : "s") +
      " under a handle whose ceiling is " + Verity.confBadge(ceil) + ".");

    // provenance / trust / derivation mix of the RETURNED set
    var mix = {};
    var trust = { authoritative: 0, observation: 0, other: 0 };
    var kinds = {};
    hits.forEach(function (h) {
      var pv = String(h.acl_provenance || "admin-assigned").toLowerCase();
      mix[pv] = (mix[pv] || 0) + 1;
      var tt = String(h.trust_tier || "").toLowerCase();
      if (tt === "authoritative") trust.authoritative++;
      else if (tt === "observation" || tt === "agent_observation") trust.observation++;
      else trust.other++;
      var kd = String(h.kind || "content").toLowerCase();
      kinds[kd] = (kinds[kd] || 0) + 1;
    });
    lines.push("ACL-provenance mix: " + Object.keys(mix).map(function (k) {
      return Verity.provenanceBadge(k) + "&times;" + mix[k];
    }).join(" "));
    lines.push("Derivation mix: " +
      Verity.tagDerivationBadge("provenance") + "&times;" + trust.authoritative + " (authoritative) &nbsp; " +
      Verity.tagDerivationBadge("inferred") + "&times;" + (trust.observation + trust.other) + " (observation/other)");
    if (kinds.knowledge) {
      lines.push('<span class="badge b-kind">knowledge</span>&times;' + kinds.knowledge +
        " — published cross-customer generalization(s); support is a BUCKET, never an exact count (provenance firewall §7g).");
    }

    // entity clamp reasoning (purely handle-vs-query derivable)
    if (S.claims && S.claims.entity_scope && S.claims.entity_scope.length) {
      lines.push("Entity clamp: only chunks whose tags are a subset of {" +
        esc(S.claims.entity_scope.join(", ")) + "} could match (deny-by-default intersection).");
    } else {
      lines.push("Entity clamp: handle is entity-unbound — no entity restriction narrowed this set.");
    }
    // confidentiality ceiling reasoning
    lines.push("Confidentiality: a hit classified above " + confName(ceil) +
      " would be pre-filtered out before ranking; the ceiling cannot be widened by any query parameter.");

    Verity.$("sc-trace").innerHTML =
      '<details style="margin-top:10px" open>' +
      '<summary style="cursor:pointer;color:var(--accent)">Boundary trace &mdash; what the returned set + handle imply</summary>' +
      '<div style="margin-top:8px">' +
      lines.map(function (l) { return '<div class="note" style="margin-top:4px">' + l + "</div>"; }).join("") +
      '<div class="note" style="margin-top:8px"><em>Honesty note:</em> this trace explains the returned set and the handle\'s ceiling. It does NOT enumerate every pre-filtered candidate &mdash; full per-candidate drop reasons require the audited debug-recall endpoint, which is deliberately OFF the read path (no LLM / live-ReBAC call here).</div>' +
      "</div></details>";
  }

  /* ---------------------------------------------- Explain-zero (0 hits) */
  function explainZero(body) {
    var p = S.claims || {};
    var reasons = [];
    if (!p.principals || !p.principals.length) {
      reasons.push("This handle's principal set is <b>empty</b> — it sees nothing by construction (fail closed).");
    }
    if (p.entity_scope && p.entity_scope.length) {
      reasons.push("The handle is clamped to {" + esc(p.entity_scope.join(", ")) +
        "}; only chunks tagged within that set are retrievable.");
    }
    reasons.push("The handle's <b>max_confidentiality</b> is " + confName(p.max_confidentiality) +
      " — anything classified higher is pre-filtered out before ranking, and no query parameter can widen that.");
    return (
      '<div class="empty" style="margin-top:8px"><b>0 hits.</b> Under this scope, nothing matches &mdash; that is the point.</div>' +
      reasons.map(function (r) { return '<div class="note" style="margin-top:4px">' + r + "</div>"; }).join("") +
      '<div class="note" style="margin-top:6px"><em>Fail-closed is correct here:</em> under-visibility is the guarantee, not a bug.</div>'
    );
  }

  /* --------------------------------------------------- 2b. brief probe */
  async function onBrief() {
    Verity.clearErr("sc-brief-err");
    Verity.$("sc-brief-out").innerHTML = "";
    if (!S.handle) return Verity.err("sc-brief-err", "decode a scope handle first");
    var entity = (Verity.$("sc-brief-e").value || "").trim();
    if (!entity) return Verity.err("sc-brief-err", "enter an entity (e.g. account:acme)");
    try {
      var b = await Verity.api("/v1/briefs/" + encodeURIComponent(entity) +
        "?scope_handle=" + encodeURIComponent(S.handle));
      S.probes.brief = { entity: entity, result: b };
      var mem = (b && b.recent_memory) || [];
      var act = (b && b.recent_activity) || [];
      var staleChip = b && b.is_stale
        ? ' <span class="badge b-st-invalidated" title="the materialized brief has not re-synced within its freshness window — disclosed, never hidden">is_stale</span>'
        : ' <span class="badge b-st-published" title="brief is within its freshness window">fresh</span>';
      Verity.$("sc-brief-out").innerHTML =
        '<div class="note">generated_at ' + esc(Verity.fmtTime(b && b.generated_at)) + staleChip +
        (b && b.last_synced_at ? " · last_synced " + esc(Verity.fmtTime(b.last_synced_at)) : "") +
        (b && b.source_version != null ? " · source_version " + esc(b.source_version) : "") +
        " · " + mem.length + " memory · " + act.length + " activity</div>" +
        mem.map(hitCard).join("") + actionRows(act) +
        (mem.length || act.length ? "" : '<div class="empty">nothing visible for this entity under this scope (fail closed).</div>');
    } catch (e) {
      Verity.err("sc-brief-err", e);
    }
  }

  /* ------------------------------------------------ 2c. activity probe */
  async function onActivity() {
    Verity.clearErr("sc-act-err");
    Verity.$("sc-act-out").innerHTML = "";
    if (!S.handle) return Verity.err("sc-act-err", "decode a scope handle first");
    var entity = (Verity.$("sc-act-e").value || "").trim();
    if (!entity) return Verity.err("sc-act-err", "enter an entity (e.g. account:acme)");
    try {
      var actions = await Verity.api("/v1/activity?scope_handle=" + encodeURIComponent(S.handle) +
        "&entity=" + encodeURIComponent(entity));
      S.probes.activity = { entity: entity, result: actions };
      Verity.$("sc-act-out").innerHTML = (actions && actions.length)
        ? actionRows(actions)
        : '<div class="empty">no visible actions on this entity under this scope (fail closed).</div>';
    } catch (e) {
      Verity.err("sc-act-err", e);
    }
  }

  /* ---------------------------------------------------- shared renderers */
  // A recall/brief-memory hit card with the FULL honesty payload.
  function hitCard(h) {
    var ceil = S.claims ? S.claims.max_confidentiality : 1;
    var derivation = trustToDerivation(h.trust_tier);
    var support = h.support_tier
      ? ' <span class="badge b-kind" title="bucketed cross-customer support — never an exact count (provenance firewall §7g)">support: ' + esc(h.support_tier) + "</span>"
      : "";
    return (
      '<div class="hit">' +
        '<span class="score">score ' + Number(h.score).toFixed(3) + "</span> " +
        Verity.kindBadge(h.kind || "content") +
        Verity.provenanceBadge(h.acl_provenance) +
        Verity.confBadge(ceil) +
        Verity.trustBadge(h.trust_tier) +
        Verity.tagDerivationBadge(derivation) +
        support +
        Verity.entityBadges(h.entity_tags) +
        '<div class="content">' + esc(h.content) + "</div>" +
        '<div class="meta">' +
          "doc " + esc(h.document_id) + " · seq " + esc(h.seq) +
          " · valid_from " + esc(Verity.fmtTime(h.valid_from)) +
          " · citation&rarr;L0 episode " + esc(h.provenance) +
          ' <button class="sc-copy-doc" data-doc="' + esc(h.document_id) + '" style="padding:1px 7px;font-size:11px;margin-left:6px">Copy document_id</button>' +
        "</div>" +
      "</div>"
    );
  }

  // trust_tier → tag_derivation: authoritative is a deterministic (provenance)
  // tag; observation is a model-/agent-derived (inferred) tag. The wire has no
  // tag_derivation field, so this is the honest deterministic mapping.
  function trustToDerivation(t) {
    var n = String(t || "").toLowerCase();
    return (n === "authoritative" || n === "tier1" || n === "tier-1") ? "provenance" : "inferred";
  }

  function actionRows(actions) {
    if (!actions || !actions.length) return "";
    return (
      '<div class="tablewrap"><table><thead><tr>' +
        "<th>occurred</th><th>type</th><th>actor</th><th>outcome</th><th>summary</th><th>entities</th><th>citation&rarr;L0</th>" +
      "</tr></thead><tbody>" +
      actions.map(function (a) {
        return "<tr><td>" + esc(Verity.fmtTime(a.occurred_at)) + "</td><td>" + esc(a.action_type) +
          "</td><td>" + esc((a.actor_sub || "—") + " · " + (a.actor_azp || "—")) +
          "</td><td>" + esc(a.outcome) +
          "</td><td>" + esc(a.summary) +
          "</td><td>" + Verity.entityBadges(a.entities) +
          "</td><td>" + esc(a.provenance != null ? a.provenance : "—") + "</td></tr>";
      }).join("") +
      "</tbody></table></div>"
    );
  }

  /* ----------------------------------------------------------- actions */
  // Copy-document_id is delegated (cards render after the fact).
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
    } else {
      fallbackCopy(text); done();
    }
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

  /* ------------------------------------- Export boundary as evidence */
  function onExport() {
    if (!S.claims) return;
    var now = new Date();
    var build = Verity.buildHash();
    var snapshot = {
      artifact: "verity-scope-boundary-evidence",
      exported_at: now.toISOString(),
      build_hash: build,
      note: "Self-contained boundary evidence. Handle decode is client-side; probes are pure reads (no LLM, no live-ReBAC). Latency is session-local, NOT the milestone-A benchmark.",
      claims: S.claims,
      probes: S.probes,
    };
    var json = JSON.stringify(snapshot, null, 2);
    var html = evidenceHtml(snapshot, json);
    download(html, "verity-boundary-" + stamp(now) + ".html", "text/html");
  }

  // A fully self-contained HTML evidence page (no external refs) with the raw
  // JSON snapshot embedded for machine consumption.
  function evidenceHtml(snap, json) {
    var claims = snap.claims || {};
    var recall = snap.probes && snap.probes.recall;
    var lat = recall && recall.latency_ms ? recall.latency_ms.slice().sort(function (a, b) { return a - b; }) : null;
    var pick = function (q) { return lat ? Verity.fmtMs(lat[Math.min(lat.length - 1, Math.floor(q * (lat.length - 1) + 0.5))]) : "—"; };
    var claimRows = Object.keys(claims).map(function (kk) {
      return "<tr><td class='k'>" + esc(kk) + "</td><td>" + esc(JSON.stringify(claims[kk])) + "</td></tr>";
    }).join("");
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
      "<div class='meta'>exported " + esc(snap.exported_at) + " · build <b>" + esc(snap.build_hash) + "</b> · <span class='pill'>read-only · client decode · pure reads</span></div>" +
      "<div class='meta' style='margin-top:6px'>" + esc(snap.note) + "</div>" +
      "<h2>Decoded claims</h2><table>" + claimRows + "</table>" +
      "<h2>Recall probe</h2>" +
      (recall
        ? "<div class='meta'>query " + esc(JSON.stringify(recall.query)) + " · k " + esc(recall.k) +
          " · " + (recall.hits ? recall.hits.length : 0) + " hit(s) · " + (recall.runs || 1) + " run(s)</div>" +
          (lat ? "<div class='meta'>session-local latency (NOT the benchmark): p50 " + pick(0.5) + " · p95 " + pick(0.95) + " · p99 " + pick(0.99) + "</div>" : "")
        : "<div class='meta'>no recall probe was run.</div>") +
      "<h2>Machine-readable snapshot (JSON)</h2><pre>" + esc(json) + "</pre>" +
      "</body></html>"
    );
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

  /* ====================================================================
     v0.2 — DERIVE A HANDLE (narrow-only)  ·  POST /v1/scopes
     --------------------------------------------------------------------
     Two actions off a decoded handle:
       • Open narrower scope — a mint dialog whose controls, by construction,
         cannot select anything BROADER than the source handle: the ceiling
         <select> is capped at the source ceiling; the entity checkboxes are
         drawn from the source entity_scope (a subset), or bind an unbound
         handle to specific entities. Principals are carried verbatim — you
         cannot add a principal the source lacks. There is no widen control.
       • Renew — re-mints the SAME claims (identical principals, entity_scope,
         ceiling, purpose, actor) with a fresh TTL. Offered only once the
         source handle is EXPIRED (re-minting a live handle is pointless).
     /v1/scopes is a PUBLIC route (not admin-gated), so no admin bearer is
     attached — this is a scope-derivation seam, not an admin surface.
     ==================================================================== */

  // Enable/disable the derive buttons + Renew (expired-only) from claims.
  function updateDeriveControls(p) {
    var openBtn = Verity.$("sc-open");
    var renewBtn = Verity.$("sc-renew");
    var hint = Verity.$("sc-mint-hint");
    if (!openBtn || !renewBtn) return;
    if (!p) {
      openBtn.disabled = true;
      renewBtn.disabled = true;
      if (hint) hint.innerHTML = "";
      return;
    }
    openBtn.disabled = false;
    var expired = isExpired(p);
    renewBtn.disabled = !expired;
    if (hint) {
      hint.innerHTML = expired
        ? 'This handle is <span class="expired">EXPIRED</span> &mdash; <b>Renew</b> re-mints its identical claims with a fresh TTL.'
        : 'This handle is <span class="live">live</span> &mdash; Renew is offered only after it expires. Use <b>Open narrower scope</b> to derive a tighter handle now.';
    }
  }

  function isExpired(p) {
    if (!p || !p.expires_at) return false;
    return new Date(p.expires_at).getTime() - Date.now() <= 0;
  }

  // The server's Confidentiality enum has NO serde rename, so the wire form is
  // the PascalCase variant name ("Internal", "Restricted", …) — verified by
  // identity_tests.rs. CONF_NAMES is lowercase (for badges), so map 0-3 → the
  // exact wire token the request body must carry.
  var CONF_WIRE = ["Public", "Internal", "Confidential", "Restricted"];
  function confWire(idx) { return CONF_WIRE[idx] || "Internal"; }

  // The source handle's confidentiality ceiling as a 0-3 index (default
  // internal=1 when the payload omits it, matching the server default).
  function ceilingIndex(p) {
    var v = p && p.max_confidentiality;
    if (typeof v === "number") return v;
    if (typeof v === "string") {
      var i = Verity.CONF_NAMES.indexOf(v.toLowerCase());
      if (i >= 0) return i;
    }
    return 1; // server default_confidentiality() = Internal
  }

  /* ------------------------------------------------- open the mint dialog */
  function openMintDialog() {
    if (!S.claims) return;
    var p = S.claims;
    Verity.clearErr("sc-mint-dlg-err");
    Verity.clearErr("sc-mint-err");

    // principals — verbatim, read-only. Empty set is shown as fail-closed.
    // Honest seam: if this handle was identity-resolved (carries a `subject`),
    // deriving from a bare handle re-supplies its already-resolved principal
    // TOKENS (the dev-mode mint path), not a live subject re-resolution. The
    // server still runs revocation-tombstone subtraction at mint, but a group
    // membership that changed AFTER the source handle was minted will not be
    // re-resolved here. Disclose it rather than imply a fresh identity pull.
    var subjNote = (typeof p.subject === "string" && p.subject)
      ? '<div class="note" style="margin-top:6px"><em>This handle was identity-resolved from subject <b>' +
        esc(p.subject) + "</b>.</em> Deriving here carries its resolved principal tokens verbatim; " +
        "it does <b>not</b> re-resolve the subject against the live group graph. For a fresh identity " +
        "pull, mint server-side from the subject. (Revocation tombstones are still applied at mint.)</div>"
      : "";
    Verity.$("sc-mint-principals").innerHTML = principalsHtml(p) + subjNote;

    // confidentiality ceiling — options 0..ceiling ONLY (no widen).
    var ceil = ceilingIndex(p);
    var sel = Verity.$("sc-mint-conf");
    var opts = "";
    for (var i = 0; i <= ceil; i++) {
      var nm = Verity.CONF_NAMES[i] || String(i);
      opts += '<option value="' + i + '"' + (i === ceil ? " selected" : "") + ">" +
        esc(nm) + (i === ceil ? " (source ceiling)" : "") + "</option>";
    }
    sel.innerHTML = opts;

    // entity_scope — subset checkboxes (bound) or free bind (unbound).
    var eWrap = Verity.$("sc-mint-entities");
    var eNote = Verity.$("sc-mint-entity-note");
    if (p.entity_scope && p.entity_scope.length) {
      eNote.textContent =
        "check a subset to narrow further (unchecking removes an entity; you cannot add one outside this set). Leave all checked to keep the source binding.";
      eWrap.innerHTML = p.entity_scope.map(function (e) {
        return '<label class="checkline" style="display:block;margin:3px 0">' +
          '<input type="checkbox" class="sc-mint-ent" value="' + esc(e) + '" checked> ' +
          Verity.entityBadges([e]) + "</label>";
      }).join("");
    } else {
      eNote.textContent =
        "the source handle is entity-UNBOUND. Binding it to specific entities is a narrowing; leave blank to keep it unbound.";
      eWrap.innerHTML =
        '<input type="text" id="sc-mint-ent-free" class="field" ' +
        'placeholder="account:acme, account:globex (comma/space separated — optional)" autocomplete="off">';
    }

    Verity.$("sc-mint-purpose").value = (typeof p.purpose === "string") ? p.purpose : "";
    Verity.$("sc-mint-ttl").value = "3600";
    Verity.dialog("sc-mint-dialog").open();
  }

  /* ---------------------------------------- collect the narrowed entity set */
  // Returns { entities, error }. Enforces the subset rule client-side so no
  // widen can be submitted; the server re-enforces regardless.
  function collectNarrowedEntities(p) {
    if (p.entity_scope && p.entity_scope.length) {
      var checked = Array.prototype.slice
        .call(document.querySelectorAll(".sc-mint-ent:checked"))
        .map(function (n) { return n.value; });
      // subset guarantee (defensive — the checkboxes are already a subset)
      for (var i = 0; i < checked.length; i++) {
        if (p.entity_scope.indexOf(checked[i]) < 0) {
          return { entities: null, error: "refusing to widen: " + checked[i] + " is not in the source entity_scope" };
        }
      }
      return { entities: checked, error: null };
    }
    var free = Verity.$("sc-mint-ent-free");
    var parts = String(free && free.value || "").split(/[\s,]+/).filter(function (s) { return s.length; });
    return { entities: parts, error: null }; // unbound → bind (narrows) or stay unbound
  }

  /* ---------------------------------------------------- mint (narrow) */
  async function onMintConfirm() {
    Verity.clearErr("sc-mint-dlg-err");
    var p = S.claims;
    if (!p) return Verity.err("sc-mint-dlg-err", "decode a scope handle first");

    var ceil = ceilingIndex(p);
    var wantConf = clampInt(Verity.$("sc-mint-conf").value, 0, ceil, ceil);
    if (wantConf > ceil) {
      // Unreachable via the UI (options are capped), but fail closed anyway.
      return Verity.err("sc-mint-dlg-err", "refusing to widen the confidentiality ceiling");
    }
    var ents = collectNarrowedEntities(p);
    if (ents.error) return Verity.err("sc-mint-dlg-err", ents.error);

    var ttl = clampInt(Verity.$("sc-mint-ttl").value, 1, 2147483647, 3600);
    var purpose = (Verity.$("sc-mint-purpose").value || "").trim();

    var body = {
      tenant_id: p.tenant_id,
      // Carry principals verbatim — minting never adds a principal.
      principals: p.principals || [],
      entity_scope: ents.entities,
      // Server takes the PascalCase Confidentiality variant name.
      max_confidentiality: confWire(wantConf),
      actor_sub: p.actor_sub != null ? p.actor_sub : undefined,
      actor_azp: p.actor_azp != null ? p.actor_azp : undefined,
      ttl_seconds: ttl,
    };
    if (purpose) body.purpose = purpose;
    stripUndefined(body);

    var btn = Verity.$("sc-mint-confirm");
    btn.disabled = true;
    try {
      var res = await Verity.api("/v1/scopes", { json: body });
      Verity.dialog("sc-mint-dialog").close();
      renderMintResult(res, "Opened a narrower scope", body);
    } catch (e) {
      Verity.err("sc-mint-dlg-err", e);
    } finally {
      btn.disabled = false;
    }
  }

  /* ---------------------------------------------------- renew (re-mint) */
  async function onRenew() {
    Verity.clearErr("sc-mint-err");
    var p = S.claims;
    if (!p) return Verity.err("sc-mint-err", "decode a scope handle first");
    // Re-mint the SAME claims — no narrowing, no widening — with a fresh TTL.
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

    var btn = Verity.$("sc-renew");
    btn.disabled = true;
    try {
      var res = await Verity.api("/v1/scopes", { json: body });
      renderMintResult(res, "Renewed — identical claims, fresh TTL", body);
    } catch (e) {
      Verity.err("sc-mint-err", e);
    } finally {
      btn.disabled = !isExpired(p); // re-lock unless still expired
    }
  }

  /* ------------------------------------------------ render a minted handle */
  function renderMintResult(res, title, body) {
    var handle = res && res.scope_handle;
    var expires = res && res.expires_at;
    if (!handle) {
      Verity.err("sc-mint-err", "server returned no scope_handle");
      return;
    }
    var out = Verity.$("sc-mint-out");
    out.innerHTML =
      '<div class="card" style="margin-top:10px">' +
        '<div class="note"><b>' + esc(title) + ".</b> A fresh signed handle was minted by the server " +
          "(POST /v1/scopes). It is <em>signed, not secret</em> — the claims below are readable by anyone holding it.</div>" +
        '<dl class="kv" style="margin-top:8px">' +
          "<dt>ceiling</dt><dd>" + Verity.confBadge(body.max_confidentiality) + "</dd>" +
          "<dt>entity_scope</dt><dd>" +
            (body.entity_scope && body.entity_scope.length
              ? Verity.entityBadges(body.entity_scope)
              : '<span style="color:var(--dim)">unbound</span>') + "</dd>" +
          (body.purpose ? "<dt>purpose</dt><dd>" + Verity.kindBadge(body.purpose) + "</dd>" : "") +
          "<dt>expires_at</dt><dd>" + esc(Verity.fmtTime(expires)) + "</dd>" +
        "</dl>" +
        '<div style="margin-top:8px"><textarea readonly spellcheck="false" ' +
          'style="min-height:60px" id="sc-mint-handle">' + esc(handle) + "</textarea></div>" +
        '<div class="row" style="margin-top:8px">' +
          '<div class="tight"><button class="primary" id="sc-mint-copy">Copy new handle</button></div>' +
          '<div class="tight"><button id="sc-mint-load">Load into intake &amp; decode</button></div>' +
        "</div>" +
      "</div>";
    Verity.$("sc-mint-copy").onclick = function () { copy(handle, this, "Copy new handle"); };
    Verity.$("sc-mint-load").onclick = function () {
      Verity.$("sc-handle").value = handle;
      onDecode();
      Verity.$("sc-handle").scrollIntoView({ behavior: "smooth", block: "start" });
    };
  }

  // Drop keys whose value is `undefined` so they serialize to `#[serde(default)]`
  // on the server (actor fields are optional).
  function stripUndefined(o) {
    Object.keys(o).forEach(function (k) { if (o[k] === undefined) delete o[k]; });
  }

  /* ------------------------------------------------------------- utils */
  function esc(s) { return Verity.esc(s == null ? "" : s); }
  function clampInt(v, lo, hi, def) {
    var n = parseInt(v, 10);
    if (isNaN(n)) n = def;
    return Math.max(lo, Math.min(hi, n));
  }
  function confName(v) {
    if (v == null) return "(none)";
    if (typeof v === "number") return Verity.CONF_NAMES[v] || String(v);
    return String(v).toLowerCase();
  }
  function stamp(d) {
    return d.toISOString().replace(/[:.]/g, "-").replace("T", "_").replace("Z", "");
  }
})();
