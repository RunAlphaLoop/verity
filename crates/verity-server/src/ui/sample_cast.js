"use strict";
/* ==========================================================================
   sample_cast.js — the "Acme Logistics (sample)" cast · FTUE §3 step 4
   --------------------------------------------------------------------------
   A console-side seeder that replays a trimmed demo.sh-shaped cast through
   the EXISTING public endpoints — no new server surface, no data baked into
   the serving binary. Exposes `window.VeritySample = { seed, remove }`;
   panel_welcome renders the fork's left card against this namespace.

   Honest-seeding rules (FTUE §3):
     • every record carries a source/tag/name starting `verity-sample` so the
       shared `Verity.sampleBadge` check labels it in every panel;
     • idempotent: `user:sample-blind` is registered LAST, as the completion
       marker — a re-run that finds the marker re-upserts the (idempotent)
       principal map and writes NOTHING else, so clicking twice can never
       duplicate L0 episodes;
     • removal runs the REAL erasure pipeline: preview → typed confirm →
       POST /v1/admin/erasure per sample subject/entity. If this build lacks
       erasure, the copy says "invalidate via forget" — never a special-cased
       delete, never a silent one.

   READ-PATH PURITY: this file only POSTs to ingest/admin endpoints; it never
   touches recall and makes no LLM calls.
   ========================================================================== */
(function () {
  var V = window.Verity;

  /* The cast (FTUE §3 step 4). user:sample-blind is the guaranteed-blind
     principal — "holds no keys, sees nothing, ever — Verity's 4242 4242" —
     and doubles as the seeded-completion marker (registered last). */
  var CAST = ["user:jordan", "user:taylor", "group:sales", "group:support", "agent:acme-crm"];
  var BLIND = "user:sample-blind";
  /* Every episode the seeder writes carries this writer_sub, so one erasure
     subject catches the whole observational cast. */
  var CAST_SUB = "user:verity-sample-cast";
  /* Fixed valid_from keys the document chunks (ON CONFLICT DO NOTHING on
     tenant/source/document_id/seq/valid_from) — part of idempotency. */
  var DOC_VALID_FROM = "2026-07-01T12:00:00Z";

  var DOCS = [
    {
      id: "verity-sample-note-renewal",
      org: true,
      content:
        "Acme Freight renewal update (sample): the renewal opportunity moved to negotiation; " +
        "the amount was revised from $48k to $61k after the pricing review. Decision expected this quarter.",
    },
    {
      id: "verity-sample-note-kickoff",
      org: true,
      content:
        "Acme Freight kickoff notes (sample): 120 trucks, dispatch integration live since March; " +
        "success criteria are 95% on-time tracking events and a monthly ops review.",
    },
    {
      id: "verity-sample-note-competitor",
      org: false, // sales-only: the team-only exemplar
      content:
        "Sales-only (sample): a competitor quote for the Acme Freight renewal is rumored at $52k — " +
        "emphasize the dispatch integration and tracking SLA in the renewal conversation.",
    },
  ];

  /* Erasure targets: the subject catches every seeded episode/action/audit
     row; the entities catch CDC facts, entity-tagged chunks, doc episodes
     (their source_entity is the document_id), and the quarantined payload
     (substring match — it names acme-freight). */
  var ERASE_SUBJECTS = [CAST_SUB];
  var ERASE_ENTITIES = [
    "account:acme-freight",
    "acme-freight",
    "acme-renewal",
    "verity-sample", // the label tag every seeded episode chunk carries
    "verity-sample-note-renewal",
    "verity-sample-note-kickoff",
    "verity-sample-note-competitor",
  ];

  function api(path, json, admin) {
    return V.api(path, { json: json, admin: admin !== false });
  }

  async function directory(tenant) {
    var res = await V.api(
      "/v1/admin/principals?tenant_id=" + encodeURIComponent(tenant) + "&limit=1000",
      { admin: true }
    );
    return (res && res.principals) || [];
  }

  /* Org-visible = every named key in the space (users, groups, agents) EXCEPT
     the deliberately-blind principals — that is what "org-visible" means, and
     it keeps the operator's own key (created in step 2) inside the audience. */
  function orgTokens(principals) {
    return principals
      .filter(function (p) {
        return (
          /^(user|group|agent):/.test(p.principal) &&
          p.principal !== BLIND &&
          p.principal !== "user:proof-blind" &&
          p.principal !== CAST_SUB
        );
      })
      .map(function (p) {
        return p.token;
      });
  }

  async function mintSeedHandle(tenant, tokens, ceiling) {
    var res = await V.api("/v1/scopes", {
      json: {
        tenant_id: tenant,
        principals: tokens,
        max_confidentiality: ceiling || "internal",
        ttl_seconds: 900,
        actor_sub: CAST_SUB,
        actor_azp: "console:sample-seeder",
      },
    });
    if (!res || !res.scope_handle) throw new Error("seed mint returned no handle");
    return res.scope_handle;
  }

  /* ------------------------------------------------------------- seed() */
  async function seed(opts) {
    var tenant = opts && opts.tenant;
    if (!tenant) throw new Error("seed needs a tenant");

    var before = await directory(tenant);
    var already = before.some(function (p) { return p.principal === BLIND; });

    // 1. The cast's keys — idempotent by construction (keyed upsert).
    var mapRes = await api("/v1/admin/principals", { tenant_id: tenant, principals: CAST });
    var map = (mapRes && mapRes.mappings) || {};

    if (already) {
      // The completion marker exists (user:sample-blind — a key, so erasure
      // rightly leaves it). Distinguish "seeded and still present" from
      // "seeded then removed": a dry-run erasure preview counts what a purge
      // WOULD delete; zero rows means the memories are gone and a re-seed is
      // the honest action. Preview unavailable → assume seeded (writes safe).
      try {
        var probe = await api("/v1/admin/erasure/preview", { tenant_id: tenant, entity: "account:acme-freight" });
        var w = (probe && probe.would_erase) || {};
        var rows = 0;
        Object.keys(w).forEach(function (k) { if (typeof w[k] === "number") rows += w[k]; });
        if (rows > 0) return { already: true };
        // fall through: marker present, memories erased — seed again.
      } catch (e) {
        return { already: true };
      }
    }

    // 2. Group membership — needs ReBAC; in dev mode the tuples don't bind,
    //    the shared keys still work. Failure here is disclosed, not fatal.
    var membershipNote = "";
    try {
      await api("/v1/admin/groups", { tenant_id: tenant, group: "group:sales", member: "user:jordan" });
      await api("/v1/admin/groups", { tenant_id: tenant, group: "group:support", member: "user:taylor" });
    } catch (e) {
      membershipNote = "group membership tuples need ReBAC (VERITY_SPICEDB_URL) — the shared keys still work";
    }

    // 3. The connector: CDC upserts under source `verity-sample-crm:*`,
    //    including one superseded field (amount 48k → 61k) so record detail
    //    shows the bi-temporal exemplar (old row valid_to + superseded_by).
    //    Event times are SECONDS ago, not days: the freshness SLO measures
    //    event→queryable from these stamps, and a back-dated sample would
    //    paint an honest-but-misleading "slow source needs you" on Home.
    var t1 = Date.now() - 45000;
    var t2 = Date.now() - 5000;
    await api(
      "/v1/ingest/debezium?tenant_id=" + encodeURIComponent(tenant) + "&pk=id",
      [
        {
          op: "c",
          after: { id: "acme-freight", name: "Acme Freight Co (sample)", plan: "enterprise", region: "NA-East", csm: "jordan" },
          source: { connector: "verity-sample-crm", table: "accounts", ts_ms: t1 },
        },
        {
          op: "c",
          after: { id: "acme-renewal", account: "acme-freight", stage: "negotiation", amount: 48000 },
          source: { connector: "verity-sample-crm", table: "opportunities", ts_ms: t1 },
        },
        {
          op: "u",
          after: { id: "acme-renewal", account: "acme-freight", stage: "negotiation", amount: 61000 },
          source: { connector: "verity-sample-crm", table: "opportunities", ts_ms: t2 },
        },
      ]
    );

    // 4. Notes with real sharing rules: two org-visible, one team-only.
    var dir = await directory(tenant);
    var org = orgTokens(dir);
    var sales = dir
      .filter(function (p) { return p.principal === "group:sales" || p.principal === "user:jordan"; })
      .map(function (p) { return p.token; });
    for (var i = 0; i < DOCS.length; i++) {
      var d = DOCS[i];
      await api("/v1/ingest/documents", {
        tenant_id: tenant,
        source: "verity-sample-notes",
        document_id: d.id,
        content: d.content,
        entities: ["account:acme-freight", "verity-sample"],
        visibility: d.org ? org : sales,
        acl_provenance: "admin-assigned",
        valid_from: DOC_VALID_FROM,
      });
    }

    // 5. Episodes through ordinary scoped handles (visibility = the handle's
    //    keys): one sales-only, one support-only, one RESTRICTED pricing note
    //    (invisible below a restricted ceiling — and dropped fail-closed at
    //    recall while ReBAC is off: that is the rule working, not a bug).
    var salesHandle = await mintSeedHandle(tenant, [map["group:sales"], map["user:jordan"]], "internal");
    var supportHandle = await mintSeedHandle(tenant, [map["group:support"], map["user:taylor"]], "internal");
    var restrictedHandle = await mintSeedHandle(tenant, [map["group:sales"]], "restricted");
    await V.api("/v1/episodes", {
      json: {
        scope_handle: salesHandle,
        observation:
          "Renewal call with Acme Freight (sample): pricing pushback — they asked for a multi-year discount. " +
          "Next step: revised quote by Friday.",
        entities: ["account:acme-freight", "verity-sample"],
      },
    });
    await V.api("/v1/episodes", {
      json: {
        scope_handle: supportHandle,
        observation:
          "Support thread (sample): Acme Freight reported intermittent tracking-webhook failures; " +
          "resolved by rotating the signing secret.",
        entities: ["account:acme-freight", "verity-sample"],
      },
    });
    await V.api("/v1/episodes", {
      json: {
        scope_handle: restrictedHandle,
        observation:
          "RESTRICTED (sample): Acme Freight renewal floor price is $58k/yr — deal desk only.",
        entities: ["account:acme-freight", "verity-sample"],
      },
    });

    // 6. One knowledge candidate (proposal, never a publish — the review
    //    queue stays a human gate).
    await V.api("/v1/knowledge", {
      json: {
        scope_handle: salesHandle,
        statement: "(sample) Customers with pricing pushback respond best to multi-year discount options.",
        categories: ["verity-sample"],
      },
    });

    // 7. The on-purpose quarantine: a webhook payload whose permissions can't
    //    be mapped is HELD, never permissively indexed (fail closed, SPEC §5e).
    var hook = await api("/v1/webhooks", {
      tenant_id: tenant,
      name: "verity-sample-inbox",
      visibility: org,
    });
    if (hook && hook.url) {
      await V.api(hook.url, {
        json: {
          source: "verity-sample-inbox",
          event: "billing.sync",
          acl: { scheme: "acme-legacy-roles", roles: ["billing-ops"] },
          note: "(sample) invoice sync for acme-freight — arrives with an ACL scheme Verity cannot map",
        },
      });
    }

    // 8. LAST: the guaranteed-blind principal — also the completion marker,
    //    so a half-failed seed never reads as done.
    await api("/v1/admin/principals", { tenant_id: tenant, principals: [BLIND] });

    return { already: false, membershipNote: membershipNote };
  }

  /* ----------------------------------------------------------- remove() */
  function sum(into, counts) {
    Object.keys(counts || {}).forEach(function (k) {
      if (typeof counts[k] === "number") into[k] = (into[k] || 0) + counts[k];
    });
  }

  async function previewAll(tenant) {
    var total = {};
    var calls = ERASE_SUBJECTS.map(function (s) { return { subject: s }; })
      .concat(ERASE_ENTITIES.map(function (e) { return { entity: e }; }));
    for (var i = 0; i < calls.length; i++) {
      var body = Object.assign({ tenant_id: tenant }, calls[i]);
      var res = await api("/v1/admin/erasure/preview", body);
      sum(total, res && res.would_erase);
    }
    return total;
  }

  async function eraseAll(tenant) {
    var total = {};
    var calls = ERASE_SUBJECTS.map(function (s) { return { subject: s }; })
      .concat(ERASE_ENTITIES.map(function (e) { return { entity: e }; }));
    for (var i = 0; i < calls.length; i++) {
      var body = Object.assign({ tenant_id: tenant }, calls[i]);
      var res = await api("/v1/admin/erasure", body);
      sum(total, (res && res.erased) || res);
    }
    return total;
  }

  function countsTable(counts) {
    var keys = Object.keys(counts).filter(function (k) { return counts[k] > 0; });
    if (!keys.length) return '<div class="note">nothing left to erase — the sample memories are already gone</div>';
    return (
      '<div class="tablewrap"><table><tr><th>table</th><th>rows</th></tr>' +
      keys.map(function (k) {
        return "<tr><td>" + V.esc(k) + "</td><td>" + counts[k] + "</td></tr>";
      }).join("") +
      "</table></div>"
    );
  }

  var CONFIRM_PHRASE = "erase sample data";

  function buildRemoveDialog() {
    if (V.$("sample-remove")) return;
    var el = document.createElement("div");
    el.className = "dialog-backdrop";
    el.id = "sample-remove";
    el.innerHTML =
      '<div class="dialog" style="max-width:560px">' +
        "<h3>Remove sample data</h3>" +
        '<div class="note" style="margin-top:0">This runs Verity&rsquo;s <b>real erasure pipeline</b> — the same ' +
          "crypto-shredding path you&rsquo;d use for a GDPR request: preview first, typed confirm, then " +
          "<span class=\"ref\">POST /v1/admin/erasure</span> per sample subject/entity. Sample memories are purged; " +
          "the audit record of their lifecycle remains. The sample <i>keys</i> (user:jordan, group:sales, " +
          "user:sample-blind, …) stay in the key directory — keys aren&rsquo;t memories.</div>" +
        '<div id="sample-remove-preview"><div class="asof">previewing what a real erasure would delete&hellip;</div></div>' +
        '<div class="row" style="margin-top:10px"><div>' +
          '<label for="sample-remove-confirm">type <b>' + CONFIRM_PHRASE + "</b> to confirm</label>" +
          '<input type="text" id="sample-remove-confirm" autocomplete="off" spellcheck="false">' +
        "</div></div>" +
        '<div class="err" id="sample-remove-err"></div>' +
        '<div id="sample-remove-result"></div>' +
        '<div class="actions">' +
          '<button id="sample-remove-cancel">Close</button>' +
          '<button class="primary" id="sample-remove-go" disabled>Erase sample data</button>' +
        "</div>" +
      "</div>";
    document.body.appendChild(el);
    V.$("sample-remove-cancel").onclick = function () { V.dialog("sample-remove").close(); };
    V.$("sample-remove-confirm").oninput = function () {
      V.$("sample-remove-go").disabled =
        V.$("sample-remove-confirm").value.trim().toLowerCase() !== CONFIRM_PHRASE;
    };
    V.$("sample-remove-go").onclick = async function () {
      var btn = V.$("sample-remove-go");
      V.clearErr("sample-remove-err");
      btn.disabled = true;
      try {
        var erased = await eraseAll(V.tenant());
        V.$("sample-remove-result").innerHTML =
          '<div class="card" style="margin-top:10px;margin-bottom:0">' +
            V.stateChip("ok", "erased") +
            '<div style="margin-top:6px">' + countsTable(erased) + "</div>" +
            '<div class="asof" style="margin-top:4px">hard-purged in one transaction per target; one audit row ' +
              "per erasure survives (verb &lsquo;erasure&rsquo;, hashed identifiers)</div>" +
          "</div>";
        try { V.reload(); } catch (e) { /* panels refresh on next visit */ }
      } catch (e) {
        var msg = String((e && e.message) || e);
        if (/HTTP 40[45]/.test(msg)) {
          V.err("sample-remove-err", new Error(
            "this build has no erasure endpoint — fall back to POST /v1/forget per item from the panels " +
            "(that INVALIDATES — bi-temporal retire — it does not hard-erase)"));
        } else {
          V.err("sample-remove-err", e);
        }
        btn.disabled = false;
      }
    };
  }

  async function remove() {
    var tenant = V.tenant();
    if (!tenant) return;
    buildRemoveDialog();
    V.clearErr("sample-remove-err");
    V.$("sample-remove-result").innerHTML = "";
    V.$("sample-remove-confirm").value = "";
    V.$("sample-remove-go").disabled = true;
    V.$("sample-remove-preview").innerHTML = '<div class="asof">previewing what a real erasure would delete&hellip;</div>';
    V.dialog("sample-remove").open();
    try {
      var counts = await previewAll(tenant);
      V.$("sample-remove-preview").innerHTML =
        '<div class="note" style="margin:8px 0 0"><b>Dry run</b> (rolled back — the preview walks the exact ' +
          "same lineage the purge would). One preview runs per sample subject/entity, so a row matching " +
          "several targets is counted once per match — <b>the purge deletes each row exactly once</b>, and the " +
          "erased counts below are the true totals:</div>" + countsTable(counts);
    } catch (e) {
      var msg = String((e && e.message) || e);
      V.$("sample-remove-preview").innerHTML = "";
      V.err("sample-remove-err", /HTTP 40[45]/.test(msg)
        ? new Error("this build has no erasure-preview endpoint — removal falls back to POST /v1/forget " +
            "(invalidate, not erase); nothing was changed")
        : e);
    }
  }

  window.VeritySample = { seed: seed, remove: remove };
})();
