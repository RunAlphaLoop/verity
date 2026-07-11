"use strict";
/* ==========================================================================
   panel_principals.js — Screen 8 · Principals & Groups  (Later → live)
   --------------------------------------------------------------------------
   The identity/membership half of the admin-curation pair (UI-SPEC §5
   Screens 8-9). Entity aliases/precedence are OWNED ELSEWHERE (entities panel).

   Writes (all admin-token; {admin:true}):
     • POST   /v1/admin/principals — body { tenant_id, principals: [str…] };
       returns { mappings: { "<principal>": <token i32> } }. Upsert is
       idempotent per tenant: an existing principal keeps its token, a new one
       is allocated max(token)+1.
     • POST   /v1/admin/groups — body { tenant_id, group, member };
       group = "group:<name>", member = "user:<id>" | "group:<inner>".
       Returns { written:true, tokens:{…} }. The group + member tokens are
       allocated eagerly so visibility sets / tombstones can reference them.
     • DELETE /v1/admin/groups — SAME body. Returns { deleted:true, tombstones,
       revoked_principals:[…], affected_members:[…] }. Removal writes revocation
       TOMBSTONES FIRST (fail-closed) and hides the removed subtree on the VERY
       NEXT READ within the revocation window.

   HONESTY (SPEC §3): no default, no permissive affordance. Removal is never a
   bare button — it is gated behind a STRONG confirm dialog that states, before
   it fires, that tombstones are written first and the member is hidden on the
   next read (drift-window note). Group management requires ReBAC server-side;
   an unconfigured plane answers 503 and we surface that verbatim rather than
   faking success. Zero LLM calls, zero live-ReBAC calls originate here.
   ========================================================================== */
(function () {
  // Group / member string shapes the server accepts (rebac::parse_principal):
  // "group:<name>" for a group, "user:<id>" | "group:<inner>" for a member.
  var GROUP_RE = /^group:.+/;
  var MEMBER_RE = /^(user:.+|group:.+)$/;

  /* Render a { principal → token } map as a chip table. Tokens are the
     load-bearing output of an upsert — show them plainly, never invented. */
  function renderTokenMap(map) {
    var keys = Object.keys(map || {});
    if (!keys.length) return '<div class="empty">no mappings returned</div>';
    var rows = keys.map(function (p) {
      return "<tr><td>" + Verity.badge(p, "b-entity") + "</td>" +
        '<td class="num">' + Verity.badge(String(map[p]), "b-kind") + "</td></tr>";
    }).join("");
    return '<div class="tablewrap"><table><thead><tr>' +
      "<th>principal</th><th class=\"num\">int token</th>" +
      "</tr></thead><tbody>" + rows + "</tbody></table></div>";
  }

  Verity.register({
    id: "principals",
    mount: function (section) {
      var el = Verity.$("principals-mount");
      if (!el) return;

      /* -- honesty note about the ReBAC dependency + tenant sourcing -------- */
      var intro = document.createElement("div");
      intro.className = "card";
      intro.innerHTML =
        '<h2>Admin curation <span class="sub">admin-token · fail-closed</span></h2>' +
        '<div class="note"><em>No default, no permissive affordance.</em> Every action here is an ' +
          'explicit admin-token write to a real endpoint. Principal upserts are idempotent ' +
          '(an existing principal keeps its token). Group membership requires the ReBAC plane to be ' +
          'configured server-side; if it is not, the server answers <b>503</b> and that is surfaced ' +
          'faithfully — never faked as a success. Removing a member writes revocation ' +
          '<b>tombstones first</b> and hides the member on the <b>very next read</b>.</div>' +
        '<div class="note" style="margin-top:6px">All calls use the active tenant ' +
          '(<span id="prn-tenant-echo" class="note"></span>) — decode a scope handle on Scope Inspector ' +
          'or type a tenant_id above.</div>';
      el.appendChild(intro);

      /* ==================================================================== */
      /*  (A) PRINCIPALS — upsert strings → int tokens                        */
      /* ==================================================================== */
      var pcard = document.createElement("div");
      pcard.className = "card";
      pcard.innerHTML =
        '<h2>Principals <span class="sub">POST /v1/admin/principals · upsert → int tokens</span></h2>' +
        '<div class="note" style="margin-bottom:8px">Enter one principal per line (or comma/space separated). ' +
          'Strings are typically <code>user:alice@corp.example</code> or <code>group:sales</code>. ' +
          'The resulting <b>int tokens</b> are what visibility sets and scope handles reference.</div>' +
        '<div class="tight">' +
          '<label for="prn-strings">principal strings</label>' +
          '<textarea id="prn-strings" class="field" rows="3" style="width:100%" ' +
            'placeholder="user:alice@corp.example&#10;group:sales" autocomplete="off"></textarea>' +
        "</div>" +
        '<div class="actions" style="justify-content:flex-start">' +
          '<button class="primary" id="prn-upsert" ' +
            'title="POST /v1/admin/principals (admin) — idempotent upsert; existing principals keep their token.">' +
            'Upsert → tokens</button>' +
        "</div>" +
        '<div class="err" id="prn-upsert-err"></div>' +
        '<div id="prn-upsert-refreshed"></div>' +
        '<div id="prn-upsert-out"></div>';
      el.appendChild(pcard);

      /* ==================================================================== */
      /*  (B) ADD GROUP MEMBER — write a membership tuple                     */
      /* ==================================================================== */
      var acard = document.createElement("div");
      acard.className = "card";
      acard.innerHTML =
        '<h2>Add group member <span class="sub">POST /v1/admin/groups · write membership tuple</span></h2>' +
        '<div class="note" style="margin-bottom:8px">The member gains the group and all its transitive ancestor ' +
          'principals. Group + member tokens are allocated eagerly so visibility sets and tombstones can ' +
          'reference them; they are shown on success. Nested groups are allowed ' +
          '(<code>member = group:&lt;inner&gt;</code>), but a group cannot be a member of itself.</div>' +
        '<div class="row">' +
          '<div class="tight"><label for="prn-add-group">group <span class="note">(group:&lt;name&gt;)</span></label>' +
            '<input type="text" id="prn-add-group" class="field" placeholder="group:sales" autocomplete="off"></div>' +
          '<div class="tight"><label for="prn-add-member">member <span class="note">(user:&lt;id&gt; | group:&lt;inner&gt;)</span></label>' +
            '<input type="text" id="prn-add-member" class="field" placeholder="user:alice@corp.example" autocomplete="off"></div>' +
          '<div class="tight"><button class="primary" id="prn-add" ' +
            'title="POST /v1/admin/groups (admin) — writes the membership tuple.">Add member</button></div>' +
        "</div>" +
        '<div class="err" id="prn-add-err"></div>' +
        '<div id="prn-add-refreshed"></div>' +
        '<div id="prn-add-out"></div>';
      el.appendChild(acard);

      /* ==================================================================== */
      /*  (C) REMOVE GROUP MEMBER — DELETE behind a STRONG confirm            */
      /* ==================================================================== */
      var rcard = document.createElement("div");
      rcard.className = "card";
      rcard.innerHTML =
        '<h2>Remove group member <span class="sub">DELETE /v1/admin/groups · tombstones first, fail-closed</span></h2>' +
        '<div class="note" style="margin-bottom:8px;border-left:3px solid var(--red,#f85149);padding-left:10px">' +
          '<em>Revocation, not a plain edit.</em> Removal writes revocation <b>tombstones first</b> ' +
          '(fail-closed: a tombstone-write failure aborts the delete and over-hides, never under-hides), ' +
          'then deletes the tuple. The removed subtree — the user, or every transitive user of a removed ' +
          'inner group — loses this group principal <b>and all its transitive ancestors</b>, and is ' +
          '<b>hidden on the very next read</b> for the revocation window.</div>' +
        '<div class="row">' +
          '<div class="tight"><label for="prn-rm-group">group <span class="note">(group:&lt;name&gt;)</span></label>' +
            '<input type="text" id="prn-rm-group" class="field" placeholder="group:sales" autocomplete="off"></div>' +
          '<div class="tight"><label for="prn-rm-member">member <span class="note">(user:&lt;id&gt; | group:&lt;inner&gt;)</span></label>' +
            '<input type="text" id="prn-rm-member" class="field" placeholder="user:alice@corp.example" autocomplete="off"></div>' +
          '<div class="tight"><button id="prn-rm" ' +
            'title="DELETE /v1/admin/groups (admin) — opens a strong tombstone-warning confirm before firing.">' +
            'Remove member…</button></div>' +
        "</div>" +
        '<div class="err" id="prn-rm-err"></div>' +
        '<div id="prn-rm-refreshed"></div>' +
        '<div id="prn-rm-out"></div>';
      el.appendChild(rcard);

      /* -- STRONG confirm dialog for removal -------------------------------- */
      var confirmEl = document.createElement("div");
      confirmEl.className = "dialog-backdrop";
      confirmEl.id = "prn-rm-dialog";
      confirmEl.innerHTML =
        '<div class="dialog" style="max-width:640px">' +
          '<h3>Confirm membership revocation</h3>' +
          '<div class="note" id="prn-rm-summary"></div>' +
          '<div class="note" style="margin-top:10px;border-left:3px solid var(--red,#f85149);padding-left:10px">' +
            '<b>This writes revocation tombstones FIRST, then deletes the tuple.</b> ' +
            'Ordering is fail-closed: if the tombstone write fails, the delete is aborted and nothing is ' +
            'under-hidden. The removed member — and every transitive user beneath a removed inner group — ' +
            'loses this group principal and all its transitive ancestor principals.' +
          "</div>" +
          '<div class="note" style="margin-top:8px">' +
            '<em>Drift window.</em> The member is <b>hidden on the very next read</b> within the revocation ' +
            'window. Already-minted scope handles pick this up immediately — resolution subtracts the ' +
            'tombstoned tokens on every scoped read, so there is no permissive gap to wait out.' +
          "</div>" +
          '<div class="err" id="prn-rm-dlg-err"></div>' +
          '<div class="actions">' +
            '<button class="primary" id="prn-rm-go">Write tombstones &amp; remove</button>' +
            '<button id="prn-rm-cancel">Cancel</button>' +
          "</div>" +
        "</div>";
      el.appendChild(confirmEl);
      var rmDlg = Verity.dialog("prn-rm-dialog");

      /* ==================================================================== */
      /*  shared helpers                                                      */
      /* ==================================================================== */
      function activeTenant() {
        return Verity.tenant() || "";
      }
      function requireTenant(errId) {
        var t = activeTenant();
        if (!t) {
          Verity.err(errId, new Error(
            "no tenant selected — decode a scope handle on Scope Inspector or type a tenant_id in the header"));
          return "";
        }
        return t;
      }
      function parseStrings(raw) {
        return String(raw || "").split(/[\s,]+/).filter(function (s) { return s.length; });
      }
      function stamp(elId, label) {
        Verity.$(elId).innerHTML =
          '<span class="refreshed">' + Verity.esc(label) +
          " · " + Verity.esc(Verity.fmtTime(Date.now())) + "</span>";
      }

      /* -- (A) upsert flow -------------------------------------------------- */
      Verity.$("prn-upsert").onclick = async function () {
        Verity.clearErr("prn-upsert-err");
        Verity.$("prn-upsert-out").innerHTML = "";
        Verity.$("prn-upsert-refreshed").innerHTML = "";
        var tenant = requireTenant("prn-upsert-err");
        if (!tenant) return;
        var principals = parseStrings(Verity.$("prn-strings").value);
        if (!principals.length) {
          Verity.err("prn-upsert-err", new Error(
            "enter at least one principal string — no default is assumed"));
          return;
        }
        var btn = Verity.$("prn-upsert");
        btn.disabled = true;
        try {
          var res = await Verity.api("/v1/admin/principals",
            { admin: true, json: { tenant_id: tenant, principals: principals } });
          Verity.$("prn-upsert-out").innerHTML = renderTokenMap(res && res.mappings);
          stamp("prn-upsert-refreshed",
            "upserted " + principals.length + " principal" + (principals.length === 1 ? "" : "s"));
        } catch (e) {
          Verity.err("prn-upsert-err", e);
        } finally {
          btn.disabled = false;
        }
      };

      /* -- (B) add-member flow --------------------------------------------- */
      Verity.$("prn-add").onclick = async function () {
        Verity.clearErr("prn-add-err");
        Verity.$("prn-add-out").innerHTML = "";
        Verity.$("prn-add-refreshed").innerHTML = "";
        var tenant = requireTenant("prn-add-err");
        if (!tenant) return;
        var group = Verity.$("prn-add-group").value.trim();
        var member = Verity.$("prn-add-member").value.trim();
        if (!GROUP_RE.test(group)) {
          Verity.err("prn-add-err", new Error('group must be "group:<name>"'));
          return;
        }
        if (!MEMBER_RE.test(member)) {
          Verity.err("prn-add-err", new Error('member must be "user:<id>" or "group:<name>"'));
          return;
        }
        if (member === group) {
          Verity.err("prn-add-err", new Error("a group cannot be a member of itself"));
          return;
        }
        var btn = Verity.$("prn-add");
        btn.disabled = true;
        try {
          var res = await Verity.api("/v1/admin/groups",
            { admin: true, json: { tenant_id: tenant, group: group, member: member } });
          Verity.$("prn-add-out").innerHTML =
            '<div class="note" style="margin-bottom:6px">Membership tuple written. Allocated tokens ' +
              '(referenceable by visibility sets and tombstones):</div>' +
            renderTokenMap(res && res.tokens);
          stamp("prn-add-refreshed",
            "added " + Verity.esc(member) + " → " + Verity.esc(group));
        } catch (e) {
          Verity.err("prn-add-err", e);
        } finally {
          btn.disabled = false;
        }
      };

      /* -- (C) remove-member flow — behind the STRONG confirm --------------- */
      // The membership the confirm dialog acts on.
      var pendingRemove = { tenant: "", group: "", member: "" };

      Verity.$("prn-rm").onclick = function () {
        Verity.clearErr("prn-rm-err");
        Verity.$("prn-rm-out").innerHTML = "";
        Verity.$("prn-rm-refreshed").innerHTML = "";
        var tenant = requireTenant("prn-rm-err");
        if (!tenant) return;
        var group = Verity.$("prn-rm-group").value.trim();
        var member = Verity.$("prn-rm-member").value.trim();
        if (!GROUP_RE.test(group)) {
          Verity.err("prn-rm-err", new Error('group must be "group:<name>"'));
          return;
        }
        if (!MEMBER_RE.test(member)) {
          Verity.err("prn-rm-err", new Error('member must be "user:<id>" or "group:<name>"'));
          return;
        }
        pendingRemove = { tenant: tenant, group: group, member: member };
        Verity.clearErr("prn-rm-dlg-err");
        Verity.$("prn-rm-summary").innerHTML =
          "Remove <b>" + Verity.esc(member) + "</b> from <b>" + Verity.esc(group) +
          "</b> (tenant <b>" + Verity.esc(tenant) + "</b>).";
        rmDlg.open();
      };
      Verity.$("prn-rm-cancel").onclick = function () { rmDlg.close(); };
      Verity.$("prn-rm-go").onclick = async function () {
        Verity.clearErr("prn-rm-dlg-err");
        var btn = Verity.$("prn-rm-go");
        btn.disabled = true;
        try {
          var res = await Verity.api("/v1/admin/groups", {
            admin: true,
            method: "DELETE",
            json: {
              tenant_id: pendingRemove.tenant,
              group: pendingRemove.group,
              member: pendingRemove.member,
            },
          });
          rmDlg.close();
          renderRemoveResult(res);
          stamp("prn-rm-refreshed",
            "removed " + Verity.esc(pendingRemove.member) + " → " + Verity.esc(pendingRemove.group));
        } catch (e) {
          // Keep the dialog open so the error is read in the destructive context.
          Verity.err("prn-rm-dlg-err", e);
        } finally {
          btn.disabled = false;
        }
      };

      function renderRemoveResult(res) {
        res = res || {};
        var revoked = res.revoked_principals || [];
        var affected = res.affected_members || [];
        var tomb = res.tombstones;
        var revChips = revoked.length
          ? revoked.map(function (p) { return Verity.badge(p, "b-quarantined"); }).join(" ")
          : '<span class="note">none materialized — nothing to tombstone</span>';
        var affChips = affected.length
          ? affected.map(function (m) { return Verity.badge(m, "b-entity"); }).join(" ")
          : '<span class="note">none</span>';
        Verity.$("prn-rm-out").innerHTML =
          '<div class="card" style="margin-top:8px">' +
            '<h2>Revocation written <span class="sub">tombstones first, then tuple delete</span></h2>' +
            '<dl class="kv">' +
              "<dt>tombstones recorded</dt><dd>" +
                Verity.badge(String(tomb == null ? "—" : tomb), "b-kind") + "</dd>" +
              "<dt>revoked principals <span class=\"note\">(subtracted on the next read)</span></dt><dd>" +
                revChips + "</dd>" +
              "<dt>affected members</dt><dd>" + affChips + "</dd>" +
            "</dl>" +
            '<div class="note" style="margin-top:6px"><em>Hidden on the very next read.</em> ' +
              'The revoked tokens are subtracted from every scoped read for the revocation window — ' +
              'already-minted handles included.</div>' +
          "</div>";
      }

      /* -- tenant echo, kept honest with the shared state ------------------- */
      function reflectTenant(t) {
        var echo = Verity.$("prn-tenant-echo");
        if (echo) echo.textContent = t ? t : "none selected";
      }
      Verity.onTenant(reflectTenant);
      reflectTenant(Verity.tenant());
    },
  });
})();
