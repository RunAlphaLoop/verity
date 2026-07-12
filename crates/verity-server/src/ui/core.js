"use strict";
/* ============================================================================
   core.js — CORE PRIMITIVES  ·  FROZEN SIGNATURES (v2, workbench rebuild)
   ----------------------------------------------------------------------------
   Hand-rolled vanilla helpers + the panel router/mount registry. Panels code
   AGAINST these signatures and never modify this file. Everything is hung off
   the single global `Verity` namespace; the short helpers ($, esc) are also
   exposed as top-level consts for terseness inside panel scripts.

   Every v1 signature survives unchanged. v2 ADDS (all additive):
     • AUTOLOAD — a panel may register `load(section, tenant)`; the router
       runs it when the panel is shown AND a tenant is known, re-runs it when
       the tenant changes, and never runs it twice for the same tenant.
       `Verity.reload(id?)` forces a re-run. THE LAW #3: no panel greets a
       first-time operator with a cold Load button.
     • RAIL COUNTS — `Verity.setCount(navId, n)` renders a live count pill on
       a rail entry (n = 0/null clears it). Counts must come from the same
       query as the target panel — a badge computed differently is a lie.
     • GLOBAL MINT — `Verity.openMint(prefill?)` opens the top-level
       mint-a-scope-handle dialog (POST /v1/scopes, UI-ACTIONS N1) from any
       panel; `Verity.onMint(fn)` subscribes to successful mints.
     • humane builders — stateChip / entityChip / refSpan / fmtAge / timeAgo.
     • tenant persistence — the active tenant_id (not a secret) is remembered
       in localStorage so returning operators land on live data. The admin
       token stays sessionStorage-ONLY, as before.

   READ-PATH PURITY: nothing here makes an LLM or live-ReBAC call. api() is a
   thin fetch wrapper; decodeHandle() is pure client-side base64url→JSON.
   ============================================================================ */

/* -------------------------------------------------------------- $ / esc */

/** $(id) → element by id (no selector engine; ids only). */
const $ = (id) => document.getElementById(id);

/** esc(s) → HTML-attribute/text-safe string. ALWAYS wrap interpolated data. */
const esc = (s) => String(s).replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ------------------------------------------------------- admin token store */
/* Admin bearer lives in sessionStorage ONLY — never localStorage, never a
   cookie, never persisted to disk. Cleared when the tab closes. */
const ADMIN_KEY = "verity.admin";
function getAdminToken() { return sessionStorage.getItem(ADMIN_KEY) || ""; }
function setAdminToken(t) {
  if (t) sessionStorage.setItem(ADMIN_KEY, t);
  else sessionStorage.removeItem(ADMIN_KEY);
}

/* ---------------------------------------------------------- api() wrapper */
/**
 * api(path, opts?) → parsed JSON (or null on empty body).
 *
 * Thin fetch wrapper with:
 *   • inline-surfaceable errors: throws Error("<endpoint> — HTTP 4xx: <body>")
 *     or ("<endpoint> — network error: …") so a panel can pipe .message
 *     straight into Verity.err().
 *   • admin bearer: pass opts.admin === true to attach
 *     `Authorization: Bearer <sessionStorage token>` (omitted when unset →
 *     dev-mode server allows + warns; the UI reflects that honestly).
 *   • JSON body helper: pass opts.json = <obj> to send a JSON POST/GET body
 *     (sets method POST by default + content-type).
 *
 * opts is otherwise a normal fetch init (method, headers, signal, …).
 */
async function api(path, opts) {
  opts = opts || {};
  const headers = Object.assign({}, opts.headers || {});
  let body = opts.body;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  }
  if (opts.admin) {
    const tok = getAdminToken();
    if (tok) headers["Authorization"] = "Bearer " + tok;
  }
  const init = {
    method: opts.method || (body !== undefined ? "POST" : "GET"),
    headers,
  };
  if (body !== undefined) init.body = body;
  if (opts.signal) init.signal = opts.signal;

  const shown = path.split("?")[0];
  let res;
  try {
    res = await fetch(path, init);
  } catch (e) {
    throw new Error(shown + " — network error: " + e.message);
  }
  const text = await res.text();
  if (!res.ok) {
    throw new Error(shown + " — HTTP " + res.status + (text ? ": " + text.slice(0, 300) : ""));
  }
  return text ? JSON.parse(text) : null;
}

/* --------------------------------------------------- inline error helpers */
/** Verity.err(elOrId, e) — show an error in a `.err` node. */
function showErr(elOrId, e) {
  const el = typeof elOrId === "string" ? $(elOrId) : elOrId;
  if (!el) return;
  el.textContent = String((e && e.message) || e);
  el.classList.add("on");
}
/** Verity.clearErr(elOrId) — hide it again. */
function clearErr(elOrId) {
  const el = typeof elOrId === "string" ? $(elOrId) : elOrId;
  if (el) el.classList.remove("on");
}

/* ----------------------------------------------- decodeHandle (pure JS) */
function b64urlToUtf8(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
/**
 * decodeHandle(str) → the handle's signed claims object.
 * Client-side base64url→JSON of the payload segment of a `vs_…` handle.
 * The payload is signed, not secret; the server-side HMAC is what makes it
 * usable — decoding here reveals only what the holder already possesses.
 * Throws Error with a human message on a malformed handle.
 */
function decodeHandle(str) {
  const h = String(str).trim();
  if (!h.startsWith("vs_")) throw new Error('not a scope handle: expected the "vs_" prefix');
  const dot = h.indexOf(".");
  if (dot < 0) throw new Error("malformed handle: missing signature segment after the payload");
  try {
    return JSON.parse(b64urlToUtf8(h.slice(3, dot)));
  } catch (e) {
    throw new Error("payload segment did not decode as base64url JSON: " + e.message);
  }
}

/* -------------------------------------------------------- badge() helpers */
/* All return an HTML string of one or more <span class="badge …">. The
   `inferred` flag (where accepted) applies the dashed-outline encoding that
   marks a probabilistic/model-derived tag vs a deterministic provenance tag. */

const CONF_NAMES = ["public", "internal", "confidential", "restricted"];

function badge(text, cls, inferred) {
  return '<span class="badge ' + cls + (inferred ? " b-inferred" : "") + '">' + esc(text) + "</span>";
}

/** ACL-provenance badge (solid): mirrored|approximated|admin-assigned|quarantined. */
function provenanceBadge(p) {
  const name = String(p || "admin-assigned").toLowerCase();
  const known = ["mirrored", "approximated", "admin-assigned", "quarantined"];
  return badge(name, known.includes(name) ? "b-" + name : "b-admin-assigned");
}

/** Confidentiality badge from a 0-3 int or a name string. */
function confBadge(v) {
  let idx, name;
  if (typeof v === "number") { idx = v; name = CONF_NAMES[v] ?? String(v); }
  else { name = String(v).toLowerCase(); idx = CONF_NAMES.indexOf(name); }
  return badge(name, "b-conf-" + (idx >= 0 ? idx : 1));
}

/** Trust-tier badge: authoritative → solid Tier-1 chip; else dim observation chip. */
function trustBadge(t) {
  const name = String(t).toLowerCase();
  const auth = name === "authoritative" || name === "tier1" || name === "tier-1";
  return badge("trust: " + name, auth ? "b-tier" : "b-trust");
}

/** Knowledge-lifecycle status badge. */
function statusBadge(s) {
  const name = String(s).toLowerCase();
  const known = ["candidate", "eligible", "published", "quarantined", "rejected", "invalidated"];
  return badge(name, known.includes(name) ? "b-st-" + name : "b-kind");
}

/** Entity-tag badges (array → string). */
function entityBadges(tags) {
  return (tags || []).map((t) => badge(t, "b-entity")).join("");
}

/**
 * tagDerivationBadge(derivation) — the guarantee/probability legend chip.
 * "provenance" → solid green; anything else ("inferred") → dashed violet.
 */
function tagDerivationBadge(derivation) {
  const d = String(derivation || "").toLowerCase();
  return d === "provenance"
    ? badge("provenance", "b-provenance")
    : badge("inferred", "b-inferred");
}

/** Neutral kind/label chip. */
function kindBadge(k) { return badge(k, "b-kind"); }

/* ----------------------------------------------- v2 · humane builders */

/**
 * stateChip(kind, label?) — THE visible-state chip (LAW #4).
 * kind ∈ "ok"|"wait"|"attn"|"fail"|"off" (aliases: healthy|waiting|
 * needs-you|failed|none). Default labels are the plain words.
 */
function stateChip(kind, label) {
  const map = {
    ok: ["st-ok", "healthy"], healthy: ["st-ok", "healthy"],
    wait: ["st-wait", "waiting"], waiting: ["st-wait", "waiting"],
    attn: ["st-attn", "needs you"], "needs-you": ["st-attn", "needs you"],
    fail: ["st-fail", "failed"], failed: ["st-fail", "failed"],
    off: ["st-off", "—"], none: ["st-off", "—"],
  };
  const m = map[String(kind).toLowerCase()] || map.off;
  return '<span class="state ' + m[0] + '">' + esc(label != null ? label : m[1]) + "</span>";
}

/**
 * entityChip(name, source?) — a named thing, name FIRST (LAW #1/#2).
 * A missing name renders an honest "no name on record", never a blank.
 */
function entityChip(name, source) {
  return '<span class="entity-chip"><b>' +
    (name ? esc(name) : '<span style="color:var(--dim);font-weight:400">no name on record</span>') +
    "</b>" + (source ? '<span class="src">' + esc(source) + "</span>" : "") + "</span>";
}

/** refSpan(ref) — a raw ref/uuid/handle: mono, small, dim. Never primary. */
function refSpan(ref) { return '<span class="ref">' + esc(ref) + "</span>"; }

/* --------------------------------------------------------- fmt utilities */
/** fmtMs(ms) → "12 ms" / "1.20 s" / "—". */
function fmtMs(ms) {
  if (ms == null) return "—";
  return ms >= 1000 ? (ms / 1000).toFixed(2) + " s" : Math.round(ms) + " ms";
}
/** fmtTime(t) → "2026-07-11 12:00:00Z". */
function fmtTime(t) {
  try { return new Date(t).toISOString().replace("T", " ").replace(/\.\d+Z/, "Z"); }
  catch { return String(t); }
}
/** fmtAge(secs) → "3d 4h" / "2h 12m" / "45s" — compact wait-age. */
function fmtAge(secs) {
  secs = Math.max(0, Math.floor(Number(secs) || 0));
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return d + "d " + h + "h";
  if (h > 0) return h + "h " + m + "m";
  if (m > 0) return m + "m";
  return secs + "s";
}
/** timeAgo(t) → "12s ago" / "3h 4m ago" from an ISO stamp, Date, or epoch ms. */
function timeAgo(t) {
  const then = t instanceof Date ? t.getTime()
    : typeof t === "number" ? t
    : Date.parse(t);
  if (!isFinite(then)) return "—";
  return fmtAge((Date.now() - then) / 1000) + " ago";
}

/* ============================================================================
   ROUTER + MOUNT REGISTRY (+ v2 AUTOLOAD)
   ----------------------------------------------------------------------------
   Panels register ONE object at load via Verity.register({...}); the router
   owns the left rail and shows exactly one panel's <section> at a time.
   ============================================================================ */
const _panels = new Map();   // id → {id, mount, onShow, load, mounted, _loadedFor}
let _current = null;
let _navParams = null;       // one-shot params passed via show(id, params)

/**
 * Verity.register(panel)
 *   panel.id      : string, matches <section id="panel-<id>"> + [data-nav]
 *   panel.mount?  : fn(sectionEl) — called ONCE, lazily, on first show
 *   panel.onShow? : fn(sectionEl) — called every time the panel is shown
 *   panel.load?   : fn(sectionEl, tenant) — v2 AUTOLOAD: run by the router
 *                   when the panel is visible and a tenant is known; re-run
 *                   on tenant change; deduped per tenant. May return a
 *                   Promise. The panel renders its own no-tenant teach state.
 * Register at fragment load; the router wires the rail in Verity.boot().
 */
function register(panel) {
  if (!panel || !panel.id) throw new Error("Verity.register: panel needs an id");
  _panels.set(panel.id, Object.assign({ mounted: false, _loadedFor: null }, panel));
}

/** Run a panel's autoload if due (visible + tenant known + not yet loaded). */
function _maybeLoad(panel, section) {
  if (!panel || !panel.load || !section) return;
  const t = _tenant;
  if (!t || panel._loadedFor === t) return;
  panel._loadedFor = t;
  try {
    Promise.resolve(panel.load(section, t))
      .catch((e) => console.error("load " + panel.id, e));
  } catch (e) { console.error("load " + panel.id, e); }
}

/**
 * Verity.show(id, params?) — switch to a panel (idempotent; lazy-mounts).
 * v2: optional one-shot `params` readable via Verity.navParams() inside the
 * target's onShow/load (e.g. Verity.show("entities", {view:"queue"})).
 */
function show(id, params) {
  const panel = _panels.get(id);
  if (!panel) return;
  _navParams = params !== undefined ? params : null;
  document.querySelectorAll(".panel").forEach((s) => s.classList.remove("active"));
  document.querySelectorAll("#rail .navitem").forEach((n) => n.classList.remove("active"));
  const section = $("panel-" + id);
  const nav = document.querySelector('#rail .navitem[data-nav="' + id + '"]');
  if (section) section.classList.add("active");
  if (nav) nav.classList.add("active");
  if (section && !panel.mounted) {
    panel.mounted = true;
    if (panel.mount) { try { panel.mount(section); } catch (e) { console.error("mount " + id, e); } }
  }
  if (section) _maybeLoad(panel, section);
  if (section && panel.onShow) { try { panel.onShow(section); } catch (e) { console.error("onShow " + id, e); } }
  _current = id;
  if (location.hash !== "#" + id) history.replaceState(null, "", "#" + id);
}

/** Verity.navParams() — the one-shot params of the current show(), or null. */
function navParams() { return _navParams; }

/**
 * Verity.reload(id?) — force a panel's autoload to re-run (defaults to the
 * current panel). Use after a mutation that should refresh the view.
 */
function reload(id) {
  const pid = id || _current;
  const panel = _panels.get(pid);
  if (!panel) return;
  panel._loadedFor = null;
  if (pid === _current) _maybeLoad(panel, $("panel-" + pid));
}

/**
 * Verity.boot() — called ONCE at the end of the assembled script, after every
 * panel fragment has registered. Restores the remembered tenant, wires rail
 * clicks, and shows the initial panel (URL hash if live, else the FIRST
 * registered panel — the home panel registers first by assembly order).
 */
function boot() {
  // Adopt the tenant BEFORE first show so autoload fires (#3):
  // 1. `?tenant=<uuid>` deep link (what the CLI/demo print) wins;
  // 2. else the tenant remembered in localStorage from a previous visit.
  const deepLink = new URLSearchParams(location.search).get("tenant");
  if (deepLink) setTenant(deepLink.trim());
  if (!_tenant) {
    let saved = "";
    try { saved = localStorage.getItem(TENANT_KEY) || ""; } catch (e) { /* private mode */ }
    if (saved) setTenant(saved);
  }
  // FTUE §1: first-run detection is derived from server truth on EVERY load —
  // the shell + panels re-render when the directory answer lands.
  refreshTenantDir();
  document.querySelectorAll('#rail .navitem[data-nav]').forEach((nav) => {
    const id = nav.getAttribute("data-nav");
    if (nav.classList.contains("soon") || !_panels.has(id)) return;
    nav.addEventListener("click", () => show(id));
  });
  const hash = location.hash.replace(/^#/, "");
  const start = _panels.has(hash) ? hash : (_panels.keys().next().value || null);
  // `?view=` deep-links a sub-view of the starting panel (e.g.
  // /ui?tenant=…&view=queue#entities) — same one-shot params as show(id, p).
  const view = new URLSearchParams(location.search).get("view");
  if (start) show(start, view ? { view } : undefined);
}

/* ---------------------------------------------------- v2 · rail counts */
/**
 * Verity.setCount(navId, n) — live count pill on a rail entry.
 * n = 0 / null clears the pill. Counts MUST be derived from the same query
 * as the panel they badge (UI-ACTIONS N3) — never a separate estimate.
 */
function setCount(navId, n) {
  const nav = document.querySelector('#rail .navitem[data-nav="' + navId + '"]');
  if (!nav) return;
  let pill = nav.querySelector(".count-pill");
  if (n == null || Number(n) === 0) { if (pill) pill.remove(); return; }
  if (!pill) {
    pill = document.createElement("span");
    pill.className = "count-pill";
    nav.appendChild(pill);
  }
  pill.textContent = Number(n) > 99 ? "99+" : String(n);
}

/* ------------------------------------------------------------- dialog() */
/**
 * Verity.dialog(id) → { open(), close() } for a <div class="dialog-backdrop"
 * id="<id>">. Clicking the backdrop closes it. Purely presentational.
 */
function dialog(id) {
  const el = $(id);
  const close = () => el && el.classList.remove("open");
  if (el && !el._wired) {
    el._wired = true;
    el.addEventListener("click", (e) => { if (e.target === el) close(); });
  }
  return { open: () => el && el.classList.add("open"), close };
}

/* -------------------------------------------------------- tenant helper */
/* One active tenant_id, shared across panels; auto-filled from a decoded
   handle or the mint dialog and REMEMBERED in localStorage (a tenant id is
   not a secret; the admin token stays sessionStorage-only). Panels read
   Verity.tenant() and subscribe via Verity.onTenant(). */
const TENANT_KEY = "verity.tenant";
let _tenant = "";
const _tenantSubs = [];
function tenant() { return _tenant; }
function setTenant(t) {
  _tenant = t || "";
  try {
    if (_tenant) localStorage.setItem(TENANT_KEY, _tenant);
    else localStorage.removeItem(TENANT_KEY);
  } catch (e) { /* storage unavailable — session-only */ }
  _tenantSubs.forEach((f) => { try { f(_tenant); } catch (e) { console.error(e); } });
  // v2 AUTOLOAD: a newly-known tenant loads the panel on screen right away.
  if (_current) _maybeLoad(_panels.get(_current), $("panel-" + _current));
}
function onTenant(fn) { _tenantSubs.push(fn); }

/* ============================================================================
   v3 · TENANT DIRECTORY (FTUE §1) — first-run detection from SERVER TRUTH
   ----------------------------------------------------------------------------
   One shared read of GET /v1/admin/tenants, refreshed at boot and whenever the
   admin token changes. Never cached in localStorage — the directory is
   re-derived on every load so it can never be a stored lie.
     status: "unknown"      — not asked yet
             "ok"           — 200; `tenants` is the authoritative list
             "locked"       — 401; prod admin plane, token needed to list
             "unsupported"  — 404/405; older server, fall back to paste
             "error"        — network/5xx; surfaced, never treated as empty
   ============================================================================ */
const _tenantDir = { status: "unknown", tenants: [], error: "" };
const _tenantDirSubs = [];
/** Verity.tenantDir() → { status, tenants:[{tenant_id,name,created_at}], error }. */
function tenantDir() { return _tenantDir; }
/** Verity.onTenantDir(fn) — fn(dir) after every refresh. */
function onTenantDir(fn) { _tenantDirSubs.push(fn); }
function _emitTenantDir() {
  _tenantDirSubs.forEach((f) => { try { f(_tenantDir); } catch (e) { console.error(e); } });
}
/** Verity.refreshTenantDir() → Promise<dir>. Re-reads the tenant list. */
async function refreshTenantDir() {
  try {
    const res = await api("/v1/admin/tenants", { admin: true });
    _tenantDir.status = "ok";
    _tenantDir.tenants = (res && res.tenants) || [];
    _tenantDir.error = "";
  } catch (e) {
    const msg = String((e && e.message) || e);
    const m = msg.match(/HTTP (\d{3})/);
    const code = m ? m[1] : "";
    if (code === "401" || code === "403") {
      _tenantDir.status = "locked"; _tenantDir.tenants = []; _tenantDir.error = "";
    } else if (code === "404" || code === "405") {
      _tenantDir.status = "unsupported"; _tenantDir.tenants = []; _tenantDir.error = "";
    } else {
      _tenantDir.status = "error"; _tenantDir.error = msg;
    }
  }
  _emitTenantDir();
  return _tenantDir;
}
/** Verity.tenantName(id) → the space's name, or "" when unknown/unlisted. */
function tenantName(id) {
  const hit = _tenantDir.tenants.find((t) => t.tenant_id === id);
  return hit ? String(hit.name || "") : "";
}

/* ---------------------------------------- v3 · working handle (per-session) */
/* The session's working scope handle — held in sessionStorage ONLY (exactly
   like the admin token: this tab, cleared on close, never disk). Set only by
   an explicit, labeled user action (setup step 3, or the mint dialog's
   "use as working handle" button) — never silently. */
const WORK_KEY = "verity.session.handle";
const _workSubs = [];
function workingHandle() { return sessionStorage.getItem(WORK_KEY) || ""; }
function setWorkingHandle(h) {
  if (h) sessionStorage.setItem(WORK_KEY, h);
  else sessionStorage.removeItem(WORK_KEY);
  _workSubs.forEach((f) => { try { f(h || ""); } catch (e) { console.error(e); } });
}
function onWorkingHandle(fn) { _workSubs.push(fn); }

/* --------------------------------------------- v3 · sample-data labeling */
/* THE shared check (FTUE §3 step 4): every record seeded by the sample cast
   carries a source/tag starting "verity-sample". Panels call these so sample
   rows are labeled EVERYWHERE and can never masquerade as real data (or leak
   into a measurement). */
function isSample(v) {
  if (v == null) return false;
  if (Array.isArray(v)) return v.some(isSample);
  return String(v).indexOf("verity-sample") !== -1;
}
/** sampleBadge(v) → a `sample data` chip when v names a verity-sample source/tag. */
function sampleBadge(v) { return isSample(v) ? badge("sample data", "b-kind") : ""; }

/* ------------------------------------------ v3 · create-a-space dialog */
/* FTUE §3 step 1: the name field is the only input — NO uuid is ever typed
   by a human. On success the console auto-adopts the returned tenant_id and
   shows it only as dim secondary text. Admin-gated exactly like the API. */
const _tenantCreatedSubs = [];
function onTenantCreated(fn) { _tenantCreatedSubs.push(fn); }

function _buildCreateTenantDialog() {
  if ($("core-newtenant")) return;
  const el = document.createElement("div");
  el.className = "dialog-backdrop";
  el.id = "core-newtenant";
  el.innerHTML =
    '<div class="dialog" style="max-width:520px">' +
      "<h3>Name your space</h3>" +
      '<div class="note" style="margin-top:0"><b>The company that owns this memory space — self-hosting ' +
        "means that's you, and there's exactly one.</b></div>" +
      '<details class="note"><summary style="cursor:pointer">what&rsquo;s this?</summary>' +
        '<div style="margin-top:6px">&#9432; You are the <b>tenant</b>; your customers are <b>entities</b> ' +
        "&mdash; things memories are <i>about</i>, scoped inside your space. Customers never get their own " +
        "tenant.</div></details>" +
      '<div class="row" style="margin-top:12px">' +
        '<div><label for="newtenant-name">Space name</label>' +
          '<input type="text" id="newtenant-name" placeholder="Acme Logistics" autocomplete="off"></div>' +
      "</div>" +
      '<div class="err" id="newtenant-err"></div>' +
      '<div id="newtenant-result"></div>' +
      '<div class="actions">' +
        '<button id="newtenant-cancel">Close</button>' +
        '<button class="primary" id="newtenant-go">Create</button>' +
      "</div>" +
    "</div>";
  document.body.appendChild(el);
  const dlg = dialog("core-newtenant");
  $("newtenant-cancel").onclick = dlg.close;
  $("newtenant-go").onclick = async () => {
    clearErr("newtenant-err");
    const name = $("newtenant-name").value.trim();
    if (!name) { showErr("newtenant-err", new Error("give the space a name — that's the only field")); return; }
    const btn = $("newtenant-go");
    btn.disabled = true;
    try {
      const res = await api("/v1/admin/tenants", { json: { name }, admin: true });
      const id = res && res.tenant_id;
      if (!id) throw new Error("the server returned no tenant_id");
      await refreshTenantDir();
      setTenant(id);
      $("newtenant-result").innerHTML =
        '<div class="card" style="margin-top:12px;margin-bottom:0">' +
          stateChip("ok", "✓ " + name + " created") +
          '<div style="margin-top:6px">' + refSpan(id) + "</div>" +
          '<div class="asof" style="margin-top:4px">adopted as this session&rsquo;s space &mdash; every screen now loads it</div>' +
        "</div>";
      _tenantCreatedSubs.forEach((f) => { try { f({ tenant_id: id, name }); } catch (e) { console.error(e); } });
    } catch (e) {
      const msg = String((e && e.message) || e);
      showErr("newtenant-err", msg.indexOf("401") >= 0
        ? new Error("creating a space needs the admin token — set it in the session bar above (dev mode needs none)")
        : e);
    } finally {
      btn.disabled = false;
    }
  };
}
/** Verity.openCreateTenant() — the "Name your space" dialog (FTUE step 1). */
function openCreateTenant() {
  _buildCreateTenantDialog();
  clearErr("newtenant-err");
  $("newtenant-result").innerHTML = "";
  $("newtenant-name").value = "";
  dialog("core-newtenant").open();
  $("newtenant-name").focus();
}

/* -------------------------------------------------------- build hash */
function buildHash() { return document.body.getAttribute("data-build-hash") || "unknown"; }

/* ============================================================================
   v2 · GLOBAL MINT DIALOG — the console's front door (UI-ACTIONS N1)
   ----------------------------------------------------------------------------
   POST /v1/scopes is public; this dialog makes it reachable from anywhere
   (topbar button + any panel via Verity.openMint()). Fail-closed facts it
   tells the operator instead of hiding:
     • empty principals AND no subject → a handle that can SEE NOTHING —
       omission refuses; there is no permissive default here or anywhere;
     • a purpose can only LOWER the confidentiality ceiling, never raise it;
     • the server enforces a 60s TTL floor (a smaller ask is raised);
     • a fresh mint re-resolves identity server-side (unlike derive/renew).
   The minted handle is shown ONCE with a copy affordance and never stored by
   the console. Verity.onMint(fn) receives { handle, claims, response }.
   ============================================================================ */
const _mintSubs = [];
function onMint(fn) { _mintSubs.push(fn); }

function _buildMintDialog() {
  if ($("core-mint")) return;
  const el = document.createElement("div");
  el.className = "dialog-backdrop";
  el.id = "core-mint";
  el.innerHTML =
    '<div class="dialog" style="max-width:600px">' +
      "<h3>Mint a scope handle</h3>" +
      '<div class="note" style="margin-top:0">A scope handle is a signed key that decides exactly what a reader ' +
        "can see. Everything below narrows it; nothing widens it. Leave <b>who</b> empty and the handle can see " +
        "<b>nothing</b> — Verity fails closed, on purpose.</div>" +
      '<div class="row" style="margin-top:12px">' +
        '<div><label for="mint-tenant">tenant <span style="font-weight:400">(the company that owns this space — that&rsquo;s you)</span></label>' +
          '<select class="field" id="mint-tenant-pick" style="display:none;margin-bottom:6px"></select>' +
          '<input type="text" id="mint-tenant" placeholder="tenant id (uuid)" spellcheck="false">' +
          '<div class="asof" id="mint-tenant-name" style="margin-top:3px"></div></div>' +
      "</div>" +
      '<div class="row" style="margin-top:10px">' +
        '<div><label for="mint-subject">who — as a person <span style="font-weight:400">(resolved server-side when identity is live)</span></label>' +
          '<input type="text" id="mint-subject" placeholder="user:alice@corp.example" spellcheck="false"></div>' +
        '<div><label for="mint-principals">or — raw principal tokens <span style="font-weight:400">(dev mode; comma-separated)</span></label>' +
          '<input type="text" id="mint-principals" placeholder="e.g. 11, 1001" spellcheck="false"></div>' +
      "</div>" +
      '<div class="row" style="margin-top:10px">' +
        '<div><label for="mint-entities">limit to entities <span style="font-weight:400">(optional, comma-separated)</span></label>' +
          '<input type="text" id="mint-entities" placeholder="account:acme" spellcheck="false"></div>' +
        '<div class="tight" style="min-width:170px"><label for="mint-conf">confidentiality ceiling</label>' +
          '<select class="field" id="mint-conf">' +
            '<option value="public">public</option>' +
            '<option value="internal" selected>internal</option>' +
            '<option value="confidential">confidential</option>' +
            '<option value="restricted">restricted</option>' +
          "</select></div>" +
      "</div>" +
      '<div class="row" style="margin-top:10px">' +
        '<div><label for="mint-purpose">purpose <span style="font-weight:400">(optional — can only lower the ceiling; unknown purposes are refused)</span></label>' +
          '<input type="text" id="mint-purpose" list="mint-purpose-list" placeholder="e.g. support_conversation" autocomplete="off">' +
          '<datalist id="mint-purpose-list">' +
            '<option value="support_conversation"><option value="sales_negotiation">' +
            '<option value="marketing"><option value="analytics"><option value="audit">' +
          "</datalist></div>" +
        '<div class="tight" style="min-width:150px"><label for="mint-ttl">expires after (seconds)</label>' +
          '<input type="number" id="mint-ttl" value="3600" min="60" step="60">' +
        "</div>" +
      "</div>" +
      '<div class="note">The server enforces a <b>60&nbsp;s minimum</b> TTL. Suggested purposes are the shipped ' +
        "default pack; a deployment may configure others. A fresh mint <b>re-resolves identity</b> server-side — " +
        "unlike derive/renew, which reuse the old claims.</div>" +
      '<div class="err" id="mint-err"></div>' +
      '<div id="mint-result"></div>' +
      '<div class="actions">' +
        '<button id="mint-cancel">Close</button>' +
        '<button class="primary" id="mint-go">Mint handle</button>' +
      "</div>" +
    "</div>";
  document.body.appendChild(el);
  const dlg = dialog("core-mint");
  $("mint-cancel").onclick = dlg.close;
  $("mint-go").onclick = async () => {
    clearErr("mint-err");
    $("mint-result").innerHTML = "";
    const t = $("mint-tenant").value.trim();
    if (!t) { showErr("mint-err", new Error("tenant is required — paste a tenant id (uuid)")); return; }
    // Refuse a malformed id in plain language BEFORE the server's serde
    // error can (it says things like "invalid character `m` at column 26").
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(t)) {
      showErr("mint-err", new Error(
        "that doesn't look like a tenant id — it's a uuid like 019f53b8-6f10-71b2-b308-83a025f1cf67. " +
        "Find yours where the server/demo printed it, or in the tenant box at the top of this page."));
      return;
    }
    const body = { tenant_id: t, actor_azp: "console:mint" };
    const subject = $("mint-subject").value.trim();
    const principalsRaw = $("mint-principals").value.trim();
    // The two "who" fields are mutually exclusive on the server: a person is
    // RESOLVED into their keys by the identity plane; raw tokens ARE the keys.
    // Refuse the impossible combo in plain language before the server does.
    if (subject && principalsRaw) {
      showErr("mint-err", new Error(
        "Choose one way to say who: EITHER a person (Verity looks up all their keys — " +
        "needs the identity plane connected) OR raw tokens (you supply the keys yourself). " +
        "Not both — clear one field."));
      return;
    }
    if (subject) body.subject = subject;
    if (principalsRaw) {
      const toks = principalsRaw.split(",").map((s) => s.trim()).filter(Boolean).map(Number);
      if (toks.some((n) => !Number.isInteger(n))) {
        showErr("mint-err", new Error("principal tokens must be integers (comma-separated), e.g. 11, 1001"));
        return;
      }
      body.principals = toks;
    }
    const ents = $("mint-entities").value.trim();
    if (ents) body.entity_scope = ents.split(",").map((s) => s.trim()).filter(Boolean);
    body.max_confidentiality = $("mint-conf").value;
    const ttl = parseInt($("mint-ttl").value, 10);
    if (!isNaN(ttl)) body.ttl_seconds = ttl;
    const purpose = $("mint-purpose").value.trim();
    if (purpose) body.purpose = purpose;
    const btn = $("mint-go");
    btn.disabled = true;
    try {
      let res;
      try {
        res = await api("/v1/scopes", { json: body });
      } catch (e) {
        if (String(e.message).includes("subject-based scopes require ReBAC")) {
          throw new Error(
            "This server runs without the identity plane (dev mode), so it can't look up " +
            "a person's keys — mint with raw tokens instead. Your people's token numbers " +
            "are listed on People & groups.");
        }
        throw e;
      }
      const handle = res && res.scope_handle;
      if (!handle) throw new Error("mint returned no scope_handle");
      let claims = null;
      try { claims = decodeHandle(handle); } catch (e) { /* still usable */ }
      setTenant(t);
      const seesNothing = !subject && (!body.principals || !body.principals.length);
      $("mint-result").innerHTML =
        '<div class="card" style="margin-top:12px;margin-bottom:0">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            stateChip("ok", "minted") +
            (seesNothing ? stateChip("attn", "sees nothing — no principals were named") : "") +
            '<span class="asof">shown once — the console does not store handles</span>' +
          "</div>" +
          '<textarea id="mint-handle-out" readonly style="margin-top:8px;min-height:74px">' + esc(handle) + "</textarea>" +
          '<div class="actions" style="justify-content:flex-start;margin-top:8px">' +
            '<button id="mint-copy">Copy handle</button>' +
            '<button id="mint-inspect">Inspect in Scope Inspector</button>' +
            '<button id="mint-keep" title="held in sessionStorage for this tab only — cleared when the tab closes; the setup checklist and proof step run recalls through it">Keep as this tab&rsquo;s working handle</button>' +
          "</div>" +
        "</div>";
      $("mint-copy").onclick = () => {
        const ta = $("mint-handle-out");
        ta.select();
        try { navigator.clipboard.writeText(handle); } catch (e) { document.execCommand("copy"); }
        $("mint-copy").textContent = "Copied";
      };
      $("mint-inspect").onclick = () => { dlg.close(); show("scope", { handle }); };
      $("mint-keep").onclick = () => {
        setWorkingHandle(handle);
        $("mint-keep").textContent = "Kept — this tab only, cleared on close";
        $("mint-keep").disabled = true;
      };
      _mintSubs.forEach((f) => { try { f({ handle, claims, response: res }); } catch (e) { console.error(e); } });
    } catch (e) {
      // Server refusals (unknown purpose, entity-scope requirement, bad
      // subject) are the teaching moment — surfaced verbatim.
      showErr("mint-err", e);
    } finally {
      btn.disabled = false;
    }
  };
}

/* v3: the mint dialog's tenant field is picker-first when the tenant
   directory is known (FTUE §1 State B) — the uuid stays dim secondary text
   and is never something a human has to author. */
function _mintSyncTenantUi() {
  const nameEl = $("mint-tenant-name");
  if (!nameEl) return;
  const t = $("mint-tenant").value.trim();
  const dir = tenantDir();
  if (!t) { nameEl.textContent = ""; return; }
  if (dir.status === "ok") {
    const n = tenantName(t);
    nameEl.innerHTML = n
      ? "&#10003; " + esc(n)
      : '<span style="color:var(--red)">this tenant doesn&rsquo;t exist on this server — pick a real one, or set one up</span>';
  } else {
    nameEl.textContent = "";
  }
}

/**
 * Verity.openMint(prefill?) — open the global mint dialog.
 * prefill: { tenant?, subject?, principals?(string), entities?(string),
 *            purpose?, confidentiality?, ttl?, lockTenant? } — tenant
 * defaults to the active tenant; lockTenant pins the tenant field (setup
 * step 3 mints against the space just created, shown by name). Returns
 * nothing; subscribe with Verity.onMint(fn).
 */
function openMint(prefill) {
  _buildMintDialog();
  prefill = prefill || {};
  $("mint-tenant").value = prefill.tenant || _tenant || "";
  // Picker-first tenant selection when the server told us the real list.
  const pick = $("mint-tenant-pick");
  const tin = $("mint-tenant");
  const dir = tenantDir();
  const locked = !!prefill.lockTenant;
  if (pick) {
    if (dir.status === "ok" && dir.tenants.length) {
      pick.innerHTML = dir.tenants.map((t) =>
        '<option value="' + esc(t.tenant_id) + '">' + esc(t.name || "(unnamed)") + "</option>"
      ).join("") + '<option value="">paste a tenant id&hellip;</option>';
      pick.style.display = "";
      const known = dir.tenants.some((t) => t.tenant_id === tin.value.trim());
      pick.value = known ? tin.value.trim() : "";
      tin.style.display = known ? "none" : "";
      pick.onchange = () => {
        if (pick.value) { tin.value = pick.value; tin.style.display = "none"; }
        else { tin.value = ""; tin.style.display = ""; tin.focus(); }
        _mintSyncTenantUi();
      };
    } else {
      pick.style.display = "none";
      tin.style.display = "";
    }
    pick.disabled = locked;
  }
  tin.readOnly = locked;
  tin.oninput = _mintSyncTenantUi;
  _mintSyncTenantUi();
  if (locked) {
    const n = tenantName(tin.value.trim());
    $("mint-tenant-name").innerHTML =
      "locked to <b>" + esc(n || tin.value.trim()) + "</b> — the space this setup is for";
  }
  if (prefill.subject !== undefined) $("mint-subject").value = prefill.subject;
  if (prefill.principals !== undefined) $("mint-principals").value = prefill.principals;
  if (prefill.entities !== undefined) $("mint-entities").value = prefill.entities;
  if (prefill.purpose !== undefined) $("mint-purpose").value = prefill.purpose;
  if (prefill.confidentiality) $("mint-conf").value = prefill.confidentiality;
  if (prefill.ttl) $("mint-ttl").value = prefill.ttl;
  clearErr("mint-err");
  $("mint-result").innerHTML = "";
  dialog("core-mint").open();
}

/* ---------------------------------------------------------- the namespace */
const Verity = {
  // helpers
  $, esc, api, decodeHandle, fmtMs, fmtTime, fmtAge, timeAgo,
  err: showErr, clearErr,
  // admin token
  getAdminToken, setAdminToken,
  // badges + humane builders
  badge, provenanceBadge, confBadge, trustBadge, statusBadge,
  entityBadges, tagDerivationBadge, kindBadge, CONF_NAMES,
  stateChip, entityChip, refSpan,
  // router / registry
  register, show, boot, dialog, reload, navParams,
  // rail counts
  setCount,
  // global mint
  openMint, onMint,
  // shared state
  tenant, setTenant, onTenant, buildHash,
  // v3 · FTUE: tenant directory + create-space + working handle + sample label
  tenantDir, onTenantDir, refreshTenantDir, tenantName,
  openCreateTenant, onTenantCreated,
  workingHandle, setWorkingHandle, onWorkingHandle,
  isSample, sampleBadge,
};
window.Verity = Verity;
