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

   v4 ADDS (additive, docs/design/ENTITY-PICKER.md): Verity.entityDirectory
   (cached admin read of GET /v1/admin/entity-tags) + Verity.entityPicker —
   the ONE chips+typeahead component for every field that names an entity;
   the mint dialog's "limit to entities" field is its first surface.

   v5 ADDS (additive): Verity.principalPicker — the ONE sectioned chooser
   (People / Groups / Agents, always-visible filter, chips, keyboard) for
   every field that names principals, over GET /v1/admin/principals; the
   ingest panel's pick-viewers list is its first surface.

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

/* -------------------------------------------------- "show API details" pref */
/* A persisted UI preference (localStorage — it is a display choice, not a
   secret) that reveals developer plumbing hidden by default: exact endpoint
   paths, HTTP status codes, un-substituted {id} templates, repo doc paths.
   Panels mark that copy with class="api-crumb"; core.css hides it unless
   body.api-details is set. Default OFF — a first-time operator never sees a
   raw route. Applied at boot and on every change. */
const API_DETAILS_KEY = "verity.ui.apiDetails";
function apiDetails() {
  try { return localStorage.getItem(API_DETAILS_KEY) === "1"; } catch (e) { return false; }
}
function setApiDetails(on) {
  on = !!on;
  try {
    if (on) localStorage.setItem(API_DETAILS_KEY, "1");
    else localStorage.removeItem(API_DETAILS_KEY);
  } catch (e) { /* private mode — fall back to this session only */ }
  applyApiDetails();
}
function applyApiDetails() {
  if (document.body) document.body.classList.toggle("api-details", apiDetails());
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

function badge(text, cls, inferred, title) {
  return '<span class="badge ' + cls + (inferred ? " b-inferred" : "") + '"' +
    (title ? ' title="' + esc(title) + '"' : "") + '>' + esc(text) + "</span>";
}

/* Hover glosses for the four permission-provenance lanes — a bare word on a
   row explains nothing to a first-time operator (LAW: label every dimension). */
const _PROV_TITLES = {
  approximated: "who can see it was approximated from a container (like workspace membership) because the source has no per-item permission API",
  mirrored: "the source's own permission list was copied exactly",
  quarantined: "no permission mapping — held out of the index",
  "admin-assigned": "permissions were set by an admin, not copied from a source",
};

/** ACL-provenance badge (solid): mirrored|approximated|admin-assigned|quarantined. */
function provenanceBadge(p) {
  const name = String(p || "admin-assigned").toLowerCase();
  const known = ["mirrored", "approximated", "admin-assigned", "quarantined"];
  return badge("permissions: " + name,
    known.includes(name) ? "b-" + name : "b-admin-assigned",
    false, _PROV_TITLES[name]);
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
    ? badge("tag: from source", "b-provenance")
    : badge("tag: inferred", "b-inferred", false,
        "this label was inferred by Verity, not sent by the source");
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
  // Reflect the persisted "show API details" preference before first paint so
  // developer crumbs are hidden (or shown) from the very first panel.
  applyApiDetails();
  // Adopt the tenant BEFORE first show so autoload fires (#3):
  // 1. `?tenant=<uuid>` deep link (what the CLI/demo print) wins;
  // 2. else the tenant remembered in localStorage from a previous visit.
  // Only a uuid-shaped value may be adopted: templated links render literal
  // "undefined"/"{id}" garbage (?tenant=undefined), and adopting it made
  // every panel fire tenant_id=undefined and surface raw serde 400s (cold
  // reviewer, 2026-07-12). A malformed deep link is dropped with a console
  // note, never adopted, never remembered.
  const uuidish = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
  const deepLink = (new URLSearchParams(location.search).get("tenant") || "").trim();
  if (deepLink && uuidish(deepLink)) setTenant(deepLink);
  else if (deepLink) console.warn("ignoring ?tenant= deep link (not a tenant id):", deepLink);
  if (!_tenant) {
    let saved = "";
    try { saved = localStorage.getItem(TENANT_KEY) || ""; } catch (e) { /* private mode */ }
    if (saved && uuidish(saved)) setTenant(saved);
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
 * Verity.setCount(navId, n, title?) — live count pill on a rail entry.
 * n = 0 / null clears the pill. Counts MUST be derived from the same query
 * as the panel they badge (UI-ACTIONS N3) — never a separate estimate.
 * Optional `title` labels what the number counts (hover + aria-label) —
 * every number is labeled with what it counts.
 */
function setCount(navId, n, title) {
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
  if (title !== undefined && title !== null && title !== "") {
    pill.title = String(title);
    pill.setAttribute("aria-label", String(title));
  }
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
    const res = await api("/v1/admin/tenants?limit=500", { admin: true });
    _tenantDir.status = "ok";
    _tenantDir.tenants = (res && res.tenants) || [];
    // Server total (may exceed the page) — the picker discloses truncation.
    _tenantDir.total = (res && typeof res.total === "number") ? res.total : _tenantDir.tenants.length;
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

/* Off-page confirmation (FTUE §2.1): a tenant id can be REAL yet absent from
   the truncated directory page. GET /v1/admin/tenants/{id} is the definitive
   point lookup — a 200 confirms the space (and gives its name), a 404 is a
   true ghost. Memoized so the picker/wizard resolve each id once, never
   re-fetching on every synchronous re-render. Result shapes:
     { state: "confirmed", name }  ·  { state: "ghost" }  ·  { state: "error" }
   plus the transient "pending" while in flight (absent from the map). */
const _confirmedById = {};
/** Verity.confirmedTenant(id) → cached result object, or undefined if not yet resolved. */
function confirmedTenant(id) { return _confirmedById[id]; }
/** Verity.confirmTenantById(id) → Promise<result>. One-shot; re-emits the
    directory subscribers when it lands so a synchronous re-render picks it up. */
async function confirmTenantById(id) {
  if (!id) return { state: "ghost" };
  if (_confirmedById[id]) return _confirmedById[id];
  // Directory page already proves it — no fetch needed.
  if (_tenantDir.tenants.some((t) => t.tenant_id === id)) {
    _confirmedById[id] = { state: "confirmed", name: tenantName(id) };
    return _confirmedById[id];
  }
  try {
    const res = await api("/v1/admin/tenants/" + encodeURIComponent(id), { admin: true });
    _confirmedById[id] = { state: "confirmed", name: String((res && res.name) || "") };
  } catch (e) {
    const code = (String((e && e.message) || e).match(/HTTP (\d{3})/) || [])[1];
    _confirmedById[id] = code === "404" ? { state: "ghost" }
      : (code === "401" || code === "403") ? { state: "error", locked: true }
      : { state: "error" };
  }
  _emitTenantDir();
  return _confirmedById[id];
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
        '<div style="margin-top:6px">&#9432; You are the <b>space (tenant)</b>; your customers are <b>entities</b> ' +
        "&mdash; things memories are <i>about</i>, scoped inside your space. Customers never get their own " +
        "space.</div></details>" +
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
      if (!id) throw new Error("the server returned no space id");
      await refreshTenantDir();
      // Belt-and-suspenders: whatever the page ordering, the tenant the user
      // JUST created must be in the dropdown. Prepend if the refresh missed it.
      if (!_tenantDir.tenants.some((x) => x.tenant_id === id)) {
        _tenantDir.tenants.unshift({ tenant_id: id, name: name, created_at: null });
        _emitTenantDir();
      }
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
   v4 · ENTITY DIRECTORY + ENTITY PICKER (docs/design/ENTITY-PICKER.md §2–§4)
   ----------------------------------------------------------------------------
   ONE shared component for every field that names an entity. Honesty rules:
     • the picker OFFERS what exists and NEVER invents — every suggestion and
       every count comes from GET /v1/admin/entity-tags, which reads the same
       rows the enforcement predicates scan;
     • fail-closed untouched — an empty picker submits an ABSENT field, adds
       no defaults, and scope copy says "limit", never "grant";
     • value() is the ONLY submission path — callers never read the inner
       <input>; a tag reaches a payload only as an explicitly committed chip;
     • the Emptiness Law (§3) — zero entities ⇒ a limiting field collapses to
       a teaching line ("hide"); a tagging field teaches birth ("teach");
     • directory-unavailable ≠ empty — degraded lint-only free entry with an
       honest note, never the "no entities yet" line, never fabricated counts.
   Zero external requests; zero LLM/ReBAC; admin-plane read only, never on
   the recall path. All additive — no frozen signature changes.
   ============================================================================ */

const _entDirCache = new Map();      // tenant + "|" + liveOnly → {at, promise}
const _ENT_DIR_TTL = 30000;          // 30 s per-tenant cache, shared by pickers

/**
 * Verity.entityDirectory(tenantId, opts?) → Promise<directory>
 *   opts: { liveOnly=true, q, force }
 * Cached admin fetch of GET /v1/admin/entity-tags (30 s per tenant+liveOnly,
 * in-flight deduped; `q` bypasses the cache; `force` refreshes it). The
 * response is { total_distinct, truncated, tags:[{tag, chunk_count,
 * action_count, total_chunk_count, last_seen, canonical_entity, …}] }.
 */
function entityDirectory(tenantId, opts) {
  opts = opts || {};
  const liveOnly = opts.liveOnly !== false;
  const t = String(tenantId || "").trim();
  if (!t) return Promise.reject(new Error("no space selected yet"));
  const path = "/v1/admin/entity-tags?tenant_id=" + encodeURIComponent(t) +
    "&live_only=" + liveOnly + "&limit=500" +
    (opts.q ? "&q=" + encodeURIComponent(String(opts.q)) : "");
  if (opts.q) return api(path, { admin: true });
  const key = t + "|" + liveOnly;
  const hit = _entDirCache.get(key);
  if (!opts.force && hit && Date.now() - hit.at < _ENT_DIR_TTL) return hit.promise;
  const promise = api(path, { admin: true });
  _entDirCache.set(key, { at: Date.now(), promise });
  promise.catch(() => {
    const cur = _entDirCache.get(key);
    if (cur && cur.promise === promise) _entDirCache.delete(key);
  });
  return promise;
}

/* The type:name lint (§1) — a SOFT warning with explicit confirm, never a
   hard block: born-by-usage means an operator may need a shape we didn't
   predict. The server binds tags verbatim; this is a console affordance. */
const _EPK_SHAPE = /^[a-z0-9_-]+:[a-z0-9._@-]+$/;

/** The ONE tokenizer (§2.2) — unifies the comma-vs-whitespace parsing split.
    Tokenization happens at commit time, inside the component, nowhere else. */
function _epkTokens(v) {
  if (Array.isArray(v)) return v.map((s) => String(s).trim()).filter(Boolean);
  return String(v == null ? "" : v).split(/[\s,]+/).filter(Boolean);
}

/** Bounded Levenshtein for the near-miss guard (≤2 or it reports 3). */
function _epkLev(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const n = b.length;
  let prev = [], cur = [];
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    const t = prev; prev = cur; cur = t;
  }
  return prev[n];
}

/* Mode packs (§2.4) — wording + rules. Copy is contractual (ENTITY-PICKER.md);
   change it there first. */
const _EPK_MODES = {
  scope: {
    teach: (t) => "new — no memory carries this tag yet. A scope handle limited to it sees nothing until data arrives tagged " + t + ".",
    warn: "this limit includes a tag with 0 memories — reads through this handle will return nothing for it until data carries it.",
    emptyHide: "No entities yet — nothing to limit to. Entity tags appear as your data carries them (like account:acme).",
    reveal: "limit to a future entity anyway →",
  },
  tags: {
    teach: () => "new — this entity starts existing when this record lands. 0 memories carry it today.",
    emptyTeach: "No entities yet — tagging is how one is born. Type a tag like account:acme and it exists once this record lands.",
  },
  target: {
    // allowNew defaults false — inventing an entity to erase is never correct.
    refuse: (t) => t + " isn't a known entity tag — inventing an entity to target is never correct. Pick an observed tag.",
    emptyHide: "No entities yet — nothing to target. Entity tags appear as your data carries them (like account:acme).",
  },
  probe: {
    teach: () => "not a known tag — the probe will return an honest zero. Checking a boundary? That's the point. Expecting data? Check the spelling.",
    emptyTeach: "no entities yet — the brief of any entity you type will be an honest zero.",
  },
};

/**
 * Verity.entityPicker(mountEl, opts) → picker  (ENTITY-PICKER.md §2.1)
 *
 * opts:
 *   mode          "scope"|"tags"|"target"|"probe"   REQUIRED — wording pack
 *   multiple      true       false → single value (replaces on commit)
 *   allowNew      true       ("target" defaults false); false → known-only
 *   restrictTo    null       string[] closed set; outside tokens are refused
 *                            with "refusing to widen" copy; forces allowNew=false
 *   liveOnly      true       directory param (erasure passes false)
 *   placeholder   "account:acme"
 *   explainer     ""         one plain-language line under the field
 *   emptyBehavior "hide"|"teach"  REQUIRED — the Emptiness Law (§3)
 *   emptyLabel    ""         override for the collapsed/teaching line
 *   prefill       []         string[] rendered as chips on mount (no onChange)
 *   tenantId      () => Verity.tenant()   re-read on each directory fetch
 *   onChange      (values) => {}          fires on every chip add/remove
 *
 * picker.value()     → string[] — the chips, and ONLY the chips. In-progress
 *                      typed text is NEVER part of value(). THE submission path.
 * picker.set(vals)     replace chips (string[] or separated string)
 * picker.clear()
 * picker.refresh()     re-fetch the directory (cache-busting)
 * picker.collapsed() → bool — true when the Emptiness Law hid the field
 * picker.destroy()
 * Aliases: getValue()/setValue(); picker.onChange(fn) subscribes another fn.
 */
function entityPicker(mountEl, opts) {
  if (!mountEl) throw new Error("entityPicker: mount element required");
  opts = opts || {};
  const pack = _EPK_MODES[opts.mode];
  if (!pack) throw new Error('entityPicker: mode must be "scope" | "tags" | "target" | "probe"');
  if (opts.emptyBehavior !== "hide" && opts.emptyBehavior !== "teach") {
    throw new Error('entityPicker: emptyBehavior must be "hide" | "teach"');
  }
  const mode = opts.mode;
  const multiple = opts.multiple !== false;
  const restrictTo = Array.isArray(opts.restrictTo) && opts.restrictTo.length
    ? opts.restrictTo.slice() : null;
  const allowNew = restrictTo ? false
    : (opts.allowNew !== undefined ? !!opts.allowNew : mode !== "target");
  const liveOnly = opts.liveOnly !== false;
  const tenantFn = typeof opts.tenantId === "function" ? opts.tenantId : tenant;
  const changeSubs = typeof opts.onChange === "function" ? [opts.onChange] : [];

  const st = {
    chips: [],          // [{tag, isNew}] — the value, nothing else
    dir: null,          // {ok:true, data} | {ok:false, msg}
    fetched: false,
    fetching: null,
    collapsed: false,   // Emptiness Law engaged
    forcedOpen: false,  // "limit to a future entity anyway" reveal taken
    open: false,        // suggestion list visible
    hl: -1,             // highlighted row (-1 = none; Enter commits typed text)
    rows: [],           // current selectable rows
    ask: null,          // pending interposition (near-miss / lint / notice)
    queue: [],          // pasted/committed tokens awaiting the pipeline
    destroyed: false,
  };

  /* ------------------------------------------------------------- DOM */
  mountEl.classList.add("epk");
  mountEl.innerHTML = "";
  const elCollapsed = document.createElement("div");
  elCollapsed.className = "epk-collapsed";
  elCollapsed.style.display = "none";
  const elMain = document.createElement("div");
  elMain.className = "epk-main";
  elMain.innerHTML =
    '<div class="epk-box"><input type="text" class="epk-input" spellcheck="false" ' +
      'autocomplete="off" aria-autocomplete="list"></div>' +
    '<div class="epk-pop" style="display:none"></div>' +
    '<div class="epk-ask" style="display:none"></div>' +
    '<div class="epk-teach" style="display:none"></div>' +
    '<div class="epk-warn" style="display:none"></div>' +
    '<div class="epk-deg" style="display:none"></div>' +
    (opts.explainer ? '<div class="epk-explain">' + esc(opts.explainer) + "</div>" : "");
  mountEl.appendChild(elCollapsed);
  mountEl.appendChild(elMain);
  const box = elMain.querySelector(".epk-box");
  const input = elMain.querySelector(".epk-input");
  const pop = elMain.querySelector(".epk-pop");
  const elAsk = elMain.querySelector(".epk-ask");
  const elTeach = elMain.querySelector(".epk-teach");
  const elWarn = elMain.querySelector(".epk-warn");
  const elDeg = elMain.querySelector(".epk-deg");
  input.placeholder = opts.placeholder || "account:acme";

  /* ------------------------------------------------- directory access */
  function dirTags() { return st.dir && st.dir.ok ? (st.dir.data.tags || []) : []; }
  function findTag(t) { return dirTags().find((x) => x.tag === t) || null; }
  function totalDistinct() {
    return st.dir && st.dir.ok ? Number(st.dir.data.total_distinct || 0) : null;
  }
  function degraded() { return st.fetched && st.dir && !st.dir.ok; }

  function ensureDir(force) {
    if (st.fetching) return st.fetching;
    if (st.fetched && !force) return Promise.resolve(st.dir);
    const p = entityDirectory(tenantFn(), { liveOnly, force })
      .then((d) => { st.dir = { ok: true, data: d || { total_distinct: 0, tags: [] } }; })
      .catch((e) => { st.dir = { ok: false, msg: String((e && e.message) || e) }; })
      .then(() => { st.fetched = true; st.fetching = null; recompute(); return st.dir; });
    st.fetching = p;
    recompute();
    return p;
  }

  /* --------------------------------------------------- count honesty */
  function cntLabel(r) {
    const live = (r.chunk_count || 0) + (r.action_count || 0);
    if (!liveOnly) {
      const tot = (r.total_chunk_count != null ? r.total_chunk_count : (r.chunk_count || 0)) +
        (r.action_count || 0);
      return live + " live / " + tot + " total";
    }
    return live + (live === 1 ? " memory" : " memories");
  }
  function cntTitle(r) {
    return (r.chunk_count || 0) + " chunks · " + (r.action_count || 0) + " actions" +
      (r.last_seen ? " · last seen " + r.last_seen : "");
  }

  /* ------------------------------------------------------- rendering */
  function emit() {
    const v = value();
    changeSubs.forEach((f) => { try { f(v); } catch (e) { console.error(e); } });
  }

  function renderChips() {
    elMain.querySelectorAll(".epk-chip").forEach((c) => c.remove());
    st.chips.forEach((c, i) => {
      const s = document.createElement("span");
      s.className = "epk-chip" + (c.isNew ? " epk-new" : "");
      if (c.isNew) s.title = "new — 0 memories carry this tag yet";
      s.appendChild(document.createTextNode(c.tag));
      const x = document.createElement("button");
      x.type = "button";
      x.className = "epk-x";
      x.setAttribute("aria-label", "remove " + c.tag);
      x.innerHTML = "&times;";
      x.onclick = () => removeChip(i);
      s.appendChild(x);
      box.insertBefore(s, input);
    });
    renderWarn();
  }

  function renderWarn() {
    const hasNew = st.chips.some((c) => c.isNew);
    if (pack.warn && hasNew) { elWarn.textContent = pack.warn; elWarn.style.display = ""; }
    else elWarn.style.display = "none";
    if (!hasNew) elTeach.style.display = "none";
  }

  function showTeach(txt) { elTeach.textContent = txt; elTeach.style.display = ""; }

  function renderCollapsed() {
    if (opts.emptyBehavior === "hide" && !st.fetched && !st.chips.length && !st.forcedOpen) {
      // resolving emptiness — never flash an input that may then vanish
      elCollapsed.innerHTML = '<span class="asof">checking known entities&hellip;</span>';
      elCollapsed.style.display = "";
      elMain.style.display = "none";
      return;
    }
    if (st.collapsed) {
      const line = opts.emptyLabel || pack.emptyHide ||
        "No entities yet. Entity tags appear as your data carries them (like account:acme).";
      elCollapsed.textContent = line;
      if (allowNew) {
        elCollapsed.appendChild(document.createTextNode(" "));
        const a = document.createElement("a");
        a.className = "epk-reveal";
        a.textContent = pack.reveal || "add a future entity anyway →";
        a.onclick = () => { st.forcedOpen = true; recompute(); input.focus(); };
        elCollapsed.appendChild(a);
      }
      elCollapsed.style.display = "";
      elMain.style.display = "none";
    } else {
      elCollapsed.style.display = "none";
      elMain.style.display = "";
    }
  }

  function recompute() {
    if (st.dir && st.dir.ok) st.chips.forEach((c) => { c.isNew = !findTag(c.tag); });
    // The Emptiness Law applies ONLY to an honestly-empty directory — never
    // to our own fetch failure, never over committed chips.
    st.collapsed = opts.emptyBehavior === "hide" && st.fetched && st.dir && st.dir.ok &&
      totalDistinct() === 0 && !st.forcedOpen && st.chips.length === 0;
    renderCollapsed();
    if (degraded()) {
      const reason = /no space selected/.test(st.dir.msg) ? "no space selected yet" : "admin read failed";
      elDeg.textContent = "couldn't load known entities (" + reason + ") — typed tags are unchecked.";
      elDeg.title = st.dir.msg;
      elDeg.style.display = "";
    } else {
      elDeg.style.display = "none";
    }
    renderChips();
    if (st.open) renderList();
  }

  /* --------------------------------------------------- suggestion list */
  function buildRows(qtext) {
    const qq = qtext.toLowerCase();
    const base = restrictTo
      ? restrictTo.map((t) => findTag(t) || { tag: t, chunk_count: 0, action_count: 0 })
      : dirTags();
    const chipSet = new Set(st.chips.map((c) => c.tag));
    const rows = (qq ? base.filter((r) => r.tag.toLowerCase().indexOf(qq) >= 0) : base.slice())
      .filter((r) => !chipSet.has(r.tag))
      .slice(0, 200)
      .map((r) => ({ kind: "tag", r }));
    if (allowNew && qtext && !base.some((r) => r.tag === qtext) && !chipSet.has(qtext)) {
      rows.push({ kind: "new", tok: qtext });
    }
    return rows;
  }

  function rowHtml(row, i) {
    const hl = i === st.hl ? " hl" : "";
    if (row.kind === "new") {
      return '<div class="epk-row epk-newrow' + hl + '" data-i="' + i + '">' + esc(row.tok) +
        '<span class="epk-cnt">new &middot; 0 memories carry this tag yet</span></div>';
    }
    const r = row.r;
    return '<div class="epk-row' + hl + '" data-i="' + i + '" title="' + esc(cntTitle(r)) + '">' +
      esc(r.tag) +
      (r.canonical_entity ? ' <span class="epk-mg">merged</span>' : "") +
      '<span class="epk-cnt">' + esc(cntLabel(r)) + "</span></div>";
  }

  function openList() { st.open = true; renderList(); }
  function closeList() { st.open = false; st.hl = -1; pop.style.display = "none"; }

  function renderList() {
    if (!st.open || st.collapsed) return;
    if (degraded()) { pop.style.display = "none"; return; }   // free entry — no invented list
    if (!st.fetched) {
      st.rows = [];
      pop.innerHTML = '<div class="epk-ns" style="text-transform:none;letter-spacing:0">checking known entities&hellip;</div>';
      pop.style.display = "";
      return;
    }
    const qtext = input.value.trim();
    const rows = buildRows(qtext);
    if (st.hl >= rows.length) st.hl = rows.length - 1;
    let html = "";
    if (totalDistinct() === 0 && !restrictTo && !qtext) {
      const t = opts.emptyLabel || pack.emptyTeach || pack.emptyHide ||
        "No entities yet. Type a tag like account:acme.";
      html += '<div class="epk-ns epk-teachline">' + esc(t) + "</div>";
    }
    if (!qtext && rows.length) {
      // namespace hinting: the tenant's OBSERVED namespaces as group headers
      const groups = []; const seen = {};
      rows.forEach((row) => {
        const c = row.r.tag.indexOf(":");
        const ns = c > 0 ? row.r.tag.slice(0, c + 1) : "(no namespace)";
        if (!(ns in seen)) { seen[ns] = groups.length; groups.push({ ns, rows: [] }); }
        groups[seen[ns]].rows.push(row);
      });
      st.rows = [];
      let i = 0;
      groups.forEach((g) => {
        html += '<div class="epk-ns">' + esc(g.ns) + "</div>";
        g.rows.forEach((row) => { html += rowHtml(row, i); st.rows.push(row); i++; });
      });
    } else {
      st.rows = rows;
      rows.forEach((row, i) => { html += rowHtml(row, i); });
    }
    if (!html) { pop.style.display = "none"; return; }
    pop.innerHTML = html;
    pop.style.display = "";
    const hlEl = pop.querySelector(".epk-row.hl");
    if (hlEl) hlEl.scrollIntoView({ block: "nearest" });
  }

  function pickRow(i) {
    const row = st.rows[i];
    if (!row) return;
    if (row.kind === "tag") { addChip(row.r.tag, false); }
    else { input.value = ""; st.queue.push(row.tok); drain(); }
  }

  /* ------------------------------------------------ the commit pipeline */
  function addChip(tag, isNew) {
    if (!multiple) st.chips = [];
    if (!st.chips.some((c) => c.tag === tag)) {
      st.chips.push({ tag, isNew: !!isNew });
      if (isNew && pack.teach) showTeach(pack.teach(tag));
    }
    input.value = "";
    closeList();
    renderChips();
    emit();
  }

  function removeChip(i) {
    st.chips.splice(i, 1);
    recompute();
    emit();
    input.focus();
  }

  function replaceChip(oldTag, newTag) {
    const i = st.chips.findIndex((c) => c.tag === oldTag);
    if (i < 0) return;
    if (st.chips.some((c) => c.tag === newTag)) st.chips.splice(i, 1);
    else st.chips[i] = { tag: newTag, isNew: !findTag(newTag) };
    renderChips();
    emit();
  }

  /* Near-miss guard (§2.2): case-insensitive equality is a MUST-interpose;
     edit distance ≤ 2 in the same namespace is a non-blocking suggestion. */
  function ciExact(tok) {
    const lc = tok.toLowerCase();
    return dirTags().find((r) => r.tag.toLowerCase() === lc && r.tag !== tok) || null;
  }
  function editNear(tok) {
    const ci = tok.indexOf(":");
    if (ci <= 0) return null;
    const ns = tok.slice(0, ci).toLowerCase();
    const name = tok.slice(ci + 1).toLowerCase();
    let best = null, bd = 3;
    dirTags().forEach((r) => {
      const rc = r.tag.indexOf(":");
      if (rc <= 0 || r.tag === tok) return;
      if (r.tag.slice(0, rc).toLowerCase() !== ns) return;
      const d = _epkLev(r.tag.slice(rc + 1).toLowerCase(), name);
      if (d > 0 && d <= 2 && d < bd) { bd = d; best = r; }
    });
    return best;
  }

  /** Commit one token. Returns true when handled (continue the queue),
      false when an interposition is waiting on the operator. */
  function commitText(tok) {
    tok = String(tok).trim();
    if (!tok) return true;
    if (st.chips.some((c) => c.tag === tok)) { input.value = ""; return true; }
    if (restrictTo) {
      if (restrictTo.indexOf(tok) >= 0) { addChip(tok, false); return true; }
      askShow({ type: "notice", text: "refusing to widen: " + tok + " is not in the source handle's entity limit" });
      return true;
    }
    if (!st.fetched && !degraded()) {
      // directory still loading — hold the token, check it when truth lands
      st.queue.unshift(tok);
      ensureDir(false).then(() => drain());
      return false;
    }
    if (degraded()) {
      // free entry never blocks — but the format lint still teaches
      if (!_EPK_SHAPE.test(tok)) { askShow({ type: "shape", tok }); return false; }
      addChip(tok, false);
      return true;
    }
    if (findTag(tok)) { addChip(tok, false); return true; }
    const ci = ciExact(tok);
    if (ci) { askShow({ type: "near", tok, match: ci }); return false; }
    if (!allowNew) {
      const near = editNear(tok);
      askShow({
        type: "notice",
        text: pack.refuse ? pack.refuse(tok)
          : tok + " isn't a known entity tag — this field only accepts tags your data already carries.",
        match: near,
      });
      return true;
    }
    if (!_EPK_SHAPE.test(tok)) { askShow({ type: "shape", tok }); return false; }
    addChip(tok, true);
    const near = editNear(tok);
    if (near) askShow({ type: "soft", tok, match: near });
    return true;
  }

  function drain() {
    while (st.queue.length) {
      const tok = st.queue.shift();
      if (!commitText(tok)) return;
    }
    if (st.open) renderList();
  }

  /* -------------------------------------------- interposition prompts */
  function askShow(a) {
    st.ask = a;
    renderAsk();
    if (a.type === "near" || a.type === "shape") closeList();
  }
  function askClear(refocus) {
    st.ask = null;
    renderAsk();
    if (refocus) input.focus();
  }
  function renderAsk() {
    if (!st.ask) { elAsk.style.display = "none"; elAsk.innerHTML = ""; return; }
    const a = st.ask;
    let html = "";
    const acts = [];
    if (a.type === "near") {
      html = "did you mean <code>" + esc(a.match.tag) + "</code> (" + esc(cntLabel(a.match)) +
        ")? Matching is exact — <code>" + esc(a.tok) + "</code> matches nothing.";
      acts.push({ label: "use " + a.match.tag, cb: () => { askClear(true); addChip(a.match.tag, false); drain(); } });
      if (allowNew) {
        acts.push({
          label: "add " + a.tok + " as typed", cb: () => {
            askClear(true);
            if (!_EPK_SHAPE.test(a.tok)) askShow({ type: "shape", tok: a.tok });
            else { addChip(a.tok, true); drain(); }
          },
        });
      }
      acts.push({ label: "cancel", cb: () => { st.queue = []; askClear(true); } });
    } else if (a.type === "shape") {
      html = "<code>" + esc(a.tok) + "</code> doesn't look like <code>type:name</code> — entity tags " +
        "are lowercase like <code>account:acme</code>. Add anyway?";
      acts.push({ label: "add anyway", cb: () => { askClear(true); addChip(a.tok, degraded() ? false : true); drain(); } });
      acts.push({ label: "cancel", cb: () => { st.queue = []; askClear(true); } });
    } else if (a.type === "soft") {
      html = "<code>" + esc(a.tok) + "</code> added — similar to known <code>" + esc(a.match.tag) +
        "</code> (" + esc(cntLabel(a.match)) + "). Matching is exact.";
      acts.push({ label: "replace with " + a.match.tag, cb: () => { replaceChip(a.tok, a.match.tag); askClear(true); } });
      acts.push({ label: "keep " + a.tok, cb: () => askClear(true) });
    } else { // notice
      html = esc(a.text);
      if (a.match) {
        html += " Did you mean <code>" + esc(a.match.tag) + "</code> (" + esc(cntLabel(a.match)) + ")?";
        acts.push({ label: "use " + a.match.tag, cb: () => { askClear(true); addChip(a.match.tag, false); drain(); } });
      }
      acts.push({ label: "ok", cb: () => askClear(true) });
    }
    elAsk.innerHTML = html + '<div class="epk-ask-actions"></div>';
    const bar = elAsk.querySelector(".epk-ask-actions");
    acts.forEach((x) => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = x.label;
      b.onclick = x.cb;
      bar.appendChild(b);
    });
    elAsk.style.display = "";
  }

  /* ------------------------------------------------------- wiring */
  function commitTyped() {
    const toks = _epkTokens(input.value);
    if (!toks.length) return;
    input.value = "";
    st.queue = st.queue.concat(toks);
    drain();
  }

  input.addEventListener("focus", () => { ensureDir(false); openList(); });
  input.addEventListener("input", () => {
    if (st.ask && (st.ask.type === "soft" || st.ask.type === "notice")) askClear(false);
    st.hl = -1;
    if (!st.open) st.open = true;
    renderList();
  });
  input.addEventListener("blur", () => {
    setTimeout(() => {
      if (!st.destroyed && document.activeElement !== input) closeList();
    }, 150);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (!st.open) openList();
      if (st.rows.length) { st.hl = Math.min(st.hl + 1, st.rows.length - 1); renderList(); }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (st.rows.length) { st.hl = Math.max(st.hl - 1, -1); renderList(); }
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (st.open && st.hl >= 0 && st.rows[st.hl]) pickRow(st.hl);
      else commitTyped();
    } else if (e.key === "," || e.key === " ") {
      if (input.value.trim()) { e.preventDefault(); commitTyped(); }
      else if (e.key === ",") e.preventDefault();
    } else if (e.key === "Escape") {
      if (st.open) { e.preventDefault(); e.stopPropagation(); closeList(); }
    } else if (e.key === "Backspace") {
      if (!input.value && st.chips.length) removeChip(st.chips.length - 1);
    } else if (e.key === "Tab") {
      closeList(); // leaves the field without committing partial text
    }
  });
  input.addEventListener("paste", (e) => {
    let txt = "";
    try { txt = (e.clipboardData || window.clipboardData).getData("text"); } catch (err) { /* no access */ }
    if (!txt || !/[\s,]/.test(txt)) return; // single token: type-through
    e.preventDefault();
    st.queue = st.queue.concat(_epkTokens(input.value)).concat(_epkTokens(txt));
    input.value = "";
    drain();
  });
  box.addEventListener("mousedown", (e) => {
    if (e.target === box) { e.preventDefault(); input.focus(); if (!st.open) openList(); }
  });
  pop.addEventListener("mousedown", (e) => {
    e.preventDefault(); // keep focus in the input
    const rowEl = e.target.closest(".epk-row");
    if (rowEl) pickRow(parseInt(rowEl.getAttribute("data-i"), 10));
  });

  /* -------------------------------------------------------- public API */
  function value() { return st.chips.map((c) => c.tag); }
  function set(values) {
    const toks = _epkTokens(values);
    const uniq = toks.filter((t, i) => toks.indexOf(t) === i);
    st.chips = (multiple ? uniq : uniq.slice(0, 1)).map((t) => ({
      tag: t,
      isNew: st.dir && st.dir.ok ? !findTag(t) : false,
    }));
    st.queue = [];
    st.ask = null;
    renderAsk();
    input.value = "";
    recompute();
    emit();
  }
  function clear() { set([]); }
  function refresh() { st.fetched = false; return ensureDir(true); }
  function destroy() {
    st.destroyed = true;
    mountEl.innerHTML = "";
    mountEl.classList.remove("epk");
  }

  /* ----------------------------------------------------------- mount */
  if (Array.isArray(opts.prefill) && opts.prefill.length) {
    st.chips = opts.prefill.map((t) => String(t).trim()).filter(Boolean)
      .filter((t, i, a) => a.indexOf(t) === i)
      .slice(0, multiple ? Infinity : 1)
      .map((t) => ({ tag: t, isNew: false }));
  }
  recompute();
  if (opts.emptyBehavior === "hide") {
    // Emptiness needs total_distinct before first paint (§2.2): hide-surfaces
    // mount at dialog-open, so this is the one cheap admin GET per open —
    // deduped with any caller-side Verity.entityDirectory pre-warm.
    ensureDir(false);
  }

  const pub = {
    value, set, clear, refresh, destroy,
    collapsed: () => st.collapsed,
    getValue: value, setValue: set,
    onChange: (fn) => { if (typeof fn === "function") changeSubs.push(fn); },
    focus: () => input.focus(),
  };
  return pub;
}

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

/* The mint dialog's entity limit is an entityPicker (ENTITY-PICKER.md §5.4,
   the founder's screenshot field): chips are the ONLY submitted values. */
let _mintEntPicker = null;

function _buildMintDialog() {
  if ($("core-mint")) return;
  const el = document.createElement("div");
  el.className = "dialog-backdrop";
  el.id = "core-mint";
  el.innerHTML =
    '<div class="dialog" style="max-width:600px">' +
      "<h3>Mint a scope handle</h3>" +
      '<div class="note" style="margin-top:0">A scope handle is a signed pass that decides exactly what a reader ' +
        "can see. Everything below narrows it; nothing widens it. Leave <b>who</b> empty and the handle can see " +
        "<b>nothing</b> — Verity fails closed, on purpose.</div>" +
      '<div class="row" style="margin-top:12px">' +
        '<div><label for="mint-tenant">space <span style="font-weight:400">(the company that owns this space — that&rsquo;s you)</span></label>' +
          '<select class="field" id="mint-tenant-pick" style="display:none;margin-bottom:6px"></select>' +
          '<input type="text" id="mint-tenant" placeholder="space id (uuid)" spellcheck="false">' +
          '<div class="asof" id="mint-tenant-name" style="margin-top:3px"></div></div>' +
      "</div>" +
      '<div class="row" style="margin-top:10px">' +
        '<div><label for="mint-subject">who — as a person <span style="font-weight:400">(resolved server-side when identity is live)</span></label>' +
          '<input type="text" id="mint-subject" placeholder="user:alice@corp.example" spellcheck="false"></div>' +
        '<div><label for="mint-principals">or — raw key (principal) tokens <span style="font-weight:400">(dev mode; comma-separated)</span></label>' +
          '<input type="text" id="mint-principals" placeholder="e.g. 11, 1001" spellcheck="false"></div>' +
      "</div>" +
      '<div class="row" style="margin-top:10px">' +
        '<div><label>limit to entities <span style="font-weight:400">(optional)</span></label>' +
          '<div id="mint-entities"></div></div>' +
        '<div class="tight" style="min-width:170px"><label for="mint-conf">confidentiality ceiling <span style="font-weight:400">(the highest confidentiality this handle may ever see)</span></label>' +
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
        '<button class="primary" id="mint-go">Mint a scope handle</button>' +
      "</div>" +
    "</div>";
  document.body.appendChild(el);
  // scope mode + Emptiness Law "hide": at zero entities this collapses to a
  // teaching line (nothing to limit to) — day-zero operators never see a
  // limiter for a tenant with nothing to limit. Empty picker ⇒ ABSENT field.
  _mintEntPicker = entityPicker($("mint-entities"), {
    mode: "scope",
    multiple: true,
    allowNew: true,
    emptyBehavior: "hide",
    placeholder: "account:acme",
    explainer: "only memories tagged with these entities can come back through this handle. Empty = no entity limit.",
    tenantId: () => {
      const f = $("mint-tenant");
      return (f && f.value.trim()) || _tenant;
    },
  });
  const dlg = dialog("core-mint");
  $("mint-cancel").onclick = dlg.close;
  $("mint-go").onclick = async () => {
    clearErr("mint-err");
    $("mint-result").innerHTML = "";
    const t = $("mint-tenant").value.trim();
    if (!t) { showErr("mint-err", new Error("space is required — paste a space id (uuid)")); return; }
    // Refuse a malformed id in plain language BEFORE the server's serde
    // error can (it says things like "invalid character `m` at column 26").
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(t)) {
      showErr("mint-err", new Error(
        "that doesn't look like a space id — it's a uuid like 019f53b8-6f10-71b2-b308-83a025f1cf67. " +
        "Find yours where the server/demo printed it, or in the space box at the top of this page."));
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
        "needs the permissions engine connected (ReBAC — set VERITY_SPICEDB_URL)) OR raw tokens " +
        "(you supply the keys yourself). Not both — clear one field."));
      return;
    }
    if (subject) body.subject = subject;
    if (principalsRaw) {
      const toks = principalsRaw.split(",").map((s) => s.trim()).filter(Boolean).map(Number);
      if (toks.some((n) => !Number.isInteger(n))) {
        showErr("mint-err", new Error("key tokens must be integers (comma-separated), e.g. 11, 1001"));
        return;
      }
      body.principals = toks;
    }
    // Chips are the only submitted values — the picker's value() is the ONE
    // path into entity_scope; empty ⇒ the field is omitted (fail-closed shape
    // unchanged: no limit means UNBOUND, and omission elsewhere still refuses).
    const ents = _mintEntPicker ? _mintEntPicker.value() : [];
    if (ents.length) body.entity_scope = ents;
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
      if (!handle) throw new Error("mint returned no scope handle");
      let claims = null;
      try { claims = decodeHandle(handle); } catch (e) { /* still usable */ }
      setTenant(t);
      const seesNothing = !subject && (!body.principals || !body.principals.length);
      $("mint-result").innerHTML =
        '<div class="card" style="margin-top:12px;margin-bottom:0">' +
          '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
            stateChip("ok", "minted") +
            (seesNothing ? stateChip("attn", "sees nothing — no keys were named") : "") +
            '<span class="asof">shown once — the console does not store handles</span>' +
          "</div>" +
          '<textarea id="mint-handle-out" readonly style="margin-top:8px;min-height:74px">' + esc(handle) + "</textarea>" +
          '<div class="actions" style="justify-content:flex-start;margin-top:8px">' +
            '<button id="mint-copy">Copy handle</button>' +
            '<button id="mint-inspect">Inspect in Scope Inspector</button>' +
            '<button id="mint-keep" title="held in sessionStorage for this tab only — cleared when the tab closes; the setup checklist and proof step run recalls through it">Keep as this tab&rsquo;s scope handle</button>' +
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
    if (n) {
      nameEl.innerHTML = "&#10003; " + esc(n);
    } else {
      // Off the (possibly truncated) directory page: resolve DEFINITIVELY via
      // the point lookup instead of a page-arithmetic guess. Memoized; kick a
      // re-check of this field when the async confirm lands.
      const c = confirmedTenant(t);
      if (!c) {
        confirmTenantById(t).then(() => { if ($("mint-tenant") && $("mint-tenant").value.trim() === t) _mintSyncTenantUi(); });
        nameEl.innerHTML = '<span style="color:var(--dim)">confirming this space by its id&hellip;</span>';
      } else if (c.state === "confirmed") {
        nameEl.innerHTML = "&#10003; " + esc(c.name || "(unnamed)") + ' <span style="color:var(--dim)">(confirmed by id)</span>';
      } else if (c.state === "ghost") {
        nameEl.innerHTML = '<span style="color:var(--red)">this space doesn&rsquo;t exist on this server — pick a real one, or set one up</span>';
      } else {
        nameEl.innerHTML = '<span style="color:var(--dim)">couldn&rsquo;t confirm this space by its id just now</span>';
      }
    }
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
      ).join("") + '<option value="">paste a space id&hellip;</option>';
      pick.style.display = "";
      const known = dir.tenants.some((t) => t.tenant_id === tin.value.trim());
      pick.value = known ? tin.value.trim() : "";
      tin.style.display = known ? "none" : "";
      pick.onchange = () => {
        if (pick.value) { tin.value = pick.value; tin.style.display = "none"; }
        else { tin.value = ""; tin.style.display = ""; tin.focus(); }
        _mintSyncTenantUi();
        // the entity directory is per-tenant — re-resolve the picker's
        // suggestions + Emptiness Law for the newly chosen space
        if (_mintEntPicker) _mintEntPicker.refresh();
      };
    } else {
      pick.style.display = "none";
      tin.style.display = "";
    }
    pick.disabled = locked;
  }
  tin.readOnly = locked;
  tin.oninput = _mintSyncTenantUi;
  tin.onchange = () => { if (_mintEntPicker) _mintEntPicker.refresh(); };
  _mintSyncTenantUi();
  if (locked) {
    const n = tenantName(tin.value.trim());
    $("mint-tenant-name").innerHTML =
      "locked to <b>" + esc(n || tin.value.trim()) + "</b> — the space this setup is for";
  }
  if (prefill.subject !== undefined) $("mint-subject").value = prefill.subject;
  if (prefill.principals !== undefined) $("mint-principals").value = prefill.principals;
  if (_mintEntPicker) {
    // prefill.entities keeps its frozen openMint shape (string) — set()
    // tokenizes through the component's ONE pipeline; string[] also accepted.
    _mintEntPicker.set(prefill.entities !== undefined ? prefill.entities : []);
    // §2.2: emptiness needs total_distinct before first paint — one cheap
    // admin GET at dialog-open (deduped/cached with every other picker).
    _mintEntPicker.refresh();
  }
  if (prefill.purpose !== undefined) $("mint-purpose").value = prefill.purpose;
  if (prefill.confidentiality) $("mint-conf").value = prefill.confidentiality;
  if (prefill.ttl) $("mint-ttl").value = prefill.ttl;
  clearErr("mint-err");
  $("mint-result").innerHTML = "";
  dialog("core-mint").open();
}

/* ============================================================================
   v5 · PRINCIPAL PICKER — the ONE chooser for fields that name principals
   ----------------------------------------------------------------------------
   Sectioned (People / Groups / Agents / Other), alphabetized, filterable
   checkbox directory over GET /v1/admin/principals — the same admin read the
   ingest panel has always made (same path + response shape:
   { principals:[{principal, token}], next_after_token }). Selected
   principals render as removable chips (the entityPicker chip look) above
   the list; value() — the chips, and ONLY the chips — is THE submission
   path. Honesty + fail-closed rules unchanged:
     • selection is explicit — never preselected, never defaulted; the
       caller's empty-selection refusal at submit stays exactly where it is;
     • an empty directory renders the teach-state (go create people), never
       an invented list; 401 renders honestly (admin read, no permissive
       fallback); a failed read says "failed" — none of these are "empty";
     • typed text is a FILTER, never a value — there is no free-entry path
       through this component (raw dev-mode tokens stay a caller concern).
   Zero LLM/ReBAC calls; admin-plane read only, never on the recall path.
   All additive — no frozen signature changes; reuses the .epk-* chip/box/
   row/section classes + the empty-teach block from core.css (no new CSS).
   ============================================================================ */

const _PPK_SECTIONS = [
  ["user", "People"],
  ["group", "Groups"],
  ["agent", "Agents"],
  ["other", "Other"],
];
/** Kind from the principal string prefix — user:/group:/agent:, else "other". */
function _ppkKind(principal) {
  const s = String(principal || "");
  const i = s.indexOf(":");
  const k = i > 0 ? s.slice(0, i) : "";
  return k === "user" || k === "group" || k === "agent" ? k : "other";
}
/** "user:alice@corp.example" → "alice@corp.example" (name-first, LAW #1). */
function _ppkName(principal) {
  const s = String(principal || "");
  const i = s.indexOf(":");
  return i < 0 ? s : s.slice(i + 1);
}

/**
 * Verity.principalPicker(mountEl, opts) → picker
 *
 * opts (all optional):
 *   tenantId        () => Verity.tenant() — re-read by load()/refresh()
 *   onChange        (selected) => {} — [{principal, token}] on every change
 *   onError         (e) => {} — a FAILED directory read (never fired for
 *                   unauth/empty — those render honestly in place)
 *   onOpenDirectory () => Verity.show("principals") — the teach-state button
 *   placeholder     filter-box placeholder
 *   emptyTitle      "No people or groups on record yet"
 *   emptyBody       teach-state body — caller-authored trusted HTML
 *   emptyAction     "Open People & groups" (the teach-state button label)
 *   unauthNote      401 explainer — caller-authored trusted HTML
 *   partialNote     shown when next_after_token was non-null
 *   maxHeight       list scroll cap, default "190px"
 *
 * picker.value()      → [{principal, token}] — the chips, and ONLY the
 *                       chips. In-progress filter text is NEVER part of
 *                       value(). THE submission path.
 * picker.tokens()     → number[] ascending (the POST /v1/scopes shape)
 * picker.principals() → string[] (named chips only)
 * picker.set(items)     replace selection ([{principal,token}] or tokens)
 * picker.clear()
 * picker.load(tenant?)→ Promise — (re)fetch the directory and render
 * picker.refresh()    → re-fetch for the last-loaded tenant
 * picker.state()      → "idle"|"loading"|"ok"|"empty"|"unauth"|"fail"
 * picker.focus() / picker.destroy(); picker.onChange(fn) subscribes.
 *
 * Keyboard (from the always-visible filter box): ↓/↑ move the highlight,
 * Enter toggles the highlighted row, Backspace on an empty filter removes
 * the last chip, Escape clears the filter.
 */
function principalPicker(mountEl, opts) {
  if (!mountEl) throw new Error("principalPicker: mount element required");
  opts = opts || {};
  const tenantFn = typeof opts.tenantId === "function" ? opts.tenantId : tenant;
  const changeSubs = typeof opts.onChange === "function" ? [opts.onChange] : [];
  const openDirFn = typeof opts.onOpenDirectory === "function"
    ? opts.onOpenDirectory : () => show("principals");

  const st = {
    dir: [],            // [{principal, token}] straight from the server
    state: "idle",      // idle | loading | ok | empty | unauth | fail
    error: "",
    partial: false,     // next_after_token was non-null (directory larger)
    checkedAt: 0,
    sel: [],            // [{principal, token}] — the value, nothing else
    hl: -1,             // highlighted row (-1 = none)
    rows: [],           // currently visible rows, keyboard order
    lastTenant: "",
    loadSeq: 0,         // stale-response guard across tenant switches
    destroyed: false,
  };

  /* ------------------------------------------------------------- DOM */
  mountEl.classList.add("epk");
  mountEl.innerHTML = "";
  const box = document.createElement("div");
  box.className = "epk-box";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "epk-input";
  input.spellcheck = false;
  input.setAttribute("autocomplete", "off");
  input.placeholder = opts.placeholder || "filter names — matches name or id";
  box.appendChild(input);
  const list = document.createElement("div");
  list.style.cssText = "margin-top:6px;max-height:" + (opts.maxHeight || "190px") +
    ";overflow:auto;border:1px solid var(--border);border-radius:var(--r-sm);padding:6px 8px";
  const foot = document.createElement("div");
  foot.className = "asof";
  foot.style.cssText = "display:none;margin-top:4px";
  mountEl.appendChild(box);
  mountEl.appendChild(list);
  mountEl.appendChild(foot);

  /* ----------------------------------------------------------- value */
  function value() { return st.sel.map((p) => ({ principal: p.principal, token: p.token })); }
  function isSel(tok) { return st.sel.some((p) => String(p.token) === String(tok)); }
  function emit() {
    const v = value();
    changeSubs.forEach((f) => { try { f(v); } catch (e) { console.error(e); } });
  }
  function setSelected(row, on) {
    if (on) {
      if (!isSel(row.token)) st.sel.push({ principal: String(row.principal || ""), token: row.token });
    } else {
      st.sel = st.sel.filter((p) => String(p.token) !== String(row.token));
    }
    renderChips();
    renderList(true);
    emit();
  }

  /* ------------------------------------------------------------ chips */
  function chipLabel(p) { return p.principal ? _ppkName(p.principal) : "token " + p.token; }
  function renderChips() {
    box.querySelectorAll(".epk-chip").forEach((c) => c.remove());
    st.sel.forEach((p, i) => {
      const s = document.createElement("span");
      s.className = "epk-chip";
      s.title = (p.principal ? p.principal + " · " : "") + "token " + p.token;
      s.appendChild(document.createTextNode(chipLabel(p)));
      const x = document.createElement("button");
      x.type = "button";
      x.className = "epk-x";
      x.setAttribute("aria-label", "remove " + chipLabel(p));
      x.innerHTML = "&times;";
      x.onclick = () => {
        st.sel.splice(i, 1);
        renderChips();
        renderList(true);
        emit();
        input.focus();
      };
      s.appendChild(x);
      box.insertBefore(s, input);
    });
  }

  /* ------------------------------------------------------------- list */
  function renderList(preserveScroll) {
    if (st.state !== "ok") return;
    const keep = preserveScroll ? list.scrollTop : 0;
    const q = input.value.trim().toLowerCase();
    const groups = _PPK_SECTIONS.map((s) => ({ kind: s[0], label: s[1], all: 0, rows: [] }));
    const byKind = {};
    groups.forEach((g) => { byKind[g.kind] = g; });
    st.dir.forEach((r) => {
      const g = byKind[_ppkKind(r.principal)];
      g.all++;
      // the filter matches the whole principal string — which contains the name
      if (!q || String(r.principal).toLowerCase().indexOf(q) >= 0) g.rows.push(r);
    });
    groups.forEach((g) => g.rows.sort((a, b) => {
      const an = _ppkName(a.principal).toLowerCase();
      const bn = _ppkName(b.principal).toLowerCase();
      if (an !== bn) return an < bn ? -1 : 1;
      return a.principal < b.principal ? -1 : a.principal > b.principal ? 1 : 0;
    }));
    const total = groups.reduce((n, g) => n + g.rows.length, 0);
    if (st.hl >= total) st.hl = total - 1;
    st.rows = [];
    let html = "";
    groups.forEach((g) => {
      if (!g.rows.length) return;
      html += '<div class="epk-ns">' + esc(g.label) +
        " (" + (q ? g.rows.length + " of " + g.all : g.all) + ")</div>";
      g.rows.forEach((r) => {
        const i = st.rows.length;
        st.rows.push(r);
        html += '<label class="epk-row' + (i === st.hl ? " hl" : "") + '">' +
          '<input type="checkbox" tabindex="-1" style="accent-color:var(--accent)" data-i="' + i + '"' +
            (isSel(r.token) ? " checked" : "") + ">" +
          '<b style="font-family:var(--sans);color:var(--text)">' + esc(_ppkName(r.principal)) + "</b>" +
          '<span class="epk-cnt"><span class="ref">' + esc(String(r.principal)) +
            " · token " + esc(String(r.token)) + "</span></span>" +
        "</label>";
      });
    });
    if (!st.rows.length) {
      html = '<div class="epk-ns epk-teachline">no names match &ldquo;' + esc(q) +
        "&rdquo; &mdash; " + st.dir.length + " on record</div>";
    }
    list.innerHTML = html;
    if (preserveScroll) list.scrollTop = keep;
    const hlEl = list.querySelector(".epk-row.hl");
    if (hlEl) hlEl.scrollIntoView({ block: "nearest" });
  }

  function render() {
    renderChips();
    list.removeAttribute("title");
    foot.style.display = "none";
    if (st.state === "ok") {
      renderList();
      foot.innerHTML = "directory checked " + new Date(st.checkedAt).toTimeString().slice(0, 8) +
        (st.partial
          ? " &middot; " + esc(opts.partialNote ||
              "showing the first 1000 names — the directory is larger; narrow with the filter.")
          : "");
      foot.style.display = "block";
      return;
    }
    st.rows = [];
    st.hl = -1;
    if (st.state === "unauth") {
      list.innerHTML =
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          stateChip("attn", "admin token required") +
          '<span style="color:var(--dim);font-size:var(--fs-sm)">' +
            (opts.unauthNote ||
              "Listing names is an admin read. Paste an admin token in the session bar to see them. There is no permissive fallback.") +
          "</span></div>";
    } else if (st.state === "fail") {
      list.innerHTML = stateChip("fail", "directory read failed");
      if (st.error) list.title = st.error;
    } else if (st.state === "empty") {
      list.innerHTML =
        '<div class="empty-teach sp-a" style="margin:2px 0">' +
          '<div class="et-title">' + esc(opts.emptyTitle || "No people or groups on record yet") + "</div>" +
          '<div class="et-body">' + (opts.emptyBody ||
            "This space&rsquo;s directory is empty &mdash; an empty list is an honest answer, not an error. " +
            "Create people and groups in <b>People &amp; groups</b>.") + "</div>" +
          '<div class="et-actions"><button type="button">' +
            esc(opts.emptyAction || "Open People & groups") + "</button></div>" +
        "</div>";
      const b = list.querySelector(".et-actions button");
      if (b) b.onclick = () => openDirFn();
    } else if (st.state === "loading") {
      list.innerHTML = stateChip("wait", "loading names…");
    } else { // idle — nothing asked for yet; never fake a spinner
      list.innerHTML = '<span class="asof">directory not loaded yet — it loads once a space is known</span>';
    }
  }

  /* -------------------------------------------------------- directory */
  function load(t) {
    const tn = String(t == null ? (tenantFn() || "") : t).trim();
    st.lastTenant = tn;
    const seq = ++st.loadSeq;
    if (!tn) {
      st.state = "idle";
      st.dir = [];
      render();
      return Promise.resolve(null);
    }
    st.state = "loading";
    st.error = "";
    render();
    return api("/v1/admin/principals?tenant_id=" + encodeURIComponent(tn) + "&limit=1000", { admin: true })
      .then((res) => {
        if (st.destroyed || seq !== st.loadSeq) return null;
        st.dir = (res && res.principals) || [];
        st.partial = !!(res && res.next_after_token != null);
        st.state = st.dir.length ? "ok" : "empty";
        st.checkedAt = Date.now();
        st.hl = -1;
        // a token-only chip (set() before the directory landed) earns its name
        st.sel.forEach((p) => {
          if (!p.principal) {
            const hit = st.dir.find((d) => String(d.token) === String(p.token));
            if (hit) p.principal = String(hit.principal);
          }
        });
        render();
        return res;
      })
      .catch((e) => {
        if (st.destroyed || seq !== st.loadSeq) return null;
        st.error = String((e && e.message) || e);
        st.state = /HTTP 401\b/.test(st.error) ? "unauth" : "fail";
        render();
        if (st.state === "fail" && typeof opts.onError === "function") {
          try { opts.onError(e); } catch (err) { console.error(err); }
        }
        return null;
      });
  }

  /* ------------------------------------------------------------ wiring */
  input.addEventListener("input", () => { st.hl = -1; renderList(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (st.rows.length) { st.hl = Math.min(st.hl + 1, st.rows.length - 1); renderList(true); }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (st.rows.length) { st.hl = Math.max(st.hl - 1, -1); renderList(true); }
    } else if (e.key === "Enter") {
      // Enter toggles the highlighted row. Typed text is a filter, never a
      // value — Enter with no highlight does nothing (no free-text commit).
      e.preventDefault();
      const row = st.hl >= 0 ? st.rows[st.hl] : null;
      if (row) setSelected(row, !isSel(row.token));
    } else if (e.key === "Backspace") {
      if (!input.value && st.sel.length) {
        st.sel.pop();
        renderChips();
        renderList(true);
        emit();
      }
    } else if (e.key === "Escape") {
      if (input.value) {
        e.preventDefault();
        e.stopPropagation();
        input.value = "";
        st.hl = -1;
        renderList();
      }
    }
  });
  box.addEventListener("mousedown", (e) => {
    if (e.target === box) { e.preventDefault(); input.focus(); }
  });
  list.addEventListener("change", (e) => {
    const t = e.target;
    if (!t || t.type !== "checkbox") return;
    const row = st.rows[parseInt(t.getAttribute("data-i"), 10)];
    if (row) setSelected(row, t.checked);
  });

  /* -------------------------------------------------------- public API */
  function set(items) {
    const arr = Array.isArray(items) ? items : [];
    const out = [];
    arr.forEach((it) => {
      let tok;
      let pr = "";
      if (it && typeof it === "object") { tok = it.token; pr = String(it.principal || ""); }
      else tok = it;
      if (tok == null || String(tok).trim() === "") return;
      if (!pr) {
        const hit = st.dir.find((d) => String(d.token) === String(tok));
        if (hit) pr = String(hit.principal);
      }
      if (!out.some((p) => String(p.token) === String(tok))) out.push({ principal: pr, token: tok });
    });
    st.sel = out;
    renderChips();
    renderList(true);
    emit();
  }
  function clear() { set([]); }
  function tokensOut() {
    return st.sel.map((p) => Number(p.token))
      .filter((n) => Number.isFinite(n))
      .sort((a, b) => a - b);
  }
  function principalsOut() { return st.sel.map((p) => p.principal).filter(Boolean); }
  function refresh() { return load(st.lastTenant || tenantFn()); }
  function destroy() {
    st.destroyed = true;
    mountEl.innerHTML = "";
    mountEl.classList.remove("epk");
  }

  render();

  return {
    value, set, clear, load, refresh, destroy,
    tokens: tokensOut,
    principals: principalsOut,
    state: () => st.state,
    focus: () => input.focus(),
    onChange: (fn) => { if (typeof fn === "function") changeSubs.push(fn); },
  };
}

/* ---------------------------------------------------------- the namespace */
const Verity = {
  // helpers
  $, esc, api, decodeHandle, fmtMs, fmtTime, fmtAge, timeAgo,
  err: showErr, clearErr,
  // admin token
  getAdminToken, setAdminToken,
  // "show API details" UI preference (developer-plumbing toggle)
  apiDetails, setApiDetails,
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
  // v4 · entity directory + picker (docs/design/ENTITY-PICKER.md)
  entityDirectory, entityPicker,
  // v5 · principal picker — the sectioned who-chooser over /v1/admin/principals
  principalPicker,
  // shared state
  tenant, setTenant, onTenant, buildHash,
  // v3 · FTUE: tenant directory + create-space + working handle + sample label
  tenantDir, onTenantDir, refreshTenantDir, tenantName,
  confirmTenantById, confirmedTenant,
  openCreateTenant, onTenantCreated,
  workingHandle, setWorkingHandle, onWorkingHandle,
  isSample, sampleBadge,
};
window.Verity = Verity;
