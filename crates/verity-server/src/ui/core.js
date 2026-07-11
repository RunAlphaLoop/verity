"use strict";
/* ============================================================================
   core.js — CORE PRIMITIVES  ·  FROZEN SIGNATURES (T0.3)
   ----------------------------------------------------------------------------
   Hand-rolled vanilla helpers + the panel router/mount registry. Panels code
   AGAINST these signatures and never modify this file. Everything is hung off
   the single global `Verity` namespace; the short helpers ($, esc) are also
   exposed as top-level consts for terseness inside panel scripts.

   READ-PATH PURITY: nothing here makes an LLM or live-ReBAC call. api() is a
   thin fetch wrapper; decodeHandle() is pure client-side base64url→JSON. The
   only network calls a panel can make go through api(), to endpoints that
   already exist server-side.
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

/* ============================================================================
   ROUTER + MOUNT REGISTRY
   ----------------------------------------------------------------------------
   Panels register ONE object at load via Verity.register({...}); the router
   owns the left rail and shows exactly one panel's <section> at a time. The
   panel's <section id="panel-<id>"> and its rail entry ([data-nav="<id>"])
   live in shell.html / the panel HTML fragment; the router just toggles the
   .active class and calls the panel's mount() the first time it is shown.
   ============================================================================ */
const _panels = new Map();   // id → {id, mount, onShow, mounted}
let _current = null;

/**
 * Verity.register(panel)
 *   panel.id      : string, matches <section id="panel-<id>"> + [data-nav]
 *   panel.mount?  : fn(sectionEl) — called ONCE, lazily, on first show
 *   panel.onShow? : fn(sectionEl) — called every time the panel is shown
 * Register at fragment load; the router wires the rail in Verity.boot().
 */
function register(panel) {
  if (!panel || !panel.id) throw new Error("Verity.register: panel needs an id");
  _panels.set(panel.id, Object.assign({ mounted: false }, panel));
}

/** Verity.show(id) — switch to a panel (idempotent; lazy-mounts). */
function show(id) {
  const panel = _panels.get(id);
  if (!panel) return;
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
  if (section && panel.onShow) { try { panel.onShow(section); } catch (e) { console.error("onShow " + id, e); } }
  _current = id;
  if (location.hash !== "#" + id) history.replaceState(null, "", "#" + id);
}

/**
 * Verity.boot() — called ONCE at the end of the assembled script, after every
 * panel fragment has registered. Wires rail clicks and shows the initial
 * panel (from the URL hash if it names a live panel, else the first live one).
 */
function boot() {
  document.querySelectorAll('#rail .navitem[data-nav]').forEach((nav) => {
    const id = nav.getAttribute("data-nav");
    if (nav.classList.contains("soon") || !_panels.has(id)) return;
    nav.addEventListener("click", () => show(id));
  });
  const hash = location.hash.replace(/^#/, "");
  const start = _panels.has(hash) ? hash : (_panels.keys().next().value || null);
  if (start) show(start);
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
   handle. Panels read Verity.tenant() and subscribe via Verity.onTenant(). */
let _tenant = "";
const _tenantSubs = [];
function tenant() { return _tenant; }
function setTenant(t) {
  _tenant = t || "";
  _tenantSubs.forEach((f) => { try { f(_tenant); } catch (e) { console.error(e); } });
}
function onTenant(fn) { _tenantSubs.push(fn); }

/* -------------------------------------------------------- build hash */
function buildHash() { return document.body.getAttribute("data-build-hash") || "unknown"; }

/* ---------------------------------------------------------- the namespace */
const Verity = {
  // helpers
  $, esc, api, decodeHandle, fmtMs, fmtTime,
  err: showErr, clearErr,
  // admin token
  getAdminToken, setAdminToken,
  // badges
  badge, provenanceBadge, confBadge, trustBadge, statusBadge,
  entityBadges, tagDerivationBadge, kindBadge, CONF_NAMES,
  // router / registry
  register, show, boot, dialog,
  // shared state
  tenant, setTenant, onTenant, buildHash,
};
window.Verity = Verity;
