//! Read-only evidence-room web console (SPEC §11d, UI-SPEC §7/§8).
//!
//! One embedded page, zero build steps: `GET /ui` serves a self-contained
//! HTML/CSS/vanilla-JS app assembled AT COMPILE TIME from per-screen
//! fragments via `concat!(include_str!(...))` — no `build.rs`, no bundler, no
//! CDN, no external requests, no static-asset directory. Splitting the source
//! into fragments (theme/core/shell + one pair per panel) lets panel builders
//! parallelize while the served artifact stays a single route in one binary,
//! so the build hash IS the version (no UI/server skew possible).
//!
//! ## Assembler contract (FROZEN — panel builders must not touch this order)
//!
//! The page is concatenated in exactly this order:
//!   1. `<style>` — `theme.css` (design tokens, FROZEN) then `core.css`
//!      (layout primitives, FROZEN).
//!   2. `shell.html` — the body chrome: left rail, tenant switcher, session
//!      badge, read-only ribbon template, build-hash header, mount `<div>`s.
//!   3. the three MVP panel HTML fragments, in rail order (scope, audit,
//!      knowledge). Each is an inert `<section>` that starts hidden and is
//!      shown by the router when its rail entry is selected.
//!   4. `<script>` — `core.js` (helpers + router + mount registry, FROZEN
//!      signatures) then the three panel JS fragments, which each call
//!      `Verity.register({...})` at load to wire themselves into the rail.
//!
//! Adding a panel is a two-line diff here: one `include_str!` in the HTML
//! group and one in the JS group. Nothing else in this file changes.
//!
//! Deliberately mutation-free at v0.1 (SPEC §11d): the page is public,
//! unauthenticated static markup; every probe it fires is enforced
//! server-side by the pasted scope handle or the admin bearer token the
//! viewer supplies (held in `sessionStorage` only, never persisted to disk).

use axum::response::Html;

/// The build hash surfaced in the header. The served page is `include_str!`-
/// embedded in this binary, so a git short SHA (when the build environment
/// provides one) uniquely identifies the served artifact; otherwise we fall
/// back to the crate version. No UI/server skew is possible either way.
const BUILD_HASH: &str = match option_env!("VERITY_BUILD_HASH") {
    Some(h) => h,
    None => concat!("v", env!("CARGO_PKG_VERSION")),
};

/// The compile-time-assembled console page, minus the doctype/head skeleton
/// and the injected build hash (both applied at request time in `ui_page`).
///
/// FRAGMENT ORDER IS THE ASSEMBLER CONTRACT — see the module docs. Panel
/// builders append their pair to the two marked groups and touch nothing else.
const UI_BODY: &str = concat!(
    "<style>\n",
    include_str!("theme.css"),
    "\n",
    include_str!("core.css"),
    "\n</style>\n",
    // ---- body chrome ----
    include_str!("shell.html"),
    "\n",
    // ---- panel HTML fragments (rail order) — APPEND ONE LINE PER PANEL ----
    include_str!("panel_scope.html"),
    "\n",
    include_str!("panel_audit.html"),
    "\n",
    include_str!("panel_knowledge.html"),
    "\n",
    // ---- scripts: core first (defines Verity registry), then panels ----
    "<script>\n",
    include_str!("core.js"),
    "\n",
    // ---- panel JS fragments — APPEND ONE LINE PER PANEL ----
    include_str!("panel_scope.js"),
    "\n",
    include_str!("panel_audit.js"),
    "\n",
    include_str!("panel_knowledge.js"),
    "\n",
    // Boot AFTER every panel has called Verity.register(...) at load.
    "Verity.boot();\n",
    "</script>\n",
);

/// GET /ui — the embedded single-page evidence room.
///
/// Wraps the assembled body in the minimal doctype/head skeleton and injects
/// the build hash into the header placeholder (`data-build-hash` marker). The
/// result is one self-contained page: zero `<link>`, zero `<script src>`, no
/// second HTTP request.
pub(crate) async fn ui_page() -> Html<String> {
    let page = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Verity Console — the evidence room</title>\n\
         </head>\n<body data-build-hash=\"{hash}\">\n{body}</body>\n</html>\n",
        hash = BUILD_HASH,
        body = UI_BODY,
    );
    Html(page)
}
