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
/// The shell chrome. Carries the `__PANEL_SECTIONS__` marker inside
/// `.content-inner`; the panel fragments are SPLICED in there at first
/// request (see `assembled_body`) so panels render inside the content pane —
/// appending them after the shell put them at body level, below the
/// 100vh-tall rail, painting a full viewport of void (the "blank console"
/// bug found 2026-07-11).
const SHELL: &str = include_str!("shell.html");

/// The marker in shell.html the panel sections replace.
const PANEL_MARKER: &str = "<!-- __PANEL_SECTIONS__ -->";

/// ---- panel HTML fragments (rail order) — APPEND ONE LINE PER PANEL ----
/// `panel_home` is FIRST: it registers first, so `Verity.boot()` lands on the
/// attention-first home when the URL carries no hash (UI-ACTIONS N3).
const PANEL_SECTIONS: &str = concat!(
    include_str!("panel_home.html"),
    "\n",
    include_str!("panel_ingest.html"),
    "\n",
    include_str!("panel_scope.html"),
    "\n",
    include_str!("panel_audit.html"),
    "\n",
    include_str!("panel_knowledge.html"),
    "\n",
    include_str!("panel_erasure.html"),
    "\n",
    include_str!("panel_sources.html"),
    "\n",
    include_str!("panel_quarantine.html"),
    "\n",
    include_str!("panel_migrations.html"),
    "\n",
    include_str!("panel_principals.html"),
    "\n",
    include_str!("panel_entities.html"),
    "\n",
);

const UI_STYLE: &str = concat!(
    "<style>\n",
    include_str!("theme.css"),
    "\n",
    include_str!("core.css"),
    "\n</style>\n",
);

const UI_SCRIPTS: &str = concat!(
    // ---- scripts: core first (defines Verity registry), then panels ----
    "<script>\n",
    include_str!("core.js"),
    "\n",
    // ---- panel JS fragments — APPEND ONE LINE PER PANEL ----
    // home FIRST: registration order decides the default panel (see above).
    include_str!("panel_home.js"),
    "\n",
    include_str!("panel_ingest.js"),
    "\n",
    include_str!("panel_scope.js"),
    "\n",
    include_str!("panel_audit.js"),
    "\n",
    include_str!("panel_knowledge.js"),
    "\n",
    include_str!("panel_erasure.js"),
    "\n",
    include_str!("panel_sources.js"),
    "\n",
    include_str!("panel_quarantine.js"),
    "\n",
    include_str!("panel_migrations.js"),
    "\n",
    include_str!("panel_principals.js"),
    "\n",
    include_str!("panel_entities.js"),
    "\n",
    // Boot AFTER every panel has called Verity.register(...) at load.
    "Verity.boot();\n",
    "</script>\n",
);

/// Assemble the body once: styles + shell (with the panel sections spliced
/// into `.content-inner` at the marker) + scripts. Panics at first request if
/// the marker is missing — a silently mis-assembled console is worse than a
/// loud failure.
fn assembled_body() -> &'static str {
    use std::sync::OnceLock;
    static BODY: OnceLock<String> = OnceLock::new();
    BODY.get_or_init(|| {
        assert!(
            SHELL.contains(PANEL_MARKER),
            "shell.html lost the {PANEL_MARKER} marker — panels would render off-screen"
        );
        format!(
            "{UI_STYLE}{}{UI_SCRIPTS}",
            SHELL.replace(PANEL_MARKER, PANEL_SECTIONS)
        )
    })
}

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
         <link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' rx='3' fill='%230d1117'/%3E%3Cpath d='M4 4l4 8 4-8' stroke='%233fb950' stroke-width='2' fill='none'/%3E%3C/svg%3E\">\n\
         </head>\n<body data-build-hash=\"{hash}\">\n{body}</body>\n</html>\n",
        hash = BUILD_HASH,
        body = assembled_body(),
    );
    Html(page)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The blank-console regression (2026-07-11): every panel section must sit
    /// INSIDE `.content-inner` (before `</main>`), never at body level below
    /// the 100vh rail where it paints off-screen.
    #[test]
    fn panels_are_spliced_inside_the_content_pane() {
        let body = assembled_body();
        let main_close = body.find("</main>").expect("shell has </main>");
        let inner_open = body
            .find("class=\"content-inner\"")
            .expect("shell has .content-inner");
        for id in [
            "panel-home",
            "panel-ingest",
            "panel-scope",
            "panel-audit",
            "panel-knowledge",
            "panel-erasure",
            "panel-sources",
            "panel-quarantine",
            "panel-migrations",
            "panel-principals",
            "panel-entities",
        ] {
            let pos = body
                .find(&format!("id=\"{id}\""))
                .unwrap_or_else(|| panic!("{id} missing from the assembled page"));
            assert!(
                pos > inner_open && pos < main_close,
                "{id} rendered OUTSIDE .content-inner (pos {pos}, main closes at {main_close}) — \
                 it would paint off-screen below the rail"
            );
        }
    }
}
