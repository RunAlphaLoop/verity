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

use axum::http::header;
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
    include_str!("panel_welcome.html"),
    "\n",
    include_str!("panel_ingest.html"),
    "\n",
    include_str!("panel_scope.html"),
    "\n",
    include_str!("panel_playground.html"),
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
    include_str!("panel_memories.html"),
    "\n",
    include_str!("panel_manifest.html"),
    "\n",
    include_str!("panel_system.html"),
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
    // The `__CSP_NONCE__` placeholder is replaced per-request in `ui_page` with a
    // fresh random nonce that the Content-Security-Policy header pins, so ONLY
    // this block executes — an injected <script> without the nonce is refused.
    "<script nonce=\"__CSP_NONCE__\">\n",
    include_str!("core.js"),
    "\n",
    // ---- panel JS fragments — APPEND ONE LINE PER PANEL ----
    // home FIRST: registration order decides the default panel (see above).
    // panel_welcome.js also defines `window.VerityFtue` (the shared setup/
    // checklist derivation); panel_home reads it lazily at load time, so the
    // relative order of the two files does not matter.
    include_str!("panel_home.js"),
    "\n",
    // sample_cast.js defines `window.VeritySample` (the Acme Logistics sample
    // seeder + honest removal); panel_welcome's fork card reads it lazily, so
    // order relative to panel_welcome.js does not matter — core-first does.
    include_str!("sample_cast.js"),
    "\n",
    include_str!("panel_welcome.js"),
    "\n",
    include_str!("panel_ingest.js"),
    "\n",
    include_str!("panel_scope.js"),
    "\n",
    include_str!("panel_playground.js"),
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
    include_str!("panel_memories.js"),
    "\n",
    include_str!("panel_manifest.js"),
    "\n",
    include_str!("panel_system.js"),
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
///
/// `Cache-Control: no-store`: the page is embedded in the binary so "the
/// build hash IS the version" — but without this header a browser
/// heuristically caches /ui and keeps serving the OLD console after a server
/// upgrade (found 2026-07-11: a rebuilt server, a reloaded tab, and a stale
/// bundle running against the new API). One header keeps the no-skew promise
/// true; the page is a single local response, so there is nothing to cache.
pub(crate) async fn ui_page() -> (axum::http::HeaderMap, Html<String>) {
    let nonce = gen_csp_nonce();
    let page = page_html(&nonce);

    // Content-Security-Policy: script-src is nonce-only (no 'unsafe-inline',
    // no 'unsafe-eval') — the single highest-value control, because it stops an
    // injected/XSS <script> from executing at all, which is what would otherwise
    // read the admin bearer out of sessionStorage or drive the credential-paste
    // endpoint. style-src keeps 'unsafe-inline' (the console has ~788 inline
    // style="" attributes that cannot carry a nonce; injected CSS cannot run
    // JS, a deliberate low-risk tradeoff). The page is fully self-contained
    // (default-src 'self'), so everything else is locked to same-origin, and
    // frame-ancestors 'none' blocks clickjacking of the console.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_str(&csp_header_value(&nonce))
            .expect("CSP header value is ASCII"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    (headers, Html(page))
}

/// A fresh, unpredictable per-request CSP nonce (128 bits from the OS CSPRNG,
/// hex-encoded). Unpredictability is load-bearing: a guessable nonce would let
/// an injected script carry it and execute.
fn gen_csp_nonce() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The CSP header value for a given nonce. Pure so it is unit-testable.
fn csp_header_value(nonce: &str) -> String {
    format!(
        "default-src 'self'; \
         script-src 'nonce-{nonce}'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self'; \
         object-src 'none'; \
         base-uri 'none'; \
         frame-ancestors 'none'; \
         form-action 'self'"
    )
}

/// The full page with every `__CSP_NONCE__` placeholder (the two inline
/// `<script>` tags) replaced by `nonce`. Pure so it is unit-testable.
fn page_html(nonce: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Verity Console — the evidence room</title>\n\
         <link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' rx='3' fill='%230d1117'/%3E%3Cpath d='M4 4l4 8 4-8' stroke='%233fb950' stroke-width='2' fill='none'/%3E%3C/svg%3E\">\n\
         </head>\n<body data-build-hash=\"{hash}\">\n{body}</body>\n</html>\n",
        hash = BUILD_HASH,
        body = assembled_body(),
    )
    .replace("__CSP_NONCE__", nonce)
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
            "panel-welcome",
            "panel-ingest",
            "panel-scope",
            "panel-playground",
            "panel-audit",
            "panel-knowledge",
            "panel-erasure",
            "panel-sources",
            "panel-quarantine",
            "panel-migrations",
            "panel-principals",
            "panel-entities",
            "panel-memories",
            "panel-manifest",
            "panel-system",
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

    /// script-src must be nonce-only: no 'unsafe-inline' / 'unsafe-eval' can
    /// creep in, or the whole point (an injected <script> cannot run) is lost.
    #[test]
    fn csp_script_src_is_nonce_only() {
        let csp = csp_header_value("deadbeef");
        assert!(
            csp.contains("script-src 'nonce-deadbeef'"),
            "script-src not nonce-based: {csp}"
        );
        // Isolate the script-src directive and prove it carries no inline/eval escape.
        let script_src = csp
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with("script-src"))
            .expect("script-src present");
        assert!(
            !script_src.contains("unsafe-inline"),
            "script-src allows unsafe-inline: {script_src}"
        );
        assert!(
            !script_src.contains("unsafe-eval"),
            "script-src allows unsafe-eval: {script_src}"
        );
        // The console has zero external script origins — nonce is the only source.
        assert!(
            !script_src.contains("http"),
            "script-src allows an external origin: {script_src}"
        );
        // Clickjacking + MIME-sniffing hardening travel with it.
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "missing frame-ancestors: {csp}"
        );
        assert!(
            csp.contains("object-src 'none'"),
            "missing object-src: {csp}"
        );
    }

    /// EVERY inline <script> in the served page must carry the request nonce.
    /// A single un-nonced block would be BLOCKED by the CSP — a blank/broken
    /// console — so this guards both the security AND the console loading.
    #[test]
    fn every_inline_script_carries_the_nonce() {
        let nonce = "nonce123abc";
        let page = page_html(nonce);
        let total = page.matches("<script").count();
        let nonced = page.matches(&format!("<script nonce=\"{nonce}\"")).count();
        assert!(
            total >= 2,
            "expected the two inline script blocks, found {total}"
        );
        assert_eq!(
            total,
            nonced,
            "{} of {} <script> tags are un-nonced — CSP would blank the console",
            total - nonced,
            total
        );
        // The placeholder must be fully substituted (none left to leak un-nonced).
        assert!(
            !page.contains("__CSP_NONCE__"),
            "an unreplaced CSP nonce placeholder remains"
        );
    }

    /// The nonce is fresh per request (unpredictable) and 128 bits.
    #[test]
    fn nonce_is_fresh_and_128_bits() {
        let a = gen_csp_nonce();
        let b = gen_csp_nonce();
        assert_eq!(a.len(), 32, "expected 16 bytes hex-encoded");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two nonces collided — not random per request");
    }
}
