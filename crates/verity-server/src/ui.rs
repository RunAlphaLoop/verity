//! Read-only scope-inspector web UI (SPEC §11d, roadmap task 24).
//!
//! One embedded page, zero build steps: `GET /ui` serves a self-contained
//! HTML/CSS/vanilla-JS app compiled into the binary via `include_str!` — no
//! bundler, no CDN, no external requests. The centerpiece is the scope
//! inspector ("what can this agent see, exactly?"): it decodes a pasted
//! `vs_` handle client-side (the payload segment is base64 — signed, not
//! secret) and then probes recall/briefs/activity THROUGH the handle, so a
//! security reviewer sees enforcement, not a diagram of it. The remaining
//! panels are thin read-only views over the admin plane: quarantine, the
//! audit tail, and the freshness SLO.
//!
//! Deliberately mutation-free (SPEC §11d: v0.1 UI is read-only — inspector
//! and dashboards; admin mutations stay on CLI/REST until v0.2). The page
//! itself is unauthenticated static markup; every API call it makes is
//! enforced server-side by the scope handle or the admin bearer token the
//! viewer supplies (held in sessionStorage only).

use axum::response::Html;

const UI_HTML: &str = include_str!("ui.html");

/// GET /ui — the embedded single-page inspector.
pub(crate) async fn ui_page() -> Html<&'static str> {
    Html(UI_HTML)
}
