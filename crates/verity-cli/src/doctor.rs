//! `verity-cli doctor` — plane-by-plane OBSERVED health of the running dev
//! stack. Every line reports what a live probe against the RUNNING server (or
//! its own boot log) actually showed — never what some process once
//! configured. `verity-cli dev` reuses these exact probe fns for its summary,
//! so the two surfaces can never drift apart.
//!
//! Honesty rules: a plane that is down degrades loudly with what that MEANS
//! (which guarantee narrows, which fallback carries it) and how to fix it;
//! a plane we cannot observe says "unknown" and why — it never guesses.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Result};

use crate::{ui, util, Ctx};

// The MinIO media tier and Temporal as deploy/docker-compose.yml publishes
// them (dev credentials — the compose file is the source of truth).
pub const MINIO_ENDPOINT: &str = "http://localhost:9000";
pub const MINIO_BUCKET: &str = "verity-media";
pub const MINIO_ACCESS_KEY: &str = "minioadmin";
pub const MINIO_SECRET_KEY: &str = "minioadmin";
pub const TEMPORAL_UI: &str = "http://localhost:8233";

/// The persistent dev signing key file name (under ~/.verity, 0600).
pub const SIGNING_KEY_FILE: &str = "dev-signing-key";

/// One plane's observed state.
pub enum Status {
    /// Probe succeeded — the plane is live.
    Ok,
    /// Plane not available / not wired — the honest fallback applies.
    Degraded,
    /// Could not observe (no boot log, no handle, …) — never a guess.
    Unknown,
}

pub struct Plane {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

impl Plane {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Ok,
            detail: detail.into(),
        }
    }
    fn degraded(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Degraded,
            detail: detail.into(),
        }
    }
    fn unknown(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Unknown,
            detail: detail.into(),
        }
    }
}

/// Print one plane line: `  ✓ media tier    detail` (✓ / ! / ?).
pub fn print_plane(p: &Plane) {
    let mark = match p.status {
        Status::Ok => ui::green("✓"),
        Status::Degraded => ui::yellow("!"),
        Status::Unknown => ui::dim("?"),
    };
    println!("  {mark} {}  {}", ui::pad(p.name, 13), p.detail);
}

// ---------- shared helpers ----------

fn with_admin(ctx: &Ctx, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match &ctx.config.admin_token {
        Some(token) => rb.bearer_auth(token),
        None => rb,
    }
}

/// Where `verity-cli dev` writes the spawned server's log.
fn server_log_path(ctx: &Ctx) -> PathBuf {
    ctx.config_path
        .parent()
        .map(|d| d.join("server.log"))
        .unwrap_or_else(|| PathBuf::from("verity-server.log"))
}

/// The persistent dev signing key path (~/.verity/dev-signing-key).
pub fn signing_key_path(ctx: &Ctx) -> PathBuf {
    ctx.config_path
        .parent()
        .map(|d| d.join(SIGNING_KEY_FILE))
        .unwrap_or_else(|| PathBuf::from(SIGNING_KEY_FILE))
}

/// The CURRENT boot's log segment. The server ends its boot preamble with an
/// unconditional "listening on http" line, so the current boot's preamble is
/// whatever sits between the previous "listening" marker (= previous boot's
/// runtime tail, which never contains boot-preamble markers) and the last one.
/// None = no log / never booted through `verity-cli dev` — probes that rely
/// on it answer "unknown", never a guess. Only the last 512 KiB are scanned.
fn current_boot_segment(ctx: &Ctx) -> Option<String> {
    let raw = std::fs::read(server_log_path(ctx)).ok()?;
    let start = raw.len().saturating_sub(512 * 1024);
    let text = String::from_utf8_lossy(&raw[start..]).into_owned();
    let marker = " listening on http";
    let last = text.rfind(marker)?;
    let prev_end = text[..last].rfind(marker).map(|i| i + marker.len());
    Some(text[prev_end.unwrap_or(0)..last + marker.len()].to_string())
}

// ---------- (a) identity plane: SpiceDB subject-resolved minting ----------

/// Is subject-based minting live on THIS server? Attempt the production
/// shape — mint a short-lived scope as `user:<probe>` — and read the outcome:
/// 2xx means the identity plane resolved the subject's keys; the specific 422
/// (ReBAC off) or any other failure reports "not available". A probe, not a
/// switch: the line states what was observed, nothing more.
pub async fn probe_identity(ctx: &Ctx, tenant_id: &str, subject: &str) -> Plane {
    let body = serde_json::json!({
        "tenant_id": tenant_id,
        "subject": subject,
        "actor_sub": subject,
        "actor_azp": "cli:doctor-identity-probe",
        "ttl_seconds": 60,
    });
    let outcome = util::send(
        ctx.http.post(format!("{}/v1/scopes", ctx.url)).json(&body),
        &ctx.url,
    )
    .await;
    match outcome {
        Ok((status, _)) if status.is_success() => Plane::ok(
            "identity",
            "connected (SpiceDB) — mint by person works (observed: a real subject mint succeeded)",
        ),
        _ => Plane::degraded(
            "identity",
            "not available — sessions use raw keys (dev fallback)",
        ),
    }
}

// ---------- (a2) SpiceDB watch consumer ----------

/// Watch health, observed via GET /v1/admin/rebac-watch — the server's own
/// counters, not this process's configuration. Note: an idle watch reports
/// `connected=false` until its first event arrives (verified server behavior,
/// see rebac_watch.rs) — `enabled` is the wired/not-wired signal.
pub async fn probe_watch(ctx: &Ctx) -> Plane {
    let req = with_admin(
        ctx,
        ctx.http.get(format!("{}/v1/admin/rebac-watch", ctx.url)),
    );
    let Ok((status, body)) = util::send(req, &ctx.url).await else {
        return Plane::unknown("rebac watch", "server unreachable — cannot observe");
    };
    if !status.is_success() {
        return Plane::unknown(
            "rebac watch",
            format!("GET /v1/admin/rebac-watch answered {status} — cannot observe"),
        );
    }
    let Ok(snap) = serde_json::from_str::<serde_json::Value>(&body) else {
        return Plane::unknown("rebac watch", "unparseable watch status — cannot observe");
    };
    let enabled = snap["enabled"].as_bool().unwrap_or(false);
    let degraded = snap["degraded"].as_bool().unwrap_or(false);
    let connected = snap["connected"].as_bool().unwrap_or(false);
    let tombstones = snap["tombstones_written"].as_u64().unwrap_or(0);
    let gaps = snap["gaps"].as_u64().unwrap_or(0);
    if !enabled {
        return Plane::degraded(
            "rebac watch",
            "off — out-of-band SpiceDB revocations wait for the revocation window / next mint \
             (the windowed baseline still enforces; dev wires the watch when SpiceDB is healthy)",
        );
    }
    if degraded {
        return Plane::degraded(
            "rebac watch",
            format!(
                "on but GAP-latched ({gaps} gap(s), last_error {:?}) — revocations covered by \
                 the windowed baseline; restart the server after reconciling",
                snap["last_error"].as_str().unwrap_or("unknown")
            ),
        );
    }
    Plane::ok(
        "rebac watch",
        format!(
            "on — out-of-band SpiceDB deletes materialize as tombstones \
             (observed /v1/admin/rebac-watch: connected={connected}, \
             tombstones_written={tombstones}, gaps={gaps}; an idle stream shows \
             connected=false until its first event)"
        ),
    )
}

// ---------- (c) persistent dev signing key ----------

/// Observed from two facts: the key file on disk, and whether the RUNNING
/// server's boot preamble carried scope.rs's "will not survive a restart"
/// warning (logged exactly when no VERITY_SIGNING_KEY/VERITY_SCOPE_KEY was
/// set). The key itself is NEVER printed.
pub fn probe_signing_key(ctx: &Ctx) -> Plane {
    let path = signing_key_path(ctx);
    let file_exists = path.is_file();
    match current_boot_segment(ctx) {
        Some(seg) if seg.contains("will not survive a restart") => Plane::degraded(
            "signing key",
            "EPHEMERAL on the running server — handles and signatures die with the process; \
             re-run `verity-cli dev` to restart it with the persistent key",
        ),
        Some(_) if file_exists => Plane::ok(
            "signing key",
            format!("persistent ({}) — handles survive restarts", path.display()),
        ),
        Some(_) => Plane::ok(
            "signing key",
            "persistent (set via VERITY_SIGNING_KEY/VERITY_SCOPE_KEY at server boot) — \
             handles survive restarts",
        ),
        None if file_exists => Plane::unknown(
            "signing key",
            format!(
                "key file present ({}) but no boot log to confirm the running server loaded it \
                 (server started outside `verity-cli dev`?)",
                path.display()
            ),
        ),
        None => Plane::degraded(
            "signing key",
            "no persistent dev key yet — run `verity-cli dev` to create it (handles currently \
             die on every server restart)",
        ),
    }
}

// ---------- (b) media tier ----------

/// FUNCTIONAL round-trip through the real media path: upload a small binary
/// blob under the given scope handle, mint its Verity-signed URL, redeem it,
/// and compare bytes. The TIER (object store vs Postgres bytea) is observed
/// from the boot preamble's "media object store enabled" line — the server
/// exposes no config endpoint, and the CLI never guesses.
pub async fn probe_media(ctx: &Ctx, handle: &str) -> Plane {
    // Fixed content on purpose: the object-store key is content-addressed
    // (media/<tenant>/<sha256>), so repeated probes collapse to one object.
    let blob: Vec<u8> = b"verity media probe \x00\x01\xfe\xff".to_vec();
    let round_trip = media_round_trip(ctx, handle, blob).await;
    let tier = current_boot_segment(ctx).map(|seg| seg.contains("media object store enabled"));
    match (round_trip, tier) {
        (Ok(()), Some(true)) => Plane::ok(
            "media tier",
            format!(
                "object store (MinIO bucket {MINIO_BUCKET}) — blob round-trip through a \
                 Verity-signed URL verified"
            ),
        ),
        (Ok(()), Some(false)) => Plane::degraded(
            "media tier",
            "not available — blobs stay in Postgres (dev fallback); round-trip through a \
             Verity-signed URL verified on the bytea tier",
        ),
        (Ok(()), None) => Plane::unknown(
            "media tier",
            "blob round-trip verified, but no boot log to tell object store from bytea \
             (server started outside `verity-cli dev`?)",
        ),
        (Err(e), _) => Plane::degraded("media tier", format!("blob round-trip FAILED: {e:#}")),
    }
}

async fn media_round_trip(ctx: &Ctx, handle: &str, blob: Vec<u8>) -> Result<()> {
    let part = reqwest::multipart::Part::bytes(blob.clone())
        .file_name("doctor-probe.bin")
        .mime_str("application/octet-stream")?;
    let form = reqwest::multipart::Form::new()
        .text("scope_handle", handle.to_string())
        .part("file", part);
    let (status, body) = util::send(
        ctx.http
            .post(format!("{}/v1/files", ctx.url))
            .multipart(form),
        &ctx.url,
    )
    .await?;
    let json = util::expect_json(status, &body, "media upload probe failed")?;
    let media_id = json["media_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("upload response carries no media_id"))?
        .to_string();
    let (status, body) = util::send(
        ctx.http
            .post(format!("{}/v1/media/{media_id}/sign", ctx.url))
            .json(&serde_json::json!({ "scope_handle": handle, "ttl_seconds": 60 })),
        &ctx.url,
    )
    .await?;
    let json = util::expect_json(status, &body, "media sign probe failed")?;
    let url = json["url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("sign response carries no url"))?
        .to_string();
    let resp = ctx
        .http
        .get(format!("{}{url}", ctx.url))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("signed GET failed: {e}"))?;
    if !resp.status().is_success() {
        bail!("signed GET answered {}", resp.status());
    }
    let got = resp.bytes().await?;
    if got.as_ref() != blob.as_slice() {
        bail!(
            "bytes did not round-trip ({} uploaded, {} returned)",
            blob.len(),
            got.len()
        );
    }
    Ok(())
}

// ---------- (e) query encoder ----------

/// Observed via the admin debug-recall trace: a text-only probe reports which
/// leg the server actually ran — `dense` iff the local encoder is loaded,
/// `bm25` when recall is sparse-only. A real behavior probe, not a config echo.
pub async fn probe_encoder(ctx: &Ctx, handle: &str) -> Plane {
    let req = with_admin(
        ctx,
        ctx.http
            .post(format!("{}/v1/admin/debug/recall", ctx.url))
            .json(&serde_json::json!({
                "scope_handle": handle,
                "text": "verity doctor encoder probe",
                "candidates": 1,
            })),
    );
    let Ok((status, body)) = util::send(req, &ctx.url).await else {
        return Plane::unknown("encoder", "server unreachable — cannot observe");
    };
    if !status.is_success() {
        return Plane::unknown(
            "encoder",
            format!("debug recall answered {status} — cannot observe the query leg"),
        );
    }
    let leg = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["query"]["leg"].as_str().map(String::from));
    match leg.as_deref() {
        Some("dense") => Plane::ok(
            "encoder",
            "loaded — hybrid recall live (observed: a text probe ran the dense leg)",
        ),
        Some("bm25") => Plane::degraded(
            "encoder",
            "not loaded — recall is sparse-only (BM25); check the boot log for the \
             model-download failure and restart",
        ),
        _ => Plane::unknown("encoder", "debug recall reported no query leg"),
    }
}

// ---------- (e2) server-side auto-resolve ----------

/// Observed from the boot preamble (main.rs logs exactly one of the two
/// lines); when no boot log exists the env DEFAULT is stated as such.
pub fn probe_resolve(ctx: &Ctx) -> Plane {
    match current_boot_segment(ctx) {
        Some(seg) if seg.contains("auto-resolve loop enabled") => Plane::ok(
            "auto-resolve",
            "on — dirty tenants re-resolve past the debounce window \
             (VERITY_RESOLVE_DEBOUNCE, default 900s)",
        ),
        Some(seg) if seg.contains("auto-resolve DISABLED") => Plane::degraded(
            "auto-resolve",
            "off (VERITY_RESOLVE_DEBOUNCE=0) — resolution stays manual / Temporal-hook-only",
        ),
        Some(_) => Plane::unknown(
            "auto-resolve",
            "boot log carries no auto-resolve line — cannot observe",
        ),
        None => Plane::unknown(
            "auto-resolve",
            "on by default (VERITY_RESOLVE_DEBOUNCE unset ⇒ 900s) — no boot log to confirm \
             this server (started outside `verity-cli dev`?)",
        ),
    }
}

// ---------- (d) Temporal (optional ingest-orchestration plane) ----------

/// Temporal serves its dev Web UI on :8233; the container healthcheck is the
/// fallback when HTTP says nothing. Honest scope note: the Rust server never
/// talks to Temporal — the Python connector workers do (ingest/), so "up"
/// means schedules are AVAILABLE, not that a worker is running.
pub async fn probe_temporal(http: &reqwest::Client) -> Plane {
    let ui_up = http
        .get(TEMPORAL_UI)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    let container_healthy = || {
        Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{.State.Health.Status}}",
                "verity-temporal",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "healthy")
            .unwrap_or(false)
    };
    if ui_up || container_healthy() {
        Plane::ok(
            "temporal",
            format!(
                "up ({TEMPORAL_UI}) — connector schedules available (workers run separately \
                 via ingest/, see docs/OPERATIONS.md \"Ingest orchestration\")"
            ),
        )
    } else {
        Plane::degraded(
            "temporal",
            "not available — optional plane, dev does not block on it; connector schedules \
             need `docker compose -f deploy/docker-compose.yml up -d temporal`",
        )
    }
}

// ---------- collection + the doctor command ----------

/// Run every plane probe against the running server. Shared verbatim between
/// `verity-cli dev`'s summary and `verity-cli doctor`.
pub async fn collect(ctx: &Ctx, tenant_id: &str, subject: &str, handle: &str) -> Vec<Plane> {
    vec![
        probe_identity(ctx, tenant_id, subject).await,
        probe_watch(ctx).await,
        probe_signing_key(ctx),
        probe_media(ctx, handle).await,
        probe_encoder(ctx, handle).await,
        probe_resolve(ctx),
        probe_temporal(&ctx.http).await,
    ]
}

/// `verity-cli doctor`: re-run the observed probes against the RUNNING server
/// + stack and print the plane-by-plane table.
pub async fn run(ctx: &Ctx) -> Result<()> {
    ui::banner("verity doctor — observed plane health (probed live, not configured)");
    println!();
    if !util::healthz(&ctx.http, &ctx.url).await {
        bail!(
            "no verity server answering at {}\n  → start the stack with `verity-cli dev`",
            ctx.url
        );
    }
    ui::step_ok("server", &format!("{} answers /healthz", ctx.url));
    let Some(tenant_id) = ctx.config.tenant_id.clone() else {
        bail!(
            "no tenant in {} — run `verity-cli dev` once, then re-run doctor",
            ctx.config_path.display()
        );
    };
    let Some(handle) = ctx.config.scope_handle.clone() else {
        bail!(
            "no scope handle in {} — run `verity-cli dev` once, then re-run doctor",
            ctx.config_path.display()
        );
    };
    let subject = util::actor_sub().unwrap_or_else(|| "user:dev".into());
    for plane in collect(ctx, &tenant_id, &subject, &handle).await {
        print_plane(&plane);
    }
    println!();
    println!(
        "  {}",
        ui::dim(
            "✓ live · ! degraded (the stated fallback carries the guarantee) · ? unobservable. \
             Re-run `verity-cli dev` to (re)wire degraded planes."
        )
    );
    Ok(())
}
