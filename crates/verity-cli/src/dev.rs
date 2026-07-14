//! `verity-cli dev` — empty laptop to permission-filtered query in five
//! minutes (SPEC §5e.1 entry point #2). Each phase is idempotent: a healthy
//! /healthz skips docker + spawn entirely, the "dev" tenant upserts to the
//! same id, and re-minting the scope just refreshes its expiry.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::{config, doctor, ui, util, Ctx};

/// The named dev principal (FTUE §5.2): `dev` registers `user:dev` and mints
/// the org-wide scope over its token — no bare magic numbers in the summary.
const DEV_PRINCIPAL: &str = "user:dev";

/// The SpiceDB HTTP gateway as deploy/docker-compose.yml publishes it:
/// service `spicedb`, `--http-enabled` on host port 8443, preshared key
/// `verity-dev-key` (VERITY_SPICEDB_KEY's documented default in rebac.rs).
/// Dev ships with the identity plane ON — these are handed to the spawned
/// server whenever the container comes up healthy.
const SPICEDB_URL: &str = "http://localhost:8443";
const SPICEDB_KEY: &str = "verity-dev-key";

/// Ask the running server to start + own the knowledge consolidation worker
/// (SPEC §2 L2). ONE OWNER: the server spawns and holds the child (the same
/// recipe that used to live here as `spawn_knowledge_worker` now lives behind
/// POST /v1/admin/planes/knowledge/start), so the console's "What's running"
/// panel can show authoritative pid/status and offer a real Stop. This avoids
/// the double-spawn (a CLI child + a console child both burning LLM calls on
/// one space).
///
/// Fail-soft by design: a missing venv/key/repo comes back as the server's own
/// 422/503 words and is surfaced verbatim as a non-fatal `knowledge` line — it
/// never aborts `verity-cli dev`. Returns the started pid on success, or the
/// server's disclosure string on a handled precondition failure.
async fn start_knowledge_worker_via_server(ctx: &Ctx, tenant_id: &str) -> Result<KnowledgeStart> {
    let mut req = ctx
        .http
        .post(format!("{}/v1/admin/planes/knowledge/start", ctx.url))
        .json(&serde_json::json!({ "tenant_id": tenant_id }));
    if let Some(token) = &ctx.config.admin_token {
        req = req.bearer_auth(token);
    }
    let (status, body) = util::send(req, &ctx.url).await?;
    if status.is_success() {
        // { started, pid } on a fresh spawn; { started:false, pid, already_running:true }
        // when the server already owns a live child (idempotent no-op).
        let json: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("the server answered {status} but not JSON: {body}"))?;
        let pid = json["pid"].as_u64().map(|p| p as u32);
        let already = json["already_running"].as_bool().unwrap_or(false);
        Ok(KnowledgeStart::Started { pid, already })
    } else {
        // Predictable precondition (missing repo/venv/key) → the server returns
        // 422/503 with the exact fix. Admin handlers answer in PLAIN TEXT
        // (crate-wide (StatusCode, String) convention), so use the raw body as
        // the disclosure — never JSON-parse it. Disclose, don't abort dev.
        Ok(KnowledgeStart::Declined {
            status,
            disclosure: body.trim().to_string(),
        })
    }
}

/// Ask the running server to start + own the directory-sync worker. Mirrors
/// `start_knowledge_worker_via_server`; reuses `KnowledgeStart` (Started/Declined).
async fn start_directory_worker_via_server(ctx: &Ctx, tenant_id: &str) -> Result<KnowledgeStart> {
    let mut req = ctx
        .http
        .post(format!("{}/v1/admin/planes/directory/start", ctx.url))
        .json(&serde_json::json!({ "tenant_id": tenant_id }));
    if let Some(token) = &ctx.config.admin_token {
        req = req.bearer_auth(token);
    }
    let (status, body) = util::send(req, &ctx.url).await?;
    if status.is_success() {
        let json: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("the server answered {status} but not JSON: {body}"))?;
        let pid = json["pid"].as_u64().map(|p| p as u32);
        let already = json["already_running"].as_bool().unwrap_or(false);
        Ok(KnowledgeStart::Started { pid, already })
    } else {
        Ok(KnowledgeStart::Declined {
            status,
            disclosure: body.trim().to_string(),
        })
    }
}

/// Outcome of asking the server to start the worker.
enum KnowledgeStart {
    /// The server owns a live child. `pid` from the response; `already` true
    /// when it was already running (idempotent no-op).
    Started { pid: Option<u32>, already: bool },
    /// The server refused for a known precondition (missing repo/venv/key);
    /// `disclosure` is its verbatim fix. Non-fatal.
    Declined {
        status: reqwest::StatusCode,
        disclosure: String,
    },
}

pub async fn run(
    ctx: &mut Ctx,
    repo_flag: Option<PathBuf>,
    knowledge: bool,
    directory: bool,
) -> Result<()> {
    ui::banner("verity dev — local memory plane, five minutes");
    println!();

    // Repo discovery is best-effort while the server is already up (we only
    // need it for the mcp binary path in the summary), mandatory otherwise.
    let repo = util::repo_root(repo_flag.as_deref());

    // (a)–(c) infrastructure, skipped wholesale when /healthz already answers.
    if util::healthz(&ctx.http, &ctx.url).await {
        ui::step_ok(
            "server",
            &format!(
                "already running at {} — reusing it (plane lines below report what IT does; \
                 stop it and re-run `verity-cli dev` to re-wire degraded planes)",
                ctx.url
            ),
        );
    } else {
        let repo = repo.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
        docker_up(repo)?;
        wait_for_postgres().await?;
        // Identity plane (SPEC §7a): dev ships with it ON. The wait is
        // bounded and NON-FATAL — SpiceDB trouble degrades to raw-key
        // sessions, disclosed in the summary; it never blocks dev.
        let spicedb_up = wait_for_spicedb().await;
        // Media tier (SPEC §10): MinIO + the one-shot bucket bootstrap.
        // Bounded and NON-FATAL — blobs degrade to Postgres bytea.
        let minio_up = wait_for_minio().await;
        // Temporal (SPEC §5): observed for the summary only — the Rust server
        // never talks to it (Python workers do), so dev NEVER blocks on it.
        wait_for_temporal().await;
        // Persistent dev signing key (scope.rs from_env): without it every
        // restart re-keys the HMAC and all outstanding handles die. Generated
        // once, stored 0600, passed as VERITY_SCOPE_KEY, NEVER printed.
        let signing_key = ensure_dev_signing_key(ctx);
        let bin = ensure_server_built(repo)?;
        spawn_and_wait(ctx, repo, &bin, spicedb_up, minio_up, signing_key).await?;
    }

    // (d) first-run setup: tenant → named principal → scope → config. All
    // idempotent.
    let tenant_id = create_tenant(ctx).await?;
    let dev_token = register_dev_principal(ctx, &tenant_id).await?;
    let (handle, expires) = util::mint_scope(ctx, &tenant_id, &[dev_token], "cli:dev", 43_200)
        .await
        .context("the server is up but scope minting failed")?;
    let expiry_note = chrono::DateTime::parse_from_rfc3339(&expires)
        .map(|t| util::human_remaining(t.with_timezone(&chrono::Utc)))
        .unwrap_or_else(|_| "12h".into());
    ui::step_ok(
        "scope",
        &format!(
            "org-wide handle minted (principal {DEV_PRINCIPAL} = token {dev_token}, expires in {expiry_note})"
        ),
    );

    ctx.config.url = Some(ctx.url.clone());
    ctx.config.tenant_id = Some(tenant_id.clone());
    ctx.config.scope_handle = Some(handle.clone());
    ctx.config.principals = Some(vec![dev_token]);
    config::save(&ctx.config_path, &ctx.config)?;
    ui::step_ok("config", &ctx.config_path.display().to_string());

    // (d.5) knowledge consolidation worker (SPEC §2 L2) — opt-in. Part of the
    // managed stack when flipped on with --knowledge; OFF by default because,
    // unlike the free deterministic planes, it makes LLM calls. Either way the
    // state is DISCLOSED here so it's never a silent mystery.
    //
    // ONE OWNER: we ask the SERVER to spawn + hold the worker child (POST
    // …/knowledge/start) rather than spawning our own. The server owns the
    // recipe (venv, key, --repo) and the child, so the console's What's-running
    // panel shows authoritative pid/status and offers a real Stop — and there's
    // never a second worker racing this one on the same space.
    if knowledge {
        match start_knowledge_worker_via_server(ctx, &tenant_id).await {
            Ok(KnowledgeStart::Started { pid, already }) => {
                let pid_note = pid
                    .map(|p| format!("pid {p}"))
                    .unwrap_or_else(|| "running".into());
                let state = if already { "already running" } else { "up" };
                ui::step_ok(
                    "knowledge",
                    &format!(
                        "consolidation worker {state} ({pid_note}) — owned by the server; \
                         anthropic extractor + judge, leasing every 30s into the review queue. \
                         Auto-publish stays OFF. Stop it from the console's What's-running panel \
                         or POST /v1/admin/planes/knowledge/stop."
                    ),
                );
            }
            // 422/503: missing repo/venv/key — the server's own fix, verbatim.
            // Non-fatal: dev completes, the summary still prints.
            Ok(KnowledgeStart::Declined { status, disclosure }) => println!(
                "  {} {}  --knowledge requested but the server ({status}) could not start it: \
                 {disclosure}",
                ui::yellow("…"),
                ui::pad("knowledge", 8)
            ),
            // Transport-level failure only (the server was healthy moments ago).
            // Still non-fatal — never abort dev over the opt-in worker.
            Err(e) => println!(
                "  {} {}  --knowledge requested but the start request failed: {e}",
                ui::yellow("…"),
                ui::pad("knowledge", 8)
            ),
        }
    } else {
        println!(
            "  {} {}  off — flip on with `verity-cli dev --knowledge` (the server starts + owns \
             the worker: LLM extraction of facts/knowledge from your text, into the review queue)",
            ui::dim("·"),
            ui::pad("knowledge", 8)
        );
    }

    if directory {
        match start_directory_worker_via_server(ctx, &tenant_id).await {
            Ok(KnowledgeStart::Started { pid, already }) => {
                let pid_note = pid
                    .map(|p| format!("pid {p}"))
                    .unwrap_or_else(|| "running".into());
                let state = if already { "already running" } else { "up" };
                ui::step_ok(
                    "directory",
                    &format!(
                        "directory-sync worker {state} ({pid_note}) — owned by the server; \
                         reconciling Google Workspace users + groups (nested membership) into \
                         SpiceDB, so group-based ACL inheritance stays fresh. Stop it from the \
                         What's-running panel or POST /v1/admin/planes/directory/stop."
                    ),
                );
            }
            // 422/503: missing repo/venv/config (SA key + subject) — verbatim fix.
            Ok(KnowledgeStart::Declined { status, disclosure }) => println!(
                "  {} {}  --directory requested but the server ({status}) could not start it: \
                 {disclosure}",
                ui::yellow("…"),
                ui::pad("directory", 8)
            ),
            Err(e) => println!(
                "  {} {}  --directory requested but the start request failed: {e}",
                ui::yellow("…"),
                ui::pad("directory", 8)
            ),
        }
    } else {
        println!(
            "  {} {}  off — flip on with `verity-cli dev --directory` (the server starts + owns \
             the worker: Google users/groups → SpiceDB, keeping group-based ACL inheritance fresh)",
            ui::dim("·"),
            ui::pad("directory", 8)
        );
    }

    // Every plane line reports OBSERVED server behavior, not what this
    // process configured: a reused server may have any wiring, so the probes
    // (shared with `verity-cli doctor`) let the outcome speak.
    let planes = doctor::collect(ctx, &tenant_id, DEV_PRINCIPAL, &handle).await;

    // (e) the summary people copy-paste from.
    print_summary(
        ctx,
        &tenant_id,
        dev_token,
        &expiry_note,
        &planes,
        repo.ok().as_deref(),
    );
    Ok(())
}

// ---------- (a) docker compose up ----------

fn docker_up(repo: &Path) -> Result<()> {
    let compose = repo.join("deploy").join("docker-compose.yml");
    let output = Command::new("docker")
        .args(["compose", "-f"])
        .arg(&compose)
        .args(["up", "-d"])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "docker not found on PATH\n  → install Docker Desktop (or colima + docker CLI) and re-run `verity-cli dev`"
                )
            } else {
                anyhow::anyhow!("failed to run docker compose: {e}")
            }
        })?;
    if !output.status.success() {
        bail!(
            "docker compose up failed:\n{}\n  → is the Docker daemon running? Start Docker Desktop and re-run `verity-cli dev`",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    // No service filter on purpose: `up -d` starts EVERY compose service —
    // spicedb (identity), minio (+ its bucket bootstrap, media tier),
    // temporal (ingest orchestration), qdrant (SCALE profile) included.
    ui::step_ok(
        "compose",
        "docker compose up -d (paradedb pg17 + spicedb + minio + temporal + qdrant)",
    );
    Ok(())
}

// ---------- (b) wait for pg health ----------

async fn wait_for_postgres() -> Result<()> {
    let started = Instant::now();
    loop {
        let health = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{.State.Health.Status}}",
                "verity-postgres",
            ])
            .output();
        if let Ok(out) = health {
            if String::from_utf8_lossy(&out.stdout).trim() == "healthy" {
                ui::step_ok(
                    "pg ready",
                    &format!("healthy after {:.1}s", started.elapsed().as_secs_f32()),
                );
                return Ok(());
            }
        }
        if started.elapsed() > Duration::from_secs(120) {
            bail!(
                "postgres (container verity-postgres) did not report healthy within 120s\n  \
                 → inspect it with `docker logs verity-postgres`, then re-run `verity-cli dev`"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

// ---------- (b2) wait for spicedb health — bounded, never fatal ----------

/// Wait (up to 45s — the container boots in seconds) for `verity-spicedb`
/// to report healthy. Returns whether the identity plane can be wired into
/// the spawned server. NON-FATAL BY DESIGN: the server treats a configured-
/// but-unusable SpiceDB as a startup error (main.rs boot contract), so we
/// only hand it the env when the container actually answers — anything else
/// degrades honestly to raw-key sessions and never blocks dev.
async fn wait_for_spicedb() -> bool {
    let started = Instant::now();
    loop {
        let health = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{.State.Health.Status}}",
                "verity-spicedb",
            ])
            .output();
        if let Ok(out) = health {
            if String::from_utf8_lossy(&out.stdout).trim() == "healthy" {
                ui::step_ok(
                    "spicedb",
                    &format!(
                        "healthy after {:.1}s — identity plane wired into the server",
                        started.elapsed().as_secs_f32()
                    ),
                );
                return true;
            }
        }
        if started.elapsed() > Duration::from_secs(45) {
            println!(
                "  {} {}  spicedb (container verity-spicedb) not healthy within 45s — \
                 continuing without it; sessions use raw keys (dev fallback). \
                 Inspect with `docker logs verity-spicedb`, then re-run `verity-cli dev`",
                ui::yellow("…"),
                ui::pad("spicedb", 8)
            );
            return false;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

// ---------- (b3) wait for the MinIO media tier — bounded, never fatal ----------

/// Container health of one name: Some(true)=healthy, Some(false)=not yet,
/// None=docker/inspect failed (container absent).
fn container_health(name: &str) -> Option<bool> {
    let out = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Health.Status}}", name])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim() == "healthy")
}

/// Wait (up to 45s) for `verity-minio` to report healthy, then (up to 20s
/// more) for the one-shot `verity-minio-init` bucket bootstrap to exit 0.
/// Returns whether the media tier can be wired into the spawned server.
/// NON-FATAL BY DESIGN: a configured-but-unbuildable media store is a hard
/// server-boot failure, so the env is handed over only when MinIO actually
/// answers — anything else degrades honestly to the Postgres bytea tier.
async fn wait_for_minio() -> bool {
    let started = Instant::now();
    loop {
        match container_health("verity-minio") {
            Some(true) => break,
            Some(false) if started.elapsed() < Duration::from_secs(45) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            _ => {
                println!(
                    "  {} {}  minio (container verity-minio) not healthy within 45s — media \
                     tier: not available — blobs stay in Postgres (dev fallback). Inspect with \
                     `docker logs verity-minio`, then re-run `verity-cli dev`",
                    ui::yellow("…"),
                    ui::pad("minio", 8)
                );
                return false;
            }
        }
    }
    // Bucket bootstrap: minio-init is a one-shot container (exits 0 after
    // `mc mb --ignore-existing`). If it is absent (pruned), proceed anyway —
    // an existing bucket still works and the media probe reports the truth.
    let bucket_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let init = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{.State.Status}} {{.State.ExitCode}}",
                "verity-minio-init",
            ])
            .output();
        match init {
            Ok(out) if out.status.success() => {
                let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if state == "exited 0" {
                    break;
                }
                if state.starts_with("exited") {
                    println!(
                        "  {} {}  bucket bootstrap (verity-minio-init) exited non-zero — check \
                         `docker logs verity-minio-init`; wiring the media tier anyway (an \
                         existing {} bucket still works; the media plane line reports the truth)",
                        ui::yellow("…"),
                        ui::pad("minio", 8),
                        doctor::MINIO_BUCKET
                    );
                    break;
                }
            }
            _ => break, // container absent: nothing to wait on
        }
        if Instant::now() > bucket_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    ui::step_ok(
        "minio",
        &format!(
            "healthy after {:.1}s — media tier (bucket {}) wired into the server",
            started.elapsed().as_secs_f32(),
            doctor::MINIO_BUCKET
        ),
    );
    true
}

// ---------- (b4) Temporal — observed only, dev never blocks on it ----------

/// Bounded (30s) wait for `verity-temporal`, purely so the summary can say
/// something true. The Rust server has no Temporal client — the Python
/// connector workers (ingest/) connect to it separately — so nothing is
/// wired into the spawned server either way.
async fn wait_for_temporal() {
    let started = Instant::now();
    loop {
        match container_health("verity-temporal") {
            Some(true) => {
                ui::step_ok(
                    "temporal",
                    &format!(
                        "healthy after {:.1}s — connector schedules available (workers run via \
                         ingest/)",
                        started.elapsed().as_secs_f32()
                    ),
                );
                return;
            }
            Some(false) if started.elapsed() < Duration::from_secs(30) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            _ => {
                println!(
                    "  {} {}  temporal (container verity-temporal) not healthy within 30s — \
                     optional plane, continuing without it (connector schedules only; \
                     `docker logs verity-temporal` to inspect)",
                    ui::yellow("…"),
                    ui::pad("temporal", 8)
                );
                return;
            }
        }
    }
}

// ---------- (b5) persistent dev signing key ----------

/// Read or create ~/.verity/dev-signing-key: 64 hex chars, file mode 0600,
/// handed to the spawned server as VERITY_SCOPE_KEY (scope.rs from_env) so
/// scope handles and purge-report signatures survive restarts. The key is
/// NEVER printed. Failure degrades to the server's ephemeral per-process key
/// (disclosed by the signing-key plane line), it never blocks dev.
fn ensure_dev_signing_key(ctx: &Ctx) -> Option<String> {
    let path = doctor::signing_key_path(ctx);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let existing = existing.trim().to_string();
        if existing.len() == 64 && existing.bytes().all(|b| b.is_ascii_hexdigit()) {
            ui::step_ok(
                "signing key",
                &format!("reusing {} (0600, never printed)", path.display()),
            );
            return Some(existing);
        }
        println!(
            "  {} {}  {} exists but is not 64 hex chars — regenerating (old handles die once)",
            ui::yellow("…"),
            ui::pad("sign key", 8),
            path.display()
        );
    }
    let mut key = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut key);
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    if let Err(e) = std::fs::write(&path, &hex) {
        println!(
            "  {} {}  cannot write {} ({e}) — the server falls back to an ephemeral key \
             (handles will die on restart)",
            ui::yellow("…"),
            ui::pad("sign key", 8),
            path.display()
        );
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    ui::step_ok(
        "signing key",
        &format!("generated {} (0600, never printed)", path.display()),
    );
    Some(hex)
}

// ---------- (c) build if missing, spawn, wait for /healthz ----------

fn ensure_server_built(repo: &Path) -> Result<PathBuf> {
    let bin = repo.join("target").join("release").join("verity");
    if bin.is_file() {
        return Ok(bin);
    }
    println!(
        "  {} {}  release binary missing — building verity-server (first run only, a few minutes)",
        ui::yellow("…"),
        ui::pad("build", 8)
    );
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "verity-server"])
        .current_dir(repo)
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "cargo not found on PATH\n  → install Rust via https://rustup.rs and re-run `verity-cli dev`"
                )
            } else {
                anyhow::anyhow!("failed to run cargo build: {e}")
            }
        })?;
    if !status.success() {
        bail!("cargo build --release -p verity-server failed — fix the build and re-run `verity-cli dev`");
    }
    if !bin.is_file() {
        bail!("build succeeded but {} is missing", bin.display());
    }
    Ok(bin)
}

/// One spawn attempt's terminal state: healthy, or exited before /healthz.
enum SpawnOutcome {
    Ready,
    ExitedEarly(std::process::ExitStatus),
}

/// Which planes get wired into the spawned server's environment. Dropped one
/// at a time (watch → spicedb → media) when the server exits at boot, so a
/// single unusable plane can never block dev — every drop is announced.
#[derive(Clone, Copy)]
struct SpawnPlan {
    spicedb: bool,
    /// VERITY_SPICEDB_WATCH=1 — only ever true alongside `spicedb` (a
    /// configured-but-unusable watch stream hard-fails server boot).
    watch: bool,
    media: bool,
}

async fn spawn_and_wait(
    ctx: &Ctx,
    repo: &Path,
    bin: &Path,
    spicedb: bool,
    minio: bool,
    signing_key: Option<String>,
) -> Result<()> {
    let log_path = ctx
        .config_path
        .parent()
        .map(|d| d.join("server.log"))
        .unwrap_or_else(|| PathBuf::from("verity-server.log"));
    if let Some(dir) = log_path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    // Full wiring first; the server hard-fails boot on a configured-but-
    // unusable plane (watch stream, SpiceDB schema, media store) — that is
    // ITS honest posture, and this ladder is ours: drop the failing plane,
    // say so, retry. Dev never blocks; the summary reports what stuck.
    let mut plan = SpawnPlan {
        spicedb,
        watch: spicedb,
        media: minio,
    };
    loop {
        match try_spawn(ctx, repo, bin, &log_path, plan, signing_key.as_deref()).await? {
            SpawnOutcome::Ready => return Ok(()),
            SpawnOutcome::ExitedEarly(status) if plan.watch => {
                println!(
                    "  {} {}  the server exited immediately with the watch consumer configured \
                     ({status}, see {}) — retrying without VERITY_SPICEDB_WATCH; out-of-band \
                     revocations fall back to the windowed baseline",
                    ui::yellow("…"),
                    ui::pad("watch", 8),
                    log_path.display()
                );
                plan.watch = false;
            }
            SpawnOutcome::ExitedEarly(status) if plan.spicedb => {
                println!(
                    "  {} {}  the server exited immediately with the identity plane configured \
                     ({status}, see {}) — retrying without it; sessions use raw keys (dev fallback)",
                    ui::yellow("…"),
                    ui::pad("spicedb", 8),
                    log_path.display()
                );
                plan.spicedb = false;
            }
            SpawnOutcome::ExitedEarly(status) if plan.media => {
                println!(
                    "  {} {}  the server exited immediately with the media object store \
                     configured ({status}, see {}) — retrying on the Postgres bytea fallback",
                    ui::yellow("…"),
                    ui::pad("minio", 8),
                    log_path.display()
                );
                plan.media = false;
            }
            SpawnOutcome::ExitedEarly(status) => bail!(
                "the server exited immediately ({status})\n  → read {} for the reason (usually the DB DSN or a port already in use)",
                log_path.display()
            ),
        }
    }
}

async fn try_spawn(
    ctx: &Ctx,
    repo: &Path,
    bin: &Path,
    log_path: &Path,
    plan: SpawnPlan,
    signing_key: Option<&str>,
) -> Result<SpawnOutcome> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("cannot open server log {}", log_path.display()))?;
    // The spawned server must listen where this invocation expects it
    // (--url may point off the 7717 default).
    let listen = ctx
        .url
        .strip_prefix("http://")
        .or_else(|| ctx.url.strip_prefix("https://"))
        .unwrap_or("127.0.0.1:7717");
    let mut cmd = Command::new(bin);
    cmd.args(["--listen", listen])
        .current_dir(repo)
        .stdin(Stdio::null())
        .stdout(log.try_clone().context("log handle clones")?)
        .stderr(log);
    if plan.spicedb {
        // rebac.rs reads exactly these: URL enables ReBAC, KEY is the
        // preshared bearer. The server writes the SpiceDB schema itself at
        // boot (ensure_schema) — no separate bootstrap call is needed.
        cmd.env("VERITY_SPICEDB_URL", SPICEDB_URL)
            .env("VERITY_SPICEDB_KEY", SPICEDB_KEY);
    }
    if plan.watch {
        // rebac_watch.rs: out-of-band SpiceDB membership DELETEs materialize
        // as revocation tombstones without waiting for the window/next mint.
        cmd.env("VERITY_SPICEDB_WATCH", "1");
    }
    if plan.media {
        // media.rs from_env: both ENDPOINT and BUCKET enable the object-store
        // tier; the credentials are the compose file's dev defaults.
        cmd.env("VERITY_MEDIA_S3_ENDPOINT", doctor::MINIO_ENDPOINT)
            .env("VERITY_MEDIA_BUCKET", doctor::MINIO_BUCKET)
            .env("VERITY_MEDIA_ACCESS_KEY", doctor::MINIO_ACCESS_KEY)
            .env("VERITY_MEDIA_SECRET_KEY", doctor::MINIO_SECRET_KEY);
    }
    if let Some(key) = signing_key {
        // scope.rs from_env: 64 hex chars → persistent HMAC key; handles and
        // purge-report signatures survive restarts.
        cmd.env("VERITY_SCOPE_KEY", key);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("cannot start {}", bin.display()))?;
    let pid = child.id();

    // First launch may download the query-encoder model; be patient.
    let started = Instant::now();
    loop {
        if util::healthz(&ctx.http, &ctx.url).await {
            ui::step_ok(
                "server",
                &format!(
                    "listening at {} (pid {pid}, logs {}) after {:.1}s",
                    ctx.url,
                    log_path.display(),
                    started.elapsed().as_secs_f32()
                ),
            );
            return Ok(SpawnOutcome::Ready);
        }
        if let Some(status) = child.try_wait().ok().flatten() {
            return Ok(SpawnOutcome::ExitedEarly(status));
        }
        if started.elapsed() > Duration::from_secs(180) {
            bail!(
                "the server did not answer /healthz within 180s (first run downloads the local \
                 embedding model)\n  → watch {} and re-run `verity-cli dev` once it settles",
                log_path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// ---------- (d) tenant ----------

async fn create_tenant(ctx: &Ctx) -> Result<String> {
    let mut req = ctx
        .http
        .post(format!("{}/v1/admin/tenants", ctx.url))
        .json(&serde_json::json!({ "name": "dev" }));
    if let Some(token) = &ctx.config.admin_token {
        req = req.bearer_auth(token);
    }
    let (status, body) = util::send(req, &ctx.url).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!(
            "the server requires an admin token for tenant creation\n  \
             → add admin_token = \"<the server's VERITY_ADMIN_TOKEN>\" to {} and re-run `verity-cli dev`",
            ctx.config_path.display()
        );
    }
    let json = util::expect_json(
        status,
        &body,
        "re-run `verity-cli dev` once the server is healthy",
    )?;
    let tenant_id = json["tenant_id"]
        .as_str()
        .context("tenant response carries tenant_id")?
        .to_string();
    let reused = ctx.config.tenant_id.as_deref() == Some(tenant_id.as_str());
    ui::step_ok(
        "tenant",
        &format!(
            "\"dev\" → {tenant_id}{}",
            if reused { " (reused)" } else { "" }
        ),
    );
    Ok(tenant_id)
}

// ---------- (d2) the named dev principal ----------

/// Register `user:dev` and return its materialized token (FTUE §5.2). The
/// upsert is idempotent — an existing principal keeps its token forever — so
/// re-runs mint the same scope. On a fresh "dev" tenant the token is 1.
async fn register_dev_principal(ctx: &Ctx, tenant_id: &str) -> Result<i32> {
    let mut req = ctx
        .http
        .post(format!("{}/v1/admin/principals", ctx.url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id,
            "principals": [DEV_PRINCIPAL],
        }));
    if let Some(token) = &ctx.config.admin_token {
        req = req.bearer_auth(token);
    }
    let (status, body) = util::send(req, &ctx.url).await?;
    let json = util::expect_json(
        status,
        &body,
        "re-run `verity-cli dev` once the server is healthy",
    )?;
    let token = json["mappings"][DEV_PRINCIPAL]
        .as_i64()
        .with_context(|| format!("principal response carries the {DEV_PRINCIPAL} token"))?
        as i32;
    ui::step_ok("principal", &format!("{DEV_PRINCIPAL} → token {token}"));
    Ok(token)
}

// ---------- (e) the copy-paste summary ----------

fn print_summary(
    ctx: &Ctx,
    tenant_id: &str,
    dev_token: i32,
    expiry_note: &str,
    planes: &[doctor::Plane],
    repo: Option<&Path>,
) {
    let mcp_bin = repo
        .map(|r| r.join("target/release/verity-mcp").display().to_string())
        .unwrap_or_else(|| "/path/to/verity/target/release/verity-mcp".to_string());
    let user = util::actor_sub().unwrap_or_else(|| "user:me".into());
    let console_link = format!("{}/ui?tenant={tenant_id}", ctx.url);

    println!();
    println!("  {}", ui::bold("Verity is up."));
    println!();
    let kv =
        |label: &str, value: &str| println!("    {}  {value}", ui::dim(&format!("{label:<13}")));
    kv("server", &ctx.url);
    kv("console", &console_link);
    kv("tenant", &format!("dev ({tenant_id})"));
    println!(
        "    {}",
        ui::dim(
            "the tenant is the company that owns this space — that's you; your \
             customers live inside it as entities"
        )
    );
    kv(
        "principal",
        &format!(
            "{DEV_PRINCIPAL} (token {dev_token}) — the org-wide key your dev session holds; \
             see People & groups in the console"
        ),
    );
    // Observed, not configured: every plane line below comes from the shared
    // doctor probes, which ran real requests against this very server
    // (re-runnable anytime via `verity-cli doctor`).
    println!();
    for plane in planes {
        doctor::print_plane(plane);
    }
    println!();
    match &ctx.config.scope_handle {
        Some(handle) => {
            kv("scope handle", handle);
            println!(
                "    {}",
                ui::dim(&format!(
                    "org-wide (principals [{dev_token}]), saved to {} — paste it into the \
                     console's Scope panel at {}/ui to decode it and run scoped reads",
                    ctx.config_path.display(),
                    ctx.url
                ))
            );
        }
        None => kv(
            "scope handle",
            &format!(
                "saved to {} (org-wide, principals [{dev_token}])",
                ctx.config_path.display()
            ),
        ),
    }
    println!(
        "    {}",
        ui::dim(&format!(
            "handle expires in {expiry_note} — when verity-cli commands start failing, \
             rerun 'verity-cli dev' to renew"
        ))
    );
    println!();
    println!("  {}", ui::bold("Connect Claude Code (MCP):"));
    println!();
    println!("      claude mcp add verity \\");
    println!("        -e VERITY_URL={} \\", ctx.url);
    println!("        -e VERITY_TENANT_ID={tenant_id} \\");
    println!("        -e VERITY_PRINCIPALS={dev_token} \\");
    println!("        -e VERITY_ACTOR_SUB={user} \\");
    println!("        -e VERITY_ACTOR_AZP=agent:claude-code \\");
    println!("        -- {mcp_bin}");
    println!();
    println!("  {}", ui::bold("Next steps:"));
    println!();
    println!(
        "    open the console — your setup checklist is waiting: {}",
        ui::cyan(&console_link)
    );
    println!();
    let step = |n: u32, what: &str, cmd: &str| {
        println!("    {n}. {}  {}", ui::pad(what, 18), ui::cyan(cmd));
    };
    step(
        1,
        "add a memory",
        &format!("verity-cli add README.md --visibility {dev_token}"),
    );
    step(2, "query it back", "verity-cli query \"what is verity\"");
    step(
        3,
        "wire a webhook",
        &format!("verity-cli webhook mint my-system --visibility {dev_token}"),
    );
    println!();
    println!(
        "    {}",
        ui::dim("every write needs --visibility: Verity never guesses who may see a memory.",)
    );
}
