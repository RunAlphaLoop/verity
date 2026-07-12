//! `verity-cli dev` — empty laptop to permission-filtered query in five
//! minutes (SPEC §5e.1 entry point #2). Each phase is idempotent: a healthy
//! /healthz skips docker + spawn entirely, the "dev" tenant upserts to the
//! same id, and re-minting the scope just refreshes its expiry.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::{config, ui, util, Ctx};

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

pub async fn run(ctx: &mut Ctx, repo_flag: Option<PathBuf>) -> Result<()> {
    ui::banner("verity dev — local memory plane, five minutes");
    println!();

    // Repo discovery is best-effort while the server is already up (we only
    // need it for the mcp binary path in the summary), mandatory otherwise.
    let repo = util::repo_root(repo_flag.as_deref());

    // (a)–(c) infrastructure, skipped wholesale when /healthz already answers.
    if util::healthz(&ctx.http, &ctx.url).await {
        ui::step_ok(
            "server",
            &format!("already running at {} — reusing it", ctx.url),
        );
    } else {
        let repo = repo.as_ref().map_err(|e| anyhow::anyhow!("{e}"))?;
        docker_up(repo)?;
        wait_for_postgres().await?;
        // Identity plane (SPEC §7a): dev ships with it ON. The wait is
        // bounded and NON-FATAL — SpiceDB trouble degrades to raw-key
        // sessions, disclosed in the summary; it never blocks dev.
        let spicedb_up = wait_for_spicedb().await;
        let bin = ensure_server_built(repo)?;
        spawn_and_wait(ctx, repo, &bin, spicedb_up).await?;
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

    // The identity-plane summary line reports OBSERVED server behavior, not
    // what this process configured: a reused server may or may not have
    // ReBAC wired, so probe with a real subject-based mint (the production
    // shape) and let the outcome speak.
    let identity_live = identity_plane_live(ctx, &tenant_id).await;

    ctx.config.url = Some(ctx.url.clone());
    ctx.config.tenant_id = Some(tenant_id.clone());
    ctx.config.scope_handle = Some(handle);
    ctx.config.principals = Some(vec![dev_token]);
    config::save(&ctx.config_path, &ctx.config)?;
    ui::step_ok("config", &ctx.config_path.display().to_string());

    // (e) the summary people copy-paste from.
    print_summary(
        ctx,
        &tenant_id,
        dev_token,
        &expiry_note,
        identity_live,
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
    // No service filter on purpose: `up -d` starts EVERY compose service,
    // spicedb (the identity plane) included.
    ui::step_ok("compose", "docker compose up -d (paradedb pg17 + spicedb)");
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

async fn spawn_and_wait(ctx: &Ctx, repo: &Path, bin: &Path, spicedb: bool) -> Result<()> {
    let log_path = ctx
        .config_path
        .parent()
        .map(|d| d.join("server.log"))
        .unwrap_or_else(|| PathBuf::from("verity-server.log"));
    if let Some(dir) = log_path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    if spicedb {
        // A server configured with ReBAC refuses to boot when SpiceDB turns
        // unusable between our health check and its schema write. Dev never
        // blocks on SpiceDB: one honest retry without the identity plane.
        match try_spawn(ctx, repo, bin, &log_path, true).await? {
            SpawnOutcome::Ready => return Ok(()),
            SpawnOutcome::ExitedEarly(status) => println!(
                "  {} {}  the server exited immediately with the identity plane configured \
                 ({status}, see {}) — retrying without it; sessions use raw keys (dev fallback)",
                ui::yellow("…"),
                ui::pad("spicedb", 8),
                log_path.display()
            ),
        }
    }
    match try_spawn(ctx, repo, bin, &log_path, false).await? {
        SpawnOutcome::Ready => Ok(()),
        SpawnOutcome::ExitedEarly(status) => bail!(
            "the server exited immediately ({status})\n  → read {} for the reason (usually the DB DSN or a port already in use)",
            log_path.display()
        ),
    }
}

async fn try_spawn(
    ctx: &Ctx,
    repo: &Path,
    bin: &Path,
    log_path: &Path,
    spicedb: bool,
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
    if spicedb {
        // rebac.rs reads exactly these: URL enables ReBAC, KEY is the
        // preshared bearer. The server writes the SpiceDB schema itself at
        // boot (ensure_schema) — no separate bootstrap call is needed.
        cmd.env("VERITY_SPICEDB_URL", SPICEDB_URL)
            .env("VERITY_SPICEDB_KEY", SPICEDB_KEY);
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

// ---------- (d3) identity-plane probe ----------

/// Is subject-based minting live on THIS server? Attempt the production
/// shape — mint a short-lived scope as `user:dev` — and read the outcome:
/// 2xx means the identity plane resolved the subject's keys; the specific
/// 422 (ReBAC off) or any other failure reports "not available". A probe,
/// not a switch: the summary line states what was observed, nothing more.
async fn identity_plane_live(ctx: &Ctx, tenant_id: &str) -> bool {
    let body = serde_json::json!({
        "tenant_id": tenant_id,
        "subject": DEV_PRINCIPAL,
        "actor_sub": DEV_PRINCIPAL,
        "actor_azp": "cli:dev-identity-probe",
        "ttl_seconds": 60,
    });
    match util::send(
        ctx.http.post(format!("{}/v1/scopes", ctx.url)).json(&body),
        &ctx.url,
    )
    .await
    {
        Ok((status, _)) => status.is_success(),
        Err(_) => false,
    }
}

// ---------- (e) the copy-paste summary ----------

fn print_summary(
    ctx: &Ctx,
    tenant_id: &str,
    dev_token: i32,
    expiry_note: &str,
    identity_live: bool,
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
    // Observed, not configured: identity_plane_live() minted (or failed to
    // mint) a real subject-based scope against this very server.
    kv(
        "identity plane",
        if identity_live {
            "connected (SpiceDB) — mint by person works"
        } else {
            "not available — sessions use raw keys (dev fallback)"
        },
    );
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
