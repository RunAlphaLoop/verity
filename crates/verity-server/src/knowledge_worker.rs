//! Console/CLI-owned knowledge consolidation worker lifecycle (SPEC §2 L2).
//!
//! The knowledge worker is an external Python process
//! (`verity_ingest.consolidation`) that leases non-CDC episodes, runs the LLM
//! extractor + judge, and posts candidates into the review queue (auto-publish
//! stays OFF). This module lets a RUNNING server own that child: spawn it,
//! track its pid, report authoritative status, and kill+reap it — the ONE
//! real Start/Stop in the "what's running" System panel.
//!
//! The spawn recipe is the EXACT one `verity-cli dev` used before this landed
//! (`dev.rs::spawn_knowledge_worker`): the ingest venv Python running
//! `verity_ingest.consolidation --base-url … --tenant-id … --extractor
//! anthropic --judge anthropic --interval 30`, cwd `<repo>/ingest`, with
//! `ANTHROPIC_API_KEY` read from `~/.verity-anthropic-key` at spawn time —
//! NEVER embedded, NEVER logged, NEVER returned. ONE owner per server: the CLI
//! `--knowledge` flag now routes through the server start endpoint so a console
//! Start and a CLI start can never stack two workers on one space.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A live consolidation worker THIS server spawned and owns. Presence in
/// `AppState.knowledge_worker` means authoritative status (pid, "started from
/// the console") and a real Stop; absence means the planes endpoint falls back
/// to the `episode_processing` activity proxy.
pub(crate) struct KnowledgeWorker {
    pub(crate) child: Child,
    pub(crate) pid: u32,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) tenant_id: Uuid,
}

/// Why a spawn attempt could not proceed — each maps to a clean HTTP status
/// (NEVER a 500) with the exact fix in the message. `Os` is the runtime spawn
/// failure; the rest are checked preconditions.
pub(crate) enum SpawnError {
    /// The server was not started with `--repo`/`VERITY_REPO`, so it can't find
    /// `ingest/.venv`. → 422.
    NoRepo,
    /// No `<repo>/ingest/.venv/bin/python`. → 422. Carries the exact fix.
    NoVenv(String),
    /// No Anthropic key at `~/.verity-anthropic-key`. → 503.
    NoKey(String),
    /// OS-level failure opening the log or spawning the process. → 503.
    Os(String),
}

/// Where the Anthropic key lives (same file the CLI reads). Read at spawn time,
/// handed to the child as `ANTHROPIC_API_KEY`, never stored or logged.
fn anthropic_key_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".verity-anthropic-key"))
}

/// The interpreter the worker runs under, given the server's repo root.
fn worker_python(repo: &Path) -> PathBuf {
    repo.join("ingest/.venv/bin/python")
}

/// Spawn + track the consolidation worker. `repo_root` is the server's
/// `--repo`/`VERITY_REPO`; `base_url` is derived from `--listen`
/// (`http://<listen>`); `admin_token` (if the server requires one) is passed
/// through so the worker can reach the admin-gated lease/complete endpoints.
///
/// Mirrors `dev.rs::spawn_knowledge_worker` EXACTLY — same args, cwd, env,
/// detached stdio → `consolidation.log`. Returns a tracked `KnowledgeWorker`
/// on success, or a typed `SpawnError` (mapped to 422/503, never 500) on any
/// checked precondition or OS failure.
pub(crate) fn spawn(
    repo_root: Option<&Path>,
    base_url: &str,
    tenant_id: Uuid,
    admin_token: Option<&str>,
) -> Result<KnowledgeWorker, SpawnError> {
    let repo = repo_root.ok_or(SpawnError::NoRepo)?;
    let py = worker_python(repo);
    if !py.exists() {
        return Err(SpawnError::NoVenv(format!(
            "no ingest virtualenv at {} — create it (cd ingest && python -m venv .venv && \
             .venv/bin/pip install -e '.[gdrive]') then try again",
            py.display()
        )));
    }
    let key_path = anthropic_key_path().filter(|p| p.exists()).ok_or_else(|| {
        SpawnError::NoKey(
            "knowledge extraction needs an Anthropic key at ~/.verity-anthropic-key (0600) — \
             add it, then try again"
                .to_string(),
        )
    })?;
    let api_key = std::fs::read_to_string(&key_path)
        .map_err(|e| SpawnError::Os(format!("reading {}: {e}", key_path.display())))?
        .trim()
        .to_string();

    // Log next to the ingest dir so it sits with the worker's own artifacts;
    // the child's stdout/stderr are detached into it (never inherited).
    let log_path = repo.join("ingest").join("consolidation.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| {
            SpawnError::Os(format!(
                "cannot open worker log {}: {e}",
                log_path.display()
            ))
        })?;
    let log2 = log
        .try_clone()
        .map_err(|e| SpawnError::Os(format!("log handle clone: {e}")))?;

    let tenant = tenant_id.to_string();
    let mut cmd = Command::new(&py);
    cmd.args(["-m", "verity_ingest.consolidation", "--base-url"])
        .arg(base_url)
        .args(["--tenant-id"])
        .arg(&tenant)
        // Live LLM extraction + judge — the whole reason to flip this on; the
        // server still gates every candidate through the review queue.
        .args([
            "--extractor",
            "anthropic",
            "--judge",
            "anthropic",
            "--interval",
            "30",
        ])
        .current_dir(repo.join("ingest"))
        .env("ANTHROPIC_API_KEY", api_key)
        .stdin(Stdio::null())
        .stdout(log2)
        .stderr(log);
    if let Some(token) = admin_token {
        cmd.env("VERITY_ADMIN_TOKEN", token);
    }
    let child = cmd.spawn().map_err(|e| {
        SpawnError::Os(format!(
            "cannot start the knowledge worker ({}): {e}",
            py.display()
        ))
    })?;
    let pid = child.id();
    Ok(KnowledgeWorker {
        child,
        pid,
        started_at: Utc::now(),
        tenant_id,
    })
}

/// Whether the ingest venv Python exists for this repo root — used by the
/// planes read to decide `startable` without attempting a spawn.
pub(crate) fn venv_exists(repo_root: Option<&Path>) -> bool {
    repo_root
        .map(|r| worker_python(r).exists())
        .unwrap_or(false)
}

/// Whether an Anthropic key file exists — used by the planes read to decide
/// `startable`. Never reads the key itself here.
pub(crate) fn key_exists() -> bool {
    anthropic_key_path().is_some_and(|p| p.exists())
}
