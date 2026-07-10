//! `verity-cli backup` / `verity-cli restore` (SPEC §11b, roadmap task 23):
//! consistent pg_dump/pg_restore of the dockerized dev Postgres, plus a
//! manifest recording schema version, timestamp, and whether a KEK was set.
//!
//! v0 honesty: this snapshots the **Postgres durable tier only**. SpiceDB
//! state, Lance/S3 blobs, and in-memory serving structures are not captured;
//! the §11b ordering rule (ACLs restored/reconciled BEFORE content serves) is
//! printed after every restore and documented in docs/OPERATIONS.md. The
//! server boots fail-closed regardless, so a restore can't under-hide.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

const CONTAINER: &str = "verity-postgres";
const DB_USER: &str = "verity";
const DB_NAME: &str = "verity";

/// `verity-cli backup <dir>`: pg_dump -Fc inside the container, saved as
/// `verity-<timestamp>.dump` next to a `manifest.json`.
pub(crate) async fn backup(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating backup directory {}", dir.display()))?;

    let now = chrono::Utc::now();
    let stamp = now.format("%Y%m%dT%H%M%SZ");
    let dump_path = dir.join(format!("verity-{stamp}.dump"));

    println!("Dumping {DB_NAME} from container {CONTAINER} (pg_dump -Fc)...");
    // Stream pg_dump's stdout straight into the file — dumps can be multiple
    // GB and must never be buffered in memory.
    let dump_file = std::fs::File::create(&dump_path)
        .with_context(|| format!("creating {}", dump_path.display()))?;
    let output = Command::new("docker")
        .args(["exec", CONTAINER, "pg_dump", "-U", DB_USER, "-Fc", DB_NAME])
        .stdout(Stdio::from(dump_file))
        .stderr(Stdio::piped())
        .spawn()
        .context("running docker exec pg_dump (is Docker running?)")?
        .wait_with_output()
        .context("waiting for pg_dump")?;
    if !output.status.success() {
        let _ = std::fs::remove_file(&dump_path); // never leave a truncated dump behind
        bail!(
            "pg_dump failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let dump_bytes = std::fs::metadata(&dump_path).map(|m| m.len()).unwrap_or(0);

    // Schema version = highest applied sqlx migration, read from the live DB
    // so the manifest states what the dump actually contains.
    let schema_version = query_scalar("SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations")
        .unwrap_or_else(|e| {
            eprintln!("warning: could not read schema version ({e:#}); recording null");
            "null".into()
        });

    // KEK flag: whether the operator's environment has VERITY_KEK set. This
    // reflects the BACKUP environment, not necessarily the server's — an
    // honest hint for the restore runbook, not an attestation.
    let kek_set = std::env::var("VERITY_KEK").map(|v| !v.trim().is_empty()) == Ok(true);

    let manifest = serde_json::json!({
        "dump_file": dump_path.file_name().and_then(|n| n.to_str()),
        "created_at": now.to_rfc3339(),
        "schema_version": schema_version.parse::<i64>().ok(),
        "kek_set": kek_set,
        "format": "pg_dump -Fc (custom)",
        "database": DB_NAME,
        "note": "Postgres durable tier only; see docs/OPERATIONS.md for the \
                 SPEC §11b restore ordering (ReBAC state before serving).",
    });
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .with_context(|| format!("writing {}", manifest_path.display()))?;

    println!("  wrote {} ({dump_bytes} bytes)", dump_path.display());
    println!("  wrote {}", manifest_path.display());
    if !kek_set {
        println!(
            "  note: VERITY_KEK not set in this environment — if the server runs \
             with a KEK, keep it (and this flag) with the backup; the dump's \
             encrypted L0 payloads are unreadable without it."
        );
    }
    Ok(())
}

/// `verity-cli restore <file>`: pg_restore --clean --if-exists into the
/// container, then print the §11b ordering note.
pub(crate) async fn restore(file: &Path) -> Result<()> {
    let mut dump =
        std::fs::File::open(file).with_context(|| format!("reading {}", file.display()))?;

    println!(
        "Restoring {} into {DB_NAME} in container {CONTAINER} (pg_restore --clean --if-exists)...",
        file.display()
    );
    println!("  stop the verity server first: live connections can block DROPs and a serving process must never overlap a restore.");
    let mut child = Command::new("docker")
        .args([
            "exec",
            "-i",
            CONTAINER,
            "pg_restore",
            "-U",
            DB_USER,
            "-d",
            DB_NAME,
            "--clean",
            "--if-exists",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running docker exec pg_restore (is Docker running?)")?;
    {
        let mut stdin = child.stdin.take().expect("stdin was piped");
        std::io::copy(&mut dump, &mut stdin).context("streaming dump into pg_restore")?;
        // stdin drops here, closing the pipe so pg_restore sees EOF.
    }
    let output = child.wait_with_output().context("waiting for pg_restore")?;
    if !output.status.success() {
        bail!(
            "pg_restore failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    println!("Restore complete.");
    println!();
    println!("SPEC §11b restore ordering — read before serving traffic:");
    println!("  1. ReBAC/SpiceDB state must be restored (or reconciled against the");
    println!("     directory/sources) BEFORE this content is served: content newer");
    println!("     than ACLs is permission drift, i.e. a leak.");
    println!("  2. The verity server boots fail-closed and re-materializes scope");
    println!("     state at startup, so a fresh start after (1) is safe by default.");
    println!("  3. If the backup was taken with VERITY_KEK set (see manifest.json),");
    println!("     the same KEK must be present or encrypted L0 payloads and wrapped");
    println!("     tenant DEKs are permanently unreadable.");
    println!("  Full runbook: docs/OPERATIONS.md");
    Ok(())
}

/// Run a single-value psql query inside the container.
fn query_scalar(sql: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "exec", CONTAINER, "psql", "-U", DB_USER, "-d", DB_NAME, "-tAc", sql,
        ])
        .output()
        .context("running docker exec psql")?;
    if !output.status.success() {
        bail!(
            "psql failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
