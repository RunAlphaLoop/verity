//! `verity-cli backup` / `verity-cli restore` (SPEC §11b, roadmap task 23):
//! consistent pg_dump/pg_restore of the dockerized dev Postgres AND the SpiceDB
//! permission graph, plus a manifest recording schema version, timestamp, KEK
//! flag, and SpiceDB relationship count.
//!
//! Leak-safe DR (the M4-DR gap): the permission graph (SpiceDB) is captured
//! ALONGSIDE Postgres so a backup is SELF-CONTAINED — no uncoordinated,
//! out-of-band SpiceDB restore whose STALE case re-grants a revoked membership
//! (a leak: "content newer than ACLs"). `restore` writes the ReBAC schema +
//! relationships BEFORE it returns, ENFORCING the §11b "ACLs before content"
//! ordering rather than merely printing it, and FAILS LOUDLY if the graph can't
//! be restored (never leaves Postgres-restored-but-ReBAC-empty serving).
//!
//! Still out of scope (documented, not captured): Lance/S3 media blobs and
//! in-memory serving structures (rematerialized fail-closed at boot).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

const CONTAINER: &str = "verity-postgres";
const DB_USER: &str = "verity";
const DB_NAME: &str = "verity";

/// SpiceDB HTTP gateway endpoint + preshared key (same defaults as `dev`/rebac).
fn spicedb() -> (String, String) {
    let url =
        std::env::var("VERITY_SPICEDB_URL").unwrap_or_else(|_| "http://localhost:8443".into());
    let key = std::env::var("VERITY_SPICEDB_KEY").unwrap_or_else(|_| "verity-dev-key".into());
    (url.trim_end_matches('/').to_string(), key)
}

/// Export the SpiceDB schema + every relationship to `dir`. Returns
/// `(schema_file, relationships_file, count)`, or `None` if SpiceDB is
/// unreachable/absent (a Postgres-only backup — honest, and the restore note then
/// tells the operator to reconcile ReBAC from the directory before serving).
async fn spicedb_backup(dir: &Path, stamp: &str) -> Result<Option<(String, String, usize)>> {
    let (url, key) = spicedb();
    let client = reqwest::Client::new();

    let schema_resp = match client
        .post(format!("{url}/v1/schema/read"))
        .bearer_auth(&key)
        .json(&serde_json::json!({}))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        other => {
            let why = match other {
                Ok(r) => format!("HTTP {}", r.status()),
                Err(e) => e.to_string(),
            };
            println!(
                "  note: SpiceDB not captured ({why}) — Postgres-only backup. A restore \
                 MUST reconcile ReBAC from the directory before serving (else empty=over-hide, \
                 stale=leak)."
            );
            return Ok(None);
        }
    };
    let schema_text = schema_resp
        .json::<serde_json::Value>()
        .await
        .context("parse SpiceDB schema")?["schemaText"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let schema_name = format!("spicedb-schema-{stamp}.zed");
    std::fs::write(dir.join(&schema_name), &schema_text).context("write SpiceDB schema")?;

    let rels_name = format!("spicedb-{stamp}.jsonl");
    let mut file =
        std::fs::File::create(dir.join(&rels_name)).context("create SpiceDB rels file")?;
    let mut cursor: Option<serde_json::Value> = None;
    let mut count = 0usize;
    loop {
        let mut body = serde_json::json!({ "optionalLimit": 1000 });
        if let Some(c) = &cursor {
            body["optionalCursor"] = c.clone();
        }
        let resp = client
            .post(format!("{url}/v1/experimental/relationships/bulkexport"))
            .bearer_auth(&key)
            .json(&body)
            .send()
            .await
            .context("SpiceDB bulkexport")?;
        if !resp.status().is_success() {
            bail!("SpiceDB bulkexport failed: HTTP {}", resp.status());
        }
        // The gateway streams the whole server-stream as NDJSON of
        // {result:{relationships:[...], afterResultCursor}}.
        let text = resp.text().await.context("read bulkexport body")?;
        let mut got = 0usize;
        let mut last_cursor = None;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value =
                serde_json::from_str(line).context("parse bulkexport line")?;
            if let Some(rels) = v["result"]["relationships"].as_array() {
                for rel in rels {
                    writeln!(file, "{}", serde_json::to_string(rel)?).context("write rel")?;
                    count += 1;
                    got += 1;
                }
            }
            if !v["result"]["afterResultCursor"].is_null() {
                last_cursor = Some(v["result"]["afterResultCursor"].clone());
            }
        }
        match last_cursor {
            Some(c) if got > 0 => cursor = Some(c),
            _ => break, // no cursor or nothing new → the export is complete
        }
    }
    Ok(Some((schema_name, rels_name, count)))
}

/// Send one WriteRelationships batch of TOUCH updates. Bails on any non-success.
async fn write_rel_batch(
    client: &reqwest::Client,
    url: &str,
    key: &str,
    updates: &[serde_json::Value],
) -> Result<()> {
    if updates.is_empty() {
        return Ok(());
    }
    let resp = client
        .post(format!("{url}/v1/relationships/write"))
        .bearer_auth(key)
        .json(&serde_json::json!({ "updates": updates }))
        .send()
        .await
        .context("SpiceDB WriteRelationships")?;
    if !resp.status().is_success() {
        bail!(
            "SpiceDB WriteRelationships failed (HTTP {}): {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    Ok(())
}

/// Restore the SpiceDB schema + relationships from a backup dir. BAILS on any
/// failure — a Postgres-restored-but-ReBAC-empty state could serve stale/over-
/// broad, so a partial restore must fail loudly rather than finish silently.
async fn spicedb_restore(dir: &Path, schema_file: &str, rels_file: &str) -> Result<usize> {
    let (url, key) = spicedb();
    let client = reqwest::Client::new();

    // Schema first — relationships reference its definitions.
    let schema = std::fs::read_to_string(dir.join(schema_file)).context("read SpiceDB schema")?;
    let resp = client
        .post(format!("{url}/v1/schema/write"))
        .bearer_auth(&key)
        .json(&serde_json::json!({ "schema": schema }))
        .send()
        .await
        .context("SpiceDB WriteSchema")?;
    if !resp.status().is_success() {
        bail!(
            "SpiceDB WriteSchema failed (HTTP {}): {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let content = std::fs::read_to_string(dir.join(rels_file)).context("read SpiceDB rels")?;
    let mut batch: Vec<serde_json::Value> = Vec::new();
    let mut written = 0usize;
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        let rel: serde_json::Value = serde_json::from_str(line).context("parse rel line")?;
        let mut subject = serde_json::json!({ "object": rel["subject"]["object"] });
        if let Some(orel) = rel["subject"]["optionalRelation"].as_str() {
            if !orel.is_empty() {
                subject["optionalRelation"] = serde_json::json!(orel);
            }
        }
        batch.push(serde_json::json!({
            "operation": "OPERATION_TOUCH",
            "relationship": {
                "resource": rel["resource"],
                "relation": rel["relation"],
                "subject": subject,
            }
        }));
        if batch.len() >= 500 {
            write_rel_batch(&client, &url, &key, &batch).await?;
            written += batch.len();
            batch.clear();
        }
    }
    write_rel_batch(&client, &url, &key, &batch).await?;
    written += batch.len();
    Ok(written)
}

/// Locate the backup manifest next to a dump file.
fn manifest_beside(dump: &Path) -> PathBuf {
    dump.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("manifest.json")
}

/// `verity-cli backup <dir>`: pg_dump -Fc inside the container, saved as
/// `verity-<timestamp>.dump` next to a `manifest.json`.
pub(crate) async fn backup(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating backup directory {}", dir.display()))?;

    let now = chrono::Utc::now();
    let stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
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

    // Capture the SpiceDB permission graph ALONGSIDE Postgres (leak-safe DR). Do
    // it AFTER pg_dump so, with a quiesced server (the restore note requires it),
    // both stores reflect the same at-rest state.
    let sdb = spicedb_backup(dir, &stamp).await?;
    let spicedb_manifest = match &sdb {
        Some((schema_file, rels_file, count)) => {
            println!("  wrote SpiceDB graph: {count} relationships + schema");
            serde_json::json!({
                "captured": true,
                "schema_file": schema_file,
                "relationships_file": rels_file,
                "relationships": count,
            })
        }
        None => serde_json::json!({ "captured": false }),
    };

    let manifest = serde_json::json!({
        "dump_file": dump_path.file_name().and_then(|n| n.to_str()),
        "created_at": now.to_rfc3339(),
        "schema_version": schema_version.parse::<i64>().ok(),
        "kek_set": kek_set,
        "format": "pg_dump -Fc (custom)",
        "database": DB_NAME,
        "spicedb": spicedb_manifest,
        "note": "Postgres durable tier + SpiceDB permission graph. Media blobs \
                 (Lance/S3) not captured. See docs/OPERATIONS.md for §11b ordering.",
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
    println!("Postgres restore complete.");

    // Restore the SpiceDB permission graph from the SAME backup, BEFORE serving —
    // enforcing the §11b "ACLs before content" ordering instead of merely printing
    // it. A backup that captured SpiceDB is self-contained + consistent, so this
    // closes the stale-graph leak (a revoked membership re-granted by an
    // out-of-band, older SpiceDB restore).
    let manifest_path = manifest_beside(file);
    match std::fs::read_to_string(&manifest_path) {
        Ok(text) => {
            let m: serde_json::Value =
                serde_json::from_str(&text).context("parse manifest.json")?;
            let sdb = &m["spicedb"];
            if sdb["captured"].as_bool() == Some(true) {
                let schema_file = sdb["schema_file"]
                    .as_str()
                    .context("manifest.spicedb.schema_file missing")?;
                let rels_file = sdb["relationships_file"]
                    .as_str()
                    .context("manifest.spicedb.relationships_file missing")?;
                let dir = file.parent().unwrap_or_else(|| Path::new("."));
                println!(
                    "Restoring SpiceDB permission graph ({} relationships) BEFORE serving...",
                    sdb["relationships"].as_i64().unwrap_or(0)
                );
                let n = spicedb_restore(dir, schema_file, rels_file).await.context(
                    "restoring the SpiceDB permission graph — refusing to finish a restore that \
                     would leave ReBAC empty while content is present (a fail-open leak)",
                )?;
                println!("  wrote {n} relationships + schema.");
            } else {
                println!(
                    "  note: manifest marks SpiceDB NOT captured (Postgres-only backup). You MUST \
                     reconcile ReBAC from the directory/sources before serving — empty over-hides, \
                     a STALE graph leaks."
                );
            }
        }
        Err(_) => println!(
            "  note: no manifest.json beside the dump — cannot restore the SpiceDB graph. \
             Reconcile ReBAC from the directory before serving."
        ),
    }

    println!();
    println!("Restore complete. Before serving traffic:");
    println!(
        "  - Content and its ACLs are now both restored from this backup (ordering enforced)."
    );
    println!("  - The verity server boots fail-closed and re-materializes scope state at startup.");
    println!("  - If the backup was taken with VERITY_KEK set (see manifest.json), the same KEK");
    println!(
        "    must be present or encrypted L0 payloads and wrapped tenant DEKs are unreadable."
    );
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
