//! `verity-cli add <path|url|->` — SPEC §5e.1 entry point #2 (files) riding
//! entry point #5 (/v1/files). The server derives a memory's visibility from
//! the scope handle it was written under, so `add` first mints a scope whose
//! principals are EXACTLY the --visibility tokens (actor cli:add) and uploads
//! under that handle. No tokens, no scope, no write — fail closed.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tokio::io::AsyncReadExt;

use crate::{ui, util, Ctx};

/// Text-like extensions ingested from a directory walk (matches the server's
/// notion of indexable text plus what verity-mcp accepts).
const TEXT_EXTENSIONS: [&str; 5] = ["txt", "md", "json", "csv", "html"];
/// Directory ingestion cap.
const MAX_DIR_FILES: usize = 200;
/// URL download cap (2 MB) and timeout, mirroring verity-mcp.
const MAX_URL_BYTES: usize = 2 * 1024 * 1024;
const URL_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn run(
    ctx: &Ctx,
    target: &str,
    visibility: Option<&str>,
    entities: &[String],
) -> Result<()> {
    let tokens = util::require_visibility(
        visibility,
        &format!("verity-cli add {target} --visibility 1"),
    );
    let tenant = util::require_tenant(ctx)?;
    let (handle, _) = util::mint_scope(ctx, &tenant, &tokens, "cli:add", 3600).await?;
    println!(
        "{}",
        ui::dim(&format!(
            "scope minted over principals {tokens:?} (actor cli:add) — uploads inherit exactly that visibility"
        ))
    );

    let entities_field = if entities.is_empty() {
        None
    } else {
        Some(entities.join(","))
    };

    if target == "-" {
        add_stdin(ctx, &handle, entities_field.as_deref()).await
    } else if target.starts_with("http://") || target.starts_with("https://") {
        add_url(ctx, &handle, target, entities_field.as_deref()).await
    } else {
        let path = Path::new(target);
        if path.is_dir() {
            add_dir(ctx, &handle, path, entities_field.as_deref()).await
        } else if path.is_file() {
            let chunks = upload_path(ctx, &handle, path, entities_field.as_deref()).await?;
            finish(1, chunks);
            Ok(())
        } else {
            bail!(
                "{target} is not a file, directory, http(s) URL, or '-'\n  \
                 → pass something that exists, e.g. `verity-cli add notes.md --visibility 1` \
                 or `echo hi | verity-cli add - --visibility 1`"
            );
        }
    }
}

fn finish(files: usize, chunks: u64) {
    println!();
    println!(
        "  {} {chunks} chunk(s) indexed from {files} file(s) — try  {}",
        ui::green("✓"),
        ui::cyan("verity-cli query \"<something in it>\"")
    );
}

// ---------- single file ----------

async fn upload_path(ctx: &Ctx, handle: &str, path: &Path, entities: Option<&str>) -> Result<u64> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("cannot read {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file.txt")
        .to_string();
    let mime = mime_for(path);
    upload(ctx, handle, name, mime, bytes, entities).await
}

/// Multipart POST /v1/files. The server decides text-likeness (text/* and
/// .md index into recall; anything else is store-only media).
async fn upload(
    ctx: &Ctx,
    handle: &str,
    filename: String,
    mime: &str,
    bytes: Vec<u8>,
    entities: Option<&str>,
) -> Result<u64> {
    let mut form = reqwest::multipart::Form::new().text("scope_handle", handle.to_string());
    if let Some(entities) = entities {
        form = form.text("entities", entities.to_string());
    }
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(filename)
        .mime_str(mime)
        .context("static mime strings parse")?;
    form = form.part("file", part);
    let (status, body) = util::send(
        ctx.http
            .post(format!("{}/v1/files", ctx.url))
            .multipart(form),
        &ctx.url,
    )
    .await?;
    let json = util::expect_json(
        status,
        &body,
        "if the scope was rejected, re-run `verity-cli dev` and retry",
    )?;
    Ok(json["chunks_indexed"].as_u64().unwrap_or(0))
}

fn mime_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("md") => "text/markdown",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("html") => "text/html",
        _ => "text/plain",
    }
}

// ---------- directory ----------

async fn add_dir(ctx: &Ctx, handle: &str, root: &Path, entities: Option<&str>) -> Result<()> {
    let (files, matched) = collect_text_files(root);
    if files.is_empty() {
        bail!(
            "no text-like files under {} (looked for .{})\n  \
             → point `add` at files with those extensions, or pipe content in with '-'",
            root.display(),
            TEXT_EXTENSIONS.join(" .")
        );
    }
    if matched > files.len() {
        println!(
            "{}",
            ui::yellow(&format!(
                "note: {matched} matching files found, ingesting the first {MAX_DIR_FILES} (cap)"
            ))
        );
    }
    let total = files.len();
    let (mut ok, mut failed, mut chunks) = (0usize, 0usize, 0u64);
    for (i, file) in files.iter().enumerate() {
        let rel = file.strip_prefix(root).unwrap_or(file).display();
        let counter = format!("[{:>3}/{total}]", i + 1);
        match upload_path(ctx, handle, file, entities).await {
            Ok(n) => {
                ok += 1;
                chunks += n;
                println!(
                    "  {} {rel}  {}",
                    ui::dim(&counter),
                    ui::dim(&format!("→ {n} chunk(s)"))
                );
            }
            Err(e) => {
                failed += 1;
                println!("  {} {rel}  {} {e:#}", ui::dim(&counter), ui::red("✗"));
            }
        }
    }
    if failed > 0 {
        println!(
            "  {}",
            ui::yellow(&format!("{failed} file(s) failed — see lines above"))
        );
    }
    finish(ok, chunks);
    Ok(())
}

/// Depth-first, name-sorted walk collecting text-like files. Hidden entries
/// are skipped. Returns (capped list, total matched) so the cap is reported.
fn collect_text_files(root: &Path) -> (Vec<PathBuf>, usize) {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            let hidden = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.'));
            if hidden {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .is_some_and(|e| TEXT_EXTENSIONS.contains(&e.as_str()))
            {
                found.push(path);
            }
        }
    }
    found.sort();
    let matched = found.len();
    found.truncate(MAX_DIR_FILES);
    (found, matched)
}

// ---------- URL ----------

async fn add_url(ctx: &Ctx, handle: &str, url: &str, entities: Option<&str>) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("invalid URL {url}"))?;
    let resp = ctx
        .http
        .get(parsed.clone())
        .timeout(URL_FETCH_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("failed to fetch {url} (10s timeout)"))?;
    if !resp.status().is_success() {
        bail!(
            "fetching {url} answered HTTP {}\n  → check the URL in a browser, then retry",
            resp.status()
        );
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut resp = resp;
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("failed while reading {url}"))?
    {
        if bytes.len() + chunk.len() > MAX_URL_BYTES {
            bail!("response from {url} exceeds the 2 MB cap — ingest a smaller page");
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8(bytes).map_err(|_| {
        anyhow::anyhow!("response from {url} is not UTF-8 text — `add` ingests text content only")
    })?;
    let looks_like_html = content_type.contains("html")
        || body
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("<!doctype")
        || body.trim_start().to_ascii_lowercase().starts_with("<html");
    let content = if looks_like_html {
        util::html_to_text(&body)
    } else {
        body
    };
    if content.trim().is_empty() {
        bail!("no textual content extracted from {url}");
    }
    let filename = parsed
        .path()
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("webpage")
        .to_string();
    let filename = if filename.contains('.') {
        format!("{}.txt", filename.replace('.', "-"))
    } else {
        format!("{filename}.txt")
    };
    let chunks = upload(
        ctx,
        handle,
        filename,
        "text/plain",
        content.into_bytes(),
        entities,
    )
    .await?;
    finish(1, chunks);
    Ok(())
}

// ---------- stdin ----------

async fn add_stdin(ctx: &Ctx, handle: &str, entities: Option<&str>) -> Result<()> {
    let mut buf = Vec::new();
    tokio::io::stdin()
        .read_to_end(&mut buf)
        .await
        .context("cannot read stdin")?;
    if buf.is_empty() {
        bail!("stdin was empty — pipe some text in, e.g. `echo \"note\" | verity-cli add - --visibility 1`");
    }
    let chunks = upload(ctx, handle, "stdin.txt".into(), "text/plain", buf, entities).await?;
    finish(1, chunks);
    Ok(())
}
