//! Shared plumbing: HTTP round-trips whose failures say what to DO next,
//! scope minting, repo-root discovery, visibility parsing (the teaching
//! refusal), and the naive HTML→text reducer shared with verity-mcp.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::ui;
use crate::Ctx;

// ---------- HTTP ----------

/// Send a request; a transport failure becomes an error that tells the user
/// how to get a server (`verity-cli dev`) instead of a bare reqwest message.
pub async fn send(
    rb: reqwest::RequestBuilder,
    base_url: &str,
) -> Result<(reqwest::StatusCode, String)> {
    let resp = rb.send().await.map_err(|e| {
        anyhow!(
            "cannot reach the verity server at {base_url} ({root})\n  \
             → start everything locally with `verity-cli dev`, or point at a \
             running server with --url",
            root = source_chain(&e)
        )
    })?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body))
}

/// Non-2xx → an error carrying the server's own words plus a next step;
/// 2xx → parsed JSON.
pub fn expect_json(
    status: reqwest::StatusCode,
    body: &str,
    next_step: &str,
) -> Result<serde_json::Value> {
    if !status.is_success() {
        bail!(
            "the server answered {status}: {body}\n  → {next_step}",
            body = body.trim()
        );
    }
    serde_json::from_str(body)
        .with_context(|| format!("the server answered 2xx but not JSON: {body}"))
}

/// Flatten a reqwest error chain into one line ("error sending request:
/// connection refused" instead of just the outer wrapper).
fn source_chain(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut cur = e.source();
    while let Some(inner) = cur {
        parts.push(inner.to_string());
        cur = inner.source();
    }
    parts.dedup();
    parts.join(": ")
}

/// GET /healthz with a short timeout; true iff the body is "ok".
pub async fn healthz(http: &reqwest::Client, base_url: &str) -> bool {
    match http
        .get(format!("{base_url}/healthz"))
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

// ---------- identity & scopes ----------

/// The tenant everything operates in — or the one instruction that creates it.
pub fn require_tenant(ctx: &Ctx) -> Result<String> {
    ctx.config.tenant_id.clone().ok_or_else(|| {
        anyhow!(
            "no tenant configured in {}\n  \
             → run `verity-cli dev` once: it starts Postgres + the server, \
             creates the \"dev\" tenant, and writes the config",
            ctx.config_path.display()
        )
    })
}

pub fn actor_sub() -> Option<String> {
    std::env::var("USER").ok().map(|u| format!("user:{u}"))
}

/// Mint a scope handle over the given principal tokens. This is the ONLY
/// credential Verity ever issues (SPEC §5e.1); visibility rides inside it.
pub async fn mint_scope(
    ctx: &Ctx,
    tenant_id: &str,
    principals: &[i32],
    actor_azp: &str,
    ttl_seconds: i64,
) -> Result<(String, String)> {
    let body = serde_json::json!({
        "tenant_id": tenant_id,
        "principals": principals,
        "actor_sub": actor_sub(),
        "actor_azp": actor_azp,
        "ttl_seconds": ttl_seconds,
    });
    let (status, text) = send(
        ctx.http.post(format!("{}/v1/scopes", ctx.url)).json(&body),
        &ctx.url,
    )
    .await?;
    let json = expect_json(
        status,
        &text,
        "scope minting failed — check the tenant id with `verity-cli status`",
    )?;
    let handle = json["scope_handle"]
        .as_str()
        .context("scope response carries scope_handle")?
        .to_string();
    let expires = json["expires_at"].as_str().unwrap_or_default().to_string();
    Ok((handle, expires))
}

/// Decode the readable middle of a `vs_` scope handle. The payload is plain
/// base64 JSON by design — HMAC-signed against tampering, not encrypted.
pub fn decode_handle(handle: &str) -> Result<serde_json::Value> {
    let rest = handle
        .strip_prefix("vs_")
        .context("not a scope handle (expected the vs_ prefix)")?;
    let (body_b64, _sig) = rest
        .split_once('.')
        .context("malformed scope handle (missing signature separator)")?;
    let body = URL_SAFE_NO_PAD
        .decode(body_b64)
        .context("malformed scope handle (payload is not base64)")?;
    serde_json::from_slice(&body).context("scope handle payload is not JSON")
}

// ---------- the teaching refusal ----------

/// Parse `--visibility 1,7,9`. Omission is a USAGE error (exit 2) that
/// teaches the doctrine instead of pointing at --help: Verity never guesses
/// who may see a memory (SPEC §5e.8 rule 9 — no default visibility, anywhere).
pub fn require_visibility(raw: Option<&str>, example: &str) -> Vec<i32> {
    let refuse = |problem: &str| -> ! {
        eprintln!("{} {problem}", ui::red("refused:"));
        eprintln!();
        eprintln!(
            "  Verity never guesses who may see a memory. Every write carries an\n  \
             explicit visibility decision — pass the principal tokens allowed to\n  \
             read it:"
        );
        eprintln!();
        eprintln!("      {example}");
        eprintln!();
        eprintln!(
            "  {}",
            ui::dim(
                "--visibility 1 is the org-wide token minted by `verity-cli dev`; \
                 comma-separate multiple tokens, e.g. --visibility 1,7,9."
            )
        );
        std::process::exit(2);
    };
    let Some(raw) = raw else {
        refuse("--visibility is required and has no default");
    };
    let mut tokens = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        match part.parse::<i32>() {
            Ok(t) => tokens.push(t),
            Err(_) => refuse(&format!(
                "{part:?} is not a principal token (integer expected)"
            )),
        }
    }
    if tokens.is_empty() {
        refuse("--visibility must carry at least one principal token");
    }
    tokens
}

// ---------- interactive prompts (the connect wizards) ----------

/// Ask on stderr, read one trimmed line from stdin. stderr keeps prompts out
/// of pipelines (`--dry-run` output stays clean when stdout is redirected).
pub fn prompt_line(label: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    eprint!("  {label}: ");
    std::io::stderr().flush().ok();
    let mut buf = String::new();
    let n = std::io::stdin()
        .lock()
        .read_line(&mut buf)
        .context("cannot read from stdin")?;
    if n == 0 {
        bail!("stdin closed while waiting for the {label}");
    }
    Ok(buf.trim().to_string())
}

/// Like `prompt_line`, but with echo disabled when stdin is a terminal —
/// tokens should not linger on screen. Piped stdin (scripts, tests) has
/// nothing to hide and falls back to a plain line read.
pub fn prompt_secret(label: &str) -> Result<String> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return prompt_line(label);
    }
    eprint!("  {label} {}: ", ui::dim("(input hidden)"));
    std::io::stderr().flush().ok();
    let secret = rpassword::read_password().context("cannot read the token from the terminal")?;
    eprintln!(); // read_password suppresses the echo of Enter too
    Ok(secret.trim().to_string())
}

// ---------- repo discovery ----------

/// Find the verity checkout (the dir holding deploy/docker-compose.yml):
/// --repo flag → walk up from the running binary → $VERITY_REPO → walk up
/// from the current directory.
pub fn repo_root(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = explicit {
        if is_repo(dir) {
            return Ok(dir.to_path_buf());
        }
        bail!(
            "--repo {} does not contain deploy/docker-compose.yml — point it at the verity checkout",
            dir.display()
        );
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(found) = walk_up(&exe) {
            return Ok(found);
        }
    }
    if let Some(env_repo) = std::env::var_os("VERITY_REPO") {
        let dir = PathBuf::from(env_repo);
        if is_repo(&dir) {
            return Ok(dir);
        }
        bail!(
            "$VERITY_REPO={} does not contain deploy/docker-compose.yml",
            dir.display()
        );
    }
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(found) = walk_up(&cwd) {
            return Ok(found);
        }
    }
    bail!(
        "cannot find the verity repo (no deploy/docker-compose.yml above the \
         binary or the current directory)\n  \
         → pass --repo /path/to/verity or set VERITY_REPO"
    )
}

fn is_repo(dir: &Path) -> bool {
    dir.join("deploy").join("docker-compose.yml").is_file()
}

fn walk_up(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|a| is_repo(a))
        .map(Path::to_path_buf)
}

// ---------- HTML → text (mirrors verity-mcp's reducer) ----------

/// Naive HTML → text: drop <script>/<style> blocks, strip every tag, decode
/// the common entities, collapse whitespace. Good enough for recall indexing;
/// deliberately no HTML-parser dependency (same trade as verity-mcp).
pub fn html_to_text(html: &str) -> String {
    let html = strip_tag_blocks(html, "script");
    let html = strip_tag_blocks(&html, "style");
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                text.push(' '); // tags separate words: "<p>a</p><p>b</p>" -> "a b"
            }
            '>' if in_tag => in_tag = false,
            _ if in_tag => {}
            _ => text.push(c),
        }
    }
    let text = text
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Remove `<tag …>…</tag>` blocks (case-insensitive), content included.
fn strip_tag_blocks(html: &str, tag: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}");
    let mut out = String::with_capacity(html.len());
    let mut pos = 0;
    while let Some(found) = lower[pos..].find(&open) {
        let start = pos + found;
        out.push_str(&html[pos..start]);
        pos = match lower[start..].find(&close) {
            Some(rel) => {
                let close_start = start + rel;
                match lower[close_start..].find('>') {
                    Some(gt) => close_start + gt + 1,
                    None => lower.len(),
                }
            }
            None => lower.len(),
        };
    }
    out.push_str(&html[pos..]);
    out
}

// ---------- time ----------

/// "11h 58m" / "42m" / "under a minute" — for handle-expiry display.
pub fn human_remaining(until: chrono::DateTime<chrono::Utc>) -> String {
    let secs = (until - chrono::Utc::now()).num_seconds();
    if secs <= 0 {
        return "already expired".into();
    }
    let (h, m) = (secs / 3600, (secs % 3600) / 60);
    match (h, m) {
        (0, 0) => "under a minute".into(),
        (0, m) => format!("{m}m"),
        (h, m) => format!("{h}h {m}m"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_reducer_strips_scripts_and_entities() {
        let html = "<html><script>var x = 1;</script><p>a&amp;b</p><p>c</p></html>";
        assert_eq!(html_to_text(html), "a&b c");
    }

    #[test]
    fn handle_decode_reads_the_signed_payload() {
        let payload = serde_json::json!({"principals": [1], "expires_at": "2026-01-01T00:00:00Z"});
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let handle = format!("vs_{body}.c2ln");
        let decoded = decode_handle(&handle).unwrap();
        assert_eq!(decoded["principals"][0], 1);
        assert!(decode_handle("not-a-handle").is_err());
    }
}
