//! `verity fsck` — read-only cross-store integrity scan. Renders the server's
//! `GET /v1/admin/fsck` report and exits non-zero when any `error`-severity
//! finding exists (so it drops into CI / cron as a health gate).

use anyhow::{bail, Context, Result};

use crate::{ui, Ctx};

pub async fn run(ctx: &Ctx, tenant: Option<&str>, json: bool) -> Result<()> {
    let mut url = format!("{}/v1/admin/fsck", ctx.url);
    if let Some(t) = tenant {
        url.push_str(&format!("?tenant_id={t}"));
    }
    let mut req = ctx.http.get(&url);
    if let Some(tok) = &ctx.config.admin_token {
        req = req.bearer_auth(tok);
    }
    let resp = req.send().await.context("GET /v1/admin/fsck")?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.context("parse fsck response")?;
    if !status.is_success() {
        bail!("fsck failed ({status}): {body}");
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        let findings = body["findings"].as_array().cloned().unwrap_or_default();
        println!();
        println!("  {} cross-store integrity scan", ui::bold("verity fsck"));
        if let Some(t) = body["scanned_tenant"].as_str() {
            println!("  {}", ui::dim(&format!("tenant {t}")));
        } else {
            println!("  {}", ui::dim("whole store"));
        }
        println!();
        if findings.is_empty() {
            println!("  {} no findings", ui::green("✓"));
        }
        for f in &findings {
            let sev = f["severity"].as_str().unwrap_or("info");
            let marker = match sev {
                "error" => ui::red("✗"),
                "warn" => ui::yellow("!"),
                _ => ui::dim("·"),
            };
            println!(
                "  {marker} {} {} — {}",
                ui::bold(f["check"].as_str().unwrap_or("?")),
                ui::dim(&format!("({})", f["count"].as_i64().unwrap_or(0))),
                f["detail"].as_str().unwrap_or(""),
            );
        }
        println!();
        if body["ok"].as_bool().unwrap_or(false) {
            println!("  {} integrity OK", ui::green("✓"));
        } else {
            println!("  {} integrity violations found", ui::red("✗"));
        }
    }

    if !body["ok"].as_bool().unwrap_or(false) {
        std::process::exit(1);
    }
    Ok(())
}
