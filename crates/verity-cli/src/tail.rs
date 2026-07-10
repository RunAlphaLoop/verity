//! `verity-cli tail` — watch the quarantine (GET /v1/admin/quarantine every
//! 2s). Quarantine is where fail-closed becomes visible: payloads Verity
//! refused to index permissively land here for review, never silently.

use std::collections::HashSet;

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};

use crate::{ui, util, Ctx};

const POLL: std::time::Duration = std::time::Duration::from_secs(2);

pub async fn run(ctx: &Ctx, once: bool) -> Result<()> {
    let tenant = util::require_tenant(ctx)?;
    let rows = fetch(ctx, &tenant).await?;
    if once {
        if rows.is_empty() {
            println!(
                "{} quarantine is empty — nothing has been refused",
                ui::green("✓")
            );
        } else {
            for row in rows.iter().rev() {
                print_row(row);
            }
        }
        return Ok(());
    }

    println!(
        "{} tailing quarantine for tenant {tenant} every 2s — {}",
        ui::cyan("◆"),
        ui::dim("Ctrl-C to stop")
    );
    let mut seen: HashSet<String> = HashSet::new();
    // First fetch prints existing rows as context, oldest first.
    for row in rows.iter().rev() {
        if seen.insert(row_id(row)) {
            print_row(row);
        }
    }
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n{} stopped", ui::dim("·"));
                return Ok(());
            }
            _ = tokio::time::sleep(POLL) => {}
        }
        let rows = match fetch(ctx, &tenant).await {
            Ok(rows) => rows,
            Err(e) => {
                println!("{} {e:#}", ui::yellow("!"));
                continue;
            }
        };
        for row in rows.iter().rev() {
            if seen.insert(row_id(row)) {
                print_row(row);
            }
        }
    }
}

fn row_id(row: &serde_json::Value) -> String {
    row["id"].as_str().unwrap_or_default().to_string()
}

async fn fetch(ctx: &Ctx, tenant: &str) -> Result<Vec<serde_json::Value>> {
    let mut req = ctx
        .http
        .get(format!("{}/v1/admin/quarantine", ctx.url))
        .query(&[("tenant_id", tenant), ("limit", "100")]);
    if let Some(token) = &ctx.config.admin_token {
        req = req.bearer_auth(token);
    }
    let (status, body) = util::send(req, &ctx.url).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!(
            "the quarantine feed is an admin surface and the server asked for a bearer token\n  \
             → add admin_token = \"<the server's VERITY_ADMIN_TOKEN value>\" to {}",
            ctx.config_path.display()
        );
    }
    let json = util::expect_json(status, &body, "retry once the server is healthy")?;
    Ok(json.as_array().cloned().unwrap_or_default())
}

fn print_row(row: &serde_json::Value) {
    let at = row["at"]
        .as_str()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .map(|t| t.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "??:??:??".into());
    let id = row["id"].as_str().unwrap_or("?");
    let short_id: String = id.chars().take(8).collect();
    let reason = row["reason"].as_str().unwrap_or("?");
    let payload = serde_json::to_string(&row["payload"]).unwrap_or_default();
    println!(
        "  {} {} {}  {}",
        ui::dim(&at),
        ui::dim(&format!("{short_id}…")),
        ui::yellow(reason),
        ui::dim(&ui::truncate(&payload, 80))
    );
}
