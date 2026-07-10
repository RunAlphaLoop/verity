//! `verity-cli reembed` — embedding-model migration tooling (SPEC §5c).
//!
//! The encoder lives in the SERVER (the CLI is a pure REST client), so the CLI
//! drives batches and shows progress while the server re-embeds. Two verbs:
//!
//!   reembed --model <id> [--tenant <uuid>] [--batch N]
//!       Loops POST /v1/admin/reembed/batch until every current chunk lacking
//!       embedding_v2 is backfilled from its stored canonical text (never a
//!       re-fetch), printing per-batch coverage.
//!
//!   reembed cutover [--tenant <uuid>] [--to v1|v2] [--force]
//!       Flips the dense query route (POST /v1/admin/reembed/cutover). The
//!       server refuses a v2 cutover below 100% coverage unless --force.
//!
//! Both are admin surfaces: the config's admin_token is sent as a bearer.

use anyhow::{bail, Result};

use crate::{ui, util, Ctx};

fn admin_post(ctx: &Ctx, path: &str, body: serde_json::Value) -> reqwest::RequestBuilder {
    let mut req = ctx.http.post(format!("{}{}", ctx.url, path)).json(&body);
    if let Some(token) = &ctx.config.admin_token {
        req = req.bearer_auth(token);
    }
    req
}

fn admin_unauthorized(ctx: &Ctx) -> anyhow::Error {
    anyhow::anyhow!(
        "reembed is an admin surface and the server asked for a bearer token\n  \
         → add admin_token = \"<the server's VERITY_ADMIN_TOKEN value>\" to {} and re-run",
        ctx.config_path.display()
    )
}

pub async fn backfill(ctx: &Ctx, model: &str, tenant: Option<&str>, batch: i64) -> Result<()> {
    ui::banner(&format!("reembed → embedding_v2 under model \"{model}\""));
    println!();
    let mut total_written = 0u64;
    let mut round = 0u32;
    loop {
        round += 1;
        let mut body = serde_json::json!({ "model": model, "batch": batch });
        if let Some(t) = tenant {
            body["tenant"] = serde_json::json!(t);
        }
        let (status, text) =
            util::send(admin_post(ctx, "/v1/admin/reembed/batch", body), &ctx.url).await?;
        if status == reqwest::StatusCode::UNAUTHORIZED {
            bail!(admin_unauthorized(ctx));
        }
        if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
            bail!(
                "the server is running sparse-only (no local encoder) — reembed needs the encoder"
            );
        }
        let json = util::expect_json(status, &text, "check the model id and admin token")?;
        let scanned = json["scanned"].as_u64().unwrap_or(0);
        let written = json["written"].as_u64().unwrap_or(0);
        total_written += written;
        let frac = json["coverage"]["fraction"].as_f64().unwrap_or(0.0);
        let covered = json["coverage"]["covered"].as_u64().unwrap_or(0);
        let total = json["coverage"]["total"].as_u64().unwrap_or(0);
        println!(
            "  {} batch {round:<3} scanned {scanned:<5} wrote {written:<5}  {} {covered}/{total} ({:.1}%)",
            ui::dim("·"),
            ui::cyan("coverage"),
            frac * 100.0
        );
        if json["done"].as_bool().unwrap_or(true) {
            break;
        }
    }
    println!();
    println!(
        "  {} backfilled {total_written} chunk(s). Cut over with:  {}",
        ui::green("done"),
        ui::bold("verity-cli reembed cutover --to v2")
    );
    Ok(())
}

pub async fn cutover(ctx: &Ctx, tenant: Option<&str>, to: &str, force: bool) -> Result<()> {
    let route = match to {
        "v1" | "v2" => to,
        other => bail!("unknown route {other:?} — use v1 or v2"),
    };
    let mut body = serde_json::json!({ "route": route, "force": force });
    if let Some(t) = tenant {
        body["tenant"] = serde_json::json!(t);
    }
    let (status, text) =
        util::send(admin_post(ctx, "/v1/admin/reembed/cutover", body), &ctx.url).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!(admin_unauthorized(ctx));
    }
    if status == reqwest::StatusCode::CONFLICT {
        // The coverage gate refused (SPEC §5c: 100% or explicit --force).
        bail!(
            "{}\n  → finish the backfill (verity-cli reembed --model <id>), or re-run with --force",
            text.trim()
        );
    }
    let json = util::expect_json(status, &text, "check the admin token")?;
    let frac = json["coverage"]["fraction"].as_f64().unwrap_or(0.0);
    ui::banner(&format!("dense query route → {}", route));
    println!();
    println!(
        "  {} recall's dense leg now searches embedding_{route} (coverage {:.1}%{})",
        ui::green("cutover"),
        frac * 100.0,
        if json["forced"].as_bool().unwrap_or(false) {
            " — FORCED below 100%; uncovered chunks fall back to sparse-only"
        } else {
            ""
        }
    );
    Ok(())
}
