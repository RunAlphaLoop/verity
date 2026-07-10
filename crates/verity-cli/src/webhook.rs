//! `verity-cli webhook mint <name>` — SPEC §5e.1 entry point #4: any system
//! that can POST JSON becomes a push source, bound at mint time to an explicit
//! visibility. The URL token is the credential; it is shown exactly once.

use anyhow::{bail, Context, Result};

use crate::{ui, util, Ctx};

/// A freshly minted webhook: the server-relative ingest path (`/wh/<token>`,
/// where the token IS the credential and only its hash persists) plus the id
/// used for revocation (`DELETE /v1/webhooks/{id}`).
pub struct Minted {
    pub id: String,
    pub path: String,
}

/// POST /v1/webhooks — shared by `webhook mint` and the `connect` wizards
/// (SPEC §5e.1 entry point #4). Visibility is bound at mint time.
pub async fn mint_raw(ctx: &Ctx, name: &str, tokens: &[i32], next_step: &str) -> Result<Minted> {
    let tenant = util::require_tenant(ctx)?;
    let mut req = ctx
        .http
        .post(format!("{}/v1/webhooks", ctx.url))
        .json(&serde_json::json!({
            "tenant_id": tenant,
            "name": name,
            "visibility": tokens,
        }));
    if let Some(token) = &ctx.config.admin_token {
        req = req.bearer_auth(token);
    }
    let (status, body) = util::send(req, &ctx.url).await?;
    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!(
            "webhook minting is an admin surface and the server asked for a bearer token\n  \
             → add admin_token = \"<the server's VERITY_ADMIN_TOKEN value>\" to {} and re-run",
            ctx.config_path.display()
        );
    }
    let json = util::expect_json(status, &body, next_step)?;
    Ok(Minted {
        id: json["webhook_id"].as_str().unwrap_or("?").to_string(),
        path: json["url"]
            .as_str()
            .context("mint response carries url")?
            .to_string(),
    })
}

pub async fn mint(ctx: &Ctx, name: &str, visibility: Option<&str>) -> Result<()> {
    let tokens = util::require_visibility(
        visibility,
        &format!("verity-cli webhook mint {name} --visibility 1"),
    );
    let minted = mint_raw(
        ctx,
        name,
        &tokens,
        "fix the request and re-run `verity-cli webhook mint`",
    )
    .await?;
    let full = format!("{}{}", ctx.url, minted.path);
    let id = minted.id.as_str();

    ui::banner(&format!("webhook \"{name}\" minted"));
    println!();
    let kv =
        |label: &str, value: &str| println!("    {}  {value}", ui::dim(&format!("{label:<10}")));
    kv("url", &ui::bold(&full));
    kv("id", id);
    kv(
        "visibility",
        &format!("{tokens:?} (bound at mint — payloads may narrow it, never widen)"),
    );
    println!();
    println!("  {}", ui::bold("Try it:"));
    println!();
    println!("      curl -s -X POST {full} \\");
    println!("        -H 'Content-Type: application/json' \\");
    println!("        -d '{{\"content\": \"hello from my system\"}}'");
    println!();
    println!(
        "  {}",
        ui::dim(
            "the token in the URL IS the credential (only its hash is stored — this is \
             the one time it is shown). Unrecognized payload shapes are quarantined, \
             never guessed at: watch them with `verity-cli tail`.",
        )
    );
    Ok(())
}
