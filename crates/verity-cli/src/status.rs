//! `verity-cli status` — server health, config location, tenant, and the
//! saved scope handle DECODED: the vs_ payload is readable base64 JSON by
//! design (HMAC-signed against tampering, not encrypted), so the CLI can show
//! exactly what a handle grants without asking the server.

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::{ui, util, Ctx};

pub async fn run(ctx: &Ctx) -> Result<()> {
    ui::banner("verity status");
    println!();
    let kv = |label: &str, value: &str| println!("  {}  {value}", ui::dim(&format!("{label:<9}")));

    // Server.
    if util::healthz(&ctx.http, &ctx.url).await {
        kv(
            "server",
            &format!("{}  {}", ctx.url, ui::green("✓ healthy")),
        );
    } else {
        kv(
            "server",
            &format!(
                "{}  {}  {}",
                ctx.url,
                ui::red("✗ unreachable"),
                ui::dim("start it with `verity-cli dev`")
            ),
        );
    }

    // Config.
    if ctx.config_path.exists() {
        kv("config", &ctx.config_path.display().to_string());
    } else {
        kv(
            "config",
            &format!(
                "{} {}",
                ctx.config_path.display(),
                ui::yellow("(not written yet — run `verity-cli dev`)")
            ),
        );
    }
    kv(
        "admin",
        match ctx.config.admin_token {
            Some(_) => "bearer token configured",
            None => "no admin token (fine against a dev-mode server)",
        },
    );

    // Tenant.
    kv(
        "tenant",
        ctx.config
            .tenant_id
            .as_deref()
            .unwrap_or("— (run `verity-cli dev`)"),
    );

    // Scope handle, decoded.
    let Some(handle) = &ctx.config.scope_handle else {
        kv("scope", "— (run `verity-cli dev` to mint one)");
        return Ok(());
    };
    match util::decode_handle(handle) {
        Ok(payload) => {
            let principals = payload["principals"].clone();
            let entities = payload["entity_scope"]
                .as_array()
                .filter(|a| !a.is_empty())
                .map(|a| serde_json::to_string(a).unwrap_or_default())
                .unwrap_or_else(|| "(unbound)".into());
            let actor = format!(
                "{} · {}",
                payload["actor_sub"].as_str().unwrap_or("-"),
                payload["actor_azp"].as_str().unwrap_or("-")
            );
            let expiry = payload["expires_at"]
                .as_str()
                .and_then(|s| s.parse::<DateTime<Utc>>().ok());
            let expires = match expiry {
                Some(t) if t < Utc::now() => format!(
                    "{}  {}",
                    ui::red(&format!("expired {t}")),
                    ui::dim("→ `verity-cli dev` (or any query) re-mints it")
                ),
                Some(t) => format!("{t}  ({} left)", util::human_remaining(t)),
                None => "unknown".into(),
            };
            kv(
                "scope",
                &format!("principals {principals} · entities {entities}"),
            );
            kv("", &format!("actor {actor}"));
            kv("", &format!("expires {expires}"));
            println!(
                "  {}",
                ui::dim(
                    "(the handle payload is readable on purpose — it is HMAC-signed so it \
                     cannot be altered, but it is not a secret-keeping envelope)",
                )
            );
        }
        Err(e) => {
            kv(
                "scope",
                &format!(
                    "{} {e:#} {}",
                    ui::red("undecodable —"),
                    ui::dim("→ re-mint with `verity-cli dev`")
                ),
            );
        }
    }
    Ok(())
}
