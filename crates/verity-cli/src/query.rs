//! `verity-cli query <text>` — scoped hybrid recall (POST /v1/recall) under
//! the config's dev scope handle. An expired handle is re-minted transparently
//! from the principals saved in the config (and noted, dimly).

use anyhow::{bail, Result};

use crate::{config, ui, util, Ctx};

pub async fn run(
    ctx: &mut Ctx,
    text: &str,
    handle_flag: Option<&str>,
    k: usize,
    json: bool,
) -> Result<()> {
    let handle = match handle_flag {
        Some(h) => h.to_string(),
        None => match &ctx.config.scope_handle {
            Some(h) => h.clone(),
            None => bail!(
                "no scope handle in {} and no --handle given\n  \
                 → run `verity-cli dev` to mint one, or pass --handle vs_…",
                ctx.config_path.display()
            ),
        },
    };

    let (status, body) = recall(ctx, &handle, text, k).await?;

    // Expired/invalid saved handle + enough config to re-mint → do it for the
    // user instead of telling them to (refusal polish, SPEC §5e.7).
    let (status, body) = if status == reqwest::StatusCode::UNAUTHORIZED
        && handle_flag.is_none()
        && ctx.config.tenant_id.is_some()
        && ctx.config.principals.is_some()
    {
        println!(
            "{}",
            ui::dim("saved scope handle rejected (likely expired) — minting a fresh one")
        );
        let tenant = ctx.config.tenant_id.clone().expect("checked above");
        let principals = ctx.config.principals.clone().expect("checked above");
        let (fresh, _) = util::mint_scope(ctx, &tenant, &principals, "cli:query", 43_200).await?;
        ctx.config.scope_handle = Some(fresh.clone());
        config::save(&ctx.config_path, &ctx.config)?;
        recall(ctx, &fresh, text, k).await?
    } else {
        (status, body)
    };

    let hits = util::expect_json(
        status,
        &body,
        "check your scope with `verity-cli status`; a rejected handle re-mints via `verity-cli dev`",
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&hits)?);
        return Ok(());
    }
    print_hits(text, hits.as_array().map(Vec::as_slice).unwrap_or(&[]));
    Ok(())
}

async fn recall(
    ctx: &Ctx,
    handle: &str,
    text: &str,
    k: usize,
) -> Result<(reqwest::StatusCode, String)> {
    let body = serde_json::json!({ "scope_handle": handle, "text": text, "k": k });
    util::send(
        ctx.http.post(format!("{}/v1/recall", ctx.url)).json(&body),
        &ctx.url,
    )
    .await
}

fn print_hits(text: &str, hits: &[serde_json::Value]) {
    if hits.is_empty() {
        println!("{} no hits for {text:?}", ui::yellow("∅"));
        println!(
            "  {}",
            ui::dim(
                "Verity fails closed: this means nothing matched OR your scope may not \
                 see what did. Inspect the scope with `verity-cli status`, or add \
                 content with `verity-cli add … --visibility <tokens>`."
            )
        );
        return;
    }
    println!();
    for (i, hit) in hits.iter().enumerate() {
        let score = hit["score"].as_f64().unwrap_or(0.0);
        let kind = hit["kind"].as_str().unwrap_or("content");
        let acl = hit["acl_provenance"].as_str().unwrap_or("?");
        let content = hit["content"].as_str().unwrap_or("");
        let rank = ui::bold(&format!("{:>2}.", i + 1));
        println!(
            " {rank} {} {} {}  {}",
            ui::cyan(&format!("{score:>6.3}")),
            ui::kind_tag(kind),
            ui::acl_tag(acl),
            ui::truncate(content, 100)
        );
        let entities: Vec<&str> = hit["entity_tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|e| e.as_str()).collect())
            .unwrap_or_default();
        let mut meta = String::new();
        if !entities.is_empty() {
            meta.push_str(&format!("entities {}  ·  ", entities.join(", ")));
        }
        meta.push_str(&format!(
            "provenance {}",
            hit["provenance"].as_str().unwrap_or("?")
        ));
        println!("      {}", ui::dim(&meta));
    }
    println!();
    println!(
        "  {}",
        ui::dim("every hit passed the scope's visibility pre-filter in-index — nothing above is post-filtered.")
    );
}
