//! `verity-cli connect <source>` — BYOT credential wizards (SPEC §5e.2,
//! consequence 3): Verity ships wizards, never vendor OAuth apps. Every
//! credential here is created in YOUR tenant and either stays on your disk
//! (slack, 0600 config) or is used exactly once and dropped (github PAT).
//!
//! - `connect slack`: app-from-manifest, ~3 minutes. Socket Mode means the
//!   future connector dials OUT over a WebSocket — zero public endpoint.
//! - `connect github`: a fine-grained PAT, pasted once from this machine,
//!   registers a repo webhook pointed at a freshly minted Verity URL. The
//!   PAT is never written to disk; the hook's minted URL becomes the only
//!   long-lived secret (blast radius: one URL, instantly revocable).

use anyhow::{bail, Context, Result};

use crate::{config, ui, util, webhook, Ctx};

// ==================== slack ====================

/// The Slack app manifest pasted at api.slack.com/apps ("From a manifest" →
/// JSON tab). Socket Mode on, so event delivery needs no request URL and no
/// public HTTPS — the one vendor where BYOT push costs nothing (SPEC §5e.2).
///
/// Scopes cover BOTH channel families the connector mirrors (public
/// `channels:*` + private `groups:*`), `users:read` + `users:read.email` for
/// the identity crosswalk (Slack Uid → the directory-vouched email), and
/// `channels:join` so the connector can self-join public channels it is asked
/// to index. Events mirror the poll lane's detection surface (message edits/
/// deletes, membership churn, channel lifecycle) for the future Socket-Mode
/// push lane; the poll connector is the truth lane either way.
fn slack_manifest() -> serde_json::Value {
    serde_json::json!({
        "display_information": {
            "name": "Verity",
            "description": "Streams channel messages into Verity — permission-aware shared memory for agents."
        },
        "features": {
            "bot_user": {
                "display_name": "verity",
                "always_online": false
            }
        },
        "oauth_config": {
            "scopes": {
                "bot": [
                    "channels:history",
                    "channels:join",
                    "channels:read",
                    "groups:history",
                    "groups:read",
                    "users:read",
                    "users:read.email"
                ]
            }
        },
        "settings": {
            "event_subscriptions": {
                "bot_events": [
                    "channel_archive",
                    "channel_converted_to_private",
                    "channel_deleted",
                    "channel_rename",
                    "member_joined_channel",
                    "member_left_channel",
                    "message.channels",
                    "message.groups"
                ]
            },
            "org_deploy_enabled": false,
            "socket_mode_enabled": true,
            "token_rotation_enabled": false
        }
    })
}

pub async fn slack(ctx: &mut Ctx, print_manifest_only: bool) -> Result<()> {
    let manifest =
        serde_json::to_string_pretty(&slack_manifest()).expect("static manifest serializes");
    if print_manifest_only {
        // Bare JSON on stdout — pipeable: `… --print-manifest-only | pbcopy`.
        println!("{manifest}");
        return Ok(());
    }

    ui::banner("connect slack — your own app, your own tokens (~3 minutes)");
    println!();
    println!(
        "  {}",
        ui::dim(
            "BYOT: the app is created in YOUR workspace and the tokens never leave \
             this machine. Socket Mode dials out — no public URL, no inbound firewall hole.",
        )
    );
    println!();
    println!(
        "  {} Open {} → \"From a manifest\" → pick your workspace →",
        ui::bold("1."),
        ui::cyan("https://api.slack.com/apps?new_app=1")
    );
    println!("     JSON tab → paste the manifest below → Next → Create.");
    println!();
    println!("{manifest}");
    println!();
    println!(
        "     {}",
        ui::dim(
            "(need it in a file? verity-cli connect slack --print-manifest-only > manifest.json)"
        )
    );
    println!();
    println!(
        "     {}",
        ui::dim(
            "already created the Verity app from an older manifest? Paste this one over it \
             (App Manifest page) and then RE-INSTALL the app (Install App → Reinstall to \
             Workspace) — Slack only grants new scopes at install time, and the reinstall \
             may mint a fresh xoxb- token: re-run this wizard to store it.",
        )
    );
    println!();
    println!(
        "  {} Basic Information → App-Level Tokens → Generate Token and Scopes:",
        ui::bold("2.")
    );
    println!(
        "     name it \"verity\", add the {} scope, Generate — copy the {} token.",
        ui::bold("connections:write"),
        ui::bold("xapp-")
    );
    println!();
    println!(
        "  {} Install App → Install to Workspace → Allow — copy the Bot User",
        ui::bold("3.")
    );
    println!(
        "     OAuth Token ({}, shown there and under OAuth & Permissions).",
        ui::bold("xoxb-")
    );
    println!();

    let app_token = prompt_slack_token(
        "Paste the app-level token",
        "xapp-",
        "generate it under Basic Information → App-Level Tokens (scope connections:write)",
    )?;
    let bot_token = prompt_slack_token(
        "Paste the bot token",
        "xoxb-",
        "copy it from OAuth & Permissions after Install to Workspace",
    )?;

    ctx.config
        .connectors
        .get_or_insert_with(Default::default)
        .slack = Some(config::SlackConnector {
        app_token,
        bot_token,
    });
    config::save(&ctx.config_path, &ctx.config)?;

    println!();
    ui::step_ok(
        "stored",
        &format!(
            "[connectors.slack] in {} (0600 — owner-only)",
            ctx.config_path.display()
        ),
    );
    println!();
    println!("  {}", ui::bold("Run the connector:"));
    println!();
    println!(
        "      {}",
        ui::cyan("python -m verity_ingest.connectors.slack --visibility 1")
    );
    println!();
    println!(
        "  {}",
        ui::dim(
            "that runner arrives with the Slack connector — your tokens are already \
             stored where it will look. Slack is ACL tier B: channel membership \
             approximates visibility, so the connector will require an explicit \
             --visibility, like every Verity write.",
        )
    );
    Ok(())
}

/// Prompt until the token carries the expected Slack prefix (three attempts).
/// The two tokens are the classic swap mistake; the prefix check catches it
/// at paste time instead of at the connector's first API call.
fn prompt_slack_token(label: &str, prefix: &str, where_to_get: &str) -> Result<String> {
    for _ in 0..3 {
        let token = util::prompt_secret(&format!("{label} ({prefix}…)"))?;
        if token.starts_with(prefix) {
            return Ok(token);
        }
        let looks_like = if token.is_empty() {
            "nothing was pasted".to_string()
        } else {
            format!(
                "that starts with {:?}, not {prefix}",
                token.chars().take(5).collect::<String>()
            )
        };
        eprintln!(
            "  {} {looks_like} — {where_to_get}",
            ui::yellow("not that token:")
        );
    }
    bail!("no {prefix} token after 3 attempts — {where_to_get}, then re-run `verity-cli connect slack`")
}

// ==================== github ====================

const GITHUB_API: &str = "https://api.github.com";
/// The hook subscribes to exactly what the future manifest maps (SPEC §5e.3):
/// commits, issues, and the conversation on them.
const GITHUB_EVENTS: [&str; 3] = ["push", "issues", "issue_comment"];

pub async fn github(
    ctx: &Ctx,
    repo: Option<&str>,
    visibility: Option<&str>,
    public_url: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let tokens = util::require_visibility(
        visibility,
        "verity-cli connect github --visibility 1 --public-url https://verity.example.com",
    );
    let public_url = require_public_url(ctx, public_url)?;

    ui::banner("connect github — PAT used once, never stored");
    println!();

    let repo = match repo {
        Some(r) if parse_repo(r).is_some() => r.to_string(),
        Some(r) => bail!("{r:?} is not owner/name — e.g. verity-cli connect github acme/website …"),
        None => prompt_repo()?,
    };

    // Mint first: the Verity side is ours and cheap to verify; the GitHub
    // call gets one fully formed URL to point at.
    let minted = webhook::mint_raw(
        ctx,
        &format!("github:{repo}"),
        &tokens,
        "fix the request and re-run `verity-cli connect github`",
    )
    .await?;
    let hook_url = format!("{public_url}{}", minted.path);
    ui::step_ok(
        "minted",
        &format!(
            "webhook \"github:{repo}\" (visibility {tokens:?}, bound at mint — id {})",
            minted.id
        ),
    );

    let body = serde_json::json!({
        "name": "web",
        "active": true,
        "events": GITHUB_EVENTS,
        "config": { "url": hook_url, "content_type": "json" }
    });
    let api_url = format!("{GITHUB_API}/repos/{repo}/hooks");

    if dry_run {
        println!();
        println!(
            "  {} {}",
            ui::bold("Would send"),
            ui::dim("(--dry-run: nothing goes to GitHub, so no PAT was asked for)")
        );
        println!();
        println!("      POST {api_url}");
        println!("      Accept: application/vnd.github+json");
        println!("      Authorization: Bearer <your fine-grained PAT — used once, never stored>");
        println!("      X-GitHub-Api-Version: 2022-11-28");
        println!("      User-Agent: verity-cli");
        println!();
        for line in serde_json::to_string_pretty(&body)
            .expect("static body serializes")
            .lines()
        {
            println!("      {line}");
        }
        println!();
        println!(
            "  {}",
            ui::dim(&format!(
                "the Verity webhook above WAS minted and is live. If this was only a \
                 rehearsal, revoke it: curl -X DELETE {}/v1/webhooks/{}",
                ctx.url, minted.id
            ))
        );
        return Ok(());
    }

    println!();
    println!(
        "  Create a fine-grained PAT at {}",
        ui::cyan("https://github.com/settings/personal-access-tokens/new")
    );
    println!(
        "  scoped to {} only, with repository permission {}.",
        ui::bold(&repo),
        ui::bold("Webhooks: read and write")
    );
    println!(
        "  {}",
        ui::dim("it is used for exactly one API call from this machine and never written to disk.")
    );
    println!();
    let pat = util::prompt_secret("Paste the fine-grained PAT (github_pat_…)")?;
    if pat.is_empty() {
        bail!("no token pasted — mint one and re-run `verity-cli connect github`");
    }
    if !pat.starts_with("github_pat_") && !pat.starts_with("ghp_") {
        eprintln!(
            "  {} that prefix doesn't look like a GitHub PAT (github_pat_… / ghp_…) — trying it anyway",
            ui::yellow("!")
        );
    }

    let resp = ctx
        .http
        .post(&api_url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "verity-cli")
        .bearer_auth(&pat)
        .json(&body)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "cannot reach api.github.com ({e})\n  \
                 → check the network and re-run `verity-cli connect github` \
                 (a fresh webhook URL will be minted; this one stays valid until revoked)"
            )
        })?;
    // The PAT's job is done the moment the request is sent; nothing below
    // ever sees it again and nothing above wrote it anywhere.
    drop(pat);

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    match status.as_u16() {
        201 => {
            let hook: serde_json::Value =
                serde_json::from_str(&text).context("GitHub answered 201 but not with JSON")?;
            let hook_id = hook["id"]
                .as_u64()
                .map_or_else(|| hook["id"].to_string(), |id| id.to_string());
            ui::step_ok(
                "hook",
                &format!(
                    "created on {repo} — id {hook_id}, events {}",
                    GITHUB_EVENTS.join("/")
                ),
            );
            println!();
            println!("  {}", ui::bold("Done."));
            println!();
            let kv = |label: &str, value: &str| {
                println!("    {}  {value}", ui::dim(&format!("{label:<11}")))
            };
            kv("delivers to", &hook_url);
            kv(
                "manage",
                &format!("https://github.com/{repo}/settings/hooks"),
            );
            println!();
            println!(
                "  Your PAT was used for that one call and dropped — it was never written to\n  \
                 disk, and Verity now holds no GitHub credential at all. The only secret left\n  \
                 is the minted URL itself (blast radius: one URL, revocable any time)."
            );
            println!();
            println!(
                "  {}",
                ui::dim(&format!(
                    "try it: push a commit or open an issue, then `verity-cli tail`. GitHub's \
                     payload shapes aren't Verity-native, so today they land in the quarantine \
                     preview — fail-closed, never guessed at — until declarative mapping \
                     (SPEC §5e.3) graduates {repo} to real facts.",
                )),
            );
            Ok(())
        }
        401 => bail!(
            "GitHub answered 401 (bad credentials)\n  \
             → the PAT is invalid, expired, or revoked. Generate a fresh fine-grained PAT at \
             https://github.com/settings/personal-access-tokens and re-run \
             `verity-cli connect github` — nothing was stored, so there is nothing to clean up"
        ),
        403 => bail!(
            "GitHub answered 403: {}\n  \
             → the PAT cannot administer webhooks on {repo}. Edit the token's repository \
             permissions to grant \"Webhooks: read and write\" and re-run",
            text.trim()
        ),
        404 => bail!(
            "GitHub answered 404 for {repo}\n  \
             → either the repository name is misspelled, or the fine-grained PAT cannot see it \
             at all (GitHub hides repos outside a token's grant as 404). Check the owner/name \
             and the PAT's \"Repository access\", then re-run `verity-cli connect github`"
        ),
        422 => bail!(
            "GitHub answered 422 (validation failed): {}\n  \
             → most often a hook with this exact URL already exists on {repo}, or GitHub \
             rejected the URL. Review https://github.com/{repo}/settings/hooks, delete stale \
             Verity hooks, and re-run",
            text.trim()
        ),
        _ => bail!(
            "GitHub answered {status}: {}\n  \
             → see https://docs.github.com/rest/repos/webhooks and re-run once resolved",
            text.trim()
        ),
    }
}

/// GitHub delivers webhooks from its own cloud: without a publicly reachable
/// base URL the hook would be created and then fail on every delivery. So the
/// flag is required, and the refusal explains the physics plus the dev answer.
fn require_public_url(ctx: &Ctx, public_url: Option<&str>) -> Result<String> {
    let Some(raw) = public_url else {
        bail!(
            "--public-url is required: GitHub delivers webhooks from its own cloud, so it \
             must be able to reach this Verity server over the public internet — {} is only \
             reachable from this machine.\n  \
             → pass the base URL GitHub should POST to:\n      \
             verity-cli connect github --visibility 1 --public-url https://verity.example.com\n  \
             → for local dev, open a tunnel to the server and use its URL:\n      \
             cloudflared tunnel --url {}     (or: ngrok http 7717)",
            ctx.url,
            ctx.url
        );
    };
    let trimmed = raw.trim_end_matches('/');
    if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
        bail!("--public-url must be an http(s) base URL, got {raw:?}");
    }
    if trimmed.starts_with("http://") {
        eprintln!(
            "  {} --public-url is plain http — GitHub will deliver, but use https for anything real",
            ui::yellow("!")
        );
    }
    Ok(trimmed.to_string())
}

/// `owner/name` — exactly one slash, both halves non-empty, no whitespace.
fn parse_repo(s: &str) -> Option<(&str, &str)> {
    let (owner, name) = s.split_once('/')?;
    let ok = |part: &str| !part.is_empty() && !part.contains(char::is_whitespace);
    (ok(owner) && ok(name) && !name.contains('/')).then_some((owner, name))
}

fn prompt_repo() -> Result<String> {
    for _ in 0..3 {
        let repo = util::prompt_line("GitHub repository (owner/name)")?;
        if parse_repo(&repo).is_some() {
            return Ok(repo);
        }
        eprintln!(
            "  {} a repository is owner/name — e.g. acme/website",
            ui::yellow("not that shape:")
        );
    }
    bail!("no owner/name repository after 3 attempts — re-run `verity-cli connect github`")
}

#[cfg(test)]
mod tests {
    use super::{parse_repo, slack_manifest};

    #[test]
    fn repo_parsing_accepts_owner_name_only() {
        assert_eq!(parse_repo("acme/website"), Some(("acme", "website")));
        for bad in ["acme", "acme/", "/website", "a/b/c", "ac me/web", ""] {
            assert!(parse_repo(bad).is_none(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn slack_manifest_pins_socket_mode_and_scopes() {
        let m = slack_manifest();
        assert_eq!(m["settings"]["socket_mode_enabled"], true);
        // The connector's full read surface: public + private channel history/
        // rosters, users + email (the identity crosswalk), and self-join for
        // public channels. Changing this list means every existing install
        // must RE-INSTALL the app (scopes grant at install time) — the wizard
        // copy says so; keep them in sync.
        assert_eq!(
            m["oauth_config"]["scopes"]["bot"],
            serde_json::json!([
                "channels:history",
                "channels:join",
                "channels:read",
                "groups:history",
                "groups:read",
                "users:read",
                "users:read.email"
            ])
        );
        assert_eq!(
            m["settings"]["event_subscriptions"]["bot_events"],
            serde_json::json!([
                "channel_archive",
                "channel_converted_to_private",
                "channel_deleted",
                "channel_rename",
                "member_joined_channel",
                "member_left_channel",
                "message.channels",
                "message.groups"
            ])
        );
    }
}
