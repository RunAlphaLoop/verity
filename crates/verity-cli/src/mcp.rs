//! `verity-cli mcp install` — print (or run) the exact `claude mcp add`
//! command that wires the configured identity into verity-mcp. Identity is
//! environment, never tool arguments (SPEC §9a), so the whole integration is
//! one command.

use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::{ui, util, Ctx};

pub async fn install(ctx: &Ctx, repo_flag: Option<PathBuf>, run: bool) -> Result<()> {
    let tenant = util::require_tenant(ctx)?;
    let principals = ctx
        .config
        .principals
        .clone()
        .unwrap_or_else(|| vec![1])
        .iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let user = util::actor_sub().unwrap_or_else(|| "user:me".into());

    let bin = match util::repo_root(repo_flag.as_deref()) {
        Ok(repo) => {
            let bin = repo.join("target/release/verity-mcp");
            if !bin.is_file() {
                println!(
                    "{} {} is not built yet — run  {}",
                    ui::yellow("!"),
                    bin.display(),
                    ui::cyan("cargo build --release -p verity-mcp")
                );
            }
            bin.display().to_string()
        }
        Err(e) => {
            println!("{} {e:#}", ui::yellow("!"));
            "/path/to/verity/target/release/verity-mcp".to_string()
        }
    };

    let env_pairs = [
        format!("VERITY_URL={}", ctx.url),
        format!("VERITY_TENANT_ID={tenant}"),
        format!("VERITY_PRINCIPALS={principals}"),
        format!("VERITY_ACTOR_SUB={user}"),
        "VERITY_ACTOR_AZP=agent:claude-code".to_string(),
    ];

    println!();
    println!("  {}", ui::bold("Wire Claude Code to Verity:"));
    println!();
    println!("      claude mcp add verity \\");
    for pair in &env_pairs {
        println!("        -e {pair} \\");
    }
    println!("        -- {bin}");
    println!();
    println!(
        "  {}",
        ui::dim(
            "tools: memory_open_scope, memory_recall, memory_get, memory_remember, \
             memory_record_action, memory_activity, memory_brief, the ingest trio, \
             memory_forget, memory_whoami.",
        )
    );

    if !run {
        println!();
        println!(
            "  {}",
            ui::dim("re-run with --run to execute this command now."),
        );
        return Ok(());
    }

    let mut args: Vec<String> = vec!["mcp".into(), "add".into(), "verity".into()];
    for pair in &env_pairs {
        args.push("-e".into());
        args.push(pair.clone());
    }
    args.push("--".into());
    args.push(bin);
    println!();
    let status = std::process::Command::new("claude").args(&args).status();
    match status {
        Ok(status) if status.success() => {
            println!(
                "  {} registered — open a new Claude Code session and ask it to `memory_whoami`",
                ui::green("✓")
            );
            Ok(())
        }
        Ok(status) => bail!("`claude mcp add` exited with {status} — see its output above"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "the `claude` CLI is not on PATH\n  \
             → install Claude Code (https://claude.com/claude-code) or copy the printed command \
             into the machine that has it"
        ),
        Err(e) => bail!("failed to run `claude`: {e}"),
    }
}
