//! verity-cli — the developer front door to Verity (roadmap task 13,
//! SPEC §5e.1 entry point #2): `dev` boots the whole local plane, `add`
//! ingests under an explicit visibility, `query` runs scoped recall,
//! `webhook mint` turns any JSON-POSTing system into a source, `tail`
//! watches the fail-closed quarantine, `mcp install` wires Claude Code.
//!
//! Like verity-mcp, this is a pure REST client of a running `verity` server:
//! no database access and no enforcement logic live here. The binary is named
//! `verity-cli` because the server crate still owns the `verity` bin name;
//! the rename ships later.

mod add;
mod config;
mod connect;
mod dev;
mod mcp;
mod query;
mod status;
mod tail;
mod ui;
mod util;
mod webhook;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

const DEFAULT_URL: &str = "http://127.0.0.1:7717";

#[derive(Parser)]
#[command(
    name = "verity-cli",
    version,
    about = "Verity — permission-aware shared memory for agents (developer CLI)",
    after_help = "Start here:  verity-cli dev   (Postgres + server + tenant + scope, in one command)"
)]
struct Cli {
    /// Verity server base URL (overrides the config file; default http://127.0.0.1:7717).
    #[arg(long, global = true, env = "VERITY_URL")]
    url: Option<String>,
    /// Config file path (default: ~/.verity/config.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// One command to a running local Verity: docker Postgres, the server,
    /// a "dev" tenant, an org-wide scope handle, and a written config.
    /// Fully idempotent — re-run it anytime.
    Dev {
        /// Path to the verity checkout (holds deploy/docker-compose.yml).
        /// Default: discovered above the binary, then $VERITY_REPO.
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Ingest a file, a directory (recursive, text-like files), an http(s)
    /// URL, or stdin ('-') into memory — under an explicit visibility.
    #[command(
        long_about = "Ingest a file, a directory (recursive over .txt/.md/.json/.csv/.html, \
capped at 200 files), an http(s) URL (10s timeout, 2 MB, HTML reduced to text), or stdin ('-').\n\n\
Visibility is enforced by the argument parser, not by convention: --visibility is required and \
has no default, because Verity never guesses who may see a memory (SPEC §5e.8).\n\n\
How it works: POST /v1/files derives a memory's visibility from the scope handle it is written \
under, so `add` first mints a short-lived scope whose principals are exactly your --visibility \
tokens (POST /v1/scopes, actor cli:add) and uploads under that handle."
    )]
    Add {
        /// File path, directory, http(s) URL, or '-' for stdin.
        target: String,
        /// REQUIRED. Comma-separated principal tokens allowed to read this
        /// memory, e.g. --visibility 1 (the org-wide token from `verity-cli dev`).
        #[arg(long)]
        visibility: Option<String>,
        /// Entity tag(s) to attach, e.g. --entity account:acme (repeatable).
        #[arg(long)]
        entity: Vec<String>,
    },
    /// Scoped hybrid recall: every hit already passed your scope's
    /// visibility pre-filter in the index.
    Query {
        /// Natural-language query text.
        text: String,
        /// Scope handle to query under (default: the one saved by `dev`).
        #[arg(long)]
        handle: Option<String>,
        /// Number of results.
        #[arg(long, short, default_value_t = 8)]
        k: usize,
        /// Print the raw JSON hits instead of the pretty view.
        #[arg(long)]
        json: bool,
    },
    /// Minted scoped webhook URLs: push memory from any system that can POST JSON.
    Webhook {
        #[command(subcommand)]
        command: WebhookCommand,
    },
    /// BYOT source wizards: credentials created in YOUR tenant, never ours.
    Connect {
        #[command(subcommand)]
        command: ConnectCommand,
    },
    /// Watch the quarantine: payloads Verity refused to index permissively.
    Tail {
        /// Fetch and print once instead of polling every 2s.
        #[arg(long)]
        once: bool,
    },
    /// Model Context Protocol integration (Claude Code, Cursor, …).
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Server health, config, tenant, and the decoded scope handle.
    Status,
}

#[derive(Subcommand)]
enum WebhookCommand {
    /// Mint a capability URL bound to an explicit visibility. The token in
    /// the URL is the credential and is shown exactly once.
    Mint {
        /// Webhook name; ingested memory carries source "webhook:<name>".
        name: String,
        /// REQUIRED. Comma-separated principal tokens every payload will be
        /// readable by (payloads may narrow this set, never widen it).
        #[arg(long)]
        visibility: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConnectCommand {
    /// Slack via app-from-manifest (~3 min): Socket Mode, no public URL;
    /// tokens stay in the 0600 config file for the upcoming connector.
    Slack {
        /// Print only the bare manifest JSON on stdout (pipeable) and exit.
        #[arg(long)]
        print_manifest_only: bool,
    },
    /// GitHub repo webhook via a fine-grained PAT — pasted once, used for
    /// one API call, never stored anywhere.
    Github {
        /// Repository as owner/name, e.g. acme/website (prompted if omitted).
        repo: Option<String>,
        /// REQUIRED. Comma-separated principal tokens every delivered payload
        /// will be readable by — bound into the minted webhook URL.
        #[arg(long)]
        visibility: Option<String>,
        /// REQUIRED. Public https base URL GitHub can reach this Verity
        /// server at (GitHub delivers from its own cloud).
        #[arg(long)]
        public_url: Option<String>,
        /// Mint the Verity webhook, then print the GitHub API request that
        /// WOULD be sent instead of sending it (no PAT asked for).
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum McpCommand {
    /// Print the exact `claude mcp add verity …` command for this config.
    Install {
        /// Execute the command via the `claude` CLI instead of printing only.
        #[arg(long)]
        run: bool,
        /// Path to the verity checkout (for the verity-mcp binary path).
        #[arg(long)]
        repo: Option<PathBuf>,
    },
}

/// Everything a command needs: resolved base URL, loaded config, HTTP client.
pub(crate) struct Ctx {
    pub http: reqwest::Client,
    pub url: String,
    pub config_path: PathBuf,
    pub config: config::Config,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{} {e:#}", ui::red("error:"));
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let config_path = match cli.config {
        Some(path) => path,
        None => config::default_path()?,
    };
    let config = config::load(&config_path)?;
    let url = cli
        .url
        .or_else(|| config.url.clone())
        .unwrap_or_else(|| DEFAULT_URL.to_string())
        .trim_end_matches('/')
        .to_string();
    let mut ctx = Ctx {
        http: reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("static client config builds"),
        url,
        config_path,
        config,
    };

    match cli.command {
        Command::Dev { repo } => dev::run(&mut ctx, repo).await,
        Command::Add {
            target,
            visibility,
            entity,
        } => add::run(&ctx, &target, visibility.as_deref(), &entity).await,
        Command::Query {
            text,
            handle,
            k,
            json,
        } => query::run(&mut ctx, &text, handle.as_deref(), k, json).await,
        Command::Webhook { command } => match command {
            WebhookCommand::Mint { name, visibility } => {
                webhook::mint(&ctx, &name, visibility.as_deref()).await
            }
        },
        Command::Connect { command } => match command {
            ConnectCommand::Slack {
                print_manifest_only,
            } => connect::slack(&mut ctx, print_manifest_only).await,
            ConnectCommand::Github {
                repo,
                visibility,
                public_url,
                dry_run,
            } => {
                connect::github(
                    &ctx,
                    repo.as_deref(),
                    visibility.as_deref(),
                    public_url.as_deref(),
                    dry_run,
                )
                .await
            }
        },
        Command::Tail { once } => tail::run(&ctx, once).await,
        Command::Mcp { command } => match command {
            McpCommand::Install { run, repo } => mcp::install(&ctx, repo, run).await,
        },
        Command::Status => status::run(&ctx).await,
    }
}
