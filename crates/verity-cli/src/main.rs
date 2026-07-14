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
mod backup;
mod config;
mod connect;
mod dev;
mod doctor;
mod manifest;
mod mcp;
mod query;
mod reembed;
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
        /// Bring up the knowledge consolidation worker with the stack (SPEC §2
        /// L2). OFF by default — unlike the free deterministic planes it makes
        /// LLM calls (needs an Anthropic key at ~/.verity-anthropic-key), so it
        /// is a deliberate flip, never automatic. Auto-publish stays off: it
        /// extracts knowledge into the review queue, never straight to memory.
        #[arg(long)]
        knowledge: bool,
        /// Bring up the Google directory-sync worker with the stack (Identity
        /// Plane §6a). OFF by default — needs the Workspace service-account key
        /// (GOOGLE_APPLICATION_CREDENTIALS) + a DWD subject
        /// (VERITY_GDIRECTORY_SUBJECT) on the server. Reconciles users + groups
        /// (nested membership) into SpiceDB so group-based ACL inheritance stays
        /// fresh; the reconcile interval is the membership-freshness bound.
        #[arg(long)]
        directory: bool,
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
    /// Community manifest registry (SPEC §5e.3): list/show/verify/fetch/install
    /// signed source manifests. Reads a local registry root (default ./registry,
    /// or --registry / VERITY_MANIFEST_REGISTRY); a git/HTTP fetch is next.
    Manifest {
        /// Registry root: a local directory holding index.json (default
        /// ./registry). Overrides $VERITY_MANIFEST_REGISTRY. A git/HTTP URL is
        /// the documented next step (rejected today).
        #[arg(long, global = true, env = "VERITY_MANIFEST_REGISTRY")]
        registry: Option<String>,
        #[command(subcommand)]
        command: ManifestCommand,
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
    /// Embedding-model migration (SPEC §5c): backfill the embedding_v2 named
    /// vector, then flip the dense query route. The server holds the encoder;
    /// this drives batches and shows progress. Admin surface (needs
    /// admin_token in the config when the server requires it).
    #[command(
        long_about = "Embedding-model migration tooling (SPEC §5c dual named-vector backfill + \
query-routing cutover).\n\n\
`verity-cli reembed --model <id>` loops the server's batch re-embed endpoint until every current \
chunk's embedding_v2 is filled from stored canonical text (never a re-fetch), printing coverage.\n\n\
`verity-cli reembed cutover --to v2` flips recall's dense leg to the new vector; the server refuses \
below 100% coverage unless --force (uncovered chunks then fall back to sparse-only for the new route).\n\n\
Dims match today (both 384), so this is honest plumbing + routing, not a real model swap — a true \
dimension change needs a wider column (docs/EMBEDDING_MIGRATION.md)."
    )]
    Reembed {
        /// Target model id (registered in the named-vector registry on first
        /// batch). Required for backfill; ignored by the `cutover` subcommand.
        #[arg(long)]
        model: Option<String>,
        /// Restrict to one tenant (uuid); default backfills all tenants.
        #[arg(long)]
        tenant: Option<String>,
        /// Chunks per server round-trip.
        #[arg(long, default_value_t = 256)]
        batch: i64,
        #[command(subcommand)]
        command: Option<ReembedCommand>,
    },
    /// Server health, config, tenant, and the decoded scope handle.
    Status,
    /// Plane-by-plane OBSERVED health of the running dev stack (identity,
    /// ReBAC watch, signing key, media tier, encoder, auto-resolve,
    /// Temporal) — the same live probes `dev` prints, re-runnable anytime.
    Doctor,
    /// Back up the dockerized Postgres (pg_dump -Fc) into <dir>, with a
    /// manifest.json recording schema version, timestamp, and KEK flag.
    Backup {
        /// Directory to write the dump + manifest into (created if absent).
        dir: PathBuf,
    },
    /// Restore a backup file (pg_restore --clean --if-exists), then print
    /// the SPEC §11b ordering note: ReBAC state before serving.
    Restore {
        /// A .dump file produced by `verity-cli backup`.
        file: PathBuf,
    },
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
enum ManifestCommand {
    /// List the manifests in the registry catalog (index.json).
    List,
    /// Show a manifest's catalog metadata and its YAML.
    Show {
        /// The manifest's source.name (see `manifest list`).
        name: String,
    },
    /// Verify a manifest: sha256 integrity + detached signature → pass/fail.
    Verify { name: String },
    /// Verify + run conformance fixtures, then copy the manifest locally.
    /// Refuses (fail closed) if verify or any fixture fails.
    Fetch {
        name: String,
        /// Output directory (default ./<name>).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify + run fixtures, then upload to the server as a DRAFT
    /// (POST /v1/manifests). Activation stays a separate human-gated admin call.
    Install {
        name: String,
        /// Tenant to upload into (uuid).
        #[arg(long)]
        tenant: String,
        /// Admin bearer token for the upload surface.
        #[arg(long)]
        admin_token: String,
    },
}

#[derive(Subcommand)]
enum ReembedCommand {
    /// Flip the dense query route once backfill is complete (SPEC §5c step 2).
    Cutover {
        /// Restrict the cutover to one tenant (uuid); default = global flip.
        #[arg(long)]
        tenant: Option<String>,
        /// Route to flip to: v2 (cut over) or v1 (rollback).
        #[arg(long, default_value = "v2")]
        to: String,
        /// Cut over below 100% coverage (uncovered chunks fall back to
        /// sparse-only for the new route — an explicit acknowledgment).
        #[arg(long)]
        force: bool,
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
        Command::Dev {
            repo,
            knowledge,
            directory,
        } => dev::run(&mut ctx, repo, knowledge, directory).await,
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
        Command::Manifest { registry, command } => {
            let registry = registry.as_deref();
            match command {
                ManifestCommand::List => manifest::list(registry),
                ManifestCommand::Show { name } => manifest::show(&name, registry),
                ManifestCommand::Verify { name } => manifest::verify(&name, registry),
                ManifestCommand::Fetch { name, out } => {
                    manifest::fetch(&name, out.as_deref(), registry)
                }
                ManifestCommand::Install {
                    name,
                    tenant,
                    admin_token,
                } => manifest::install(&ctx, &name, &tenant, &admin_token, registry).await,
            }
        }
        Command::Tail { once } => tail::run(&ctx, once).await,
        Command::Mcp { command } => match command {
            McpCommand::Install { run, repo } => mcp::install(&ctx, repo, run).await,
        },
        Command::Reembed {
            model,
            tenant,
            batch,
            command,
        } => match command {
            Some(ReembedCommand::Cutover { tenant, to, force }) => {
                reembed::cutover(&ctx, tenant.as_deref(), &to, force).await
            }
            None => match model {
                Some(model) => reembed::backfill(&ctx, &model, tenant.as_deref(), batch).await,
                None => anyhow::bail!(
                    "reembed needs --model <id> to backfill, or the `cutover` subcommand\n  \
                     → e.g. verity-cli reembed --model bge-small-en-v2"
                ),
            },
        },
        Command::Status => status::run(&ctx).await,
        Command::Doctor => doctor::run(&ctx).await,
        Command::Backup { dir } => backup::backup(&dir).await,
        Command::Restore { file } => backup::restore(&file).await,
    }
}
