//! Qdrant-vs-Postgres profile honesty benchmark (docs/BENCHMARKS.md).
//!
//! Seeds an identical chunk corpus into BOTH profiles — one write through the
//! hybrid adapter's real dual-write path lands every chunk in Postgres
//! (pgvector) and Qdrant — then measures filtered dense recall latency
//! through each `StorageAdapter::recall` at controlled visibility
//! selectivities. Same construction as `verity-bench`: principal token 0 is
//! the broad "all company" token on every chunk; token 2 is present with
//! probability 1% (the Postgres profile's known worst-case selectivity band).
//!
//! Numbers are in-process adapter calls: no HTTP API hop, no query encoder.

use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use hdrhistogram::Histogram;
use rand::prelude::*;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;
use verity_storage_qdrant::{collection_name, QdrantAdapter};

const DIM: usize = 384;
const BROAD_TOKEN: i32 = 0;
const ONE_PCT_TOKEN: i32 = 2;
const TENANT_NAME: &str = "qdrant-bench";

#[derive(Parser)]
#[command(
    name = "qdrant-bench",
    about = "Qdrant (SCALE) vs Postgres (DEFAULT) profile: filtered dense recall"
)]
struct Cli {
    /// Postgres DSN. A dedicated bench database keeps corpus size exact —
    /// it is created on `seed` when missing.
    #[arg(
        long,
        default_value = "postgres://verity:verity@localhost:5433/verity_qbench"
    )]
    dsn: String,
    /// Qdrant gRPC URL.
    #[arg(long, default_value = "http://localhost:6334")]
    qdrant_url: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Seed the corpus through the hybrid adapter (dual write: pg + Qdrant).
    Seed {
        #[arg(long, default_value_t = 100_000)]
        chunks: usize,
        #[arg(long, default_value_t = 500)]
        batch: usize,
        /// Concurrent seeding workers.
        #[arg(long, default_value_t = 8)]
        workers: usize,
    },
    /// Measure filtered dense recall on both profiles.
    Run {
        #[arg(long, default_value_t = 200)]
        queries: usize,
        #[arg(long, default_value_t = 10)]
        k: usize,
    },
}

fn unit_vec(rng: &mut impl Rng) -> Vec<f32> {
    let v: Vec<f32> = (0..DIM).map(|_| rng.random_range(-1.0..1.0)).collect();
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    v.into_iter().map(|x| x / n).collect()
}

/// Create the dedicated bench database when missing (admin connection to the
/// compose default `verity` db).
async fn ensure_database(dsn: &str) -> Result<()> {
    let (base, db) = dsn
        .rsplit_once('/')
        .context("dsn has no database segment")?;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base}/verity"))
        .await
        .context("connect admin db")?;
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(db)
        .fetch_optional(&admin)
        .await?;
    if exists.is_none() {
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}")))
            .execute(&admin)
            .await?;
        println!("created database {db}");
    }
    Ok(())
}

async fn seed(cli: &Cli, chunks: usize, batch: usize, workers: usize) -> Result<()> {
    ensure_database(&cli.dsn).await?;
    let inner = PostgresAdapter::connect(&cli.dsn).await?;
    inner.migrate().await?;
    let adapter = std::sync::Arc::new(QdrantAdapter::with_inner(inner, &cli.qdrant_url)?);
    let tenant = adapter.create_tenant(TENANT_NAME).await?;
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "bench".into(),
            source_entity: None,
            kind: EpisodeKind::CdcEvent,
            payload: serde_json::json!({}),
            content_hash: "bench".into(),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await?;

    let started = Instant::now();
    let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..workers {
        let adapter = adapter.clone();
        let next = next.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let start = next.fetch_add(batch, std::sync::atomic::Ordering::Relaxed);
                if start >= chunks {
                    return anyhow::Ok(());
                }
                let end = (start + batch).min(chunks);
                // ThreadRng is !Send: keep it scoped so it never lives
                // across the await below.
                let writes: Vec<ChunkWrite> = {
                    let mut rng = rand::rng();
                    (start..end)
                        .map(|i| {
                            let mut visibility = vec![BROAD_TOKEN];
                            if rng.random_bool(0.01) {
                                visibility.push(ONE_PCT_TOKEN);
                            }
                            ChunkWrite {
                                tenant_id: tenant,
                                source: "bench".into(),
                                document_id: format!("doc-{i}"),
                                seq: 0,
                                content: format!("bench chunk {i} renewal pricing pipeline"),
                                content_hash: format!("b-{i}"),
                                embedding: Some(unit_vec(&mut rng)),
                                visibility,
                                entity_tags: vec![format!("account:{}", i % 1000)],
                                confidentiality: Confidentiality::Internal,
                                trust_tier: TrustTier::Authoritative,
                                valid_from: Utc::now(),
                                provenance: episode,
                                acl_provenance: AclProvenance::AdminAssigned,
                            }
                        })
                        .collect()
                };
                adapter
                    .upsert_chunks(writes)
                    .await
                    .map_err(|e| anyhow::anyhow!("seed batch {start}..{end} failed: {e}"))?;
                if (end / batch).is_multiple_of(20) {
                    println!("  seeded ~{end} chunks");
                }
            }
        }));
    }
    for t in tasks {
        t.await??;
    }
    println!(
        "seeded {chunks} chunks into both profiles in {:.1}s",
        started.elapsed().as_secs_f64()
    );

    // pg planner stats are load-bearing for the selectivity router.
    sqlx::query("ANALYZE chunks")
        .execute(adapter.inner().pool())
        .await?;

    // Wait for Qdrant background HNSW optimization to settle so the run
    // measures index search, not a build in progress. Status 1 = green.
    let collection = collection_name(tenant);
    loop {
        let info = adapter.qdrant().collection_info(&collection).await?;
        let status = info.result.as_ref().map(|r| r.status).unwrap_or_default();
        if status == 1 {
            break;
        }
        println!("  waiting for qdrant optimizer (status {status})...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    println!("qdrant collection green");
    Ok(())
}

async fn tenant_id(adapter: &PostgresAdapter) -> Result<TenantId> {
    let id: Uuid = sqlx::query_scalar("SELECT id FROM tenants WHERE name = $1")
        .bind(TENANT_NAME)
        .fetch_one(adapter.pool())
        .await
        .context("bench tenant missing — run seed first")?;
    Ok(id)
}

fn scope(tenant: TenantId, token: i32) -> Scope {
    Scope {
        tenant_id: tenant,
        principals: vec![token],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Confidential,
    }
}

async fn measure(
    label: &str,
    adapter: &dyn StorageAdapter,
    tenant: TenantId,
    token: i32,
    queries: usize,
    k: usize,
) -> Result<()> {
    let mut rng = rand::rng();
    let mut hist = Histogram::<u64>::new(3)?;
    let mut total_hits = 0usize;
    // Warmup.
    for _ in 0..10 {
        adapter
            .recall(RecallQuery {
                scope: scope(tenant, token),
                embedding: Some(unit_vec(&mut rng)),
                text: None,
                k,
            })
            .await
            .map_err(|e| anyhow::anyhow!("warmup recall failed: {e}"))?;
    }
    for _ in 0..queries {
        let query = RecallQuery {
            scope: scope(tenant, token),
            embedding: Some(unit_vec(&mut rng)),
            text: None,
            k,
        };
        let t0 = Instant::now();
        let hits = adapter
            .recall(query)
            .await
            .map_err(|e| anyhow::anyhow!("recall failed: {e}"))?;
        hist.record(t0.elapsed().as_micros() as u64)?;
        total_hits += hits.len();
    }
    println!(
        "| {label} | {:.2}ms | {:.2}ms | {:.2}ms |  (avg hits {:.1})",
        hist.value_at_quantile(0.50) as f64 / 1000.0,
        hist.value_at_quantile(0.95) as f64 / 1000.0,
        hist.value_at_quantile(0.99) as f64 / 1000.0,
        total_hits as f64 / queries as f64,
    );
    Ok(())
}

async fn run(cli: &Cli, queries: usize, k: usize) -> Result<()> {
    let pg = PostgresAdapter::connect(&cli.dsn).await?;
    let tenant = tenant_id(&pg).await?;
    let hybrid =
        QdrantAdapter::with_inner(PostgresAdapter::connect(&cli.dsn).await?, &cli.qdrant_url)?;

    println!("| Case | p50 | p95 | p99 |");
    println!("|---|---|---|---|");
    let one = ONE_PCT_TOKEN;
    let broad = BROAD_TOKEN;
    measure(
        "Qdrant dense @ 1% selectivity",
        &hybrid,
        tenant,
        one,
        queries,
        k,
    )
    .await?;
    measure(
        "Qdrant dense broad token",
        &hybrid,
        tenant,
        broad,
        queries,
        k,
    )
    .await?;
    measure(
        "Postgres dense @ 1% selectivity",
        &pg,
        tenant,
        one,
        queries,
        k,
    )
    .await?;
    measure("Postgres dense broad token", &pg, tenant, broad, queries, k).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Seed {
            chunks,
            batch,
            workers,
        } => seed(&cli, chunks, batch, workers).await,
        Command::Run { queries, k } => run(&cli, queries, k).await,
    }
}
