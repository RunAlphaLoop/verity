//! The week-1 honesty benchmark (SPEC §4, §13 Milestone A).
//!
//! Measures what the spec actually claims, at realistic ACL shape:
//! filtered ANN at controlled visibility selectivities, BM25, hybrid fusion,
//! and L1 point reads. Every published Verity number comes from here, at a
//! stated corpus size, selectivity, and machine — never from vendor docs.
//!
//! Selectivity is constructed, not sampled: principal token T_s is present in
//! a chunk's visibility array with probability s, so a query scoped to {T_s}
//! sees exactly ~s of the corpus. Token 0 is the "all company" broad token on
//! every chunk (the unfiltered baseline).

use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use hdrhistogram::Histogram;
use rand::prelude::*;
use rand_distr::StandardNormal;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

const DIM: usize = 384;
/// (principal token id, fraction of corpus it can see)
const SELECTIVITY_TOKENS: &[(i32, f64)] = &[(1, 0.001), (2, 0.01), (3, 0.1), (4, 0.5)];
const BROAD_TOKEN: i32 = 0;
const WORDS: &[&str] = &[
    "renewal",
    "pricing",
    "quote",
    "discount",
    "opportunity",
    "pipeline",
    "contract",
    "churn",
    "onboarding",
    "escalation",
    "ticket",
    "invoice",
    "meeting",
    "demo",
    "integration",
    "security",
    "review",
    "budget",
    "quarter",
    "stakeholder",
    "procurement",
    "legal",
    "redline",
    "expansion",
    "usage",
    "adoption",
    "support",
    "incident",
    "migration",
    "roadmap",
    "feedback",
    "champion",
];

#[derive(Parser)]
#[command(
    name = "verity-bench",
    about = "Verity filtered-retrieval honesty benchmark"
)]
struct Cli {
    /// Postgres DSN (the deploy/docker-compose.yml default).
    #[arg(long, default_value = "postgres://verity:verity@localhost:5433/verity")]
    dsn: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create schema and load a synthetic corpus with constructed ACL selectivities.
    Seed {
        #[arg(long, default_value_t = 100_000)]
        chunks: usize,
        #[arg(long, default_value_t = 1_000)]
        entities: usize,
        /// L1 fact rows to seed for the point-read benchmark.
        #[arg(long, default_value_t = 10_000)]
        facts: usize,
    },
    /// Run the latency suite against a seeded corpus.
    Run {
        #[arg(long, default_value_t = 200)]
        queries: usize,
        #[arg(long, default_value_t = 10)]
        k: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let adapter = PostgresAdapter::connect(&cli.dsn)
        .await
        .context("connecting to Postgres — is deploy/docker-compose.yml up?")?;

    match cli.command {
        Command::Seed {
            chunks,
            entities,
            facts,
        } => seed(&adapter, chunks, entities, facts).await,
        Command::Run { queries, k } => run(&adapter, queries, k).await,
    }
}

fn random_unit_vector(rng: &mut impl Rng) -> Vec<f32> {
    let mut v: Vec<f32> = (0..DIM).map(|_| rng.sample(StandardNormal)).collect();
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    v.iter_mut().for_each(|x| *x /= norm);
    v
}

fn random_sentence(rng: &mut impl Rng) -> String {
    (0..12)
        .map(|_| *WORDS.choose(rng).expect("word pool is non-empty"))
        .collect::<Vec<_>>()
        .join(" ")
}

async fn seed(
    adapter: &PostgresAdapter,
    n_chunks: usize,
    n_entities: usize,
    n_facts: usize,
) -> Result<()> {
    adapter.migrate().await?;
    let tenant = adapter.create_tenant("bench").await?;
    let mut rng = rand::rng();

    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "bench".into(),
            source_entity: None,
            kind: EpisodeKind::CdcEvent,
            payload: serde_json::json!({"seed": true}),
            content_hash: "seed".into(),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await?;

    println!("seeding {n_chunks} chunks ({DIM}-d vectors, constructed ACL selectivities)...");
    let started = Instant::now();
    let mut batch = Vec::with_capacity(500);
    for i in 0..n_chunks {
        let mut visibility = vec![BROAD_TOKEN];
        for &(token, selectivity) in SELECTIVITY_TOKENS {
            if rng.random_bool(selectivity) {
                visibility.push(token);
            }
        }
        batch.push(ChunkWrite {
            tenant_id: tenant,
            source: "bench".into(),
            document_id: format!("doc-{}", i / 10),
            seq: (i % 10) as i32,
            content: random_sentence(&mut rng),
            content_hash: format!("h{i}"),
            embedding: Some(random_unit_vector(&mut rng)),
            visibility,
            entity_tags: vec![format!("account:{}", rng.random_range(0..n_entities))],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: Utc::now(),
            provenance: episode,
        });
        if batch.len() == 500 {
            adapter.upsert_chunks(std::mem::take(&mut batch)).await?;
            if (i + 1) % 10_000 == 0 {
                println!("  {} / {n_chunks} ({:.0?})", i + 1, started.elapsed());
            }
        }
    }
    if !batch.is_empty() {
        adapter.upsert_chunks(batch).await?;
    }

    println!("seeding {n_facts} L1 facts...");
    for i in 0..n_facts {
        adapter
            .upsert_fact(FactWrite {
                tenant_id: tenant,
                key: FactKey {
                    source: "bench".into(),
                    entity_id: format!("account-{}", i % n_entities),
                    field: format!("field-{}", i / n_entities),
                },
                value: serde_json::json!(i),
                valid_from: Utc::now(),
                provenance: episode,
            })
            .await?;
    }

    println!("seed complete in {:.0?}", started.elapsed());
    Ok(())
}

async fn run(adapter: &PostgresAdapter, n_queries: usize, k: usize) -> Result<()> {
    let tenant = adapter.create_tenant("bench").await?;
    let mut rng = rand::rng();
    let mut report = Vec::new();

    let corpus: i64 = sqlx::query_scalar("SELECT count(*) FROM chunks WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(adapter.pool())
        .await?;
    println!("corpus: {corpus} chunks, k={k}, {n_queries} queries per case\n");

    let mut cases: Vec<(String, Vec<PrincipalToken>)> =
        vec![("unfiltered (broad token)".into(), vec![BROAD_TOKEN])];
    for &(token, s) in SELECTIVITY_TOKENS {
        cases.push((
            format!("filtered ANN @ {:.1}% selectivity", s * 100.0),
            vec![token],
        ));
    }

    for (label, principals) in &cases {
        let mut hist = Histogram::<u64>::new(3)?;
        let mut total_hits = 0usize;
        for _ in 0..n_queries {
            let scope = Scope {
                tenant_id: tenant,
                principals: principals.clone(),
                entity_scope: vec![],
                max_confidentiality: Confidentiality::Confidential,
            };
            let embedding = random_unit_vector(&mut rng);
            let t = Instant::now();
            let hits = adapter
                .recall(RecallQuery {
                    scope,
                    embedding: Some(embedding),
                    text: None,
                    k,
                })
                .await?;
            hist.record(t.elapsed().as_micros() as u64)?;
            total_hits += hits.len();
        }
        report.push(print_case(
            label,
            &hist,
            total_hits as f64 / n_queries as f64,
            k,
        ));
    }

    // BM25-only and hybrid, at the 1% selectivity token.
    for (label, with_dense) in [
        ("BM25 @ 1% selectivity", false),
        ("hybrid (dense+BM25) @ 1%", true),
    ] {
        let mut hist = Histogram::<u64>::new(3)?;
        let mut total_hits = 0usize;
        for _ in 0..n_queries {
            let scope = Scope {
                tenant_id: tenant,
                principals: vec![2],
                entity_scope: vec![],
                max_confidentiality: Confidentiality::Confidential,
            };
            let text = format!(
                "{} {}",
                WORDS.choose(&mut rng).expect("word pool"),
                WORDS.choose(&mut rng).expect("word pool")
            );
            let embedding = with_dense.then(|| random_unit_vector(&mut rng));
            let t = Instant::now();
            let hits = adapter
                .recall(RecallQuery {
                    scope,
                    embedding,
                    text: Some(text),
                    k,
                })
                .await?;
            hist.record(t.elapsed().as_micros() as u64)?;
            total_hits += hits.len();
        }
        report.push(print_case(
            label,
            &hist,
            total_hits as f64 / n_queries as f64,
            k,
        ));
    }

    // L1 point reads: the ~ms `get` path.
    let mut hist = Histogram::<u64>::new(3)?;
    for i in 0..n_queries {
        let key = FactKey {
            source: "bench".into(),
            entity_id: format!("account-{}", i % 1000),
            field: "field-0".into(),
        };
        let t = Instant::now();
        adapter.current_fact(tenant, &key).await?;
        hist.record(t.elapsed().as_micros() as u64)?;
    }
    report.push(print_case("L1 point read (current_fact)", &hist, 1.0, 1));

    std::fs::create_dir_all("bench-results")?;
    let path = format!("bench-results/{}.json", Utc::now().format("%Y%m%dT%H%M%S"));
    std::fs::write(&path, serde_json::to_string_pretty(&report)?)?;
    println!("\nresults written to {path}");
    println!("(corpus={corpus}; report p50/p95/p99 with this context — numbers without corpus size and selectivity are not honest numbers)");
    Ok(())
}

fn print_case(label: &str, hist: &Histogram<u64>, mean_hits: f64, k: usize) -> serde_json::Value {
    let (p50, p95, p99) = (
        hist.value_at_quantile(0.50) as f64 / 1000.0,
        hist.value_at_quantile(0.95) as f64 / 1000.0,
        hist.value_at_quantile(0.99) as f64 / 1000.0,
    );
    println!(
        "{label:<38} p50 {p50:>7.2}ms  p95 {p95:>7.2}ms  p99 {p99:>7.2}ms  hits {mean_hits:.1}/{k}"
    );
    serde_json::json!({
        "case": label, "p50_ms": p50, "p95_ms": p95, "p99_ms": p99,
        "mean_hits": mean_hits, "k": k,
    })
}
