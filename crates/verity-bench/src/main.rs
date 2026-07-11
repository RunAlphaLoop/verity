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

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use hdrhistogram::Histogram;
use rand::prelude::*;
use rand_distr::StandardNormal;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

mod consolidation;
mod srb;

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
    /// Benchmark the local query encoder (SPEC §4a) — the embedding cost that
    /// honest recall numbers must include. Needs no database.
    Encode {
        #[arg(long, default_value_t = 100)]
        queries: usize,
    },
    /// QPS-under-load (SPEC §4d): N concurrent tasks run a mixed workload
    /// (70% hybrid recall @ 1% selectivity, 20% L1 point reads, 10% activity
    /// timeline reads) against the adapter in-process — same pattern as `run`,
    /// no HTTP hop, no query encoder.
    Load {
        #[arg(long, default_value_t = 16)]
        concurrency: usize,
        #[arg(long, default_value_t = 30)]
        duration_secs: u64,
        #[arg(long, default_value_t = 10)]
        k: usize,
        /// Run concurrency levels {4, 16, 64} sequentially instead of --concurrency.
        #[arg(long, default_value_t = false)]
        sweep: bool,
    },
    /// Scoped Recall Benchmark v0 (SPEC §13): metric 1 (cross-entity leakage
    /// under adversarial probes, target 0) and metric 2 (stale-citation rate
    /// after CDC supersession, target ~0) on fresh tenants it seeds itself,
    /// plus metric 4 (scoped-read latency + QPS, local encoder included)
    /// against the pre-seeded corpus. Emits versioned JSON and a markdown
    /// report. Metrics 3 and 5 are defined-not-yet-reported.
    Srb {
        /// Tenant holding the pre-seeded latency corpus (see `seed`).
        #[arg(long, default_value = "bench")]
        corpus_tenant: String,
        /// Output directory for RESULTS-<date>.{json,md}.
        #[arg(long, default_value = "docs/benchmark")]
        out: String,
        /// Randomized adversarial scopes for metric 1 (each probes every read path).
        #[arg(long, default_value_t = 200)]
        scopes: usize,
        /// Write→supersede→read cycles for metric 2.
        #[arg(long, default_value_t = 100)]
        cycles: usize,
        /// Queries per latency case (metric 4).
        #[arg(long, default_value_t = 200)]
        queries: usize,
        /// Seconds per load-sweep level (metric 4 runs N=4 and N=16).
        #[arg(long, default_value_t = 20)]
        load_secs: u64,
        /// Metric 6 labeled statement-pair eval set.
        #[arg(long, default_value = consolidation::DEFAULT_PAIRS_PATH)]
        consolidation_pairs: String,
        /// Metric 6 merge threshold (mirrors VERITY_KNOWLEDGE_MERGE_THRESHOLD).
        #[arg(long, default_value_t = consolidation::DEFAULT_MERGE_THRESHOLD)]
        merge_threshold: f32,
    },
    /// SRB metric 6 CI gate (docs/design/knowledge-merge-tuning.md §4): score
    /// the labeled consolidation-pair eval set with the CURRENT merge decision
    /// and fail (nonzero exit) if the false-merge rate FP/(FP+TN) at the
    /// operating threshold exceeds the target. Needs no database — the merge
    /// decision is encoder+cosine only. Wire into CI to block any tuning that
    /// raises the false-merge rate.
    ConsolidationGate {
        /// Labeled statement-pair eval set.
        #[arg(long, default_value = consolidation::DEFAULT_PAIRS_PATH)]
        pairs: String,
        /// Merge threshold under test (mirrors VERITY_KNOWLEDGE_MERGE_THRESHOLD).
        #[arg(long, default_value_t = consolidation::DEFAULT_MERGE_THRESHOLD)]
        threshold: f32,
        /// Maximum tolerated false-merge rate FP/(FP+TN).
        #[arg(long, default_value_t = 0.01)]
        max_false_merge_rate: f64,
        /// If set, also write a standalone dated RESULTS-consolidation-<date>.{json,md}.
        #[arg(long)]
        out: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::Encode { queries } = cli.command {
        return encode(queries);
    }
    // The consolidation gate is encoder+cosine only — no database.
    if let Command::ConsolidationGate {
        pairs,
        threshold,
        max_false_merge_rate,
        out,
    } = &cli.command
    {
        return consolidation::gate(pairs, *threshold, *max_false_merge_rate, out.as_deref());
    }

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
        Command::Load {
            concurrency,
            duration_secs,
            k,
            sweep,
        } => {
            let levels: &[usize] = if sweep { &[4, 16, 64] } else { &[concurrency] };
            load(Arc::new(adapter), levels, duration_secs, k).await
        }
        Command::Srb {
            corpus_tenant,
            out,
            scopes,
            cycles,
            queries,
            load_secs,
            consolidation_pairs,
            merge_threshold,
        } => {
            srb::run_srb(
                Arc::new(adapter),
                srb::SrbArgs {
                    corpus_tenant,
                    out,
                    scopes,
                    cycles,
                    queries,
                    load_secs,
                    consolidation_pairs,
                    merge_threshold,
                },
            )
            .await
        }
        Command::Encode { .. } | Command::ConsolidationGate { .. } => {
            unreachable!("handled above")
        }
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
            acl_provenance: AclProvenance::AdminAssigned,
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
                acl_provenance: AclProvenance::AdminAssigned,
            })
            .await?;
    }

    println!("seed complete in {:.0?}", started.elapsed());
    Ok(())
}

async fn run(adapter: &PostgresAdapter, n_queries: usize, k: usize) -> Result<()> {
    let (corpus, report) = run_suite(adapter, "bench", n_queries, k).await?;

    std::fs::create_dir_all("bench-results")?;
    let path = format!("bench-results/{}.json", Utc::now().format("%Y%m%dT%H%M%S"));
    std::fs::write(&path, serde_json::to_string_pretty(&report)?)?;
    println!("\nresults written to {path}");
    println!("(corpus={corpus}; report p50/p95/p99 with this context — numbers without corpus size and selectivity are not honest numbers)");
    Ok(())
}

/// The latency suite, reusable by both the `run` subcommand and the SRB
/// harness (metric 4). Returns (corpus size, per-case JSON reports).
async fn run_suite(
    adapter: &PostgresAdapter,
    tenant_name: &str,
    n_queries: usize,
    k: usize,
) -> Result<(i64, Vec<serde_json::Value>)> {
    let tenant = adapter.create_tenant(tenant_name).await?;
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

    // BM25 with an entity-bound scope over the *broad* visibility token: the
    // migration-0004 caveat probe. Visibility/validity are pushed into Tantivy,
    // but `entity_tags <@ scope` stays a heap filter — a broad principal set
    // maximizes the pushed-down candidate set that filter must chew through.
    {
        let mut hist = Histogram::<u64>::new(3)?;
        let mut total_hits = 0usize;
        for _ in 0..n_queries {
            let scope = Scope {
                tenant_id: tenant,
                principals: vec![BROAD_TOKEN],
                entity_scope: vec!["account:0".into()],
                max_confidentiality: Confidentiality::Confidential,
            };
            let text = format!(
                "{} {}",
                WORDS.choose(&mut rng).expect("word pool"),
                WORDS.choose(&mut rng).expect("word pool")
            );
            let t = Instant::now();
            let hits = adapter
                .recall(RecallQuery {
                    scope,
                    embedding: None,
                    text: Some(text),
                    k,
                })
                .await?;
            hist.record(t.elapsed().as_micros() as u64)?;
            total_hits += hits.len();
        }
        report.push(print_case(
            "BM25 entity-bound + broad visibility",
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

    Ok((corpus, report))
}

/// The mixed-workload op types, in workload-share order.
const LOAD_OPS: &[&str] = &["hybrid recall @ 1%", "current_fact", "activity"];

/// QPS-under-load (SPEC §4d): closed-loop, zero think time. Each of N tokio
/// tasks loops the 70/20/10 mix until the deadline; latencies are recorded
/// under load (they include any wait for one of the adapter pool's 16
/// connections — at N > 16 that queueing is the point of the measurement).
async fn load(
    adapter: Arc<PostgresAdapter>,
    levels: &[usize],
    duration_secs: u64,
    k: usize,
) -> Result<()> {
    let tenant = adapter.create_tenant("bench").await?;
    let corpus: i64 = sqlx::query_scalar("SELECT count(*) FROM chunks WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(adapter.pool())
        .await?;
    println!(
        "corpus: {corpus} chunks, k={k}, {duration_secs}s per level, mix: 70% hybrid recall @ 1% / 20% current_fact / 10% activity\n"
    );

    let mut report = Vec::new();
    for &concurrency in levels {
        report.push(load_at(&adapter, tenant, concurrency, duration_secs, k).await?);
        println!();
    }

    std::fs::create_dir_all("bench-results")?;
    let path = format!(
        "bench-results/load-{}.json",
        Utc::now().format("%Y%m%dT%H%M%S")
    );
    std::fs::write(&path, serde_json::to_string_pretty(&report)?)?;
    println!("results written to {path}");
    println!("(corpus={corpus}; in-process adapter calls — no HTTP hop, no query encoder; closed loop, zero think time)");
    Ok(())
}

async fn load_at(
    adapter: &Arc<PostgresAdapter>,
    tenant: TenantId,
    concurrency: usize,
    duration_secs: u64,
    k: usize,
) -> Result<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let started = Instant::now();

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let adapter = Arc::clone(adapter);
        handles.push(tokio::spawn(async move {
            let mut rng = StdRng::from_os_rng();
            let mut hists = [
                Histogram::<u64>::new(3)?,
                Histogram::<u64>::new(3)?,
                Histogram::<u64>::new(3)?,
            ];
            while Instant::now() < deadline {
                let roll: f64 = rng.random();
                let (op, t) = if roll < 0.7 {
                    let query = RecallQuery {
                        scope: Scope {
                            tenant_id: tenant,
                            principals: vec![2], // the 1% selectivity token
                            entity_scope: vec![],
                            max_confidentiality: Confidentiality::Confidential,
                        },
                        embedding: Some(random_unit_vector(&mut rng)),
                        text: Some(format!(
                            "{} {}",
                            WORDS.choose(&mut rng).expect("word pool"),
                            WORDS.choose(&mut rng).expect("word pool")
                        )),
                        k,
                    };
                    let t = Instant::now();
                    adapter.recall(query).await?;
                    (0, t)
                } else if roll < 0.9 {
                    let key = FactKey {
                        source: "bench".into(),
                        entity_id: format!("account-{}", rng.random_range(0..1000)),
                        field: "field-0".into(),
                    };
                    let t = Instant::now();
                    adapter.current_fact(tenant, &key).await?;
                    (1, t)
                } else {
                    let query = ActivityQuery {
                        scope: Scope {
                            tenant_id: tenant,
                            principals: vec![BROAD_TOKEN],
                            entity_scope: vec![],
                            max_confidentiality: Confidentiality::Confidential,
                        },
                        entity: format!("account:{}", rng.random_range(0..1000)),
                        since: None,
                        action_types: vec![],
                        actors: vec![],
                        limit: 20,
                    };
                    let t = Instant::now();
                    adapter.activity(query).await?;
                    (2, t)
                };
                hists[op].record(t.elapsed().as_micros() as u64)?;
            }
            anyhow::Ok(hists)
        }));
    }

    let mut merged = [
        Histogram::<u64>::new(3)?,
        Histogram::<u64>::new(3)?,
        Histogram::<u64>::new(3)?,
    ];
    for handle in handles {
        let hists = handle.await??;
        for (m, h) in merged.iter_mut().zip(hists.iter()) {
            m.add(h)?;
        }
    }
    let elapsed = started.elapsed().as_secs_f64();

    let total_ops: u64 = merged.iter().map(|h| h.len()).sum();
    println!(
        "concurrency {concurrency:>3}: {total_ops} ops in {elapsed:.1}s = {:.0} QPS overall",
        total_ops as f64 / elapsed
    );
    let mut per_op = Vec::new();
    for (label, hist) in LOAD_OPS.iter().zip(merged.iter()) {
        let (p50, p95, p99) = (
            hist.value_at_quantile(0.50) as f64 / 1000.0,
            hist.value_at_quantile(0.95) as f64 / 1000.0,
            hist.value_at_quantile(0.99) as f64 / 1000.0,
        );
        let throughput = hist.len() as f64 / elapsed;
        println!(
            "  {label:<24} {:>8} ops  {throughput:>8.1} ops/s  p50 {p50:>7.2}ms  p95 {p95:>7.2}ms  p99 {p99:>7.2}ms",
            hist.len()
        );
        per_op.push(serde_json::json!({
            "op": label, "ops": hist.len(), "ops_per_sec": throughput,
            "p50_ms": p50, "p95_ms": p95, "p99_ms": p99,
        }));
    }
    Ok(serde_json::json!({
        "concurrency": concurrency,
        "duration_secs": elapsed,
        "total_ops": total_ops,
        "qps": total_ops as f64 / elapsed,
        "ops": per_op,
    }))
}

/// Local query-encoder latency (SPEC §4a): tokenizer + MiniLM-L6 ONNX forward
/// pass + mean-pool + normalize, per short synthetic query. This is the cost
/// every published dense/hybrid recall number must carry on cache misses.
fn encode(n_queries: usize) -> Result<()> {
    encode_suite(n_queries)?;
    println!("\n({n_queries} short queries, single thread, cold cache per query — SPEC §4a budgets 5-15ms)");
    Ok(())
}

/// The encoder measurement, reusable by the SRB harness. Returns the case JSON.
fn encode_suite(n_queries: usize) -> Result<serde_json::Value> {
    println!(
        "loading {} ({}-d; first run downloads to the hf-hub cache)...",
        verity_encoder::MODEL_ID,
        verity_encoder::DIM
    );
    let started = Instant::now();
    let encoder = verity_encoder::QueryEncoder::load()?;
    println!("encoder ready in {:.1?}", started.elapsed());

    for _ in 0..5 {
        encoder.encode("warmup query about renewal pricing for the acme account")?;
    }

    let mut rng = rand::rng();
    let mut hist = Histogram::<u64>::new(3)?;
    for i in 0..n_queries {
        let query = format!(
            "{} {} status for account {}",
            WORDS.choose(&mut rng).expect("word pool"),
            WORDS.choose(&mut rng).expect("word pool"),
            i % 100,
        );
        let t = Instant::now();
        let v = encoder.encode(&query)?;
        hist.record(t.elapsed().as_micros() as u64)?;
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        anyhow::ensure!(
            v.len() == verity_encoder::DIM && (norm - 1.0).abs() < 1e-3,
            "embedding sanity check failed: len {}, norm {norm}",
            v.len()
        );
    }
    Ok(print_case(
        "local query encode (MiniLM-L6 ONNX)",
        &hist,
        1.0,
        1,
    ))
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
