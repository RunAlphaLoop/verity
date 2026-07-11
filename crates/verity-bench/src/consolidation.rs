//! SRB metric #6 — consolidation precision/recall (docs/design/knowledge-merge-tuning.md §4).
//!
//! Measures the CURRENT knowledge-statement merge decision on a labeled corpus
//! of statement PAIRS (docs/benchmark/consolidation-pairs.jsonl), each tagged
//! `same_generalization: true|false`. For every pair we reproduce the exact
//! propose-or-merge decision the server makes today and compare it to the label:
//! confusion matrix (TP/FP/TN/FN), precision, recall, F1, and a PR curve swept
//! over the cosine threshold so the operating point where precision reaches
//! >= 0.99 is visible and the recall it buys is reported.
//!
//! ## What this mirrors, exactly
//!
//! This harness reproduces `crates/verity-server/src/consolidation.rs`'s
//! `propose_or_merge` (lines 373-405), which decides merge with the SQL predicate
//! at lines 381-397:
//!
//! ```sql
//!   lower(regexp_replace(statement, '\s+', ' ', 'g')) = $normalized   -- normalized-exact
//!   OR (1 - (statement_embedding <=> $vec) >= $threshold)             -- cosine >= threshold
//! ```
//!
//! We mirror both legs:
//!   - normalized-exact via `normalize_term` (lowercase, collapse whitespace),
//!     the exact deterministic normalization consolidation.rs uses (lines 56-61);
//!   - the cosine leg by embedding both statements with the SAME encoder the
//!     server uses on the write path (`verity_encoder::QueryEncoder`, invoked by
//!     `AppState::encode`, main.rs line 172) and comparing cosine similarity to
//!     `VERITY_KNOWLEDGE_MERGE_THRESHOLD` (default 0.85, consolidation.rs line 52,
//!     read in main.rs lines 250-253).
//!
//! pgvector's `<=>` is cosine DISTANCE; `1 - distance` is cosine similarity.
//! The encoder returns L2-normalized vectors, so cosine similarity is their dot
//! product — computed here directly, no database round-trip needed. This is a
//! MEASUREMENT of the shipped decision; it changes no behavior.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use verity_encoder::QueryEncoder;

/// Default cosine merge threshold, mirroring
/// `verity_server::consolidation::DEFAULT_MERGE_THRESHOLD` (0.85) and the
/// `VERITY_KNOWLEDGE_MERGE_THRESHOLD` env default read in verity-server/main.rs.
pub(crate) const DEFAULT_MERGE_THRESHOLD: f32 = 0.85;

/// Default eval-set path (relative to repo root; overridable on the CLI).
pub(crate) const DEFAULT_PAIRS_PATH: &str = "docs/benchmark/consolidation-pairs.jsonl";

#[derive(Deserialize)]
pub(crate) struct Pair {
    #[allow(dead_code)]
    pub id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub domain: String,
    #[serde(default)]
    pub kind: String,
    pub a: String,
    pub b: String,
    pub same_generalization: bool,
}

/// Mirror of `verity_server::consolidation::normalize_term`
/// (consolidation.rs lines 56-61): lowercase, trim, collapse whitespace.
fn normalize_term(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Cosine similarity of two L2-normalized vectors == their dot product.
/// Mirrors `1 - (statement_embedding <=> vec)` for normalized embeddings.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// The merge similarity SCORE for a pair, on [0,1]: 1.0 if the two statements
/// are normalized-exact equal (the fast path consolidation.rs takes before the
/// cosine leg), else their cosine similarity. Sweeping a threshold over this
/// score reproduces the full merge decision (>= threshold => merge).
fn merge_score(enc: &QueryEncoder, a: &str, b: &str) -> Result<f32> {
    if normalize_term(a) == normalize_term(b) {
        return Ok(1.0);
    }
    let va = enc.encode(a)?;
    let vb = enc.encode(b)?;
    Ok(cosine(&va, &vb))
}

#[derive(Default, Clone, Copy)]
struct Confusion {
    tp: u64,
    fp: u64,
    tn: u64,
    fn_: u64,
}

impl Confusion {
    fn observe(&mut self, predicted_merge: bool, truth_same: bool) {
        match (predicted_merge, truth_same) {
            (true, true) => self.tp += 1,
            (true, false) => self.fp += 1,
            (false, false) => self.tn += 1,
            (false, true) => self.fn_ += 1,
        }
    }
    fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 {
            1.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    fn recall(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 {
            0.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
    /// False-merge rate = FP / (FP + TN): the fraction of genuinely-DISTINCT
    /// pairs the decision wrongly merges. This is the CI-gated quantity —
    /// a false merge fabricates cross-customer support (§1's governing asymmetry).
    fn false_merge_rate(&self) -> f64 {
        let d = self.fp + self.tn;
        if d == 0 {
            0.0
        } else {
            self.fp as f64 / d as f64
        }
    }
}

/// Load the labeled pair corpus (one JSON object per line).
pub(crate) fn load_pairs(path: &Path) -> Result<Vec<Pair>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading consolidation eval set {}", path.display()))?;
    let mut pairs = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let p: Pair = serde_json::from_str(line)
            .with_context(|| format!("parsing pair at line {} of {}", i + 1, path.display()))?;
        pairs.push(p);
    }
    anyhow::ensure!(!pairs.is_empty(), "eval set {} is empty", path.display());
    Ok(pairs)
}

/// Result of scoring every pair, plus per-pair scores for the PR sweep.
pub(crate) struct Scored {
    pub scores: Vec<f32>,
    pub truth: Vec<bool>,
    pub n_positive: u64,
    pub n_hard_neg: u64,
    pub n_easy_neg: u64,
    /// Highest-scoring false pair (worst hard negative) for disclosure.
    pub worst_false: Option<(f32, String, String)>,
    /// Lowest-scoring true pair (hardest paraphrase to catch) for disclosure.
    pub worst_true: Option<(f32, String, String)>,
}

/// Embed and score every pair once. Reused by both the SRB report and the
/// stand-alone CI gate so the two never diverge.
pub(crate) fn score_pairs(pairs: &[Pair]) -> Result<Scored> {
    let enc = QueryEncoder::load().context("loading MiniLM-L6 encoder for metric #6")?;
    let mut scores = Vec::with_capacity(pairs.len());
    let mut truth = Vec::with_capacity(pairs.len());
    let (mut n_positive, mut n_hard_neg, mut n_easy_neg) = (0u64, 0u64, 0u64);
    let mut worst_false: Option<(f32, String, String)> = None;
    let mut worst_true: Option<(f32, String, String)> = None;
    for p in pairs {
        let s = merge_score(&enc, &p.a, &p.b)?;
        scores.push(s);
        truth.push(p.same_generalization);
        match (p.same_generalization, p.kind.as_str()) {
            (true, _) => n_positive += 1,
            (false, "hard_negative") => n_hard_neg += 1,
            (false, "easy_negative") => n_easy_neg += 1,
            (false, _) => n_hard_neg += 1,
        }
        if !p.same_generalization && worst_false.as_ref().map(|(x, ..)| s > *x).unwrap_or(true) {
            worst_false = Some((s, p.a.clone(), p.b.clone()));
        }
        if p.same_generalization && worst_true.as_ref().map(|(x, ..)| s < *x).unwrap_or(true) {
            worst_true = Some((s, p.a.clone(), p.b.clone()));
        }
    }
    Ok(Scored {
        scores,
        truth,
        n_positive,
        n_hard_neg,
        n_easy_neg,
        worst_false,
        worst_true,
    })
}

/// Confusion matrix at a given threshold: predict merge iff score >= threshold.
fn confusion_at(scored: &Scored, threshold: f32) -> Confusion {
    let mut c = Confusion::default();
    for (s, t) in scored.scores.iter().zip(&scored.truth) {
        c.observe(*s >= threshold, *t);
    }
    c
}

/// One row of the PR curve.
fn pr_point(scored: &Scored, threshold: f32) -> Value {
    let c = confusion_at(scored, threshold);
    json!({
        "threshold": threshold,
        "tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn_,
        "precision": c.precision(),
        "recall": c.recall(),
        "f1": c.f1(),
        "false_merge_rate": c.false_merge_rate(),
    })
}

/// Build the full metric-6 JSON block from the pre-scored pairs. `encoder` and
/// `threshold` are self-labeled into the block per the honesty policy.
pub(crate) fn build_report(scored: &Scored, operating_threshold: f32, pairs_path: &str) -> Value {
    // PR curve: sweep the cosine threshold 0.30..=1.00 in 0.05 steps, plus the
    // shipped operating point so it always appears exactly.
    let mut sweep_thresholds: Vec<f32> = (6..=20).map(|i| i as f32 * 0.05).collect();
    if !sweep_thresholds
        .iter()
        .any(|t| (*t - operating_threshold).abs() < 1e-6)
    {
        sweep_thresholds.push(operating_threshold);
        sweep_thresholds.sort_by(|a, b| a.partial_cmp(b).unwrap());
    }
    let pr_curve: Vec<Value> = sweep_thresholds
        .iter()
        .map(|t| pr_point(scored, *t))
        .collect();

    // The operating point at the shipped threshold (the number we headline).
    let op = confusion_at(scored, operating_threshold);

    // The lowest threshold that still holds precision >= 0.99 (false-merge rate
    // <= 1%) and the recall it buys — the §4 "defensible operating point".
    let mut best_p99: Option<Value> = None;
    // fine sweep to locate the >=0.99-precision frontier
    let fine: Vec<f32> = (30..=100).map(|i| i as f32 * 0.01).collect();
    for t in &fine {
        let c = confusion_at(scored, *t);
        if c.precision() >= 0.99 {
            // first (lowest) threshold at >=0.99 precision maximizes recall there
            best_p99 = Some(json!({
                "threshold": t,
                "precision": c.precision(),
                "recall": c.recall(),
                "false_merge_rate": c.false_merge_rate(),
                "tp": c.tp, "fp": c.fp, "tn": c.tn, "fn": c.fn_,
            }));
            break;
        }
    }

    let total = scored.truth.len() as u64;
    json!({
        "metric": "consolidation_precision_recall",
        "spec": "docs/design/knowledge-merge-tuning.md §4",
        "mirrors": "crates/verity-server/src/consolidation.rs propose_or_merge (lines 373-405), merge predicate lines 381-397; normalize_term lines 56-61; threshold DEFAULT_MERGE_THRESHOLD line 52",
        "encoder": verity_encoder::MODEL_ID,
        "encoder_dim": verity_encoder::DIM,
        "operating_threshold": operating_threshold,
        "threshold_source": "VERITY_KNOWLEDGE_MERGE_THRESHOLD (default 0.85)",
        "eval_set": pairs_path,
        "corpus": {
            "total_pairs": total,
            "positives": scored.n_positive,
            "hard_negatives": scored.n_hard_neg,
            "easy_negatives": scored.n_easy_neg,
            "negatives": scored.n_hard_neg + scored.n_easy_neg,
        },
        "operating_point": {
            "threshold": operating_threshold,
            "confusion": { "tp": op.tp, "fp": op.fp, "tn": op.tn, "fn": op.fn_ },
            "precision": op.precision(),
            "recall": op.recall(),
            "f1": op.f1(),
            "false_merge_rate": op.false_merge_rate(),
        },
        "precision_99_frontier": best_p99.unwrap_or(json!(null)),
        "pr_curve": pr_curve,
        "worst_hard_negative": scored.worst_false.as_ref().map(|(s, a, b)| json!({
            "score": s, "a": a, "b": b,
            "note": "highest-cosine genuinely-DISTINCT pair — the false merge risk the threshold must stay above",
        })),
        "hardest_true_paraphrase": scored.worst_true.as_ref().map(|(s, a, b)| json!({
            "score": s, "a": a, "b": b,
            "note": "lowest-cosine same-generalization pair — the paraphrase recall the 0.85 threshold misses",
        })),
    })
}

/// Run metric #6 end-to-end for the SRB harness. Loads the eval set, scores
/// every pair, and returns the JSON block.
pub(crate) fn run(pairs_path: &str, operating_threshold: f32) -> Result<Value> {
    let pairs = load_pairs(Path::new(pairs_path))?;
    println!(
        "  loaded {} labeled pairs from {pairs_path}; encoding with {} (threshold {operating_threshold})",
        pairs.len(),
        verity_encoder::MODEL_ID
    );
    let scored = score_pairs(&pairs)?;
    let report = build_report(&scored, operating_threshold, pairs_path);
    let op = &report["operating_point"];
    println!(
        "  operating point @ {operating_threshold}: precision {:.4}  recall {:.4}  F1 {:.4}  false-merge-rate {:.4}",
        op["precision"].as_f64().unwrap_or(f64::NAN),
        op["recall"].as_f64().unwrap_or(f64::NAN),
        op["f1"].as_f64().unwrap_or(f64::NAN),
        op["false_merge_rate"].as_f64().unwrap_or(f64::NAN),
    );
    let c = &op["confusion"];
    println!(
        "  confusion: TP {} FP {} TN {} FN {}",
        c["tp"], c["fp"], c["tn"], c["fn"]
    );
    Ok(report)
}

/// CI gate: score the eval set and assert the false-merge rate at the operating
/// threshold stays <= `max_false_merge_rate`. Returns Err (nonzero exit) on a
/// breach, per the SRB "failure is reportable" rule. Also prints the PR curve.
pub(crate) fn gate(
    pairs_path: &str,
    operating_threshold: f32,
    max_false_merge_rate: f64,
    out: Option<&str>,
) -> Result<()> {
    let report = run(pairs_path, operating_threshold)?;

    // Optionally check in a standalone metric-6 result (RESULTS-consolidation-
    // <date>.{json,md}) — the append-only dated record, same policy as `srb`.
    if let Some(dir) = out {
        std::fs::create_dir_all(dir).with_context(|| format!("creating output dir {dir}"))?;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let machine = crate::srb::machine_info();
        let full = json!({
            "srb_version": "srb-v0",
            "metric": "6",
            "date": date,
            "machine": machine,
            "ci_gate": {
                "target_false_merge_rate": max_false_merge_rate,
                "measured_false_merge_rate": report["operating_point"]["false_merge_rate"],
            },
            "result": report,
        });
        let json_path = format!("{dir}/RESULTS-consolidation-{date}.json");
        std::fs::write(&json_path, serde_json::to_string_pretty(&full)?)?;
        let mut md = format!(
            "# Consolidation precision/recall — SRB metric 6, {date}\n\n**Machine:** {} · {} · {}.\n\n**CI gate:** false-merge-rate target ≤ {:.4}; measured {:.4} at the shipped threshold.\n",
            machine["cpu"].as_str().unwrap_or("?"),
            machine["mem"].as_str().unwrap_or("?"),
            machine["os"].as_str().unwrap_or("?"),
            max_false_merge_rate,
            report["operating_point"]["false_merge_rate"].as_f64().unwrap_or(f64::NAN),
        );
        md.push_str(&render_markdown(&report));
        let md_path = format!("{dir}/RESULTS-consolidation-{date}.md");
        std::fs::write(&md_path, md)?;
        println!("standalone metric-6 report written to {json_path} and {md_path}");
    }

    let fmr = report["operating_point"]["false_merge_rate"]
        .as_f64()
        .unwrap_or(f64::NAN);
    let fp = report["operating_point"]["confusion"]["fp"]
        .as_u64()
        .unwrap_or(0);
    println!(
        "\nCI gate: false-merge-rate {fmr:.4} (FP={fp}) vs target <= {max_false_merge_rate:.4} @ threshold {operating_threshold}"
    );
    anyhow::ensure!(
        fmr <= max_false_merge_rate + 1e-9,
        "CONSOLIDATION FALSE-MERGE RATE {fmr:.4} EXCEEDS TARGET {max_false_merge_rate:.4} \
         (FP={fp} at threshold {operating_threshold}) — a false merge fabricates cross-customer \
         support (knowledge-merge-tuning.md §1); do not ship this tuning"
    );
    println!("CI gate PASSED");
    Ok(())
}

/// Render the metric-6 markdown section for the SRB report.
pub(crate) fn render_markdown(m6: &Value) -> String {
    use std::fmt::Write;
    let mut md = String::new();
    let f = |v: &Value| v.as_f64().unwrap_or(f64::NAN);

    let _ = writeln!(
        md,
        "\n## Metric 6 — consolidation precision/recall (knowledge-merge decision)"
    );
    let c = &m6["corpus"];
    let _ = writeln!(
        md,
        "\n**Encoder:** {} ({}-d). **Operating threshold:** {:.2} ({}). **Eval set:** `{}` — {} pairs ({} positives, {} hard negatives, {} easy negatives).",
        m6["encoder"].as_str().unwrap_or("?"),
        m6["encoder_dim"],
        f(&m6["operating_threshold"]),
        m6["threshold_source"].as_str().unwrap_or("?"),
        m6["eval_set"].as_str().unwrap_or("?"),
        c["total_pairs"], c["positives"], c["hard_negatives"], c["easy_negatives"]
    );
    let _ = writeln!(
        md,
        "\nThis metric mirrors the shipped merge decision: {}. It measures — it changes nothing.",
        m6["mirrors"].as_str().unwrap_or("?")
    );

    let op = &m6["operating_point"];
    let cc = &op["confusion"];
    let _ = writeln!(
        md,
        "\n### Operating point at the shipped threshold ({:.2})",
        f(&op["threshold"])
    );
    let _ = writeln!(md, "\n| | predicted merge | predicted distinct |");
    let _ = writeln!(md, "|---|---|---|");
    let _ = writeln!(
        md,
        "| **actually same** | TP {} | FN {} |",
        cc["tp"], cc["fn"]
    );
    let _ = writeln!(
        md,
        "| **actually distinct** | FP {} | TN {} |",
        cc["fp"], cc["tn"]
    );
    let _ = writeln!(
        md,
        "\n**precision {:.4} · recall {:.4} · F1 {:.4} · false-merge-rate {:.4}**",
        f(&op["precision"]),
        f(&op["recall"]),
        f(&op["f1"]),
        f(&op["false_merge_rate"])
    );

    let fr = &m6["precision_99_frontier"];
    if fr.is_object() {
        let _ = writeln!(
            md,
            "\n### The ≥99%-precision frontier\n\nLowest threshold holding precision ≥ 0.99 (false-merge rate ≤ 1%): **threshold {:.2}** → precision {:.4}, **recall {:.4}** (FP {}, FN {}). *That recall is the capability disclosure: at the precision the trust contract requires, this is how much true paraphrase the current cosine-only decision can catch.*",
            f(&fr["threshold"]),
            f(&fr["precision"]),
            f(&fr["recall"]),
            fr["fp"],
            fr["fn"]
        );
    } else {
        let _ = writeln!(
            md,
            "\n### The ≥99%-precision frontier\n\nNo swept threshold reaches precision ≥ 0.99 on this eval set (hard negatives sit above every threshold that recovers any paraphrase). The cosine-only decision cannot meet the trust contract at any operating point — motivating the cascade (§2)."
        );
    }

    let _ = writeln!(md, "\n### PR curve (threshold sweep)\n");
    let _ = writeln!(
        md,
        "| threshold | TP | FP | TN | FN | precision | recall | F1 | false-merge-rate |"
    );
    let _ = writeln!(md, "|---|---|---|---|---|---|---|---|---|");
    if let Some(rows) = m6["pr_curve"].as_array() {
        for r in rows {
            let _ = writeln!(
                md,
                "| {:.2} | {} | {} | {} | {} | {:.4} | {:.4} | {:.4} | {:.4} |",
                f(&r["threshold"]),
                r["tp"],
                r["fp"],
                r["tn"],
                r["fn"],
                f(&r["precision"]),
                f(&r["recall"]),
                f(&r["f1"]),
                f(&r["false_merge_rate"])
            );
        }
    }

    if let Some(w) = m6["worst_hard_negative"].as_object() {
        let _ = writeln!(
            md,
            "\n**Hardest false pair (highest cosine, genuinely distinct):** {:.4}\n- A: {}\n- B: {}",
            f(&w["score"]),
            w["a"].as_str().unwrap_or("?"),
            w["b"].as_str().unwrap_or("?")
        );
    }
    if let Some(w) = m6["hardest_true_paraphrase"].as_object() {
        let _ = writeln!(
            md,
            "\n**Hardest true paraphrase (lowest cosine, same generalization):** {:.4}\n- A: {}\n- B: {}",
            f(&w["score"]),
            w["a"].as_str().unwrap_or("?"),
            w["b"].as_str().unwrap_or("?")
        );
    }
    md
}
