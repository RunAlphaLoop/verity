//! Local ONNX query encoder (SPEC §4a, mechanism 2).
//!
//! `recall`'s dense leg needs a query vector, and the honest-numbers policy
//! (§4a, CLAUDE.md) says published retrieval latency must *include* query
//! embedding — no silently-omitted 50–300ms remote round trip. This crate is
//! the default local dense path: sentence-transformers/all-MiniLM-L6-v2
//! (384-d, matching the `vector(384)` chunk schema) executed on CPU via ONNX
//! Runtime. No GPU, no network on the read path; model files are fetched once
//! from the Hugging Face Hub into its default cache.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;
use tokenizers::{Tokenizer, TruncationParams};

/// Hugging Face Hub repo the encoder weights come from.
pub const MODEL_ID: &str = "sentence-transformers/all-MiniLM-L6-v2";
/// Output embedding dimensionality — must match the `vector(384)` schema.
pub const DIM: usize = 384;
/// Queries are truncated to this many tokens before encoding.
pub const MAX_TOKENS: usize = 256;

/// A local, CPU-only query encoder producing L2-normalized 384-d vectors.
///
/// `Send + Sync`: share one instance behind an `Arc` across request handlers.
/// ort 2.0.0-rc.12's `Session::run` takes `&mut self`, so runs are serialized
/// through an internal mutex; the model is small enough (~23MB, ~6 layers)
/// that per-query latency, not intra-encoder parallelism, is the story.
pub struct QueryEncoder {
    tokenizer: Tokenizer,
    session: Mutex<Session>,
}

impl QueryEncoder {
    /// Fetch model files (cached after the first call) and build a ready
    /// encoder.
    pub fn load() -> Result<Self> {
        let (model, tokenizer) = fetch_model_files()?;
        Self::from_files(&model, &tokenizer)
    }

    /// Build an encoder from already-downloaded `model.onnx` and
    /// `tokenizer.json` paths (air-gapped deployments).
    pub fn from_files(model: &Path, tokenizer: &Path) -> Result<Self> {
        let mut tokenizer =
            Tokenizer::from_file(tokenizer).map_err(|e| anyhow!("loading tokenizer: {e}"))?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: MAX_TOKENS,
                ..Default::default()
            }))
            .map_err(|e| anyhow!("configuring truncation: {e}"))?;

        // Builder errors carry the `SessionBuilder` back (`Error<SessionBuilder>`,
        // not Send + Sync); funnel through `ort::Result` to erase that payload
        // before handing anyhow the error.
        let session = (|| -> ort::Result<Session> {
            Session::builder()?
                .with_optimization_level(GraphOptimizationLevel::Level3)?
                .commit_from_file(model)
        })()
        .context("loading ONNX model")?;

        Ok(Self {
            tokenizer,
            session: Mutex::new(session),
        })
    }

    /// Encode a query: tokenize (truncated to [`MAX_TOKENS`]), run the model,
    /// mean-pool token embeddings over the attention mask, L2-normalize.
    pub fn encode(&self, text: &str) -> Result<Vec<f32>> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow!("tokenizing query: {e}"))?;
        let ids: Vec<i64> = encoding.get_ids().iter().map(|&t| t as i64).collect();
        let mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&m| m as i64)
            .collect();
        let type_ids: Vec<i64> = encoding.get_type_ids().iter().map(|&t| t as i64).collect();
        let seq = ids.len();

        let inputs = ort::inputs! {
            "input_ids" => Tensor::from_array(([1, seq], ids))?,
            "attention_mask" => Tensor::from_array(([1, seq], mask.clone()))?,
            "token_type_ids" => Tensor::from_array(([1, seq], type_ids))?,
        };
        let mut session = self.session.lock().expect("encoder session mutex poisoned");
        let outputs = session.run(inputs)?;
        let (shape, hidden) = outputs["last_hidden_state"].try_extract_tensor::<f32>()?;
        anyhow::ensure!(
            **shape == [1, seq as i64, DIM as i64],
            "unexpected model output shape {shape:?}"
        );

        // Mean-pool over real (unmasked) tokens, then L2-normalize.
        let mut pooled = vec![0.0f32; DIM];
        let mut n_tokens = 0.0f32;
        for (t, &m) in mask.iter().enumerate() {
            if m == 0 {
                continue;
            }
            n_tokens += 1.0;
            let row = &hidden[t * DIM..(t + 1) * DIM];
            for (acc, &x) in pooled.iter_mut().zip(row) {
                *acc += x;
            }
        }
        anyhow::ensure!(n_tokens > 0.0, "query produced no tokens");
        let inv = 1.0 / n_tokens;
        pooled.iter_mut().for_each(|x| *x *= inv);
        let norm = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
        anyhow::ensure!(norm > 0.0, "degenerate zero embedding");
        pooled.iter_mut().for_each(|x| *x /= norm);
        Ok(pooled)
    }
}

/// Download `onnx/model.onnx` and `tokenizer.json` from [`MODEL_ID`] into the
/// hf-hub default cache (no-op after the first run) and return their paths.
pub fn fetch_model_files() -> Result<(PathBuf, PathBuf)> {
    let api = hf_hub::api::sync::Api::new().context("initializing hf-hub client")?;
    let repo = api.model(MODEL_ID.to_string());
    let model = repo
        .get("onnx/model.onnx")
        .with_context(|| format!("fetching onnx/model.onnx from {MODEL_ID}"))?;
    let tokenizer = repo
        .get("tokenizer.json")
        .with_context(|| format!("fetching tokenizer.json from {MODEL_ID}"))?;
    Ok((model, tokenizer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b).map(|(x, y)| x * y).sum()
    }

    /// Norm checks can't catch valid-norm garbage (wrong output tensor, broken
    /// pooling); related queries must land measurably closer than unrelated
    /// ones. Gated on VERITY_ENCODER_TEST=1 (downloads the model on first run).
    #[test]
    fn embeddings_are_semantically_ordered() {
        if std::env::var("VERITY_ENCODER_TEST").as_deref() != Ok("1") {
            eprintln!("VERITY_ENCODER_TEST != 1; skipping");
            return;
        }
        let encoder = QueryEncoder::load().expect("load encoder");
        let quote = encoder
            .encode("renewal quote and pricing discussion")
            .unwrap();
        let discount = encoder
            .encode("discount offered on the contract renewal")
            .unwrap();
        let unrelated = encoder
            .encode("kubernetes cluster crashed during deploy")
            .unwrap();

        let related = cosine(&quote, &discount);
        let cross = cosine(&quote, &unrelated);
        assert!(
            related > cross + 0.2,
            "semantic ordering broken: related={related:.3} unrelated={cross:.3}"
        );
    }
}
