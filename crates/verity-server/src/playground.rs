//! Playground — "ask the memory, through one key" (docs/design/PLAYGROUND.md).
//!
//! **Read-path purity is NOT violated by this feature.** `POST /v1/recall` and
//! `GET /v1/records/{source}/{entity}/{field}` remain exactly as they are:
//! zero LLM calls, zero live ReBAC-engine calls, scope filters materialized
//! into the index and applied as mandatory pre-filters, enforcement in the ONE
//! shared layer above `StorageAdapter`. The playground is a **consumer** of
//! the read path: the LLM sits *above* it, in `POST /v1/playground/ask`,
//! calling recall/get as tools. Each tool execution invokes the same internal
//! pipeline the public handlers use — `verify_scope → (encode) → scope_for →
//! storage.recall → revocation::enforce_restricted → spawn_audit` for search,
//! `verify_scope → current_fact/fact_as_of → spawn_audit` for point reads —
//! so every tool read is enforced, fail-closed, and audited identically to a
//! normal agent read. Nothing in `recall`/`get` changes; nothing in the loop
//! can widen a handle; Python appears nowhere (the loop is Rust here, calling
//! the Anthropic Messages API directly with the workspace `reqwest` + rustls).
//!
//! Fail-closed corollary: the agent's only source of facts is tool results
//! returned through the chosen scope handle. There is no fallback scope, no
//! admin bypass, no server-side default principal, and no "retry wider."
//!
//! Honesty contract: every displayed number is measured — one
//! `std::time::Instant` span per model round-trip (`llm_ms`, includes network
//! to Anthropic), one per tool execution (`storage_ms`, includes the local
//! encode() dense leg the public handler also performs), one around the whole
//! handler (`wall_ms`). Token counts are copied from the Anthropic response's
//! `usage` block, never estimated. No dollar figures anywhere.
//!
//! Key handling: the Anthropic key is read from the file named by
//! `VERITY_ANTHROPIC_KEY_FILE` **per request** (rotation works without a
//! restart), trimmed, held in [`AnthropicKey`] whose `Debug`/`Display` print
//! `«redacted»`, and used only to build the `x-api-key` header. It is never
//! logged, never appears in any response, and never reaches the browser. An
//! absent/unreadable key file is a valid degraded state: `status` reports
//! `ready: false` and `ask` returns a teaching 503.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::audit::spawn_audit;
use crate::revocation;
use crate::scope::ScopePayload;
use crate::AppState;
use verity_core::adapter::StorageAdapter;
use verity_core::types::{ChunkId, FactKey, FactRow, RecallHit, RecallQuery};

// ---------- constants (the whole configurable surface, per the contract) ----

pub(crate) const KEY_FILE_ENV: &str = "VERITY_ANTHROPIC_KEY_FILE";

const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

const MODEL_HAIKU: &str = "claude-haiku-4-5-20251001";
const MODEL_SONNET: &str = "claude-sonnet-4-6";
const ALLOWED_MODELS: [&str; 2] = [MODEL_HAIKU, MODEL_SONNET];

const MAX_TURNS_CAP: u32 = 8;
const MAX_TOKENS_PER_CALL: u32 = 1024;
const QUESTION_MAX_CHARS: usize = 2000;
const DEFAULT_SEARCH_K: u64 = 8;

/// Per-model-call timeout (reqwest client) and whole-ask budget (PLAYGROUND.md §4).
const MODEL_CALL_TIMEOUT: Duration = Duration::from_secs(60);
const ASK_BUDGET: Duration = Duration::from_secs(120);

/// The fixed system prompt — a server-side constant, disclosed verbatim in
/// every response (`system_prompt`) so the trace can show exactly what the
/// model was instructed to do. No knobs, no per-request overrides: comparable
/// runs and honest disclosure (PLAYGROUND.md §4, §9).
const SYSTEM_PROMPT: &str = "You are an agent answering questions from an enterprise memory store. \
You are reading through a permission scope: whatever the tools return is everything you are allowed to see. \
Answer ONLY from tool results in this conversation — never use outside knowledge, never guess, never fill gaps. \
Always search before answering. If your searches return nothing, say plainly that nothing is visible to this scope and stop; \
an empty answer is a correct answer here. When you do answer, cite the memories supporting each claim by their bracketed evidence number. \
Be concise.";

const UNAVAILABLE_DETAIL: &str = "This server has no Anthropic key configured. \
Set VERITY_ANTHROPIC_KEY_FILE to the path of a file containing an API key \
(e.g. ~/.verity-anthropic-key, chmod 600), then restart. The key is read \
server-side only and never logged. Recall itself needs no key — this gates \
only the model on top.";

const NOT_FOUND_SENTENCE: &str = "no value for that key/time";

// ---------- key loading (redacted newtype; per-request read) ----------------

/// The Anthropic API key. `Debug`/`Display` are redacted so no log line,
/// panic message, or error path can ever carry the key material.
struct AnthropicKey(String);

impl AnthropicKey {
    /// The only accessor; used solely to build the `x-api-key` header.
    fn header_value(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AnthropicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("«redacted»")
    }
}

impl fmt::Display for AnthropicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("«redacted»")
    }
}

/// Key availability, probed without reading contents (status endpoint) or
/// surfaced from a failed per-request load (ask endpoint). The filesystem
/// path never appears in any response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyProbe {
    Ready,
    Unset,
    NotFound,
    Unreadable,
}

impl KeyProbe {
    fn reason(self) -> &'static str {
        match self {
            KeyProbe::Ready => "ready",
            KeyProbe::Unset => "VERITY_ANTHROPIC_KEY_FILE is not set",
            KeyProbe::NotFound => "key file not found",
            KeyProbe::Unreadable => "key file unreadable",
        }
    }
}

/// Existence/readability check only — opens the file but reads nothing.
fn probe_key_at(path: Option<&str>) -> KeyProbe {
    let Some(path) = path.filter(|p| !p.trim().is_empty()) else {
        return KeyProbe::Unset;
    };
    match std::fs::File::open(path) {
        Ok(_) => KeyProbe::Ready,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => KeyProbe::NotFound,
        Err(_) => KeyProbe::Unreadable,
    }
}

/// Read + trim the key. Called once per ask (rotation works without restart);
/// an empty file is treated as unreadable — never an empty header.
fn load_key_from(path: Option<&str>) -> Result<AnthropicKey, KeyProbe> {
    let Some(path) = path.filter(|p| !p.trim().is_empty()) else {
        return Err(KeyProbe::Unset);
    };
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                Err(KeyProbe::Unreadable)
            } else {
                Ok(AnthropicKey(trimmed.to_string()))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KeyProbe::NotFound),
        Err(_) => Err(KeyProbe::Unreadable),
    }
}

fn key_file_path() -> Option<String> {
    std::env::var(KEY_FILE_ENV).ok()
}

// ---------- GET /v1/playground/status ---------------------------------------

fn status_body(probe: KeyProbe) -> Value {
    match probe {
        KeyProbe::Ready => json!({
            "ready": true,
            "models": [
                { "id": MODEL_HAIKU,  "label": "Haiku 4.5 — fast, cheap",      "default": true  },
                { "id": MODEL_SONNET, "label": "Sonnet 4.6 — smarter, slower", "default": false },
            ],
            "max_turns": MAX_TURNS_CAP,
        }),
        not_ready => json!({
            "ready": false,
            "reason": not_ready.reason(),
            "env_var": KEY_FILE_ENV,
        }),
    }
}

/// Always 200 — absence of a key is a state, not an error. Confirms the key
/// file's existence/readability only; contents are read solely at ask time.
pub(crate) async fn status() -> Json<Value> {
    let path = key_file_path();
    Json(status_body(probe_key_at(path.as_deref())))
}

// ---------- POST /v1/playground/ask: request/response types -----------------

#[derive(Deserialize)]
pub(crate) struct AskRequest {
    scope_handle: String,
    question: String,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    max_turns: Option<u32>,
}

/// Server-computed from measured hit counts — the UI trusts this field, not
/// the model's prose (PLAYGROUND.md §5: denial is enforced, not requested).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Visibility {
    Grounded,
    NothingVisible,
    NoReads,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct Usage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
}

#[derive(Serialize)]
struct ToolCallRecord {
    tool: String,
    /// The model's tool input, verbatim.
    input: Value,
    /// Measured around the whole in-process read (includes the encode leg).
    storage_ms: f64,
    hits: u64,
    /// Evidence numbers assigned to this call's hits (empty for `get_fact`).
    evidence_ns: Vec<usize>,
    /// `get_fact` only: the row the scope could see.
    fact: Option<FactRow>,
    /// `"unknown tool"`, the not-found sentence, or a bad-argument message.
    error: Option<String>,
}

#[derive(Serialize)]
struct Turn {
    n: usize,
    /// Measured server-side around the Anthropic round-trip; includes network.
    llm_ms: f64,
    /// Anthropic's stop_reason, verbatim.
    stop_reason: String,
    text: String,
    /// Copied from the API response's usage block — never estimated.
    usage: Usage,
    tool_calls: Vec<ToolCallRecord>,
}

/// One deduped evidence entry: the exact `RecallHit` serialization the model
/// received (same wire shape as `POST /v1/recall`) plus its number.
#[derive(Serialize)]
struct EvidenceItem {
    n: usize,
    #[serde(flatten)]
    hit: RecallHit,
}

#[derive(Serialize)]
struct Totals {
    wall_ms: f64,
    llm_ms: f64,
    llm_calls: usize,
    storage_ms: f64,
    storage_calls: usize,
    visible_hits_total: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
}

#[derive(Serialize)]
pub(crate) struct AskResponse {
    answer: String,
    visibility: Visibility,
    stop: &'static str,
    model: String,
    system_prompt: &'static str,
    evidence: Vec<EvidenceItem>,
    turns: Vec<Turn>,
    totals: Totals,
}

/// Errors carry plain-language JSON bodies (PLAYGROUND.md §6), surfaced
/// verbatim by the panel.
type AskErr = (StatusCode, Json<Value>);

fn err_body(status: StatusCode, error: &str, detail: String) -> AskErr {
    (status, Json(json!({ "error": error, "detail": detail })))
}

fn err_unavailable() -> AskErr {
    err_body(
        StatusCode::SERVICE_UNAVAILABLE,
        "playground_unavailable",
        UNAVAILABLE_DETAIL.to_string(),
    )
}

/// Wrap an internal `(StatusCode, String)` handler error (storage/encoder
/// failures) into the JSON error shape. Not one of the contract's enumerated
/// outcomes — this is the ordinary 500 path, same as the public handlers.
fn err_internal((status, msg): (StatusCode, String)) -> AskErr {
    err_body(status, "internal", msg)
}

// ---------- running tallies + evidence numbering -----------------------------

/// Per-ask accumulators. Sums are over the already-rounded per-turn addends,
/// each visible in `turns[]`, so every total is checkable by hand.
#[derive(Default)]
struct RunTally {
    llm_ms: f64,
    llm_calls: usize,
    storage_ms: f64,
    storage_calls: usize,
    visible_hits_total: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
}

impl RunTally {
    fn totals(&self, wall_ms: f64) -> Totals {
        Totals {
            wall_ms,
            llm_ms: round1(self.llm_ms),
            llm_calls: self.llm_calls,
            storage_ms: round1(self.storage_ms),
            storage_calls: self.storage_calls,
            visible_hits_total: self.visible_hits_total,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cache_read_input_tokens: self.cache_read_input_tokens,
        }
    }
}

/// Evidence numbers are stable across the whole ask: the first time a chunk
/// is seen it gets the next number; re-retrieval by a later search reuses it.
#[derive(Default)]
struct EvidenceTable {
    by_chunk: HashMap<ChunkId, usize>,
    items: Vec<EvidenceItem>,
}

impl EvidenceTable {
    fn assign(&mut self, hit: &RecallHit) -> usize {
        if let Some(&n) = self.by_chunk.get(&hit.chunk_id) {
            return n;
        }
        let n = self.items.len() + 1;
        self.by_chunk.insert(hit.chunk_id, n);
        self.items.push(EvidenceItem {
            n,
            hit: hit.clone(),
        });
        n
    }
}

fn compute_visibility(storage_calls: usize, visible_hits_total: u64) -> Visibility {
    if storage_calls == 0 {
        Visibility::NoReads
    } else if visible_hits_total >= 1 {
        Visibility::Grounded
    } else {
        Visibility::NothingVisible
    }
}

/// Milliseconds with one decimal — raw measured values, never "~2s".
fn round1(ms: f64) -> f64 {
    (ms * 10.0).round() / 10.0
}

fn elapsed_ms(t0: Instant) -> f64 {
    round1(t0.elapsed().as_secs_f64() * 1000.0)
}

// ---------- request validation -----------------------------------------------

fn validate_model(requested: Option<&str>) -> Result<String, AskErr> {
    let model = requested.unwrap_or(MODEL_HAIKU);
    if ALLOWED_MODELS.contains(&model) {
        Ok(model.to_string())
    } else {
        Err(err_body(
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_request",
            format!(
                "unknown model {model:?} — allowed: {}",
                ALLOWED_MODELS.join(", ")
            ),
        ))
    }
}

fn validate_question(question: &str) -> Result<(), AskErr> {
    if question.trim().is_empty() {
        return Err(err_body(
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_request",
            "question must be non-empty".to_string(),
        ));
    }
    let chars = question.chars().count();
    if chars > QUESTION_MAX_CHARS {
        return Err(err_body(
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_request",
            format!("question is {chars} characters — the limit is {QUESTION_MAX_CHARS}"),
        ));
    }
    Ok(())
}

fn clamp_turns(requested: Option<u32>) -> u32 {
    requested.unwrap_or(MAX_TURNS_CAP).clamp(1, MAX_TURNS_CAP)
}

// ---------- Anthropic Messages API wire types --------------------------------

/// The two tool definitions sent to the model (PLAYGROUND.md §4, verbatim).
fn tool_definitions() -> Value {
    json!([
        {
            "name": "search_memory",
            "description": "Search this company's shared memory THROUGH the caller's permission scope. Returns only memories this scope is allowed to see, each with a bracketed evidence number. An empty result means nothing is visible — that is a true answer, not an error.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "what to search for" },
                    "k":    { "type": "integer", "minimum": 1, "maximum": 20, "description": "max results (default 8)" }
                },
                "required": ["text"]
            }
        },
        {
            "name": "get_fact",
            "description": "Point-read one structured fact by exact key (source, entity_id, field), as visible to your scope — e.g. the current DUNS number on record. Optionally as of a past moment (RFC3339). Use search_memory first to discover keys; use this to pin an exact current or historical value.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "source":    { "type": "string" },
                    "entity_id": { "type": "string" },
                    "field":     { "type": "string" },
                    "as_of":     { "type": "string", "description": "optional RFC3339 timestamp; absent = current value" }
                },
                "required": ["source", "entity_id", "field"]
            }
        }
    ])
}

fn build_api_request(model: &str, messages: &[Value]) -> Value {
    json!({
        "model": model,
        "max_tokens": MAX_TOKENS_PER_CALL,
        "system": SYSTEM_PROMPT,
        "tools": tool_definitions(),
        "messages": messages,
    })
}

#[derive(Deserialize)]
struct ApiUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: Option<u64>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    /// Unknown block kinds (e.g. future thinking blocks) are carried through
    /// to the next request verbatim but contribute nothing to the trace.
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ApiResponse {
    content: Vec<ContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    usage: ApiUsage,
}

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(MODEL_CALL_TIMEOUT)
            .build()
            .expect("reqwest client construction cannot fail with these options")
    })
}

// ---------- tool execution (the SAME internal pipeline as the public handlers)

/// Execute one `tool_use` block against the pinned, verified scope payload.
/// Returns the trace record, the `tool_result` content string the model gets,
/// and whether that result is an error block. Unknown tools and malformed
/// arguments are NEVER executed and do not count as storage calls.
async fn execute_tool(
    state: &Arc<AppState>,
    payload: &ScopePayload,
    name: &str,
    input: Value,
    evidence: &mut EvidenceTable,
    tally: &mut RunTally,
) -> Result<(ToolCallRecord, String, bool), AskErr> {
    match name {
        "search_memory" => execute_search(state, payload, input, evidence, tally).await,
        "get_fact" => execute_get_fact(state, payload, input, tally).await,
        other => Ok((
            ToolCallRecord {
                tool: other.to_string(),
                input,
                storage_ms: 0.0,
                hits: 0,
                evidence_ns: vec![],
                fact: None,
                error: Some("unknown tool".to_string()),
            },
            "unknown tool".to_string(),
            true,
        )),
    }
}

/// A tool call the server refuses to execute (bad arguments): an error
/// `tool_result` for the model, an `error` line in the trace, zero storage.
fn refused_tool(tool: &str, input: Value, message: &str) -> (ToolCallRecord, String, bool) {
    (
        ToolCallRecord {
            tool: tool.to_string(),
            input,
            storage_ms: 0.0,
            hits: 0,
            evidence_ns: vec![],
            fact: None,
            error: Some(message.to_string()),
        },
        message.to_string(),
        true,
    )
}

/// `search_memory` — the recall pipeline verbatim (same functions the public
/// `POST /v1/recall` handler calls): encode → scope_for (revocation
/// subtraction) → storage.recall → enforce_restricted → spawn_audit. The
/// `storage_ms` span covers the whole in-process read, encode leg included.
async fn execute_search(
    state: &Arc<AppState>,
    payload: &ScopePayload,
    input: Value,
    evidence: &mut EvidenceTable,
    tally: &mut RunTally,
) -> Result<(ToolCallRecord, String, bool), AskErr> {
    let Some(text) = input.get("text").and_then(Value::as_str).map(String::from) else {
        return Ok(refused_tool(
            "search_memory",
            input,
            "search_memory requires a string \"text\" argument",
        ));
    };
    let k = input
        .get("k")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_SEARCH_K)
        .clamp(1, 20) as usize;

    let t0 = Instant::now();
    let embedding = state.encode(&text).await.map_err(err_internal)?;
    let query = RecallQuery {
        scope: state.scope_for(payload).await.map_err(err_internal)?,
        embedding,
        text: Some(text.clone()),
        k,
    };
    let hits = state
        .storage
        .recall(query)
        .await
        .map_err(crate::internal)
        .map_err(err_internal)?;
    let hits = revocation::enforce_restricted(state, payload, hits)
        .await
        .map_err(err_internal)?;
    spawn_audit(
        state,
        payload,
        "recall",
        Some(&text),
        hits.iter().map(|h| h.chunk_id).collect(),
    );
    let storage_ms = elapsed_ms(t0);

    let evidence_ns: Vec<usize> = hits.iter().map(|h| evidence.assign(h)).collect();
    tally.storage_ms += storage_ms;
    tally.storage_calls += 1;
    tally.visible_hits_total += hits.len() as u64;

    // The model sees the exact RecallHit wire shape, each hit prefixed with
    // its stable evidence number.
    let numbered: Vec<Value> = evidence_ns
        .iter()
        .zip(hits.iter())
        .map(|(&n, hit)| {
            let mut obj = json!({ "n": n });
            if let (Value::Object(dst), Ok(Value::Object(src))) =
                (&mut obj, serde_json::to_value(hit))
            {
                dst.extend(src);
            }
            obj
        })
        .collect();
    let content = serde_json::to_string(&numbered).unwrap_or_else(|_| "[]".to_string());

    Ok((
        ToolCallRecord {
            tool: "search_memory".to_string(),
            input,
            storage_ms,
            hits: numbered.len() as u64,
            evidence_ns,
            fact: None,
            error: None,
        },
        content,
        false,
    ))
}

/// `get_fact` — the get pipeline verbatim (same functions the public
/// `GET /v1/records/...` handler calls): current_fact / fact_as_of →
/// spawn_audit. A missing key is a normal `tool_result` ("no value for that
/// key/time"), not an error block — an empty answer is a correct answer.
async fn execute_get_fact(
    state: &Arc<AppState>,
    payload: &ScopePayload,
    input: Value,
    tally: &mut RunTally,
) -> Result<(ToolCallRecord, String, bool), AskErr> {
    let field_str = |key: &str| input.get(key).and_then(Value::as_str).map(String::from);
    let (Some(source), Some(entity_id), Some(field)) = (
        field_str("source"),
        field_str("entity_id"),
        field_str("field"),
    ) else {
        return Ok(refused_tool(
            "get_fact",
            input,
            "get_fact requires string \"source\", \"entity_id\" and \"field\" arguments",
        ));
    };
    let as_of: Option<DateTime<Utc>> = match input.get("as_of").and_then(Value::as_str) {
        None => None,
        Some(raw) => match DateTime::parse_from_rfc3339(raw) {
            Ok(t) => Some(t.with_timezone(&Utc)),
            Err(_) => {
                return Ok(refused_tool(
                    "get_fact",
                    input,
                    "as_of must be an RFC3339 timestamp",
                ));
            }
        },
    };

    let key = FactKey {
        source,
        entity_id,
        field,
    };
    // The denial demo depends on this: get_fact passes the SAME scoped gate as
    // the public GET /v1/records/... handler (SPEC §7e — the documented leak came
    // through unguarded get-by-id). scope_for compiles visibility + revocations.
    let scope = state.scope_for(payload).await.map_err(err_internal)?;
    let t0 = Instant::now();
    let result = match as_of {
        Some(at) => state.storage.fact_as_of(&scope, &key, at).await,
        None => state.storage.current_fact(&scope, &key).await,
    }
    .map_err(crate::internal)
    .map_err(err_internal)?;
    if let Some(fact) = &result {
        // Audited exactly like the public handler: on a visible row only.
        spawn_audit(
            state,
            payload,
            "get",
            Some(&format!("{}/{}/{}", key.source, key.entity_id, key.field)),
            vec![fact.id],
        );
    }
    let storage_ms = elapsed_ms(t0);
    tally.storage_ms += storage_ms;
    tally.storage_calls += 1;

    match result {
        Some(fact) => {
            tally.visible_hits_total += 1;
            let content =
                serde_json::to_string(&fact).unwrap_or_else(|_| NOT_FOUND_SENTENCE.to_string());
            Ok((
                ToolCallRecord {
                    tool: "get_fact".to_string(),
                    input,
                    storage_ms,
                    hits: 1,
                    evidence_ns: vec![],
                    fact: Some(fact),
                    error: None,
                },
                content,
                false,
            ))
        }
        None => Ok((
            ToolCallRecord {
                tool: "get_fact".to_string(),
                input,
                storage_ms,
                hits: 0,
                evidence_ns: vec![],
                fact: None,
                error: Some(NOT_FOUND_SENTENCE.to_string()),
            },
            NOT_FOUND_SENTENCE.to_string(),
            false,
        )),
    }
}

// ---------- POST /v1/playground/ask ------------------------------------------

/// The agentic loop. Order of operations is fail-before-spend: key file, then
/// scope verification (an invalid/expired handle fails BEFORE any LLM call —
/// fail closed, no tokens spent on a dead key), then input validation, then
/// the model loop. The handle is verified once at admission and its payload
/// pinned for the whole ask — exactly like a single public request; nothing
/// in the loop can widen it, and each tool read still re-subtracts revocation
/// tombstones via `scope_for`.
pub(crate) async fn ask(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AskRequest>,
) -> Result<Json<AskResponse>, AskErr> {
    let wall = Instant::now();

    // 1. Key first: absent/unreadable is a teaching 503, before anything else.
    let key = load_key_from(key_file_path().as_deref()).map_err(|_| err_unavailable())?;

    // 2. Fail closed before any spend.
    let payload = state.verify_scope(&req.scope_handle).map_err(|(_, msg)| {
        err_body(
            StatusCode::UNAUTHORIZED,
            "scope_refused",
            format!("{msg} — the model was never called; no tokens were spent."),
        )
    })?;

    // 3. Input validation.
    let model = validate_model(req.model.as_deref())?;
    validate_question(&req.question)?;
    let max_turns = clamp_turns(req.max_turns);

    // 4. The loop. Every ask is a fresh, stateless conversation.
    let deadline = wall + ASK_BUDGET;
    let mut messages: Vec<Value> = vec![json!({ "role": "user", "content": req.question })];
    let mut turns: Vec<Turn> = Vec::new();
    let mut tally = RunTally::default();
    let mut evidence = EvidenceTable::default();
    let mut answer = String::new();
    let mut stop = "turn_cap";

    for turn_n in 1..=(max_turns as usize) {
        // 120 s whole-ask budget: measured work is never thrown away.
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Err(err_timed_out(turn_n, &turns, &tally, wall));
        };

        let body = build_api_request(&model, &messages);
        let t0 = Instant::now();
        let send = http_client()
            .post(ANTHROPIC_URL)
            .header("x-api-key", key.header_value())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
            .send();
        let response = match tokio::time::timeout(remaining, send).await {
            Err(_) => return Err(err_timed_out(turn_n, &turns, &tally, wall)),
            Ok(Err(e)) => {
                // reqwest errors never carry the key (it lives in a header we
                // never Display); the 60 s per-call timeout lands here too.
                return Err(err_model_failed(
                    format!(
                        "the Anthropic API call failed on turn {turn_n}: {e}. Verity's read path was unaffected."
                    ),
                    &turns,
                    &tally,
                    wall,
                ));
            }
            Ok(Ok(r)) => r,
        };
        let http_status = response.status();
        let raw = match tokio::time::timeout(remaining, response.text()).await {
            Err(_) => return Err(err_timed_out(turn_n, &turns, &tally, wall)),
            Ok(Err(e)) => {
                return Err(err_model_failed(
                    format!(
                        "reading the Anthropic API response failed on turn {turn_n}: {e}. Verity's read path was unaffected."
                    ),
                    &turns,
                    &tally,
                    wall,
                ));
            }
            Ok(Ok(text)) => text,
        };
        let llm_ms = elapsed_ms(t0);

        if !http_status.is_success() {
            let excerpt: String = raw.chars().take(300).collect();
            return Err(err_model_failed(
                format!(
                    "Anthropic API returned HTTP {} on turn {turn_n}: {excerpt} — Verity's read path was unaffected.",
                    http_status.as_u16()
                ),
                &turns,
                &tally,
                wall,
            ));
        }

        let raw_value: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                return Err(err_model_failed(
                    format!(
                        "the Anthropic API response on turn {turn_n} was not valid JSON: {e}. Verity's read path was unaffected."
                    ),
                    &turns,
                    &tally,
                    wall,
                ));
            }
        };
        let parsed: ApiResponse = match serde_json::from_value(raw_value.clone()) {
            Ok(p) => p,
            Err(e) => {
                return Err(err_model_failed(
                    format!(
                        "the Anthropic API response on turn {turn_n} had an unexpected shape: {e}. Verity's read path was unaffected."
                    ),
                    &turns,
                    &tally,
                    wall,
                ));
            }
        };

        // Usage: copied from the API response, never estimated.
        let usage = Usage {
            input_tokens: parsed.usage.input_tokens,
            output_tokens: parsed.usage.output_tokens,
            cache_read_input_tokens: parsed.usage.cache_read_input_tokens.unwrap_or(0),
        };
        tally.llm_ms += llm_ms;
        tally.llm_calls += 1;
        tally.input_tokens += usage.input_tokens;
        tally.output_tokens += usage.output_tokens;
        tally.cache_read_input_tokens += usage.cache_read_input_tokens;

        let stop_reason = parsed.stop_reason.unwrap_or_default();
        let text: String = parsed
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");
        let tool_uses: Vec<(String, String, Value)> = parsed
            .content
            .into_iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse { id, name, input } => Some((id, name, input)),
                _ => None,
            })
            .collect();

        if tool_uses.is_empty() {
            // Natural termination (end_turn, max_tokens, …): the loop is done.
            turns.push(Turn {
                n: turn_n,
                llm_ms,
                stop_reason,
                text: text.clone(),
                usage,
                tool_calls: vec![],
            });
            answer = text;
            stop = "end_turn";
            break;
        }

        // Execute every tool_use block server-side against the pinned scope,
        // then feed tool_result back. The assistant content is appended
        // verbatim from the wire so the conversation the model sees is exact.
        messages.push(json!({ "role": "assistant", "content": raw_value["content"] }));
        let mut tool_records = Vec::with_capacity(tool_uses.len());
        let mut result_blocks = Vec::with_capacity(tool_uses.len());
        for (id, name, input) in tool_uses {
            let (record, content, is_error) =
                execute_tool(&state, &payload, &name, input, &mut evidence, &mut tally).await?;
            result_blocks.push(json!({
                "type": "tool_result",
                "tool_use_id": id,
                "content": content,
                "is_error": is_error,
            }));
            tool_records.push(record);
        }
        answer = text.clone();
        turns.push(Turn {
            n: turn_n,
            llm_ms,
            stop_reason,
            text,
            usage,
            tool_calls: tool_records,
        });
        messages.push(json!({ "role": "user", "content": result_blocks }));
    }

    let visibility = compute_visibility(tally.storage_calls, tally.visible_hits_total);
    let totals = tally.totals(elapsed_ms(wall));
    Ok(Json(AskResponse {
        answer,
        visibility,
        stop,
        model,
        system_prompt: SYSTEM_PROMPT,
        evidence: evidence.items,
        turns,
        totals,
    }))
}

// ---------- partial-carrying error bodies (measured work is never discarded) -

fn partial_value(turns: &[Turn], tally: &RunTally, wall: Instant) -> Value {
    json!({
        "turns": turns,
        "totals": tally.totals(elapsed_ms(wall)),
    })
}

fn err_timed_out(turn_n: usize, turns: &[Turn], tally: &RunTally, wall: Instant) -> AskErr {
    (
        StatusCode::GATEWAY_TIMEOUT,
        Json(json!({
            "error": "ask_timed_out",
            "detail": format!(
                "the 120 s ask budget elapsed on turn {turn_n}; every completed turn below is measured"
            ),
            "partial": partial_value(turns, tally, wall),
        })),
    )
}

fn err_model_failed(detail: String, turns: &[Turn], tally: &RunTally, wall: Instant) -> AskErr {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": "model_call_failed",
            "detail": detail,
            "partial": partial_value(turns, tally, wall),
        })),
    )
}

// ---------- tests (no network, no live key — ever) ---------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use verity_core::types::{AclProvenance, TrustTier};

    fn sample_hit(chunk_id: ChunkId) -> RecallHit {
        RecallHit {
            chunk_id,
            document_id: "doc-1".into(),
            seq: 0,
            content: "champion Dana G left for Initech".into(),
            score: 12.31,
            entity_tags: vec!["account:acme".into()],
            kind: "content".into(),
            support_tier: None,
            acl_provenance: AclProvenance::Mirrored,
            trust_tier: TrustTier::Authoritative,
            valid_from: Utc.with_ymd_and_hms(2026, 5, 14, 9, 12, 0).unwrap(),
            provenance: uuid::Uuid::nil(),
        }
    }

    // -- key handling --

    #[test]
    fn key_debug_and_display_are_redacted() {
        let key = AnthropicKey("sk-ant-super-secret".into());
        assert_eq!(format!("{key:?}"), "«redacted»");
        assert_eq!(format!("{key}"), "«redacted»");
        assert!(!format!("{key:?}").contains("secret"));
    }

    #[test]
    fn probe_reports_unset_missing_and_ready() {
        assert_eq!(probe_key_at(None), KeyProbe::Unset);
        assert_eq!(probe_key_at(Some("")), KeyProbe::Unset);
        assert_eq!(
            probe_key_at(Some("/nonexistent/verity-playground-test-key")),
            KeyProbe::NotFound
        );
        let path =
            std::env::temp_dir().join(format!("verity-playground-probe-{}", std::process::id()));
        std::fs::write(&path, "sk-ant-test\n").unwrap();
        assert_eq!(probe_key_at(path.to_str()), KeyProbe::Ready);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_key_trims_and_rejects_empty() {
        assert_eq!(load_key_from(None).unwrap_err(), KeyProbe::Unset);
        assert_eq!(
            load_key_from(Some("/nonexistent/verity-playground-test-key")).unwrap_err(),
            KeyProbe::NotFound
        );
        let path =
            std::env::temp_dir().join(format!("verity-playground-load-{}", std::process::id()));
        std::fs::write(&path, "  sk-ant-test-123\n").unwrap();
        let key = load_key_from(path.to_str()).unwrap();
        assert_eq!(key.header_value(), "sk-ant-test-123");
        std::fs::write(&path, "   \n").unwrap();
        assert_eq!(
            load_key_from(path.to_str()).unwrap_err(),
            KeyProbe::Unreadable
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn no_key_yields_teaching_503_naming_the_env_var() {
        let (status, Json(body)) = err_unavailable();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "playground_unavailable");
        let detail = body["detail"].as_str().unwrap();
        assert!(detail.contains(KEY_FILE_ENV));
        assert!(detail.contains("Recall itself needs no key"));
    }

    // -- status bodies --

    #[test]
    fn status_ready_lists_the_two_models_with_haiku_default() {
        let body = status_body(KeyProbe::Ready);
        assert_eq!(body["ready"], true);
        assert_eq!(body["max_turns"], MAX_TURNS_CAP);
        let models = body["models"].as_array().unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0]["id"], MODEL_HAIKU);
        assert_eq!(models[0]["default"], true);
        assert_eq!(models[1]["id"], MODEL_SONNET);
        assert_eq!(models[1]["default"], false);
    }

    #[test]
    fn status_not_ready_names_the_env_var_and_reason() {
        for (probe, reason) in [
            (KeyProbe::Unset, "VERITY_ANTHROPIC_KEY_FILE is not set"),
            (KeyProbe::NotFound, "key file not found"),
            (KeyProbe::Unreadable, "key file unreadable"),
        ] {
            let body = status_body(probe);
            assert_eq!(body["ready"], false);
            assert_eq!(body["reason"], reason);
            assert_eq!(body["env_var"], KEY_FILE_ENV);
            // The filesystem path never appears in any response.
            assert!(!body.to_string().contains('/'));
        }
    }

    // -- validation --

    #[test]
    fn model_allowlist_defaults_to_haiku_and_rejects_unknown_ids() {
        assert_eq!(validate_model(None).unwrap(), MODEL_HAIKU);
        assert_eq!(validate_model(Some(MODEL_SONNET)).unwrap(), MODEL_SONNET);
        let (status, Json(body)) = validate_model(Some("gpt-4o")).unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"], "bad_request");
        let detail = body["detail"].as_str().unwrap();
        assert!(detail.contains(MODEL_HAIKU) && detail.contains(MODEL_SONNET));
    }

    #[test]
    fn question_must_be_nonempty_and_bounded() {
        assert!(validate_question("what's the renewal risk at Acme?").is_ok());
        let (status, _) = validate_question("   ").unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let long: String = "x".repeat(QUESTION_MAX_CHARS + 1);
        let (status, _) = validate_question(&long).unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(validate_question(&"x".repeat(QUESTION_MAX_CHARS)).is_ok());
    }

    #[test]
    fn max_turns_clamps_to_one_through_eight() {
        assert_eq!(clamp_turns(None), 8);
        assert_eq!(clamp_turns(Some(0)), 1);
        assert_eq!(clamp_turns(Some(3)), 3);
        assert_eq!(clamp_turns(Some(99)), 8);
    }

    // -- request building & tool schemas --

    #[test]
    fn tool_definitions_match_the_contract() {
        let tools = tool_definitions();
        let arr = tools.as_array().unwrap();
        assert_eq!(arr.len(), 2, "two tools, not one and not three");
        assert_eq!(arr[0]["name"], "search_memory");
        assert_eq!(arr[0]["input_schema"]["required"], json!(["text"]));
        assert_eq!(arr[0]["input_schema"]["properties"]["k"]["maximum"], 20);
        assert_eq!(arr[1]["name"], "get_fact");
        assert_eq!(
            arr[1]["input_schema"]["required"],
            json!(["source", "entity_id", "field"])
        );
    }

    #[test]
    fn api_request_carries_model_cap_system_tools_and_messages() {
        let messages = vec![json!({ "role": "user", "content": "hi" })];
        let body = build_api_request(MODEL_HAIKU, &messages);
        assert_eq!(body["model"], MODEL_HAIKU);
        assert_eq!(body["max_tokens"], MAX_TOKENS_PER_CALL);
        assert_eq!(body["system"], SYSTEM_PROMPT);
        assert_eq!(body["tools"].as_array().unwrap().len(), 2);
        assert_eq!(body["messages"], json!(messages));
        // The disclosed prompt forbids parametric answers.
        assert!(SYSTEM_PROMPT.contains("Answer ONLY from tool results"));
    }

    // -- response parsing --

    #[test]
    fn api_response_parsing_handles_text_tool_use_and_unknown_blocks() {
        let raw = json!({
            "content": [
                { "type": "text", "text": "let me search" },
                { "type": "tool_use", "id": "tu_1", "name": "search_memory",
                  "input": { "text": "acme renewal risk", "k": 8 } },
                { "type": "server_tool_use_future_thing", "mystery": true },
            ],
            "stop_reason": "tool_use",
            "usage": { "input_tokens": 903, "output_tokens": 71 }
        });
        let parsed: ApiResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(parsed.usage.input_tokens, 903);
        assert_eq!(parsed.usage.output_tokens, 71);
        // cache_read_input_tokens absent → 0, never estimated.
        assert_eq!(parsed.usage.cache_read_input_tokens, None);
        assert_eq!(parsed.content.len(), 3);
        assert!(
            matches!(&parsed.content[0], ContentBlock::Text { text } if text == "let me search")
        );
        assert!(matches!(
            &parsed.content[1],
            ContentBlock::ToolUse { id, name, .. } if id == "tu_1" && name == "search_memory"
        ));
        assert!(matches!(&parsed.content[2], ContentBlock::Other));
    }

    // -- evidence numbering & trace assembly --

    #[test]
    fn evidence_numbers_are_stable_and_deduped_across_the_ask() {
        let mut table = EvidenceTable::default();
        let a = sample_hit(uuid::Uuid::from_u128(1));
        let b = sample_hit(uuid::Uuid::from_u128(2));
        assert_eq!(table.assign(&a), 1);
        assert_eq!(table.assign(&b), 2);
        // A later search re-returning chunk `a` reuses its number.
        assert_eq!(table.assign(&a), 1);
        assert_eq!(table.items.len(), 2);
        // The serialized evidence item is n + the exact RecallHit wire shape.
        let item = serde_json::to_value(&table.items[0]).unwrap();
        assert_eq!(item["n"], 1);
        assert_eq!(item["content"], "champion Dana G left for Initech");
        assert_eq!(item["score"], json!(12.31f32));
        assert_eq!(item["kind"], "content");
    }

    #[test]
    fn visibility_is_computed_from_measured_counts() {
        assert_eq!(compute_visibility(0, 0), Visibility::NoReads);
        assert_eq!(compute_visibility(3, 0), Visibility::NothingVisible);
        assert_eq!(compute_visibility(1, 6), Visibility::Grounded);
        // Serialized names match the contract enum.
        assert_eq!(
            serde_json::to_value(Visibility::NothingVisible).unwrap(),
            json!("nothing_visible")
        );
        assert_eq!(
            serde_json::to_value(Visibility::NoReads).unwrap(),
            json!("no_reads")
        );
        assert_eq!(
            serde_json::to_value(Visibility::Grounded).unwrap(),
            json!("grounded")
        );
    }

    #[test]
    fn unknown_tools_are_refused_and_never_counted_as_reads() {
        let record = ToolCallRecord {
            tool: "delete_everything".into(),
            input: json!({}),
            storage_ms: 0.0,
            hits: 0,
            evidence_ns: vec![],
            fact: None,
            error: Some("unknown tool".into()),
        };
        let v = serde_json::to_value(&record).unwrap();
        assert_eq!(v["error"], "unknown tool");
        assert_eq!(v["storage_ms"], 0.0);
        assert_eq!(v["fact"], Value::Null);
    }

    #[test]
    fn totals_are_checkable_sums_of_per_turn_addends() {
        let tally = RunTally {
            llm_ms: 812.4 + 1594.0,
            llm_calls: 2,
            storage_ms: 6.3,
            storage_calls: 1,
            visible_hits_total: 6,
            input_tokens: 903 + 1287,
            output_tokens: 71 + 214,
            cache_read_input_tokens: 0,
        };
        let totals = tally.totals(2412.7);
        let v = serde_json::to_value(&totals).unwrap();
        assert_eq!(v["wall_ms"], 2412.7);
        assert_eq!(v["llm_ms"], 2406.4);
        assert_eq!(v["llm_calls"], 2);
        assert_eq!(v["storage_ms"], 6.3);
        assert_eq!(v["storage_calls"], 1);
        assert_eq!(v["visible_hits_total"], 6);
        assert_eq!(v["input_tokens"], 2190);
        assert_eq!(v["output_tokens"], 285);
    }

    #[test]
    fn round1_keeps_exactly_one_decimal() {
        assert_eq!(round1(6.34), 6.3);
        assert_eq!(round1(6.35), 6.4);
        assert_eq!(round1(0.0), 0.0);
        assert_eq!(round1(2412.7199), 2412.7);
    }

    #[test]
    fn partial_bodies_carry_completed_turns_and_totals() {
        let turns = vec![Turn {
            n: 1,
            llm_ms: 812.4,
            stop_reason: "tool_use".into(),
            text: String::new(),
            usage: Usage {
                input_tokens: 903,
                output_tokens: 71,
                cache_read_input_tokens: 0,
            },
            tool_calls: vec![],
        }];
        let tally = RunTally {
            llm_ms: 812.4,
            llm_calls: 1,
            ..RunTally::default()
        };
        let (status, Json(body)) = err_timed_out(2, &turns, &tally, Instant::now());
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(body["error"], "ask_timed_out");
        assert!(body["detail"].as_str().unwrap().contains("turn 2"));
        assert_eq!(body["partial"]["turns"].as_array().unwrap().len(), 1);
        assert_eq!(body["partial"]["totals"]["llm_calls"], 1);

        let (status, Json(body)) = err_model_failed(
            "Anthropic API returned HTTP 529 on turn 2: overloaded — Verity's read path was unaffected.".into(),
            &turns,
            &tally,
            Instant::now(),
        );
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"], "model_call_failed");
        assert_eq!(body["partial"]["turns"].as_array().unwrap().len(), 1);
    }
}
