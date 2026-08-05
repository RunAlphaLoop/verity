//! verity-mcp — stdio MCP server over the Verity REST substrate (SPEC §9a/§9b).
//!
//! A thin proxy: every tool call becomes exactly one REST call against a
//! running `verity` server. No database access and no enforcement logic live
//! here — the REST layer verifies scope handles and applies visibility.
//!
//! Identity is never agent-supplied (SPEC §9a): tenant, principals, and actor
//! sub/azp come from process configuration (env/CLI), and tool schemas do not
//! expose them. The only cross-call state an agent holds is the scope handle
//! minted by `memory_open_scope`, which it passes back to every other verb.
//!
//! # Change notifications: a poll tool, not MCP resource subscriptions
//!
//! Verity's server pushes changes over SSE (`GET /v1/subscribe`), and rmcp
//! 2.2 *can* forward pushes to the client: `Peer<RoleServer>` is cloneable
//! into background tasks and exposes `notify_resource_updated`, and
//! `ServerHandler::subscribe`/`unsubscribe` are overridable, so bridging the
//! SSE feed to `notifications/resources/updated` is mechanically possible.
//! It would not be useful over stdio today, and we deliberately do not do it:
//!
//! - Agent hosts drive **tools**, not resources — mainstream MCP clients
//!   neither subscribe to resources nor deliver update notifications into
//!   the model's context, and an agent cannot react mid-turn to a push in
//!   any case (a notification has no delivery channel until the next turn).
//! - `notifications/resources/updated` carries no payload — only the URI —
//!   so the client must re-read to learn what changed; a pull surface would
//!   be required even with the bridge in place.
//! - The bridge would add durable per-subscription background tasks keyed to
//!   scope handles that expire, in a proxy that is otherwise stateless.
//!
//! So the pull surface is exposed directly: [`memory_poll_changes`] — a
//! cursor-disciplined one-shot poll built on the existing REST reads
//! (`GET /v1/activity?since=` for actions, `GET /v1/briefs/{entity}` for new
//! memory chunks, filtered client-side by `valid_from > since`). Agents call
//! it between turns, which is the honest MCP delivery model. If hosts grow
//! real subscription support, the SSE bridge can be added later without
//! changing this tool.
//!
//! [`memory_poll_changes`]: VerityMcp::memory_poll_changes

use chrono::{DateTime, SecondsFormat, Utc};
use clap::Parser;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "verity-mcp",
    about = "Verity — permission-aware shared memory, exposed as MCP tools over stdio"
)]
struct Cli {
    /// Base URL of the Verity REST server (SPEC §9b substrate).
    #[arg(long, env = "VERITY_URL", default_value = "http://127.0.0.1:7717")]
    url: String,
    /// Tenant every scope is minted for.
    #[arg(long, env = "VERITY_TENANT_ID")]
    tenant_id: Uuid,
    /// Materialized principal tokens for this agent's identity
    /// (comma-separated ints). Empty set = everything invisible (fail closed).
    /// Mutually exclusive with --subject: with a subject, the SERVER resolves
    /// the principal set (the user + its transitive group closure) itself.
    #[arg(long, env = "VERITY_PRINCIPALS", value_delimiter = ',')]
    principals: Vec<i32>,
    /// Identity-resolved mode (SPEC §6/§9a — the production shape): a
    /// `user:<id>` subject the server resolves to its principal set (the user
    /// plus its transitive group closure) via ReBAC. Mutually exclusive with
    /// --principals — the agent names WHO it is, never what powers it holds.
    #[arg(long, env = "VERITY_SUBJECT")]
    subject: Option<String>,
    /// Stable subject identifier (`sub`) stamped on writes.
    #[arg(long, env = "VERITY_ACTOR_SUB")]
    actor_sub: Option<String>,
    /// Authorized-party / agent identifier (`azp`) stamped on writes.
    #[arg(long, env = "VERITY_ACTOR_AZP")]
    actor_azp: Option<String>,
}

#[derive(Clone)]
struct VerityMcp {
    http: reqwest::Client,
    config: Arc<Cli>,
    tool_router: ToolRouter<Self>,
}

// ---------- tool inputs (JSON-schema'd; identity fields deliberately absent) ----------

#[derive(Deserialize, JsonSchema)]
struct OpenScopeParams {
    /// Entities to bind the scope to, e.g. ["account:acme-corp"]. Reads are
    /// filtered to these entities and writes may only tag them. Omit for an
    /// unbound scope (visibility filtering still applies).
    entity_scope: Option<Vec<String>>,
    /// Why the scope is being opened, e.g. "support_conversation". Advisory
    /// until purpose-pack policies land server-side; not enforced today.
    #[allow(dead_code)]
    purpose: Option<String>,
    /// Scope lifetime in seconds (server default: 3600).
    ttl_seconds: Option<i64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct RecallParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Natural-language query. The server embeds it locally for the dense leg
    /// and runs BM25 for the sparse leg (hybrid recall).
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    /// Precomputed query embedding (rare; prefer `text`).
    #[serde(skip_serializing_if = "Option::is_none")]
    embedding: Option<Vec<f32>>,
    /// Number of results to return (server default: 8, max 100).
    #[serde(skip_serializing_if = "Option::is_none")]
    k: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct GetParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Source system the record came from, e.g. "salesforce".
    source: String,
    /// Entity id within the source, e.g. "006xx0000012345".
    entity: String,
    /// Field name, e.g. "Amount".
    field: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct RememberParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// The observation to remember, in plain prose.
    observation: String,
    /// Entity tags, e.g. ["account:acme-corp"]. Must be inside the scope's
    /// entity_scope; omit to inherit the whole scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    entities: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Succeeded,
    Failed,
    Pending,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct RecordActionParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Caller-chosen unique id; retries with the same id are deduplicated.
    action_id: String,
    /// Dotted action type, e.g. "quote.issued" or "email.sent".
    action_type: String,
    /// Entities the action touched, e.g. ["account:acme-corp"]. Must be
    /// inside the scope's entity_scope; omit to inherit the whole scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    entities: Option<Vec<String>>,
    /// One-line human-readable summary of what was done.
    summary: String,
    /// Structured details of the action (free-form JSON object).
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
    /// Result of the action.
    outcome: Outcome,
    /// When the action happened (RFC 3339, e.g. "2026-07-09T17:41:02Z").
    occurred_at: DateTime<Utc>,
}

#[derive(Deserialize, JsonSchema)]
struct ActivityParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Entity whose timeline to read, e.g. "account:acme-corp".
    entity: String,
    /// Only return actions at or after this instant (RFC 3339).
    since: Option<DateTime<Utc>>,
    /// Comma-separated exact types or "prefix.*" patterns,
    /// e.g. "email.*,quote.issued".
    action_types: Option<String>,
    /// Maximum records to return (server default: 50).
    limit: Option<u32>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
struct ProposeLearningParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// The generalization, written about CATEGORIES, never entities — no
    /// customer names, quotes, or identifying amounts. Statements containing
    /// known entity identifiers are quarantined, not published.
    statement: String,
    /// Category tags, e.g. ["industry:healthcare", "objection:dpa"].
    #[serde(default)]
    categories: Vec<String>,
    /// Supporting episode ids (from memory_remember results or recall
    /// provenance). Attribution is computed server-side from these.
    #[serde(default)]
    evidence: Vec<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct BriefParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Entity to brief, e.g. "account:acme-corp".
    entity: String,
}

#[derive(Deserialize, JsonSchema)]
struct IngestTextParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// The document text to ingest verbatim (plain text, markdown, JSON, …).
    content: String,
    /// Entity tags, e.g. ["account:acme-corp"]. Must be inside the scope's
    /// entity_scope; omit to inherit the whole scope.
    entities: Option<Vec<String>>,
    /// Reserved for future use (stable document identity for re-ingestion);
    /// accepted but not yet sent to the server.
    #[allow(dead_code)]
    document_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct IngestFileParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Path to a LOCAL file. Allowed extensions: .txt, .md, .json, .csv,
    /// .html (UTF-8 text) and .png, .jpg, .jpeg (server-side local OCR).
    /// Maximum size: 512 KB.
    path: String,
    /// Entity tags, e.g. ["account:acme-corp"]. Must be inside the scope's
    /// entity_scope; omit to inherit the whole scope.
    entities: Option<Vec<String>>,
}

#[derive(Deserialize, JsonSchema)]
struct IngestUrlParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Public http(s) URL of the page to read and remember.
    url: String,
    /// Entity tags, e.g. ["account:acme-corp"]. Must be inside the scope's
    /// entity_scope; omit to inherit the whole scope.
    entities: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ForgetRefKind {
    Chunk,
    Episode,
}

#[derive(Deserialize, JsonSchema)]
struct ForgetParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// What to forget: "chunk" (one recall result) or "episode" (one
    /// remembered observation and the chunks derived from it).
    ref_kind: ForgetRefKind,
    /// Id of the chunk or episode, as returned by memory_recall provenance
    /// or memory_remember / the ingest tools.
    id: String,
    /// Why this memory must be forgotten (kept in the audit trail),
    /// e.g. "customer data-deletion request" or "ingested by mistake".
    reason: String,
}

#[derive(Deserialize, JsonSchema)]
struct PollChangesParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Entities to watch, e.g. ["account:acme-corp"]. Each must be visible
    /// to the scope; out-of-scope entities silently yield no changes
    /// (fail closed).
    entities: Vec<String>,
    /// The cursor: only changes strictly after this instant are returned
    /// (RFC 3339, e.g. "2026-07-09T17:41:02Z"). First call: use the moment
    /// your task started. Every later call: pass back the previous result's
    /// `next_since` verbatim.
    since: DateTime<Utc>,
}

// ---------- REST proxy plumbing ----------

impl VerityMcp {
    fn new(cli: Cli) -> Self {
        Self {
            http: reqwest::Client::new(),
            config: Arc::new(cli),
            tool_router: Self::tool_router(),
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.config.url.trim_end_matches('/'))
    }

    /// One REST round-trip → one tool result. Non-2xx becomes a tool-level
    /// error carrying the status and body text (visible to the agent);
    /// 2xx bodies pass through as pretty-printed JSON.
    async fn proxy(&self, req: reqwest::RequestBuilder) -> Result<CallToolResult, ErrorData> {
        let resp = match req.send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "verity server unreachable at {}: {e}",
                    self.config.url
                ))]));
            }
        };
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "verity REST error {status}: {body}"
            ))]));
        }
        let text = serde_json::from_str::<serde_json::Value>(&body)
            .and_then(|v| serde_json::to_string_pretty(&v))
            .unwrap_or(body);
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    async fn post_json(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<CallToolResult, ErrorData> {
        self.proxy(self.http.post(self.endpoint(path)).json(body))
            .await
    }

    /// GET returning parsed JSON, for tools that combine several REST reads
    /// (memory_poll_changes). Errors are tool-visible strings.
    async fn get_json(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<serde_json::Value, String> {
        let resp = self
            .http
            .get(self.endpoint(path))
            .query(query)
            .send()
            .await
            .map_err(|e| format!("verity server unreachable at {}: {e}", self.config.url))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("verity REST error {status} on {path}: {body}"));
        }
        serde_json::from_str(&body).map_err(|e| format!("invalid JSON from {path}: {e}"))
    }

    /// Multipart POST /v1/files: fields `scope_handle`, `entities`
    /// (comma-separated, only when tags were given), and `file`. The part is
    /// caller-built: text content for the UTF-8 lane, raw bytes + image mime
    /// for the OCR lane (the server extracts by magic either way).
    async fn post_file(
        &self,
        scope_handle: String,
        entities: Option<Vec<String>>,
        part: reqwest::multipart::Part,
    ) -> Result<CallToolResult, ErrorData> {
        let mut form = reqwest::multipart::Form::new().text("scope_handle", scope_handle);
        if let Some(entities) = entities.filter(|e| !e.is_empty()) {
            form = form.text("entities", entities.join(","));
        }
        form = form.part("file", part);
        self.proxy(self.http.post(self.endpoint("/v1/files")).multipart(form))
            .await
    }
}

/// A tool-level error the agent can see and react to (bad input, unreadable
/// file, unreachable URL) — as opposed to a protocol-level ErrorData.
fn tool_error(msg: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::error(vec![ContentBlock::text(msg.into())]))
}

// ---------- local helpers for the ingest tools ----------

/// Extensions memory_ingest_file accepts as UTF-8 text.
const INGEST_FILE_EXTENSIONS: [&str; 5] = ["txt", "md", "json", "csv", "html"];
/// Extensions memory_ingest_file accepts as raw image bytes: the server's
/// local OCR tier (extract.rs + ocr.rs) extracts printed text best-effort,
/// disclosed as method "image-ocr" on the receipt.
const INGEST_IMAGE_EXTENSIONS: [&str; 3] = ["png", "jpg", "jpeg"];
/// memory_ingest_file size cap.
const MAX_FILE_BYTES: u64 = 512 * 1024;
/// memory_ingest_url download cap.
const MAX_URL_BYTES: usize = 2 * 1024 * 1024;
/// memory_ingest_url fetch timeout.
const URL_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Naive HTML → text: drop <script>/<style> blocks, strip every tag, decode
/// the common entities, collapse whitespace. Deliberately hand-rolled — good
/// enough for recall indexing, no HTML-parser dependency.
fn html_to_text(html: &str) -> String {
    let html = strip_tag_blocks(html, "script");
    let html = strip_tag_blocks(&html, "style");
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                text.push(' '); // tags separate words: "<p>a</p><p>b</p>" -> "a b"
            }
            '>' if in_tag => in_tag = false,
            _ if in_tag => {}
            _ => text.push(c),
        }
    }
    let text = text
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Remove `<tag …>…</tag>` blocks (case-insensitive), content included.
/// An unclosed block is dropped through end-of-input.
fn strip_tag_blocks(html: &str, tag: &str) -> String {
    // ASCII lowercasing preserves byte offsets, so indices found in `lower`
    // are valid char boundaries in `html`.
    let lower = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}");
    let mut out = String::with_capacity(html.len());
    let mut pos = 0;
    while let Some(found) = lower[pos..].find(&open) {
        let start = pos + found;
        out.push_str(&html[pos..start]);
        pos = match lower[start..].find(&close) {
            Some(rel) => {
                let close_start = start + rel;
                match lower[close_start..].find('>') {
                    Some(gt) => close_start + gt + 1,
                    None => lower.len(),
                }
            }
            None => lower.len(),
        };
    }
    out.push_str(&html[pos..]);
    out
}

/// File name for a fetched page, from the last non-empty URL path segment.
fn file_name_from_url(url: &reqwest::Url) -> String {
    url.path()
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("webpage.txt")
        .to_owned()
}

// ---------- local helpers for memory_recall ----------

/// Response header the server sets when the per-source freshness gate dropped
/// hits from stale/never-heartbeated connector sources.
const SOURCE_FENCE_HEADER: &str = "x-verity-source-fence";

/// Parse the fence header value (`dropped=<n>; stale=<s1,s2>`) into a
/// structured object; an unrecognized value is passed through verbatim under
/// `"raw"` (never silently dropped — the whole point is disclosure).
fn parse_source_fence(value: &str) -> serde_json::Value {
    let mut dropped: Option<u64> = None;
    let mut stale: Option<Vec<String>> = None;
    for part in value.split(';') {
        match part.trim().split_once('=') {
            Some(("dropped", n)) => dropped = n.parse().ok(),
            Some(("stale", s)) => {
                stale = Some(
                    s.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                )
            }
            _ => {}
        }
    }
    match (dropped, stale) {
        (Some(dropped), Some(stale)) => serde_json::json!({
            "dropped": dropped,
            "stale_sources": stale,
        }),
        _ => serde_json::json!({ "raw": value }),
    }
}

/// Shape the `memory_recall` tool text: the BARE hits array whenever the
/// server reported no fence drops (backward-compatible — identical to the REST
/// body), and the `{hits, source_fence}` envelope ONLY when hits were actually
/// dropped (disclosure trumps shape stability in that case).
fn render_recall_result(hits: serde_json::Value, fence: Option<serde_json::Value>) -> String {
    let value = match fence {
        Some(fence) => serde_json::json!({ "hits": hits, "source_fence": fence }),
        None => hits,
    };
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}

// ---------- local helpers for memory_poll_changes ----------

/// Parse an RFC 3339 timestamp field out of a server JSON record.
fn record_timestamp(record: &serde_json::Value, field: &str) -> Option<DateTime<Utc>> {
    record
        .get(field)?
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
}

/// Fold one entity's REST reads into cursor-ordered changes: actions from
/// `/v1/activity` keyed on `occurred_at` (the field the server's `since`
/// filter compares against, inclusively — hence the strict `>` here so a
/// re-poll at `next_since` doesn't repeat the boundary change), and brief
/// `recent_memory` chunks keyed on `valid_from`. Action-derived chunks
/// (document_id "action:…") are skipped — the action leg already reports
/// them. Records without a parseable timestamp cannot be positioned on the
/// cursor and are dropped.
fn changes_for_entity(
    since: DateTime<Utc>,
    entity: &str,
    actions: &[serde_json::Value],
    memory: &[serde_json::Value],
) -> Vec<(DateTime<Utc>, serde_json::Value)> {
    let action_changes = actions.iter().filter_map(|record| {
        let at = record_timestamp(record, "occurred_at").filter(|at| *at > since)?;
        Some((at, "action", record))
    });
    let memory_changes = memory.iter().filter_map(|record| {
        let from_action = record
            .get("document_id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id.starts_with("action:"));
        if from_action {
            return None;
        }
        let at = record_timestamp(record, "valid_from").filter(|at| *at > since)?;
        Some((at, "memory", record))
    });
    action_changes
        .chain(memory_changes)
        .map(|(at, kind, record)| {
            let change = serde_json::json!({
                "entity": entity,
                "kind": kind,
                "at": at.to_rfc3339_opts(SecondsFormat::Micros, true),
                "record": record,
            });
            (at, change)
        })
        .collect()
}

// ---------- the fourteen tools (SPEC §9a naming, snake_case) ----------

#[tool_router]
impl VerityMcp {
    #[tool(
        name = "memory_open_scope",
        description = "Open a memory scope and get back a scope_handle. Call this FIRST, once per task; every other memory tool requires the handle. Optionally bind the scope to entities (e.g. [\"account:acme-corp\"]) so reads and writes stay inside them. Identity (tenant, principals, actor) is fixed by server configuration and cannot be set here."
    )]
    async fn memory_open_scope(
        &self,
        Parameters(p): Parameters<OpenScopeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        #[derive(Serialize)]
        struct Body<'a> {
            tenant_id: Uuid,
            // Exactly one of subject / principals is sent — the server rejects
            // both (self-assertion) and resolves a subject to its group closure.
            #[serde(skip_serializing_if = "Option::is_none")]
            subject: Option<&'a String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            principals: Option<&'a [i32]>,
            entity_scope: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            actor_sub: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            actor_azp: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            ttl_seconds: Option<i64>,
        }
        // Identity-resolved mode when a subject is configured; else the
        // materialized-token mode (unchanged). main() guarantees not-both.
        let (subject, principals) = match &self.config.subject {
            Some(s) => (Some(s), None),
            None => (None, Some(self.config.principals.as_slice())),
        };
        let body = Body {
            tenant_id: self.config.tenant_id,
            subject,
            principals,
            entity_scope: p.entity_scope.unwrap_or_default(),
            actor_sub: &self.config.actor_sub,
            actor_azp: &self.config.actor_azp,
            ttl_seconds: p.ttl_seconds,
        };
        self.post_json("/v1/scopes", &body).await
    }

    #[tool(
        name = "memory_recall",
        description = "Scoped hybrid search over shared memory. Use for open-ended questions (\"what do we know about X?\"): returns the k best-matching memory chunks the scope is allowed to see, with entity tags, trust tier, timestamps, and provenance."
    )]
    async fn memory_recall(
        &self,
        Parameters(p): Parameters<RecallParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // Not `post_json`: the per-source freshness fence discloses drops in a
        // RESPONSE HEADER (the HTTP body stays a bare hits array — REST
        // integrations depend on that shape). The MCP layer is where the
        // header becomes agent-visible: when the server reported drops this
        // tool wraps the array in a {hits, source_fence} envelope; with no
        // drops it returns the bare hits array unchanged (backward-compatible
        // with pre-gate consumers).
        let resp = match self
            .http
            .post(self.endpoint("/v1/recall"))
            .json(&p)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "verity server unreachable at {}: {e}",
                    self.config.url
                ))]));
            }
        };
        let status = resp.status();
        let fence = resp
            .headers()
            .get(SOURCE_FENCE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(parse_source_fence);
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "verity REST error {status}: {body}"
            ))]));
        }
        let hits: serde_json::Value =
            serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body));
        let text = render_recall_result(hits, fence);
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(
        name = "memory_get",
        description = "Point lookup of the current value of one structured record field, addressed as source/entity/field (e.g. salesforce/006xx0000012345/Amount). Use when you know exactly which field you need — faster and more precise than memory_recall. Returns 404 if there is no current value."
    )]
    async fn memory_get(
        &self,
        Parameters(p): Parameters<GetParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = format!("/v1/records/{}/{}/{}", p.source, p.entity, p.field);
        let req = self
            .http
            .get(self.endpoint(&path))
            .query(&[("scope_handle", p.scope_handle)]);
        self.proxy(req).await
    }

    #[tool(
        name = "memory_remember",
        description = "Append an observation to shared memory (immutable episode + immediately searchable chunk). Use to record durable knowledge learned during the task — decisions, facts, customer statements — so this and other agents can surface it later via memory_recall. Entity tags must stay inside the scope."
    )]
    async fn memory_remember(
        &self,
        Parameters(p): Parameters<RememberParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post_json("/v1/episodes", &p).await
    }

    #[tool(
        name = "memory_record_action",
        description = "Record an action you performed on the entity activity timeline (idempotent on action_id — safe to retry). Call AFTER completing a side-effecting action (email sent, quote issued, ticket updated) so other agents see it via memory_activity and don't repeat it. Actor identity is stamped server-side from configuration."
    )]
    async fn memory_record_action(
        &self,
        Parameters(p): Parameters<RecordActionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post_json("/v1/actions", &p).await
    }

    #[tool(
        name = "memory_activity",
        description = "Check what other agents have done on this entity BEFORE acting — returns the scoped activity timeline: who did what, when, with what outcome. Filter with `since` and `action_types` patterns like \"email.*,quote.issued\"."
    )]
    async fn memory_activity(
        &self,
        Parameters(p): Parameters<ActivityParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut query: Vec<(&str, String)> =
            vec![("scope_handle", p.scope_handle), ("entity", p.entity)];
        if let Some(since) = p.since {
            query.push(("since", since.to_rfc3339_opts(SecondsFormat::Secs, true)));
        }
        if let Some(types) = p.action_types {
            query.push(("action_types", types));
        }
        if let Some(limit) = p.limit {
            query.push(("limit", limit.to_string()));
        }
        let req = self.http.get(self.endpoint("/v1/activity")).query(&query);
        self.proxy(req).await
    }

    #[tool(
        name = "memory_poll_changes",
        description = "Poll for changes on watched entities since a cursor — the pull-based change feed. MCP delivers no pushes into a running turn, so call this periodically BETWEEN turns or task steps (e.g. before each new step on an entity) to learn what other agents did meanwhile. Returns, per watched entity, actions recorded by other agents and new memory (observations, ingested documents, webhook writes), oldest first, plus `next_since`. CURSOR DISCIPLINE: first call — pass `since` = the moment your task started; every later call — pass back the previous result's `next_since` VERBATIM (never invent, round, or reuse an older cursor; on a failed poll retry with the same cursor). Everything is scope-filtered: entities outside the scope yield nothing (fail closed). Note: the memory leg inspects each entity's 10 newest chunks, so poll more often than an entity gains 10 memories."
    )]
    async fn memory_poll_changes(
        &self,
        Parameters(p): Parameters<PollChangesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let since_str = p.since.to_rfc3339_opts(SecondsFormat::Micros, true);
        let mut changes: Vec<(DateTime<Utc>, serde_json::Value)> = Vec::new();
        for entity in &p.entities {
            // Action leg: the server's `since` bounds the fetch (inclusive,
            // on occurred_at); changes_for_entity re-filters strictly.
            let activity = self
                .get_json(
                    "/v1/activity",
                    &[
                        ("scope_handle", p.scope_handle.clone()),
                        ("entity", entity.clone()),
                        ("since", since_str.clone()),
                        ("limit", "500".to_owned()),
                    ],
                )
                .await;
            // Memory leg: the entity brief's newest chunks, filtered
            // client-side by valid_from > since.
            let brief = self
                .get_json(
                    &format!("/v1/briefs/{entity}"),
                    &[("scope_handle", p.scope_handle.clone())],
                )
                .await;
            // Any failed read fails the whole poll: a partial result with an
            // advanced next_since would silently skip changes. The agent
            // retries with the same cursor.
            let (activity, brief) = match (activity, brief) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return tool_error(e),
            };
            let actions = activity.as_array().cloned().unwrap_or_default();
            let memory = brief
                .get("recent_memory")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            changes.extend(changes_for_entity(p.since, entity, &actions, &memory));
        }
        changes.sort_by_key(|(at, _)| *at);
        let next_since = changes.last().map_or(p.since, |(at, _)| *at);
        let result = serde_json::json!({
            "changes": changes.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
            "next_since": next_since.to_rfc3339_opts(SecondsFormat::Micros, true),
        });
        let text = serde_json::to_string_pretty(&result)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    #[tool(
        name = "memory_propose_learning",
        description = "Propose a cross-customer generalization for the shared knowledge layer — a PROPOSAL, never a publish: it enters a de-identification gate, needs support from 3+ distinct entities, and awaits review. Use when you notice a pattern that would help agents on OTHER accounts (objection trends, segment behaviors, playbooks). Write about categories, never name customers."
    )]
    async fn memory_propose_learning(
        &self,
        Parameters(p): Parameters<ProposeLearningParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post_json("/v1/knowledge", &p).await
    }

    #[tool(
        name = "memory_brief",
        description = "One-call current state of an entity: its newest memory (observations, documents, actions) plus the recent agent activity timeline. Call this FIRST when starting work on an entity — it replaces several recall/activity round-trips."
    )]
    async fn memory_brief(
        &self,
        Parameters(p): Parameters<BriefParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let req = self
            .http
            .get(self.endpoint(&format!("/v1/briefs/{}", p.entity)))
            .query(&[("scope_handle", p.scope_handle)]);
        self.proxy(req).await
    }

    #[tool(
        name = "memory_ingest_text",
        description = "Ingest a document-sized piece of text into shared memory verbatim, so it becomes searchable via memory_recall. Use for pasted documents, meeting transcripts, reports, or notes you already hold in-context — anything bigger than the one-line observations memory_remember is for. Tag entities so the content surfaces on their briefs."
    )]
    async fn memory_ingest_text(
        &self,
        Parameters(p): Parameters<IngestTextParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // document_id is reserved (schema-only) until the server keys
        // re-ingestion on it; deliberately not sent on the wire.
        #[derive(Serialize)]
        struct Body {
            scope_handle: String,
            observation: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            entities: Option<Vec<String>>,
        }
        let body = Body {
            scope_handle: p.scope_handle,
            observation: p.content,
            entities: p.entities,
        };
        self.post_json("/v1/episodes", &body).await
    }

    #[tool(
        name = "memory_ingest_file",
        description = "Read a LOCAL file and ingest its contents into shared memory, so it becomes searchable via memory_recall. Use when the knowledge lives in a file on this machine rather than in-context. Accepts UTF-8 text (.txt/.md/.json/.csv/.html) and images (.png/.jpg/.jpeg — printed text is extracted by the server's local OCR, best-effort, disclosed as method image-ocr) up to 512 KB; anything else is rejected with an error."
    )]
    async fn memory_ingest_file(
        &self,
        Parameters(p): Parameters<IngestFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = std::path::Path::new(&p.path);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let is_image = INGEST_IMAGE_EXTENSIONS.contains(&ext.as_str());
        if !is_image && !INGEST_FILE_EXTENSIONS.contains(&ext.as_str()) {
            return tool_error(format!(
                "unsupported file type {:?}: memory_ingest_file accepts UTF-8 text files (.txt, .md, .json, .csv, .html) and images (.png, .jpg, .jpeg)",
                p.path
            ));
        }
        let meta = match tokio::fs::metadata(path).await {
            Ok(meta) => meta,
            Err(e) => return tool_error(format!("cannot read file {:?}: {e}", p.path)),
        };
        if !meta.is_file() {
            return tool_error(format!("{:?} is not a regular file", p.path));
        }
        if meta.len() > MAX_FILE_BYTES {
            return tool_error(format!(
                "file {:?} is {} bytes; memory_ingest_file caps at {MAX_FILE_BYTES} bytes (512 KB)",
                p.path,
                meta.len()
            ));
        }
        let bytes = match tokio::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(e) => return tool_error(format!("cannot read file {:?}: {e}", p.path)),
        };
        if is_image {
            // Raw bytes to the server's OCR lane; the server sniffs magic and
            // returns a typed, disclosed failure if OCR finds nothing.
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file.png")
                .to_owned();
            let mime = if ext == "png" {
                "image/png"
            } else {
                "image/jpeg"
            };
            let part = match reqwest::multipart::Part::bytes(bytes)
                .file_name(file_name)
                .mime_str(mime)
            {
                Ok(part) => part,
                Err(e) => return tool_error(format!("building upload part: {e}")),
            };
            return self.post_file(p.scope_handle, p.entities, part).await;
        }
        let content = match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(_) => {
                return tool_error(format!(
                    "file {:?} is not valid UTF-8 text; memory_ingest_file accepts text files only",
                    p.path
                ))
            }
        };
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.txt")
            .to_owned();
        let part = reqwest::multipart::Part::text(content).file_name(file_name);
        self.post_file(p.scope_handle, p.entities, part).await
    }

    #[tool(
        name = "memory_ingest_url",
        description = "Read and remember a public webpage: fetch an http(s) URL (10s timeout, 2 MB cap), reduce HTML to plain readable text, and ingest it into shared memory for memory_recall. Use when an agent should retain the contents of an article, documentation page, or other public page. Non-HTML text responses are ingested unmodified."
    )]
    async fn memory_ingest_url(
        &self,
        Parameters(p): Parameters<IngestUrlParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = match reqwest::Url::parse(&p.url) {
            Ok(url) => url,
            Err(e) => return tool_error(format!("invalid URL {:?}: {e}", p.url)),
        };
        if !matches!(url.scheme(), "http" | "https") {
            return tool_error(format!(
                "unsupported URL scheme {:?}: memory_ingest_url fetches http/https only",
                url.scheme()
            ));
        }
        let resp = match self
            .http
            .get(url.clone())
            .timeout(URL_FETCH_TIMEOUT)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => return tool_error(format!("failed to fetch {url}: {e}")),
        };
        if !resp.status().is_success() {
            return tool_error(format!("failed to fetch {url}: HTTP {}", resp.status()));
        }
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut resp = resp;
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if bytes.len() + chunk.len() > MAX_URL_BYTES {
                        return tool_error(format!(
                            "response from {url} exceeds the {MAX_URL_BYTES}-byte (2 MB) cap"
                        ));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => return tool_error(format!("failed while reading {url}: {e}")),
            }
        }
        let body = match String::from_utf8(bytes) {
            Ok(body) => body,
            Err(_) => {
                return tool_error(format!(
                    "response from {url} is not UTF-8 text; memory_ingest_url handles text content only"
                ))
            }
        };
        let looks_like_html = content_type.contains("html")
            || (content_type.is_empty()
                && (body
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("<!doctype")
                    || body.trim_start().to_ascii_lowercase().starts_with("<html")));
        let content = if looks_like_html {
            html_to_text(&body)
        } else {
            body
        };
        if content.trim().is_empty() {
            return tool_error(format!("no textual content extracted from {url}"));
        }
        let file_name = file_name_from_url(&url);
        let part = reqwest::multipart::Part::text(content).file_name(file_name);
        self.post_file(p.scope_handle, p.entities, part).await
    }

    #[tool(
        name = "memory_forget",
        description = "Invalidate one specific memory — a chunk (recall result) or an episode (remembered observation) — by id, with an audited reason. Use when a memory is wrong, sensitive, or was ingested by mistake, so it stops surfacing in recall for every agent. Take ids from memory_recall provenance or memory_remember/ingest results."
    )]
    async fn memory_forget(
        &self,
        Parameters(p): Parameters<ForgetParams>,
    ) -> Result<CallToolResult, ErrorData> {
        #[derive(Serialize)]
        struct RefBody {
            kind: ForgetRefKind,
            id: String,
        }
        #[derive(Serialize)]
        struct Body {
            scope_handle: String,
            #[serde(rename = "ref")]
            target: RefBody,
            reason: String,
        }
        let body = Body {
            scope_handle: p.scope_handle,
            target: RefBody {
                kind: p.ref_kind,
                id: p.id,
            },
            reason: p.reason,
        };
        self.post_json("/v1/forget", &body).await
    }

    #[tool(
        name = "memory_whoami",
        description = "Return this server's configured identity defaults: Verity URL, tenant, principal tokens, and actor sub/azp. Diagnostic only — identity is process configuration and can never be changed through tool arguments."
    )]
    fn memory_whoami(&self) -> Result<CallToolResult, ErrorData> {
        let info = serde_json::json!({
            "url": self.config.url,
            "tenant_id": self.config.tenant_id,
            "mode": if self.config.subject.is_some() { "subject-resolved" } else { "materialized-tokens" },
            "subject": self.config.subject,
            "principals": self.config.principals,
            "actor_sub": self.config.actor_sub,
            "actor_azp": self.config.actor_azp,
        });
        let text = serde_json::to_string_pretty(&info)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for VerityMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("verity-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Verity: permission-aware shared memory for agents. Workflow: \
                 memory_open_scope once to get a scope_handle, then pass it to every \
                 other tool. Check memory_activity before side-effecting actions; \
                 poll memory_poll_changes between turns to see what other agents \
                 changed (pass each result's next_since back as the next cursor); \
                 record completed actions with memory_record_action; persist durable \
                 knowledge with memory_remember; ingest documents with \
                 memory_ingest_text / memory_ingest_file / memory_ingest_url; \
                 retract bad memories with memory_forget; query with memory_recall \
                 (search) or memory_get (exact field). All results are filtered to \
                 what this agent's configured identity is allowed to see.",
            )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout is the MCP transport; logs must go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    // Exactly one identity mode: a subject (server-resolved) OR materialized
    // tokens — never both (that is self-assertion; the server 422s it). An empty
    // principal set with no subject is the legitimate fail-closed "see nothing".
    if cli.subject.is_some() && !cli.principals.is_empty() {
        anyhow::bail!(
            "set VERITY_SUBJECT or VERITY_PRINCIPALS, not both — with a subject the server \
             resolves the principal set (user + transitive groups) itself"
        );
    }
    tracing::info!(
        url = %cli.url,
        tenant = %cli.tenant_id,
        mode = if cli.subject.is_some() { "subject-resolved" } else { "materialized-tokens" },
        "verity-mcp serving on stdio"
    );
    let service = VerityMcp::new(cli).serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        changes_for_entity, file_name_from_url, html_to_text, parse_source_fence,
        render_recall_result,
    };
    use chrono::{DateTime, Utc};

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn changes_are_strictly_after_the_cursor_and_carry_positions() {
        let since = ts("2026-07-10T12:00:00Z");
        let actions = vec![
            // At the cursor exactly: the server's inclusive `since` returns
            // it, the strict client filter must drop it (already reported).
            serde_json::json!({"occurred_at": "2026-07-10T12:00:00Z", "summary": "old"}),
            serde_json::json!({"occurred_at": "2026-07-10T12:00:05Z", "summary": "new"}),
        ];
        let memory = vec![
            serde_json::json!({"valid_from": "2026-07-10T11:59:00Z", "content": "old chunk"}),
            serde_json::json!({"valid_from": "2026-07-10T12:00:07.5Z", "content": "new chunk"}),
        ];
        let changes = changes_for_entity(since, "account:acme", &actions, &memory);
        assert_eq!(changes.len(), 2);
        let (at, change) = &changes[0];
        assert_eq!(*at, ts("2026-07-10T12:00:05Z"));
        assert_eq!(change["entity"], "account:acme");
        assert_eq!(change["kind"], "action");
        assert_eq!(change["at"], "2026-07-10T12:00:05.000000Z");
        assert_eq!(change["record"]["summary"], "new");
        let (at, change) = &changes[1];
        assert_eq!(*at, ts("2026-07-10T12:00:07.5Z"));
        assert_eq!(change["kind"], "memory");
        assert_eq!(change["record"]["content"], "new chunk");
    }

    #[test]
    fn action_derived_chunks_are_not_double_reported() {
        let since = ts("2026-07-10T12:00:00Z");
        let memory = vec![
            serde_json::json!({
                "valid_from": "2026-07-10T12:00:05Z",
                "document_id": "action:quote-1",
                "content": "quote.issued: sent quote"
            }),
            serde_json::json!({
                "valid_from": "2026-07-10T12:00:06Z",
                "document_id": "note.txt",
                "content": "kept"
            }),
        ];
        let changes = changes_for_entity(since, "account:acme", &[], &memory);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].1["record"]["content"], "kept");
    }

    #[test]
    fn unparseable_timestamps_never_position_a_change() {
        let since = ts("2026-07-10T12:00:00Z");
        let actions = vec![serde_json::json!({"occurred_at": "not-a-time"})];
        let memory = vec![serde_json::json!({"content": "no valid_from at all"})];
        assert!(changes_for_entity(since, "e", &actions, &memory).is_empty());
    }

    #[test]
    fn html_to_text_strips_script_style_tags_and_entities() {
        let html = "<!DOCTYPE html><html><head><title>T</title>\
                    <STYLE>body { color: red; }</STYLE>\
                    <script type=\"text/javascript\">var x = \"<p>sneaky</p>\";</script>\
                    </head><body>\n  <h1>Hello&nbsp;&amp; welcome</h1>\
                    <p>line   one</p><p>line&#39;s two &lt;3</p></body></html>";
        assert_eq!(
            html_to_text(html),
            "T Hello & welcome line one line's two <3"
        );
    }

    #[test]
    fn html_to_text_drops_unclosed_script_through_eof() {
        assert_eq!(html_to_text("<p>kept</p><script>var dropped;"), "kept");
    }

    #[test]
    fn source_fence_header_parses_or_passes_through_raw() {
        assert_eq!(
            parse_source_fence("dropped=3; stale=gdrive,gmail"),
            serde_json::json!({"dropped": 3, "stale_sources": ["gdrive", "gmail"]})
        );
        assert_eq!(
            parse_source_fence("dropped=1; stale=hubspot"),
            serde_json::json!({"dropped": 1, "stale_sources": ["hubspot"]})
        );
        // Unrecognized shapes are disclosed verbatim, never dropped.
        assert_eq!(
            parse_source_fence("weird"),
            serde_json::json!({"raw": "weird"})
        );
    }

    #[test]
    fn recall_result_is_bare_hits_array_when_nothing_was_fenced() {
        // Backward-compatible: no fence header → the tool text IS the REST
        // body (a bare hits array), not an envelope.
        let hits = serde_json::json!([{"chunk_id": "c1", "content": "body"}]);
        let text = render_recall_result(hits.clone(), None);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            hits
        );
    }

    #[test]
    fn recall_result_is_enveloped_only_when_the_server_reported_drops() {
        let hits = serde_json::json!([{"chunk_id": "c1", "content": "body"}]);
        let fence = parse_source_fence("dropped=2; stale=gdrive");
        let text = render_recall_result(hits.clone(), Some(fence));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            serde_json::json!({
                "hits": hits,
                "source_fence": {"dropped": 2, "stale_sources": ["gdrive"]},
            })
        );
    }

    #[test]
    fn file_name_from_url_takes_last_segment_or_falls_back() {
        let url = reqwest::Url::parse("https://example.com/docs/page.html?q=1").unwrap();
        assert_eq!(file_name_from_url(&url), "page.html");
        let root = reqwest::Url::parse("https://example.com/").unwrap();
        assert_eq!(file_name_from_url(&root), "webpage.txt");
    }
}
