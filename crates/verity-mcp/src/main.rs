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
    #[arg(
        long,
        env = "VERITY_PRINCIPALS",
        value_delimiter = ',',
        required = true
    )]
    principals: Vec<i32>,
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
    /// Path to a LOCAL UTF-8 text file. Allowed extensions: .txt, .md,
    /// .json, .csv, .html. Maximum size: 512 KB.
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

    /// Multipart POST /v1/files: fields `scope_handle`, `entities`
    /// (comma-separated, only when tags were given), and `file`.
    async fn post_file(
        &self,
        scope_handle: String,
        entities: Option<Vec<String>>,
        file_name: String,
        content: String,
    ) -> Result<CallToolResult, ErrorData> {
        let mut form = reqwest::multipart::Form::new().text("scope_handle", scope_handle);
        if let Some(entities) = entities.filter(|e| !e.is_empty()) {
            form = form.text("entities", entities.join(","));
        }
        form = form.part(
            "file",
            reqwest::multipart::Part::text(content).file_name(file_name),
        );
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

/// Extensions memory_ingest_file accepts (UTF-8 text-like content only).
const INGEST_FILE_EXTENSIONS: [&str; 5] = ["txt", "md", "json", "csv", "html"];
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

// ---------- the thirteen tools (SPEC §9a naming, snake_case) ----------

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
            principals: &'a [i32],
            entity_scope: Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            actor_sub: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            actor_azp: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            ttl_seconds: Option<i64>,
        }
        let body = Body {
            tenant_id: self.config.tenant_id,
            principals: &self.config.principals,
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
        self.post_json("/v1/recall", &p).await
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
        description = "Read a LOCAL text file and ingest its contents into shared memory, so it becomes searchable via memory_recall. Use when the knowledge lives in a file on this machine rather than in-context. Accepts UTF-8 .txt/.md/.json/.csv/.html up to 512 KB; anything else is rejected with an error."
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
        if !INGEST_FILE_EXTENSIONS.contains(&ext.as_str()) {
            return tool_error(format!(
                "unsupported file type {:?}: memory_ingest_file accepts only UTF-8 text files with extension .txt, .md, .json, .csv, or .html",
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
        self.post_file(p.scope_handle, p.entities, file_name, content)
            .await
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
        self.post_file(p.scope_handle, p.entities, file_name, content)
            .await
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
    tracing::info!(url = %cli.url, tenant = %cli.tenant_id, "verity-mcp serving on stdio");
    let service = VerityMcp::new(cli).serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{file_name_from_url, html_to_text};

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
    fn file_name_from_url_takes_last_segment_or_falls_back() {
        let url = reqwest::Url::parse("https://example.com/docs/page.html?q=1").unwrap();
        assert_eq!(file_name_from_url(&url), "page.html");
        let root = reqwest::Url::parse("https://example.com/").unwrap();
        assert_eq!(file_name_from_url(&root), "webpage.txt");
    }
}
