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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct BriefParams {
    /// Scope handle from memory_open_scope.
    scope_handle: String,
    /// Entity to brief, e.g. "account:acme-corp".
    entity: String,
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
}

// ---------- the seven tools (SPEC §9a naming, snake_case) ----------

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
                 knowledge with memory_remember; query with memory_recall (search) or \
                 memory_get (exact field). All results are filtered to what this \
                 agent's configured identity is allowed to see.",
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
