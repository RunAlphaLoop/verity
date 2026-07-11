use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type TenantId = Uuid;
pub type EpisodeId = Uuid;
pub type FactId = Uuid;
pub type ChunkId = Uuid;

/// A materialized principal token: the unit of visibility. Every chunk carries
/// the set of tokens allowed to see it; the caller's principal set is resolved
/// once per session and intersected in the index. Empty set = invisible.
pub type PrincipalToken = i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(i16)]
pub enum TrustTier {
    /// CDC/webhook-derived content mirroring a system of record. Agent-immutable.
    Authoritative = 1,
    /// Agent- or human-written observations; ranked below tier 1 at recall.
    Observation = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(i16)]
pub enum Confidentiality {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    /// Pricing, quotes, negotiation terms land here by default; gets a
    /// mandatory live ReBAC recheck at recall time (SPEC §7b) once the
    /// permission plane lands.
    Restricted = 3,
}

/// How a memory's visibility was determined (SPEC §5e.6). Surfaced on every
/// read so the convenience lane and the truth lane are labeled in-product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AclProvenance {
    /// Real per-object ACLs mirrored from the source system (Tier A).
    Mirrored,
    /// Container-membership approximation (Tier B).
    Approximated,
    /// Explicit admin/agent-assigned visibility policy.
    AdminAssigned,
    Quarantined,
}

impl AclProvenance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mirrored => "mirrored",
            Self::Approximated => "approximated",
            Self::AdminAssigned => "admin-assigned",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "mirrored" => Self::Mirrored,
            "approximated" => Self::Approximated,
            "quarantined" => Self::Quarantined,
            _ => Self::AdminAssigned,
        }
    }
}

/// Provenance stamped on every L0 episode; everything above L0 links back here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewEpisode {
    pub tenant_id: TenantId,
    pub source: String,
    pub source_entity: Option<String>,
    pub kind: EpisodeKind,
    pub payload: serde_json::Value,
    pub content_hash: String,
    pub trust_tier: TrustTier,
    pub writer_sub: Option<String>,
    pub writer_azp: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeKind {
    CdcEvent,
    Webhook,
    DocVersion,
    Observation,
    AgentAction,
    KnowledgePublish,
    WebSnapshot,
}

impl EpisodeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CdcEvent => "cdc_event",
            Self::Webhook => "webhook",
            Self::DocVersion => "doc_version",
            Self::Observation => "observation",
            Self::AgentAction => "agent_action",
            Self::KnowledgePublish => "knowledge_publish",
            Self::WebSnapshot => "web_snapshot",
        }
    }
}

/// The L1 key: one current value per (source, entity, field) per tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FactKey {
    pub source: String,
    pub entity_id: String,
    pub field: String,
}

/// A deterministic L1 write. `valid_from` is event time (when true in the
/// world), distinct from ingestion time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactWrite {
    pub tenant_id: TenantId,
    pub key: FactKey,
    pub value: serde_json::Value,
    pub valid_from: DateTime<Utc>,
    pub provenance: EpisodeId,
    pub acl_provenance: AclProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactRow {
    pub id: FactId,
    pub tenant_id: TenantId,
    pub key: FactKey,
    pub value: serde_json::Value,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
    pub superseded_by: Option<FactId>,
    pub recorded_at: DateTime<Utc>,
    pub provenance: EpisodeId,
    pub acl_provenance: AclProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactUpsertOutcome {
    /// First value ever recorded for this key.
    Inserted,
    /// Old row structurally retired (valid_to + superseded_by set), new row current.
    Superseded,
    /// Identical value already current — write skipped (idempotent replay).
    Unchanged,
    /// Incoming valid_from is older than the current row's — stored as history,
    /// current value untouched (late-arriving event).
    StaleEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkWrite {
    pub tenant_id: TenantId,
    pub source: String,
    pub document_id: String,
    pub seq: i32,
    pub content: String,
    pub content_hash: String,
    pub embedding: Option<Vec<f32>>,
    pub visibility: Vec<PrincipalToken>,
    pub entity_tags: Vec<String>,
    pub confidentiality: Confidentiality,
    pub trust_tier: TrustTier,
    pub valid_from: DateTime<Utc>,
    pub provenance: EpisodeId,
    pub acl_provenance: AclProvenance,
}

/// The caller's compiled scope, resolved server-side from token + MemoryScope
/// handle — never from agent-supplied parameters. Mandatory on every read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub tenant_id: TenantId,
    /// Resolved principal set. Empty = every read returns nothing (fail closed).
    pub principals: Vec<PrincipalToken>,
    /// When non-empty, only chunks whose entity tags are a subset of this set
    /// are retrievable (deny-by-default intersection semantics, SPEC §7d).
    pub entity_scope: Vec<String>,
    /// Highest confidentiality class this scope may retrieve.
    pub max_confidentiality: Confidentiality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallQuery {
    pub scope: Scope,
    /// Dense query vector (local encoder). None = sparse/BM25-only path.
    pub embedding: Option<Vec<f32>>,
    /// Text for BM25. None = dense-only.
    pub text: Option<String>,
    pub k: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallHit {
    pub chunk_id: ChunkId,
    pub document_id: String,
    pub seq: i32,
    pub content: String,
    pub score: f32,
    pub entity_tags: Vec<String>,
    /// "content" (scoped memory) or "knowledge" (published, entity-free — §7g).
    pub kind: String,
    /// Bucketed cross-customer support, present ONLY on `kind == "knowledge"`
    /// hits (knowledge-merge-tuning.md §5): a coarse tier the agent can weight
    /// by, never an exact count. `None` on ordinary content chunks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_tier: Option<SupportTier>,
    pub acl_provenance: AclProvenance,
    pub trust_tier: TrustTier,
    pub valid_from: DateTime<Utc>,
    pub provenance: EpisodeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    Succeeded,
    Failed,
    Pending,
}

impl ActionOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Pending => "pending",
        }
    }
}

/// A consequential agent act, destined for the append-only activity timeline
/// (SPEC §2, Action records). Actor fields are stamped server-side from the
/// authenticated token — an adapter must never accept them from tool arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionWrite {
    pub tenant_id: TenantId,
    /// Client idempotency key: replaying the same (tenant, action_id) is a no-op.
    pub action_id: String,
    pub actor_sub: Option<String>,
    pub actor_azp: Option<String>,
    /// Namespaced verb, e.g. "quote.issued", "email.sent".
    pub action_type: String,
    pub entities: Vec<String>,
    pub summary: String,
    pub payload: serde_json::Value,
    pub outcome: ActionOutcome,
    pub occurred_at: DateTime<Utc>,
    pub visibility: Vec<PrincipalToken>,
    pub confidentiality: Confidentiality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub id: Uuid,
    pub action_id: String,
    pub actor_sub: Option<String>,
    pub actor_azp: Option<String>,
    pub action_type: String,
    pub entities: Vec<String>,
    pub summary: String,
    pub payload: serde_json::Value,
    pub outcome: ActionOutcome,
    pub occurred_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub provenance: EpisodeId,
}

/// Timeline query: "what has been done on this entity, by whom?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityQuery {
    pub scope: Scope,
    pub entity: String,
    pub since: Option<DateTime<Utc>>,
    /// Exact types ("quote.issued") or prefix patterns ("email.*").
    pub action_types: Vec<String>,
    /// Filter by agent identity (actor_azp).
    pub actors: Vec<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeStatus {
    /// Passed the de-identification gate; awaiting review + support checks.
    Candidate,
    /// Failed the gate — held for audit, never retrievable outside audit scopes.
    Quarantined,
    /// Crossed k-support with auto-publish OFF (the default): reviewed-ready,
    /// waiting on a human/policy publish. Between `Candidate` and `Published`,
    /// and NEVER retrievable — publishing is the only thing that mints the §7g
    /// carve-out chunk (knowledge-merge-tuning.md §5: "publishing is never
    /// automatic").
    Eligible,
    /// Broad-visibility semantic memory; retrievable via the §7g carve-out.
    Published,
    /// A reviewer refused it. Remembered so the same canonical_statement does
    /// not resurrect as a fresh candidate (§5: "rejection is remembered").
    Rejected,
    Invalidated,
}

impl KnowledgeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Quarantined => "quarantined",
            Self::Eligible => "eligible",
            Self::Published => "published",
            Self::Rejected => "rejected",
            Self::Invalidated => "invalidated",
        }
    }
}

/// Bucketed support disclosure (knowledge-merge-tuning.md §5, SPEC §2). A
/// consuming agent sees a COARSE tier so it can weight published knowledge,
/// never a false-precision exact count — exact `distinct_entities` stays
/// admin-only, to blunt membership inference. Derived deterministically from
/// the distinct-entity support; `< 3` never publishes (the k-support floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportTier {
    /// 3-4 distinct entities.
    Emerging,
    /// 5-9 distinct entities.
    Established,
    /// 10+ distinct entities.
    Extensive,
}

impl SupportTier {
    /// Bucket a distinct-entity support count. `None` below the k=3 floor —
    /// nothing that thin is ever published, so it has no tier to disclose.
    pub fn from_distinct(distinct: i32) -> Option<Self> {
        match distinct {
            d if d >= 10 => Some(Self::Extensive),
            d if d >= 5 => Some(Self::Established),
            d if d >= 3 => Some(Self::Emerging),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Emerging => "emerging",
            Self::Established => "established",
            Self::Extensive => "extensive",
        }
    }
}

/// An agent- or worker-proposed generalization (SPEC v1.3 §2). A proposal,
/// never a publish: it enters the gate + review pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeProposal {
    pub tenant_id: TenantId,
    pub statement: String,
    pub categories: Vec<String>,
    /// Supporting L0 episodes; entity/writer/trust attribution is read from
    /// the episodes themselves, never caller-supplied.
    pub evidence: Vec<EpisodeId>,
    pub proposed_by_sub: Option<String>,
    pub proposed_by_azp: Option<String>,
    /// Normalized canonical form of `statement`, when the caller/extractor has
    /// one. Stored for the exact-match merge fast path AND checked against the
    /// rejection memory (§5): a canonical form a reviewer already rejected must
    /// not resurrect as a fresh candidate. `None` = no canonical form supplied;
    /// the rejection memory then falls back to exact-statement matching.
    #[serde(default)]
    pub canonical_statement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeItem {
    pub id: Uuid,
    pub statement: String,
    pub categories: Vec<String>,
    pub status: KnowledgeStatus,
    pub quarantine_reason: Option<String>,
    /// Exact distinct-entity support. ADMIN-ONLY: this struct is returned by the
    /// admin/review surfaces (bearer-gated); the read path never exposes it —
    /// agents see `support_tier` buckets instead (SPEC §2 membership-inference).
    pub distinct_entities: i32,
    /// Bucketed disclosure of `distinct_entities` (§5). `None` below the k=3
    /// floor. Mirrors what a consuming agent would see on a recall hit.
    pub support_tier: Option<SupportTier>,
    pub episode_count: i32,
    pub writer_count: i32,
    pub has_tier1_evidence: bool,
    /// The judge's recorded rationale for the last judged merge, when any
    /// (§5: "no merge is authoritative without the judge's recorded reason").
    pub merge_reason: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_reinforced: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

/// What `memory.forget` targets (roadmap task 5). Chunk = one retrieval unit;
/// Episode = the L0 event and everything derived from it (chunks, facts, and
/// the knowledge-support cascade). Forget is invalidate-don't-delete: rows get
/// `valid_to`, never removal — hard purge stays with the §8 crypto-shredding
/// pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum ForgetRef {
    Chunk(ChunkId),
    Episode(EpisodeId),
}

/// A materialized L3 brief row (SPEC §2 L3). The `body` is the recomputed
/// summary produced under a broad MATERIALIZATION scope — it is metadata and a
/// cached summary, NEVER the served item set. Serving always re-derives the
/// actual `recent_memory`/`recent_activity` under the caller's scope, so no
/// materialized item can leak (main.rs::brief). `source_visibility` is the
/// INTERSECTION of contributing chunk/action visibilities (derived-scope
/// inheritance, fail-closed): the brief-level summary is visible only to
/// principals present in ALL its sources; an empty intersection = nobody.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializedBrief {
    pub entity: String,
    pub body: serde_json::Value,
    pub source_visibility: Vec<PrincipalToken>,
    pub is_stale: bool,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub source_version: i64,
}

/// Which dense vector column `recall` searches (SPEC §5c query-routing
/// cutover). `V1` = the original `embedding` column (default); `V2` = the
/// migration's `embedding_v2` named vector, selected once a cutover flips the
/// per-tenant/global `embedding_route` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingRoute {
    V1,
    V2,
}

impl EmbeddingRoute {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
    pub fn from_str_lossy(s: &str) -> Self {
        if s == "v2" {
            Self::V2
        } else {
            Self::V1
        }
    }
}

/// Backfill coverage for an embedding-model migration (SPEC §5c): the cutover
/// gate refuses to flip below 100% unless forced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EmbeddingCoverage {
    pub total: i64,
    pub covered: i64,
}

impl EmbeddingCoverage {
    pub fn is_complete(&self) -> bool {
        self.total == 0 || self.covered >= self.total
    }
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.covered as f64 / self.total as f64
        }
    }
}

/// One source's losing value for a field in the merged view (SPEC §7f:
/// "conflict made visible beats conflict resolved wrong"). Every field that
/// had a current value in more than one source carries its alternatives so the
/// provenance of the picked value — and what it beat — is inspectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedAlternative {
    pub source: String,
    pub value: serde_json::Value,
    pub entity_id: String,
    pub valid_from: DateTime<Utc>,
    pub provenance: EpisodeId,
}

/// The resolved value for one field of a merged entity (SPEC §7f). The value is
/// the highest-precedence source's current fact; `superseded_alternatives`
/// carries every other source's current value for the same field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedField {
    pub value: serde_json::Value,
    /// The source whose fact won under the precedence rule.
    pub winning_source: String,
    /// The source-native entity_id the winning fact came from.
    pub winning_entity_id: String,
    pub valid_from: DateTime<Utc>,
    pub provenance: EpisodeId,
    /// The (source, value) pairs that lost — order-preserving, precedence-ranked.
    pub superseded_alternatives: Vec<MergedAlternative>,
}

/// The cross-source merged entity view (SPEC §7f). A deterministic, view-time
/// projection over the current facts of every (source, entity_id) aliased to
/// `canonical`; L1 rows are never merged or mutated. `members` is the resolved
/// alias set (a single self-member when the entity is unmapped). `fields` is
/// keyed by field name, each resolved to its precedence-winning source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedRecord {
    pub tenant_id: TenantId,
    pub canonical_entity: String,
    /// The (source, entity_id) pairs that contributed, in stable order.
    pub members: Vec<AliasMember>,
    /// Resolved fields, keyed by field name.
    pub fields: std::collections::BTreeMap<String, MergedField>,
}

/// One (source, entity_id) member of a canonical entity (SPEC §7f resolution).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasMember {
    pub source: String,
    pub entity_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(String),
    #[error("unknown tenant {0}")]
    UnknownTenant(TenantId),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;
