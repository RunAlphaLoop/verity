use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pgvector::Vector;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;

/// One source entity's current L1 facts, grouped for the Tier-1 producers
/// (§4.2 S1): `((source, entity_id), [(field, value), …])`. Returned by
/// [`PostgresAdapter::list_current_facts_grouped`].
pub type GroupedFacts = ((String, String), Vec<(String, serde_json::Value)>);

/// One prioritized review-queue candidate: the full [`EvidenceRow`] plus the
/// priority signals [`PostgresAdapter::review_queue`] computes for ordering
/// (design §8 Later — review-queue prioritization + SLA). Ordering-only
/// enrichment; the ledger row itself is unchanged. `wait_age_secs` is the
/// SLA read-out (now() − valid_from), surfaced per row so an operator can watch
/// the oldest-waiting candidate; `priority` is the score the query ORDERs by.
#[derive(Debug, Clone)]
pub struct ReviewQueueItem {
    /// The underlying ledger row (unchanged — this is display ordering only).
    pub evidence: EvidenceRow,
    /// The combined priority score (see the `review_queue` doc comment). Higher
    /// = surfaced sooner. Unbounded because of the linear aging term.
    pub priority: f64,
    /// Seconds this candidate has waited (now() − valid_from) — the SLA read-out.
    pub wait_age_secs: f64,
    /// FREQUENCY signal: live evidence rows recurring on this unordered ref-pair.
    pub frequency: i64,
    /// ENTITY VALUE signal: distinct alias members in the two refs' clusters.
    pub entity_value: i64,
}

/// One observed entity tag in the picker directory
/// (docs/design/ENTITY-PICKER.md §4): a DISTINCT member of
/// `chunks.entity_tags ∪ actions.entities` — exactly the vocabulary the scope
/// filter enforces on — with honest per-source counts and the display-only
/// merged badge. Serialized verbatim by `GET /v1/admin/entity-tags`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EntityTagRow {
    pub tag: String,
    /// LIVE chunk rows (`valid_to IS NULL`) carrying the tag: the same rows
    /// `entity_scope_predicate` can return.
    pub chunk_count: i64,
    /// Action rows carrying the tag (the activity containment filter's rows).
    pub action_count: i64,
    /// ALL chunk rows including invalidated ones; populated only when
    /// `live_only = false` (erasure targets physical rows —
    /// invalidate-don't-delete means superseded rows persist until the §8
    /// hard-purge pipeline runs).
    pub total_chunk_count: Option<i64>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Display hint only (drives the `merged` badge): the canonical this
    /// source-native tag resolves to, when an `entity_aliases` row exists.
    /// Null for unmerged tags — the common case.
    pub canonical_entity: Option<String>,
    /// `entity_link_meta` confidence for the alias link, when materialized.
    pub link_confidence: Option<String>,
}

/// The picker directory response ([`PostgresAdapter::list_entity_tags`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EntityTagDirectory {
    /// Distinct tags for the tenant under `live_only`, IGNORING `q` and
    /// `limit` — the Emptiness Law keys off this; a filtered page must not
    /// fake emptiness.
    pub total_distinct: i64,
    /// True when more tags matched `q` than `limit` returned.
    pub truncated: bool,
    /// Observed namespace prefixes (`account`, `deal`, …) across the whole
    /// directory (ignoring `q`/`limit`), sorted — derived from data, never a
    /// hardcoded list, so the console teaches the tenant's actual vocabulary.
    pub namespaces: Vec<String>,
    pub tags: Vec<EntityTagRow>,
}

/// One tenant-only-filtered candidate for the ADMIN debug-recall "why-out"
/// trace ([`PostgresAdapter::debug_recall_candidates`]). Carries the RAW
/// enforcement inputs (visibility tokens, confidentiality class, entity tags,
/// `valid_to`) so the admin plane can evaluate every mandatory pre-filter
/// per-candidate and name the drop reason. Never crosses the read path.
#[derive(Debug, Clone)]
pub struct DebugCandidate {
    pub chunk_id: Uuid,
    pub document_id: String,
    pub seq: i32,
    pub content: String,
    pub score: f32,
    /// Materialized principal tokens; empty = invisible (fail closed).
    pub visibility: Vec<PrincipalToken>,
    pub entity_tags: Vec<String>,
    pub kind: String,
    /// Raw class (0 public … 3 restricted) — kept numeric so the trace can
    /// compare against the scope ceiling without lossy round-trips.
    pub confidentiality: i16,
    pub acl_provenance: String,
    pub trust_tier: i16,
    pub valid_from: DateTime<Utc>,
    /// Some = superseded/invalidated — recall never surfaces it (staleness drop).
    pub valid_to: Option<DateTime<Utc>>,
    pub provenance: Uuid,
}

// ---------- Permission Graph (admin/operator plane) result types ----------

/// One `GROUP BY` bucket of the corpus aggregate. Exactly one of `key`
/// (source / provenance) or `level` (confidentiality 0..3) is meaningful.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AccessGroupCount {
    pub key: String,
    pub level: Option<i32>,
    pub chunks: i64,
    pub docs: i64,
}

/// The Endpoint-1 corpus aggregate: total + three `GROUP BY` breakdowns over
/// the enforcement pre-filter (visibility-authorized set). Counts only (NG2).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AccessCorpus {
    pub total_chunks: i64,
    pub total_docs: i64,
    pub by_source: Vec<AccessGroupCount>,
    pub by_confidentiality: Vec<AccessGroupCount>,
    pub by_provenance: Vec<AccessGroupCount>,
}

/// One live chunk row of the Endpoint-1 documents page. Metadata only — no
/// `content` is ever projected (NG2).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccessChunkRow {
    pub id: Uuid,
    pub document_id: String,
    pub source: String,
    pub confidentiality: i32,
    pub valid_from: DateTime<Utc>,
}

/// Which object Endpoint 2 decodes. `Document` is cheap; `Source`/`Entity` are
/// unbounded aggregate scans, bounded by statement_timeout + a corpus ceiling.
#[derive(Debug, Clone, Copy)]
pub enum ObjectSelector<'a> {
    Document(&'a str),
    Source(&'a str),
    Entity(&'a str),
}

/// The Endpoint-2 object decode: distinct visibility tokens + object metadata.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AccessObjectDecode {
    pub tokens: Vec<PrincipalToken>,
    pub min_confidentiality: Option<i32>,
    pub provenance: Vec<String>,
    /// The statement-timeout fired mid-decode: results are partial.
    pub approximate: bool,
    /// `source`/`entity` mode refused because the corpus exceeds the ceiling.
    pub refused_over_ceiling: bool,
}

/// Postgres reports a `SET LOCAL statement_timeout` cancellation as SQLSTATE
/// `57014` (query_canceled). Detect it so the admin plane degrades to an
/// `approximate` result instead of surfacing a hard 500.
fn is_timeout(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("57014")
    )
}

/// One quarantined webhook payload with its lifecycle disposition (0023):
/// `resolution` None = open, `"reingested"` (re-admitted ONLY through an
/// admin-supplied corrected ACL mapping) or `"dismissed"` (acknowledged, never
/// indexed). There is deliberately no permissive third state.
#[derive(Debug, Clone)]
pub struct QuarantineRow {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub payload: serde_json::Value,
    pub reason: String,
    pub at: DateTime<Utc>,
    pub resolution: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_note: Option<String>,
}

/// One row of the console's Memories browser (`GET /v1/admin/memories`): a
/// chunk, fact, or action projected into a common shape, tagged with its
/// `kind` and stable `id`. Content is a PREVIEW (≤240 chars) on list reads;
/// only the single-row `id` lookup returns the full text. Visibility is
/// surfaced as a COUNT of principal tokens, never the tokens themselves.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryBrowseRow {
    /// "chunk" | "fact" | "action".
    pub kind: String,
    pub id: Uuid,
    /// Chunk/fact source column; actions always report "agent" (the source
    /// their L0 provenance episode is stamped with in `record_action`).
    pub source: String,
    /// Content (chunk) / JSON value (fact) / summary (action), ≤240 chars on
    /// list reads; full on an `id` lookup.
    pub preview: String,
    /// True when `preview` was cut at 240 chars (list reads only).
    pub preview_truncated: bool,
    /// Chunk `entity_tags` / action `entities`; a fact carries its synthetic
    /// source-native tag `source:entity_id` so the one containment filter
    /// covers all three kinds.
    pub entities: Vec<String>,
    /// COUNT of materialized visibility tokens (chunks/actions). None for
    /// facts — L1 rows carry no per-row tokens; `get` is tenant-gated.
    pub visible_to: Option<i32>,
    /// 0 public … 3 restricted; None for facts (no per-row class).
    pub confidentiality: Option<i32>,
    pub acl_provenance: Option<String>,
    /// 1 authoritative / 2 observation; chunks only.
    pub trust_tier: Option<i32>,
    /// Event time: chunk/fact `valid_from`, action `occurred_at`.
    pub valid_from: DateTime<Utc>,
    /// Some = replaced/invalidated (never deleted); actions never supersede.
    pub valid_to: Option<DateTime<Utc>>,
    /// Fact supersession chain link (the row that replaced this one).
    pub superseded_by: Option<Uuid>,
    /// The L0 provenance episode — every row's citation.
    pub provenance: Uuid,
    /// Fact key parts (facts only).
    pub entity_id: Option<String>,
    pub field: Option<String>,
    /// Chunk version key parts (chunks only) — lets the console reconstruct a
    /// chunk's supersession chain client-side.
    pub document_id: Option<String>,
    pub seq: Option<i32>,
    /// Action verb + outcome (actions only).
    pub action_type: Option<String>,
    pub outcome: Option<String>,
    /// Ingestion time — the browse ordering / keyset-pagination key.
    pub recorded_at: DateTime<Utc>,
}

/// Per-source row count for the browser's source dropdown. Computed from the
/// SAME filtered union as the browse rows (all filters applied EXCEPT the
/// source filter itself and pagination), so the dropdown never advertises a
/// source the current filters can't reach.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemorySourceCount {
    pub source: String,
    pub count: i64,
}

/// One page of the Memories browser ([`PostgresAdapter::browse_memories`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryBrowsePage {
    /// Newest first by `recorded_at` (ties broken by id, descending).
    pub rows: Vec<MemoryBrowseRow>,
    pub sources: Vec<MemorySourceCount>,
    /// Keyset cursor: pass back as `before` to fetch the next-older page.
    /// None = this page reached the end.
    pub next_before: Option<DateTime<Utc>>,
    /// Tie-breaker half of the cursor (rows written in one transaction share
    /// `recorded_at`): pass back as `before_id` with `next_before` so a page
    /// boundary inside a same-instant batch never skips rows.
    pub next_before_id: Option<Uuid>,
}

/// Filters for [`PostgresAdapter::browse_memories`]. All optional; absent =
/// unfiltered (within the tenant — the tenant partition is never optional).
#[derive(Debug, Clone, Default)]
pub struct MemoryBrowseFilter {
    pub source: Option<String>,
    /// Entity-tag containment: chunk `entity_tags` / action `entities` /
    /// a fact's synthetic `source:entity_id` tag.
    pub entity: Option<String>,
    /// "chunk" | "fact" | "action"; anything else is refused (InvalidInput).
    pub kind: Option<String>,
    /// Case-insensitive substring over content / value / summary.
    pub q: Option<String>,
    /// false (default) = live rows only (`valid_to IS NULL`); true also shows
    /// replaced rows — bi-temporal history, never deleted.
    pub include_superseded: bool,
    /// Clamped to 1..=200.
    pub limit: i64,
    /// Keyset pagination: only rows with `recorded_at` strictly before this
    /// (or, when `before_id` is also given, `(recorded_at, id)` row-wise
    /// strictly before `(before, before_id)` — the tie-safe form).
    pub before: Option<DateTime<Utc>>,
    /// Tie-breaker half of the cursor; meaningful only with `before`.
    pub before_id: Option<Uuid>,
    /// Single-row detail lookup (the console drawer): full untruncated
    /// content/value, superseded rows included, per-source counts skipped.
    pub id: Option<Uuid>,
}

pub struct PostgresAdapter {
    pool: PgPool,
    /// Deployment KEK (SPEC §8a, crypto.rs). None = envelope encryption
    /// disabled: L0 payloads stay plaintext, DEKs are stored unwrapped.
    kek: Option<crate::crypto::Kek>,
    /// Unwrapped per-tenant DEKs, cached after first use (bounded; the DEK is
    /// 32 bytes and provisioning is one row per tenant, ever).
    deks: moka::sync::Cache<TenantId, [u8; crate::crypto::DEK_BYTES]>,
    /// Per-tenant embedding-route decisions, cached so the dense read path
    /// (`recall_dense`) does not re-`SELECT` the `settings` row on every call.
    /// The route changes only on a rare cutover event (`set_embedding_route`),
    /// which flushes this cache; a warm dense recall spends ~0.2ms on this
    /// lookup otherwise (docs/BENCHMARKS.md 2026-07-12). A cache MISS resolves
    /// the tenant vs global (NULL-tenant) default from `settings` exactly as
    /// before, so the fail-safe default (`V1`) is unchanged.
    routes: moka::sync::Cache<TenantId, EmbeddingRoute>,
    /// M0 instrumentation seam: incremented each time `recall_dense` takes the
    /// ≤`EXACT_SCAN_MAX_ROWS` exact-scan branch, so `/metrics` can expose
    /// `exact_scan_fallback_total` without the storage crate depending on the
    /// server. `None` unless the server wires a shared counter at construction
    /// (`set_exact_scan_counter`); the increment is a `Relaxed` atomic add on a
    /// cloned `Arc`, no lock, read-path-safe.
    exact_scan_fallback: Option<Arc<AtomicU64>>,
}

impl PostgresAdapter {
    /// Connect with the KEK from env `VERITY_KEK` (warned when absent).
    pub async fn connect(dsn: &str) -> Result<Self> {
        let kek = crate::crypto::Kek::from_env()?;
        Self::connect_with_kek(dsn, kek).await
    }

    /// Explicit-KEK constructor: the test seam (no env mutation) and the
    /// future config-file/KMS profiles.
    pub async fn connect_with_kek(dsn: &str, kek: Option<crate::crypto::Kek>) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(dsn)
            .await
            .map_err(db_err)?;
        Ok(Self {
            pool,
            kek,
            deks: moka::sync::Cache::new(10_000),
            routes: moka::sync::Cache::new(10_000),
            exact_scan_fallback: None,
        })
    }

    /// Wire the shared `exact_scan_fallback_total` counter (M0 `/metrics`). The
    /// server calls this once at construction with the counter it also renders
    /// at scrape time; keeps the storage crate free of any server dependency.
    pub fn set_exact_scan_counter(&mut self, counter: Arc<AtomicU64>) {
        self.exact_scan_fallback = Some(counter);
    }

    /// The tenant's data-encryption key, provisioning it lazily on first use
    /// (SPEC §8a). Stored KEK-wrapped when a KEK is configured, plaintext
    /// otherwise; a concurrent first-writer race is settled by the primary
    /// key — the loser re-reads the winner's DEK.
    async fn tenant_dek(&self, tenant: TenantId) -> Result<[u8; crate::crypto::DEK_BYTES]> {
        if let Some(dek) = self.deks.get(&tenant) {
            return Ok(dek);
        }
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT dek FROM tenant_deks WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        let dek = match stored {
            Some(bytes) => crate::crypto::unwrap_dek(self.kek.as_ref(), &bytes)?,
            None => {
                let dek = crate::crypto::generate_dek();
                let to_store = match &self.kek {
                    Some(kek) => crate::crypto::wrap_dek(kek, &dek)?,
                    None => dek.to_vec(),
                };
                let inserted = sqlx::query(
                    "INSERT INTO tenant_deks (tenant_id, dek) VALUES ($1, $2)
                     ON CONFLICT (tenant_id) DO NOTHING",
                )
                .bind(tenant)
                .bind(&to_store)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
                if inserted.rows_affected() == 0 {
                    // Lost the provisioning race: adopt the winner's DEK.
                    let bytes: Vec<u8> =
                        sqlx::query_scalar("SELECT dek FROM tenant_deks WHERE tenant_id = $1")
                            .bind(tenant)
                            .fetch_one(&self.pool)
                            .await
                            .map_err(db_err)?;
                    crate::crypto::unwrap_dek(self.kek.as_ref(), &bytes)?
                } else {
                    dek
                }
            }
        };
        self.deks.insert(tenant, dek);
        Ok(dek)
    }

    /// Decrypt-on-demand read of one L0 payload (SPEC §8a; used by DSAR
    /// export and admin forensics — never by the serving read path). Returns
    /// the plaintext payload whether or not the row is encrypted; None for an
    /// unknown episode.
    pub async fn episode_payload(
        &self,
        tenant: TenantId,
        id: EpisodeId,
    ) -> Result<Option<serde_json::Value>> {
        let row = sqlx::query(
            "SELECT payload, payload_enc FROM episodes WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let Some(row) = row else { return Ok(None) };
        let payload: serde_json::Value = row.try_get("payload").map_err(db_err)?;
        let payload_enc: Option<Vec<u8>> = row.try_get("payload_enc").map_err(db_err)?;
        self.decrypt_payload(tenant, payload, payload_enc)
            .await
            .map(Some)
    }

    /// Shared decrypt helper: `payload_enc` present → decrypt under the
    /// tenant DEK (requires the KEK for wrapped DEKs, fail closed); absent →
    /// the plaintext `payload` column is authoritative.
    pub(crate) async fn decrypt_payload(
        &self,
        tenant: TenantId,
        payload: serde_json::Value,
        payload_enc: Option<Vec<u8>>,
    ) -> Result<serde_json::Value> {
        match payload_enc {
            None => Ok(payload),
            Some(blob) => {
                let dek = self.tenant_dek(tenant).await?;
                let plain = crate::crypto::decrypt(&dek, &blob)?;
                serde_json::from_slice(&plain).map_err(db_err)
            }
        }
    }

    // ---- Connector credential intake (SPEC §5e, Phase-2 secret intake) ----
    //
    // All crypto is in-crate: these methods call the pub(crate) crypto helpers
    // and `self.tenant_dek`, and hand callers only a fingerprint or a
    // decrypted-on-demand value. The trait forwards to them (below).

    /// The tenant DEK for a WRITE that must be genuinely protected: unlike
    /// `tenant_dek` (which tolerates a plaintext-provenance DEK for the L0
    /// dev path), this HARD-REFUSES unless a KEK is configured AND the stored
    /// DEK is actually KEK-wrapped (raw length > 32). A DEK minted plaintext
    /// before a KEK was set stays plaintext even after `VERITY_KEK` is added
    /// (unwrap_dek keys off length), so a secret written against it would sit
    /// unprotected — refuse. Provisions the DEK first (via `tenant_dek`) so a
    /// brand-new tenant with a KEK set gets a properly wrapped DEK, then
    /// re-reads the raw row to check provenance.
    async fn tenant_dek_for_secret(
        &self,
        tenant: TenantId,
    ) -> Result<[u8; crate::crypto::DEK_BYTES]> {
        if self.kek.is_none() {
            return Err(StorageError::InvalidInput(
                "refusing to store a connector secret: VERITY_KEK is not set \
                 (encrypt-at-rest is mandatory for tier-C bearer tokens)"
                    .into(),
            ));
        }
        // Ensure the DEK exists and is unwrappable (also fails closed on a
        // wrapped-DEK/no-KEK mismatch, though we already required a KEK).
        let dek = self.tenant_dek(tenant).await?;
        // Provenance check on the RAW stored bytes: length <= 32 = plaintext.
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT dek FROM tenant_deks WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;
        if stored.len() <= crate::crypto::DEK_BYTES {
            return Err(StorageError::InvalidInput(
                "refusing to store a connector secret: the tenant DEK is \
                 plaintext-provenance (minted before VERITY_KEK was set) — \
                 rotate the tenant DEK under the KEK before storing secrets"
                    .into(),
            ));
        }
        Ok(dek)
    }

    /// Store a tier-C bearer token encrypted-at-rest; returns its fingerprint.
    /// See [`StorageAdapter::store_connector_bearer`].
    pub async fn store_connector_bearer_impl(
        &self,
        tenant: TenantId,
        source: &str,
        plaintext: &[u8],
        visibility: &[i32],
    ) -> Result<String> {
        let dek = self.tenant_dek_for_secret(tenant).await?;
        let ciphertext = crate::crypto::encrypt(&dek, plaintext)?;
        // The visibility set is a non-secret side-field (like `subject` on a
        // path row): persisted alongside the ciphertext but NEVER fed into the
        // fingerprint (which covers the secret bytes only).
        let fingerprint = crate::crypto::credential_fingerprint(plaintext);
        sqlx::query(
            "INSERT INTO connector_credentials
                 (tenant_id, source, kind, ciphertext, path, visibility, fingerprint, updated_at)
             VALUES ($1, $2, 'bearer', $3, NULL, $4, $5, now())
             ON CONFLICT (tenant_id, source) DO UPDATE
                 SET kind = 'bearer', ciphertext = EXCLUDED.ciphertext,
                     path = NULL, visibility = EXCLUDED.visibility,
                     fingerprint = EXCLUDED.fingerprint,
                     updated_at = now()",
        )
        .bind(tenant)
        .bind(source)
        .bind(&ciphertext)
        .bind(visibility)
        .bind(&fingerprint)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(fingerprint)
    }

    /// Store a Google SA-key file PATH (no crypto); returns its fingerprint.
    /// See [`StorageAdapter::store_connector_path`].
    pub async fn store_connector_path_impl(
        &self,
        tenant: TenantId,
        source: &str,
        path: &str,
        subject: Option<&str>,
    ) -> Result<String> {
        let fingerprint = crate::crypto::credential_fingerprint(path.as_bytes());
        sqlx::query(
            "INSERT INTO connector_credentials
                 (tenant_id, source, kind, ciphertext, path, subject, fingerprint, updated_at)
             VALUES ($1, $2, 'path', NULL, $3, $4, $5, now())
             ON CONFLICT (tenant_id, source) DO UPDATE
                 SET kind = 'path', ciphertext = NULL,
                     path = EXCLUDED.path, subject = EXCLUDED.subject,
                     fingerprint = EXCLUDED.fingerprint,
                     updated_at = now()",
        )
        .bind(tenant)
        .bind(source)
        .bind(path)
        .bind(subject)
        .bind(&fingerprint)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(fingerprint)
    }

    /// Non-secret status of a stored credential.
    /// See [`StorageAdapter::get_connector_credential_status`].
    pub async fn get_connector_credential_status_impl(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<ConnectorCredentialStatus>> {
        let row = sqlx::query(
            "SELECT kind, fingerprint, subject, visibility, updated_at FROM connector_credentials
             WHERE tenant_id = $1 AND source = $2",
        )
        .bind(tenant)
        .bind(source)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let Some(row) = row else { return Ok(None) };
        let kind_str: String = row.try_get("kind").map_err(db_err)?;
        let kind = match kind_str.as_str() {
            "bearer" => ConnectorCredentialKind::Bearer,
            "path" => ConnectorCredentialKind::Path,
            other => {
                return Err(StorageError::Database(format!(
                    "connector_credentials.kind has an unknown value {other:?}"
                )))
            }
        };
        Ok(Some(ConnectorCredentialStatus {
            kind,
            fingerprint: row.try_get("fingerprint").map_err(db_err)?,
            subject: row.try_get("subject").map_err(db_err)?,
            visibility: row.try_get("visibility").map_err(db_err)?,
            updated_at: row.try_get("updated_at").map_err(db_err)?,
        }))
    }

    /// Read back a stored Google `path` credential (path plaintext + subject) for
    /// a Phase-3 backfill spawn. See [`StorageAdapter::materialize_connector_path`].
    pub async fn materialize_connector_path_impl(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<ConnectorPathCredential>> {
        let row = sqlx::query(
            "SELECT kind, path, subject FROM connector_credentials
             WHERE tenant_id = $1 AND source = $2",
        )
        .bind(tenant)
        .bind(source)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let Some(row) = row else { return Ok(None) };
        let kind: String = row.try_get("kind").map_err(db_err)?;
        if kind != "path" {
            return Err(StorageError::InvalidInput(format!(
                "connector credential for source {source:?} is a {kind} credential, \
                 not a path — no SA-key path to materialize"
            )));
        }
        Ok(Some(ConnectorPathCredential {
            path: row.try_get("path").map_err(db_err)?,
            subject: row.try_get("subject").map_err(db_err)?,
        }))
    }

    /// Decrypt-on-demand read of a stored bearer secret.
    /// See [`StorageAdapter::materialize_connector_bearer`].
    pub async fn materialize_connector_bearer_impl(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query(
            "SELECT kind, ciphertext FROM connector_credentials
             WHERE tenant_id = $1 AND source = $2",
        )
        .bind(tenant)
        .bind(source)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let Some(row) = row else { return Ok(None) };
        let kind: String = row.try_get("kind").map_err(db_err)?;
        if kind != "bearer" {
            return Err(StorageError::InvalidInput(format!(
                "connector credential for source {source:?} is a {kind} credential, \
                 not a bearer — nothing to materialize"
            )));
        }
        let ciphertext: Vec<u8> = row.try_get("ciphertext").map_err(db_err)?;
        // Decrypt-on-demand under the tenant DEK. This inherits the KEK-unset
        // hard-refuse for free: tenant_dek → unwrap_dek fails closed when a
        // wrapped-provenance DEK meets a missing KEK.
        let dek = self.tenant_dek(tenant).await?;
        let plain = crate::crypto::decrypt(&dek, &ciphertext)?;
        Ok(Some(plain))
    }

    /// Revoke (delete) a stored credential row.
    /// See [`StorageAdapter::revoke_connector_credential`].
    pub async fn revoke_connector_credential_impl(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<bool> {
        let done =
            sqlx::query("DELETE FROM connector_credentials WHERE tenant_id = $1 AND source = $2")
                .bind(tenant)
                .bind(source)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(done.rows_affected() > 0)
    }

    /// Upsert a continuous-sync schedule.
    /// See [`StorageAdapter::upsert_sync_schedule`].
    pub async fn upsert_sync_schedule_impl(
        &self,
        tenant: TenantId,
        source: &str,
        interval_secs: i32,
        enabled: bool,
    ) -> Result<SyncSchedule> {
        // Enforce the interval floor here (not only via the DB CHECK) so a
        // sub-floor value returns a clean InvalidInput → 422 instead of a raw
        // constraint-violation Database error. The DB CHECK is the belt; this is
        // the braces — either way a sub-floor interval is never armed.
        if interval_secs < SYNC_INTERVAL_FLOOR_SECS {
            return Err(StorageError::InvalidInput(format!(
                "continuous-sync interval {interval_secs}s is below the \
                 {SYNC_INTERVAL_FLOOR_SECS}s floor — refusing to arm a schedule that would \
                 hammer the source API"
            )));
        }
        let row = sqlx::query(
            "INSERT INTO sync_schedules
                 (tenant_id, source, interval_secs, enabled, updated_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (tenant_id, source) DO UPDATE
                 SET interval_secs = EXCLUDED.interval_secs,
                     enabled = EXCLUDED.enabled,
                     updated_at = now()
             RETURNING tenant_id, source, interval_secs, enabled, last_run_at,
                       created_at, updated_at",
        )
        .bind(tenant)
        .bind(source)
        .bind(interval_secs)
        .bind(enabled)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        sync_schedule_from_row(&row)
    }

    /// Read the schedule for (tenant, source).
    /// See [`StorageAdapter::get_sync_schedule`].
    pub async fn get_sync_schedule_impl(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<SyncSchedule>> {
        let row = sqlx::query(
            "SELECT tenant_id, source, interval_secs, enabled, last_run_at,
                    created_at, updated_at
             FROM sync_schedules
             WHERE tenant_id = $1 AND source = $2",
        )
        .bind(tenant)
        .bind(source)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        match row {
            Some(row) => Ok(Some(sync_schedule_from_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Every enabled schedule across tenants — the boot re-arm read.
    /// See [`StorageAdapter::list_enabled_sync_schedules`].
    pub async fn list_enabled_sync_schedules_impl(&self) -> Result<Vec<SyncSchedule>> {
        let rows = sqlx::query(
            "SELECT tenant_id, source, interval_secs, enabled, last_run_at,
                    created_at, updated_at
             FROM sync_schedules
             WHERE enabled
             ORDER BY tenant_id, source",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(sync_schedule_from_row).collect()
    }

    /// Stamp `last_run_at = now()` after a poll cycle.
    /// See [`StorageAdapter::touch_sync_schedule_last_run`].
    pub async fn touch_sync_schedule_last_run_impl(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE sync_schedules SET last_run_at = now(), updated_at = now()
             WHERE tenant_id = $1 AND source = $2",
        )
        .bind(tenant)
        .bind(source)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(done.rows_affected() > 0)
    }

    /// Run pending migrations and return how many were applied, so boot can
    /// print `applied N migrations` (FTUE §2.3 — a bare `./verity` on a fresh
    /// database must say what it did). The count-before read is best-effort:
    /// on a virgin database the `_sqlx_migrations` ledger doesn't exist yet
    /// (sqlx creates it during `run`), which reads as 0.
    pub async fn migrate(&self) -> Result<u64> {
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(after.saturating_sub(before) as u64)
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Cheap PK existence check for a tenant. Admin write handlers call this
    /// before any tenant-scoped mutation so a nonexistent tenant surfaces as a
    /// clean `UnknownTenant` (→ 404) instead of a raw foreign-key violation
    /// bubbling up as `Database` (→ 500).
    pub async fn ensure_tenant(&self, tenant: TenantId) -> Result<()> {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)")
            .bind(tenant)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        if exists {
            Ok(())
        } else {
            Err(StorageError::UnknownTenant(tenant))
        }
    }

    pub async fn get_knowledge(&self, tenant: TenantId, id: Uuid) -> Result<KnowledgeItem> {
        let row = sqlx::query("SELECT * FROM knowledge WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        row_to_knowledge(&row)
    }

    /// Public fetch of one knowledge item (admin/review plane).
    pub async fn knowledge_item(
        &self,
        tenant: TenantId,
        id: Uuid,
    ) -> Result<Option<KnowledgeItem>> {
        let row = sqlx::query("SELECT * FROM knowledge WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.as_ref().map(row_to_knowledge).transpose()
    }

    /// Is per-tenant auto-publish opted IN? (knowledge-merge-tuning.md §5, the
    /// load-bearing promise.) Reads the `knowledge_auto_publish` setting,
    /// per-tenant row winning over the global (NULL-tenant) default. ABSENT =
    /// OFF — the OSS-conservative default: candidates that cross k-support
    /// become `eligible` and WAIT for a human/policy publish call, they never
    /// auto-publish. Only 'true' (case-insensitive) enables it.
    pub async fn knowledge_auto_publish(&self, tenant: TenantId) -> Result<bool> {
        let value: Option<String> = sqlx::query_scalar(
            "SELECT value FROM settings
             WHERE key = 'knowledge_auto_publish'
               AND (tenant_id = $1 OR tenant_id IS NULL)
             ORDER BY tenant_id NULLS LAST
             LIMIT 1",
        )
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(value.is_some_and(|v| v.trim().eq_ignore_ascii_case("true")))
    }

    /// Set the per-tenant (or global, tenant=None) auto-publish flag. Admin
    /// plane only. Upserts on the same COALESCE(tenant, zero-uuid) key the
    /// embedding-route setting uses.
    pub async fn set_knowledge_auto_publish(
        &self,
        tenant: Option<TenantId>,
        enabled: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (tenant_id, key, value, updated_at)
             VALUES ($1, 'knowledge_auto_publish', $2, now())
             ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), key)
             DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        )
        .bind(tenant)
        .bind(if enabled { "true" } else { "false" })
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// Promote a candidate that has crossed k-support to `eligible` — the
    /// waiting-for-human/policy state under auto-publish OFF (§5). Only a
    /// `candidate` transitions; anything else is left untouched. Returns
    /// whether the row moved. NEVER mints a carve-out chunk (that is publish's
    /// job): an eligible item is not retrievable.
    pub async fn mark_knowledge_eligible(&self, tenant: TenantId, id: Uuid) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE knowledge SET status = 'eligible', eligible_at = now()
             WHERE tenant_id = $1 AND id = $2 AND status = 'candidate'",
        )
        .bind(tenant)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(r.rows_affected() > 0)
    }

    /// Reject a candidate/eligible item, REMEMBERED (§5): status = 'rejected'
    /// with the reason, so the same canonical_statement does not resurrect as a
    /// fresh candidate (enforced in propose_knowledge). Only a candidate or
    /// eligible item can be rejected — rejecting a published item is refused
    /// (retraction is `forget`'s job, not rejection). Returns the updated item;
    /// None when there is no such rejectable row.
    pub async fn reject_knowledge(
        &self,
        tenant: TenantId,
        id: Uuid,
        reason: &str,
    ) -> Result<Option<KnowledgeItem>> {
        let updated = sqlx::query_scalar::<_, Uuid>(
            "UPDATE knowledge
             SET status = 'rejected', rejected_at = now(), rejected_reason = $3
             WHERE tenant_id = $1 AND id = $2 AND status IN ('candidate', 'eligible')
             RETURNING id",
        )
        .bind(tenant)
        .bind(id)
        .bind(reason)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        match updated {
            Some(_) => self.get_knowledge(tenant, id).await.map(Some),
            None => Ok(None),
        }
    }

    /// The evidence lineage for one knowledge item (admin detail surface, §5:
    /// "the evidence episode/entity list"). Bucketed counts are for agents; the
    /// admin plane gets the exact rows.
    pub async fn knowledge_evidence(
        &self,
        tenant: TenantId,
        id: Uuid,
    ) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query(
            "SELECT ke.episode_id, ke.entity, ke.writer_azp, ke.trust_tier
             FROM knowledge_evidence ke
             JOIN knowledge k ON k.id = ke.knowledge_id
             WHERE ke.knowledge_id = $1 AND k.tenant_id = $2
             ORDER BY ke.episode_id",
        )
        .bind(id)
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| -> Result<serde_json::Value> {
                Ok(serde_json::json!({
                    "episode_id": r.try_get::<Uuid, _>("episode_id").map_err(db_err)?,
                    "entity": r.try_get::<Option<String>, _>("entity").map_err(db_err)?,
                    "writer_azp": r.try_get::<Option<String>, _>("writer_azp").map_err(db_err)?,
                    "trust_tier": r.try_get::<i16, _>("trust_tier").map_err(db_err)?,
                }))
            })
            .collect()
    }

    // ---------- cross-source entity resolution & precedence (SPEC §7f) ----------

    /// Map a source-native `(source, entity_id)` to a canonical entity key
    /// (SPEC §7f resolution). Idempotent upsert: re-linking a member to a
    /// different canonical just repoints it. Admin plane.
    pub async fn upsert_entity_alias(
        &self,
        tenant: TenantId,
        source: &str,
        entity_id: &str,
        canonical: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO entity_aliases (tenant_id, source, entity_id, canonical_entity)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, source, entity_id)
             DO UPDATE SET canonical_entity = EXCLUDED.canonical_entity",
        )
        .bind(tenant)
        .bind(source)
        .bind(entity_id)
        .bind(canonical)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// Set the per-field source precedence for a canonical entity (SPEC §7f).
    /// `canonical` / `field` of `"*"` set the defaults. Highest precedence
    /// first; a source absent from `source_order` ranks last at merge time.
    /// Admin plane.
    pub async fn set_entity_precedence(
        &self,
        tenant: TenantId,
        canonical: &str,
        field: &str,
        source_order: &[String],
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO entity_precedence (tenant_id, canonical_entity, field, source_order, updated_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (tenant_id, canonical_entity, field)
             DO UPDATE SET source_order = EXCLUDED.source_order, updated_at = now()",
        )
        .bind(tenant)
        .bind(canonical)
        .bind(field)
        .bind(source_order)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// The (source, entity_id) members aliased to `canonical` (SPEC §7f), in
    /// stable order. Empty when nothing is linked to that key.
    pub async fn list_entity_aliases(
        &self,
        tenant: TenantId,
        canonical: &str,
    ) -> Result<Vec<AliasMember>> {
        let rows = sqlx::query(
            "SELECT source, entity_id FROM entity_aliases
             WHERE tenant_id = $1 AND canonical_entity = $2
             ORDER BY source, entity_id",
        )
        .bind(tenant)
        .bind(canonical)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok(AliasMember {
                    source: r.try_get("source").map_err(db_err)?,
                    entity_id: r.try_get("entity_id").map_err(db_err)?,
                })
            })
            .collect()
    }

    /// Reverse lookup: the canonical entity a `(source, entity_id)` resolves to
    /// (SPEC §7f). `None` when the pair has no alias — it is then its own
    /// canonical entity (unmapped entities merge over just their own facts).
    pub async fn resolve_canonical(
        &self,
        tenant: TenantId,
        source: &str,
        entity_id: &str,
    ) -> Result<Option<String>> {
        let canonical: Option<String> = sqlx::query_scalar(
            "SELECT canonical_entity FROM entity_aliases
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3",
        )
        .bind(tenant)
        .bind(source)
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(canonical)
    }

    // ---------- entity-resolution evidence ledger + fold output (§4.1) --------
    //
    // These are the WORKER-PLANE writers/readers that PRODUCE the rows the §7f
    // read path (merged_record / load_precedence / the entity_tags pre-filter)
    // already consumes. The read path is untouched: the fold (S4) reuses
    // `upsert_entity_alias` (:302) and `resolve_canonical` (:382); these methods
    // only add the append-only ledger, its config, and the materialized
    // `entity_link_meta` badge. Invalidate-don't-delete throughout.

    /// Append one piece of evidence to the ledger (§4.1). Stamps a fresh
    /// `evidence_id` and returns the persisted row. Append-only — this NEVER
    /// updates or deletes an existing row; retraction is `retract_evidence`.
    pub async fn insert_evidence(&self, ev: EvidenceWrite) -> Result<EvidenceRow> {
        let row = sqlx::query(
            "INSERT INTO entity_evidence
                 (evidence_id, tenant_id, left_ref, right_ref, tier, method,
                  key_value, key_namespace, score, evidence_l0_ref, polarity)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             RETURNING evidence_id, tenant_id, left_ref, right_ref, tier, method,
                       key_value, key_namespace, score, evidence_l0_ref, polarity,
                       valid_from, valid_to, superseded_by",
        )
        .bind(Uuid::now_v7())
        .bind(ev.tenant_id)
        .bind(&ev.left_ref)
        .bind(&ev.right_ref)
        .bind(ev.tier)
        .bind(&ev.method)
        .bind(&ev.key_value)
        .bind(&ev.key_namespace)
        .bind(ev.score)
        .bind(&ev.evidence_l0_ref)
        .bind(ev.polarity)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row_to_evidence(&row)
    }

    /// Append evidence under a caller-supplied **deterministic** `evidence_id`,
    /// idempotently (§4.2: "re-running produces no duplicate evidence"). Uses
    /// `INSERT ... ON CONFLICT (evidence_id) DO NOTHING` so a repeated Tier-1
    /// production run over the same live L1 facts converges — the second run
    /// stamps the identical id and the conflict is a no-op.
    ///
    /// Returns `true` if a new row was inserted, `false` if it already existed
    /// (the idempotent skip). The id must be stable across runs — see
    /// [`crate::resolve::producers::deterministic_evidence_id`] for the derivation
    /// (a uuid v5 over `tenant + left_ref + right_ref + method + key_value +
    /// key_namespace`).
    pub async fn insert_evidence_with_id(
        &self,
        evidence_id: Uuid,
        ev: &EvidenceWrite,
    ) -> Result<bool> {
        let res = sqlx::query(
            "INSERT INTO entity_evidence
                 (evidence_id, tenant_id, left_ref, right_ref, tier, method,
                  key_value, key_namespace, score, evidence_l0_ref, polarity)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (evidence_id) DO NOTHING",
        )
        .bind(evidence_id)
        .bind(ev.tenant_id)
        .bind(&ev.left_ref)
        .bind(&ev.right_ref)
        .bind(ev.tier)
        .bind(&ev.method)
        .bind(&ev.key_value)
        .bind(&ev.key_namespace)
        .bind(ev.score)
        .bind(&ev.evidence_l0_ref)
        .bind(ev.polarity)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    /// Read every CURRENT L1 fact (`valid_to IS NULL`) for a tenant, grouped by
    /// `(source, entity_id)` (§4.2: the Tier-1 producer input). Each group is the
    /// full field→value map of one source entity, so a producer can pull the
    /// full field→value map of one source entity, so a producer can pull the
    /// email / FK / external-id fields it needs off a single entity's facts. The
    /// value is the raw jsonb; the producer-input builder scalarizes it.
    ///
    /// Ordered by `(source, entity_id, field)` for a reproducible grouping.
    pub async fn list_current_facts_grouped(&self, tenant: TenantId) -> Result<Vec<GroupedFacts>> {
        let rows = sqlx::query(
            "SELECT source, entity_id, field, value FROM facts
              WHERE tenant_id = $1 AND valid_to IS NULL
              ORDER BY source, entity_id, field",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let mut out: Vec<GroupedFacts> = Vec::new();
        for r in &rows {
            let source: String = r.try_get("source").map_err(db_err)?;
            let entity_id: String = r.try_get("entity_id").map_err(db_err)?;
            let field: String = r.try_get("field").map_err(db_err)?;
            let value: serde_json::Value = r.try_get("value").map_err(db_err)?;
            let key = (source, entity_id);
            match out.last_mut() {
                Some((k, fields)) if *k == key => fields.push((field, value)),
                _ => out.push((key, vec![(field, value)])),
            }
        }
        Ok(out)
    }

    /// Retract a live evidence row (§3.3 invalidate-don't-delete): stamps
    /// `valid_to = now()` (and optionally `superseded_by` to chain to a
    /// replacement row) so the fold stops reading it, WITHOUT deleting — the
    /// audit trail of "what we once believed and why we stopped" survives.
    /// Only affects a currently-live row (`valid_to IS NULL`); returns the
    /// number of rows retracted (0 if already retracted / not found).
    pub async fn retract_evidence(
        &self,
        tenant: TenantId,
        evidence_id: Uuid,
        superseded_by: Option<Uuid>,
    ) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE entity_evidence
                SET valid_to = now(), superseded_by = COALESCE($3, superseded_by)
              WHERE tenant_id = $1 AND evidence_id = $2 AND valid_to IS NULL",
        )
        .bind(tenant)
        .bind(evidence_id)
        .bind(superseded_by)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(res.rows_affected())
    }

    /// All LIVE evidence (`valid_to IS NULL`) touching any of `refs` on either
    /// side (§4.2 S4 step 1). This is the fold's neighborhood read: pass a
    /// component's member refs, get back every live positive/anti-link edge that
    /// bears on it. Ordered deterministically for a reproducible fold.
    pub async fn live_evidence_for_refs(
        &self,
        tenant: TenantId,
        refs: &[String],
    ) -> Result<Vec<EvidenceRow>> {
        let rows = sqlx::query(
            "SELECT evidence_id, tenant_id, left_ref, right_ref, tier, method,
                    key_value, key_namespace, score, evidence_l0_ref, polarity,
                    valid_from, valid_to, superseded_by
               FROM entity_evidence
              WHERE tenant_id = $1
                AND valid_to IS NULL
                AND (left_ref = ANY($2) OR right_ref = ANY($2))
              ORDER BY valid_from, evidence_id",
        )
        .bind(tenant)
        .bind(refs)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_evidence).collect()
    }

    /// Read the key-quality config for a `(key_kind, key_namespace)`, falling
    /// back to `EntityResolutionConfig::defaults` when the tenant has no row
    /// (§4.1). Fail-closed-friendly: producers always get a usable policy.
    pub async fn read_resolution_config(
        &self,
        tenant: TenantId,
        key_kind: &str,
        key_namespace: &str,
    ) -> Result<EntityResolutionConfig> {
        let row = sqlx::query(
            "SELECT key_kind, key_namespace, eligible_as_edge, denylist_values,
                    min_independent_keys, auto_merge_tier1, auto_link_tier3,
                    tau_nil, margin_delta, component_size_cap
               FROM entity_resolution_config
              WHERE tenant_id = $1 AND key_kind = $2 AND key_namespace = $3",
        )
        .bind(tenant)
        .bind(key_kind)
        .bind(key_namespace)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        match row {
            None => Ok(EntityResolutionConfig::defaults(
                tenant,
                key_kind,
                key_namespace,
            )),
            Some(r) => Ok(EntityResolutionConfig {
                tenant_id: tenant,
                key_kind: r.try_get("key_kind").map_err(db_err)?,
                key_namespace: r.try_get("key_namespace").map_err(db_err)?,
                eligible_as_edge: r.try_get("eligible_as_edge").map_err(db_err)?,
                denylist_values: r.try_get("denylist_values").map_err(db_err)?,
                min_independent_keys: r.try_get("min_independent_keys").map_err(db_err)?,
                auto_merge_tier1: r.try_get("auto_merge_tier1").map_err(db_err)?,
                auto_link_tier3: r.try_get("auto_link_tier3").map_err(db_err)?,
                tau_nil: r.try_get("tau_nil").map_err(db_err)?,
                margin_delta: r.try_get("margin_delta").map_err(db_err)?,
                component_size_cap: r.try_get("component_size_cap").map_err(db_err)?,
            }),
        }
    }

    /// Upsert (admin plane) the key-quality config for a `(key_kind,
    /// key_namespace)` (§4.1). Idempotent on the primary key.
    pub async fn write_resolution_config(&self, cfg: &EntityResolutionConfig) -> Result<()> {
        sqlx::query(
            "INSERT INTO entity_resolution_config
                 (tenant_id, key_kind, key_namespace, eligible_as_edge,
                  denylist_values, min_independent_keys, auto_merge_tier1,
                  auto_link_tier3, tau_nil, margin_delta, component_size_cap)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (tenant_id, key_kind, key_namespace) DO UPDATE SET
                 eligible_as_edge     = EXCLUDED.eligible_as_edge,
                 denylist_values      = EXCLUDED.denylist_values,
                 min_independent_keys = EXCLUDED.min_independent_keys,
                 auto_merge_tier1     = EXCLUDED.auto_merge_tier1,
                 auto_link_tier3      = EXCLUDED.auto_link_tier3,
                 tau_nil              = EXCLUDED.tau_nil,
                 margin_delta         = EXCLUDED.margin_delta,
                 component_size_cap   = EXCLUDED.component_size_cap",
        )
        .bind(cfg.tenant_id)
        .bind(&cfg.key_kind)
        .bind(&cfg.key_namespace)
        .bind(cfg.eligible_as_edge)
        .bind(&cfg.denylist_values)
        .bind(cfg.min_independent_keys)
        .bind(cfg.auto_merge_tier1)
        .bind(cfg.auto_link_tier3)
        .bind(cfg.tau_nil)
        .bind(cfg.margin_delta)
        .bind(cfg.component_size_cap)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// Upsert one materialized fold-output badge row (§4.1, §4.3). Idempotent on
    /// `(tenant, subject_kind, subject_ref, canonical_entity)` — re-folding a
    /// component overwrites the confidence/method/justifying-evidence in place.
    /// This is a DERIVED view the read path may see; it is never the source of
    /// truth (that is `entity_evidence`).
    /// Returns `true` when the link row was newly CREATED (vs refreshed) so the
    /// caller can audit only genuinely new links — the fold re-upserts its whole
    /// plan every run, and re-logging unchanged links buried the audit trail in
    /// duplicates (founder's cold reviewer read them as data-credibility bugs).
    pub async fn upsert_entity_link_meta(&self, meta: &EntityLinkMeta) -> Result<bool> {
        let row = sqlx::query(
            "INSERT INTO entity_link_meta
                 (tenant_id, subject_kind, subject_ref, canonical_entity,
                  confidence, strongest_method, justifying_evidence,
                  evidence_count, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
             ON CONFLICT (tenant_id, subject_kind, subject_ref, canonical_entity)
             DO UPDATE SET
                 confidence          = EXCLUDED.confidence,
                 strongest_method    = EXCLUDED.strongest_method,
                 justifying_evidence = EXCLUDED.justifying_evidence,
                 evidence_count      = EXCLUDED.evidence_count,
                 updated_at          = now()
             RETURNING (xmax = 0) AS inserted",
        )
        .bind(meta.tenant_id)
        .bind(&meta.subject_kind)
        .bind(&meta.subject_ref)
        .bind(&meta.canonical_entity)
        .bind(&meta.confidence)
        .bind(&meta.strongest_method)
        .bind(&meta.justifying_evidence)
        .bind(meta.evidence_count)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row.try_get("inserted").map_err(db_err)
    }

    /// Materialize the fold's chunk-tag decision (§4.3 item 2, §5): set the
    /// current chunk version's `entity_tags` to `tags`. This is the fold's sole
    /// path from `entity_aliases`/evidence to the read-time `entity_tags`
    /// pre-filter — closing the documented alias→tag gap (§2.1). It targets the
    /// LIVE chunk version (`valid_to IS NULL`) by `(source, document_id, seq)`
    /// and never mutates L0 or history. Returns rows affected. The read-time
    /// pre-filter (postgres.rs:665) is unchanged; only the stored tag set moves.
    pub async fn chunk_entity_tags_upsert(
        &self,
        tenant: TenantId,
        source: &str,
        document_id: &str,
        seq: i32,
        tags: &[String],
    ) -> Result<u64> {
        let res = sqlx::query(
            "UPDATE chunks SET entity_tags = $5
              WHERE tenant_id = $1 AND source = $2 AND document_id = $3
                AND seq = $4 AND valid_to IS NULL",
        )
        .bind(tenant)
        .bind(source)
        .bind(document_id)
        .bind(seq)
        .bind(tags)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        // Entity tags are the lineage key for briefs (§2 L3): a tag change marks
        // the affected entities' briefs stale, same as upsert_chunks does.
        if res.rows_affected() > 0 {
            let mut tx = self.pool.begin().await.map_err(db_err)?;
            mark_briefs_stale_tx(&mut tx, tenant, tags).await?;
            tx.commit().await.map_err(db_err)?;
        }
        Ok(res.rows_affected())
    }

    /// All LIVE evidence (`valid_to IS NULL`) for a tenant (§4.2 S4). The
    /// materializer's full-fold read: pass to `fold` to re-materialize the whole
    /// tenant. Deterministically ordered (matches `live_evidence_for_refs`).
    pub async fn all_live_evidence(&self, tenant: TenantId) -> Result<Vec<EvidenceRow>> {
        let rows = sqlx::query(
            "SELECT evidence_id, tenant_id, left_ref, right_ref, tier, method,
                    key_value, key_namespace, score, evidence_l0_ref, polarity,
                    valid_from, valid_to, superseded_by
               FROM entity_evidence
              WHERE tenant_id = $1 AND valid_to IS NULL
              ORDER BY valid_from, evidence_id",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_evidence).collect()
    }

    /// Read the `entity_link_meta` badge for a canonical entity's alias-membership
    /// (§4.3 item 3). Returns the single `subject_kind='alias_member'` row that
    /// carries the confidence + strongest_method the read path surfaces on the
    /// merged-entity response. `None` when the canonical has no materialized badge
    /// (an unmapped / admin-only entity — the read still works, just unbadged).
    /// This is a DERIVED read, no LLM/ReBAC — read-path safe.
    pub async fn link_meta_for_canonical(
        &self,
        tenant: TenantId,
        canonical: &str,
    ) -> Result<Option<EntityLinkMeta>> {
        let row = sqlx::query(
            "SELECT subject_kind, subject_ref, canonical_entity, confidence,
                    strongest_method, justifying_evidence, evidence_count
               FROM entity_link_meta
              WHERE tenant_id = $1 AND canonical_entity = $2
                AND subject_kind = 'alias_member'
              ORDER BY evidence_count DESC, subject_ref
              LIMIT 1",
        )
        .bind(tenant)
        .bind(canonical)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(EntityLinkMeta {
                tenant_id: tenant,
                subject_kind: r.try_get("subject_kind").map_err(db_err)?,
                subject_ref: r.try_get("subject_ref").map_err(db_err)?,
                canonical_entity: r.try_get("canonical_entity").map_err(db_err)?,
                confidence: r.try_get("confidence").map_err(db_err)?,
                strongest_method: r.try_get("strongest_method").map_err(db_err)?,
                justifying_evidence: r.try_get("justifying_evidence").map_err(db_err)?,
                evidence_count: r.try_get("evidence_count").map_err(db_err)?,
            })),
        }
    }

    /// The review queue (§4.1, §4.3): live positive evidence whose pair is
    /// still UNDECIDED — not welded into one canonical, not anti-linked. That
    /// covers three populations in one coherent rule:
    ///
    /// - **Tier-2** candidates awaiting `human_confirmed` (the fuzzy producer's
    ///   proposals);
    /// - **Tier-3** mentions (never auto-merge; reviewer hints);
    /// - **Deferred Tier-1 pairs** (extended 2026-07-11, closing the flagged
    ///   follow-up in RESULTS-tuning-defaults-2026-07-11.md): a live Tier-1
    ///   pair that did NOT materialize into a shared canonical — min-keys
    ///   suppression (a lone domain; a lone email post-amendment), key-node
    ///   fan-out, or size-cap quarantine. Derived from STATE (evidence vs
    ///   `entity_aliases`), never by re-deriving fold logic in SQL, so it can't
    ///   drift from the fold; and it self-heals — the moment a pair welds (or
    ///   a human anti-links it), it drops out of the queue.
    ///
    /// Decision rows themselves (`human_confirmed` / `human_rejected`) are
    /// excluded — they are verdicts, not candidates — and any pair carrying a
    /// live anti-link (`polarity = -1`) is excluded wholesale: a human already
    /// said no, and the anti-link is permanent.
    ///
    /// PRIORITIZED (design §8 Later: "review-queue prioritization + SLA —
    /// starvation risk, surface high-value/high-frequency entities first").
    /// No fold/merge behaviour touched, read path untouched. We compute a
    /// `priority` per candidate from ledger-visible signals and order by it
    /// DESC so the reviewer's finite attention lands on the candidates that
    /// matter most — while an aging term guarantees no candidate can be buried
    /// forever (anti-starvation / SLA).
    ///
    /// ── PRIORITY FORMULA ────────────────────────────────────────────────────
    /// All signals come straight from the append-only ledger (`entity_evidence`)
    /// + the derived `entity_aliases` — zero LLM, zero live ReBAC, zero fold.
    ///
    /// ```text
    /// priority =  W_FREQ  * ln(1 + frequency)      -- FREQUENCY
    ///          +  W_VALUE * ln(1 + entity_value)   -- ENTITY VALUE
    ///          +  W_TIER  * tier_weight            -- TIER (2 before 3)
    ///          +  W_REC   * recency_decay          -- RECENCY (newest evidence)
    ///          +  W_AGE   * age_days               -- SLA / ANTI-STARVATION
    /// ```
    ///
    /// - `frequency` — count of LIVE evidence rows recurring between this exact
    ///   `{left_ref,right_ref}` pair (order-independent). Two refs that keep
    ///   co-occurring are a stronger, higher-stakes call.
    /// - `entity_value` — total distinct alias MEMBERS in the clusters the two
    ///   refs already belong to (via `entity_aliases`). Bigger clusters = more
    ///   facts/members downstream = higher blast radius, so a merge/split
    ///   decision there is worth more.
    /// - `tier_weight` — 1.2 for a deferred Tier-1 pair (the strongest signal
    ///   the fold refused fail-closed; a confirm welds it), 1.0 for Tier-2
    ///   (a confirm can FORM an edge — actionable), 0.4 for Tier-3 (never
    ///   auto-merges; corroboration only).
    /// - `recency_decay` — `exp(-age_days / RECENCY_TAU)`: a freshly-produced
    ///   candidate is likelier to reflect a live workflow the reviewer cares
    ///   about right now; decays smoothly, never dominates aging.
    /// - `age_days` — `now() - valid_from`, in days (the candidate's WAIT AGE).
    ///
    /// ── AGING / SLA (anti-starvation) ───────────────────────────────────────
    /// `W_AGE * age_days` is an UNBOUNDED linear term: every other signal is
    /// bounded (ln() grows sub-linearly and the corpus is finite; tier/recency
    /// are ≤1), so for any candidate, however low its intrinsic score, its
    /// priority strictly increases with wait time and will EVENTUALLY exceed any
    /// fixed-score competitor. The oldest-waiting candidate can never be
    /// indefinitely buried — it ages into the top of the queue on its own. Tune
    /// `AGE_WEIGHT` to the SLA: larger = the queue drains closer to strict FIFO;
    /// smaller = value/frequency dominate until a candidate is quite stale. The
    /// wait age is returned per row so an operator can watch the SLA directly.
    ///
    /// Weights live as SQL constants below so the policy is auditable in one place.
    /// Ties (identical priority) break by `valid_from ASC` (oldest first) then
    /// `evidence_id` for a fully deterministic order.
    pub async fn review_queue(&self, tenant: TenantId, limit: i64) -> Result<Vec<ReviewQueueItem>> {
        let rows = sqlx::query(
            // Priority-policy constants (see the doc comment above). Kept inline
            // so the whole scoring policy is one auditable block.
            "WITH params AS (
                 SELECT 1.5::float8  AS freq_weight,
                        1.0::float8  AS value_weight,
                        2.0::float8  AS tier_weight,
                        1.0::float8  AS recency_weight,
                        0.20::float8 AS age_weight,      -- SLA slope (per day)
                        14.0::float8 AS recency_tau      -- recency half-life-ish (days)
             ),
             -- The candidate set: live POSITIVE evidence (any tier) whose pair
             -- is still UNDECIDED — not welded into one canonical, not
             -- anti-linked, and not itself a human verdict. Tier-1 rows here
             -- are exactly the DEFERRED pairs (min-keys / fan-out / size-cap
             -- suppressed) the fold refused fail-closed.
             cand AS (
                 SELECT e.evidence_id, e.tenant_id, e.left_ref, e.right_ref,
                        e.tier, e.method, e.key_value, e.key_namespace, e.score,
                        e.evidence_l0_ref, e.polarity, e.valid_from, e.valid_to,
                        e.superseded_by
                   FROM entity_evidence e
                  WHERE e.tenant_id = $1 AND e.valid_to IS NULL
                    AND e.polarity = 1
                    AND e.method NOT IN ('human_confirmed', 'human_rejected')
                    -- undecided: no live anti-link on this unordered pair …
                    AND NOT EXISTS (
                        SELECT 1 FROM entity_evidence al
                         WHERE al.tenant_id = $1 AND al.valid_to IS NULL
                           AND al.polarity = -1
                           AND least(al.left_ref, al.right_ref)
                               = least(e.left_ref, e.right_ref)
                           AND greatest(al.left_ref, al.right_ref)
                               = greatest(e.left_ref, e.right_ref)
                    )
                    -- … and the two refs do not already share a canonical.
                    AND NOT EXISTS (
                        SELECT 1
                          FROM entity_aliases l
                          JOIN entity_aliases r
                            ON r.tenant_id = l.tenant_id
                           AND r.canonical_entity = l.canonical_entity
                         WHERE l.tenant_id = $1
                           AND l.source || ':' || l.entity_id = e.left_ref
                           AND r.source || ':' || r.entity_id = e.right_ref
                    )
             ),
             -- FREQUENCY: how often this same unordered ref-pair recurs across
             -- LIVE positive evidence (any tier). least/greatest makes
             -- {a,b} == {b,a}.
             freq AS (
                 SELECT least(left_ref, right_ref)    AS a,
                        greatest(left_ref, right_ref) AS b,
                        count(*)                       AS n
                   FROM entity_evidence
                  WHERE tenant_id = $1 AND valid_to IS NULL AND polarity = 1
                  GROUP BY 1, 2
             ),
             -- ENTITY VALUE: distinct alias members in each ref's existing
             -- cluster. A ref like 'salesforce:001' maps to a canonical via
             -- entity_aliases (source,entity_id); we count members of that
             -- canonical. Refs with no alias contribute 0 (their own singleton).
             cluster_size AS (
                 SELECT a2.canonical_entity, count(*) AS members
                   FROM entity_aliases a2
                  WHERE a2.tenant_id = $1
                  GROUP BY a2.canonical_entity
             )
             SELECT c.evidence_id, c.tenant_id, c.left_ref, c.right_ref, c.tier,
                    c.method, c.key_value, c.key_namespace, c.score,
                    c.evidence_l0_ref, c.polarity, c.valid_from, c.valid_to,
                    c.superseded_by,
                    -- returned wait age in seconds (the SLA read-out for the UI).
                    EXTRACT(EPOCH FROM (now() - c.valid_from))::float8 AS wait_age_secs,
                    COALESCE(f.n, 1)                                   AS frequency,
                    (COALESCE(ls.members, 0) + COALESCE(rs.members, 0))::bigint
                                                                      AS entity_value,
                    (
                      p.freq_weight    * ln(1 + COALESCE(f.n, 1))
                    + p.value_weight   * ln(1 + COALESCE(ls.members, 0)
                                                 + COALESCE(rs.members, 0))
                    + p.tier_weight    * (CASE c.tier WHEN 1 THEN 1.2
                                                      WHEN 2 THEN 1.0
                                                      ELSE 0.4 END)
                    + p.recency_weight * exp(
                          - (EXTRACT(EPOCH FROM (now() - c.valid_from)) / 86400.0)
                            / p.recency_tau)
                    -- SLA / anti-starvation: UNBOUNDED linear in wait age (days).
                    + p.age_weight     * (EXTRACT(EPOCH FROM (now() - c.valid_from))
                                          / 86400.0)
                    )::float8                                         AS priority
               FROM cand c
               CROSS JOIN params p
               LEFT JOIN freq f
                      ON f.a = least(c.left_ref, c.right_ref)
                     AND f.b = greatest(c.left_ref, c.right_ref)
               LEFT JOIN entity_aliases la
                      ON la.tenant_id = c.tenant_id
                     AND la.source || ':' || la.entity_id = c.left_ref
               LEFT JOIN cluster_size ls ON ls.canonical_entity = la.canonical_entity
               LEFT JOIN entity_aliases ra
                      ON ra.tenant_id = c.tenant_id
                     AND ra.source || ':' || ra.entity_id = c.right_ref
               LEFT JOIN cluster_size rs ON rs.canonical_entity = ra.canonical_entity
              ORDER BY priority DESC, c.valid_from ASC, c.evidence_id
              LIMIT $2",
        )
        .bind(tenant)
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_review_item).collect()
    }

    /// List all key-quality config rows for a tenant (admin plane, §4.1). The GET
    /// side of the config CRUD; `write_resolution_config` is the PUT side.
    pub async fn list_resolution_config(
        &self,
        tenant: TenantId,
    ) -> Result<Vec<EntityResolutionConfig>> {
        let rows = sqlx::query(
            "SELECT key_kind, key_namespace, eligible_as_edge, denylist_values,
                    min_independent_keys, auto_merge_tier1, auto_link_tier3,
                    tau_nil, margin_delta, component_size_cap
               FROM entity_resolution_config
              WHERE tenant_id = $1
              ORDER BY key_kind, key_namespace",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok(EntityResolutionConfig {
                    tenant_id: tenant,
                    key_kind: r.try_get("key_kind").map_err(db_err)?,
                    key_namespace: r.try_get("key_namespace").map_err(db_err)?,
                    eligible_as_edge: r.try_get("eligible_as_edge").map_err(db_err)?,
                    denylist_values: r.try_get("denylist_values").map_err(db_err)?,
                    min_independent_keys: r.try_get("min_independent_keys").map_err(db_err)?,
                    auto_merge_tier1: r.try_get("auto_merge_tier1").map_err(db_err)?,
                    auto_link_tier3: r.try_get("auto_link_tier3").map_err(db_err)?,
                    tau_nil: r.try_get("tau_nil").map_err(db_err)?,
                    margin_delta: r.try_get("margin_delta").map_err(db_err)?,
                    component_size_cap: r.try_get("component_size_cap").map_err(db_err)?,
                })
            })
            .collect()
    }

    /// LIST the tenant's canonical entities for the entities browser (§4.3 / §9
    /// Group D). Returns one [`CanonicalEntitySummary`] per DISTINCT
    /// `canonical_entity` in `entity_aliases`, each carrying its `(source,
    /// entity_id)` members, a light `name`/`domain` field summary (from current
    /// facts on any member), and the `entity_link_meta` confidence badge. Ordered
    /// by canonical key, capped by `limit`.
    ///
    /// Purely additive DERIVED reads — `merged_record`'s precedence-resolution is
    /// UNTOUCHED (the summary is a display hint, not the authoritative merge);
    /// zero LLM, zero live ReBAC, zero fold. Entities with no alias row are their
    /// own implicit canonical and are intentionally NOT listed here (there is no
    /// `entity_aliases` row to enumerate them from — the browser lists MERGED
    /// entities).
    ///
    /// ADMIN-PLANE read (SPEC §7e): the ONLY caller is the bearer-gated admin
    /// entities browser (`admin_list_entities`), which legitimately sees every
    /// entity. The name/domain summary it fetches (`member_field_summary`) is
    /// therefore admin-all — it may surface a value from a fact no agent scope
    /// could see. There is no scope-handle path into this method, so no
    /// visibility pre-filter is applied; a scoped caller would go through
    /// `merged_record` (visible-only) instead.
    pub async fn list_canonical_entities(
        &self,
        tenant: TenantId,
        limit: i64,
    ) -> Result<Vec<CanonicalEntitySummary>> {
        // 1. Distinct canonicals + their members in one pass, ordered stably.
        let rows = sqlx::query(
            "SELECT canonical_entity, source, entity_id
               FROM entity_aliases
              WHERE tenant_id = $1
                AND canonical_entity IN (
                    SELECT canonical_entity FROM entity_aliases
                     WHERE tenant_id = $1
                     GROUP BY canonical_entity
                     ORDER BY canonical_entity
                     LIMIT $2)
              ORDER BY canonical_entity, source, entity_id",
        )
        .bind(tenant)
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        // Group members per canonical, preserving order.
        let mut grouped: Vec<(String, Vec<AliasMember>)> = Vec::new();
        for r in &rows {
            let canonical: String = r.try_get("canonical_entity").map_err(db_err)?;
            let member = AliasMember {
                source: r.try_get("source").map_err(db_err)?,
                entity_id: r.try_get("entity_id").map_err(db_err)?,
            };
            match grouped.last_mut() {
                Some((c, members)) if *c == canonical => members.push(member),
                _ => grouped.push((canonical, vec![member])),
            }
        }

        // 2. For each canonical, attach the light summary + the badge. Both are
        //    single-canonical derived reads; the corpus here is bounded by
        //    `limit`, so a per-canonical round trip is fine for an admin browser.
        let mut out = Vec::with_capacity(grouped.len());
        for (canonical, members) in grouped {
            let summary = self.member_field_summary(tenant, &members).await?;
            let badge = self
                .link_meta_for_canonical(tenant, &canonical)
                .await?
                .map(|m| EntityConfidenceBadge {
                    confidence: m.confidence,
                    strongest_method: m.strongest_method,
                    evidence_count: m.evidence_count,
                });
            out.push(CanonicalEntitySummary {
                tenant_id: tenant,
                canonical_entity: canonical,
                members,
                summary,
                badge,
                merged: true,
            });
        }

        // 3. SINGLE-SOURCE entities: every distinct (source, entity_id) that has
        //    current facts but is NOT aliased to any canonical — i.e. the
        //    resolver never welded it to anything. Without these the browser is
        //    empty whenever a corpus has no cross-source duplicate keys (a clean
        //    inbox of unique domains/emails), hiding entities that plainly exist.
        //    They carry no badge (nothing was inferred) and merged=false so the
        //    UI can label them honestly. Fill only the remaining `limit` budget
        //    so the merged canonicals (the interesting ones) always come first.
        let clamped = limit.clamp(1, 1000);
        let remaining = clamped - (out.len() as i64);
        if remaining > 0 {
            let singles = sqlx::query(
                "SELECT DISTINCT f.source, f.entity_id
                   FROM facts f
                  WHERE f.tenant_id = $1
                    AND f.valid_to IS NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM entity_aliases a
                         WHERE a.tenant_id = f.tenant_id
                           AND a.source || ':' || a.entity_id
                               = f.source || ':' || f.entity_id)
                  ORDER BY f.source, f.entity_id
                  LIMIT $2",
            )
            .bind(tenant)
            .bind(remaining)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;

            for r in &singles {
                let source: String = r.try_get("source").map_err(db_err)?;
                let entity_id: String = r.try_get("entity_id").map_err(db_err)?;
                let members = vec![AliasMember {
                    source: source.clone(),
                    entity_id: entity_id.clone(),
                }];
                let summary = self.member_field_summary(tenant, &members).await?;
                out.push(CanonicalEntitySummary {
                    tenant_id: tenant,
                    // Composed ref (source:entity_id) — the same grammar the
                    // member summary + merged_record compose on.
                    canonical_entity: format!("{source}:{entity_id}"),
                    members,
                    summary,
                    badge: None,
                    merged: false,
                });
            }
        }
        Ok(out)
    }

    /// The entity-tag DIRECTORY for the console's entity picker
    /// (docs/design/ENTITY-PICKER.md §4): DISTINCT tags observed on
    /// `chunks.entity_tags ∪ actions.entities` and NOTHING else — the exact
    /// union the enforcement predicates scan (`entity_scope_predicate`, the
    /// activity `entities @>` containment), so the picker never offers an
    /// entity the scope filter cannot see. (The de-id lexicon additionally
    /// unions `facts.entity_id` — correct for leak-screening, noise here.)
    ///
    /// - `chunk_count` is always LIVE rows (`valid_to IS NULL`). With
    ///   `live_only = false`, invalidated chunk rows also ADMIT their tags to
    ///   the directory and `total_chunk_count` is populated — a tag carried
    ///   only by superseded rows is a legitimate erasure target that a
    ///   live-only directory would hide.
    /// - `total_distinct` and `namespaces` ignore `q`/`limit` (Emptiness Law).
    /// - `q` is a case-insensitive substring over the tag; ordering is total
    ///   memories carrying the tag (desc) then tag; `limit` clamps 1..=500
    ///   with `truncated` set when more matched.
    /// - The `entity_aliases`/`entity_link_meta` LEFT JOINs are display hints
    ///   only (the `merged` badge); both are at-most-one by primary key, so
    ///   they can never fan a tag row out.
    ///
    /// Worker/admin plane only — never consulted by `recall`/`get` (read-path
    /// purity: zero LLM, zero live ReBAC). Performance honesty: unnest
    /// aggregation is a per-tenant seq scan (the GIN indexes serve
    /// containment, not this) — fine for an admin dialog at current corpus
    /// sizes; if it ever hurts, materialize a tag summary rather than count a
    /// different (dishonest) source.
    pub async fn list_entity_tags(
        &self,
        tenant: TenantId,
        q: Option<&str>,
        live_only: bool,
        limit: i64,
    ) -> Result<EntityTagDirectory> {
        let limit = limit.clamp(1, 500);
        // $2 = NOT live_only ("include invalidated chunk rows").
        let include_invalidated = !live_only;

        let head = sqlx::query(
            "SELECT count(*) AS total_distinct,
                    array_agg(DISTINCT split_part(tag, ':', 1)
                              ORDER BY split_part(tag, ':', 1))
                        FILTER (WHERE strpos(tag, ':') > 0) AS namespaces
             FROM (
                 SELECT DISTINCT tag FROM (
                     SELECT unnest(entity_tags) AS tag FROM chunks
                      WHERE tenant_id = $1 AND ($2 OR valid_to IS NULL)
                     UNION ALL
                     SELECT unnest(entities) FROM actions WHERE tenant_id = $1
                 ) u
             ) t",
        )
        .bind(tenant)
        .bind(include_invalidated)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        let total_distinct: i64 = head.try_get("total_distinct").map_err(db_err)?;
        let namespaces: Vec<String> = head
            .try_get::<Option<Vec<String>>, _>("namespaces")
            .map_err(db_err)?
            .unwrap_or_default();

        // Page: fetch limit+1 to detect truncation without a second count.
        let rows = sqlx::query(
            "SELECT agg.tag,
                    agg.chunk_count,
                    agg.total_chunk_count,
                    agg.action_count,
                    agg.last_seen,
                    ea.canonical_entity,
                    elm.confidence AS link_confidence
             FROM (
                 SELECT tag,
                        sum(live_chunks)::bigint AS chunk_count,
                        sum(all_chunks)::bigint  AS total_chunk_count,
                        sum(actions)::bigint     AS action_count,
                        max(last_seen)           AS last_seen
                 FROM (
                     SELECT unnest(entity_tags) AS tag,
                            count(*) FILTER (WHERE valid_to IS NULL) AS live_chunks,
                            count(*)  AS all_chunks,
                            0::bigint AS actions,
                            max(valid_from) AS last_seen
                       FROM chunks
                      WHERE tenant_id = $1 AND ($2 OR valid_to IS NULL)
                      GROUP BY 1
                     UNION ALL
                     SELECT unnest(entities), 0::bigint, 0::bigint, count(*),
                            max(occurred_at)
                       FROM actions
                      WHERE tenant_id = $1
                      GROUP BY 1
                 ) t
                 WHERE ($3::text IS NULL OR tag ILIKE '%' || $3 || '%')
                 GROUP BY tag
             ) agg
             LEFT JOIN entity_aliases ea
                    ON ea.tenant_id = $1
                   AND ea.source || ':' || ea.entity_id = agg.tag
             LEFT JOIN entity_link_meta elm
                    ON elm.tenant_id = $1
                   AND elm.subject_kind = 'alias_member'
                   AND elm.subject_ref = agg.tag
                   AND elm.canonical_entity = ea.canonical_entity
             ORDER BY agg.total_chunk_count + agg.action_count DESC, agg.tag
             LIMIT $4",
        )
        .bind(tenant)
        .bind(include_invalidated)
        .bind(q)
        .bind(limit + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let truncated = rows.len() as i64 > limit;
        let tags = rows
            .iter()
            .take(limit as usize)
            .map(|r| {
                Ok(EntityTagRow {
                    tag: r.try_get("tag").map_err(db_err)?,
                    chunk_count: r.try_get("chunk_count").map_err(db_err)?,
                    action_count: r.try_get("action_count").map_err(db_err)?,
                    total_chunk_count: if live_only {
                        None
                    } else {
                        r.try_get("total_chunk_count").map_err(db_err)?
                    },
                    last_seen: r.try_get("last_seen").map_err(db_err)?,
                    canonical_entity: r.try_get("canonical_entity").map_err(db_err)?,
                    link_confidence: r.try_get("link_confidence").map_err(db_err)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(EntityTagDirectory {
            total_distinct,
            truncated,
            namespaces,
            tags,
        })
    }

    /// The console's Memories browser (`GET /v1/admin/memories`): one tenant's
    /// chunk ∪ fact ∪ action rows in a common shape, newest-recorded first,
    /// keyset-paginated. **ADMIN plane** — a plain filtered SQL read: zero LLM,
    /// zero live ReBAC, never consulted by `recall`/`get` (read-path purity
    /// holds). It surfaces visibility as a token COUNT (never the tokens) and
    /// bypasses no enforcement for agents: per-scope retrievability is decided
    /// at read time on the scoped paths; this is the operator's evidence view.
    ///
    /// Semantics:
    /// - the tenant partition is mandatory; every other filter optional;
    /// - `include_superseded=false` (default) shows LIVE rows only; true adds
    ///   replaced rows (invalidate-don't-delete — history persists until the
    ///   §8 hard-purge pipeline);
    /// - `entity` is containment over the same arrays the scope filter
    ///   enforces on (facts match their synthetic `source:entity_id` tag);
    /// - `sources` counts come from the SAME filtered union minus the source
    ///   filter itself, so the dropdown reflects what the other filters match;
    /// - an `id` lookup returns that single row with FULL content (superseded
    ///   included — a replaced row must stay inspectable) and skips counts.
    pub async fn browse_memories(
        &self,
        tenant: TenantId,
        f: &MemoryBrowseFilter,
    ) -> Result<MemoryBrowsePage> {
        if let Some(k) = f.kind.as_deref() {
            if !matches!(k, "chunk" | "fact" | "action") {
                return Err(StorageError::InvalidInput(format!(
                    "kind must be one of chunk | fact | action (got {k:?})"
                )));
            }
        }
        let limit = f.limit.clamp(1, 200);
        // An id lookup must be able to show a replaced row (the drawer opens
        // it from a history listing); list reads honor the toggle.
        let include_invalidated = f.include_superseded || f.id.is_some();

        // The ONE union both statements share. Placeholders:
        //   $1 tenant  $2 include_invalidated  $3 kind  $4 source
        //   $5 entity  $6 q  $7 id
        // Previews are cut at 240 chars EXCEPT on an id lookup (the drawer's
        // full-content read). Actions are append-only (no valid_to) and their
        // provenance episodes are always source='agent' (record_action).
        const UNION_SQL: &str = "
            SELECT 'chunk'::text AS kind, id, source,
                   CASE WHEN $7::uuid IS NOT NULL THEN content
                        ELSE left(content, 240) END AS preview,
                   ($7::uuid IS NULL AND length(content) > 240) AS preview_truncated,
                   entity_tags AS entities,
                   cardinality(visibility) AS visible_to,
                   confidentiality::int4 AS confidentiality,
                   acl_provenance,
                   trust_tier::int4 AS trust_tier,
                   valid_from, valid_to,
                   NULL::uuid AS superseded_by,
                   provenance,
                   NULL::text AS entity_id, NULL::text AS field,
                   document_id, seq,
                   NULL::text AS action_type, NULL::text AS outcome,
                   recorded_at
              FROM chunks
             WHERE tenant_id = $1
               AND ($2 OR valid_to IS NULL)
               AND ($3::text IS NULL OR $3 = 'chunk')
               AND ($4::text IS NULL OR source = $4)
               AND ($5::text IS NULL OR entity_tags @> ARRAY[$5])
               AND ($6::text IS NULL OR content ILIKE '%' || $6 || '%')
               AND ($7::uuid IS NULL OR id = $7)
            UNION ALL
            SELECT 'fact', id, source,
                   CASE WHEN $7::uuid IS NOT NULL THEN value::text
                        ELSE left(value::text, 240) END,
                   ($7::uuid IS NULL AND length(value::text) > 240),
                   ARRAY[source || ':' || entity_id],
                   NULL::int4,
                   NULL::int4,
                   acl_provenance,
                   NULL::int4,
                   valid_from, valid_to,
                   superseded_by,
                   provenance,
                   entity_id, field,
                   NULL::text, NULL::int4,
                   NULL::text, NULL::text,
                   recorded_at
              FROM facts
             WHERE tenant_id = $1
               AND ($2 OR valid_to IS NULL)
               AND ($3::text IS NULL OR $3 = 'fact')
               AND ($4::text IS NULL OR source = $4)
               AND ($5::text IS NULL OR source || ':' || entity_id = $5)
               AND ($6::text IS NULL OR value::text ILIKE '%' || $6 || '%')
               AND ($7::uuid IS NULL OR id = $7)
            UNION ALL
            SELECT 'action', id, 'agent'::text,
                   CASE WHEN $7::uuid IS NOT NULL THEN summary
                        ELSE left(summary, 240) END,
                   ($7::uuid IS NULL AND length(summary) > 240),
                   entities,
                   cardinality(visibility),
                   confidentiality::int4,
                   NULL::text,
                   NULL::int4,
                   occurred_at, NULL::timestamptz,
                   NULL::uuid,
                   provenance,
                   NULL::text, NULL::text,
                   NULL::text, NULL::int4,
                   action_type, outcome,
                   recorded_at
              FROM actions
             WHERE tenant_id = $1
               AND ($3::text IS NULL OR $3 = 'action')
               AND ($4::text IS NULL OR $4 = 'agent')
               AND ($5::text IS NULL OR entities @> ARRAY[$5])
               AND ($6::text IS NULL OR summary ILIKE '%' || $6 || '%')
               AND ($7::uuid IS NULL OR id = $7)";

        // Page: limit+1 detects a further page without a second count. The
        // statement text is assembled ONLY from const fragments (every dynamic
        // value is a bind parameter), so AssertSqlSafe is honest here.
        let raw = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM ({UNION_SQL}) m
              WHERE ($8::timestamptz IS NULL
                     OR ($10::uuid IS NOT NULL AND (m.recorded_at, m.id) < ($8, $10))
                     OR ($10::uuid IS NULL AND m.recorded_at < $8))
              ORDER BY m.recorded_at DESC, m.id DESC
              LIMIT $9"
        )))
        .bind(tenant)
        .bind(include_invalidated)
        .bind(f.kind.as_deref())
        .bind(f.source.as_deref())
        .bind(f.entity.as_deref())
        .bind(f.q.as_deref())
        .bind(f.id)
        .bind(f.before)
        .bind(limit + 1)
        .bind(f.before_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let has_more = raw.len() as i64 > limit;
        let rows = raw
            .iter()
            .take(limit as usize)
            .map(|r| {
                Ok(MemoryBrowseRow {
                    kind: r.try_get("kind").map_err(db_err)?,
                    id: r.try_get("id").map_err(db_err)?,
                    source: r.try_get("source").map_err(db_err)?,
                    preview: r.try_get("preview").map_err(db_err)?,
                    preview_truncated: r.try_get("preview_truncated").map_err(db_err)?,
                    entities: r.try_get("entities").map_err(db_err)?,
                    visible_to: r.try_get("visible_to").map_err(db_err)?,
                    confidentiality: r.try_get("confidentiality").map_err(db_err)?,
                    acl_provenance: r.try_get("acl_provenance").map_err(db_err)?,
                    trust_tier: r.try_get("trust_tier").map_err(db_err)?,
                    valid_from: r.try_get("valid_from").map_err(db_err)?,
                    valid_to: r.try_get("valid_to").map_err(db_err)?,
                    superseded_by: r.try_get("superseded_by").map_err(db_err)?,
                    provenance: r.try_get("provenance").map_err(db_err)?,
                    entity_id: r.try_get("entity_id").map_err(db_err)?,
                    field: r.try_get("field").map_err(db_err)?,
                    document_id: r.try_get("document_id").map_err(db_err)?,
                    seq: r.try_get("seq").map_err(db_err)?,
                    action_type: r.try_get("action_type").map_err(db_err)?,
                    outcome: r.try_get("outcome").map_err(db_err)?,
                    recorded_at: r.try_get("recorded_at").map_err(db_err)?,
                })
            })
            .collect::<Result<Vec<MemoryBrowseRow>>>()?;
        let (next_before, next_before_id) = if has_more {
            (
                rows.last().map(|r| r.recorded_at),
                rows.last().map(|r| r.id),
            )
        } else {
            (None, None)
        };

        // Per-source counts: the SAME union, all filters EXCEPT source (bound
        // NULL) and pagination — the dropdown shows every source the other
        // filters can reach, with honest counts. Skipped on an id lookup.
        let sources = if f.id.is_some() {
            Vec::new()
        } else {
            // Const fragments only — every dynamic value is a bind parameter.
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT m.source, count(*)::bigint AS n
                   FROM ({UNION_SQL}) m
                  GROUP BY m.source
                  ORDER BY n DESC, m.source"
            )))
            .bind(tenant)
            .bind(include_invalidated)
            .bind(f.kind.as_deref())
            .bind(Option::<&str>::None) // source: never filtered here
            .bind(f.entity.as_deref())
            .bind(f.q.as_deref())
            .bind(Option::<Uuid>::None)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?
            .iter()
            .map(|r| {
                Ok(MemorySourceCount {
                    source: r.try_get("source").map_err(db_err)?,
                    count: r.try_get("n").map_err(db_err)?,
                })
            })
            .collect::<Result<Vec<_>>>()?
        };

        Ok(MemoryBrowsePage {
            rows,
            sources,
            next_before,
            next_before_id,
        })
    }

    /// The COMPLETE set of DISTINCT canonical keys folded for a tenant, in
    /// stable order — the paginated/uncapped counterpart to
    /// `list_canonical_entities` used by the fold's §5 precondition (a). The
    /// browser read is capped for display; the fold's Tier-3 tagging must see
    /// EVERY prior canonical or it under-tags large tenants (a fail-closed
    /// under-tag, never a wrong tag). This is a DISTINCT-only projection — no
    /// members, no summaries, no badges — so it stays cheap even when the tenant
    /// has hundreds of thousands of canonicals, and it pages internally so no
    /// single statement materializes an unbounded result set. Worker/admin plane
    /// only; the recall/`get` read path never calls it.
    pub async fn all_canonical_keys(&self, tenant: TenantId) -> Result<Vec<String>> {
        // Keyset pagination over the DISTINCT canonical keys, ordered so the
        // `> $2` cursor is a strict, index-friendly advance. A single
        // `SELECT DISTINCT ... ORDER BY` would also be correct, but paging keeps
        // any one round trip bounded and lets a very large tenant stream.
        const PAGE: i64 = 10_000;
        let mut out: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let rows = sqlx::query(
                "SELECT DISTINCT canonical_entity
                   FROM entity_aliases
                  WHERE tenant_id = $1
                    AND ($2::text IS NULL OR canonical_entity > $2)
                  ORDER BY canonical_entity
                  LIMIT $3",
            )
            .bind(tenant)
            .bind(cursor.as_deref())
            .bind(PAGE)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
            if rows.is_empty() {
                break;
            }
            for r in &rows {
                out.push(r.try_get("canonical_entity").map_err(db_err)?);
            }
            // Advance the cursor to the last key of this page; a short page is
            // the final page.
            cursor = out.last().cloned();
            if (rows.len() as i64) < PAGE {
                break;
            }
        }
        Ok(out)
    }

    // ---------- admin principal-directory read (UI-ACTIONS N5) ----------

    /// One page of the tenant's principal directory (the `principals` table
    /// that POST /v1/admin/principals upserts into): `(principal, token)`
    /// pairs ordered by token, keyset-paginated with `token > after_token`.
    /// `limit` is clamped to 1..=1000. A tenant with no principals (or an
    /// unknown tenant) yields an empty page — a read discloses nothing and
    /// creates nothing. **Admin plane only; never on the recall/`get` path.**
    pub async fn list_principals(
        &self,
        tenant: TenantId,
        after_token: PrincipalToken,
        limit: i64,
    ) -> Result<Vec<(String, PrincipalToken)>> {
        let rows = sqlx::query(
            "SELECT principal, token
               FROM principals
              WHERE tenant_id = $1 AND token > $2
              ORDER BY token
              LIMIT $3",
        )
        .bind(tenant)
        .bind(after_token)
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("principal").map_err(db_err)?,
                    r.try_get("token").map_err(db_err)?,
                ))
            })
            .collect()
    }

    // ---------- admin debug-recall "why-out" trace (UI-SPEC §6 Later) ----------

    /// Candidate rows for the ADMIN debug-recall trace: the top-`limit` chunks
    /// by query similarity with ONLY the tenant filter applied — visibility,
    /// confidentiality, entity-scope, and `valid_to` are deliberately NOT
    /// filtered here, so the caller can evaluate each mandatory pre-filter
    /// per-candidate and report WHY a near-miss was excluded.
    ///
    /// **Never on the read path.** `recall` applies these filters inside the
    /// index as mandatory pre-filters and refuses this extra work; this method
    /// exists solely for the admin-gated, audited debug endpoint. Honesty
    /// bounds: the candidate set is a similarity top-N — a chunk that doesn't
    /// rank inside `limit` under the tenant-only ordering is not enumerable
    /// here, and everything is evaluated against the index AS OF NOW, not as of
    /// any past recall.
    ///
    /// Ranking legs mirror recall's: dense (cosine, honoring the tenant's
    /// embedding route) when an embedding is given, else BM25 over `content`.
    pub async fn debug_recall_candidates(
        &self,
        tenant: TenantId,
        embedding: Option<&[f32]>,
        text: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DebugCandidate>> {
        let rows = if let Some(embedding) = embedding {
            let col = match self.embedding_route(tenant).await? {
                EmbeddingRoute::V1 => "embedding",
                EmbeddingRoute::V2 => "embedding_v2",
            };
            // Safe: `col` is a validated constant; caller data goes through binds.
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT id, document_id, seq, content, visibility, entity_tags, kind,
                        confidentiality, acl_provenance, trust_tier, valid_from, valid_to,
                        provenance, 1 - ({col} <=> $1) AS score
                 FROM chunks
                 WHERE tenant_id = $2 AND {col} IS NOT NULL
                 ORDER BY {col} <=> $1
                 LIMIT $3",
            )))
            .bind(Vector::from(embedding.to_vec()))
            .bind(tenant)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?
        } else if let Some(text) = text {
            sqlx::query(
                "SELECT id, document_id, seq, content, visibility, entity_tags, kind,
                        confidentiality, acl_provenance, trust_tier, valid_from, valid_to,
                        provenance, paradedb.score(id) AS score
                 FROM chunks
                 WHERE id @@@ paradedb.match('content', $1)
                   AND tenant_id = $2
                 ORDER BY paradedb.score(id) DESC
                 LIMIT $3",
            )
            .bind(text)
            .bind(tenant)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?
        } else {
            return Err(StorageError::InvalidInput(
                "debug recall needs text or an embedding".into(),
            ));
        };
        rows.iter()
            .map(|row| {
                Ok(DebugCandidate {
                    chunk_id: row.try_get("id").map_err(db_err)?,
                    document_id: row.try_get("document_id").map_err(db_err)?,
                    seq: row.try_get("seq").map_err(db_err)?,
                    content: row.try_get("content").map_err(db_err)?,
                    score: row
                        .try_get::<f64, _>("score")
                        .map(|s| s as f32)
                        .or_else(|_| row.try_get::<f32, _>("score"))
                        .map_err(db_err)?,
                    visibility: row.try_get("visibility").map_err(db_err)?,
                    entity_tags: row.try_get("entity_tags").map_err(db_err)?,
                    kind: row.try_get("kind").map_err(db_err)?,
                    confidentiality: row.try_get("confidentiality").map_err(db_err)?,
                    acl_provenance: row.try_get("acl_provenance").map_err(db_err)?,
                    trust_tier: row.try_get("trust_tier").map_err(db_err)?,
                    valid_from: row.try_get("valid_from").map_err(db_err)?,
                    valid_to: row.try_get("valid_to").map_err(db_err)?,
                    provenance: row.try_get("provenance").map_err(db_err)?,
                })
            })
            .collect()
    }

    // ---------- Permission Graph (admin/operator plane, permission-graph-viz) ----------
    //
    // Every method below is ADMIN PLANE ONLY; never on the recall/`get` read
    // path (same contract as `list_principals` / `debug_recall_candidates`).
    // They may issue rich aggregate SQL and reverse token resolves the read
    // path is forbidden — that is the point of the admin plane.

    /// Resolve visibility tokens back to their principal strings (Endpoint 2,
    /// BUILD 4a). Reverse of the string→token query `admin_group_remove` runs.
    /// Index-backed by `principals` UNIQUE (tenant_id, token).
    ///
    /// **Admin plane only; never on the recall/`get` path.**
    pub async fn resolve_tokens(
        &self,
        tenant: TenantId,
        tokens: &[PrincipalToken],
    ) -> Result<Vec<(PrincipalToken, String)>> {
        let rows = sqlx::query(
            "SELECT token, principal FROM principals
              WHERE tenant_id = $1 AND token = ANY($2)",
        )
        .bind(tenant)
        .bind(tokens)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("token").map_err(db_err)?,
                    r.try_get("principal").map_err(db_err)?,
                ))
            })
            .collect()
    }

    /// Resolve principal strings to their materialized tokens (Endpoint 1
    /// closure → tokens). Same query `admin_group_remove` runs; principals with
    /// no materialized token simply do not appear (fail-closed: they contribute
    /// no visibility).
    ///
    /// **Admin plane only; never on the recall/`get` path.**
    pub async fn resolve_principals(
        &self,
        tenant: TenantId,
        principals: &[String],
    ) -> Result<Vec<(String, PrincipalToken)>> {
        let rows = sqlx::query(
            "SELECT principal, token FROM principals
              WHERE tenant_id = $1 AND principal = ANY($2)",
        )
        .bind(tenant)
        .bind(principals)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("principal").map_err(db_err)?,
                    r.try_get("token").map_err(db_err)?,
                ))
            })
            .collect()
    }

    /// In-window revoked tokens for a tenant, read straight from the
    /// `revocations` table (Endpoint 1, BUILD: inline parity with the read
    /// path's `RevocationPlane::subtract`). Re-implemented here rather than
    /// calling `scope_for`/`RevocationPlane` — the admin plane shares no code
    /// with the read-path helpers, but MUST apply the same subtraction so the
    /// aggregate neither over- nor under-states real access during a window.
    ///
    /// **Admin plane only; never on the recall/`get` path.**
    pub async fn windowed_revoked_tokens(
        &self,
        tenant: TenantId,
        window_secs: i64,
    ) -> Result<Vec<PrincipalToken>> {
        let rows = sqlx::query(
            "SELECT DISTINCT token FROM revocations
              WHERE tenant_id = $1 AND at > now() - make_interval(secs => $2)",
        )
        .bind(tenant)
        .bind(window_secs.max(0) as f64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| r.try_get("token").map_err(db_err))
            .collect()
    }

    /// The Endpoint-1 corpus aggregate: the visibility-authorized set — EXACTLY
    /// what recall pre-filters to before its ANN/embedding stage. Three
    /// `GROUP BY` counts (source / confidentiality / acl_provenance) plus a
    /// total, over the ENFORCEMENT pre-filter predicate (T1 parity baseline):
    ///
    /// ```text
    /// tenant_id = $1 AND visibility && $2 AND confidentiality <= $3 AND valid_to IS NULL
    /// ```
    ///
    /// Deliberately NOT recall's ANN-returnable shaping: no `{col} IS NOT NULL`
    /// embedding-presence filter, no entity_scope fence, no `kind` shaping —
    /// those shape what ANN can RETURN, not what is AUTHORIZED. `$2` is the
    /// POST-revocation token set (caller subtracts in-window revocations first).
    ///
    /// `include_facts` unions the identical predicate over `facts` (facts'
    /// `visibility` is nullable — a NULL visibility never overlaps, staying
    /// fail-closed). A `statement_timeout` is set on the transaction; on
    /// timeout the caller treats the counts as approximate.
    ///
    /// **Admin plane only; never on the recall/`get` path.**
    #[allow(clippy::too_many_arguments)]
    pub async fn access_corpus_aggregate(
        &self,
        tenant: TenantId,
        tokens: &[PrincipalToken],
        max_confidentiality: i16,
        include_facts: bool,
        timeout_ms: i64,
    ) -> Result<(AccessCorpus, bool)> {
        // Fail-closed: an empty token set overlaps nothing. Skip the scan
        // entirely and return an empty corpus (never "show everything").
        if tokens.is_empty() {
            return Ok((AccessCorpus::default(), false));
        }
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        // Bound the whole aggregate: on a low-selectivity company-wide token
        // set the GROUP BYs can seqscan. SET LOCAL reverts at COMMIT.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SET LOCAL statement_timeout = '{}'",
            timeout_ms.max(0)
        )))
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        // Facts union fragment: identical predicate; facts have no
        // document_id, so its docs count is DISTINCT (source,entity_id,field)
        // — but for the corpus rollup we only need chunk-vs-doc counts from
        // chunks; facts contribute chunk-equivalent rows only. To keep the
        // aggregate honest and simple we union facts as additional rows whose
        // "document" identity is (source||':'||entity_id||':'||field).
        let facts_total = if include_facts {
            "UNION ALL SELECT source, confidentiality, acl_provenance,
                    source || ':' || entity_id || ':' || field AS document_id
               FROM facts
              WHERE tenant_id = $1 AND visibility && $2
                AND confidentiality <= $3 AND valid_to IS NULL"
        } else {
            ""
        };

        let base = format!(
            "WITH rows AS (
                 SELECT source, confidentiality, acl_provenance, document_id
                   FROM chunks
                  WHERE tenant_id = $1 AND visibility && $2
                    AND confidentiality <= $3 AND valid_to IS NULL
                 {facts_total}
             )"
        );

        let total_row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "{base}
             SELECT count(*)::bigint AS chunks,
                    count(DISTINCT document_id)::bigint AS docs FROM rows"
        )))
        .bind(tenant)
        .bind(tokens)
        .bind(max_confidentiality)
        .fetch_one(&mut *tx)
        .await;

        // A statement-timeout surfaces as a DB error; treat it as "approximate"
        // rather than a hard failure — return what we have (empty) + the flag.
        let total_row = match total_row {
            Ok(r) => r,
            Err(e) if is_timeout(&e) => {
                let _ = tx.rollback().await;
                return Ok((AccessCorpus::default(), true));
            }
            Err(e) => return Err(db_err(e)),
        };

        // statement_timeout is per-statement and resets for each query, so each
        // GROUP BY gets the full budget independently. The plain total count(*)
        // above is the CHEAPEST query; the GROUP BY sort/hash aggregates are the
        // ones most likely to blow the budget on the exact scenario the guard
        // exists for (a low-selectivity company-wide token set). So a 57014 on
        // ANY of them must degrade to `approximate` (roll back, return partial)
        // — never surface as a hard 500 (spec §6/T8: never hang, never a hard
        // failure for the company-wide set). `is_timeout` is only meaningful if
        // consulted on these paths, not just on `total_row`.
        macro_rules! grouped_or_approx {
            ($q:expr) => {
                match $q.fetch_all(&mut *tx).await {
                    Ok(rows) => rows,
                    Err(e) if is_timeout(&e) => {
                        let _ = tx.rollback().await;
                        return Ok((AccessCorpus::default(), true));
                    }
                    Err(e) => return Err(db_err(e)),
                }
            };
        }

        let by_source = grouped_or_approx!(sqlx::query(sqlx::AssertSqlSafe(format!(
            "{base}
             SELECT source AS k, count(*)::bigint AS chunks,
                    count(DISTINCT document_id)::bigint AS docs
               FROM rows GROUP BY source ORDER BY chunks DESC"
        )))
        .bind(tenant)
        .bind(tokens)
        .bind(max_confidentiality));

        let by_conf = grouped_or_approx!(sqlx::query(sqlx::AssertSqlSafe(format!(
            "{base}
             SELECT confidentiality::int4 AS lvl, count(*)::bigint AS chunks,
                    count(DISTINCT document_id)::bigint AS docs
               FROM rows GROUP BY confidentiality ORDER BY lvl"
        )))
        .bind(tenant)
        .bind(tokens)
        .bind(max_confidentiality));

        let by_prov = grouped_or_approx!(sqlx::query(sqlx::AssertSqlSafe(format!(
            "{base}
             SELECT acl_provenance AS k, count(*)::bigint AS chunks,
                    count(DISTINCT document_id)::bigint AS docs
               FROM rows GROUP BY acl_provenance ORDER BY chunks DESC"
        )))
        .bind(tenant)
        .bind(tokens)
        .bind(max_confidentiality));

        match tx.commit().await {
            Ok(()) => {}
            Err(e) if is_timeout(&e) => return Ok((AccessCorpus::default(), true)),
            Err(e) => return Err(db_err(e)),
        }

        let corpus = AccessCorpus {
            total_chunks: total_row.try_get("chunks").map_err(db_err)?,
            total_docs: total_row.try_get("docs").map_err(db_err)?,
            by_source: by_source
                .iter()
                .map(|r| {
                    Ok(AccessGroupCount {
                        key: r.try_get("k").map_err(db_err)?,
                        level: None,
                        chunks: r.try_get("chunks").map_err(db_err)?,
                        docs: r.try_get("docs").map_err(db_err)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            by_confidentiality: by_conf
                .iter()
                .map(|r| {
                    Ok(AccessGroupCount {
                        key: String::new(),
                        level: Some(r.try_get("lvl").map_err(db_err)?),
                        chunks: r.try_get("chunks").map_err(db_err)?,
                        docs: r.try_get("docs").map_err(db_err)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            by_provenance: by_prov
                .iter()
                .map(|r| {
                    Ok(AccessGroupCount {
                        key: r.try_get("k").map_err(db_err)?,
                        level: None,
                        chunks: r.try_get("chunks").map_err(db_err)?,
                        docs: r.try_get("docs").map_err(db_err)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };
        // Reaching here means all four counts completed within the timeout.
        Ok((corpus, false))
    }

    /// Endpoint-1 documents page: raw live chunk rows on the STORED-column
    /// `(valid_from, id)` keyset (never an aggregate keyset — a `max(valid_from)`
    /// keyset would force a full GROUP BY re-scan of the whole visible corpus
    /// per page). GIN `visibility &&` is the primary narrowing. Metadata only
    /// — no `content` column is selected (NG2). The caller rolls up per-document
    /// WITHIN the page (page-local `n_chunks`/`min_confidentiality`); the
    /// authoritative per-document totals come from the aggregate above.
    ///
    /// **Admin plane only; never on the recall/`get` path.**
    pub async fn access_documents_page(
        &self,
        tenant: TenantId,
        tokens: &[PrincipalToken],
        max_confidentiality: i16,
        after: Option<(DateTime<Utc>, Uuid)>,
        chunk_page: i64,
    ) -> Result<Vec<AccessChunkRow>> {
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        // Keyset over stored (valid_from, id); a null cursor means "from the
        // top". `(valid_from, id) < ($ts, $id)` via a lexicographic compare
        // that also holds when the cursor is absent.
        let (after_ts, after_id, has_after) = match after {
            Some((ts, id)) => (ts, id, true),
            None => (Utc::now(), Uuid::nil(), false),
        };
        let rows = sqlx::query(
            "SELECT id, document_id, source, confidentiality::int4 AS confidentiality, valid_from
               FROM chunks
              WHERE tenant_id = $1 AND visibility && $2
                AND confidentiality <= $3 AND valid_to IS NULL
                AND (NOT $6 OR (valid_from, id) < ($4, $5))
              ORDER BY valid_from DESC, id DESC
              LIMIT $7",
        )
        .bind(tenant)
        .bind(tokens)
        .bind(max_confidentiality)
        .bind(after_ts)
        .bind(after_id)
        .bind(has_after)
        .bind(chunk_page.clamp(1, 5000))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok(AccessChunkRow {
                    id: r.try_get("id").map_err(db_err)?,
                    document_id: r.try_get("document_id").map_err(db_err)?,
                    source: r.try_get("source").map_err(db_err)?,
                    confidentiality: r.try_get("confidentiality").map_err(db_err)?,
                    valid_from: r.try_get("valid_from").map_err(db_err)?,
                })
            })
            .collect()
    }

    /// Endpoint-2 object → visibility tokens decode (BUILD 4c guards). Returns
    /// the DISTINCT visibility tokens over the object's live chunks, its
    /// min confidentiality, and the set of granting `acl_provenance` values.
    ///
    /// `document_id` mode is cheap (few chunks). `source`/`entity` mode is an
    /// UNBOUNDED FULL AGGREGATE SCAN (`source` has no index; `DISTINCT
    /// unnest(visibility)` scans every matching row's array): those are bounded
    /// by `SET LOCAL statement_timeout` and, above `corpus_ceiling` live chunks,
    /// REFUSED until a supporting index exists. On timeout, returns whatever was
    /// decoded with `approximate = true` rather than hanging a pooled connection.
    ///
    /// **Admin plane only; never on the recall/`get` path.**
    pub async fn access_object_tokens(
        &self,
        tenant: TenantId,
        selector: ObjectSelector<'_>,
        timeout_ms: i64,
        corpus_ceiling: i64,
    ) -> Result<AccessObjectDecode> {
        // The predicate + bind differ by mode; document_id is exempt from the
        // ceiling (few chunks), source/entity are gated.
        let (pred, bind_val): (&str, &str) = match selector {
            ObjectSelector::Document(id) => ("document_id = $2", id),
            ObjectSelector::Source(s) => ("source = $2", s),
            ObjectSelector::Entity(e) => ("entity_tags @> ARRAY[$2]", e),
        };
        let gated = !matches!(selector, ObjectSelector::Document(_));

        // All scans — including the ceiling COUNT — run inside ONE transaction
        // under `SET LOCAL statement_timeout`. Running the ceiling count outside
        // the timeout (on `&self.pool`) would leave the exact large tenant it
        // guards able to hang an unbounded, un-timed-out count on a full/large
        // scan (chunks has no `(tenant_id, valid_to)` index), holding a pooled
        // connection indefinitely — defeating the guard. Inside the tx, a 57014
        // on the count is itself proof the corpus is too big to decode safely,
        // so we fail closed to `refused_over_ceiling`.
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SET LOCAL statement_timeout = '{}'",
            timeout_ms.max(0)
        )))
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if gated {
            // Corpus-size ceiling: refuse the unbounded scan on a corpus larger
            // than we can decode safely without a supporting index. Timeout on
            // the count => the corpus is (at least) large enough to blow the
            // budget => refuse (fail closed), never fall through to the decode.
            let live_q =
                sqlx::query("SELECT count(*)::bigint AS n FROM chunks WHERE tenant_id = $1 AND valid_to IS NULL")
                    .bind(tenant)
                    .fetch_one(&mut *tx)
                    .await;
            let live: i64 = match live_q {
                Ok(r) => r.try_get("n").map_err(db_err)?,
                Err(e) if is_timeout(&e) => {
                    let _ = tx.rollback().await;
                    return Ok(AccessObjectDecode {
                        tokens: Vec::new(),
                        min_confidentiality: None,
                        provenance: Vec::new(),
                        approximate: false,
                        refused_over_ceiling: true,
                    });
                }
                Err(e) => return Err(db_err(e)),
            };
            if live > corpus_ceiling {
                let _ = tx.rollback().await;
                return Ok(AccessObjectDecode {
                    tokens: Vec::new(),
                    min_confidentiality: None,
                    provenance: Vec::new(),
                    approximate: false,
                    refused_over_ceiling: true,
                });
            }
        }

        let tokens_q = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT DISTINCT unnest(visibility) AS token FROM chunks
              WHERE tenant_id = $1 AND {pred} AND valid_to IS NULL"
        )))
        .bind(tenant)
        .bind(bind_val)
        .fetch_all(&mut *tx)
        .await;

        let token_rows = match tokens_q {
            Ok(rows) => rows,
            Err(e) if is_timeout(&e) => {
                let _ = tx.rollback().await;
                return Ok(AccessObjectDecode {
                    tokens: Vec::new(),
                    min_confidentiality: None,
                    provenance: Vec::new(),
                    approximate: true,
                    refused_over_ceiling: false,
                });
            }
            Err(e) => return Err(db_err(e)),
        };
        let tokens: Vec<PrincipalToken> = token_rows
            .iter()
            .map(|r| r.try_get("token").map_err(db_err))
            .collect::<Result<Vec<_>>>()?;

        let meta = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT min(confidentiality)::int4 AS minc,
                    array_agg(DISTINCT acl_provenance) AS provs
               FROM chunks WHERE tenant_id = $1 AND {pred} AND valid_to IS NULL"
        )))
        .bind(tenant)
        .bind(bind_val)
        .fetch_one(&mut *tx)
        .await;

        let (min_confidentiality, provenance) = match meta {
            Ok(r) => (
                r.try_get::<Option<i32>, _>("minc").map_err(db_err)?,
                r.try_get::<Option<Vec<String>>, _>("provs")
                    .map_err(db_err)?
                    .unwrap_or_default(),
            ),
            Err(e) if is_timeout(&e) => {
                let _ = tx.rollback().await;
                return Ok(AccessObjectDecode {
                    tokens,
                    min_confidentiality: None,
                    provenance: Vec::new(),
                    approximate: true,
                    refused_over_ceiling: false,
                });
            }
            Err(e) => return Err(db_err(e)),
        };

        tx.commit().await.map_err(db_err)?;
        Ok(AccessObjectDecode {
            tokens,
            min_confidentiality,
            provenance,
            approximate: false,
            refused_over_ceiling: false,
        })
    }

    /// Append one Permission Graph audit row (migration 0034). Append-only:
    /// INSERT only. `result_meta` carries counts, never content (NG2).
    ///
    /// **Admin plane only; never on the recall/`get` path.**
    pub async fn write_access_audit(
        &self,
        tenant: TenantId,
        actor: &str,
        endpoint: &str,
        query_target: &str,
        params: &serde_json::Value,
        result_meta: &serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO admin_access_audit
                 (id, tenant_id, actor, endpoint, query_target, params, result_meta)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(actor)
        .bind(endpoint)
        .bind(query_target)
        .bind(params)
        .bind(result_meta)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    // ---------- quarantine lifecycle (UI-SPEC §5 Screen 6 write surface) ----------

    /// One quarantined payload with its lifecycle disposition (0023). `None`
    /// resolution = open/awaiting triage.
    pub async fn quarantine_item(
        &self,
        tenant: TenantId,
        id: Uuid,
    ) -> Result<Option<QuarantineRow>> {
        let row = sqlx::query(
            "SELECT id, webhook_id, payload, reason, at, resolution, resolved_at, resolution_note
             FROM quarantine_preview WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|row| {
            Ok(QuarantineRow {
                id: row.try_get("id").map_err(db_err)?,
                webhook_id: row.try_get("webhook_id").map_err(db_err)?,
                payload: row.try_get("payload").map_err(db_err)?,
                reason: row.try_get("reason").map_err(db_err)?,
                at: row.try_get("at").map_err(db_err)?,
                resolution: row.try_get("resolution").map_err(db_err)?,
                resolved_at: row.try_get("resolved_at").map_err(db_err)?,
                resolution_note: row.try_get("resolution_note").map_err(db_err)?,
            })
        })
        .transpose()
    }

    /// Atomically claim an OPEN quarantine row with a terminal disposition
    /// (`reingested` | `dismissed`). Returns false when the row is missing or
    /// already resolved (the WHERE `resolution IS NULL` guard makes a concurrent
    /// double-claim lose cleanly). Invalidate-don't-delete: the payload row
    /// survives for audit; only its disposition is stamped.
    pub async fn resolve_quarantine(
        &self,
        tenant: TenantId,
        id: Uuid,
        resolution: &str,
        note: Option<&str>,
    ) -> Result<bool> {
        if resolution != "reingested" && resolution != "dismissed" {
            return Err(StorageError::InvalidInput(format!(
                "invalid quarantine resolution {resolution:?} (reingested|dismissed)"
            )));
        }
        let done = sqlx::query(
            "UPDATE quarantine_preview
             SET resolution = $3, resolved_at = now(), resolution_note = $4
             WHERE tenant_id = $1 AND id = $2 AND resolution IS NULL",
        )
        .bind(tenant)
        .bind(id)
        .bind(resolution)
        .bind(note)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(done.rows_affected() > 0)
    }

    /// Revert a claimed quarantine row to OPEN — the compensation path when a
    /// re-ingest fails AFTER the claim (claim-first prevents double-ingest
    /// races; this puts the item back in the triage queue on failure).
    pub async fn reopen_quarantine(&self, tenant: TenantId, id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE quarantine_preview
             SET resolution = NULL, resolved_at = NULL, resolution_note = NULL
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// A light `name`/`domain` summary over a canonical's members (§4.3): the
    /// first current (`valid_to IS NULL`) `name`/`domain` fact found on any
    /// member, in stable `(source, entity_id)` order. This is a display hint for
    /// the browser — NOT the precedence-resolved truth, which stays in
    /// `merged_record`. Empty when no member carries either field.
    pub async fn member_field_summary(
        &self,
        tenant: TenantId,
        members: &[AliasMember],
    ) -> Result<EntityFieldSummary> {
        if members.is_empty() {
            return Ok(EntityFieldSummary::default());
        }
        let sources: Vec<String> = members.iter().map(|m| m.source.clone()).collect();
        let entity_ids: Vec<String> = members.iter().map(|m| m.entity_id.clone()).collect();
        // Match on the (source, entity_id) pairs via UNNEST-zipped arrays (same
        // fence merged_record uses) so member A/X never picks up B/X. Deterministic
        // order so the chosen name/domain is stable across calls.
        //
        // Matched on the CONCATENATION, not the exact pair: alias members come
        // from `split_member_ref`, which splits the ambiguous ref grammar on
        // the FIRST `:` — but Debezium sources contain `:`, so the member pair
        // ("hubspot", "crm.companies:hs-77") disagrees with the fact pair
        // ("hubspot:crm.companies", "hs-77") for the same entity. The composed
        // ref is identical either way, so equality on it is exact (the same
        // fix ref_field_summary got on 2026-07-11; entities browser showed
        // name:null for entities whose name facts existed, 2026-07-12).
        let rows = sqlx::query(
            "SELECT f.field, f.value FROM facts f
               JOIN unnest($2::text[], $3::text[]) AS m(source, entity_id)
                 ON f.source || ':' || f.entity_id = m.source || ':' || m.entity_id
              WHERE f.tenant_id = $1 AND f.valid_to IS NULL
                AND f.field IN ('name', 'domain')
              ORDER BY f.field, f.source, f.entity_id",
        )
        .bind(tenant)
        .bind(&sources)
        .bind(&entity_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let mut summary = EntityFieldSummary::default();
        for r in &rows {
            let field: String = r.try_get("field").map_err(db_err)?;
            let value: serde_json::Value = r.try_get("value").map_err(db_err)?;
            let scalar = json_scalar_string(&value);
            match field.as_str() {
                "name" if summary.name.is_none() => summary.name = scalar,
                "domain" if summary.domain.is_none() => summary.domain = scalar,
                _ => {}
            }
        }
        Ok(summary)
    }

    /// Resolve a ledger REF (`source:entity_id`) to the canonical it currently
    /// belongs to, for the decide-response (§4.2 S4). Splits on the FIRST `:`
    /// (matching `split_member_ref`), looks up `entity_aliases`, and falls back
    /// to the ref itself when unmapped (an unmapped entity is its own canonical —
    /// "annoying, never wrong"). Non-member refs (`key:*`/`chunk:*`) and
    /// malformed refs also fall back to the ref as-is.
    pub async fn resolve_canonical_for_ref(&self, tenant: TenantId, reff: &str) -> Result<String> {
        if reff.starts_with("key:") || reff.starts_with("chunk:") {
            return Ok(reff.to_string());
        }
        let Some((source, entity_id)) = reff.split_once(':') else {
            return Ok(reff.to_string());
        };
        if source.is_empty() || entity_id.is_empty() {
            return Ok(reff.to_string());
        }
        Ok(self
            .resolve_canonical(tenant, source, entity_id)
            .await?
            .unwrap_or_else(|| reff.to_string()))
    }

    /// The light `name`/`domain` summary for a single ledger REF
    /// (`source:entity_id`) — the review-queue side-by-side needs each candidate
    /// ref's member fields (§4.3 review enrichment). Non-member refs (`key:*`,
    /// `chunk:*`, malformed) yield an empty summary.
    ///
    /// The ref grammar is ambiguous from the string alone: SOURCES may contain
    /// `:` (Debezium sources are `connector:db.table`, so a ref reads
    /// `hubspot:crm.companies:hs-88`) AND entity_ids may contain `:`. So we
    /// don't guess the split — we match the concatenation directly in SQL
    /// (`source || ':' || entity_id = ref`), which is exact for however the
    /// ref was composed. This fixed the review queue showing "no name on
    /// record" for refs whose facts existed all along (2026-07-11).
    pub async fn ref_field_summary(
        &self,
        tenant: TenantId,
        reff: &str,
    ) -> Result<EntityFieldSummary> {
        if reff.starts_with("key:") || reff.starts_with("chunk:") || !reff.contains(':') {
            return Ok(EntityFieldSummary::default());
        }
        let rows = sqlx::query(
            "SELECT field, value FROM facts
              WHERE tenant_id = $1
                AND source || ':' || entity_id = $2
                AND valid_to IS NULL
                AND lower(field) IN ('name', 'domain', 'website')",
        )
        .bind(tenant)
        .bind(reff)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        let mut out = EntityFieldSummary::default();
        for row in rows {
            let field: String = row.try_get("field").map_err(db_err)?;
            let value: serde_json::Value = row.try_get("value").map_err(db_err)?;
            let text = value
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| value.to_string());
            match field.to_lowercase().as_str() {
                "name" => out.name = Some(text),
                // Website URLs read fine as a domain summary line.
                "domain" | "website" => out.domain = Some(text),
                _ => {}
            }
        }
        Ok(out)
    }

    /// The cross-source merged entity view (SPEC §7f). Gathers every current
    /// fact (`valid_to IS NULL`) across all (source, entity_id) members aliased
    /// to `canonical`, then resolves each field to the value of the
    /// highest-precedence source that has a current fact for it. When
    /// `canonical` has no aliases at all, it is treated as its own single
    /// member `(source=?, entity_id=canonical)` — but since we cannot know the
    /// source of an unmapped key, the unmapped case is served over any facts
    /// whose `entity_id == canonical` directly (annoying-never-wrong: an
    /// unmapped entity merges over just its own source rows).
    ///
    /// Precedence resolution per field is most-specific-wins:
    ///   (canonical, field)  →  (canonical, '*')  →  ('*', '*')  →  none.
    /// A source absent from the resolved order ranks after all listed sources;
    /// ties (including the no-precedence-config case) break by most-recent
    /// `valid_from`, then by source name — fully deterministic.
    /// Scoped cross-source merged view (SPEC §7f). Precedence resolves over
    /// caller-VISIBLE facts ONLY — an invisible higher-precedence fact must never
    /// win a field (its winning value would leak) nor appear as a
    /// `superseded_alternative`. Two callers with different scopes may therefore
    /// see a different winning source for the same field: correct, if surprising.
    /// The admin plane calls `merged_record_admin` (no visibility predicate).
    pub async fn merged_record(&self, scope: &Scope, canonical: &str) -> Result<MergedRecord> {
        self.merged_record_inner(scope.tenant_id, canonical, Some(scope))
            .await
    }

    /// Admin-plane merged view: resolves over EVERY fact regardless of
    /// visibility. Bearer-gated at the handler; NEVER reachable from an agent
    /// scope handle (there is no scope argument to smuggle a bypass through).
    /// For DSAR export / the admin entities browser / audit.
    pub async fn merged_record_admin(
        &self,
        tenant: TenantId,
        canonical: &str,
    ) -> Result<MergedRecord> {
        self.merged_record_inner(tenant, canonical, None).await
    }

    /// Shared merged-view body. `scope = Some` applies the visibility
    /// pre-filter (scoped handler); `None` is the admin-all plane. All three
    /// fact-gather queries filter BEFORE precedence runs so an invisible fact
    /// influences neither the winner nor the alternatives list.
    async fn merged_record_inner(
        &self,
        tenant: TenantId,
        canonical: &str,
        scope: Option<&Scope>,
    ) -> Result<MergedRecord> {
        // A scoped read with no principals is fail-closed: nothing is visible.
        if let Some(s) = scope {
            if s.principals.is_empty() {
                return Ok(MergedRecord {
                    tenant_id: tenant,
                    canonical_entity: canonical.to_string(),
                    members: Vec::new(),
                    fields: std::collections::BTreeMap::new(),
                });
            }
        }

        // 1. Resolve members. Explicit aliases win; else the unmapped fallback
        //    (any facts keyed directly on `canonical` as entity_id).
        let members = self.list_entity_aliases(tenant, canonical).await?;

        // 2. Gather current facts for those members (or the unmapped fallback),
        //    filtered to caller-visible rows when scoped.
        let mut fact_rows: Vec<FactRow> = if members.is_empty() {
            let (vis_pred, entity_ids) = match scope {
                Some(s) => (
                    "AND visibility && $3 AND confidentiality <= $4",
                    Some((s.principals.clone(), s.max_confidentiality as i16)),
                ),
                None => ("", None),
            };
            let sql = format!(
                "SELECT * FROM facts
                 WHERE tenant_id = $1 AND entity_id = $2 AND valid_to IS NULL {vis_pred}"
            );
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(tenant)
                .bind(canonical);
            if let Some((principals, max_conf)) = &entity_ids {
                q = q.bind(principals).bind(max_conf);
            }
            let rows = q.fetch_all(&self.pool).await.map_err(db_err)?;
            rows.iter().map(row_to_fact).collect::<Result<_>>()?
        } else {
            let sources: Vec<String> = members.iter().map(|m| m.source.clone()).collect();
            let entity_ids: Vec<String> = members.iter().map(|m| m.entity_id.clone()).collect();
            // Match on the (source, entity_id) pairs via UNNEST-zipped arrays so
            // a member of source A / entity X never picks up source B / entity X.
            // Concatenation equality, not exact-pair: alias members carry the
            // first-colon split of the ambiguous ref grammar, which disagrees
            // with the fact pair whenever the source contains `:` (Debezium's
            // `connector:db.table`). The composed ref matches exactly for
            // however the split fell — see member_field_summary for the full
            // story. Without this, the MERGED record silently dropped every
            // colon-source member's fields.
            let vis_pred = match scope {
                Some(_) => "AND f.visibility && $4 AND f.confidentiality <= $5",
                None => "",
            };
            let sql = format!(
                "SELECT f.* FROM facts f
                 JOIN unnest($2::text[], $3::text[]) AS m(source, entity_id)
                   ON f.source || ':' || f.entity_id = m.source || ':' || m.entity_id
                 WHERE f.tenant_id = $1 AND f.valid_to IS NULL {vis_pred}"
            );
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(tenant)
                .bind(&sources)
                .bind(&entity_ids);
            if let Some(s) = scope {
                q = q.bind(&s.principals).bind(s.max_confidentiality as i16);
            }
            let rows = q.fetch_all(&self.pool).await.map_err(db_err)?;
            rows.iter().map(row_to_fact).collect::<Result<_>>()?
        };

        // Entity-scope fence (scoped only): a fact's entity IS its key, so drop
        // any gathered row whose entity_id is outside a non-empty entity_scope.
        // Mirrors the Rust short-circuit in current_fact/fact_as_of.
        if let Some(s) = scope {
            if !s.entity_scope.is_empty() {
                fact_rows.retain(|f| s.entity_scope.contains(&f.key.entity_id));
            }
        }

        // 3. Load precedence config for this canonical + the defaults.
        let prec = self.load_precedence(tenant, canonical).await?;

        // 4. Group facts by field, resolve each independently.
        let mut by_field: HashMap<String, Vec<FactRow>> = HashMap::new();
        for f in fact_rows {
            by_field.entry(f.key.field.clone()).or_default().push(f);
        }

        let mut fields: std::collections::BTreeMap<String, MergedField> =
            std::collections::BTreeMap::new();
        for (field, mut facts) in by_field {
            let order = prec.resolve(&field);
            // Deterministic ranking: precedence index (lower wins), then
            // most-recent valid_from, then source name.
            facts.sort_by(|a, b| {
                let ra = precedence_rank(&order, &a.key.source);
                let rb = precedence_rank(&order, &b.key.source);
                ra.cmp(&rb)
                    .then_with(|| b.valid_from.cmp(&a.valid_from))
                    .then_with(|| a.key.source.cmp(&b.key.source))
                    .then_with(|| a.key.entity_id.cmp(&b.key.entity_id))
            });
            let winner = &facts[0];
            let superseded_alternatives = facts[1..]
                .iter()
                .map(|f| MergedAlternative {
                    source: f.key.source.clone(),
                    value: f.value.clone(),
                    entity_id: f.key.entity_id.clone(),
                    valid_from: f.valid_from,
                    provenance: f.provenance,
                })
                .collect();
            fields.insert(
                field,
                MergedField {
                    value: winner.value.clone(),
                    winning_source: winner.key.source.clone(),
                    winning_entity_id: winner.key.entity_id.clone(),
                    valid_from: winner.valid_from,
                    provenance: winner.provenance,
                    superseded_alternatives,
                },
            );
        }

        // Members for the response: the alias set, or the unmapped self-member.
        let out_members = if members.is_empty() {
            Vec::new()
        } else {
            members
        };

        Ok(MergedRecord {
            tenant_id: tenant,
            canonical_entity: canonical.to_string(),
            members: out_members,
            fields,
        })
    }

    /// Load the precedence rows relevant to `canonical` (its specific rows plus
    /// the '*' defaults) into a resolver. One round trip.
    async fn load_precedence(&self, tenant: TenantId, canonical: &str) -> Result<PrecedenceConfig> {
        let rows = sqlx::query(
            "SELECT canonical_entity, field, source_order FROM entity_precedence
             WHERE tenant_id = $1 AND canonical_entity IN ($2, '*')",
        )
        .bind(tenant)
        .bind(canonical)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        let mut cfg = PrecedenceConfig::default();
        for r in &rows {
            let c: String = r.try_get("canonical_entity").map_err(db_err)?;
            let field: String = r.try_get("field").map_err(db_err)?;
            let order: Vec<String> = r.try_get("source_order").map_err(db_err)?;
            cfg.insert(&c, &field, canonical, order);
        }
        Ok(cfg)
    }

    /// Below this many matching rows, brute-force distance over the filtered
    /// subset beats HNSW iterative traversal (measured at 1M chunks: exact
    /// 11ms vs HNSW 72ms p50 at 1% selectivity — docs/BENCHMARKS.md). The
    /// probe that decides is capped at this bound, so broad scopes pay a few
    /// bounded milliseconds, not a full count.
    const EXACT_SCAN_MAX_ROWS: i64 = 20_000;

    /// HNSW candidate-list size for the broad-scope (HNSW) branch. pgvector's
    /// default is 40, which — measured on the 115k-chunk my-workspace corpus at
    /// broad (union-of-all-tokens) scope — silently returns recall@8 = 0/8: the
    /// dense single-token cluster gives the graph a poor entry point and the
    /// small candidate list never reaches the true neighbours. There is a sharp
    /// recall cliff (0/8 at ef<=150, 8/8 at ef>=200, docs/BENCHMARKS.md), so 200
    /// is the *minimum proven* value for full recall — not a magic number. Cost:
    /// broad-scope p50 ~0.3ms(wrong)->~2.5ms(correct), still ~40x under the
    /// ~106ms exact baseline. The exact/small-set branch never touches HNSW, so
    /// this GUC only applies where the planner actually chooses the graph.
    const HNSW_EF_SEARCH: i64 = 200;

    async fn recall_dense(&self, q: &RecallQuery, embedding: &[f32]) -> Result<Vec<RecallHit>> {
        let scope = &q.scope;
        // Query-routing cutover (SPEC §5c step 2): once a tenant's route is
        // flipped to V2, the dense leg searches the `embedding_v2` named vector
        // and its HNSW index. Chunks not yet backfilled (embedding_v2 IS NULL)
        // fall out of the dense leg — sparse/BM25 still covers them, exactly as
        // SPEC §5c's "uncovered chunks fall back to sparse-only for the new
        // route" describes. Column name is a validated constant, never caller
        // data.
        let col = match self.embedding_route(scope.tenant_id).await? {
            EmbeddingRoute::V1 => "embedding",
            EmbeddingRoute::V2 => "embedding_v2",
        };
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        // Selectivity router: ask the planner for its row estimate (pure
        // planning, no scan — an actual count via GIN builds the full bitmap
        // before LIMIT and costs ~100ms on broad scopes), then pick the
        // winning plan. The 1–10% selectivity band is where HNSW-under-filter
        // collapses (the "valley", docs/BENCHMARKS.md finding 2). Estimates
        // come from pg_stats' most_common_elems on the visibility array;
        // order-of-magnitude accuracy is all the routing decision needs.
        let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (FORMAT JSON) SELECT 1 FROM chunks
             WHERE tenant_id = $1
               AND valid_to IS NULL
               AND {col} IS NOT NULL
               AND visibility && $2
               AND confidentiality <= $3
               {}",
            entity_scope_predicate(scope, "$4"),
        )))
        .bind(scope.tenant_id)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .bind(&scope.entity_scope)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        let estimated_rows = plan[0]["Plan"]["Plan Rows"].as_i64().unwrap_or(i64::MAX);

        if estimated_rows <= Self::EXACT_SCAN_MAX_ROWS {
            // Small filtered set: exact top-k over it (perfect recall, and
            // faster than graph traversal under selective filters). M0: count
            // the fallback so `/metrics` can expose how often the exact branch
            // runs (cheap Relaxed add on the optional shared counter).
            if let Some(c) = &self.exact_scan_fallback {
                c.fetch_add(1, Ordering::Relaxed);
            }
            sqlx::query("SET LOCAL enable_indexscan = off")
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        } else {
            // Broad set: HNSW. Two GUCs, both SET LOCAL so they revert at
            // tx.commit() and can never leak onto the next pooled checkout
            // (max_connections=16; the whole recall runs in this one tx).
            //
            // (1) ef_search: pgvector's default 40 silently drops recall to 0/8
            //     on the 115k corpus at broad scope — a live correctness bug.
            //     HNSW_EF_SEARCH=200 is the measured minimum for recall@8 = 1.0.
            //     The literal is an i64 const (never caller data), so the format!
            //     is SQL-safe by the same argument as the predicate strings.
            // (2) iterative_scan=strict_order: keeps HNSW re-pulling candidates
            //     until k pass the mandatory scope pre-filter, WITHOUT the
            //     mis-ordering/recall risk of relaxed_order (pgvector #862).
            //     strict_order preserves distance ordering; measured cost here
            //     is ~zero because the planner already picks HNSW when the
            //     filter is non-selective.
            //
            // Neither GUC changes WHAT is allowed: tenant_id / valid_to IS NULL
            // / visibility && $scope / confidentiality <= ceiling (+ entity
            // fence) remain HARD pre-filters on the ranked SELECT below. These
            // only change HOW the ANN is scanned.
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "SET LOCAL hnsw.ef_search = {}",
                Self::HNSW_EF_SEARCH
            )))
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            sqlx::query("SET LOCAL hnsw.iterative_scan = strict_order")
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        }
        // Safe: the predicate string is assembled from constants only; all
        // caller data goes through binds.
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id, document_id, seq, content, entity_tags, kind, support_tier, acl_provenance, trust_tier, valid_from, provenance,
                    1 - ({col} <=> $1) AS score
             FROM chunks
             WHERE tenant_id = $2
               AND valid_to IS NULL
               AND {col} IS NOT NULL
               AND visibility && $3
               AND confidentiality <= $4
               {}
             ORDER BY {col} <=> $1
             LIMIT $5",
            entity_scope_predicate(scope, "$6"),
        )))
        .bind(Vector::from(embedding.to_vec()))
        .bind(scope.tenant_id)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .bind(q.k as i64)
        .bind(&scope.entity_scope)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        rows.iter().map(row_to_hit).collect()
    }

    async fn recall_bm25(&self, q: &RecallQuery, text: &str) -> Result<Vec<RecallHit>> {
        let scope = &q.scope;
        // Visibility rides INTO the Tantivy query: `&&` is not a pushable
        // operator for pg_search, and heap-filtering the raw match set costs
        // ~280ms at 1M rows (docs/BENCHMARKS.md finding 3). term_set on the
        // int[] fast field has exact overlap semantics — and matches nothing
        // for an empty principal array, preserving fail-closed. tenant/
        // confidentiality/valid_to push down as indexed scalars (0004).
        // Entity-bound scopes pre-filter INSIDE Tantivy: term_set on the
        // keyword-tokenized entity_tags field is any-overlap — a superset of
        // the required subset semantics — with the §7g knowledge carve-out
        // OR'd in on the indexed kind field. The exact `<@` residual check
        // runs over a MATERIALIZED candidate set that is bounded by the
        // entity's own chunk count (never the corpus), because mixing the
        // residual into the @@@ query breaks the TopK plan and heap-scans the
        // full match set (measured 542ms p50; docs/BENCHMARKS.md). This is
        // filter-then-rank, never truncate-then-authorize.
        let sql = if scope.entity_scope.is_empty() {
            "SELECT id, document_id, seq, content, entity_tags, kind, support_tier, acl_provenance, trust_tier, valid_from, provenance,
                    paradedb.score(id) AS score
             FROM chunks
             WHERE id @@@ paradedb.match('content', $1)
               AND id @@@ paradedb.term_set('visibility', $3)
               AND tenant_id = $2
               AND valid_to IS NULL
               AND confidentiality <= $4
             ORDER BY paradedb.score(id) DESC
             LIMIT $5"
                .to_string()
        } else {
            "WITH cand AS MATERIALIZED (
                 SELECT id, paradedb.score(id) AS score
                 FROM chunks
                 WHERE id @@@ paradedb.match('content', $1)
                   AND id @@@ paradedb.term_set('visibility', $3)
                   AND id @@@ paradedb.boolean(should => ARRAY[
                           paradedb.term_set('entity_tags', $6),
                           paradedb.term('kind', 'knowledge')
                       ])
                   AND tenant_id = $2
                   AND valid_to IS NULL
                   AND confidentiality <= $4
             )
             SELECT c.id, document_id, seq, content, entity_tags, kind, support_tier, acl_provenance, trust_tier, valid_from, provenance,
                    cand.score AS score
             FROM cand JOIN chunks c ON c.id = cand.id
             WHERE (c.kind = 'knowledge'
                    OR (c.entity_tags <> '{}' AND c.entity_tags <@ $6))
             ORDER BY cand.score DESC
             LIMIT $5"
                .to_string()
        };
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(text)
            .bind(scope.tenant_id)
            .bind(&scope.principals)
            .bind(scope.max_confidentiality as i16)
            .bind(q.k as i64)
            .bind(&scope.entity_scope)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.iter().map(row_to_hit).collect()
    }
}

/// Entity scoping, deny-by-default (SPEC §7d): in an entity-bound scope a chunk
/// is retrievable only when its tags are non-empty and a subset of the scope's
/// entity set; zero-tag content is excluded. The one verified exception (§7g):
/// `kind = 'knowledge'` chunks — positively entity-free, published through the
/// de-identification gates — are admitted into entity-bound scopes.
fn entity_scope_predicate(scope: &Scope, bind: &str) -> String {
    if scope.entity_scope.is_empty() {
        String::new()
    } else {
        format!("AND (kind = 'knowledge' OR (entity_tags <> '{{}}' AND entity_tags <@ {bind}))")
    }
}

fn row_to_hit(row: &PgRow) -> Result<RecallHit> {
    Ok(RecallHit {
        chunk_id: row.try_get("id").map_err(db_err)?,
        document_id: row.try_get("document_id").map_err(db_err)?,
        seq: row.try_get("seq").map_err(db_err)?,
        content: row.try_get("content").map_err(db_err)?,
        score: row
            .try_get::<f64, _>("score")
            .map(|s| s as f32)
            .or_else(|_| row.try_get::<f32, _>("score"))
            .map_err(db_err)?,
        entity_tags: row.try_get("entity_tags").map_err(db_err)?,
        kind: row.try_get("kind").map_err(db_err)?,
        // Only kind='knowledge' chunks carry a stored tier (set at publish,
        // recomputed on support accrual); content chunks are NULL. Parse it
        // leniently — an unknown string reads as "no tier disclosed" rather
        // than failing the read.
        support_tier: row
            .try_get::<Option<String>, _>("support_tier")
            .ok()
            .flatten()
            .and_then(|s| support_tier_from_str(&s)),
        acl_provenance: AclProvenance::from_str_lossy(
            &row.try_get::<String, _>("acl_provenance").map_err(db_err)?,
        ),
        trust_tier: tier_from_i16(row.try_get("trust_tier").map_err(db_err)?),
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        provenance: row.try_get("provenance").map_err(db_err)?,
    })
}

fn support_tier_from_str(s: &str) -> Option<SupportTier> {
    match s {
        "emerging" => Some(SupportTier::Emerging),
        "established" => Some(SupportTier::Established),
        "extensive" => Some(SupportTier::Extensive),
        _ => None,
    }
}

fn row_to_knowledge(row: &PgRow) -> Result<KnowledgeItem> {
    let status = match row.try_get::<String, _>("status").map_err(db_err)?.as_str() {
        "candidate" => KnowledgeStatus::Candidate,
        "quarantined" => KnowledgeStatus::Quarantined,
        "eligible" => KnowledgeStatus::Eligible,
        "published" => KnowledgeStatus::Published,
        "rejected" => KnowledgeStatus::Rejected,
        _ => KnowledgeStatus::Invalidated,
    };
    let distinct_entities: i32 = row.try_get("distinct_entities").map_err(db_err)?;
    Ok(KnowledgeItem {
        id: row.try_get("id").map_err(db_err)?,
        statement: row.try_get("statement").map_err(db_err)?,
        categories: row.try_get("categories").map_err(db_err)?,
        status,
        quarantine_reason: row.try_get("quarantine_reason").map_err(db_err)?,
        distinct_entities,
        support_tier: SupportTier::from_distinct(distinct_entities),
        episode_count: row.try_get("episode_count").map_err(db_err)?,
        writer_count: row.try_get("writer_count").map_err(db_err)?,
        has_tier1_evidence: row.try_get("has_tier1_evidence").map_err(db_err)?,
        merge_reason: row.try_get("merge_reason").map_err(db_err)?,
        first_seen: row.try_get("first_seen").map_err(db_err)?,
        last_reinforced: row.try_get("last_reinforced").map_err(db_err)?,
        published_at: row.try_get("published_at").map_err(db_err)?,
    })
}

fn tier_from_i16(v: i16) -> TrustTier {
    if v == 1 {
        TrustTier::Authoritative
    } else {
        TrustTier::Observation
    }
}

pub(crate) fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// Continuous-sync interval floor (seconds) — mirrors the `sync_schedules`
/// `CHECK interval_secs >= 60`. Enforced in `upsert_sync_schedule_impl` so a
/// sub-floor interval returns a clean `InvalidInput` (→ 422) rather than a raw
/// constraint-violation from the DB. A schedule tighter than this is never armed.
pub const SYNC_INTERVAL_FLOOR_SECS: i32 = 60;

/// Map a `sync_schedules` row to a [`SyncSchedule`].
fn sync_schedule_from_row(row: &PgRow) -> Result<SyncSchedule> {
    Ok(SyncSchedule {
        tenant_id: row.try_get("tenant_id").map_err(db_err)?,
        source: row.try_get("source").map_err(db_err)?,
        interval_secs: row.try_get("interval_secs").map_err(db_err)?,
        enabled: row.try_get("enabled").map_err(db_err)?,
        last_run_at: row.try_get("last_run_at").map_err(db_err)?,
        created_at: row.try_get("created_at").map_err(db_err)?,
        updated_at: row.try_get("updated_at").map_err(db_err)?,
    })
}

/// Reciprocal-rank fusion of the dense and sparse result lists.
fn rrf_fuse(lists: Vec<Vec<RecallHit>>, k: usize) -> Vec<RecallHit> {
    const RRF_K: f32 = 60.0;
    let mut scores: HashMap<Uuid, (f32, RecallHit)> = HashMap::new();
    for list in lists {
        for (rank, hit) in list.into_iter().enumerate() {
            let contribution = 1.0 / (RRF_K + rank as f32 + 1.0);
            scores
                .entry(hit.chunk_id)
                .and_modify(|(s, _)| *s += contribution)
                .or_insert((contribution, hit));
        }
    }
    let mut fused: Vec<(f32, RecallHit)> = scores.into_values().collect();
    fused.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    fused
        .into_iter()
        .take(k)
        .map(|(score, mut hit)| {
            hit.score = score;
            hit
        })
        .collect()
}

#[async_trait]
impl StorageAdapter for PostgresAdapter {
    async fn create_tenant(&self, name: &str) -> Result<TenantId> {
        let id = Uuid::now_v7();
        let row = sqlx::query(
            "INSERT INTO tenants (id, name) VALUES ($1, $2)
             ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
             RETURNING id",
        )
        .bind(id)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row.try_get("id").map_err(db_err)
    }

    /// Tenant directory (FTUE §2.1): oldest first so the dev/first tenant
    /// heads the console picker; id is the tiebreak for a stable order.
    async fn list_tenants(&self, limit: i64) -> Result<Vec<TenantRow>> {
        let rows = sqlx::query(
            // Newest FIRST: a picker on a long-lived dev db (5,500 test tenants
            // observed) must surface what was just created, not 2-month-old
            // suite debris. Found via founder report: "created a tenant, it
            // doesn't show up in the menu" — it was row 5,500 of an ASC page.
            "SELECT id, name, created_at FROM tenants ORDER BY created_at DESC, id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|row| {
                Ok(TenantRow {
                    tenant_id: row.try_get("id").map_err(db_err)?,
                    name: row.try_get("name").map_err(db_err)?,
                    created_at: row.try_get("created_at").map_err(db_err)?,
                })
            })
            .collect()
    }

    async fn count_tenants(&self) -> Result<i64> {
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM tenants")
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(n)
    }

    async fn get_tenant(&self, tenant: TenantId) -> Result<Option<TenantRow>> {
        let row = sqlx::query("SELECT id, name, created_at FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(|r| {
            Ok(TenantRow {
                tenant_id: r.try_get("id").map_err(db_err)?,
                name: r.try_get("name").map_err(db_err)?,
                created_at: r.try_get("created_at").map_err(db_err)?,
            })
        })
        .transpose()
    }

    async fn append_episode(&self, ep: NewEpisode) -> Result<EpisodeId> {
        let id = Uuid::now_v7();
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        self.insert_episode_tx(&mut tx, id, &ep).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(id)
    }

    async fn upsert_fact(&self, fact: FactWrite) -> Result<FactUpsertOutcome> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let current = sqlx::query(
            "SELECT id, value, valid_from FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_to IS NULL
             FOR UPDATE",
        )
        .bind(fact.tenant_id)
        .bind(&fact.key.source)
        .bind(&fact.key.entity_id)
        .bind(&fact.key.field)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let new_id = Uuid::now_v7();
        let outcome = match current {
            None => {
                insert_fact_row(&mut tx, new_id, &fact, None).await?;
                FactUpsertOutcome::Inserted
            }
            Some(row) => {
                let cur_id: Uuid = row.try_get("id").map_err(db_err)?;
                let cur_value: serde_json::Value = row.try_get("value").map_err(db_err)?;
                let cur_from: DateTime<Utc> = row.try_get("valid_from").map_err(db_err)?;
                if cur_value == fact.value {
                    FactUpsertOutcome::Unchanged
                } else if fact.valid_from <= cur_from {
                    // Late-arriving event: record as already-superseded history;
                    // the current row is untouched.
                    insert_fact_row(&mut tx, new_id, &fact, Some(cur_from)).await?;
                    FactUpsertOutcome::StaleEvent
                } else {
                    // Retire before insert: the one-current-row unique index is
                    // checked immediately, so the old row must lose valid_to NULL
                    // first. superseded_by is linked after insert (FK target).
                    sqlx::query("UPDATE facts SET valid_to = $1 WHERE id = $2")
                        .bind(fact.valid_from)
                        .bind(cur_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    insert_fact_row(&mut tx, new_id, &fact, None).await?;
                    sqlx::query("UPDATE facts SET superseded_by = $1 WHERE id = $2")
                        .bind(new_id)
                        .bind(cur_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    FactUpsertOutcome::Superseded
                }
            }
        };
        // Staleness (SPEC §2 L3): an L1 change retires the entity's brief. A
        // no-op upsert (Unchanged/StaleEvent) leaves briefs alone. The fact's
        // source-native entity_id is the lineage key; briefs materialized under
        // a matching entity tag pick it up.
        if matches!(
            outcome,
            FactUpsertOutcome::Inserted | FactUpsertOutcome::Superseded
        ) {
            mark_briefs_stale_tx(
                &mut tx,
                fact.tenant_id,
                std::slice::from_ref(&fact.key.entity_id),
            )
            .await?;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(outcome)
    }

    async fn current_fact(&self, scope: &Scope, key: &FactKey) -> Result<Option<FactRow>> {
        // Fail closed: no principals, nothing visible. Also short-circuits the
        // query so an empty `&&` bind never even runs.
        if scope.principals.is_empty() {
            return Ok(None);
        }
        // Entity-scope fence: a fact's entity IS its key, so this is a cheap Rust
        // membership check rather than the tag-subset `entity_scope_predicate`
        // (which is chunk-shaped). Out-of-scope entity → invisible.
        if !scope.entity_scope.is_empty() && !scope.entity_scope.contains(&key.entity_id) {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT * FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_to IS NULL
               AND visibility && $5
               AND confidentiality <= $6",
        )
        .bind(scope.tenant_id)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| row_to_fact(&r)).transpose()
    }

    async fn fact_as_of(
        &self,
        scope: &Scope,
        key: &FactKey,
        as_of: DateTime<Utc>,
    ) -> Result<Option<FactRow>> {
        if scope.principals.is_empty() {
            return Ok(None);
        }
        if !scope.entity_scope.is_empty() && !scope.entity_scope.contains(&key.entity_id) {
            return Ok(None);
        }
        // The visibility/confidentiality predicate filters on the row's CURRENT
        // ACL column (corrections are applied in place across all rows of a key,
        // §5e.6b), so a historical value is gated by now-ACL: an un-shared
        // principal cannot reach it via `as_of`.
        let row = sqlx::query(
            "SELECT * FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_from <= $5 AND (valid_to IS NULL OR valid_to > $5)
               AND visibility && $6
               AND confidentiality <= $7
             ORDER BY valid_from DESC
             LIMIT 1",
        )
        .bind(scope.tenant_id)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .bind(as_of)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| row_to_fact(&r)).transpose()
    }

    async fn upsert_chunks(&self, chunks: Vec<ChunkWrite>) -> Result<usize> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let mut written = 0usize;
        for c in &chunks {
            // Retire the previous current version of this chunk position.
            sqlx::query(
                "UPDATE chunks SET valid_to = $1
                 WHERE tenant_id = $2 AND source = $3 AND document_id = $4 AND seq = $5
                   AND valid_to IS NULL AND valid_from < $1",
            )
            .bind(c.valid_from)
            .bind(c.tenant_id)
            .bind(&c.source)
            .bind(&c.document_id)
            .bind(c.seq)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

            let result = sqlx::query(
                "INSERT INTO chunks (id, tenant_id, source, document_id, seq, content,
                                     content_hash, embedding, visibility, entity_tags,
                                     confidentiality, trust_tier, valid_from, provenance,
                                     acl_provenance)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                 ON CONFLICT (tenant_id, source, document_id, seq, valid_from) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(c.tenant_id)
            .bind(&c.source)
            .bind(&c.document_id)
            .bind(c.seq)
            .bind(&c.content)
            .bind(&c.content_hash)
            .bind(c.embedding.as_ref().map(|e| Vector::from(e.clone())))
            .bind(&c.visibility)
            .bind(&c.entity_tags)
            .bind(c.confidentiality as i16)
            .bind(c.trust_tier as i16)
            .bind(c.valid_from)
            .bind(c.provenance)
            .bind(c.acl_provenance.as_str())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            written += result.rows_affected() as usize;
        }
        // Derived-view staleness (SPEC §2 L3): a write to any chunk marks the
        // briefs of the entities it touches STALE, synchronously, in the same
        // transaction (cheap UPDATE; recompute is lazy/batch). Entity tags are
        // the lineage key for briefs.
        let affected: Vec<String> = chunks
            .iter()
            .flat_map(|c| c.entity_tags.iter().cloned())
            .collect();
        if let Some(t) = chunks.first().map(|c| c.tenant_id) {
            mark_briefs_stale_tx(&mut tx, t, &affected).await?;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(written)
    }

    async fn recall(&self, query: RecallQuery) -> Result<Vec<RecallHit>> {
        // Fail closed: no principals, no results — checked here in the shared
        // layer so no adapter can forget it.
        if query.scope.principals.is_empty() {
            return Ok(Vec::new());
        }
        match (&query.embedding, &query.text) {
            (Some(embedding), Some(text)) => {
                let (dense, sparse) = tokio::join!(
                    self.recall_dense(&query, embedding),
                    self.recall_bm25(&query, text)
                );
                Ok(rrf_fuse(vec![dense?, sparse?], query.k))
            }
            (Some(embedding), None) => self.recall_dense(&query, embedding).await,
            (None, Some(text)) => self.recall_bm25(&query, text).await,
            (None, None) => Err(StorageError::InvalidInput(
                "recall requires an embedding, text, or both".into(),
            )),
        }
    }

    async fn record_action(&self, action: ActionWrite) -> Result<bool> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let episode_id = Uuid::now_v7();
        // The action's L0 provenance episode rides the shared encrypted
        // insert path (insert_episode_tx) — the serialized action payload is
        // ciphertext at rest whenever a KEK is configured.
        self.insert_episode_tx(
            &mut tx,
            episode_id,
            &NewEpisode {
                tenant_id: action.tenant_id,
                source: "agent".into(),
                source_entity: Some(action.action_id.clone()),
                kind: EpisodeKind::AgentAction,
                payload: serde_json::to_value(&action).map_err(db_err)?,
                content_hash: format!("action-{}", action.action_id),
                trust_tier: TrustTier::Observation,
                writer_sub: action.actor_sub.clone(),
                writer_azp: action.actor_azp.clone(),
            },
        )
        .await?;

        let inserted = sqlx::query(
            "INSERT INTO actions (id, tenant_id, action_id, actor_sub, actor_azp, action_type,
                                  entities, summary, payload, outcome, occurred_at,
                                  visibility, confidentiality, provenance)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (tenant_id, action_id) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(action.tenant_id)
        .bind(&action.action_id)
        .bind(&action.actor_sub)
        .bind(&action.actor_azp)
        .bind(&action.action_type)
        .bind(&action.entities)
        .bind(&action.summary)
        .bind(&action.payload)
        .bind(action.outcome.as_str())
        .bind(action.occurred_at)
        .bind(&action.visibility)
        .bind(action.confidentiality as i16)
        .bind(episode_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if inserted.rows_affected() == 0 {
            // Idempotent replay: discard the episode too.
            tx.rollback().await.map_err(db_err)?;
            return Ok(false);
        }
        Self::insert_action_chunk(&mut tx, &action, episode_id).await?;
        // Staleness: an action for an entity retires its brief (SPEC §2 L3).
        mark_briefs_stale_tx(&mut tx, action.tenant_id, &action.entities).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(true)
    }

    async fn propose_knowledge(&self, proposal: KnowledgeProposal) -> Result<KnowledgeItem> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        // Rejection memory (knowledge-merge-tuning.md §5): a canonical form a
        // reviewer already rejected must NOT resurrect as a fresh candidate.
        // Match on the canonical form when supplied (the strong key), else on
        // the exact statement. A hit returns the remembered rejected item
        // unchanged — the propose is a no-op, never a new candidate row.
        let canon = proposal
            .canonical_statement
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty());
        let rejected: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM knowledge
             WHERE tenant_id = $1 AND status = 'rejected'
               AND (($2::text IS NOT NULL AND canonical_statement = $2)
                    OR ($2::text IS NULL AND statement = $3))
             ORDER BY rejected_at DESC NULLS LAST
             LIMIT 1",
        )
        .bind(proposal.tenant_id)
        .bind(canon)
        .bind(&proposal.statement)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
        if let Some(id) = rejected {
            tx.rollback().await.map_err(db_err)?;
            return self.get_knowledge(proposal.tenant_id, id).await;
        }

        // Evidence attribution comes from the episodes themselves.
        let evidence = sqlx::query(
            "SELECT id, source_entity, writer_azp, trust_tier FROM episodes
             WHERE tenant_id = $1 AND id = ANY($2)",
        )
        .bind(proposal.tenant_id)
        .bind(&proposal.evidence)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;

        // De-identification gate (SPEC v1.3 §2, deterministic): the statement
        // must not contain any known entity identifier — entity tags on chunks
        // and actions (with and without their "type:" prefix) or L1 entity ids.
        // Terms shorter than 4 chars are skipped as false-positive noise; such
        // identifiers are caught by review, which is on by default.
        let lexicon: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT term FROM (
                 SELECT unnest(entity_tags) AS term FROM chunks WHERE tenant_id = $1
                 UNION SELECT unnest(entities) FROM actions WHERE tenant_id = $1
                 UNION SELECT entity_id FROM facts WHERE tenant_id = $1
             ) t",
        )
        .bind(proposal.tenant_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        let statement_lc = proposal.statement.to_lowercase();
        let leaked = lexicon.iter().find_map(|term| {
            let bare = term.rsplit(':').next().unwrap_or(term);
            [term.as_str(), bare]
                .into_iter()
                .find(|t| t.len() >= 4 && statement_lc.contains(&t.to_lowercase()))
                .map(str::to_string)
        });

        let mut distinct_entities: Vec<String> = Vec::new();
        let mut writers: Vec<String> = Vec::new();
        let mut has_tier1 = false;
        for row in &evidence {
            if let Ok(Some(e)) = row.try_get::<Option<String>, _>("source_entity") {
                if !distinct_entities.contains(&e) {
                    distinct_entities.push(e);
                }
            }
            if let Ok(Some(w)) = row.try_get::<Option<String>, _>("writer_azp") {
                if !writers.contains(&w) {
                    writers.push(w);
                }
            }
            has_tier1 |= matches!(row.try_get::<i16, _>("trust_tier"), Ok(1));
        }

        let (status, reason) = match &leaked {
            Some(term) => (
                KnowledgeStatus::Quarantined,
                Some(format!(
                    "statement contains known entity identifier {term:?}"
                )),
            ),
            None => (KnowledgeStatus::Candidate, None),
        };

        // EXACT-STATEMENT ACCRUAL (the Phase-1 fast path of
        // knowledge-merge-tuning.md, applied at propose time): an identical
        // live lesson gains SUPPORT — it never clones. Match on the canonical
        // form when supplied, else the exact statement; only a clean
        // (non-quarantined) proposal accrues, and only onto a live
        // candidate/eligible twin. Counters are recomputed from the evidence
        // rows, so the accrual is idempotent (re-proposing the same episode is
        // a no-op via ON CONFLICT). Deterministic string equality only — the
        // fuzzy/LLM merge stays in the worker cascade.
        if matches!(status, KnowledgeStatus::Candidate) {
            let twin: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM knowledge
                  WHERE tenant_id = $1 AND status IN ('candidate', 'eligible')
                    AND (($2::text IS NOT NULL AND canonical_statement = $2)
                         OR statement = $3)
                  ORDER BY id
                  LIMIT 1
                  FOR UPDATE",
            )
            .bind(proposal.tenant_id)
            .bind(canon)
            .bind(&proposal.statement)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
            if let Some(twin_id) = twin {
                for row in &evidence {
                    let eid: Uuid = row.try_get("id").map_err(db_err)?;
                    let entity: Option<String> = row.try_get("source_entity").map_err(db_err)?;
                    let writer: Option<String> = row.try_get("writer_azp").map_err(db_err)?;
                    let tier: i16 = row.try_get("trust_tier").map_err(db_err)?;
                    sqlx::query(
                        "INSERT INTO knowledge_evidence
                             (knowledge_id, episode_id, entity, writer_azp, trust_tier)
                         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                    )
                    .bind(twin_id)
                    .bind(eid)
                    .bind(&entity)
                    .bind(&writer)
                    .bind(tier)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
                sqlx::query(
                    "UPDATE knowledge SET
                         categories = ARRAY(SELECT DISTINCT c
                                              FROM unnest(categories || $2::text[]) AS c),
                         distinct_entities = (SELECT count(DISTINCT entity) FROM knowledge_evidence
                                               WHERE knowledge_id = $1 AND entity IS NOT NULL),
                         episode_count = (SELECT count(*) FROM knowledge_evidence
                                           WHERE knowledge_id = $1),
                         writer_count = (SELECT count(DISTINCT writer_azp) FROM knowledge_evidence
                                          WHERE knowledge_id = $1 AND writer_azp IS NOT NULL),
                         has_tier1_evidence = EXISTS(SELECT 1 FROM knowledge_evidence
                                                      WHERE knowledge_id = $1 AND trust_tier = 1),
                         merge_reason = COALESCE(merge_reason,
                             'exact-statement accrual (propose fast path)')
                     WHERE id = $1",
                )
                .bind(twin_id)
                .bind(&proposal.categories)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
                tx.commit().await.map_err(db_err)?;
                return self.get_knowledge(proposal.tenant_id, twin_id).await;
            }
        }

        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO knowledge (id, tenant_id, statement, categories, status,
                                    quarantine_reason, distinct_entities, episode_count,
                                    writer_count, has_tier1_evidence,
                                    proposed_by_sub, proposed_by_azp, canonical_statement)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(id)
        .bind(proposal.tenant_id)
        .bind(&proposal.statement)
        .bind(&proposal.categories)
        .bind(status.as_str())
        .bind(&reason)
        .bind(distinct_entities.len() as i32)
        .bind(evidence.len() as i32)
        .bind(writers.len() as i32)
        .bind(has_tier1)
        .bind(&proposal.proposed_by_sub)
        .bind(&proposal.proposed_by_azp)
        .bind(canon)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        for row in &evidence {
            sqlx::query(
                "INSERT INTO knowledge_evidence (knowledge_id, episode_id, entity, writer_azp, trust_tier)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(row.try_get::<Uuid, _>("id").map_err(db_err)?)
            .bind(row.try_get::<Option<String>, _>("source_entity").map_err(db_err)?)
            .bind(row.try_get::<Option<String>, _>("writer_azp").map_err(db_err)?)
            .bind(row.try_get::<i16, _>("trust_tier").map_err(db_err)?)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        self.get_knowledge(proposal.tenant_id, id).await
    }

    async fn publish_knowledge(
        &self,
        tenant: TenantId,
        id: Uuid,
        visibility: Vec<PrincipalToken>,
        k_min: i32,
        embedding: Option<Vec<f32>>,
    ) -> Result<KnowledgeItem> {
        if visibility.is_empty() {
            return Err(StorageError::InvalidInput(
                "publishing requires a non-empty visibility set".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let row = sqlx::query(
            "SELECT statement, categories, status, distinct_entities, writer_count,
                    has_tier1_evidence
             FROM knowledge WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?
        .ok_or_else(|| StorageError::InvalidInput("unknown knowledge item".into()))?;

        let status: String = row.try_get("status").map_err(db_err)?;
        // Both a fresh `candidate` and an `eligible` item (crossed k-support
        // under auto-publish OFF, awaiting the human/policy gate) can publish.
        // Everything else — quarantined, rejected, already-published,
        // invalidated — cannot.
        if status != "candidate" && status != "eligible" {
            return Err(StorageError::InvalidInput(format!(
                "only candidate/eligible items can be published (status: {status})"
            )));
        }
        // Promotion gates (SPEC v1.3 §2). Category-size floor is not yet
        // enforceable — it needs entity→category facts (documented seam).
        let distinct: i32 = row.try_get("distinct_entities").map_err(db_err)?;
        let writers: i32 = row.try_get("writer_count").map_err(db_err)?;
        let tier1: bool = row.try_get("has_tier1_evidence").map_err(db_err)?;
        if distinct < k_min {
            return Err(StorageError::InvalidInput(format!(
                "k-support unmet: {distinct} distinct entities < k_min {k_min}"
            )));
        }
        if writers < 2 && !tier1 {
            return Err(StorageError::InvalidInput(
                "corroboration unmet: needs >=2 distinct writers or tier-1 evidence".into(),
            ));
        }

        let statement: String = row.try_get("statement").map_err(db_err)?;
        let categories: Vec<String> = row.try_get("categories").map_err(db_err)?;
        // Bucketed support carried onto the carve-out chunk so recall exposes a
        // coarse tier, never the exact count (§5). Guaranteed Some here: the
        // k-support gate above rejected anything below distinct == k_min >= 3.
        let tier = SupportTier::from_distinct(distinct).map(|t| t.as_str().to_string());

        let episode_id = Uuid::now_v7();
        // Publish provenance goes through the shared encrypted insert path;
        // the statement stays readable via the §7g carve-out chunk below —
        // the episode payload is lineage, not the serving copy.
        self.insert_episode_tx(
            &mut tx,
            episode_id,
            &NewEpisode {
                tenant_id: tenant,
                source: "knowledge".into(),
                source_entity: Some(id.to_string()),
                kind: EpisodeKind::KnowledgePublish,
                payload: serde_json::json!({ "knowledge_id": id, "statement": statement }),
                content_hash: format!("knowledge-{id}"),
                trust_tier: TrustTier::Observation,
                writer_sub: None,
                writer_azp: None,
            },
        )
        .await?;

        // The §7g carve-out artifact: kind='knowledge', entity-free, broad
        // visibility. Lineage lives in knowledge_evidence, NEVER here.
        sqlx::query(
            "INSERT INTO chunks (id, tenant_id, source, document_id, seq, content,
                                 content_hash, embedding, visibility, entity_tags,
                                 confidentiality, trust_tier, valid_from, provenance,
                                 kind, categories, support_tier)
             VALUES ($1, $2, 'knowledge', $3, 0, $4, $5, $6, $7, '{}', $8, $9, now(), $10,
                     'knowledge', $11, $12)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(format!("knowledge:{id}"))
        .bind(&statement)
        .bind(format!("knowledge-{id}"))
        .bind(embedding.map(Vector::from))
        .bind(&visibility)
        .bind(Confidentiality::Internal as i16)
        .bind(TrustTier::Observation as i16)
        .bind(episode_id)
        .bind(&categories)
        .bind(&tier)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        sqlx::query(
            "UPDATE knowledge SET status = 'published', published_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        self.get_knowledge(tenant, id).await
    }

    async fn list_knowledge(
        &self,
        tenant: TenantId,
        status: Option<KnowledgeStatus>,
    ) -> Result<Vec<KnowledgeItem>> {
        let rows = sqlx::query(
            "SELECT * FROM knowledge
             WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2)
             ORDER BY first_seen DESC LIMIT 200",
        )
        .bind(tenant)
        .bind(status.map(|s| s.as_str()))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_knowledge).collect()
    }

    async fn latest_chunks(
        &self,
        scope: &Scope,
        entity: &str,
        limit: usize,
    ) -> Result<Vec<RecallHit>> {
        if scope.principals.is_empty() {
            return Ok(Vec::new());
        }
        // An entity-bound scope may only read entities it covers (same rule
        // as activity()).
        if !scope.entity_scope.is_empty() && !scope.entity_scope.contains(&entity.to_string()) {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT id, document_id, seq, content, entity_tags, kind, support_tier, acl_provenance, trust_tier, valid_from, provenance,
                    0.0::float8 AS score
             FROM chunks
             WHERE tenant_id = $1
               AND valid_to IS NULL
               AND entity_tags @> ARRAY[$2]::text[]
               AND visibility && $3
               AND confidentiality <= $4
             ORDER BY valid_from DESC
             LIMIT $5",
        )
        .bind(scope.tenant_id)
        .bind(entity)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .bind(limit.clamp(1, 100) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_hit).collect()
    }

    async fn forget(&self, tenant: TenantId, ref_kind: ForgetRef, reason: &str) -> Result<u64> {
        match ref_kind {
            ForgetRef::Chunk(chunk_id) => {
                // Tenant-checked structural retire — the row stays for audit,
                // it just stops being current (invalidate-don't-delete).
                let result = sqlx::query(
                    "UPDATE chunks SET valid_to = now()
                     WHERE tenant_id = $1 AND id = $2 AND valid_to IS NULL",
                )
                .bind(tenant)
                .bind(chunk_id)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
                tracing::info!(%chunk_id, reason, "forget: chunk retired");
                Ok(result.rows_affected())
            }
            ForgetRef::Episode(episode_id) => {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let chunks_retired = sqlx::query(
                    "UPDATE chunks SET valid_to = now()
                     WHERE tenant_id = $1 AND provenance = $2 AND valid_to IS NULL",
                )
                .bind(tenant)
                .bind(episode_id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();
                let facts_retired = sqlx::query(
                    "UPDATE facts SET valid_to = now()
                     WHERE tenant_id = $1 AND provenance = $2 AND valid_to IS NULL",
                )
                .bind(tenant)
                .bind(episode_id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();

                // Knowledge retraction cascade: withdraw this episode's
                // evidence, recount support, and pull published items whose
                // k-support falls below the k=3 privacy floor.
                let knowledge_ids: Vec<Uuid> = sqlx::query_scalar(
                    "SELECT ke.knowledge_id FROM knowledge_evidence ke
                     JOIN knowledge k ON k.id = ke.knowledge_id
                     WHERE ke.episode_id = $1 AND k.tenant_id = $2
                     FOR UPDATE OF k",
                )
                .bind(episode_id)
                .bind(tenant)
                .fetch_all(&mut *tx)
                .await
                .map_err(db_err)?;

                for kid in knowledge_ids {
                    sqlx::query(
                        "DELETE FROM knowledge_evidence
                         WHERE knowledge_id = $1 AND episode_id = $2",
                    )
                    .bind(kid)
                    .bind(episode_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    let row = sqlx::query(
                        "SELECT count(DISTINCT entity) AS entities, count(*) AS episodes
                         FROM knowledge_evidence WHERE knowledge_id = $1",
                    )
                    .bind(kid)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    let distinct: i64 = row.try_get("entities").map_err(db_err)?;
                    let episodes: i64 = row.try_get("episodes").map_err(db_err)?;
                    sqlx::query(
                        "UPDATE knowledge SET distinct_entities = $2, episode_count = $3
                         WHERE id = $1",
                    )
                    .bind(kid)
                    .bind(distinct as i32)
                    .bind(episodes as i32)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    if distinct < 3 {
                        let invalidated = sqlx::query(
                            "UPDATE knowledge
                             SET status = 'invalidated', invalidated_at = now(),
                                 invalidated_reason = 'support_withdrawn'
                             WHERE id = $1 AND status = 'published'",
                        )
                        .bind(kid)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        if invalidated.rows_affected() > 0 {
                            // Retire the §7g carve-out artifact so the
                            // statement stops surfacing in recall.
                            sqlx::query(
                                "UPDATE chunks SET valid_to = now()
                                 WHERE tenant_id = $1 AND document_id = $2
                                   AND valid_to IS NULL",
                            )
                            .bind(tenant)
                            .bind(format!("knowledge:{kid}"))
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                        }
                    }
                }
                tx.commit().await.map_err(db_err)?;
                tracing::info!(
                    %episode_id,
                    reason,
                    chunks_retired,
                    facts_retired,
                    "forget: episode retired"
                );
                Ok(chunks_retired + facts_retired)
            }
        }
    }

    async fn retire_entity(
        &self,
        tenant: TenantId,
        source: &str,
        entity_id: &str,
        deleted_at: DateTime<Utc>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE facts SET valid_to = $1
             WHERE tenant_id = $2 AND source = $3 AND entity_id = $4 AND valid_to IS NULL",
        )
        .bind(deleted_at)
        .bind(tenant)
        .bind(source)
        .bind(entity_id)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    async fn activity(&self, query: ActivityQuery) -> Result<Vec<ActionRecord>> {
        let scope = &query.scope;
        // Fail closed, same contract as recall.
        if scope.principals.is_empty() {
            return Ok(Vec::new());
        }
        // An entity-bound scope may only query entities it covers.
        if !scope.entity_scope.is_empty() && !scope.entity_scope.contains(&query.entity) {
            return Ok(Vec::new());
        }
        // Patterns split into exact matches and "prefix.*" wildcards so the SQL
        // stays fully bind-parameterized.
        let (exact, prefixes): (Vec<String>, Vec<String>) = query
            .action_types
            .iter()
            .cloned()
            .partition(|t| !t.ends_with(".*"));
        let prefixes: Vec<String> = prefixes
            .into_iter()
            .map(|p| p.trim_end_matches(".*").to_string())
            .collect();

        let rows = sqlx::query(
            "SELECT * FROM actions
             WHERE tenant_id = $1
               AND entities @> ARRAY[$2]::text[]
               AND visibility && $3
               AND confidentiality <= $4
               AND occurred_at >= COALESCE($5, '-infinity'::timestamptz)
               AND (cardinality($6::text[]) = 0 AND cardinality($7::text[]) = 0
                    OR action_type = ANY($6)
                    OR EXISTS (SELECT 1 FROM unnest($7::text[]) p
                               WHERE action_type LIKE p || '.%'))
               AND (cardinality($8::text[]) = 0 OR actor_azp = ANY($8))
             ORDER BY occurred_at DESC
             LIMIT $9",
        )
        .bind(scope.tenant_id)
        .bind(&query.entity)
        .bind(&scope.principals)
        .bind(scope.max_confidentiality as i16)
        .bind(query.since)
        .bind(&exact)
        .bind(&prefixes)
        .bind(&query.actors)
        .bind(query.limit.clamp(1, 500) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_action).collect()
    }

    // ---- L3 materialized briefs (SPEC §2 L3) ----

    async fn refresh_brief(&self, tenant: TenantId, entity: &str) -> Result<MaterializedBrief> {
        // Materialize under a BROAD scope (no visibility/confidentiality
        // ceiling): the row is a cache + metadata, never the served payload.
        // Serving re-derives items under the caller's scope, so this breadth is
        // safe — it never widens what a caller can see.
        let mem_rows = sqlx::query(
            "SELECT content, entity_tags, kind, visibility, confidentiality, valid_from
             FROM chunks
             WHERE tenant_id = $1
               AND valid_to IS NULL
               AND entity_tags @> ARRAY[$2]::text[]
             ORDER BY valid_from DESC
             LIMIT 10",
        )
        .bind(tenant)
        .bind(entity)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let act_rows = sqlx::query(
            "SELECT action_id, action_type, summary, visibility, confidentiality, occurred_at
             FROM actions
             WHERE tenant_id = $1
               AND entities @> ARRAY[$2]::text[]
             ORDER BY occurred_at DESC
             LIMIT 10",
        )
        .bind(tenant)
        .bind(entity)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        // Derived-scope inheritance (SPEC §2, fail-closed): source_visibility =
        // INTERSECTION of every contributing chunk/action visibility. A brief
        // is visible only to principals present in ALL its sources. Empty
        // corpus => empty intersection => visible to nobody (fail-closed).
        let mut visibilities: Vec<Vec<i32>> = Vec::new();
        let mut recent_memory = Vec::new();
        for r in &mem_rows {
            let vis: Vec<i32> = r.try_get("visibility").map_err(db_err)?;
            visibilities.push(vis);
            recent_memory.push(serde_json::json!({
                "content": r.try_get::<String, _>("content").map_err(db_err)?,
                "kind": r.try_get::<String, _>("kind").map_err(db_err)?,
                "confidentiality": r.try_get::<i16, _>("confidentiality").map_err(db_err)?,
                "valid_from": r.try_get::<DateTime<Utc>, _>("valid_from").map_err(db_err)?,
            }));
        }
        let mut recent_activity = Vec::new();
        for r in &act_rows {
            let vis: Vec<i32> = r.try_get("visibility").map_err(db_err)?;
            visibilities.push(vis);
            recent_activity.push(serde_json::json!({
                "action_id": r.try_get::<String, _>("action_id").map_err(db_err)?,
                "action_type": r.try_get::<String, _>("action_type").map_err(db_err)?,
                "summary": r.try_get::<String, _>("summary").map_err(db_err)?,
                "occurred_at": r.try_get::<DateTime<Utc>, _>("occurred_at").map_err(db_err)?,
            }));
        }
        let source_visibility = intersect_visibilities(&visibilities);

        let body = serde_json::json!({
            "recent_memory": recent_memory,
            "recent_activity": recent_activity,
            "memory_count": mem_rows.len(),
            "activity_count": act_rows.len(),
        });

        // UPSERT: clear stale, stamp last_synced_at, keep source_version (it is
        // bumped only by stale-marking writes, so a reader can tell whether the
        // body predates a known write even right after a refresh).
        let row = sqlx::query(
            "INSERT INTO briefs (tenant_id, entity, body, source_visibility,
                                 is_stale, last_synced_at, source_version)
             VALUES ($1, $2, $3, $4, false, now(), 0)
             ON CONFLICT (tenant_id, entity) DO UPDATE
               SET body = EXCLUDED.body,
                   source_visibility = EXCLUDED.source_visibility,
                   is_stale = false,
                   last_synced_at = now()
             RETURNING entity, body, source_visibility, is_stale, last_synced_at, source_version",
        )
        .bind(tenant)
        .bind(entity)
        .bind(&body)
        .bind(&source_visibility)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        row_to_brief(&row)
    }

    async fn get_brief(&self, tenant: TenantId, entity: &str) -> Result<Option<MaterializedBrief>> {
        let row = sqlx::query(
            "SELECT entity, body, source_visibility, is_stale, last_synced_at, source_version
             FROM briefs WHERE tenant_id = $1 AND entity = $2",
        )
        .bind(tenant)
        .bind(entity)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.as_ref().map(row_to_brief).transpose()
    }

    async fn mark_briefs_stale(&self, tenant: TenantId, entities: &[String]) -> Result<u64> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let n = mark_briefs_stale_tx(&mut tx, tenant, entities).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(n)
    }

    async fn refresh_stale_briefs(&self, tenant: TenantId) -> Result<u64> {
        let entities: Vec<String> =
            sqlx::query_scalar("SELECT entity FROM briefs WHERE tenant_id = $1 AND is_stale")
                .bind(tenant)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        let mut refreshed = 0u64;
        for entity in &entities {
            self.refresh_brief(tenant, entity).await?;
            refreshed += 1;
        }
        Ok(refreshed)
    }

    // ---- Embedding-model migration (SPEC §5c) ----

    async fn register_embedding_model(&self, id: &str, dim: i32) -> Result<()> {
        sqlx::query(
            "INSERT INTO embedding_models (id, dim) VALUES ($1, $2)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(dim)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn chunks_needing_v2(
        &self,
        tenant: Option<TenantId>,
        limit: i64,
    ) -> Result<Vec<(ChunkId, String)>> {
        let rows = sqlx::query(
            "SELECT id, content FROM chunks
             WHERE ($1::uuid IS NULL OR tenant_id = $1)
               AND valid_to IS NULL
               AND embedding IS NOT NULL
               AND embedding_v2 IS NULL
             ORDER BY id
             LIMIT $2",
        )
        .bind(tenant)
        .bind(limit.clamp(1, 10_000))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get::<Uuid, _>("id").map_err(db_err)?,
                    r.try_get::<String, _>("content").map_err(db_err)?,
                ))
            })
            .collect()
    }

    async fn fill_embedding_v2(&self, model: &str, rows: &[(ChunkId, Vec<f32>)]) -> Result<u64> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let mut written = 0u64;
        for (id, vec) in rows {
            let r = sqlx::query(
                "UPDATE chunks SET embedding_v2 = $1, embedding_v2_model = $2
                 WHERE id = $3 AND embedding_v2 IS NULL",
            )
            .bind(Vector::from(vec.clone()))
            .bind(model)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            written += r.rows_affected();
        }
        tx.commit().await.map_err(db_err)?;
        Ok(written)
    }

    async fn embedding_v2_coverage(&self, tenant: Option<TenantId>) -> Result<EmbeddingCoverage> {
        let row = sqlx::query(
            "SELECT count(*) AS total,
                    count(*) FILTER (WHERE embedding_v2 IS NOT NULL) AS covered
             FROM chunks
             WHERE ($1::uuid IS NULL OR tenant_id = $1)
               AND valid_to IS NULL
               AND embedding IS NOT NULL",
        )
        .bind(tenant)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(EmbeddingCoverage {
            total: row.try_get("total").map_err(db_err)?,
            covered: row.try_get("covered").map_err(db_err)?,
        })
    }

    async fn embedding_route(&self, tenant: TenantId) -> Result<EmbeddingRoute> {
        // Read-path hot cache: the route is effectively static (changes only on
        // a cutover, which flushes this cache in `set_embedding_route`), so the
        // dense leg reads it from memory instead of re-querying `settings` on
        // every recall. The resolved value — including the fail-safe `V1`
        // default when no row exists — is what gets cached, so a repeat call
        // returns the identical decision the SELECT would have.
        if let Some(route) = self.routes.get(&tenant) {
            return Ok(route);
        }
        // Per-tenant row wins over the global (NULL-tenant) default.
        let value: Option<String> = sqlx::query_scalar(
            "SELECT value FROM settings
             WHERE key = 'embedding_route'
               AND (tenant_id = $1 OR tenant_id IS NULL)
             ORDER BY tenant_id NULLS LAST
             LIMIT 1",
        )
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let route = value
            .map(|v| EmbeddingRoute::from_str_lossy(&v))
            .unwrap_or(EmbeddingRoute::V1);
        self.routes.insert(tenant, route);
        Ok(route)
    }

    async fn set_embedding_route(
        &self,
        tenant: Option<TenantId>,
        route: EmbeddingRoute,
    ) -> Result<()> {
        // The unique index is on COALESCE(tenant_id, zero-uuid), so upsert keys
        // on that expression.
        sqlx::query(
            "INSERT INTO settings (tenant_id, key, value, updated_at)
             VALUES ($1, 'embedding_route', $2, now())
             ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), key)
             DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        )
        .bind(tenant)
        .bind(route.as_str())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        // Flush the whole route cache, not just this key: a GLOBAL
        // (NULL-tenant) write changes the resolved route for every tenant that
        // lacks a per-tenant row, and those are cached under their own keys.
        // Cutovers are rare, the cache is tiny, and correctness beats
        // bookkeeping — the same rationale as `CachedAdapter::flush_facts`.
        self.routes.invalidate_all();
        Ok(())
    }

    // ---- Connector credential intake (SPEC §5e, Phase-2) ----
    // Thin forwarders to the inherent `*_impl` methods where the crypto lives.

    async fn store_connector_bearer(
        &self,
        tenant: TenantId,
        source: &str,
        plaintext: &[u8],
        visibility: &[i32],
    ) -> Result<String> {
        self.store_connector_bearer_impl(tenant, source, plaintext, visibility)
            .await
    }

    async fn store_connector_path(
        &self,
        tenant: TenantId,
        source: &str,
        path: &str,
        subject: Option<&str>,
    ) -> Result<String> {
        self.store_connector_path_impl(tenant, source, path, subject)
            .await
    }

    async fn get_connector_credential_status(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<ConnectorCredentialStatus>> {
        self.get_connector_credential_status_impl(tenant, source)
            .await
    }

    async fn materialize_connector_path(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<ConnectorPathCredential>> {
        self.materialize_connector_path_impl(tenant, source).await
    }

    async fn materialize_connector_bearer(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.materialize_connector_bearer_impl(tenant, source).await
    }

    async fn revoke_connector_credential(&self, tenant: TenantId, source: &str) -> Result<bool> {
        self.revoke_connector_credential_impl(tenant, source).await
    }

    async fn upsert_sync_schedule(
        &self,
        tenant: TenantId,
        source: &str,
        interval_secs: i32,
        enabled: bool,
    ) -> Result<SyncSchedule> {
        self.upsert_sync_schedule_impl(tenant, source, interval_secs, enabled)
            .await
    }

    async fn get_sync_schedule(
        &self,
        tenant: TenantId,
        source: &str,
    ) -> Result<Option<SyncSchedule>> {
        self.get_sync_schedule_impl(tenant, source).await
    }

    async fn list_enabled_sync_schedules(&self) -> Result<Vec<SyncSchedule>> {
        self.list_enabled_sync_schedules_impl().await
    }

    async fn touch_sync_schedule_last_run(&self, tenant: TenantId, source: &str) -> Result<bool> {
        self.touch_sync_schedule_last_run_impl(tenant, source).await
    }
}

/// The reason an ACL correction was applied, stamped on the `fact_acl_audit`
/// row (migration 0026). Mirrors the CHECK-free `reason` vocabulary the audit
/// table documents; kept as a Rust enum so callers cannot free-type a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclCorrectionReason {
    SourceReshare,
    SourceUnshare,
    AdminCorrection,
    RebacWatchDelete,
}

impl AclCorrectionReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::SourceReshare => "source_reshare",
            Self::SourceUnshare => "source_unshare",
            Self::AdminCorrection => "admin_correction",
            Self::RebacWatchDelete => "rebac_watch_delete",
        }
    }
}

impl PostgresAdapter {
    /// ACL-correction-in-place (SPEC §5e.6b, the append-only carve-out). Value
    /// changes stay append-only (valid_to + superseded_by); an ACL change does
    /// NOT — a re-share/un-share UPDATEs `visibility`/`confidentiality` across
    /// EVERY row of the key (current + superseded history) in one transaction
    /// and appends exactly one `fact_acl_audit` row. It takes effect immediately,
    /// like a revocation tombstone: were the new ACL appended as a fresh value
    /// row, the old permissive ACL would sit behind `valid_to IS NULL` until the
    /// next value write — a leak window. Because history rows are touched too,
    /// `fact_as_of` enforces NOW-ACL: an un-shared principal cannot reach a
    /// historical value via `?as_of=`.
    ///
    /// Admin/connector plane only — reachable from admin correction handlers and
    /// the rebac-watch `group#member` DELETE path, NEVER from an agent scope.
    /// Returns the number of fact rows whose ACL was updated (0 = unknown key).
    #[allow(clippy::too_many_arguments)]
    pub async fn correct_fact_acl(
        &self,
        tenant: TenantId,
        key: &FactKey,
        new_visibility: &[PrincipalToken],
        new_confidentiality: Confidentiality,
        reason: AclCorrectionReason,
        acl_provenance: AclProvenance,
        changed_by: Option<&str>,
    ) -> Result<u64> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        // Snapshot the CURRENT row's old ACL for the audit trail (the current
        // row is the one whose "who could see the live value" is forensically
        // interesting). NULL old_* when the key has no current row.
        let current = sqlx::query(
            "SELECT id, visibility, confidentiality FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_to IS NULL",
        )
        .bind(tenant)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let (fact_id, old_vis, old_conf): (Option<Uuid>, Option<Vec<i32>>, Option<i16>) =
            match &current {
                Some(r) => (
                    Some(r.try_get("id").map_err(db_err)?),
                    Some(r.try_get("visibility").map_err(db_err)?),
                    Some(r.try_get("confidentiality").map_err(db_err)?),
                ),
                None => (None, None, None),
            };

        // In-place UPDATE across ALL rows of the key (current + superseded).
        let updated = sqlx::query(
            "UPDATE facts SET visibility = $5, confidentiality = $6
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4",
        )
        .bind(tenant)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .bind(new_visibility)
        .bind(new_confidentiality as i16)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?
        .rows_affected();

        // One append-only audit row (old -> new).
        sqlx::query(
            "INSERT INTO fact_acl_audit
                (id, tenant_id, source, entity_id, field, fact_id,
                 old_visibility, new_visibility, old_confidentiality, new_confidentiality,
                 reason, acl_provenance, changed_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .bind(fact_id)
        .bind(old_vis)
        .bind(new_visibility)
        .bind(old_conf)
        .bind(new_confidentiality as i16)
        .bind(reason.as_str())
        .bind(acl_provenance.as_str())
        .bind(changed_by)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(updated)
    }

    /// The ONE L0 episode insert path (SPEC §8a): every episode row — agent
    /// observations, CDC envelopes, doc versions, action provenance,
    /// knowledge-publish provenance — is written here, so envelope encryption
    /// cannot be bypassed by an inline INSERT elsewhere. With a KEK
    /// configured the payload is stored AES-256-GCM under the tenant DEK in
    /// `payload_enc` and the jsonb column carries the `'{}'` sentinel; reads
    /// that need the payload go through `episode_payload()` — the serving
    /// read path never does. The DEK is provisioned lazily either way.
    async fn insert_episode_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: EpisodeId,
        ep: &NewEpisode,
    ) -> Result<()> {
        // Note: DEK provisioning runs on the pool, outside `tx` — it is
        // idempotent (ON CONFLICT DO NOTHING + re-read), so a rolled-back
        // caller transaction at worst leaves a provisioned DEK behind.
        let dek = self.tenant_dek(ep.tenant_id).await?;
        let (payload, payload_enc, encrypted): (serde_json::Value, Option<Vec<u8>>, Option<bool>) =
            if self.kek.is_some() {
                let plaintext = serde_json::to_vec(&ep.payload).map_err(db_err)?;
                (
                    serde_json::json!({}),
                    Some(crate::crypto::encrypt(&dek, &plaintext)?),
                    Some(true),
                )
            } else {
                (ep.payload.clone(), None, None)
            };
        sqlx::query(
            "INSERT INTO episodes (id, tenant_id, source, source_entity, kind, payload,
                                   payload_enc, payload_encrypted,
                                   content_hash, trust_tier, writer_sub, writer_azp)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(id)
        .bind(ep.tenant_id)
        .bind(&ep.source)
        .bind(&ep.source_entity)
        .bind(ep.kind.as_str())
        .bind(&payload)
        .bind(&payload_enc)
        .bind(encrypted)
        .bind(&ep.content_hash)
        .bind(ep.trust_tier as i16)
        .bind(&ep.writer_sub)
        .bind(&ep.writer_azp)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn insert_action_chunk(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        a: &ActionWrite,
        episode: EpisodeId,
    ) -> Result<()> {
        // Actions surface in semantic recall too (SPEC §2): the summary is
        // indexed as a Tier-2 chunk. Embedding is added when the local encoder
        // joins the write path; BM25 covers it until then.
        sqlx::query(
            "INSERT INTO chunks (id, tenant_id, source, document_id, seq, content,
                                 content_hash, embedding, visibility, entity_tags,
                                 confidentiality, trust_tier, valid_from, provenance,
                                 acl_provenance)
             VALUES ($1, $2, 'agent', $3, 0, $4, $5, NULL, $6, $7, $8, $9, $10, $11,
                     'admin-assigned')
             ON CONFLICT (tenant_id, source, document_id, seq, valid_from) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(a.tenant_id)
        .bind(format!("action:{}", a.action_id))
        .bind(format!("{}: {}", a.action_type, a.summary))
        .bind(format!("action-{}", a.action_id))
        .bind(&a.visibility)
        .bind(&a.entities)
        .bind(a.confidentiality as i16)
        .bind(TrustTier::Observation as i16)
        .bind(a.occurred_at)
        .bind(episode)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
        Ok(())
    }
}

async fn insert_fact_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    fact: &FactWrite,
    valid_to: Option<DateTime<Utc>>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO facts (id, tenant_id, source, entity_id, field, value,
                            valid_from, valid_to, visibility, confidentiality,
                            provenance, acl_provenance)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(fact.tenant_id)
    .bind(&fact.key.source)
    .bind(&fact.key.entity_id)
    .bind(&fact.key.field)
    .bind(&fact.value)
    .bind(fact.valid_from)
    .bind(valid_to)
    .bind(&fact.visibility)
    .bind(fact.confidentiality as i16)
    .bind(fact.provenance)
    .bind(fact.acl_provenance.as_str())
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Mark the briefs of `entities` STALE in the same transaction as the write
/// that caused it (SPEC §2 L3: synchronous, cheap staleness marking off the
/// hot recompute path). `source_version` bumps so a reader can detect a body
/// that predates known writes. Only touches already-materialized briefs —
/// non-existent ones are created lazily on first read. Distinct-dedups the
/// input so the UPDATE stays a single pass.
async fn mark_briefs_stale_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: TenantId,
    entities: &[String],
) -> Result<u64> {
    if entities.is_empty() {
        return Ok(0);
    }
    let mut uniq: Vec<String> = entities.to_vec();
    uniq.sort();
    uniq.dedup();
    let r = sqlx::query(
        "UPDATE briefs
           SET is_stale = true, source_version = source_version + 1
         WHERE tenant_id = $1 AND entity = ANY($2)",
    )
    .bind(tenant)
    .bind(&uniq)
    .execute(&mut **tx)
    .await
    .map_err(db_err)?;
    Ok(r.rows_affected())
}

/// Set-intersection of contributing visibility arrays (derived-scope
/// inheritance, SPEC §2). Empty input (no sources) => empty set => visible to
/// nobody (fail-closed). Order-independent; result is sorted+deduped.
fn intersect_visibilities(lists: &[Vec<i32>]) -> Vec<i32> {
    let mut iter = lists.iter();
    let Some(first) = iter.next() else {
        return Vec::new();
    };
    let mut acc: std::collections::BTreeSet<i32> = first.iter().copied().collect();
    for list in iter {
        let s: std::collections::HashSet<i32> = list.iter().copied().collect();
        acc.retain(|t| s.contains(t));
        if acc.is_empty() {
            break;
        }
    }
    acc.into_iter().collect()
}

fn row_to_brief(row: &PgRow) -> Result<MaterializedBrief> {
    Ok(MaterializedBrief {
        entity: row.try_get("entity").map_err(db_err)?,
        body: row.try_get("body").map_err(db_err)?,
        source_visibility: row.try_get("source_visibility").map_err(db_err)?,
        is_stale: row.try_get("is_stale").map_err(db_err)?,
        last_synced_at: row.try_get("last_synced_at").map_err(db_err)?,
        source_version: row.try_get("source_version").map_err(db_err)?,
    })
}

fn row_to_action(row: &PgRow) -> Result<ActionRecord> {
    let outcome = match row
        .try_get::<String, _>("outcome")
        .map_err(db_err)?
        .as_str()
    {
        "succeeded" => ActionOutcome::Succeeded,
        "failed" => ActionOutcome::Failed,
        _ => ActionOutcome::Pending,
    };
    Ok(ActionRecord {
        id: row.try_get("id").map_err(db_err)?,
        action_id: row.try_get("action_id").map_err(db_err)?,
        actor_sub: row.try_get("actor_sub").map_err(db_err)?,
        actor_azp: row.try_get("actor_azp").map_err(db_err)?,
        action_type: row.try_get("action_type").map_err(db_err)?,
        entities: row.try_get("entities").map_err(db_err)?,
        summary: row.try_get("summary").map_err(db_err)?,
        payload: row.try_get("payload").map_err(db_err)?,
        outcome,
        occurred_at: row.try_get("occurred_at").map_err(db_err)?,
        recorded_at: row.try_get("recorded_at").map_err(db_err)?,
        provenance: row.try_get("provenance").map_err(db_err)?,
    })
}

/// Resolved per-field source precedence for one canonical entity (SPEC §7f).
/// Holds the most-specific `(canonical, field)` orders, the `(canonical, '*')`
/// entity default, and the global `('*', '*')` default; `resolve` picks the
/// most specific applicable one for a field.
#[derive(Default)]
struct PrecedenceConfig {
    /// field -> order, for rows scoped to THIS canonical entity specifically.
    per_field: HashMap<String, Vec<String>>,
    /// (canonical, '*') — the entity-level default.
    entity_default: Option<Vec<String>>,
    /// ('*', '*') — the global default.
    global_default: Option<Vec<String>>,
}

impl PrecedenceConfig {
    /// Route one DB row into the right slot. `canonical` is the target entity
    /// being resolved (used to tell an entity-specific row from the '*' one).
    fn insert(&mut self, row_canonical: &str, field: &str, canonical: &str, order: Vec<String>) {
        match (row_canonical == canonical, field) {
            (true, "*") => self.entity_default = Some(order),
            (true, _) => {
                self.per_field.insert(field.to_string(), order);
            }
            (false, "*") => self.global_default = Some(order),
            // ('*', specific-field) is a legal, if unusual, global per-field
            // default; keep it only when no entity-specific row overrides.
            (false, _) => {
                self.per_field
                    .entry(field.to_string())
                    .or_insert_with(|| order.clone());
            }
        }
    }

    /// Most-specific-wins: (canonical, field) → (canonical, '*') → ('*', '*') →
    /// empty (no config: every source ties, valid_from breaks it).
    fn resolve(&self, field: &str) -> Vec<String> {
        if let Some(o) = self.per_field.get(field) {
            return o.clone();
        }
        if let Some(o) = &self.entity_default {
            return o.clone();
        }
        if let Some(o) = &self.global_default {
            return o.clone();
        }
        Vec::new()
    }
}

/// Rank of `source` in a precedence order: its index if listed, else a value
/// past the end (every unlisted source ties last, SPEC §7f). Lower wins.
fn precedence_rank(order: &[String], source: &str) -> usize {
    order
        .iter()
        .position(|s| s == source)
        .unwrap_or(order.len())
}

/// Render a jsonb fact value as a short display string for the entity summary:
/// a JSON string yields its inner text; any other scalar/compound yields its
/// compact JSON. `None` for a JSON null. Display-only — never a match key.
fn json_scalar_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn row_to_evidence(row: &PgRow) -> Result<EvidenceRow> {
    Ok(EvidenceRow {
        evidence_id: row.try_get("evidence_id").map_err(db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(db_err)?,
        left_ref: row.try_get("left_ref").map_err(db_err)?,
        right_ref: row.try_get("right_ref").map_err(db_err)?,
        tier: row.try_get("tier").map_err(db_err)?,
        method: row.try_get("method").map_err(db_err)?,
        key_value: row.try_get("key_value").map_err(db_err)?,
        key_namespace: row.try_get("key_namespace").map_err(db_err)?,
        score: row.try_get("score").map_err(db_err)?,
        evidence_l0_ref: row.try_get("evidence_l0_ref").map_err(db_err)?,
        polarity: row.try_get("polarity").map_err(db_err)?,
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        valid_to: row.try_get("valid_to").map_err(db_err)?,
        superseded_by: row.try_get("superseded_by").map_err(db_err)?,
    })
}

/// Map a prioritized review-queue row (the `EvidenceRow` columns + the computed
/// `priority` / `wait_age_secs` / `frequency` / `entity_value`) to a
/// [`ReviewQueueItem`]. The evidence columns are the same set `row_to_evidence`
/// reads, so we reuse it for the embedded row.
fn row_to_review_item(row: &PgRow) -> Result<ReviewQueueItem> {
    Ok(ReviewQueueItem {
        evidence: row_to_evidence(row)?,
        priority: row.try_get("priority").map_err(db_err)?,
        wait_age_secs: row.try_get("wait_age_secs").map_err(db_err)?,
        frequency: row.try_get("frequency").map_err(db_err)?,
        entity_value: row.try_get("entity_value").map_err(db_err)?,
    })
}

fn row_to_fact(row: &PgRow) -> Result<FactRow> {
    Ok(FactRow {
        id: row.try_get("id").map_err(db_err)?,
        tenant_id: row.try_get("tenant_id").map_err(db_err)?,
        key: FactKey {
            source: row.try_get("source").map_err(db_err)?,
            entity_id: row.try_get("entity_id").map_err(db_err)?,
            field: row.try_get("field").map_err(db_err)?,
        },
        value: row.try_get("value").map_err(db_err)?,
        valid_from: row.try_get("valid_from").map_err(db_err)?,
        valid_to: row.try_get("valid_to").map_err(db_err)?,
        superseded_by: row.try_get("superseded_by").map_err(db_err)?,
        recorded_at: row.try_get("recorded_at").map_err(db_err)?,
        visibility: row.try_get("visibility").map_err(db_err)?,
        confidentiality: Confidentiality::from_i16(
            row.try_get::<i16, _>("confidentiality").map_err(db_err)?,
        ),
        provenance: row.try_get("provenance").map_err(db_err)?,
        acl_provenance: AclProvenance::from_str_lossy(
            &row.try_get::<String, _>("acl_provenance").map_err(db_err)?,
        ),
    })
}
