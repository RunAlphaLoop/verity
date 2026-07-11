use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pgvector::Vector;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;

pub struct PostgresAdapter {
    pool: PgPool,
    /// Deployment KEK (SPEC §8a, crypto.rs). None = envelope encryption
    /// disabled: L0 payloads stay plaintext, DEKs are stored unwrapped.
    kek: Option<crate::crypto::Kek>,
    /// Unwrapped per-tenant DEKs, cached after first use (bounded; the DEK is
    /// 32 bytes and provisioning is one row per tenant, ever).
    deks: moka::sync::Cache<TenantId, [u8; crate::crypto::DEK_BYTES]>,
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
        })
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

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn get_knowledge(&self, tenant: TenantId, id: Uuid) -> Result<KnowledgeItem> {
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
    pub async fn upsert_entity_link_meta(&self, meta: &EntityLinkMeta) -> Result<()> {
        sqlx::query(
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
                 updated_at          = now()",
        )
        .bind(meta.tenant_id)
        .bind(&meta.subject_kind)
        .bind(&meta.subject_ref)
        .bind(&meta.canonical_entity)
        .bind(&meta.confidence)
        .bind(&meta.strongest_method)
        .bind(&meta.justifying_evidence)
        .bind(meta.evidence_count)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
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

    /// The review queue (§4.1, §4.3): live Tier-2/Tier-3 evidence that never
    /// auto-forms an edge (Tier-2 awaits `human_confirmed`; Tier-3 never merges).
    /// A read-only view over `entity_evidence` — empty in the MVP (no Tier-2/3
    /// producers ship yet) but fully wired so the admin surface exists. Newest
    /// first, capped.
    pub async fn review_queue(&self, tenant: TenantId, limit: i64) -> Result<Vec<EvidenceRow>> {
        let rows = sqlx::query(
            "SELECT evidence_id, tenant_id, left_ref, right_ref, tier, method,
                    key_value, key_namespace, score, evidence_l0_ref, polarity,
                    valid_from, valid_to, superseded_by
               FROM entity_evidence
              WHERE tenant_id = $1 AND valid_to IS NULL AND tier IN (2, 3)
              ORDER BY valid_from DESC, evidence_id
              LIMIT $2",
        )
        .bind(tenant)
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_evidence).collect()
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
    pub async fn merged_record(&self, tenant: TenantId, canonical: &str) -> Result<MergedRecord> {
        // 1. Resolve members. Explicit aliases win; else the unmapped fallback
        //    (any facts keyed directly on `canonical` as entity_id).
        let members = self.list_entity_aliases(tenant, canonical).await?;

        // 2. Gather current facts for those members (or the unmapped fallback).
        let fact_rows: Vec<FactRow> = if members.is_empty() {
            let rows = sqlx::query(
                "SELECT * FROM facts
                 WHERE tenant_id = $1 AND entity_id = $2 AND valid_to IS NULL",
            )
            .bind(tenant)
            .bind(canonical)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
            rows.iter().map(row_to_fact).collect::<Result<_>>()?
        } else {
            let sources: Vec<String> = members.iter().map(|m| m.source.clone()).collect();
            let entity_ids: Vec<String> = members.iter().map(|m| m.entity_id.clone()).collect();
            // Match on the (source, entity_id) pairs via UNNEST-zipped arrays so
            // a member of source A / entity X never picks up source B / entity X.
            let rows = sqlx::query(
                "SELECT f.* FROM facts f
                 JOIN unnest($2::text[], $3::text[]) AS m(source, entity_id)
                   ON f.source = m.source AND f.entity_id = m.entity_id
                 WHERE f.tenant_id = $1 AND f.valid_to IS NULL",
            )
            .bind(tenant)
            .bind(&sources)
            .bind(&entity_ids)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
            rows.iter().map(row_to_fact).collect::<Result<_>>()?
        };

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
            // faster than graph traversal under selective filters).
            sqlx::query("SET LOCAL enable_indexscan = off")
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
        } else {
            // Broad set: HNSW with iterative scans so selective predicates
            // don't collapse recall (pgvector 0.8, SPEC §4).
            sqlx::query("SET LOCAL hnsw.iterative_scan = relaxed_order")
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

    async fn current_fact(&self, tenant: TenantId, key: &FactKey) -> Result<Option<FactRow>> {
        let row = sqlx::query(
            "SELECT * FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_to IS NULL",
        )
        .bind(tenant)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| row_to_fact(&r)).transpose()
    }

    async fn fact_as_of(
        &self,
        tenant: TenantId,
        key: &FactKey,
        as_of: DateTime<Utc>,
    ) -> Result<Option<FactRow>> {
        let row = sqlx::query(
            "SELECT * FROM facts
             WHERE tenant_id = $1 AND source = $2 AND entity_id = $3 AND field = $4
               AND valid_from <= $5 AND (valid_to IS NULL OR valid_to > $5)
             ORDER BY valid_from DESC
             LIMIT 1",
        )
        .bind(tenant)
        .bind(&key.source)
        .bind(&key.entity_id)
        .bind(&key.field)
        .bind(as_of)
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
        Ok(value
            .map(|v| EmbeddingRoute::from_str_lossy(&v))
            .unwrap_or(EmbeddingRoute::V1))
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
        Ok(())
    }
}

impl PostgresAdapter {
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
                            valid_from, valid_to, provenance, acl_provenance)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(fact.tenant_id)
    .bind(&fact.key.source)
    .bind(&fact.key.entity_id)
    .bind(&fact.key.field)
    .bind(&fact.value)
    .bind(fact.valid_from)
    .bind(valid_to)
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
        provenance: row.try_get("provenance").map_err(db_err)?,
        acl_provenance: AclProvenance::from_str_lossy(
            &row.try_get::<String, _>("acl_provenance").map_err(db_err)?,
        ),
    })
}
