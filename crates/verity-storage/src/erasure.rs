//! Hard purge + DSAR export (SPEC §8b/§8e, roadmap task 23 — v0 slice).
//!
//! This is the GDPR path, deliberately distinct from `memory.forget`
//! (SPEC §8f): forget is scope-bound *invalidation* (rows keep existing with
//! `valid_to`); erasure is an admin-initiated lineage-driven **hard DELETE**
//! that runs in one transaction and returns per-table counts.
//!
//! What erasure covers (v0): L0 episodes attributable to the subject
//! (`writer_sub`) or entity (`source_entity`), the chunks and facts derived
//! from them (by provenance), the subject's actions (`actor_sub`) / the
//! entity's actions (tag membership) plus their provenance episodes, the
//! knowledge-evidence rows those episodes support (with a support recount —
//! published items falling below the k=3 floor are invalidated and their §7g
//! carve-out chunks retired), quarantine-preview payloads mentioning the
//! subject/entity (conservative substring match — over-deletion by design),
//! and the subject's audit rows. Entity purge also hard-deletes facts keyed
//! on the entity and every chunk tagged with it — multi-tag chunks are
//! deleted whole, never tag-stripped (conservative over-deletion, documented
//! in docs/OPERATIONS.md along with what erasure does NOT yet cover).
//!
//! One audit row survives: verb='erasure' with the per-table counts and a
//! sha256 of the subject/entity — no plaintext PII.

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use verity_core::types::{Result, StorageError, TenantId};

use crate::postgres::{db_err, PostgresAdapter};

/// Per-table hard-delete counts, returned to the caller and preserved in the
/// surviving audit row.
#[derive(Debug, Default, Clone, Serialize)]
pub struct ErasureReport {
    pub episodes: u64,
    pub chunks: u64,
    pub facts: u64,
    pub actions: u64,
    pub knowledge_evidence: u64,
    /// Published knowledge items whose distinct-entity support fell below the
    /// k=3 privacy floor after evidence withdrawal (invalidated, not deleted:
    /// the de-identified statement itself contains no subject data).
    pub knowledge_invalidated: u64,
    pub quarantine_preview: u64,
    pub audit_log: u64,
    /// Media blobs purged by explicit `media_ids` (tenant-checked). Media has
    /// no automatic subject attribution in v0 — operators list candidates via
    /// GET /v1/admin/media and name them on the erasure request.
    pub media: u64,
}

/// The honest coverage-gap disclosure carried on every preview (SPEC §8b):
/// erasure is not instantaneous perfection, and the console must say so with
/// the same words whether the operator previews or runs. Static strings, not
/// runtime state — they describe the *shape* of the walk, which is identical
/// for preview and erase because they share the lineage code.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageGaps {
    /// Media carries no automatic subject attribution in v0 — only the blobs
    /// the operator explicitly names in `media_ids` are purged.
    pub operator_named_media: String,
    /// Subject/entity matching is exact-string; an alias or differently-cased
    /// identifier is not walked.
    pub exact_string_matching: String,
    /// Hard purge removes live rows + destroys keys in the primary store, but
    /// physical backups already taken persist until they age out.
    pub backup_retention_window: String,
}

impl Default for CoverageGaps {
    fn default() -> Self {
        Self {
            operator_named_media:
                "Media has no automatic subject attribution in v0. Only blobs named explicitly \
                 in media_ids are purged (list candidates via GET /v1/admin/media); an unnamed \
                 blob survives the walk."
                    .into(),
            exact_string_matching:
                "Subject/entity matching is exact-string. An alias, a differently-cased sub, or a \
                 mistyped entity is not walked — confirm identifiers before running."
                    .into(),
            backup_retention_window:
                "Hard purge removes live rows and destroys keys in the primary store; physical \
                 backups already taken persist until they age out of the retention window and are \
                 then crypto-shredded. This window is real and disclosed, not instantaneous."
                    .into(),
        }
    }
}

/// The dry-run result: the exact counts an `erase()` with the same arguments
/// WOULD purge (same lineage walk, rolled back — nothing is destroyed), plus
/// the coverage-gap disclosure. `would_erase` is the identical shape to the
/// destructive `ErasureReport`, so the console renders one table for both.
#[derive(Debug, Clone, Serialize)]
pub struct ErasurePreview {
    pub would_erase: ErasureReport,
    pub coverage_gaps: CoverageGaps,
}

impl PostgresAdapter {
    /// POST /v1/admin/erasure/preview — the dry run. Walks the SAME lineage as
    /// `erase()` (via the shared `walk_lineage`, so the two cannot drift), but
    /// rolls the transaction back: nothing is purged, no surviving audit row is
    /// written. Returns the counts that a real erasure WOULD delete plus the
    /// coverage-gap disclosure. Requires the same arg validation as `erase()`.
    pub async fn erase_preview(
        &self,
        tenant: TenantId,
        subject: Option<&str>,
        entity: Option<&str>,
        media_ids: &[Uuid],
    ) -> Result<ErasurePreview> {
        if subject.is_none() && entity.is_none() && media_ids.is_empty() {
            return Err(StorageError::InvalidInput(
                "erasure preview requires a subject, an entity, and/or media_ids".into(),
            ));
        }
        let mut tx = self.pool().begin().await.map_err(db_err)?;
        let report = self
            .walk_lineage(&mut tx, tenant, subject, entity, media_ids)
            .await?;
        // Roll back: a preview must PURGE NOTHING. Dropping the tx (or an
        // explicit rollback) undoes every DELETE the shared walk issued.
        tx.rollback().await.map_err(db_err)?;
        tracing::info!(%tenant, ?report, "erasure preview (dry-run, rolled back)");
        Ok(ErasurePreview {
            would_erase: report,
            coverage_gaps: CoverageGaps::default(),
        })
    }

    /// POST /v1/admin/erasure — lineage-driven hard purge, one transaction.
    /// At least one of `subject` / `entity` / `media_ids` is required.
    /// `media_ids` are explicit, operator-named media blobs purged in the
    /// same transaction (tenant-checked: foreign-tenant ids delete nothing).
    pub async fn erase(
        &self,
        tenant: TenantId,
        subject: Option<&str>,
        entity: Option<&str>,
        media_ids: &[Uuid],
    ) -> Result<ErasureReport> {
        if subject.is_none() && entity.is_none() && media_ids.is_empty() {
            return Err(StorageError::InvalidInput(
                "erasure requires a subject, an entity, and/or media_ids".into(),
            ));
        }
        let mut tx = self.pool().begin().await.map_err(db_err)?;
        let report = self
            .walk_lineage(&mut tx, tenant, subject, entity, media_ids)
            .await?;

        // ONE surviving audit row: verb='erasure', counts, sha256 of the
        // identifiers — no plaintext PII beyond that. (Preview skips this: a
        // dry run leaves no trace, and its read is audited by the handler.)
        let summary = serde_json::json!({
            "subject_sha256": subject.map(sha256_hex),
            "entity_sha256": entity.map(sha256_hex),
            "counts": &report,
        });
        sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, actor_sub, actor_azp, verb, principals,
                                    entity_scope, confidentiality, query_summary, result_ids)
             VALUES ($1, $2, NULL, NULL, 'erasure', '{}', '{}', 0, $3, '{}')",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .bind(summary.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        // Facts were hard-deleted underneath any L1 cache; callers holding a
        // CachedAdapter must flush (the server handler does).
        tracing::info!(%tenant, ?report, "erasure completed");
        Ok(report)
    }

    /// The single lineage-walk both `erase` and `erase_preview` run, so a dry
    /// run can never disagree with the real purge. Issues every DELETE/UPDATE
    /// against the caller-supplied transaction and returns the per-table
    /// counts; the caller decides whether to COMMIT (erase) or ROLLBACK
    /// (preview) and whether to write the surviving audit row. This method
    /// never commits, never rolls back, and never writes the audit row itself.
    async fn walk_lineage(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: TenantId,
        subject: Option<&str>,
        entity: Option<&str>,
        media_ids: &[Uuid],
    ) -> Result<ErasureReport> {
        let mut report = ErasureReport::default();

        // 1. Enumerate the L0 episode set (SPEC §8b: purge is a walk, not a
        //    search): the subject's writes, the entity's source rows.
        let mut episode_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM episodes
             WHERE tenant_id = $1
               AND (($2::text IS NOT NULL AND writer_sub = $2)
                 OR ($3::text IS NOT NULL AND source_entity = $3))",
        )
        .bind(tenant)
        .bind(subject)
        .bind(entity)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;

        // 2. Actions (actor_sub = subject, or entity ∈ entities). Their
        //    provenance episodes carry the serialized action payload, so they
        //    join the episode delete set.
        let action_provenance: Vec<Uuid> = sqlx::query_scalar(
            "DELETE FROM actions
             WHERE tenant_id = $1
               AND (($2::text IS NOT NULL AND actor_sub = $2)
                 OR ($3::text IS NOT NULL AND $3 = ANY(entities)))
             RETURNING provenance",
        )
        .bind(tenant)
        .bind(subject)
        .bind(entity)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
        report.actions = action_provenance.len() as u64;
        episode_ids.extend(action_provenance);
        episode_ids.sort_unstable();
        episode_ids.dedup();

        // 3. Chunks: derived from the episode set (provenance), plus — for
        //    entity purge — every chunk tagged with the entity. Multi-tag
        //    chunks are deleted whole (conservative over-deletion).
        report.chunks = sqlx::query(
            "DELETE FROM chunks
             WHERE tenant_id = $1
               AND (provenance = ANY($2)
                 OR ($3::text IS NOT NULL AND entity_tags @> ARRAY[$3::text]))",
        )
        .bind(tenant)
        .bind(&episode_ids)
        .bind(entity)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?
        .rows_affected();

        // 4. Facts: by provenance, plus — entity purge — by entity_id.
        //    Surviving rows may point at deleted ones via superseded_by;
        //    unlink first so the self-referential FK holds.
        sqlx::query(
            "UPDATE facts SET superseded_by = NULL
             WHERE tenant_id = $1 AND superseded_by IN (
                 SELECT id FROM facts
                 WHERE tenant_id = $1
                   AND (provenance = ANY($2)
                     OR ($3::text IS NOT NULL AND entity_id = $3)))",
        )
        .bind(tenant)
        .bind(&episode_ids)
        .bind(entity)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
        report.facts = sqlx::query(
            "DELETE FROM facts
             WHERE tenant_id = $1
               AND (provenance = ANY($2)
                 OR ($3::text IS NOT NULL AND entity_id = $3))",
        )
        .bind(tenant)
        .bind(&episode_ids)
        .bind(entity)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?
        .rows_affected();

        // 5. Knowledge-evidence withdrawal + support recount (same cascade as
        //    forget, but the evidence rows are hard-deleted). Items whose
        //    distinct-entity support drops below the k=3 privacy floor are
        //    invalidated and their §7g carve-out chunks retired.
        let mut affected_knowledge: Vec<Uuid> = sqlx::query_scalar(
            "SELECT ke.knowledge_id FROM knowledge_evidence ke
             JOIN knowledge k ON k.id = ke.knowledge_id
             WHERE k.tenant_id = $1 AND ke.episode_id = ANY($2)
             FOR UPDATE OF k",
        )
        .bind(tenant)
        .bind(&episode_ids)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
        affected_knowledge.sort_unstable();
        affected_knowledge.dedup();
        report.knowledge_evidence = sqlx::query(
            "DELETE FROM knowledge_evidence
             WHERE knowledge_id = ANY($1) AND episode_id = ANY($2)",
        )
        .bind(&affected_knowledge)
        .bind(&episode_ids)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?
        .rows_affected();
        for kid in &affected_knowledge {
            let row = sqlx::query(
                "SELECT count(DISTINCT entity) AS entities, count(*) AS episodes
                 FROM knowledge_evidence WHERE knowledge_id = $1",
            )
            .bind(kid)
            .fetch_one(&mut **tx)
            .await
            .map_err(db_err)?;
            let distinct: i64 = row.try_get("entities").map_err(db_err)?;
            let episodes: i64 = row.try_get("episodes").map_err(db_err)?;
            sqlx::query(
                "UPDATE knowledge SET distinct_entities = $2, episode_count = $3 WHERE id = $1",
            )
            .bind(kid)
            .bind(distinct as i32)
            .bind(episodes as i32)
            .execute(&mut **tx)
            .await
            .map_err(db_err)?;
            if distinct < 3 {
                let invalidated = sqlx::query(
                    "UPDATE knowledge
                     SET status = 'invalidated', invalidated_at = now(),
                         invalidated_reason = 'erasure_support_withdrawn'
                     WHERE id = $1 AND status = 'published'",
                )
                .bind(kid)
                .execute(&mut **tx)
                .await
                .map_err(db_err)?
                .rows_affected();
                report.knowledge_invalidated += invalidated;
                if invalidated > 0 {
                    sqlx::query(
                        "UPDATE chunks SET valid_to = now()
                         WHERE tenant_id = $1 AND document_id = $2 AND valid_to IS NULL",
                    )
                    .bind(tenant)
                    .bind(format!("knowledge:{kid}"))
                    .execute(&mut **tx)
                    .await
                    .map_err(db_err)?;
                }
            }
        }

        // 6. Quarantine-preview payloads mentioning the subject/entity.
        //    Substring match is conservative by design: over-deleting an
        //    unparsed payload is safe, retaining PII is not.
        report.quarantine_preview = sqlx::query(
            "DELETE FROM quarantine_preview
             WHERE tenant_id = $1
               AND (($2::text IS NOT NULL AND payload::text ILIKE '%' || $2 || '%')
                 OR ($3::text IS NOT NULL AND payload::text ILIKE '%' || $3 || '%'))",
        )
        .bind(tenant)
        .bind(subject)
        .bind(entity)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?
        .rows_affected();

        // 7. The subject's own audit rows (their query text is their data).
        //    Other actors' rows survive — result_ids are opaque uuids of
        //    now-deleted rows, a skeleton with no payload (SPEC §8b "redact
        //    payloads, preserve skeleton").
        if let Some(subject) = subject {
            report.audit_log =
                sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1 AND actor_sub = $2")
                    .bind(tenant)
                    .bind(subject)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_err)?
                    .rows_affected();
        }

        // 8. Explicitly named media blobs, same transaction. Tenant-checked:
        //    an id belonging to another tenant (or unknown) deletes nothing
        //    and shows up as a shortfall in the returned count. Media has no
        //    subject attribution in v0, so this is operator-named, not walked.
        if !media_ids.is_empty() {
            report.media = sqlx::query("DELETE FROM media WHERE tenant_id = $1 AND id = ANY($2)")
                .bind(tenant)
                .bind(media_ids)
                .execute(&mut **tx)
                .await
                .map_err(db_err)?
                .rows_affected();
        }

        // 9. Finally the L0 episodes themselves.
        report.episodes = sqlx::query("DELETE FROM episodes WHERE tenant_id = $1 AND id = ANY($2)")
            .bind(tenant)
            .bind(&episode_ids)
            .execute(&mut **tx)
            .await
            .map_err(db_err)?
            .rows_affected();

        // The caller commits (erase) or rolls back (preview) and, if it
        // committed, writes the single surviving audit row.
        Ok(report)
    }

    /// GET /v1/admin/dsar/export (SPEC §8e): everything attributable to a
    /// subject, as one machine-readable JSON bundle. Episode payloads are
    /// decrypted under admin authority; the caller audits the access.
    pub async fn dsar_export(&self, tenant: TenantId, subject: &str) -> Result<serde_json::Value> {
        // L0 episodes the subject wrote.
        let rows = sqlx::query(
            "SELECT id, source, source_entity, kind, payload, payload_enc, content_hash,
                    trust_tier, writer_sub, writer_azp, recorded_at
             FROM episodes WHERE tenant_id = $1 AND writer_sub = $2
             ORDER BY recorded_at",
        )
        .bind(tenant)
        .bind(subject)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?;
        let mut episode_ids: Vec<Uuid> = Vec::with_capacity(rows.len());
        let mut episodes = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: Uuid = row.try_get("id").map_err(db_err)?;
            episode_ids.push(id);
            let payload = self
                .decrypt_payload(
                    tenant,
                    row.try_get("payload").map_err(db_err)?,
                    row.try_get("payload_enc").map_err(db_err)?,
                )
                .await?;
            episodes.push(serde_json::json!({
                "id": id,
                "source": row.try_get::<String, _>("source").map_err(db_err)?,
                "source_entity": row.try_get::<Option<String>, _>("source_entity").map_err(db_err)?,
                "kind": row.try_get::<String, _>("kind").map_err(db_err)?,
                "payload": payload,
                "content_hash": row.try_get::<String, _>("content_hash").map_err(db_err)?,
                "trust_tier": row.try_get::<i16, _>("trust_tier").map_err(db_err)?,
                "writer_sub": row.try_get::<Option<String>, _>("writer_sub").map_err(db_err)?,
                "writer_azp": row.try_get::<Option<String>, _>("writer_azp").map_err(db_err)?,
                "recorded_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at").map_err(db_err)?,
            }));
        }

        // Chunks derived from those episodes.
        let chunks = sqlx::query(
            "SELECT id, source, document_id, seq, content, entity_tags, kind,
                    confidentiality, trust_tier, valid_from, valid_to, provenance
             FROM chunks WHERE tenant_id = $1 AND provenance = ANY($2)
             ORDER BY valid_from",
        )
        .bind(tenant)
        .bind(&episode_ids)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(db_err)?,
                "source": row.try_get::<String, _>("source").map_err(db_err)?,
                "document_id": row.try_get::<String, _>("document_id").map_err(db_err)?,
                "seq": row.try_get::<i32, _>("seq").map_err(db_err)?,
                "content": row.try_get::<String, _>("content").map_err(db_err)?,
                "entity_tags": row.try_get::<Vec<String>, _>("entity_tags").map_err(db_err)?,
                "kind": row.try_get::<String, _>("kind").map_err(db_err)?,
                "confidentiality": row.try_get::<i16, _>("confidentiality").map_err(db_err)?,
                "trust_tier": row.try_get::<i16, _>("trust_tier").map_err(db_err)?,
                "valid_from": row.try_get::<chrono::DateTime<chrono::Utc>, _>("valid_from").map_err(db_err)?,
                "valid_to": row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("valid_to").map_err(db_err)?,
                "provenance": row.try_get::<Uuid, _>("provenance").map_err(db_err)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;

        // L1 facts derived from those episodes — linked by provenance exactly
        // like chunks. DSAR runs under admin authority (SPEC §8e), so this is
        // deliberately the admin-all view: it exports facts regardless of their
        // per-principal visibility (migration 0026), because a subject-access
        // request must return everything attributable to the subject, not only
        // what some scope could read. The visibility tokens themselves are
        // included so the export is faithful about who could see each fact.
        let facts = sqlx::query(
            "SELECT id, source, entity_id, field, value, valid_from, valid_to,
                    superseded_by, recorded_at, provenance, acl_provenance,
                    visibility, confidentiality
             FROM facts WHERE tenant_id = $1 AND provenance = ANY($2)
             ORDER BY valid_from",
        )
        .bind(tenant)
        .bind(&episode_ids)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(db_err)?,
                "source": row.try_get::<String, _>("source").map_err(db_err)?,
                "entity_id": row.try_get::<String, _>("entity_id").map_err(db_err)?,
                "field": row.try_get::<String, _>("field").map_err(db_err)?,
                "value": row.try_get::<serde_json::Value, _>("value").map_err(db_err)?,
                "valid_from": row.try_get::<chrono::DateTime<chrono::Utc>, _>("valid_from").map_err(db_err)?,
                "valid_to": row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("valid_to").map_err(db_err)?,
                "superseded_by": row.try_get::<Option<Uuid>, _>("superseded_by").map_err(db_err)?,
                "recorded_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at").map_err(db_err)?,
                "provenance": row.try_get::<Uuid, _>("provenance").map_err(db_err)?,
                "acl_provenance": row.try_get::<String, _>("acl_provenance").map_err(db_err)?,
                "visibility": row.try_get::<Vec<i32>, _>("visibility").map_err(db_err)?,
                "confidentiality": row.try_get::<i16, _>("confidentiality").map_err(db_err)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;

        // The subject's actions.
        let actions = sqlx::query(
            "SELECT id, action_id, actor_sub, actor_azp, action_type, entities, summary,
                    payload, outcome, occurred_at, recorded_at
             FROM actions WHERE tenant_id = $1 AND actor_sub = $2
             ORDER BY occurred_at",
        )
        .bind(tenant)
        .bind(subject)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(db_err)?,
                "action_id": row.try_get::<String, _>("action_id").map_err(db_err)?,
                "actor_sub": row.try_get::<Option<String>, _>("actor_sub").map_err(db_err)?,
                "actor_azp": row.try_get::<Option<String>, _>("actor_azp").map_err(db_err)?,
                "action_type": row.try_get::<String, _>("action_type").map_err(db_err)?,
                "entities": row.try_get::<Vec<String>, _>("entities").map_err(db_err)?,
                "summary": row.try_get::<String, _>("summary").map_err(db_err)?,
                "payload": row.try_get::<serde_json::Value, _>("payload").map_err(db_err)?,
                "outcome": row.try_get::<String, _>("outcome").map_err(db_err)?,
                "occurred_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("occurred_at").map_err(db_err)?,
                "recorded_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("recorded_at").map_err(db_err)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;

        // The subject's access events (who-retrieved-what skeleton).
        let audit = sqlx::query(
            "SELECT id, verb, query_summary, result_ids, at
             FROM audit_log WHERE tenant_id = $1 AND actor_sub = $2
             ORDER BY at",
        )
        .bind(tenant)
        .bind(subject)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(db_err)?,
                "verb": row.try_get::<String, _>("verb").map_err(db_err)?,
                "query_summary": row.try_get::<Option<String>, _>("query_summary").map_err(db_err)?,
                "result_ids": row.try_get::<Vec<Uuid>, _>("result_ids").map_err(db_err)?,
                "at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("at").map_err(db_err)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;

        // Knowledge items the subject proposed.
        let knowledge = sqlx::query(
            "SELECT id, statement, categories, status, distinct_entities, episode_count,
                    first_seen, published_at
             FROM knowledge WHERE tenant_id = $1 AND proposed_by_sub = $2
             ORDER BY first_seen",
        )
        .bind(tenant)
        .bind(subject)
        .fetch_all(self.pool())
        .await
        .map_err(db_err)?
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "id": row.try_get::<Uuid, _>("id").map_err(db_err)?,
                "statement": row.try_get::<String, _>("statement").map_err(db_err)?,
                "categories": row.try_get::<Vec<String>, _>("categories").map_err(db_err)?,
                "status": row.try_get::<String, _>("status").map_err(db_err)?,
                "distinct_entities": row.try_get::<i32, _>("distinct_entities").map_err(db_err)?,
                "episode_count": row.try_get::<i32, _>("episode_count").map_err(db_err)?,
                "first_seen": row.try_get::<chrono::DateTime<chrono::Utc>, _>("first_seen").map_err(db_err)?,
                "published_at": row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("published_at").map_err(db_err)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;

        Ok(serde_json::json!({
            "tenant_id": tenant,
            "subject": subject,
            "generated_at": chrono::Utc::now(),
            "episodes": episodes,
            "chunks": chunks,
            "facts": facts,
            "actions": actions,
            "audit_log": audit,
            "knowledge": knowledge,
        }))
    }
}

fn sha256_hex(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}
