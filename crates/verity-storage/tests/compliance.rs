//! Compliance plane v0 (SPEC §8, roadmap task 23): DEK/envelope-encryption
//! roundtrip, hard erasure (subject + entity), and the DSAR export bundle.
//! Requires VERITY_TEST_DSN; skips when absent.

use chrono::Utc;
use serde_json::json;
use sqlx::Row;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{Kek, PostgresAdapter};

const TEST_KEK_HEX: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";

async fn setup(kek: Option<Kek>) -> Option<(PostgresAdapter, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let adapter = PostgresAdapter::connect_with_kek(&dsn, kek)
        .await
        .expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    Some((adapter, tenant))
}

fn kek() -> Kek {
    Kek::from_hex(TEST_KEK_HEX).expect("valid test KEK")
}

/// One scoped interaction attributed to `entity`/`writer_sub`: an L0 episode
/// plus a derived chunk tagged with the entity.
async fn interaction(
    adapter: &PostgresAdapter,
    tenant: TenantId,
    entity: &str,
    writer_sub: Option<&str>,
    writer_azp: &str,
) -> EpisodeId {
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "agent".into(),
            source_entity: Some(entity.into()),
            kind: EpisodeKind::Observation,
            payload: json!({ "observation": format!("renewal pricing notes for {entity}") }),
            content_hash: format!("i-{entity}-{writer_azp}"),
            trust_tier: TrustTier::Observation,
            writer_sub: writer_sub.map(Into::into),
            writer_azp: Some(writer_azp.into()),
        })
        .await
        .unwrap();
    adapter
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "agent".into(),
            document_id: format!("doc-{entity}-{writer_azp}"),
            seq: 0,
            content: format!("churn signal renewal negotiation notes for {entity}"),
            content_hash: format!("c-{entity}-{writer_azp}"),
            embedding: None,
            visibility: vec![7],
            entity_tags: vec![entity.into()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Observation,
            valid_from: Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        }])
        .await
        .unwrap();
    episode
}

fn scope(tenant: TenantId) -> Scope {
    Scope {
        tenant_id: tenant,
        principals: vec![7],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Confidential,
    }
}

async fn recall_text(adapter: &PostgresAdapter, tenant: TenantId, text: &str) -> Vec<RecallHit> {
    adapter
        .recall(RecallQuery {
            scope: scope(tenant),
            embedding: None,
            text: Some(text.into()),
            k: 50,
        })
        .await
        .unwrap()
}

// ---------- DEK / envelope-encryption roundtrip ----------

#[tokio::test]
async fn dek_roundtrip_with_kek() {
    let Some((adapter, tenant)) = setup(Some(kek())).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let payload = json!({ "observation": "customer asked for a 20% discount", "n": 42 });
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "agent".into(),
            source_entity: Some("account:acme".into()),
            kind: EpisodeKind::Observation,
            payload: payload.clone(),
            content_hash: "h1".into(),
            trust_tier: TrustTier::Observation,
            writer_sub: Some("user:alice".into()),
            writer_azp: None,
        })
        .await
        .unwrap();

    // At rest: sentinel payload, ciphertext present, marker set.
    let row =
        sqlx::query("SELECT payload, payload_enc, payload_encrypted FROM episodes WHERE id = $1")
            .bind(episode)
            .fetch_one(adapter.pool())
            .await
            .unwrap();
    assert_eq!(
        row.try_get::<serde_json::Value, _>("payload").unwrap(),
        json!({}),
        "plaintext payload must be replaced by the sentinel"
    );
    let enc: Option<Vec<u8>> = row.try_get("payload_enc").unwrap();
    assert!(enc.is_some(), "payload_enc must hold the ciphertext");
    assert_eq!(
        row.try_get::<Option<bool>, _>("payload_encrypted").unwrap(),
        Some(true)
    );

    // The stored DEK is KEK-wrapped (longer than the raw 32 bytes).
    let dek: Vec<u8> = sqlx::query_scalar("SELECT dek FROM tenant_deks WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(adapter.pool())
        .await
        .unwrap();
    assert!(
        dek.len() > 32,
        "DEK must be stored wrapped when a KEK is set"
    );

    // Decrypt-on-demand returns the original payload.
    let decrypted = adapter.episode_payload(tenant, episode).await.unwrap();
    assert_eq!(decrypted, Some(payload));

    // A fresh adapter (cold DEK cache) with the same KEK also decrypts.
    let dsn = std::env::var("VERITY_TEST_DSN").unwrap();
    let fresh = PostgresAdapter::connect_with_kek(&dsn, Some(kek()))
        .await
        .unwrap();
    assert!(fresh
        .episode_payload(tenant, episode)
        .await
        .unwrap()
        .is_some());

    // Without the KEK, the wrapped DEK fails closed.
    let keyless = PostgresAdapter::connect_with_kek(&dsn, None).await.unwrap();
    assert!(keyless.episode_payload(tenant, episode).await.is_err());
}

#[tokio::test]
async fn without_kek_payloads_stay_plaintext_and_dek_is_unwrapped() {
    let Some((adapter, tenant)) = setup(None).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let payload = json!({ "observation": "plaintext mode" });
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "agent".into(),
            source_entity: None,
            kind: EpisodeKind::Observation,
            payload: payload.clone(),
            content_hash: "h2".into(),
            trust_tier: TrustTier::Observation,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .unwrap();
    let row = sqlx::query("SELECT payload, payload_enc FROM episodes WHERE id = $1")
        .bind(episode)
        .fetch_one(adapter.pool())
        .await
        .unwrap();
    assert_eq!(
        row.try_get::<serde_json::Value, _>("payload").unwrap(),
        payload
    );
    assert_eq!(
        row.try_get::<Option<Vec<u8>>, _>("payload_enc").unwrap(),
        None
    );
    // DEK is still provisioned (lazily), stored as raw 32 plaintext bytes.
    let dek: Vec<u8> = sqlx::query_scalar("SELECT dek FROM tenant_deks WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(adapter.pool())
        .await
        .unwrap();
    assert_eq!(dek.len(), 32);
    // Reads pass the plaintext through.
    assert_eq!(
        adapter.episode_payload(tenant, episode).await.unwrap(),
        Some(payload)
    );
}

/// Task 28: record_action's L0 provenance episode must flow through the same
/// encrypted insert path as append_episode — sentinel payload, ciphertext in
/// payload_enc, decrypt-on-demand roundtrip.
#[tokio::test]
async fn record_action_episode_is_encrypted_with_kek() {
    let Some((adapter, tenant)) = setup(Some(kek())).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let action_id = format!("act-{}", uuid::Uuid::now_v7());
    adapter
        .record_action(ActionWrite {
            tenant_id: tenant,
            action_id: action_id.clone(),
            actor_sub: Some("user:enc-actor".into()),
            actor_azp: Some("agent:enc".into()),
            action_type: "email.sent".into(),
            entities: vec!["account:acme".into()],
            summary: "sent a confidential renewal email".into(),
            payload: json!({ "to": "cfo@acme.example" }),
            outcome: ActionOutcome::Succeeded,
            occurred_at: Utc::now(),
            visibility: vec![7],
            confidentiality: Confidentiality::Internal,
        })
        .await
        .unwrap();

    let row = sqlx::query(
        "SELECT id, payload, payload_enc, payload_encrypted FROM episodes
         WHERE tenant_id = $1 AND kind = 'agent_action' AND source_entity = $2",
    )
    .bind(tenant)
    .bind(&action_id)
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert_eq!(
        row.try_get::<serde_json::Value, _>("payload").unwrap(),
        json!({}),
        "action episode payload must be the sentinel, not the serialized action"
    );
    assert!(
        row.try_get::<Option<Vec<u8>>, _>("payload_enc")
            .unwrap()
            .is_some(),
        "action episode must carry ciphertext"
    );
    assert_eq!(
        row.try_get::<Option<bool>, _>("payload_encrypted").unwrap(),
        Some(true)
    );
    // Roundtrip: decrypt-on-demand recovers the serialized action.
    let episode: uuid::Uuid = row.try_get("id").unwrap();
    let decrypted = adapter
        .episode_payload(tenant, episode)
        .await
        .unwrap()
        .expect("episode exists");
    assert_eq!(decrypted["summary"], "sent a confidential renewal email");
    assert_eq!(decrypted["payload"]["to"], "cfo@acme.example");
}

/// Task 28 companion: publish_knowledge's provenance episode also rides the
/// shared encrypted path.
#[tokio::test]
async fn publish_knowledge_episode_is_encrypted_with_kek() {
    let Some((adapter, tenant)) = setup(Some(kek())).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let e1 = interaction(&adapter, tenant, "account:alpha", None, "agent:a").await;
    let e2 = interaction(&adapter, tenant, "account:beta", None, "agent:b").await;
    let e3 = interaction(&adapter, tenant, "account:gamma", None, "agent:c").await;
    let item = adapter
        .propose_knowledge(KnowledgeProposal {
            tenant_id: tenant,
            statement: "Renewal conversations stall without an executive sponsor.".into(),
            categories: vec![],
            evidence: vec![e1, e2, e3],
            proposed_by_sub: None,
            proposed_by_azp: Some("agent:proposer".into()),
            canonical_statement: None,
        })
        .await
        .unwrap();
    adapter
        .publish_knowledge(tenant, item.id, vec![7], 3, None)
        .await
        .unwrap();

    let row = sqlx::query(
        "SELECT payload, payload_enc FROM episodes
         WHERE tenant_id = $1 AND kind = 'knowledge_publish' AND source_entity = $2",
    )
    .bind(tenant)
    .bind(item.id.to_string())
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert_eq!(
        row.try_get::<serde_json::Value, _>("payload").unwrap(),
        json!({}),
        "publish episode payload must be the sentinel"
    );
    assert!(row
        .try_get::<Option<Vec<u8>>, _>("payload_enc")
        .unwrap()
        .is_some());
}

// ---------- hard erasure ----------

#[tokio::test]
async fn subject_erasure_hard_deletes_and_cascades_knowledge() {
    let Some((adapter, tenant)) = setup(Some(kek())).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let subject = "user:gdpr-subject";

    // The subject's interaction supports a published knowledge item at
    // exactly the k=3 floor, together with two other writers' evidence.
    let e1 = interaction(
        &adapter,
        tenant,
        "account:medcore",
        Some(subject),
        "agent:a",
    )
    .await;
    let e2 = interaction(&adapter, tenant, "account:healthfirst", None, "agent:b").await;
    let e3 = interaction(&adapter, tenant, "account:vitalgroup", None, "agent:c").await;
    let item = adapter
        .propose_knowledge(KnowledgeProposal {
            tenant_id: tenant,
            statement: "Buyers in this segment escalate renewal pricing to procurement.".into(),
            categories: vec![],
            evidence: vec![e1, e2, e3],
            proposed_by_sub: None,
            proposed_by_azp: Some("agent:proposer".into()),
            canonical_statement: None,
        })
        .await
        .unwrap();
    adapter
        .publish_knowledge(tenant, item.id, vec![7], 3, None)
        .await
        .unwrap();

    // A fact derived from the subject's episode, and an action by the subject.
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: "agent".into(),
                entity_id: "account:medcore".into(),
                field: "stage".into(),
            },
            value: json!("negotiation"),
            valid_from: Utc::now(),
            visibility: vec![1],
            confidentiality: Confidentiality::Internal,
            provenance: e1,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();
    adapter
        .record_action(ActionWrite {
            tenant_id: tenant,
            action_id: format!("act-{}", uuid::Uuid::now_v7()),
            actor_sub: Some(subject.into()),
            actor_azp: Some("agent:a".into()),
            action_type: "email.sent".into(),
            entities: vec!["account:medcore".into()],
            summary: "sent renewal email".into(),
            payload: json!({}),
            outcome: ActionOutcome::Succeeded,
            occurred_at: Utc::now(),
            visibility: vec![7],
            confidentiality: Confidentiality::Internal,
        })
        .await
        .unwrap();

    let hits = recall_text(&adapter, tenant, "churn renewal medcore").await;
    assert!(
        hits.iter()
            .any(|h| h.entity_tags.contains(&"account:medcore".to_string())),
        "subject's chunk retrievable before erasure"
    );

    let report = adapter
        .erase(tenant, Some(subject), None, &[])
        .await
        .unwrap();
    assert_eq!(
        report.episodes, 2,
        "subject's observation episode + the action's L0 episode: {report:?}"
    );

    // Subject's data is gone from recall.
    let hits = recall_text(&adapter, tenant, "churn renewal medcore").await;
    assert!(
        !hits
            .iter()
            .any(|h| h.entity_tags.contains(&"account:medcore".to_string())),
        "subject's chunk still retrievable after erasure"
    );
    // The published item fell to 2 distinct entities: invalidated, carve-out retired.
    let (status, distinct): (String, i32) = {
        let row = sqlx::query("SELECT status, distinct_entities FROM knowledge WHERE id = $1")
            .bind(item.id)
            .fetch_one(adapter.pool())
            .await
            .unwrap();
        (
            row.try_get("status").unwrap(),
            row.try_get("distinct_entities").unwrap(),
        )
    };
    assert_eq!(status, "invalidated");
    assert_eq!(distinct, 2);
    let knowledge_hits = recall_text(&adapter, tenant, "procurement renewal pricing").await;
    assert!(
        !knowledge_hits.iter().any(|h| h.kind == "knowledge"),
        "retracted knowledge chunk still surfaces"
    );
    // Hard delete, not invalidation: no episode/action/fact rows remain.
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM episodes WHERE tenant_id = $1 AND writer_sub = $2",
    )
    .bind(tenant)
    .bind(subject)
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert_eq!(remaining, 0);
    let remaining_actions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM actions WHERE tenant_id = $1 AND actor_sub = $2")
            .bind(tenant)
            .bind(subject)
            .fetch_one(adapter.pool())
            .await
            .unwrap();
    assert_eq!(remaining_actions, 0);
    assert!(report.facts >= 1, "the derived fact must be hard-deleted");
    assert!(
        report.chunks >= 2,
        "observation chunk + action chunk deleted"
    );
    assert_eq!(report.knowledge_evidence, 1);
    assert_eq!(report.knowledge_invalidated, 1);

    // Exactly one surviving audit row, PII-free.
    let audit_rows = sqlx::query(
        "SELECT query_summary FROM audit_log WHERE tenant_id = $1 AND verb = 'erasure'",
    )
    .bind(tenant)
    .fetch_all(adapter.pool())
    .await
    .unwrap();
    assert_eq!(audit_rows.len(), 1);
    let summary: Option<String> = audit_rows[0].try_get("query_summary").unwrap();
    let summary = summary.unwrap();
    assert!(
        !summary.contains(subject),
        "audit row must not carry the subject in plaintext"
    );
    assert!(summary.contains("subject_sha256"));
}

#[tokio::test]
async fn entity_erasure_deletes_facts_and_multitag_chunks() {
    let Some((adapter, tenant)) = setup(None).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let entity = "contact:jane@example.com";
    let episode = interaction(&adapter, tenant, entity, None, "agent:crm").await;
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: "agent".into(),
                entity_id: entity.into(),
                field: "email".into(),
            },
            value: json!("jane@example.com"),
            valid_from: Utc::now(),
            visibility: vec![1],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();
    // A multi-tag chunk (the entity plus another): deleted whole, never
    // tag-stripped (conservative over-deletion, documented).
    let other_episode = interaction(&adapter, tenant, "account:other", None, "agent:x").await;
    adapter
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "agent".into(),
            document_id: "doc-multitag".into(),
            seq: 0,
            content: "meeting notes mentioning jane and the other account".into(),
            content_hash: "c-multitag".into(),
            embedding: None,
            visibility: vec![7],
            entity_tags: vec![entity.into(), "account:other".into()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Observation,
            valid_from: Utc::now(),
            provenance: other_episode,
            acl_provenance: AclProvenance::AdminAssigned,
        }])
        .await
        .unwrap();

    let report = adapter
        .erase(tenant, None, Some(entity), &[])
        .await
        .unwrap();
    assert_eq!(report.episodes, 1);
    assert_eq!(report.facts, 1);
    assert_eq!(
        report.chunks, 2,
        "entity chunk + multi-tag chunk both deleted"
    );

    let fact_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM facts WHERE tenant_id = $1 AND entity_id = $2")
            .bind(tenant)
            .bind(entity)
            .fetch_one(adapter.pool())
            .await
            .unwrap();
    assert_eq!(fact_rows, 0);
    let tagged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chunks WHERE tenant_id = $1 AND entity_tags @> ARRAY[$2::text]",
    )
    .bind(tenant)
    .bind(entity)
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert_eq!(tagged, 0);
    // The unrelated single-tag chunk for account:other survives.
    let other: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chunks WHERE tenant_id = $1 AND entity_tags = ARRAY['account:other']::text[]",
    )
    .bind(tenant)
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert_eq!(other, 1);

    // Neither-subject-nor-entity requests fail closed.
    assert!(adapter.erase(tenant, None, None, &[]).await.is_err());
}

/// Task 28: erasure with explicit media_ids purges the named blobs in the
/// same transaction, tenant-checked — a foreign tenant's id deletes nothing.
#[tokio::test]
async fn erasure_purges_listed_media_tenant_checked() {
    let Some((adapter, tenant)) = setup(None).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let (_, other_tenant) = setup(None).await.unwrap();

    async fn insert_media(adapter: &PostgresAdapter, tenant: TenantId, name: &str) -> uuid::Uuid {
        let id = uuid::Uuid::now_v7();
        sqlx::query(
            "INSERT INTO media (id, tenant_id, sha256, mime, filename, bytes, size_bytes)
             VALUES ($1, $2, 'deadbeef', 'text/plain', $3, $4, 5)",
        )
        .bind(id)
        .bind(tenant)
        .bind(name)
        .bind(b"hello".to_vec())
        .execute(adapter.pool())
        .await
        .unwrap();
        id
    }
    let mine = insert_media(&adapter, tenant, "subject-photo.txt").await;
    let kept = insert_media(&adapter, tenant, "unrelated.txt").await;
    let foreign = insert_media(&adapter, other_tenant, "foreign.txt").await;

    // Media-only erasure is legal (no subject/entity), and only the named,
    // tenant-owned blob goes.
    let report = adapter
        .erase(tenant, None, None, &[mine, foreign])
        .await
        .unwrap();
    assert_eq!(
        report.media, 1,
        "only the tenant-owned id purges: {report:?}"
    );
    assert_eq!(report.episodes, 0);

    let count = |id: uuid::Uuid| {
        let pool = adapter.pool().clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM media WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(count(mine).await, 0, "named blob hard-deleted");
    assert_eq!(count(kept).await, 1, "unnamed blob survives");
    assert_eq!(count(foreign).await, 1, "foreign tenant's blob survives");

    // Combined subject + media erasure works in one call/transaction.
    let subject = "user:media-subject";
    interaction(&adapter, tenant, "account:m", Some(subject), "agent:m").await;
    let second = insert_media(&adapter, tenant, "second.txt").await;
    let report = adapter
        .erase(tenant, Some(subject), None, &[second])
        .await
        .unwrap();
    assert_eq!(report.media, 1);
    assert_eq!(report.episodes, 1);
    assert_eq!(count(second).await, 0);
}

// ---------- DSAR export ----------

#[tokio::test]
async fn dsar_bundle_contains_expected_rows_with_decrypted_payloads() {
    let Some((adapter, tenant)) = setup(Some(kek())).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let subject = "user:dsar-subject";
    let subject_episode =
        interaction(&adapter, tenant, "account:acme", Some(subject), "agent:a").await;
    // An L1 fact derived from the subject's episode (linked by provenance) with
    // a RESTRICTED visibility no ordinary scope holds — DSAR runs under admin
    // authority and must export it regardless (SPEC §8e).
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: "agent".into(),
                entity_id: "account:acme".into(),
                field: "arr".into(),
            },
            value: json!(240000),
            valid_from: Utc::now(),
            visibility: vec![4242],
            confidentiality: Confidentiality::Restricted,
            provenance: subject_episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();
    adapter
        .record_action(ActionWrite {
            tenant_id: tenant,
            action_id: format!("act-{}", uuid::Uuid::now_v7()),
            actor_sub: Some(subject.into()),
            actor_azp: Some("agent:a".into()),
            action_type: "quote.issued".into(),
            entities: vec!["account:acme".into()],
            summary: "issued a quote".into(),
            payload: json!({ "amount": 1200 }),
            outcome: ActionOutcome::Succeeded,
            occurred_at: Utc::now(),
            visibility: vec![7],
            confidentiality: Confidentiality::Internal,
        })
        .await
        .unwrap();
    adapter
        .propose_knowledge(KnowledgeProposal {
            tenant_id: tenant,
            statement: "Quotes above list price stall in procurement review.".into(),
            categories: vec![],
            evidence: vec![],
            proposed_by_sub: Some(subject.into()),
            proposed_by_azp: None,
            canonical_statement: None,
        })
        .await
        .unwrap();

    let bundle = adapter.dsar_export(tenant, subject).await.unwrap();
    let episodes = bundle["episodes"].as_array().unwrap();
    // observation + the action's L0 episode
    assert_eq!(episodes.len(), 2);
    // Payloads come back decrypted, not as the '{}' sentinel.
    let obs = episodes
        .iter()
        .find(|e| e["kind"] == "observation")
        .expect("observation episode in bundle");
    assert!(
        obs["payload"]["observation"]
            .as_str()
            .unwrap()
            .contains("renewal pricing notes"),
        "episode payload must be decrypted in the DSAR bundle"
    );
    let chunks = bundle["chunks"].as_array().unwrap();
    assert!(
        chunks.len() >= 2,
        "observation chunk + action summary chunk expected, got {}",
        chunks.len()
    );
    // The subject's L1 fact is exported despite its restricted visibility —
    // DSAR is admin-authority, not scope-gated.
    let facts = bundle["facts"].as_array().unwrap();
    let arr = facts
        .iter()
        .find(|f| f["field"] == "arr")
        .expect("the subject's fact is in the DSAR bundle");
    assert_eq!(arr["value"], json!(240000));
    assert_eq!(
        arr["visibility"],
        json!([4242]),
        "the fact's visibility tokens are disclosed in the export"
    );
    assert_eq!(bundle["actions"].as_array().unwrap().len(), 1);
    assert_eq!(bundle["actions"][0]["action_type"], "quote.issued");
    assert_eq!(bundle["knowledge"].as_array().unwrap().len(), 1);
    assert_eq!(bundle["subject"], subject);
    // No rows for a stranger.
    let empty = adapter.dsar_export(tenant, "user:nobody").await.unwrap();
    assert!(empty["episodes"].as_array().unwrap().is_empty());
    assert!(empty["actions"].as_array().unwrap().is_empty());
    assert!(empty["facts"].as_array().unwrap().is_empty());
}
