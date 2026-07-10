//! Action records against the Qdrant hybrid profile: idempotency, scoped
//! timeline reads (delegated), fail-closed rules, and recall surfacing (BM25
//! delegated leg + the mirrored action point in Qdrant). Adapted copy of
//! `verity-storage/tests/actions.rs`. Requires VERITY_TEST_DSN +
//! VERITY_QDRANT_URL; skips when absent.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage_qdrant::QdrantAdapter;

async fn test_adapter() -> Option<(QdrantAdapter, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let qurl = std::env::var("VERITY_QDRANT_URL").ok()?;
    let adapter = QdrantAdapter::connect(&dsn, &qurl).await.expect("connect");
    adapter.inner().migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("qtest-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    Some((adapter, tenant))
}

fn quote_action(tenant: TenantId, action_id: &str, at: chrono::DateTime<Utc>) -> ActionWrite {
    ActionWrite {
        tenant_id: tenant,
        action_id: action_id.into(),
        actor_sub: Some("user:jane".into()),
        actor_azp: Some("agent:sales-bot".into()),
        action_type: "quote.issued".into(),
        entities: vec!["account:acme".into()],
        summary: "Issued renewal quote at $84,000 (12mo, net-30).".into(),
        payload: json!({ "amount": 84000 }),
        outcome: ActionOutcome::Succeeded,
        occurred_at: at,
        visibility: vec![7],
        confidentiality: Confidentiality::Confidential,
    }
}

fn scope(tenant: TenantId, principals: Vec<PrincipalToken>) -> Scope {
    Scope {
        tenant_id: tenant,
        principals,
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Confidential,
    }
}

fn timeline(scope: Scope, entity: &str) -> ActivityQuery {
    ActivityQuery {
        scope,
        entity: entity.into(),
        since: None,
        action_types: vec![],
        actors: vec![],
        limit: 50,
    }
}

#[tokio::test]
async fn record_is_idempotent_and_timeline_is_ordered() {
    let Some((adapter, tenant)) = test_adapter().await else {
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
        return;
    };
    let t0 = Utc::now() - Duration::hours(2);

    assert!(adapter
        .record_action(quote_action(tenant, "a1", t0))
        .await
        .unwrap());
    // Replay of the same action_id is a no-op.
    assert!(!adapter
        .record_action(quote_action(tenant, "a1", t0))
        .await
        .unwrap());

    let mut email = quote_action(tenant, "a2", t0 + Duration::hours(1));
    email.action_type = "email.sent".into();
    email.actor_azp = Some("agent:marketing-bot".into());
    email.summary = "Sent renewal follow-up email.".into();
    assert!(adapter.record_action(email).await.unwrap());

    let acts = adapter
        .activity(timeline(scope(tenant, vec![7]), "account:acme"))
        .await
        .unwrap();
    assert_eq!(acts.len(), 2);
    // Newest first; actor identity preserved.
    assert_eq!(acts[0].action_type, "email.sent");
    assert_eq!(acts[1].action_type, "quote.issued");
    assert_eq!(acts[1].actor_azp.as_deref(), Some("agent:sales-bot"));

    // Prefix pattern filter.
    let mut q = timeline(scope(tenant, vec![7]), "account:acme");
    q.action_types = vec!["quote.*".into()];
    let acts = adapter.activity(q).await.unwrap();
    assert_eq!(acts.len(), 1);
    assert_eq!(acts[0].action_type, "quote.issued");

    // Actor filter: agent B asks "what did sales-bot do here?"
    let mut q = timeline(scope(tenant, vec![7]), "account:acme");
    q.actors = vec!["agent:sales-bot".into()];
    assert_eq!(adapter.activity(q).await.unwrap().len(), 1);

    // The mirrored action points surface through latest_chunks (served from
    // Qdrant), newest first — addition over the Postgres copy to cover the
    // mirror path.
    let latest = adapter
        .latest_chunks(&scope(tenant, vec![7]), "account:acme", 10)
        .await
        .unwrap();
    assert_eq!(latest.len(), 2);
    assert_eq!(latest[0].document_id, "action:a2");
    assert_eq!(latest[1].document_id, "action:a1");
}

#[tokio::test]
async fn activity_fails_closed() {
    let Some((adapter, tenant)) = test_adapter().await else {
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
        return;
    };
    let t0 = Utc::now();
    adapter
        .record_action(quote_action(tenant, "b1", t0))
        .await
        .unwrap();

    // Empty principal set: nothing.
    let acts = adapter
        .activity(timeline(scope(tenant, vec![]), "account:acme"))
        .await
        .unwrap();
    assert!(acts.is_empty());

    // Wrong principal: nothing.
    let acts = adapter
        .activity(timeline(scope(tenant, vec![8]), "account:acme"))
        .await
        .unwrap();
    assert!(acts.is_empty());

    // Confidentiality ceiling below the action's class: nothing.
    let mut s = scope(tenant, vec![7]);
    s.max_confidentiality = Confidentiality::Internal;
    assert!(adapter
        .activity(timeline(s, "account:acme"))
        .await
        .unwrap()
        .is_empty());

    // Entity-bound scope for a different entity may not query acme's timeline.
    let mut s = scope(tenant, vec![7]);
    s.entity_scope = vec!["account:globex".into()];
    assert!(adapter
        .activity(timeline(s, "account:acme"))
        .await
        .unwrap()
        .is_empty());

    // The action's chunk shows up in scoped semantic recall (BM25 path)...
    let hits = adapter
        .recall(RecallQuery {
            scope: scope(tenant, vec![7]),
            embedding: None,
            text: Some("renewal quote".into()),
            k: 5,
        })
        .await
        .unwrap();
    assert!(hits.iter().any(|h| h.document_id == "action:b1"));

    // ...and stays invisible to the wrong principal there too.
    let hits = adapter
        .recall(RecallQuery {
            scope: scope(tenant, vec![8]),
            embedding: None,
            text: Some("renewal quote".into()),
            k: 5,
        })
        .await
        .unwrap();
    assert!(hits.iter().all(|h| h.document_id != "action:b1"));
}

#[tokio::test]
async fn recall_tolerates_query_syntax_characters() {
    let Some((adapter, tenant)) = test_adapter().await else {
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
        return;
    };
    adapter
        .record_action(quote_action(tenant, "syn-1", Utc::now()))
        .await
        .unwrap();
    // Apostrophes, quotes, colons, and parens are user text, never Tantivy
    // query syntax.
    for text in [
        "the agent's renewal quote",
        "\"quoted phrase\" and more",
        "field:injection (attempt) AND OR",
    ] {
        let hits = adapter
            .recall(RecallQuery {
                scope: scope(tenant, vec![7]),
                embedding: None,
                text: Some(text.into()),
                k: 5,
            })
            .await
            .unwrap_or_else(|e| panic!("recall failed on {text:?}: {e}"));
        drop(hits);
    }
}
