//! ZERO-TOKEN-HANDLE PROBE (M0 deliverable #3): a scope/handle resolving to an
//! EMPTY principal set (`scope.principals == []`) must return NOTHING from
//! EVERY read entry point. This is the fail-closed core of the whole trust
//! story — an unresolvable subject sees nothing, never "everything" — and it
//! has a DEMONSTRATED history of silent violation (SPEC §5e.6a: L1 facts once
//! returned to a zero-token handle). One test, every read method, non-skippable.
//!
//! Enforcement lives in the ONE shared layer above the `StorageAdapter` trait,
//! so probing at the adapter level covers the invariant: the HTTP handlers are
//! thin pass-throughs that build a `Scope` via `scope_for` (which only SHRINKS
//! the principal set via revocation subtraction — it can never re-inflate an
//! empty set), so an adapter-level empty-principal probe is the load-bearing
//! proof. The read methods enumerated here are the real scope-taking reads on
//! the trait + the inherent `merged_record` (the cross-source welded view —
//! the "adjacency/related" surface).
//!
//! Requires VERITY_TEST_DSN; HARD-ERRORS (panics) when absent, exactly like the
//! scope fuzzer — a fail-closed gate that silently no-ops is the single most
//! dangerous process gap in the trust story.

use chrono::{Duration, Utc};
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

const ENTITY: &str = "account:acme";
const CANONICAL: &str = "det:zero-canon";
const MEMBER_SOURCE: &str = "hubspot";
const MEMBER_ENTITY: &str = "det:zero-acme";
/// The single token EVERY seeded item is visible to. A populated scope holding
/// it must SEE the content (control); an empty scope must not.
const TOKEN: PrincipalToken = 5;

async fn seeded() -> (PostgresAdapter, TenantId, EpisodeId, FactKey) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the zero-token-handle fail-closed probe; refusing to \
         silently no-op — an empty-principal read leaking is the exact §5e.6a failure this gate \
         exists to catch",
    );
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("zero-token-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "test".into(),
            source_entity: None,
            kind: EpisodeKind::CdcEvent,
            payload: json!({}),
            content_hash: "zt".into(),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("episode");
    let now = Utc::now();

    // A chunk visible to TOKEN, tagged with ENTITY (feeds recall + latest_chunks).
    adapter
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "test".into(),
            document_id: "zt-doc".into(),
            seq: 0,
            content: "quantum acme renewal pricing".into(),
            content_hash: "zt-c".into(),
            embedding: Some({
                let v: Vec<f32> = (0..384).map(|i| (i as f32).sin()).collect();
                let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                v.into_iter().map(|x| x / n).collect()
            }),
            visibility: vec![TOKEN],
            entity_tags: vec![ENTITY.into()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: now - Duration::hours(1),
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
            derived_from: vec![],
        }])
        .await
        .expect("chunk");

    // An action targeting ENTITY (feeds activity).
    adapter
        .record_action(ActionWrite {
            tenant_id: tenant,
            action_id: "zt-act".into(),
            actor_sub: Some("user:seed".into()),
            actor_azp: Some("agent:seed".into()),
            action_type: "zt.probe".into(),
            entities: vec![ENTITY.into()],
            summary: "quantum action".into(),
            payload: json!({}),
            outcome: ActionOutcome::Succeeded,
            occurred_at: now,
            visibility: vec![TOKEN],
            confidentiality: Confidentiality::Internal,
        })
        .await
        .expect("action");

    // A fact under a canonical entity (feeds current_fact, fact_as_of,
    // merged_record). The alias welds MEMBER_ENTITY into CANONICAL.
    let key = FactKey {
        source: MEMBER_SOURCE.into(),
        entity_id: MEMBER_ENTITY.into(),
        field: "name".into(),
    };
    adapter
        .upsert_entity_alias(tenant, MEMBER_SOURCE, MEMBER_ENTITY, CANONICAL)
        .await
        .expect("alias");
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: key.clone(),
            value: json!("acme-name"),
            valid_from: now - Duration::hours(1),
            visibility: vec![TOKEN],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .expect("fact");

    // Materialize the brief (its item-serving leg is latest_chunks).
    adapter.refresh_brief(tenant, ENTITY).await.expect("brief");

    (adapter, tenant, episode, key)
}

fn scope(tenant: TenantId, principals: Vec<PrincipalToken>) -> Scope {
    Scope {
        tenant_id: tenant,
        principals,
        // Unbounded entity scope + top ceiling: the STRONGEST possible reader,
        // so the only thing keeping the empty scope empty is the empty principal
        // set — no entity fence or confidentiality ceiling can be credited.
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    }
}

/// An empty principal set returns NOTHING from every read entry point; a
/// populated scope carrying the seeding token DOES see the content (so the
/// empties are provably non-vacuous).
#[tokio::test]
async fn empty_principal_set_returns_nothing_from_every_read_path() {
    let (adapter, tenant, _episode, key) = seeded().await;

    let empty = scope(tenant, vec![]);
    let populated = scope(tenant, vec![TOKEN]);
    let now = Utc::now();

    let recall_q = |scope: Scope, embedding: Option<Vec<f32>>| RecallQuery {
        scope,
        embedding,
        text: Some("quantum".into()),
        k: 50,
    };
    let hybrid_embedding = || {
        let v: Vec<f32> = (0..384).map(|i| (i as f32).cos()).collect();
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        Some(v.into_iter().map(|x| x / n).collect::<Vec<f32>>())
    };

    // ---- CONTROL: the populated scope sees the content on every path, so a
    // later empty result is a real deny, not a seeding/vacuity artifact. ----
    assert!(
        !adapter
            .recall(recall_q(populated.clone(), None))
            .await
            .expect("recall")
            .is_empty(),
        "control: populated scope must see the chunk via recall(bm25)"
    );
    assert!(
        !adapter
            .recall(recall_q(populated.clone(), hybrid_embedding()))
            .await
            .expect("recall")
            .is_empty(),
        "control: populated scope must see the chunk via recall(hybrid)"
    );
    assert!(
        adapter
            .current_fact(&populated, &key)
            .await
            .expect("current_fact")
            .is_some(),
        "control: populated scope must see the fact via current_fact"
    );
    assert!(
        adapter
            .fact_as_of(&populated, &key, now)
            .await
            .expect("fact_as_of")
            .is_some(),
        "control: populated scope must see the fact via fact_as_of"
    );
    assert!(
        !adapter
            .latest_chunks(&populated, ENTITY, 50)
            .await
            .expect("latest_chunks")
            .is_empty(),
        "control: populated scope must see the chunk via latest_chunks"
    );
    assert!(
        !adapter
            .activity(ActivityQuery {
                scope: populated.clone(),
                entity: ENTITY.into(),
                since: None,
                action_types: vec![],
                actors: vec![],
                limit: 50,
            })
            .await
            .expect("activity")
            .is_empty(),
        "control: populated scope must see the action via activity"
    );
    assert!(
        adapter
            .merged_record(&populated, CANONICAL)
            .await
            .expect("merged_record")
            .fields
            .contains_key("name"),
        "control: populated scope must see the field via merged_record"
    );

    // ---- THE PROBE: an empty principal set reads NOTHING, everywhere. ----

    // recall — BM25-only.
    assert!(
        adapter
            .recall(recall_q(empty.clone(), None))
            .await
            .expect("recall")
            .is_empty(),
        "ZERO-TOKEN LEAK: recall(bm25) returned rows to an empty principal set"
    );
    // recall — hybrid (dense + BM25).
    assert!(
        adapter
            .recall(recall_q(empty.clone(), hybrid_embedding()))
            .await
            .expect("recall")
            .is_empty(),
        "ZERO-TOKEN LEAK: recall(hybrid) returned rows to an empty principal set"
    );

    // current_fact.
    assert!(
        adapter
            .current_fact(&empty, &key)
            .await
            .expect("current_fact")
            .is_none(),
        "ZERO-TOKEN LEAK: current_fact returned a fact to an empty principal set"
    );

    // fact_as_of — at several event times, incl. before the first write and now.
    for at in [
        now - Duration::hours(5),
        now - Duration::minutes(30),
        now,
        now + Duration::hours(1),
    ] {
        assert!(
            adapter
                .fact_as_of(&empty, &key, at)
                .await
                .expect("fact_as_of")
                .is_none(),
            "ZERO-TOKEN LEAK: fact_as_of returned a fact @ {at} to an empty principal set"
        );
    }

    // latest_chunks (the brief's item-serving memory leg).
    assert!(
        adapter
            .latest_chunks(&empty, ENTITY, 50)
            .await
            .expect("latest_chunks")
            .is_empty(),
        "ZERO-TOKEN LEAK: latest_chunks returned rows to an empty principal set"
    );

    // activity.
    assert!(
        adapter
            .activity(ActivityQuery {
                scope: empty.clone(),
                entity: ENTITY.into(),
                since: None,
                action_types: vec![],
                actors: vec![],
                limit: 50,
            })
            .await
            .expect("activity")
            .is_empty(),
        "ZERO-TOKEN LEAK: activity returned rows to an empty principal set"
    );

    // merged_record (the cross-source welded / "adjacency-related" view): no
    // field may resolve, and no superseded alternative may surface.
    let merged = adapter
        .merged_record(&empty, CANONICAL)
        .await
        .expect("merged_record");
    assert!(
        merged.fields.is_empty(),
        "ZERO-TOKEN LEAK: merged_record resolved fields for an empty principal set: {:?}",
        merged.fields.keys().collect::<Vec<_>>()
    );
    for (field, mf) in &merged.fields {
        assert!(
            mf.superseded_alternatives.is_empty(),
            "ZERO-TOKEN LEAK: merged_record surfaced a superseded alternative for {field}"
        );
    }

    println!(
        "zero-token probe: empty principal set returned nothing from recall(bm25), \
         recall(hybrid), current_fact, fact_as_of, latest_chunks, activity, merged_record — \
         and the populated control saw all of them"
    );
}
