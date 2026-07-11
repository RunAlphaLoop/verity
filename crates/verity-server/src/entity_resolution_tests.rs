//! Server-side cross-source entity resolution tests (SPEC §7f, task 50),
//! exercising the real handlers in-process: admin alias/precedence config and
//! the scope-handle-gated merged read. Scoping mirrors get_record — a bad
//! handle fails closed (401).
//! Requires VERITY_TEST_DSN; skips when absent.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::{ScopeMinter, ScopePayload};
use crate::{AdminAuth, AppState};

async fn test_state() -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("er-test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 10_000),
        encoder: None,
        minter: ScopeMinter::ephemeral(),
        purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
        admin: AdminAuth {
            key: [0u8; 32],
            expected_tag: None,
        },
        rebac: None,
        revocations: RevocationPlane::new(300),
        allow_restricted_without_rebac: false,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        media_store: None,
    });
    Some((state, tenant))
}

async fn fact(
    state: &AppState,
    tenant: TenantId,
    source: &str,
    entity_id: &str,
    field: &str,
    value: serde_json::Value,
) {
    let episode = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: source.into(),
            source_entity: Some(entity_id.into()),
            kind: EpisodeKind::CdcEvent,
            payload: json!({ field: value }),
            content_hash: format!("{source}-{entity_id}-{field}-{value}"),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("episode");
    state
        .storage
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: source.into(),
                entity_id: entity_id.into(),
                field: field.into(),
            },
            value,
            valid_from: Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .expect("fact");
}

fn handle(state: &AppState, tenant: TenantId) -> String {
    let (h, _) = state.minter.mint(
        ScopePayload {
            tenant_id: tenant,
            principals: vec![7],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted,
            actor_sub: None,
            actor_azp: None,
            subject: None,
            expires_at: Utc::now(),
        },
        300,
    );
    h
}

/// Full server flow: admin aliases + admin precedence + scope-gated GET
/// /v1/entities → merged record with the precedence winner and the superseded
/// alternative.
#[tokio::test]
async fn merged_entity_endpoint_resolves_precedence() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    fact(&state, tenant, "hubspot", "hs-1", "name", json!("Acme HS")).await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-1",
        "name",
        json!("Acme SF"),
    )
    .await;

    // Admin: alias both into account:acme.
    let _ = crate::admin_entity_aliases(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "tenant_id": tenant,
                "canonical": "account:acme",
                "members": [
                    {"source": "hubspot", "entity_id": "hs-1"},
                    {"source": "salesforce", "entity_id": "sf-1"}
                ]
            }))
            .unwrap(),
        ),
    )
    .await
    .expect("aliases");

    // Admin: salesforce wins `name`.
    let _ = crate::admin_entity_precedence(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "tenant_id": tenant,
                "canonical": "account:acme",
                "field": "name",
                "source_order": ["salesforce", "hubspot"]
            }))
            .unwrap(),
        ),
    )
    .await
    .expect("precedence");

    // Scoped read.
    let h = handle(&state, tenant);
    let Json(merged) = crate::get_merged_entity(
        State(Arc::clone(&state)),
        Path("account:acme".to_string()),
        Query(serde_json::from_value(json!({ "scope_handle": h })).unwrap()),
    )
    .await
    .expect("merged");

    assert_eq!(merged.canonical_entity, "account:acme");
    assert_eq!(merged.members.len(), 2);
    let name = &merged.fields["name"];
    assert_eq!(name.winning_source, "salesforce");
    assert_eq!(name.value, json!("Acme SF"));
    assert_eq!(name.superseded_alternatives.len(), 1);
    assert_eq!(name.superseded_alternatives[0].source, "hubspot");
}

/// **Live Tier-1 entity resolution, end-to-end (§4.2 S1 → S4).** Ingest real L1
/// facts for the SAME company across TWO sources, then drive the actual
/// produce+run path (`resolver::run_resolution` = `produce_tier1_evidence` → the
/// `run_full_fold` materializer) and assert the merge is correct, badged
/// deterministically, and — the security check — that a DIFFERENT company (an
/// internal-directory actor sharing a byte-identical name/local, and a free-mail
/// contact) never welds in. Finally re-run to prove idempotency.
///
/// This exercises the WHOLE live pipeline off L1: nothing here writes evidence or
/// aliases by hand — the producer reads `list_current_facts_grouped`, the fold
/// materializes `entity_aliases` + `entity_link_meta`, and the read path
/// (`merged_record` + the badge) sees only what the worker plane produced.
#[tokio::test]
async fn live_tier1_resolution_merges_company_across_sources_and_fences_others() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };

    // ---- ACME, the company we expect to resolve into one canonical. ----
    // Salesforce Account: Website (a domain-bearing field, MEDIUM) + a synced
    // DUNS crosswalk (STRONG external_id — the key that clears min_independent_keys
    // on its own). The Website/domain pair is deliberately present to prove the
    // MEDIUM key alone is NOT what merges; the STRONG external_id is.
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-acme",
        "Website",
        json!("https://www.acme.com"),
    )
    .await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-acme",
        "duns",
        json!("123456789"),
    )
    .await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-acme",
        "name",
        json!("Acme Corp (SF)"),
    )
    .await;
    // HubSpot company: domain + the SAME DUNS.
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-acme",
        "domain",
        json!("acme.com"),
    )
    .await;
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-acme",
        "duns",
        json!("123456789"),
    )
    .await;
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-acme",
        "name",
        json!("Acme Corp (HS)"),
    )
    .await;

    // Two customer contacts for ACME sharing a corporate email → they resolve into
    // their OWN canonical (a person), independently, in the customer_contact
    // namespace. This is the "matching contact email" second independent key path.
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-jane",
        "Email",
        json!("jane@acme.com"),
    )
    .await;
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-jane",
        "email",
        json!("jane@acme.com"),
    )
    .await;

    // ---- The security fence: DIFFERENT identities that must NOT merge in. ----
    // (1) An INTERNAL actor whose email is jane@acme.dev — a Linear-origin
    //     `email` is stamped internal_directory (§4.4). Even though it is a "jane"
    //     at an acme-ish domain, the namespace fence forbids any edge to the
    //     customer_contact jane, and nothing welds it to the ACME account.
    fact(
        &state,
        tenant,
        "linear",
        "lin-jane",
        "email",
        json!("jane@acme.dev"),
    )
    .await;
    // (2) A free-mail contact (gmail.com is denylisted) — never a key, never an
    //     edge, so bob resolves to nothing shared even though a second gmail bob
    //     exists in another source.
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-bob",
        "email",
        json!("bob@gmail.com"),
    )
    .await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-bob",
        "Email",
        json!("bob@gmail.com"),
    )
    .await;

    // ---- Run the LIVE produce+run path (S1 producers → S4 fold materializer). ----
    let report1 = crate::resolver::run_resolution(&state, tenant)
        .await
        .expect("run_resolution");
    assert!(
        report1.evidence_produced >= 2,
        "producer must emit ≥2 tier-1 edges (acme external_id + jane email_exact); got {}",
        report1.evidence_produced
    );

    let storage = state.storage.inner();

    // ---- ASSERT 1: exactly one canonical for ACME, with BOTH source members. ----
    let acme_canon = storage
        .resolve_canonical(tenant, "salesforce", "sf-acme")
        .await
        .unwrap()
        .expect("sf-acme must resolve to a canonical");
    assert_eq!(
        storage
            .resolve_canonical(tenant, "hubspot", "hs-acme")
            .await
            .unwrap()
            .as_deref(),
        Some(acme_canon.as_str()),
        "both sources must resolve to the SAME canonical"
    );
    // Canonical name is deterministic: canon:<lexically-min source:entity_id>.
    assert_eq!(acme_canon, "canon:hubspot:hs-acme");

    let members = storage
        .list_entity_aliases(tenant, &acme_canon)
        .await
        .unwrap();
    assert_eq!(
        members.len(),
        2,
        "exactly two source members in the canonical"
    );
    assert!(members.contains(&AliasMember {
        source: "salesforce".into(),
        entity_id: "sf-acme".into()
    }));
    assert!(members.contains(&AliasMember {
        source: "hubspot".into(),
        entity_id: "hs-acme".into()
    }));

    // merged_record reflects the same two members (the read-path view is unchanged).
    let merged = storage.merged_record(tenant, &acme_canon).await.unwrap();
    assert_eq!(
        merged.members.len(),
        2,
        "merged_record: both members present"
    );

    // ---- ASSERT 2: the entity_link_meta confidence badge is present + deterministic. ----
    let badge = storage
        .link_meta_for_canonical(tenant, &acme_canon)
        .await
        .unwrap()
        .expect("acme canonical must carry a materialized badge");
    assert_eq!(
        badge.confidence, "deterministic",
        "a Tier-1 external_id merge is deterministic, never approximated"
    );
    assert_eq!(
        badge.strongest_method.as_deref(),
        Some("external_id"),
        "the strongest justifying method is the STRONG external_id key"
    );
    assert!(
        badge.evidence_count >= 1,
        "badge must cite ≥1 justifying evidence row"
    );

    // The two customer contacts merged on the shared corporate email — their own
    // canonical, also deterministic, via email_exact in customer_contact.
    let jane_canon = storage
        .resolve_canonical(tenant, "hubspot", "hs-jane")
        .await
        .unwrap()
        .expect("hs-jane must resolve");
    assert_eq!(
        storage
            .resolve_canonical(tenant, "salesforce", "sf-jane")
            .await
            .unwrap()
            .as_deref(),
        Some(jane_canon.as_str()),
        "both contacts share one canonical person"
    );
    assert_ne!(jane_canon, acme_canon, "the person is not the account");
    let jane_badge = storage
        .link_meta_for_canonical(tenant, &jane_canon)
        .await
        .unwrap()
        .expect("jane badge");
    assert_eq!(jane_badge.confidence, "deterministic");
    assert_eq!(jane_badge.strongest_method.as_deref(), Some("email_exact"));

    // ---- ASSERT 3 (the security check): the DIFFERENT company never merges in. ----
    // The internal-directory actor is fenced out of BOTH the customer person and
    // the account: it resolves to NOTHING shared (no alias row at all).
    assert_eq!(
        storage
            .resolve_canonical(tenant, "linear", "lin-jane")
            .await
            .unwrap(),
        None,
        "internal_directory jane@acme.dev must never weld to a customer_contact entity"
    );
    // The ACME canonical must contain no linear member.
    assert!(
        !members.iter().any(|m| m.source == "linear"),
        "no internal actor may appear inside the customer account canonical"
    );
    // Free-mail contacts form no edge → each resolves to nothing shared.
    assert_eq!(
        storage
            .resolve_canonical(tenant, "hubspot", "hs-bob")
            .await
            .unwrap(),
        None,
        "gmail.com is denylisted — never a key, never a merge"
    );
    assert_eq!(
        storage
            .resolve_canonical(tenant, "salesforce", "sf-bob")
            .await
            .unwrap(),
        None,
        "the second free-mail bob likewise stays unmerged"
    );

    // ---- ASSERT 4: idempotency — a second run adds no evidence, stable canonical. ----
    let report2 = crate::resolver::run_resolution(&state, tenant)
        .await
        .expect("second run_resolution");
    assert_eq!(
        report2.evidence_produced, 0,
        "re-running over unchanged L1 facts produces NO duplicate evidence (deterministic evidence_id + ON CONFLICT DO NOTHING)"
    );
    // Canonical + membership are unchanged after the repeat run.
    assert_eq!(
        storage
            .resolve_canonical(tenant, "salesforce", "sf-acme")
            .await
            .unwrap()
            .as_deref(),
        Some(acme_canon.as_str()),
        "canonical is stable across repeat runs"
    );
    let members2 = storage
        .list_entity_aliases(tenant, &acme_canon)
        .await
        .unwrap();
    assert_eq!(members2.len(), 2, "no duplicate members after re-run");
    // Still exactly one badge row for the canonical (idempotent upsert).
    assert!(
        storage
            .link_meta_for_canonical(tenant, &acme_canon)
            .await
            .unwrap()
            .is_some(),
        "badge survives the idempotent re-materialize"
    );
}

/// The merged read is scope-handle gated exactly like get_record: a garbage
/// handle fails closed with 401 (never leaks the merged view).
#[tokio::test]
async fn merged_entity_bad_handle_fails_closed() {
    let Some((state, _tenant)) = test_state().await else {
        return;
    };
    let err = crate::get_merged_entity(
        State(Arc::clone(&state)),
        Path("account:acme".to_string()),
        Query(serde_json::from_value(json!({ "scope_handle": "not-a-real-handle" })).unwrap()),
    )
    .await
    .expect_err("must reject");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}
