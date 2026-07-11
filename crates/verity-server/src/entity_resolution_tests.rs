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
