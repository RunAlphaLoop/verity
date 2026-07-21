//! M2 slice 2b — RUST UNIT TESTS for the canonical-principal registry, the
//! crosswalk resolvers, and the admin write/deprovision routes (BUILD #1 scope).
//!
//! These are the resolver-and-route unit tests the 2b Rust build owns; the full
//! ingest→mint→recall acceptance trace lives in the B3 conformance suite
//! (`identity_tests.rs`) — this file does NOT touch it. DSN-only (no SpiceDB):
//! every leg here operates on the registry tables + token allocator directly.
//! Hard-error without `VERITY_TEST_DSN` (M0 pattern) — never silent-skip.
//!
//! The handlers return `HandlerResult<Json<Value>>`; several assertions only
//! need the `Ok`/`Err` outcome, so we deliberately drop the `Json` wrapper.
#![allow(unused_must_use)]

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::TenantId;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::ScopeMinter;
use crate::{AdminAuth, AppState};

const TEST_ADMIN_TOKEN: &str = "test-admin-token";

/// Minimal real AppState against `VERITY_TEST_DSN` with an admin bearer so the
/// `require`-gated 2b routes return `Ok`. No encoder/ReBAC — unused on these legs.
async fn crosswalk_state() -> (Arc<AppState>, TenantId) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the M2-2b crosswalk unit tests; \
         refusing to silently no-op",
    );
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("crosswalk-test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 10_000),
        encoder: None,
        minter: ScopeMinter::ephemeral(),
        purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
        admin: AdminAuth::for_test(Some(TEST_ADMIN_TOKEN), None),
        rebac: None,
        revocations: RevocationPlane::new(300),
        watch: std::sync::Arc::new(crate::rebac_watch::WatchStatus::new()),
        watch_staleness_fence_secs: 900,
        folder_watchers: std::sync::Arc::new(crate::folder_watch::WatcherRegistry::new()),
        folder_scans: std::sync::Arc::new(crate::folder_watch::FolderScanPlane::new()),
        knowledge_worker: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
        sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
        allow_restricted_without_rebac: true,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    (state, tenant)
}

fn admin_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {TEST_ADMIN_TOKEN}").parse().unwrap(),
    );
    h
}

/// Publish a canonical registry row via the real route.
async fn seed_canonical(
    state: &Arc<AppState>,
    tenant: TenantId,
    canonical: &str,
    idp_subject: &str,
) {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principals": [{ "canonical": canonical, "kind": "user", "idp_subject": idp_subject }],
    }))
    .unwrap();
    crate::admin_registry_canonical(State(Arc::clone(state)), admin_headers(), Json(req))
        .await
        .expect("seed canonical");
}

/// Link a source-local id via POST /v1/admin/crosswalk.
async fn seed_crosswalk(
    state: &Arc<AppState>,
    tenant: TenantId,
    source: &str,
    local_id: &str,
    canonical: &str,
) -> crate::HandlerResult<()> {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": source,
        "local_id": local_id,
        "canonical": canonical,
        "link_method": "admin_explicit",
    }))
    .unwrap();
    crate::admin_crosswalk_link(State(Arc::clone(state)), admin_headers(), Json(req)).await?;
    Ok(())
}

/// resolve_crosswalk: a live link resolves; a missing local_id → None;
/// an inactive crosswalk row → None (fail closed).
#[tokio::test]
async fn crosswalk_resolve_hit_miss_inactive() {
    let (state, tenant) = crosswalk_state().await;
    seed_canonical(&state, tenant, "user:alice@corp.com", "alice@corp.com").await;
    seed_crosswalk(&state, tenant, "hubspot", "77", "user:alice@corp.com")
        .await
        .expect("link");

    let out = crate::resolve_crosswalk(
        state.pool(),
        tenant,
        "hubspot",
        &["77".to_string(), "999".to_string()],
    )
    .await
    .expect("resolve");
    assert_eq!(
        out[0].as_deref(),
        Some("user:alice@corp.com"),
        "live link resolves"
    );
    assert_eq!(out[1], None, "missing local_id → None (fail closed)");

    // Deactivate the crosswalk row → resolves to None.
    sqlx::query(
        "UPDATE principal_crosswalk SET active = false WHERE tenant_id = $1 AND local_id = '77'",
    )
    .bind(tenant)
    .execute(state.pool())
    .await
    .unwrap();
    let out = crate::resolve_crosswalk(state.pool(), tenant, "hubspot", &["77".to_string()])
        .await
        .expect("resolve");
    assert_eq!(out[0], None, "inactive crosswalk row → None (fail closed)");
}

/// resolve_crosswalk also fails closed when the canonical itself is inactive
/// (deprovisioned) even though the crosswalk row is still active.
#[tokio::test]
async fn crosswalk_resolve_inactive_canonical() {
    let (state, tenant) = crosswalk_state().await;
    seed_canonical(&state, tenant, "user:alice@corp.com", "alice@corp.com").await;
    seed_crosswalk(&state, tenant, "hubspot", "77", "user:alice@corp.com")
        .await
        .expect("link");
    sqlx::query("UPDATE canonical_principal SET active = false WHERE tenant_id = $1")
        .bind(tenant)
        .execute(state.pool())
        .await
        .unwrap();
    let out = crate::resolve_crosswalk(state.pool(), tenant, "hubspot", &["77".to_string()])
        .await
        .expect("resolve");
    assert_eq!(
        out[0], None,
        "inactive canonical → None even with a live crosswalk row"
    );
}

/// resolve_idp_subject: direct idp_subject hit, SSO-alias hit, and an unvouched
/// address → None (no implicit weld).
#[tokio::test]
async fn idp_subject_resolves_direct_and_alias() {
    let (state, tenant) = crosswalk_state().await;
    seed_canonical(&state, tenant, "user:alice@corp.com", "alice@corp.com").await;
    // Declare an SSO alias (the SF FederationIdentifier target).
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "aliases": [{ "canonical": "user:alice@corp.com", "alias": "alice@corp.com", "source": "google_customschema" }],
    }))
    .unwrap();
    let _ = crate::admin_registry_alias(State(Arc::clone(&state)), admin_headers(), Json(req))
        .await
        .expect("alias");

    let out = crate::resolve_idp_subject(
        state.pool(),
        tenant,
        &[
            "alice@corp.com".to_string(), // idp_subject + alias both match
            "bob@corp.com".to_string(),   // unvouched
        ],
    )
    .await
    .expect("resolve");
    assert_eq!(
        out[0].as_deref(),
        Some("user:alice@corp.com"),
        "vouched subject resolves"
    );
    assert_eq!(out[1], None, "unvouched address → None (no weld)");
}

/// The admin_principals splice: a `resolvable` HubSpot owner that resolves is
/// stamped; when NO declared owner survives, the response quarantines.
#[tokio::test]
async fn admin_principals_splice_resolves_and_quarantines() {
    let (state, tenant) = crosswalk_state().await;
    seed_canonical(&state, tenant, "user:alice@corp.com", "alice@corp.com").await;
    seed_crosswalk(&state, tenant, "hubspot", "77", "user:alice@corp.com")
        .await
        .expect("link");

    // Resolvable owner survives → mapping is keyed on the CANONICAL string.
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "resolvable": [{ "source": "hubspot", "local_id": "77" }],
    }))
    .unwrap();
    let Json(v) = crate::admin_principals(State(Arc::clone(&state)), admin_headers(), Json(req))
        .await
        .expect("principals");
    assert_eq!(v["quarantined"], json!(false));
    assert!(
        v["mappings"]["user:alice@corp.com"].is_number(),
        "canonical string is the token key (same string open_scope hits)"
    );

    // An unlinked owner → nothing survives → quarantine.
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "resolvable": [{ "source": "hubspot", "local_id": "unlinked-999" }],
    }))
    .unwrap();
    let Json(v) = crate::admin_principals(State(Arc::clone(&state)), admin_headers(), Json(req))
        .await
        .expect("principals");
    assert_eq!(
        v["quarantined"],
        json!(true),
        "all-None owners → quarantine (fail closed)"
    );
    assert_eq!(v["mappings"].as_object().unwrap().len(), 0);
}

/// The crosswalk link route rejects a non-user:/group: canonical (422) and
/// writes an audit row on success.
#[tokio::test]
async fn crosswalk_link_route_validates_and_audits() {
    let (state, tenant) = crosswalk_state().await;
    seed_canonical(&state, tenant, "user:alice@corp.com", "alice@corp.com").await;

    // 422 on a bare (non-namespaced) canonical.
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": "hubspot",
        "local_id": "77",
        "canonical": "alice@corp.com",
    }))
    .unwrap();
    let err = crate::admin_crosswalk_link(State(Arc::clone(&state)), admin_headers(), Json(req))
        .await
        .expect_err("must reject bare canonical");
    assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);

    // 401 without the admin bearer (require-gated).
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": "hubspot",
        "local_id": "77",
        "canonical": "user:alice@corp.com",
    }))
    .unwrap();
    let err =
        crate::admin_crosswalk_link(State(Arc::clone(&state)), HeaderMap::new(), Json(req)).await;
    assert!(err.is_err(), "no bearer → require-gate rejects");

    // Success writes an audit row.
    seed_crosswalk(&state, tenant, "hubspot", "77", "user:alice@corp.com")
        .await
        .expect("link");
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_access_audit WHERE tenant_id = $1 AND endpoint = 'crosswalk/link'",
    )
    .bind(tenant)
    .fetch_one(state.pool())
    .await
    .unwrap();
    assert!(n >= 1, "crosswalk link is audited");
}

/// No-false-weld: a second canonical claiming an already-bound idp_subject is
/// quarantined; the established canonical is untouched.
#[tokio::test]
async fn registry_canonical_rejects_idp_subject_reweld() {
    let (state, tenant) = crosswalk_state().await;
    seed_canonical(&state, tenant, "user:alice@corp.com", "alice@corp.com").await;

    // A DIFFERENT canonical presenting the SAME idp_subject → quarantine that row.
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principals": [{ "canonical": "user:imposter@corp.com", "kind": "user", "idp_subject": "alice@corp.com" }],
    }))
    .unwrap();
    let Json(v) =
        crate::admin_registry_canonical(State(Arc::clone(&state)), admin_headers(), Json(req))
            .await
            .expect("canonical");
    assert_eq!(v["upserted"].as_array().unwrap().len(), 0);
    assert_eq!(
        v["quarantined"].as_array().unwrap().len(),
        1,
        "reweld quarantines"
    );

    // The established binding is intact.
    let out = crate::resolve_idp_subject(state.pool(), tenant, &["alice@corp.com".to_string()])
        .await
        .expect("resolve");
    assert_eq!(
        out[0].as_deref(),
        Some("user:alice@corp.com"),
        "established principal untouched"
    );
}

/// Deprovision route: flips `canonical_principal.active=false` AND fires the 2a
/// durable revoke (revoked_set now contains the principal's token).
#[tokio::test]
async fn deprovision_flips_inactive_and_fires_2a_revoke() {
    let (state, tenant) = crosswalk_state().await;
    seed_canonical(&state, tenant, "user:alice@corp.com", "alice@corp.com").await;
    seed_crosswalk(&state, tenant, "hubspot", "77", "user:alice@corp.com")
        .await
        .expect("link");

    // Materialize the token so we can assert the durable revoke landed on it.
    let token =
        crate::upsert_principal_tokens(state.pool(), tenant, &["user:alice@corp.com".to_string()])
            .await
            .expect("token")[0]
            .1;

    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principal": "user:alice@corp.com",
    }))
    .unwrap();
    let Json(v) = crate::admin_deprovision(State(Arc::clone(&state)), admin_headers(), Json(req))
        .await
        .expect("deprovision");
    assert_eq!(v["deprovisioned"], json!(true));

    // 1. canonical_principal + crosswalk flipped inactive.
    let active: bool =
        sqlx::query_scalar("SELECT active FROM canonical_principal WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(state.pool())
            .await
            .unwrap();
    assert!(!active, "canonical flipped inactive");
    let out = crate::resolve_crosswalk(state.pool(), tenant, "hubspot", &["77".to_string()])
        .await
        .expect("resolve");
    assert_eq!(out[0], None, "crosswalk rows deactivated by deprovision");

    // 2. The 2a durable revoked set now contains the token — indefinite denial.
    let revoked = state
        .revocations
        .revoked_set(state.pool(), tenant)
        .await
        .expect("revoked set");
    assert!(
        revoked.contains(&token),
        "deprovision fired 2a durable revoke_principal"
    );

    // A require-gated non-user: principal is rejected (422).
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "principal": "group:eng",
    }))
    .unwrap();
    let err = crate::admin_deprovision(State(Arc::clone(&state)), admin_headers(), Json(req))
        .await
        .expect_err("group principal rejected");
    assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
}
