//! FTUE §2 server-trio tests: the tenant directory read (GET
//! /v1/admin/tenants — the console picker's data source and first-run
//! detector) and the ghost-tenant trap (POST /v1/scopes 404s for a tenant
//! that was never born). DSN-gated on VERITY_TEST_DSN, like principals_tests —
//! each test skips (passes trivially) when it's absent.
//!
//! What these tests pin down:
//! - the GET returns `{tenants:[{tenant_id,name,created_at}],count}` with the
//!   exact field names the FTUE contract specifies, ordered oldest-first, and
//!   respects/clamps `limit`;
//! - the GET is admin-gated exactly like the POST (401 without/with a bad
//!   bearer when VERITY_ADMIN_TOKEN semantics are active);
//! - `POST /v1/scopes` for a never-born tenant is a loud 404 whose body names
//!   the error and a working next step — never a plausibly-empty session.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use serde_json::json;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::ScopeMinter;
use crate::{AdminAuth, AppState};

/// Real AppState against VERITY_TEST_DSN (no encoder; dev-mode admin unless
/// `admin` overrides it). Returns None (⇒ skip) when the DSN is absent.
async fn test_state(admin: AdminAuth) -> Option<Arc<AppState>> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    Some(Arc::new(AppState {
        storage: CachedAdapter::new(pg, 10_000),
        encoder: None,
        minter: ScopeMinter::ephemeral(),
        purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
        admin,
        rebac: None,
        revocations: RevocationPlane::new(300),
        watch: Arc::new(crate::rebac_watch::WatchStatus::new()),
        allow_restricted_without_rebac: false,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    }))
}

fn dev_admin() -> AdminAuth {
    AdminAuth {
        key: [0u8; 32],
        expected_tag: None, // dev mode: admin surfaces open
    }
}

async fn list(state: &Arc<AppState>, headers: HeaderMap, query: serde_json::Value) -> HandlerJson {
    let q = serde_json::from_value(query).expect("query shape");
    crate::list_tenants(State(Arc::clone(state)), headers, Query(q)).await
}

type HandlerJson = crate::HandlerResult<Json<serde_json::Value>>;

/// DSN-only: the directory read returns the FTUE contract shape —
/// `tenants: [{tenant_id, name, created_at}]` — includes freshly created
/// tenants in creation order (oldest first), and honors `limit`.
#[tokio::test]
async fn tenant_directory_lists_created_tenants_in_creation_order() {
    let Some(state) = test_state(dev_admin()).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let name_a = format!("tenants-test-a-{}", Uuid::now_v7());
    let name_b = format!("tenants-test-b-{}", Uuid::now_v7());
    let id_a = state
        .storage
        .create_tenant(&name_a)
        .await
        .expect("tenant a");
    let id_b = state
        .storage
        .create_tenant(&name_b)
        .await
        .expect("tenant b");

    // Storage-level read with a huge limit: both tenants present, a before b,
    // every row fully populated, order ascending by created_at throughout.
    let rows = state
        .storage
        .list_tenants(i64::MAX)
        .await
        .expect("list_tenants");
    let pos = |id| rows.iter().position(|r| r.tenant_id == id);
    let (pa, pb) = (pos(id_a).expect("a listed"), pos(id_b).expect("b listed"));
    assert!(pa < pb, "creation order: a was born before b");
    assert_eq!(rows[pa].name, name_a);
    assert_eq!(rows[pb].name, name_b);
    assert!(
        rows.windows(2).all(|w| w[0].created_at <= w[1].created_at),
        "directory must be ordered oldest-first"
    );

    // Handler-level read: contract shape + limit honored. limit=1 ⇒ exactly
    // one row carrying the three contract fields, count matching.
    let Json(v) = list(&state, HeaderMap::new(), json!({ "limit": 1 }))
        .await
        .expect("list tenants");
    let tenants = v["tenants"].as_array().expect("tenants array");
    assert_eq!(tenants.len(), 1);
    assert_eq!(v["count"], 1);
    let row = &tenants[0];
    assert!(row["tenant_id"].as_str().is_some(), "tenant_id serialized");
    assert!(row["name"].as_str().is_some(), "name serialized");
    assert!(
        row["created_at"].as_str().is_some(),
        "created_at serialized"
    );
    assert_eq!(
        row["tenant_id"],
        json!(rows[0].tenant_id),
        "same order as storage"
    );

    // An absent limit defaults sanely (no panic, contract shape intact).
    let Json(v) = list(&state, HeaderMap::new(), json!({}))
        .await
        .expect("default limit");
    assert!(v["tenants"].is_array());
}

/// DSN-only: GET is admin-gated exactly like POST — no/bad bearer ⇒ 401,
/// the right bearer ⇒ 200.
#[tokio::test]
async fn tenant_directory_is_admin_gated() {
    let key = [7u8; 32];
    let admin = AdminAuth {
        expected_tag: Some(AdminAuth::tag(&key, "sekrit")),
        key,
    };
    let Some(state) = test_state(admin).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

    let err = list(&state, HeaderMap::new(), json!({}))
        .await
        .expect_err("no bearer must be rejected");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);

    let mut bad = HeaderMap::new();
    bad.insert(header::AUTHORIZATION, "Bearer wrong".parse().unwrap());
    let err = list(&state, bad, json!({}))
        .await
        .expect_err("bad bearer must be rejected");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);

    let mut good = HeaderMap::new();
    good.insert(header::AUTHORIZATION, "Bearer sekrit".parse().unwrap());
    let Json(v) = list(&state, good, json!({}))
        .await
        .expect("good bearer lists");
    assert!(v["tenants"].is_array());
}

/// DSN-only: the ghost-tenant trap (FTUE §2.2). Minting a scope for a uuid
/// that was never born is a loud 404 naming the error and a working next
/// step; the same request against a real tenant mints a handle.
#[tokio::test]
async fn open_scope_rejects_never_born_tenant_with_loud_404() {
    let Some(state) = test_state(dev_admin()).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

    let mint = |tenant: Uuid| {
        let state = Arc::clone(&state);
        async move {
            let req = serde_json::from_value(json!({
                "tenant_id": tenant,
                "principals": [1],
            }))
            .expect("request shape");
            crate::open_scope(State(state), Json(req)).await
        }
    };

    // A fabricated uuid must never mint a plausible, permanently-empty session.
    let ghost = Uuid::now_v7();
    let (status, body) = mint(ghost).await.expect_err("ghost tenant must 404");
    assert_eq!(status, StatusCode::NOT_FOUND);
    let body: serde_json::Value = serde_json::from_str(&body).expect("json error body");
    assert_eq!(body["error"], "unknown tenant");
    assert_eq!(
        body["hint"],
        "create one: POST /v1/admin/tenants, or run verity-cli dev"
    );

    // The same request against a born tenant mints.
    let real = state
        .storage
        .create_tenant(&format!("tenants-test-real-{}", Uuid::now_v7()))
        .await
        .expect("tenant");
    let Json(v) = mint(real).await.expect("real tenant mints");
    assert!(v["scope_handle"].as_str().is_some());
    assert!(v["expires_at"].as_str().is_some());
}
