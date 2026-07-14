//! FTUE §2 server-trio tests: the tenant directory read (GET
//! /v1/admin/tenants — the console picker's data source and first-run
//! detector) and the ghost-tenant trap (POST /v1/scopes 404s for a tenant
//! that was never born). DSN-gated on VERITY_TEST_DSN, like principals_tests —
//! each test skips (passes trivially) when it's absent.
//!
//! What these tests pin down:
//! - the GET returns `{tenants:[{tenant_id,name,created_at}],count}` with the
//!   exact field names the FTUE contract specifies, ordered NEWEST-first (a
//!   picker must surface what was just created — amended 2026-07-12), and
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
        folder_watchers: Arc::new(crate::folder_watch::WatcherRegistry::new()),
        knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
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

/// DSN-only: the point lookup GET /v1/admin/tenants/{id} — a real id returns
/// its name/created_at, a never-born id is a definitive 404 (the wizard's
/// ghost hard-stop and the picker's off-page confirm both key off this).
#[tokio::test]
async fn tenant_by_id_confirms_real_and_404s_ghost() {
    let Some(state) = test_state(dev_admin()).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let name = format!("by-id-{}", Uuid::now_v7());
    let id = state.storage.create_tenant(&name).await.expect("create");

    let Json(v) = crate::get_tenant(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        axum::extract::Path(id),
    )
    .await
    .expect("real tenant resolves");
    assert_eq!(v["tenant_id"], json!(id));
    assert_eq!(v["name"], json!(name));
    assert!(v["created_at"].as_str().is_some());

    let ghost = Uuid::now_v7();
    let err = crate::get_tenant(State(state), HeaderMap::new(), axum::extract::Path(ghost))
        .await
        .expect_err("never-born id must 404");
    assert_eq!(err.0, StatusCode::NOT_FOUND);
}

/// DSN-only: the point lookup is admin-gated exactly like the directory read.
#[tokio::test]
async fn tenant_by_id_is_admin_gated() {
    let key = [9u8; 32];
    let admin = AdminAuth {
        expected_tag: Some(AdminAuth::tag(&key, "sekrit")),
        key,
    };
    let Some(state) = test_state(admin).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let err = crate::get_tenant(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        axum::extract::Path(Uuid::now_v7()),
    )
    .await
    .expect_err("no bearer must be rejected before any lookup");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}

/// DSN-only: the directory read returns the FTUE contract shape —
/// `tenants: [{tenant_id, name, created_at}]` — includes freshly created
/// tenants NEWEST first (a just-created space must land on the first page
/// of a long-lived dev db), and honors `limit`.
#[tokio::test]
async fn tenant_directory_lists_created_tenants_newest_first() {
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

    // Storage-level read with a huge limit: both tenants present, b (newer)
    // BEFORE a, every row fully populated, order descending throughout.
    let rows = state
        .storage
        .list_tenants(i64::MAX)
        .await
        .expect("list_tenants");
    let pos = |id| rows.iter().position(|r| r.tenant_id == id);
    let (pa, pb) = (pos(id_a).expect("a listed"), pos(id_b).expect("b listed"));
    assert!(
        pb < pa,
        "newest first: b was born after a, so b lists first"
    );
    assert_eq!(rows[pa].name, name_a);
    assert_eq!(rows[pb].name, name_b);
    assert!(
        rows.windows(2).all(|w| w[0].created_at >= w[1].created_at),
        "directory must be ordered newest-first"
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
    // Handler returns newest-first: the single row must be at least as new as
    // `b`, the newest tenant THIS test created. Asserted as a `>=` invariant,
    // not identity against `rows[0]` — the shared dev DB has other tests
    // creating tenants concurrently, and a newer one legitimately takes the top
    // slot between the two list calls (that identity check flaked under
    // parallel `cargo test`). Newest-first ordering itself is pinned race-free
    // by the storage-level windows() assertion above.
    let b_created = rows[pb].created_at;
    let top_created = row["created_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .expect("created_at parses");
    assert!(
        top_created >= b_created,
        "handler's newest-first row must be >= the newest tenant we created"
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
