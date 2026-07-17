//! Tests for `GET /v1/admin/planes` — the console's "what's running"
//! infrastructure-status surface (main.rs `admin_planes`). DSN-gated on
//! VERITY_TEST_DSN, like tenants_tests: each test skips (passes trivially)
//! when it's absent, because the handler queries `episode_processing` for the
//! consolidation-worker activity proxy.
//!
//! What these pin down:
//! - the read is admin-gated EXACTLY like every other /v1/admin read (no
//!   bearer ⇒ 401, before any DB work);
//! - the report shape is the contract: `{ planes: [{name,label,class,status,
//!   detail,startable,start_hint}], summary, checked_at }`, one row per
//!   infrastructure plane, every status drawn from the closed vocabulary
//!   {on,off,degraded,unknown} and every class from {startable,command-only,
//!   config-only};
//! - the OBSERVED plane states reflect this dev-mode AppState honestly
//!   (permissions off, media off, encoder off, auto-resolve off), and the
//!   knowledge worker — with no server-owned child and no activity for this
//!   tenant — is reported "off (observed)", not startable (no repo), never a
//!   fabricated running claim and never a dead button;
//! - start with no repo/venv/key is a clean typed 422/503 (never a 500), and
//!   stop with nothing owned is an honest 200 no-op.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::ScopeMinter;
use crate::{AdminAuth, AppState};

/// Real AppState against VERITY_TEST_DSN — a maximally-bare dev-mode server
/// (no encoder, no rebac, no media, auto-resolve disabled): the honest "almost
/// nothing wired" baseline the planes report must describe truthfully. Returns
/// None (⇒ skip) when the DSN is absent.
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
        connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
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
        allowed_origin: None,
    }
}

/// A throwaway tenant id for the (now-required) `tenant_id` query param. The
/// admin-gate and bare-shape tests don't depend on any rows existing for it.
fn any_tenant() -> uuid::Uuid {
    uuid::Uuid::nil()
}

/// DSN-only: the planes read is admin-gated exactly like the other admin
/// reads — no bearer must be rejected BEFORE any observation is made.
#[tokio::test]
async fn planes_is_admin_gated() {
    let key = [7u8; 32];
    let admin = AdminAuth {
        expected_tag: Some(AdminAuth::tag(&key, "sekrit")),
        allowed_origin: None,
        key,
    };
    let Some(state) = test_state(admin).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let err = crate::admin_planes(
        State(state),
        axum::extract::Query(crate::PlanesQuery {
            tenant_id: any_tenant(),
        }),
        HeaderMap::new(),
    )
    .await
    .expect_err("no bearer must be rejected");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}

/// DSN-only: the report shape is the contract, and every plane's status is
/// drawn from the closed vocabulary. The bare dev-mode state above must read
/// as permissions-off / media-off / encoder-off / auto-resolve-off, and the
/// external knowledge worker — unobservable from the server — as "unknown".
#[tokio::test]
async fn planes_reports_observed_shape() {
    let Some(state) = test_state(dev_admin()).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let Json(v) = crate::admin_planes(
        State(state),
        axum::extract::Query(crate::PlanesQuery {
            tenant_id: any_tenant(),
        }),
        HeaderMap::new(),
    )
    .await
    .expect("dev-mode admin is open");

    assert!(
        v["checked_at"].as_str().is_some(),
        "checked_at must be an rfc3339 stamp"
    );
    // The summary line the panel reads for its ten-second comprehension.
    assert!(v["summary"]["total"].as_u64().is_some(), "summary.total");
    assert!(v["summary"]["up"].as_u64().is_some(), "summary.up");
    let planes = v["planes"].as_array().expect("planes is an array");
    assert!(!planes.is_empty(), "at least one plane is reported");

    // Every row carries the contract fields and a vocabulary status. `class`,
    // `startable`, and `start_hint` are the machine-authoritative honesty
    // fields the panel keys off (never a dead button).
    for p in planes {
        assert!(p["name"].as_str().is_some(), "each plane has a name");
        assert!(p["label"].as_str().is_some(), "each plane has a label");
        assert!(p["detail"].as_str().is_some(), "each plane has a detail");
        let class = p["class"].as_str().expect("each plane has a class");
        assert!(
            matches!(class, "startable" | "command-only" | "config-only"),
            "class {class:?} outside the closed vocabulary"
        );
        assert!(
            p["startable"].as_bool().is_some(),
            "each plane has a startable flag"
        );
        assert!(
            p.get("start_hint").is_some(),
            "each plane carries start_hint (may be null)"
        );
        let status = p["status"].as_str().expect("each plane has a status");
        assert!(
            matches!(status, "on" | "off" | "degraded" | "unknown"),
            "status {status:?} outside the closed vocabulary"
        );
    }

    // The six planes the console expects are all present.
    let by_name = |name: &str| planes.iter().find(|p| p["name"] == name);
    for name in [
        "rebac",
        "revocation_watch",
        "media_store",
        "encoder",
        "auto_resolve",
        "knowledge_worker",
    ] {
        assert!(
            by_name(name).is_some(),
            "plane {name} missing from the report"
        );
    }

    // This bare dev-mode server: every AppState-observed plane is honestly off.
    assert_eq!(by_name("rebac").unwrap()["status"], "off");
    assert_eq!(by_name("media_store").unwrap()["status"], "off");
    assert_eq!(by_name("encoder").unwrap()["status"], "off");
    assert_eq!(by_name("auto_resolve").unwrap()["status"], "off");
    assert_eq!(by_name("revocation_watch").unwrap()["status"], "off");

    // Under the two-tier rule, a bare state with no episode_processing rows for
    // this tenant is Tier-2-stale ⇒ "off" (not the old "unknown"), reported via
    // the observed proxy, with no owned child ⇒ not stoppable. And with no repo
    // configured in the test AppState, it is not startable — a copyable fix,
    // never a dead button.
    let kw = by_name("knowledge_worker").unwrap();
    assert_eq!(kw["status"], "off");
    assert_eq!(kw["class"], "startable");
    assert_eq!(kw["authority"], "observed");
    assert_eq!(kw["stoppable"], false);
    assert_eq!(kw["startable"], false, "no repo_root ⇒ not startable");
    assert!(
        kw["start_hint"].as_str().is_some(),
        "off-and-not-startable carries the fix in start_hint"
    );

    // No plane other than knowledge is ever startable (no dead buttons).
    for p in planes {
        if p["name"] != "knowledge_worker" {
            assert_eq!(
                p["startable"], false,
                "only knowledge_worker is ever startable"
            );
        }
    }
}

/// DSN-only: starting the worker with no repo configured (the test AppState)
/// returns a clean typed 422 with the fix — NEVER a 500 for a predictable
/// precondition — and does not leave a child tracked.
#[tokio::test]
async fn knowledge_start_without_repo_is_clean_422() {
    let Some(state) = test_state(dev_admin()).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let err = crate::admin_planes_knowledge_start(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(crate::KnowledgeWorkerBody {
            tenant_id: any_tenant(),
        }),
    )
    .await
    .expect_err("no repo ⇒ typed precondition error");
    assert_eq!(
        err.0,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown repo path is 422, not 500"
    );
    assert!(
        err.1.contains("--repo"),
        "the message is the next action: {}",
        err.1
    );
    // Nothing was tracked.
    assert!(state.knowledge_worker.lock().await.is_none());
}

/// DSN-only: the start endpoint is admin-gated before it touches the handle.
#[tokio::test]
async fn knowledge_start_is_admin_gated() {
    let key = [9u8; 32];
    let admin = AdminAuth {
        expected_tag: Some(AdminAuth::tag(&key, "sekrit")),
        allowed_origin: None,
        key,
    };
    let Some(state) = test_state(admin).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let err = crate::admin_planes_knowledge_start(
        State(state),
        HeaderMap::new(),
        Json(crate::KnowledgeWorkerBody {
            tenant_id: any_tenant(),
        }),
    )
    .await
    .expect_err("no bearer must be rejected");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}

/// DSN-only: stopping when this console owns no worker is an honest 200 no-op,
/// not an error and not a fabricated "stopped".
#[tokio::test]
async fn knowledge_stop_when_nothing_is_honest_noop() {
    let Some(state) = test_state(dev_admin()).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let Json(v) = crate::admin_planes_knowledge_stop(
        State(state),
        HeaderMap::new(),
        Json(crate::KnowledgeWorkerBody {
            tenant_id: any_tenant(),
        }),
    )
    .await
    .expect("stop is a 200 no-op when nothing is owned");
    assert_eq!(v["stopped"], false);
    assert!(
        v["note"]
            .as_str()
            .is_some_and(|n| n.contains("nothing to stop")),
        "no-op explains why: {v:?}"
    );
}
