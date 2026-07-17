//! Continuous-sync SCHEDULER integration tests (Phase 4). DSN-gated on
//! VERITY_TEST_DSN like identity_tests/console_later_tests — each test skips
//! (passes trivially) when the DSN is absent. These pin the SCHEDULER MECHANICS,
//! NEVER a real continuous crawl against a live source:
//!
//! - the interval FLOOR is enforced in storage (a sub-floor upsert → InvalidInput
//!   → 422), so no code path can arm a schedule tighter than the floor;
//! - upsert_sync_schedule is idempotent-by-(tenant,source) (a second enable
//!   rotates the interval in place) and the enabled-flag is durable;
//! - list_enabled_sync_schedules returns ONLY enabled rows (the boot re-arm read);
//! - boot re-arm (`reestablish_on_boot`) arms exactly one loop per enabled row and
//!   a disabled row is left inert — with NO source ever polled (the loops fire
//!   their first cycle one full interval out, and we disarm immediately);
//! - the SKIP-IF-IN-FLIGHT decision: `fire_cycle` returns `SkippedInFlight` when a
//!   live owned child already holds the (tenant,source) cursor — proven with a
//!   fake sleeping `--once` child, never a real source poll.

use std::sync::Arc;

use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::ScopeMinter;
use crate::sync_scheduler::{self, CycleDecision};
use crate::{AdminAuth, AppState};

/// Real AppState against VERITY_TEST_DSN. `repo_root`/`listen` are set so a
/// fire_cycle that DID spawn would have a real interpreter path — but the
/// skip-if-in-flight test seeds a live child so the spawn is never reached.
async fn test_state() -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("sync-sched-test-{}", Uuid::now_v7()))
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
            allowed_origin: None,
        },
        rebac: None,
        revocations: RevocationPlane::new(300),
        watch: Arc::new(crate::rebac_watch::WatchStatus::new()),
        folder_watchers: Arc::new(crate::folder_watch::WatcherRegistry::new()),
        folder_scans: Arc::new(crate::folder_watch::FolderScanPlane::new()),
        knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        connectors: Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
        sync: Arc::new(crate::sync_scheduler::SyncPlane::new()),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        allow_restricted_without_rebac: false,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    Some((state, tenant))
}

#[tokio::test]
async fn interval_floor_rejects_sub_floor_upsert() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    // Below the 60s floor → InvalidInput (→ 422 at the handler), never a silent
    // clamp, never a raw DB constraint error.
    let err = state
        .storage
        .upsert_sync_schedule(tenant, "gdrive", 59, true)
        .await
        .expect_err("sub-floor interval must be rejected");
    assert!(
        matches!(err, StorageError::InvalidInput(_)),
        "expected InvalidInput, got {err:?}"
    );
    // Exactly at the floor → accepted.
    let s = state
        .storage
        .upsert_sync_schedule(tenant, "gdrive", 60, true)
        .await
        .expect("floor value accepted");
    assert_eq!(s.interval_secs, 60);
    assert!(s.enabled);
}

#[tokio::test]
async fn upsert_is_idempotent_and_enabled_flag_is_durable() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    // First enable at 300.
    let a = state
        .storage
        .upsert_sync_schedule(tenant, "hubspot", 300, true)
        .await
        .expect("enable");
    assert_eq!(a.interval_secs, 300);
    assert!(a.enabled);
    // Re-enable at a new interval → rotates in place (same key, no second row).
    let b = state
        .storage
        .upsert_sync_schedule(tenant, "hubspot", 600, true)
        .await
        .expect("re-enable");
    assert_eq!(b.interval_secs, 600);
    // Disable → durable off-state, interval preserved.
    let c = state
        .storage
        .upsert_sync_schedule(tenant, "hubspot", 600, false)
        .await
        .expect("disable");
    assert!(!c.enabled);
    // get returns the durable disabled row.
    let got = state
        .storage
        .get_sync_schedule(tenant, "hubspot")
        .await
        .expect("get")
        .expect("row present");
    assert!(!got.enabled);
    assert_eq!(got.interval_secs, 600);
}

#[tokio::test]
async fn list_enabled_returns_only_enabled_rows() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    state
        .storage
        .upsert_sync_schedule(tenant, "gdrive", 300, true)
        .await
        .expect("enable gdrive");
    state
        .storage
        .upsert_sync_schedule(tenant, "gmail", 300, false)
        .await
        .expect("disable gmail");
    let enabled = state
        .storage
        .list_enabled_sync_schedules()
        .await
        .expect("list");
    // Only THIS tenant's enabled gdrive row (other tenants' rows may exist from
    // parallel tests, so filter to ours).
    let ours: Vec<_> = enabled.iter().filter(|s| s.tenant_id == tenant).collect();
    assert_eq!(ours.len(), 1, "only the enabled row: {ours:?}");
    assert_eq!(ours[0].source, "gdrive");
    assert!(ours[0].enabled);
}

#[tokio::test]
async fn touch_last_run_stamps_and_no_ops_off_row() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    // No row yet → honest no-op (false).
    assert!(
        !state
            .storage
            .touch_sync_schedule_last_run(tenant, "gdrive")
            .await
            .expect("touch"),
        "touch of a non-existent schedule must be a no-op"
    );
    state
        .storage
        .upsert_sync_schedule(tenant, "gdrive", 300, true)
        .await
        .expect("enable");
    // Now a row exists → stamped (true).
    assert!(state
        .storage
        .touch_sync_schedule_last_run(tenant, "gdrive")
        .await
        .expect("touch"));
    let got = state
        .storage
        .get_sync_schedule(tenant, "gdrive")
        .await
        .expect("get")
        .expect("row");
    assert!(got.last_run_at.is_some(), "last_run_at must be stamped");
}

#[tokio::test]
async fn boot_rearm_arms_one_loop_per_enabled_schedule() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    // Seed a fake schedule list: gdrive enabled at a LONG interval (so the loop's
    // first fire is far out and never polls a source), gmail disabled (inert).
    state
        .storage
        .upsert_sync_schedule(tenant, "gdrive", 3600, true)
        .await
        .expect("enable gdrive");
    state
        .storage
        .upsert_sync_schedule(tenant, "gmail", 3600, false)
        .await
        .expect("disable gmail");

    // Boot re-arm reads enabled schedules and arms one loop each.
    sync_scheduler::reestablish_on_boot(Arc::clone(&state)).await;

    // The enabled gdrive schedule is armed; the disabled gmail one is NOT.
    assert!(
        state.sync.is_armed(tenant, "gdrive").await,
        "enabled schedule must be re-armed on boot"
    );
    assert!(
        !state.sync.is_armed(tenant, "gmail").await,
        "disabled schedule must be left inert"
    );

    // Disarm so the long-interval loop task doesn't linger past the test.
    assert!(state.sync.disarm(tenant, "gdrive").await);
    assert!(!state.sync.is_armed(tenant, "gdrive").await);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fire_cycle_skips_when_a_prior_cycle_is_in_flight() {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    let Some((state, tenant)) = test_state().await else {
        return;
    };

    // Build a fake ingest tree whose `python` just sleeps, so a spawned `--once`
    // child stays live long enough to be observed in-flight. We spawn it directly
    // through the ConnectorPlane in PollOnce mode, then assert a SECOND fire_cycle
    // SKIPS (never double-spawns against the same cursor). No real source is ever
    // polled — the shim ignores its argv.
    let root: PathBuf = std::env::temp_dir().join(format!("verity-sync-skip-{}", Uuid::new_v4()));
    let bin = root.join("ingest/.venv/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let py = bin.join("python");
    std::fs::write(&py, "#!/bin/sh\nexec sleep 5\n").unwrap();
    std::fs::set_permissions(&py, std::fs::Permissions::from_mode(0o755)).unwrap();
    let key = root.join("sa.json");
    std::fs::write(&key, "{}").unwrap();

    // Point the poll cursor dir somewhere writable + isolated.
    std::env::set_var(
        crate::connector_worker::POLL_STATE_DIR_ENV,
        root.join("cursors"),
    );

    // Seed a LIVE --once child for (tenant, gdrive) via the plane directly.
    let started = state
        .connectors
        .start(
            state.pool().clone(),
            crate::connector_worker::SpawnMode::PollOnce,
            Some(root.as_path()),
            "http://127.0.0.1:0",
            tenant,
            "gdrive",
            None,
            crate::connector_worker::BackfillIdentity::Google {
                sa_key_path: key,
                subject: None,
            },
            Uuid::new_v4(),
        )
        .await
        .expect("seed a live poll child");
    assert!(started > 0);
    assert!(state
        .connectors
        .owned_live(tenant, "gdrive")
        .await
        .is_some());

    // A fire_cycle now MUST skip — the prior cycle still owns the cursor.
    let decision = sync_scheduler::fire_cycle(&state, tenant, "gdrive").await;
    assert!(
        matches!(decision, CycleDecision::SkippedInFlight),
        "expected SkippedInFlight, got {decision:?}"
    );

    // Clean up the live child + the fake tree.
    let _ = state.connectors.stop(tenant, "gdrive").await;
    std::env::remove_var(crate::connector_worker::POLL_STATE_DIR_ENV);
    let _ = std::fs::remove_dir_all(&root);
}
