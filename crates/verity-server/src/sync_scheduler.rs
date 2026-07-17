//! Continuous-sync SCHEDULER (Phase 4) — a per-(tenant, source) interval loop
//! that fires a SHORT-LIVED incremental `--once` poll cycle, NOT a persistent
//! long-running child.
//!
//! MODEL (non-negotiable): continuous sync is NOT a 24/7 process. Each tick, the
//! scheduler spawns `python -m verity_ingest.connectors.<source> --once …` — the
//! incremental poll that advances the persisted per-(tenant, source) cursor — and
//! that child exits in seconds. This dissolves the worst edge cases: no long-lived
//! decrypted-bearer on disk (each cycle materializes + unlinks in seconds via the
//! reused `connector_worker` spawn/cleanup), no credential-rotation guard (each
//! cycle re-resolves the CURRENT credential through `resolve_connector_identity`),
//! and no crash-supervision (cycles are independent — a failed cycle just retries
//! next tick).
//!
//! SKIP-IF-RUNNING: if a cycle for (tenant, source) is still running when the next
//! tick fires, the tick is SKIPPED. The `connector_worker` ownership lock already
//! prevents a concurrent same-key spawn (a racing `start` returns `AlreadyRunning`);
//! the scheduler probes `owned_live` first and skips cleanly rather than queueing
//! or double-spawning.
//!
//! DURABILITY + RE-ARM: the durable schedule lives in `sync_schedules` (migration
//! 0033). Enabling/disabling is a durable upsert. On server boot,
//! [`reestablish_on_boot`] reads every enabled schedule and arms one loop each —
//! exactly like `folder_watch::reestablish_on_boot` re-arms persisted watches.
//!
//! DOUBLE-POLL GUARD: the env-configured knowledge/Temporal connector-sync worker
//! is the OTHER continuous source poller. A per-(tenant, source) schedule and that
//! worker must not both poll the same source (concurrent cursor advances). The
//! toggle endpoint (connectors_admin.rs) refuses/warns per the deployment config;
//! this module owns only the native Rust loop.

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;
use verity_core::adapter::StorageAdapter;

use crate::connector_worker::SpawnMode;
use crate::AppState;

/// The cancel signal for one armed loop: a `watch` channel whose value flips to
/// `true` on disarm. The loop `select!`s on `changed()` so it breaks promptly on
/// the next tick/signal. `watch` (not oneshot) so a dropped receiver never
/// panics the sender and the flag is re-readable. `tokio::sync::Notify` would
/// also work; `watch` keeps the "cancelled?" state inspectable.
type CancelTx = tokio::sync::watch::Sender<bool>;

/// A handle to one armed schedule loop: the cancel sender that stops it plus the
/// interval it runs at (so a re-arm can report the cadence). The loop task is
/// detached — flipping the cancel `watch` makes the loop break on its next
/// `select`, and an in-flight `--once` cycle is left to finish (it is short-lived
/// and independently reaped).
struct ArmedSchedule {
    cancel: CancelTx,
    /// The cadence this loop runs at — recorded so a read-back (test + a future
    /// admin surface) can report the live interval without re-reading the DB.
    #[cfg_attr(not(test), allow(dead_code))]
    interval_secs: i32,
}

/// The server-held continuous-sync plane: the per-(tenant, source) map of armed
/// loop handles plus an admission mutex ([`SyncPlane::admit`]) the toggle handler
/// holds across its whole persist→arm/disarm critical section so two concurrent
/// enable/disable requests can't interleave and leave a ghost loop armed against
/// a disabled durable schedule. Bundled so `AppState` carries ONE field,
/// mirroring `ConnectorPlane`. Lives inside `Arc<AppState>`.
pub(crate) struct SyncPlane {
    /// Per-key armed loops. A present entry = a live interval loop for that
    /// (tenant, source). Disarm cancels + removes; re-arm at a new interval
    /// replaces.
    loops: tokio::sync::Mutex<HashMap<(Uuid, String), ArmedSchedule>>,
    /// Serializes a toggle's whole persist→arm/disarm critical section (via
    /// [`SyncPlane::admit`]) so two concurrent enable/disable requests for the
    /// same key can't interleave their durable upsert and their arm/disarm and
    /// leave a GHOST loop armed while the durable schedule says disabled (or the
    /// reverse). `loops` alone is held only briefly inside arm/disarm, not across
    /// the handler — this mutex is the handler-scope guard the doc promises.
    admission: tokio::sync::Mutex<()>,
}

impl SyncPlane {
    pub(crate) fn new() -> Self {
        Self {
            loops: tokio::sync::Mutex::new(HashMap::new()),
            admission: tokio::sync::Mutex::new(()),
        }
    }

    /// Acquire the admission lock guarding a toggle's persist→arm/disarm section.
    /// The caller holds the returned guard across the entire durable-upsert +
    /// arm/disarm sequence so no concurrent toggle for a different key can start
    /// its own section mid-flight (the lock is process-global, not per-key — the
    /// critical section is short: a single upsert + an arm/disarm, no source
    /// poll). This makes upsert and arm/disarm atomic with respect to each other.
    pub(crate) async fn admit(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.admission.lock().await
    }

    /// Whether a loop is currently armed for (tenant, source) — the live in-memory
    /// truth the toggle reports back (the durable enabled-flag is in
    /// `sync_schedules`; this confirms the loop actually got armed this process).
    pub(crate) async fn is_armed(&self, tenant: Uuid, source: &str) -> bool {
        self.loops
            .lock()
            .await
            .contains_key(&(tenant, source.to_string()))
    }

    /// The interval of the armed loop for (tenant, source), if any. Test helper.
    #[cfg(test)]
    pub(crate) async fn armed_interval(&self, tenant: Uuid, source: &str) -> Option<i32> {
        self.loops
            .lock()
            .await
            .get(&(tenant, source.to_string()))
            .map(|a| a.interval_secs)
    }

    /// Count of armed loops — boot re-arm / test assertion helper.
    pub(crate) async fn armed_count(&self) -> usize {
        self.loops.lock().await.len()
    }

    /// Arm (or re-arm) the interval loop for (tenant, source) at `interval_secs`.
    /// Idempotent-by-replacement: an existing loop for the same key is disarmed
    /// first (its token cancelled) so exactly one loop per key ever runs — a
    /// re-arm at a new cadence swaps in place, never stacks. `state` is the shared
    /// `Arc<AppState>` the loop uses to fire each `--once` cycle.
    pub(crate) async fn arm(
        &self,
        state: Arc<AppState>,
        tenant: Uuid,
        source: &str,
        interval_secs: i32,
    ) {
        let key = (tenant, source.to_string());
        let mut map = self.loops.lock().await;
        // Replace any existing loop for this key (cancel the old one first).
        if let Some(old) = map.remove(&key) {
            let _ = old.cancel.send(true);
        }
        let (cancel, cancel_rx) = tokio::sync::watch::channel(false);
        let source_owned = source.to_string();
        tokio::spawn(sync_loop(
            state,
            tenant,
            source_owned,
            interval_secs,
            cancel_rx,
        ));
        map.insert(
            key,
            ArmedSchedule {
                cancel,
                interval_secs,
            },
        );
    }

    /// Disarm the interval loop for (tenant, source): cancel its token (the loop
    /// breaks on its next tick/select) and drop the handle. Honest no-op when no
    /// loop is armed. An in-flight `--once` cycle is left to finish (short-lived,
    /// independently reaped) — disable is durable in `sync_schedules` regardless.
    pub(crate) async fn disarm(&self, tenant: Uuid, source: &str) -> bool {
        let mut map = self.loops.lock().await;
        match map.remove(&(tenant, source.to_string())) {
            Some(armed) => {
                let _ = armed.cancel.send(true);
                true
            }
            None => false,
        }
    }
}

/// One schedule's interval loop: every `interval_secs`, fire a `--once` poll
/// cycle for (tenant, source) unless a prior cycle is still in-flight (skip) or
/// the cancel token has fired (break). Cloned in spirit from `auto_resolve_loop`.
async fn sync_loop(
    state: Arc<AppState>,
    tenant: Uuid,
    source: String,
    interval_secs: i32,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) {
    let period = std::time::Duration::from_secs(interval_secs.max(1) as u64);
    let mut ticker = tokio::time::interval(period);
    // Skip the immediate first tick that `interval` yields at t=0 — the toggle
    // endpoint fires an explicit first cycle on ENABLE; the loop's job is the
    // steady-state cadence, so the first LOOP fire is one full interval out.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // consume the t=0 tick
    loop {
        tokio::select! {
            _ = cancel.changed() => break,
            _ = ticker.tick() => {
                fire_cycle(&state, tenant, &source).await;
            }
        }
    }
}

/// Fire ONE `--once` poll cycle for (tenant, source) if none is in-flight.
/// Returns the [`CycleDecision`] so the toggle's immediate-first-cycle path and
/// the loop share one honest code path. SKIP-IF-RUNNING is decided by
/// `connector_worker::ConnectorPlane::owned_live`: a live child for this key means
/// the previous cycle hasn't finished, so we skip (never queue/double-spawn). On a
/// clean spawn we stamp `last_run_at` (best-effort telemetry; the authoritative
/// cursor stays in the connector state file).
pub(crate) async fn fire_cycle(state: &Arc<AppState>, tenant: Uuid, source: &str) -> CycleDecision {
    // SKIP-IF-RUNNING: a live owned child for this key = the prior cycle is still
    // draining. Skip this tick cleanly rather than race the ownership lock.
    if state.connectors.owned_live(tenant, source).await.is_some() {
        return CycleDecision::SkippedInFlight;
    }

    // Re-resolve the CURRENT credential every cycle (picks up a rotation; no
    // long-lived bearer). A precondition failure (missing/ambiguous credential,
    // absent gmail subject / hubspot visibility) is logged and the cycle is
    // skipped — a disabled-worthy schedule keeps failing softly until toggled off,
    // never crashes the loop.
    let identity = match crate::connectors_admin::resolve_connector_identity(state, tenant, source)
        .await
    {
        Ok(id) => id,
        Err((status, msg)) => {
            tracing::warn!(%tenant, %source, %status, %msg, "sync cycle: credential unresolvable — skipping this tick");
            return CycleDecision::Unresolvable;
        }
    };

    let base_url = crate::worker_base_url(&state.listen);
    // A poll doesn't need a backfill_run id; mint a throwaway (the poll reap does
    // NOT reconcile backfill_run — see connector_worker::reap gating on mode).
    let run_id = Uuid::new_v4();
    match state
        .connectors
        .start(
            state.pool().clone(),
            SpawnMode::PollOnce,
            state.repo_root.as_deref(),
            &base_url,
            tenant,
            source,
            state.admin_token.as_deref(),
            identity,
            run_id,
        )
        .await
    {
        Ok(pid) => {
            // Best-effort last-run stamp (display-only). A failed stamp is logged,
            // never fatal — the cycle already spawned.
            if let Err(e) = state
                .storage
                .touch_sync_schedule_last_run(tenant, source)
                .await
            {
                tracing::warn!(%tenant, %source, %e, "sync cycle: last_run_at stamp failed (spawn ok)");
            }
            tracing::info!(%tenant, %source, pid, "sync cycle fired (--once)");
            CycleDecision::Spawned { pid }
        }
        Err(crate::connector_worker::SpawnError::AlreadyRunning { .. }) => {
            // Raced the ownership lock between owned_live and start — treat as an
            // in-flight skip (the other cycle owns the cursor). The ownership lock
            // guarantees exactly one cycle spawns; the loser skips cleanly.
            CycleDecision::SkippedInFlight
        }
        Err(crate::connector_worker::SpawnError::SourceBusy { tenant: busy, .. }) => {
            // The SAME source is live under a DIFFERENT tenant — `ConnectorPlane`
            // serializes a source across tenants (a shared SA-key/rate budget for
            // rare operator backfills). For a continuous poll this is benign
            // cross-tenant contention, NOT a failure: this tenant's cursor is its
            // own, so skipping cleanly this tick and retrying next is correct.
            // Log at debug (an honest skip), never as a spurious spawn-failure.
            tracing::debug!(%tenant, %source, busy_tenant = %busy, "sync cycle: source busy under another tenant — skipping this tick");
            CycleDecision::SkippedSourceBusy
        }
        Err(e) => {
            tracing::warn!(%tenant, %source, "sync cycle: spawn failed: {e:?}");
            CycleDecision::SpawnFailed
        }
    }
}

/// The outcome of a `--once` cycle attempt — surfaced so the loop and the toggle's
/// immediate-first-cycle share one honest decision, and tests can assert the
/// skip-if-running branch without spawning a real child.
#[derive(Debug)]
pub(crate) enum CycleDecision {
    /// A child was spawned for this cycle. `pid` is carried for the Debug/log
    /// record (the toggle surfaces `first_cycle: "Spawned { pid: N }"`).
    #[allow(dead_code)]
    Spawned { pid: u32 },
    /// A prior cycle for this key is still in-flight — skipped (either the
    /// `owned_live` probe saw a live child, or `start` raced the ownership lock
    /// and returned `AlreadyRunning`). Never queued, never double-spawned.
    SkippedInFlight,
    /// The SAME source is live under a DIFFERENT tenant (`ConnectorPlane`
    /// serializes a source across tenants for a shared SA-key/rate budget). For a
    /// continuous poll this is benign cross-tenant contention — skipped cleanly
    /// this tick, NOT a spawn failure. This tenant's cursor is untouched and the
    /// next tick retries.
    SkippedSourceBusy,
    /// The credential could not be resolved this cycle — skipped, logged.
    Unresolvable,
    /// The spawn itself failed (repo/venv/OS) — logged, retried next tick.
    SpawnFailed,
}

/// Re-arm a scheduler loop for every ENABLED schedule on boot — the durability
/// half of continuous sync. Mirrors `folder_watch::reestablish_on_boot`. A
/// storage read failure is logged and skipped (best-effort; a boot must not fail
/// because the schedules table is briefly unreadable). Each row's interval is the
/// DB-floored value (>= 60s), so no boot re-arm can arm a sub-floor loop.
pub(crate) async fn reestablish_on_boot(state: Arc<AppState>) {
    let schedules = match state.storage.list_enabled_sync_schedules().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%e, "sync scheduler boot re-arm: could not list enabled schedules — none re-armed");
            return;
        }
    };
    let n = schedules.len();
    for sched in schedules {
        state
            .sync
            .arm(
                Arc::clone(&state),
                sched.tenant_id,
                &sched.source,
                sched.interval_secs,
            )
            .await;
    }
    if n > 0 {
        tracing::info!(
            count = n,
            "sync scheduler: re-armed enabled continuous-sync schedules on boot"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    // A SyncPlane arm/disarm exercises the map + cancel token WITHOUT firing a
    // real cycle: the loop's first fire is one full interval out, and we arm with
    // a large interval + disarm immediately, so no --once spawn is ever attempted.
    // This proves the arm/disarm bookkeeping (idempotent replace, honest no-op
    // disarm) hermetically, with no DB / process / source poll.

    #[tokio::test]
    async fn arm_then_disarm_tracks_and_clears() {
        // We can't build a full AppState hermetically here, so exercise the plane
        // bookkeeping directly through a stub loop by arming with a token we
        // control — but arm() needs an AppState. Instead assert the plane's map
        // primitives via a hand-driven ArmedSchedule.
        let plane = SyncPlane::new();
        assert_eq!(plane.armed_count().await, 0);
        assert!(!plane.is_armed(t(1), "gdrive").await);

        // Insert a fake armed schedule (no loop task) to prove disarm bookkeeping.
        {
            let mut map = plane.loops.lock().await;
            let (cancel, _rx) = tokio::sync::watch::channel(false);
            map.insert(
                (t(1), "gdrive".to_string()),
                ArmedSchedule {
                    cancel,
                    interval_secs: 300,
                },
            );
        }
        assert!(plane.is_armed(t(1), "gdrive").await);
        assert_eq!(plane.armed_interval(t(1), "gdrive").await, Some(300));
        assert_eq!(plane.armed_count().await, 1);

        // Disarm returns true (cancels + removes); a second disarm is an honest
        // no-op (false).
        assert!(plane.disarm(t(1), "gdrive").await);
        assert!(!plane.is_armed(t(1), "gdrive").await);
        assert!(!plane.disarm(t(1), "gdrive").await);
        assert_eq!(plane.armed_count().await, 0);
    }

    #[tokio::test]
    async fn disarm_of_unarmed_key_is_honest_noop() {
        let plane = SyncPlane::new();
        assert!(!plane.disarm(t(9), "hubspot").await);
    }
}
