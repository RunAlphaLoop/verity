//! Server-side debounced auto-resolve (closes the DIRECT-ingest gap).
//!
//! Entity resolution used to auto-fire ONLY after the Temporal
//! `ConnectorSyncWorkflow` poll cycle (a Python hook). Data written through the
//! DIRECT ingest endpoints (`/v1/ingest/debezium`, `/v1/ingest/documents`, the
//! minted `/wh/{token}` webhooks) never triggered a resolve — an operator had to
//! POST `/v1/admin/entity-resolution/run` by hand. This scheduler closes that
//! gap: every successful L1-mutating ingest marks its tenant "dirty"; a
//! background loop periodically runs the resolver for any tenant that is dirty
//! AND past the debounce window.
//!
//! Because the connector sinks ALSO POST to `/v1/ingest/*`, this server-side
//! trigger now covers BOTH the direct paths AND the connector sinks. It and the
//! Temporal Python hook are therefore belt-and-suspenders: a resolve may be
//! requested from either side, but they can't stack up or duplicate work —
//! `run_resolution` is idempotent (deterministic evidence ids + `ON CONFLICT DO
//! NOTHING`, plus a pure fold), and the shared `VERITY_RESOLVE_DEBOUNCE` window
//! keeps either trigger from hot-looping.
//!
//! Config: `VERITY_RESOLVE_DEBOUNCE` (seconds, default 900) is the SAME env var
//! the Python side reads, for a single source of truth. `0` DISABLES the
//! server-side loop entirely (resolution stays manual / Temporal-only). Negative
//! or non-numeric values clamp to the default rather than crashing the server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use verity_core::types::TenantId;

/// Default post-ingest debounce, mirroring the Python side (900s = 15 min).
pub(crate) const DEFAULT_RESOLVE_DEBOUNCE_SECONDS: f64 = 900.0;
const RESOLVE_DEBOUNCE_ENV: &str = "VERITY_RESOLVE_DEBOUNCE";

/// Per-tenant scheduling state.
#[derive(Debug, Default, Clone, Copy)]
struct TenantState {
    /// An L1-mutating ingest happened since the last resolve.
    dirty: bool,
    /// When this tenant was last resolved (stamped whether the run succeeded or
    /// failed, so a persistently-failing tenant can't hot-loop). `None` = never
    /// resolved by this scheduler yet.
    last_resolve: Option<Instant>,
}

/// Tracks dirty tenants and the debounce window; the background loop drains it.
pub(crate) struct ResolutionScheduler {
    /// `None` when server-side auto-resolve is disabled (`VERITY_RESOLVE_DEBOUNCE
    /// == 0`): `mark_dirty` becomes a cheap no-op and no loop is spawned.
    debounce: Option<Duration>,
    tenants: Mutex<HashMap<TenantId, TenantState>>,
}

/// PURE due-decision (clock injected so tests don't sleep real seconds).
///
/// A tenant is due iff it is dirty AND either it has never been resolved by this
/// scheduler, or at least `debounce` has elapsed since the last resolve. Not
/// dirty ⇒ never due. `debounce == 0` (disabled) ⇒ never due.
pub(crate) fn due(
    dirty: bool,
    last_resolve: Option<Instant>,
    now: Instant,
    debounce: Duration,
) -> bool {
    if !dirty || debounce.is_zero() {
        return false;
    }
    match last_resolve {
        None => true,
        Some(last) => now.saturating_duration_since(last) >= debounce,
    }
}

impl ResolutionScheduler {
    /// Build from the process env. Reads `VERITY_RESOLVE_DEBOUNCE` (seconds):
    /// unset ⇒ default 900; `0` ⇒ disabled; negative / non-numeric ⇒ default
    /// (warned), never a crash.
    pub(crate) fn from_env() -> Self {
        let seconds = match std::env::var(RESOLVE_DEBOUNCE_ENV) {
            Err(_) => DEFAULT_RESOLVE_DEBOUNCE_SECONDS,
            Ok(raw) => match raw.trim().parse::<f64>() {
                Ok(v) if v >= 0.0 => v,
                _ => {
                    tracing::warn!(
                        "invalid {RESOLVE_DEBOUNCE_ENV}={raw:?}, using default {DEFAULT_RESOLVE_DEBOUNCE_SECONDS}s"
                    );
                    DEFAULT_RESOLVE_DEBOUNCE_SECONDS
                }
            },
        };
        Self::with_debounce_seconds(seconds)
    }

    /// Construct with an explicit debounce (seconds). `0.0` ⇒ disabled.
    pub(crate) fn with_debounce_seconds(seconds: f64) -> Self {
        let debounce = if seconds <= 0.0 {
            None
        } else {
            Some(Duration::from_secs_f64(seconds))
        };
        Self {
            debounce,
            tenants: Mutex::new(HashMap::new()),
        }
    }

    /// Whether the background loop should be spawned (auto-resolve enabled).
    pub(crate) fn enabled(&self) -> bool {
        self.debounce.is_some()
    }

    /// The configured debounce window, or `None` when disabled.
    pub(crate) fn debounce(&self) -> Option<Duration> {
        self.debounce
    }

    /// Mark a tenant dirty — called at the END of a successful, L1-mutating
    /// ingest. Cheap: one lock + map insert. A no-op when auto-resolve is
    /// disabled. Never fails, never blocks the ingest response.
    pub(crate) fn mark_dirty(&self, tenant: TenantId) {
        if self.debounce.is_none() {
            return;
        }
        let mut tenants = self.tenants.lock().expect("scheduler mutex poisoned");
        tenants.entry(tenant).or_default().dirty = true;
    }

    /// Tenants that are due to resolve NOW (dirty AND past the debounce window),
    /// as of `now`. Non-mutating — the caller drives the runs, then calls
    /// `stamp_resolved` for each so the debounce clock advances even on failure.
    pub(crate) fn due_tenants(&self, now: Instant) -> Vec<TenantId> {
        let Some(debounce) = self.debounce else {
            return Vec::new();
        };
        let tenants = self.tenants.lock().expect("scheduler mutex poisoned");
        tenants
            .iter()
            .filter(|(_, st)| due(st.dirty, st.last_resolve, now, debounce))
            .map(|(t, _)| *t)
            .collect()
    }

    /// Clear the dirty flag and stamp the last-resolve time for a tenant,
    /// REGARDLESS of whether the run succeeded — a persistently-failing tenant
    /// must not hot-loop. A fresh ingest arriving mid-run re-dirties the tenant
    /// (worst case: one extra idempotent resolve next window).
    pub(crate) fn stamp_resolved(&self, tenant: TenantId, now: Instant) {
        let mut tenants = self.tenants.lock().expect("scheduler mutex poisoned");
        let st = tenants.entry(tenant).or_default();
        st.dirty = false;
        st.last_resolve = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: u64) -> Instant {
        // A fixed base + offset; Instant has no public constructor, so we anchor
        // on a single `now` and add. Tests never touch the real clock's rate.
        BASE.get_or_init(Instant::now);
        *BASE.get().unwrap() + Duration::from_secs(secs)
    }

    use std::sync::OnceLock;
    static BASE: OnceLock<Instant> = OnceLock::new();

    const WINDOW: Duration = Duration::from_secs(900);

    #[test]
    fn not_dirty_is_never_due() {
        assert!(!due(false, None, t(0), WINDOW));
        assert!(!due(false, Some(t(0)), t(10_000), WINDOW));
    }

    #[test]
    fn dirty_with_no_prior_resolve_is_due() {
        assert!(due(true, None, t(0), WINDOW));
    }

    #[test]
    fn dirty_within_window_is_not_due() {
        // resolved at 100s, now 500s → only 400s elapsed < 900s window.
        assert!(!due(true, Some(t(100)), t(500), WINDOW));
    }

    #[test]
    fn dirty_past_window_is_due() {
        // resolved at 100s, now 1100s → 1000s elapsed ≥ 900s window.
        assert!(due(true, Some(t(100)), t(1100), WINDOW));
        // exactly at the boundary is due (>=).
        assert!(due(true, Some(t(100)), t(1000), WINDOW));
    }

    #[test]
    fn debounce_zero_disables() {
        assert!(!due(true, None, t(0), Duration::ZERO));
        assert!(!due(true, Some(t(0)), t(10_000), Duration::ZERO));
    }

    #[test]
    fn disabled_scheduler_marks_and_yields_nothing() {
        let sched = ResolutionScheduler::with_debounce_seconds(0.0);
        assert!(!sched.enabled());
        let tenant = TenantId::new_v4();
        sched.mark_dirty(tenant); // no-op
        assert!(sched.due_tenants(t(10_000)).is_empty());
    }

    #[test]
    fn enabled_scheduler_marks_then_becomes_due() {
        let sched = ResolutionScheduler::with_debounce_seconds(900.0);
        assert!(sched.enabled());
        let tenant = TenantId::new_v4();
        // clean → nothing due.
        assert!(sched.due_tenants(t(0)).is_empty());
        // dirty & never resolved → immediately due.
        sched.mark_dirty(tenant);
        assert_eq!(sched.due_tenants(t(0)), vec![tenant]);
        // stamp resolved → not due until the window passes.
        sched.stamp_resolved(tenant, t(0));
        assert!(sched.due_tenants(t(0)).is_empty());
        assert!(sched.due_tenants(t(400)).is_empty());
        // still clean (no new ingest) even past the window → not due.
        assert!(sched.due_tenants(t(1000)).is_empty());
        // a new ingest re-dirties → due again once past the window.
        sched.mark_dirty(tenant);
        assert!(sched.due_tenants(t(400)).is_empty());
        assert_eq!(sched.due_tenants(t(1000)), vec![tenant]);
    }
}
