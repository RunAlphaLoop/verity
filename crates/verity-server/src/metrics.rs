//! M0 instrument panel (deliverable #4): hand-rolled Prometheus metrics.
//!
//! No metrics crate is a dependency, so this mirrors the codebase idiom
//! already used by [`crate::rebac_watch::WatchStatus`]: a block of
//! `AtomicU64`/`AtomicBool` counters held behind an `Arc` on `AppState`, plus a
//! `/metrics` handler that renders the Prometheus text exposition format by
//! hand. The hot-path counters are `fetch_add(1, Relaxed)` — no lock, no
//! allocation, read-path-safe.
//!
//! Two kinds of series live here:
//!   * **In-process counters/gauges** (this struct): incremented at the hook
//!     points (recall handler, revocation subtract, audit-insert failure) and
//!     the shared `exact_scan_fallback` counter the storage crate bumps.
//!   * **Scrape-time DB gauges** (rendered in the handler, not stored here):
//!     `quarantine_depth`, `degraded_acl_runs`, `watch_cursor_lag_seconds` —
//!     bounded `COUNT`/`EXTRACT` queries run when `/metrics` is scraped.
//!
//! AGGREGATE-ONLY: every series is a global counter/gauge. No per-tenant
//! labels, no secrets, no chunk content ever appears in the output.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;

use crate::AppState;

/// Sentinel emitted for `watch_cursor_lag_seconds` when the lag is not a real
/// measurement (watch disabled, or the cursor row has never advanced). A
/// negative value can never be a true lag, so a dead/disabled consumer stays
/// visibly distinct from a fresh one (`0`) on the dashboard.
const LAG_SENTINEL: f64 = -1.0;

/// Recall-latency histogram buckets (seconds). Fixed, aggregate-only; chosen to
/// straddle the SPEC read-path budget (single-digit-ms p50 up to tail).
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

/// Hand-rolled in-process metric block, shared via `AppState.metrics`.
pub(crate) struct Metrics {
    /// `recall_requests_total` — every `recall` handler entry.
    pub(crate) recall_requests: AtomicU64,
    /// `recall_latency_seconds` histogram: per-bucket cumulative counts, the
    /// `+Inf`/total count, and the running sum (millis, folded to seconds at
    /// render). Bucket `i` counts observations ≤ `LATENCY_BUCKETS[i]`.
    latency_buckets: Vec<AtomicU64>,
    latency_count: AtomicU64,
    /// Sum of observed latencies in microseconds (integer-accumulated to keep
    /// the observe path allocation- and float-free; divided to seconds at
    /// render).
    latency_sum_micros: AtomicU64,
    /// `exact_scan_fallback_total` — bumped inside `recall_dense`'s ≤20k exact
    /// branch. Shared with `PostgresAdapter` (see `set_exact_scan_counter`), so
    /// the storage crate increments the *same* `Arc<AtomicU64>` rendered here.
    pub(crate) exact_scan_fallback: Arc<AtomicU64>,
    /// `revocation_subtractions_total` — bumped when `RevocationPlane::subtract`
    /// actually drops one or more tokens from a principal set. Shared with the
    /// plane (see `set_subtraction_counter`), so both increment/read the same
    /// atomic.
    pub(crate) revocation_subtractions: Arc<AtomicU64>,
    /// `audit_insert_drops_total` — bumped when a spawned audit insert fails.
    pub(crate) audit_insert_drops: AtomicU64,
    /// `staleness_fence_engaged_total` — bumped each time the recall-side
    /// staleness fence trips (Watch enabled + stale) and forces a tier-≤2 scope
    /// into live re-resolution / fail-closed. A rising counter = the Watch is
    /// degraded/lagging and the read path is over-hiding to stay honest.
    pub(crate) staleness_fence_engaged: AtomicU64,
    /// `source_fence_drops_total` — recall hits dropped by the per-source
    /// freshness gate (source_freshness.rs): stale or never-heartbeated
    /// connector sources refused while the gate was active. A rising counter =
    /// a connector is stalled (or was never run) and recall is over-hiding its
    /// rows to stay honest.
    pub(crate) source_fence_drops: AtomicU64,
}

impl Metrics {
    pub(crate) fn new() -> Self {
        Self {
            recall_requests: AtomicU64::new(0),
            latency_buckets: LATENCY_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            latency_count: AtomicU64::new(0),
            latency_sum_micros: AtomicU64::new(0),
            exact_scan_fallback: Arc::new(AtomicU64::new(0)),
            revocation_subtractions: Arc::new(AtomicU64::new(0)),
            audit_insert_drops: AtomicU64::new(0),
            staleness_fence_engaged: AtomicU64::new(0),
            source_fence_drops: AtomicU64::new(0),
        }
    }

    /// Count one recall-side staleness-fence engagement.
    pub(crate) fn record_staleness_fence(&self) {
        self.staleness_fence_engaged.fetch_add(1, Ordering::Relaxed);
    }

    /// Count hits dropped by the per-source freshness gate (by the number
    /// actually dropped, never the whole result set).
    pub(crate) fn record_source_fence_drops(&self, dropped: u64) {
        self.source_fence_drops
            .fetch_add(dropped, Ordering::Relaxed);
    }

    /// A clone of the shared exact-scan counter, to wire into `PostgresAdapter`
    /// at construction. Both sides then increment/read the same atomic.
    pub(crate) fn exact_scan_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.exact_scan_fallback)
    }

    /// The shared revocation-subtraction counter, to wire into `RevocationPlane`
    /// at construction. Both sides increment/read the same atomic.
    pub(crate) fn revocation_subtractions_arc(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.revocation_subtractions)
    }

    /// Count one recall request.
    pub(crate) fn record_recall_request(&self) {
        self.recall_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Observe one recall latency into the histogram. Cheap: a handful of
    /// `Relaxed` adds, no allocation, no lock.
    pub(crate) fn observe_recall_latency(&self, elapsed: std::time::Duration) {
        let secs = elapsed.as_secs_f64();
        for (i, edge) in LATENCY_BUCKETS.iter().enumerate() {
            if secs <= *edge {
                self.latency_buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }

    /// Count one dropped audit insert.
    pub(crate) fn record_audit_drop(&self) {
        self.audit_insert_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the in-process series in Prometheus text exposition format,
    /// appending to `out`. Scrape-time DB gauges are added by the handler.
    fn render_in_process(&self, out: &mut String) {
        let _ = writeln!(out, "# HELP up 1 if the server is serving.");
        let _ = writeln!(out, "# TYPE up gauge");
        let _ = writeln!(out, "up 1");

        let _ = writeln!(out, "# HELP build_info Build metadata (constant 1).");
        let _ = writeln!(out, "# TYPE build_info gauge");
        let _ = writeln!(
            out,
            "build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );

        let _ = writeln!(
            out,
            "# HELP recall_requests_total Total recall requests handled."
        );
        let _ = writeln!(out, "# TYPE recall_requests_total counter");
        let _ = writeln!(
            out,
            "recall_requests_total {}",
            self.recall_requests.load(Ordering::Relaxed)
        );

        let _ = writeln!(out, "# HELP recall_latency_seconds Recall handler latency.");
        let _ = writeln!(out, "# TYPE recall_latency_seconds histogram");
        let mut cumulative;
        for (i, edge) in LATENCY_BUCKETS.iter().enumerate() {
            cumulative = self.latency_buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "recall_latency_seconds_bucket{{le=\"{edge}\"}} {cumulative}"
            );
        }
        let count = self.latency_count.load(Ordering::Relaxed);
        let _ = writeln!(out, "recall_latency_seconds_bucket{{le=\"+Inf\"}} {count}");
        let sum = self.latency_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(out, "recall_latency_seconds_sum {sum}");
        let _ = writeln!(out, "recall_latency_seconds_count {count}");

        let _ = writeln!(
            out,
            "# HELP exact_scan_fallback_total Recall dense ≤20k exact-scan branch taken."
        );
        let _ = writeln!(out, "# TYPE exact_scan_fallback_total counter");
        let _ = writeln!(
            out,
            "exact_scan_fallback_total {}",
            self.exact_scan_fallback.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP revocation_subtractions_total Revoked tokens subtracted from principal sets."
        );
        let _ = writeln!(out, "# TYPE revocation_subtractions_total counter");
        let _ = writeln!(
            out,
            "revocation_subtractions_total {}",
            self.revocation_subtractions.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP audit_insert_drops_total Audit-log inserts that failed off the request path."
        );
        let _ = writeln!(out, "# TYPE audit_insert_drops_total counter");
        let _ = writeln!(
            out,
            "audit_insert_drops_total {}",
            self.audit_insert_drops.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP staleness_fence_engaged_total Recall-side staleness fence trips (Watch stale → tier-≤2 fail-closed / live re-resolution)."
        );
        let _ = writeln!(out, "# TYPE staleness_fence_engaged_total counter");
        let _ = writeln!(
            out,
            "staleness_fence_engaged_total {}",
            self.staleness_fence_engaged.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP source_fence_drops_total Recall hits dropped by the per-source freshness gate (stale/never-heartbeated connector sources)."
        );
        let _ = writeln!(out, "# TYPE source_fence_drops_total counter");
        let _ = writeln!(
            out,
            "source_fence_drops_total {}",
            self.source_fence_drops.load(Ordering::Relaxed)
        );
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Freshness alarm inputs: watch-consumer enablement + cursor lag.
///
/// `enabled` mirrors `WatchStatus.enabled` (only true once the consumer is
/// spawned). `lag_seconds` is `now() - rebac_watch_cursor.updated_at` when the
/// cursor exists AND the consumer is enabled; otherwise the [`LAG_SENTINEL`] so
/// a disabled or never-advanced consumer is VISIBLE, never a misleading `0`.
struct WatchFreshness {
    enabled: bool,
    connected: bool,
    degraded: bool,
    lag_seconds: f64,
}

impl WatchFreshness {
    async fn probe(state: &AppState) -> Self {
        let enabled = state.watch.enabled_now();
        let connected = state.watch.connected_now();
        let degraded = state.watch.degraded_now();
        // Only report a real lag when the consumer is enabled; a disabled
        // consumer's cursor row (if any is stale from a prior run) must not read
        // as fresh. Enabled-but-no-row (never advanced) also stays sentinel.
        //
        // Prefer the in-process cached gauge (the SAME lock-free signal the
        // recall-side staleness fence keys off, so the gauge and the fence can
        // never disagree). Fall back to the bounded DB query only when the
        // cursor has not advanced in THIS process (cache empty) — e.g. a fresh
        // replica reading a cursor a peer advanced — so the metric still
        // reflects durable state rather than reading sentinel forever.
        let lag_seconds = if enabled {
            match state.watch.lag_seconds_cached() {
                Some(lag) => lag as f64,
                None => query_cursor_lag(state).await.unwrap_or(LAG_SENTINEL),
            }
        } else {
            LAG_SENTINEL
        };
        Self {
            enabled,
            connected,
            degraded,
            lag_seconds,
        }
    }

    fn render(&self, out: &mut String) {
        let b = |x: bool| if x { 1 } else { 0 };
        let _ = writeln!(
            out,
            "# HELP watch_enabled 1 if the SpiceDB watch consumer is running."
        );
        let _ = writeln!(out, "# TYPE watch_enabled gauge");
        let _ = writeln!(out, "watch_enabled {}", b(self.enabled));
        let _ = writeln!(
            out,
            "# HELP watch_connected 1 if the watch stream is connected."
        );
        let _ = writeln!(out, "# TYPE watch_connected gauge");
        let _ = writeln!(out, "watch_connected {}", b(self.connected));
        let _ = writeln!(
            out,
            "# HELP watch_degraded 1 if the watch consumer latched a gap."
        );
        let _ = writeln!(out, "# TYPE watch_degraded gauge");
        let _ = writeln!(out, "watch_degraded {}", b(self.degraded));
        let _ = writeln!(
            out,
            "# HELP watch_cursor_lag_seconds Seconds since the watch cursor last advanced; {LAG_SENTINEL} = disabled/never-advanced (NOT fresh)."
        );
        let _ = writeln!(out, "# TYPE watch_cursor_lag_seconds gauge");
        let _ = writeln!(out, "watch_cursor_lag_seconds {}", self.lag_seconds);
    }
}

/// Ceiling on any single scrape-time DB query. `/metrics` is unauthenticated
/// and draws from the SAME read pool as recall; without a bound an attacker who
/// floods scrapes while a `COUNT(*)` relation is large could pin pooled
/// connections on slow scans and starve the read path. Every query below is
/// wrapped in this timeout; on expiry the gauge is omitted (never blocks, never
/// holds a connection unbounded). Mirrors `HEALTH_PROBE_TIMEOUT`.
const METRICS_DB_TIMEOUT: Duration = Duration::from_secs(2);

/// `now() - rebac_watch_cursor.updated_at` in seconds, or `None` when the row
/// is missing (consumer never advanced), the query fails, or the bounded
/// timeout expires (don't fail the whole scrape). A single indexed PK lookup.
async fn query_cursor_lag(state: &AppState) -> Option<f64> {
    let query = sqlx::query_scalar(
        "SELECT extract(epoch FROM now() - updated_at)::float8
         FROM rebac_watch_cursor WHERE id = 1",
    )
    .fetch_optional(state.pool());
    let lag: Option<f64> = tokio::time::timeout(METRICS_DB_TIMEOUT, query)
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten();
    lag
}

/// Run a scrape-time `COUNT(*)` under [`METRICS_DB_TIMEOUT`]. `Err(())` on query
/// failure OR timeout expiry, which [`render_count_gauge`] renders as an absent
/// gauge. The timeout is what stops an unauthenticated scrape from pinning a
/// pooled connection on a slow full-relation scan and starving the read path.
async fn bounded_count_gauge(state: &AppState, sql: &'static str) -> Result<i64, ()> {
    let query = sqlx::query_scalar::<_, i64>(sql).fetch_one(state.pool());
    match tokio::time::timeout(METRICS_DB_TIMEOUT, query).await {
        Ok(Ok(n)) => Ok(n),
        _ => Err(()),
    }
}

/// A scrape-time `COUNT(*)` gauge; on query error the gauge is OMITTED (absent)
/// rather than emitted as a misleading 0, and never fails the whole response.
async fn render_count_gauge(out: &mut String, name: &str, help: &str, count: Result<i64, ()>) {
    match count {
        Ok(n) => {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            let _ = writeln!(out, "{name} {n}");
        }
        Err(()) => {
            let _ = writeln!(out, "# HELP {name} {help} (unavailable this scrape)");
        }
    }
}

/// GET /metrics — Prometheus text exposition (M0). Unauthenticated but
/// aggregate-only: no tenant labels, no secrets, no chunk content. Renders the
/// in-process atomics, the watch freshness alarm, and the scrape-time DB
/// gauges.
pub(crate) async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut out = String::with_capacity(2048);

    state.metrics.render_in_process(&mut out);
    WatchFreshness::probe(&state).await.render(&mut out);

    let quarantine = bounded_count_gauge(&state, "SELECT count(*) FROM quarantine_preview").await;
    render_count_gauge(
        &mut out,
        "quarantine_depth",
        "Rows currently in quarantine_preview (unmappable ACL / held media).",
        quarantine,
    )
    .await;

    let degraded = bounded_count_gauge(
        &state,
        "SELECT count(*) FROM backfill_run WHERE state = 'degraded_acl'",
    )
    .await;
    render_count_gauge(
        &mut out,
        "degraded_acl_runs",
        "Backfill runs terminated in the degraded_acl state.",
        degraded,
    )
    .await;

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_histogram_is_monotone_and_counted() {
        let m = Metrics::new();
        m.record_recall_request();
        m.observe_recall_latency(std::time::Duration::from_millis(3));
        m.observe_recall_latency(std::time::Duration::from_millis(30));
        let mut out = String::new();
        m.render_in_process(&mut out);
        assert!(out.contains("recall_requests_total 1"));
        assert!(out.contains("recall_latency_seconds_count 2"));
        // 3ms falls in ≤0.005 bucket; 30ms does not — cumulative counts rise.
        assert!(out.contains("recall_latency_seconds_bucket{le=\"0.005\"} 1"));
        assert!(out.contains("recall_latency_seconds_bucket{le=\"0.05\"} 2"));
        assert!(out.contains("recall_latency_seconds_bucket{le=\"+Inf\"} 2"));
    }

    #[test]
    fn hot_path_counters_render() {
        let m = Metrics::new();
        m.exact_scan_counter().fetch_add(4, Ordering::Relaxed);
        m.revocation_subtractions_arc()
            .fetch_add(2, Ordering::Relaxed);
        m.record_audit_drop();
        let mut out = String::new();
        m.render_in_process(&mut out);
        assert!(out.contains("exact_scan_fallback_total 4"));
        assert!(out.contains("revocation_subtractions_total 2"));
        assert!(out.contains("audit_insert_drops_total 1"));
        assert!(out.contains("up 1"));
        assert!(out.contains("build_info{version="));
    }

    #[test]
    fn watch_disabled_renders_sentinel_not_zero() {
        // A disabled consumer must NOT render lag 0 (which reads as fresh).
        let f = WatchFreshness {
            enabled: false,
            connected: false,
            degraded: false,
            lag_seconds: LAG_SENTINEL,
        };
        let mut out = String::new();
        f.render(&mut out);
        assert!(out.contains("watch_enabled 0"));
        assert!(out.contains("watch_cursor_lag_seconds -1"));
        assert!(!out.contains("watch_cursor_lag_seconds 0\n"));
    }

    #[test]
    fn count_gauge_error_omits_value() {
        let mut out = String::new();
        futures_lite_block(render_count_gauge(
            &mut out,
            "quarantine_depth",
            "help",
            Err(()),
        ));
        assert!(out.contains("unavailable this scrape"));
        assert!(!out.contains("\nquarantine_depth "));
    }

    // Tiny synchronous executor for the one async unit above (no tokio rt in
    // these pure-render tests; the fn only awaits already-ready futures).
    fn futures_lite_block<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll};
        let mut fut = Box::pin(fut);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }
}
