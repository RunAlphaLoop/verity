//! SpiceDB Watch-driven revocation materialization (SPEC §7b, opt-in).
//!
//! INVARIANT — one consumer per database: the durable cursor
//! (`rebac_watch_cursor`) is a single row, owned by exactly one running
//! consumer. Two consumers sharing a database would fight over it (each
//! resumes past events the other processed) and both go quietly blind. M1
//! removes this hazard with LEADER ELECTION: [`crate::watch_leader`] takes a
//! session-level Postgres advisory lock, and only the lock holder consumes the
//! stream + advances the cursor. Follower replicas stay idle and poll-retry the
//! lock, taking over automatically when the leader's session lock auto-releases
//! (process death / connection loss). This makes the single-row cursor safe
//! across multiple replicas. Tests still spawn a scratch database so an
//! already-running dev consumer's lock/cursor cannot interfere.
//!
//! A background consumer of SpiceDB's `/v1/watch` stream. On every
//! `group#member` tuple DELETE observed on the stream — including deletes
//! performed DIRECTLY against SpiceDB (zed CLI, a SCIM bridge, another
//! writer) that the admin plane never saw — it materializes the same durable
//! revocation tombstones `admin_group_remove` writes (revocation.rs), so an
//! out-of-band membership removal takes effect on the very next read instead
//! of waiting for handle expiry. Grants (TOUCH/CREATE) are deliberately not
//! accelerated: SPEC §7b rule 3 — the staleness window applies only to
//! grants, never revocations — so grant freshness stays "next mint".
//!
//! ## Fail-closed contract (the load-bearing part)
//!
//! The watch consumer is an ACCELERATOR, never a replacement:
//! - It only ever ADDS tombstones. Mint-time fully-consistent resolution,
//!   the windowed subtraction, and the restricted-class recheck all keep
//!   running regardless of watch health — a dead stream can never under-hide
//!   relative to the v0.1 baseline, and no code may treat "the watch saw
//!   nothing" as "nothing was revoked".
//! - Read-path purity is untouched: this is a background task; `recall`/`get`
//!   never consult it.
//! - Processing failures never ack-and-drop: the durable cursor
//!   (`rebac_watch_cursor`, migration 0025) advances only AFTER a frame's
//!   deltas are recorded, so errors reconnect-and-replay. Replay is safe —
//!   tombstones are additive/over-hiding, deduped by a short recent-token
//!   window (which also absorbs the duplicate event the admin remove path
//!   produces for its own tuple delete).
//! - An unresumable cursor (SpiceDB GC'd the revision) is a GAP, not a fresh
//!   start: it LATCHES `degraded` (cleared only by restart, after operator
//!   reconciliation), logs at error level, and resumes from head — the
//!   baseline guarantees cover the gap exactly as they cover a deployment
//!   with the watch disabled. Never fail-open.
//!
//! Health is exposed at `GET /v1/admin/rebac-watch` (admin-gated):
//! enabled/connected/degraded, gap + reconnect + delta counters, last cursor.
//!
//! Gating (M1): DEFAULT-ON whenever `VERITY_SPICEDB_URL` is set (ReBAC
//! configured). `VERITY_SPICEDB_WATCH=0` is an explicit opt-OUT for operators
//! who want the windowed baseline only. A configured watch whose stream cannot
//! be opened at startup is a hard startup failure — same posture as
//! `ensure_schema`. The consumer is SUPERVISED ([`run_supervised`]): a panic in
//! the stream task auto-restarts with capped backoff so a bug can never
//! silently end materialization, and it is LEADER-ELECTED (see the invariant
//! above) so it is safe on more than one replica.
//!
//! ## Staleness-fence primitive (recall-side, M1)
//!
//! [`WatchStatus::is_stale`] is a cheap, LOCALLY-OBSERVABLE "is the cursor too
//! stale to trust the materialized set?" check the recall path calls to decide
//! whether to FAIL CLOSED. It reads only in-process atomics ([`WatchStatus`]
//! flags + a cached last-advance instant updated by this loop) — NO database
//! query, NO live ReBAC call — so it preserves read-path purity and adds zero
//! per-read latency. `recall`/`get` (owned by the integration layer) consult it
//! to force tier-≤2 into live re-resolution / drop when the watch is enabled but
//! degraded, disconnected, or lagging beyond the fence bound.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::LazyLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use futures_util::StreamExt;
use serde_json::{json, Value};
use sqlx::PgPool;

use verity_core::types::{PrincipalToken, TenantId};

use crate::rebac::{parse_any_object_id, PrincipalKind, Rebac, RebacError};
use crate::watch_leader::WatchLeadership;
use crate::{AppState, HandlerResult};

/// Tokens already tombstoned within this many seconds are not re-recorded.
/// This dedupes (a) the duplicate watch event for admin-plane removals (the
/// admin handler writes tombstones synchronously, then deletes the tuple we
/// then observe) and (b) replays after a cursor-behind reconnect. Skipping a
/// re-record only shortens the effective window end by ≤ this bound —
/// negligible against the 300s default window, and never under-hiding for
/// the event that wrote the recent row.
const DEDUPE_SECS: i64 = 15;
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(60);

/// Supervisor restart backoff bounds — a PANIC in the stream task (as opposed
/// to a transport error, which `run`'s own reconnect loop already handles) is
/// caught by [`run_supervised`], which respawns after a capped-exponential
/// sleep so a repeatedly-panicking task can't hot-loop.
const SUPERVISE_MIN: Duration = Duration::from_secs(1);
const SUPERVISE_MAX: Duration = Duration::from_secs(60);

/// How often the leader refreshes the `watch_leader` observability heartbeat and
/// the cached lag gauge while the stream is idle (a quiet datastore sends no
/// bytes). Also the follower's lock poll cadence between reconnect attempts.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);

/// Process-start monotonic baseline. The cached last-cursor-advance instant is
/// stored as whole seconds since this baseline in an `AtomicU64` (0 = never
/// advanced), so the staleness fence reads a lock-free atomic instead of a DB
/// query. Monotonic (`Instant`), immune to wall-clock jumps.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Seconds since [`PROCESS_START`], saturating — the unit stored in the cached
/// last-advance gauge.
fn secs_since_start() -> u64 {
    PROCESS_START.elapsed().as_secs()
}

// ---------- status plane ----------

/// Watch health, shared with the admin endpoint. Counters are monotonic;
/// `degraded` latches on a detected gap and is cleared only by restart.
pub(crate) struct WatchStatus {
    enabled: AtomicBool,
    connected: AtomicBool,
    degraded: AtomicBool,
    gaps: AtomicU64,
    reconnects: AtomicU64,
    /// Watch frames (update batches / checkpoints) received.
    events_seen: AtomicU64,
    /// Membership-DELETE deltas fully applied (including no-op dedupes).
    deltas_applied: AtomicU64,
    /// Revocation tombstone rows written by the watch consumer.
    tombstones_written: AtomicU64,
    /// Cached last-cursor-advance time as seconds since [`PROCESS_START`]
    /// (0 = never advanced this process). Updated by the loop when the cursor
    /// moves AND by the leader's idle heartbeat ticker (an idle-but-connected
    /// stream is fresh, not stale). Read lock-free by [`is_stale`] /
    /// [`lag_seconds_cached`] so the recall-side fence needs no DB query.
    last_advance_secs: AtomicU64,
    last_token: Mutex<Option<String>>,
    last_error: Mutex<Option<String>>,
}

impl WatchStatus {
    pub(crate) fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            degraded: AtomicBool::new(false),
            gaps: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            events_seen: AtomicU64::new(0),
            deltas_applied: AtomicU64::new(0),
            tombstones_written: AtomicU64::new(0),
            last_advance_secs: AtomicU64::new(0),
            last_token: Mutex::new(None),
            last_error: Mutex::new(None),
        }
    }

    pub(crate) fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// M0 `/metrics` reads: the enablement/connection/degraded flags as bools
    /// so the freshness alarm can expose `watch_enabled` / `watch_connected` /
    /// `watch_degraded` gauges. A disabled consumer (`enabled_now() == false`)
    /// makes the cursor-lag sentinel meaningful — see metrics.rs.
    pub(crate) fn enabled_now(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub(crate) fn connected_now(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub(crate) fn degraded_now(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Mark the cursor as freshly advanced (or the leader as freshly heartbeat
    /// while idle) — records "now" into the cached last-advance gauge. Called
    /// on every persisted cursor move and on the leader's idle heartbeat tick,
    /// so an idle-but-connected stream reads as fresh, not stale.
    fn mark_advance(&self) {
        // +1 keeps 0 reserved as the "never advanced" sentinel even at t≈0.
        self.last_advance_secs
            .store(secs_since_start().saturating_add(1), Ordering::Relaxed);
    }

    /// Seconds since the cursor last advanced (in-process, monotonic), or `None`
    /// if it has never advanced this process. Lock-free; the LOCAL source for
    /// the recall-side staleness fence — NO DB query, NO live ReBAC.
    pub(crate) fn lag_seconds_cached(&self) -> Option<u64> {
        let stamp = self.last_advance_secs.load(Ordering::Relaxed);
        if stamp == 0 {
            return None; // never advanced this process
        }
        Some(secs_since_start().saturating_add(1).saturating_sub(stamp))
    }

    /// STALENESS-FENCE PRIMITIVE (recall-side). Returns `true` when the recall
    /// path must FAIL CLOSED for tier-≤2 because the materialized revocation set
    /// can no longer be trusted to be fresh. Reads ONLY in-process atomics — no
    /// DB query, no live ReBAC — so it preserves read-path purity and adds zero
    /// per-read latency.
    ///
    /// Fences (over-hides) iff the watch is ENABLED and any of:
    ///   * `degraded` latched (a cursor gap was seen — revocations may be
    ///     missing from the stream);
    ///   * not `connected` (the stream is down right now);
    ///   * the cursor has never advanced this process (no fresh evidence);
    ///   * the cached lag exceeds `bound_secs`.
    ///
    /// When the watch is DISABLED (opt-out), the fence is INERT: the windowed /
    /// durable-tombstone baseline is the guarantee, exactly as the M0
    /// `WatchFreshness` treats `enabled == false`. Fail-closed: every true
    /// branch causes the caller to over-hide, never under-hide.
    ///
    /// Wired into the recall/get staleness fence (`AppState::fence_scope`).
    pub(crate) fn is_stale(&self, bound_secs: u64) -> bool {
        if !self.enabled_now() {
            return false; // opt-out: baseline is the guarantee, fence inert
        }
        if self.degraded_now() || !self.connected_now() {
            return true;
        }
        match self.lag_seconds_cached() {
            None => true, // never advanced → no fresh evidence
            Some(lag) => lag > bound_secs,
        }
    }

    fn set_connected(&self, on: bool) {
        self.connected.store(on, Ordering::Relaxed);
    }

    /// A gap means revocations may have been missed ON THE STREAM; the
    /// windowed baseline still covers them. Latches until restart.
    fn mark_gap(&self, msg: &str) {
        self.degraded.store(true, Ordering::Relaxed);
        self.gaps.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().unwrap() = Some(msg.to_string());
    }

    fn record_error(&self, msg: &str) {
        *self.last_error.lock().unwrap() = Some(msg.to_string());
    }

    fn note_token(&self, token: &str) {
        *self.last_token.lock().unwrap() = Some(token.to_string());
    }

    pub(crate) fn snapshot(&self) -> Value {
        json!({
            "enabled": self.enabled.load(Ordering::Relaxed),
            "connected": self.connected.load(Ordering::Relaxed),
            "degraded": self.degraded.load(Ordering::Relaxed),
            "gaps": self.gaps.load(Ordering::Relaxed),
            "reconnects": self.reconnects.load(Ordering::Relaxed),
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "deltas_applied": self.deltas_applied.load(Ordering::Relaxed),
            "tombstones_written": self.tombstones_written.load(Ordering::Relaxed),
            "cursor_lag_seconds": self.lag_seconds_cached(),
            "last_token": self.last_token.lock().unwrap().clone(),
            "last_error": self.last_error.lock().unwrap().clone(),
        })
    }
}

impl Default for WatchStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// GET /v1/admin/rebac-watch (admin): watch health for operators/alerts.
pub(crate) async fn admin_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> HandlerResult<Json<Value>> {
    state.admin.check(&headers)?;
    Ok(Json(state.watch.snapshot()))
}

// ---------- frame parsing (pure) ----------

/// One `group#member` DELETE recovered from a watch frame.
#[derive(Debug, PartialEq)]
pub(crate) struct MembershipDelete {
    pub(crate) tenant: TenantId,
    /// Group name (tenant prefix stripped, unescaped).
    pub(crate) group: String,
    /// The removed member. None = the subject didn't parse for this tenant
    /// (impossible by Verity's own construction) — the delta is still applied
    /// with a placeholder affected principal: over-hide, never skip a DELETE
    /// whose group resolved.
    pub(crate) member: Option<(PrincipalKind, String)>,
}

#[derive(Debug, PartialEq)]
pub(crate) enum WatchLine {
    /// A frame's deletes (possibly empty — grants and checkpoints) plus the
    /// resume cursor (`changesThrough.token`).
    Updates {
        deletes: Vec<MembershipDelete>,
        token: Option<String>,
    },
    /// In-stream error frame.
    Error(String),
}

/// Parse one NDJSON watch line. Foreign/malformed RESOURCE ids are skipped —
/// a tuple Verity never wrote has no tokens to revoke (same fail-closed
/// posture as `parse_object_id`); operations other than DELETE on
/// `group#member` are ignored (grants stay "next mint").
pub(crate) fn parse_watch_line(line: &str) -> Result<WatchLine, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("bad watch line: {e}"))?;
    if let Some(err) = v.get("error") {
        return Ok(WatchLine::Error(err.to_string()));
    }
    let r = v
        .get("result")
        .ok_or_else(|| format!("no result in watch line: {v}"))?;
    let token = r["changesThrough"]["token"].as_str().map(String::from);
    let mut deletes = Vec::new();
    if let Some(updates) = r["updates"].as_array() {
        for u in updates {
            if u["operation"].as_str() != Some("OPERATION_DELETE") {
                continue;
            }
            let rel = &u["relationship"];
            if rel["resource"]["objectType"].as_str() != Some("group")
                || rel["relation"].as_str() != Some("member")
            {
                continue;
            }
            let Some(roid) = rel["resource"]["objectId"].as_str() else {
                continue;
            };
            let Some((tenant, group)) = parse_any_object_id(roid) else {
                tracing::warn!(oid = roid, "watch: foreign/malformed resource id skipped");
                continue;
            };
            let member = (|| {
                let sobj = &rel["subject"]["object"];
                let kind = match sobj["objectType"].as_str()? {
                    "user" => PrincipalKind::User,
                    "group" => PrincipalKind::Group,
                    _ => return None,
                };
                let (stenant, name) = parse_any_object_id(sobj["objectId"].as_str()?)?;
                // Cross-tenant membership is impossible by construction;
                // treat a mismatch as unresolvable (over-hide path).
                (stenant == tenant).then_some((kind, name))
            })();
            deletes.push(MembershipDelete {
                tenant,
                group,
                member,
            });
        }
    }
    Ok(WatchLine::Updates { deletes, token })
}

/// Does an error message indicate the start cursor is unresumable (SpiceDB
/// rejects cursors older than the datastore GC window with
/// FAILED_PRECONDITION)? Used to classify IN-STREAM error frames as gaps.
pub(crate) fn cursor_rejected(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("failed_precondition") || m.contains("garbage collected")
}

/// Drop tokens that already have a very recent tombstone (see [`DEDUPE_SECS`]).
fn dedupe_lost(
    lost: Vec<(String, PrincipalToken)>,
    recent: &[PrincipalToken],
) -> Vec<(String, PrincipalToken)> {
    lost.into_iter()
        .filter(|(_, t)| !recent.contains(t))
        .collect()
}

// ---------- delta application ----------

/// Materialize one membership DELETE as revocation tombstones — exactly the
/// `admin_group_remove` resolution, computed post-delete: the removed
/// member's own subtree still resolves from the remaining graph, and the
/// group + its transitive ancestors are the principals lost. Returns rows
/// written (0 = nothing materialized / already tombstoned).
async fn apply_delete(
    state: &AppState,
    rebac: &Rebac,
    d: &MembershipDelete,
) -> Result<u64, String> {
    let affected: Vec<String> = match &d.member {
        Some((PrincipalKind::User, name)) => vec![format!("user:{name}")],
        Some((PrincipalKind::Group, name)) => {
            // The removed inner group's user subtree — resolved from the
            // DELETED relationship's subject, which still holds its own
            // members (only the group→member edge is gone).
            let mut users = rebac
                .group_users(d.tenant, name)
                .await
                .map_err(|e| format!("group_users: {e}"))?;
            users.push(format!("group:{name}"));
            users
        }
        // Unresolvable subject: still tombstone the group's tokens
        // tenant-wide (enforcement keys on token; `principal` is audit-only).
        None => vec!["watch:unresolved-member".to_string()],
    };
    let lost_principals = rebac
        .group_and_ancestors(d.tenant, &d.group)
        .await
        .map_err(|e| format!("group_and_ancestors: {e}"))?;
    // Only principals that ever materialized a token can appear in a
    // visibility set or a handle; unmaterialized ones have nothing to revoke.
    let lost_tokens: Vec<(String, PrincipalToken)> = sqlx::query_as(
        "SELECT principal, token FROM principals
         WHERE tenant_id = $1 AND principal = ANY($2)",
    )
    .bind(d.tenant)
    .bind(&lost_principals)
    .fetch_all(state.pool())
    .await
    .map_err(|e| format!("token lookup: {e}"))?;
    if lost_tokens.is_empty() {
        return Ok(0);
    }
    let candidates: Vec<PrincipalToken> = lost_tokens.iter().map(|(_, t)| *t).collect();
    let recent: Vec<PrincipalToken> = sqlx::query_scalar(
        "SELECT DISTINCT token FROM revocations
         WHERE tenant_id = $1 AND token = ANY($2)
           AND at > now() - make_interval(secs => $3)",
    )
    .bind(d.tenant)
    .bind(&candidates)
    .bind(DEDUPE_SECS as f64)
    .fetch_all(state.pool())
    .await
    .map_err(|e| format!("dedupe lookup: {e}"))?;
    let fresh = dedupe_lost(lost_tokens, &recent);
    if fresh.is_empty() {
        return Ok(0);
    }
    state
        .revocations
        .record(state.pool(), d.tenant, &affected, &fresh)
        .await
        .map_err(|(_, msg)| format!("tombstone record: {msg}"))
}

// ---------- the stream loop ----------

enum StreamEnd {
    /// Server closed the stream; reconnect from the persisted cursor.
    Closed,
    /// Transport/processing failure; reconnect from the persisted cursor —
    /// the failed frame's cursor was never persisted, so it replays.
    Failed(String),
    /// The stream itself reported an unresumable cursor: a GAP.
    Gap(String),
}

/// Consume an open watch response until it ends. The cursor is persisted
/// only after ALL of a frame's deltas are durably recorded — never
/// ack-and-drop.
async fn consume_stream(state: &AppState, rebac: &Rebac, resp: reqwest::Response) -> StreamEnd {
    let mut body = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => return StreamEnd::Failed(format!("stream read: {e}")),
        };
        buf.extend_from_slice(&chunk);
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=pos).collect();
            let Ok(line) = std::str::from_utf8(&line) else {
                return StreamEnd::Failed("non-utf8 watch frame".into());
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Err(end) = handle_line(state, rebac, line).await {
                return end;
            }
        }
    }
    StreamEnd::Closed
}

async fn handle_line(state: &AppState, rebac: &Rebac, line: &str) -> Result<(), StreamEnd> {
    let parsed = parse_watch_line(line).map_err(StreamEnd::Failed)?;
    match parsed {
        WatchLine::Error(msg) => {
            if cursor_rejected(&msg) {
                Err(StreamEnd::Gap(msg))
            } else {
                Err(StreamEnd::Failed(msg))
            }
        }
        WatchLine::Updates { deletes, token } => {
            state.watch.events_seen.fetch_add(1, Ordering::Relaxed);
            for d in &deletes {
                match apply_delete(state, rebac, d).await {
                    Ok(written) => {
                        state.watch.deltas_applied.fetch_add(1, Ordering::Relaxed);
                        state
                            .watch
                            .tombstones_written
                            .fetch_add(written, Ordering::Relaxed);
                        if written > 0 {
                            tracing::info!(
                                tenant = %d.tenant,
                                group = %d.group,
                                tombstones = written,
                                "watch: membership DELETE materialized as revocation tombstones"
                            );
                        }
                    }
                    // Do NOT persist the cursor: reconnect replays this frame.
                    Err(e) => return Err(StreamEnd::Failed(format!("delta application: {e}"))),
                }
            }
            if let Some(token) = token {
                if let Err(e) = store_cursor(state.pool(), &token).await {
                    return Err(StreamEnd::Failed(format!("cursor persist: {e}")));
                }
                state.watch.note_token(&token);
                // The materialized set is now provably fresh through this token:
                // refresh the local lag gauge the recall-side fence reads.
                state.watch.mark_advance();
            }
            Ok(())
        }
    }
}

/// SUPERVISED entrypoint — spawn THIS from `main()`, not [`run`] directly.
///
/// [`run`] reconnects forever on transport/stream errors (its inner loop), so
/// the only way it can stop is a PANIC in a frame handler. A fire-and-forget
/// `tokio::spawn(run(..))` would let such a panic silently end materialization
/// with no restart. This supervisor holds the `JoinHandle`, and on a panicked
/// task respawns after capped-exponential backoff so a bug cannot permanently
/// blind the freshness plane. A clean return (only reachable in tests that
/// break out of `run`) is respawned the same way. Never returns.
///
/// Spawned from `main()` (default-ON when ReBAC is configured) in place of the
/// former fire-and-forget `tokio::spawn(run(..))`.
pub(crate) async fn run_supervised(state: Arc<AppState>) {
    let mut backoff = SUPERVISE_MIN;
    loop {
        let handle = tokio::spawn(run(Arc::clone(&state)));
        match handle.await {
            Ok(()) => {
                // `run` returned (only in tests, or a mis-spawn without ReBAC).
                tracing::warn!("spicedb watch loop returned; supervisor respawning");
            }
            Err(join_err) if join_err.is_panic() => {
                let msg = format!("watch task panicked: {join_err}");
                state.watch.record_error(&msg);
                tracing::error!(
                    "{msg} — supervisor respawning after {:?}; windowed baseline still enforced",
                    backoff
                );
            }
            Err(join_err) => {
                // Cancelled (e.g. runtime shutdown): stop supervising.
                tracing::info!("spicedb watch task ended ({join_err}); supervisor exiting");
                return;
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(SUPERVISE_MAX);
    }
}

/// The background loop, spawned (via [`run_supervised`]) when ReBAC is
/// configured and the watch is not opted out. Reconnects forever with capped
/// backoff; degraded states are loud (log + status), never silent, and the
/// windowed baseline keeps enforcing regardless.
///
/// LEADER-ELECTED: each iteration first tries to acquire the watch-cursor
/// advisory lock ([`WatchLeadership`]). Only the leader connects the stream and
/// advances the cursor; a follower stays idle and poll-retries the lock so it
/// takes over automatically when the leader dies. This makes the single-row
/// cursor safe on >1 replica.
pub(crate) async fn run(state: Arc<AppState>) {
    let Some(rebac) = state.rebac.as_ref() else {
        tracing::error!("watch loop spawned without ReBAC configured; exiting");
        return;
    };
    let holder = format!("{}#{}", state.listen, std::process::id());
    let mut backoff = RECONNECT_MIN;
    loop {
        // --- leader election: acquire (or re-poll) the cursor advisory lock ---
        let mut leadership = match WatchLeadership::try_acquire(state.pool()).await {
            Ok(Some(guard)) => guard,
            Ok(None) => {
                // Another replica leads. Stay idle — a follower must NOT consume
                // the stream or advance the cursor (that is the go-blind hazard).
                // BUT the follower's LOCAL freshness signal must reflect the
                // SHARED durable state, not this idle process's (never-connected)
                // stream: the leader writes revocation tombstones to the shared
                // `revocations` table that `retained_tombstones` reads, so a
                // follower whose leader is heartbeating recently is materially
                // fresh. Mirror the leader heartbeat into this process's status so
                // the recall-side staleness fence does NOT fire a false-positive
                // read outage (or a per-read live-ReBAC re-resolution) on every
                // follower. If the leader heartbeat is stale/missing, leave the
                // signal untouched so the fence trips (fail closed) as it should.
                mark_follower_freshness(&state).await;
                // Poll-retry on the heartbeat cadence; take over if the leader dies.
                tokio::time::sleep(HEARTBEAT_EVERY).await;
                continue;
            }
            Err(e) => {
                state.watch.record_error(&format!("leader lock: {e}"));
                tracing::warn!("watch: leader-lock acquire failed, retrying: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_MAX);
                continue;
            }
        };
        let _ = leadership.heartbeat(&holder).await;

        let cursor = match load_cursor(state.pool()).await {
            Ok(c) => c,
            Err(e) => {
                state.watch.record_error(&format!("cursor load: {e}"));
                tracing::warn!("watch: cursor load failed, retrying: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_MAX);
                continue;
            }
        };
        // NOTE (verified live): an idle watch sends no bytes — not even
        // response headers — until the first event, so this await may pend
        // for a long time on a quiet datastore. That is the correct posture,
        // not a hang: the watch anchors its start revision at RPC receipt
        // (a write made just before connecting is still delivered), so
        // nothing is missed while pending, and dropping/re-opening WOULD
        // risk missing an event between streams. `connected` therefore only
        // flips true once the first frame arrives.
        match rebac.watch_connect(cursor.as_deref()).await {
            Ok(resp) => {
                state.watch.set_connected(true);
                // Connected-and-leading: the materialized set is trustworthy as
                // of now, so seed the local lag gauge (an idle stream that never
                // advances the cursor would otherwise read as "never advanced").
                state.watch.mark_advance();
                backoff = RECONNECT_MIN;
                tracing::info!(
                    resumed = cursor.is_some(),
                    "spicedb watch connected (leader)"
                );
                let end =
                    consume_while_leading(&state, rebac, &mut leadership, &holder, resp).await;
                state.watch.set_connected(false);
                match end {
                    StreamEnd::Closed => {
                        tracing::warn!("spicedb watch stream closed by server; reconnecting")
                    }
                    StreamEnd::Failed(e) => {
                        state.watch.record_error(&e);
                        tracing::warn!(
                            "spicedb watch stream failed (will replay from cursor): {e}"
                        );
                    }
                    StreamEnd::Gap(e) => {
                        state.watch.mark_gap(&e);
                        let _ = clear_cursor(state.pool()).await;
                        tracing::error!(
                            "spicedb watch GAP (in-stream cursor rejection) — degraded latched; \
                             windowed baseline still enforced: {e}"
                        );
                    }
                }
            }
            // The server refused our cursor (FAILED_PRECONDITION: revision
            // older than the datastore GC window): a GAP, not a fresh start.
            Err(RebacError::Api { status, body }) if cursor.is_some() => {
                state.watch.mark_gap(&format!("{status}: {body}"));
                let _ = clear_cursor(state.pool()).await;
                tracing::error!(
                    "spicedb watch cursor unresumable ({status}) — GAP, degraded latched, \
                     resuming from head; windowed baseline still enforced: {body}"
                );
            }
            Err(e) => {
                state.watch.record_error(&e.to_string());
                tracing::warn!("spicedb watch connect failed: {e}");
            }
        }
        // Relinquish leadership between attempts so a healthier replica can take
        // over if this one is flapping; it re-acquires at the top of the next
        // loop. `release()` runs an explicit pg_advisory_unlock (prompt takeover)
        // and, via the armed close_on_drop, guarantees the lock is not leaked
        // back into the pool — the bug where the sole consumer would demote
        // itself to a permanent follower after the first reconnect.
        leadership.release().await;
        state.watch.reconnects.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

/// Consume the stream while keeping the leader heartbeat + cached lag gauge
/// ticking. An idle (quiet-datastore) stream sends no bytes for a long time; a
/// bare `consume_stream` await would let the `watch_leader` heartbeat and the
/// local lag gauge go stale even though the leader is perfectly healthy. This
/// selects the stream against a heartbeat ticker so idle-but-connected reads as
/// FRESH, not stale.
async fn consume_while_leading(
    state: &AppState,
    rebac: &Rebac,
    leadership: &mut WatchLeadership,
    holder: &str,
    resp: reqwest::Response,
) -> StreamEnd {
    let mut stream = std::pin::pin!(consume_stream(state, rebac, resp));
    let mut ticker = tokio::time::interval(HEARTBEAT_EVERY);
    ticker.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            end = &mut stream => return end,
            _ = ticker.tick() => {
                // Leader is alive and connected: refresh the observability
                // heartbeat and the local lag gauge so the recall-side fence
                // does not falsely flag a healthy idle stream as stale.
                //
                // The heartbeat runs on the SAME connection that holds the
                // leadership advisory lock. If it ERRORS, that connection is
                // almost certainly dead (network/pgbouncer drop) — which means
                // the session lock has ALREADY auto-released and a follower may
                // have taken over. Continuing to consume would make this a
                // "zombie leader" racing the new leader on the single cursor. So
                // treat a heartbeat error as loss of leadership: stop consuming
                // and let `run` relinquish + re-elect (fail closed on the lock).
                if let Err(e) = leadership.heartbeat(holder).await {
                    return StreamEnd::Failed(format!(
                        "leadership heartbeat failed (lock connection likely lost); \
                         relinquishing to avoid a zombie-leader cursor race: {e}"
                    ));
                }
                state.watch.mark_advance();
            }
        }
    }
}

/// How stale the leader's `watch_leader.heartbeat_at` may be before a follower
/// STOPS trusting the shared materialized set. The leader heartbeats every
/// `HEARTBEAT_EVERY` (5s); allow a few missed beats for jitter/GC pauses before
/// the follower's fence trips (fail closed). Kept well under the recall-side
/// `watch_staleness_fence_secs` bound so a genuinely dead leader still fences.
const FOLLOWER_LEADER_FRESH_SECS: i64 = 3 * HEARTBEAT_EVERY.as_secs() as i64;

/// Follower-side freshness: if a leader's heartbeat is recent, the shared
/// materialized revocation set this process reads is fresh, so mark THIS
/// process's local watch status connected+advanced — otherwise the recall-side
/// fence (which keys off per-process stream activity) would fire a false-
/// positive outage on every follower replica. Best-effort and fail-closed: on a
/// stale/missing heartbeat or a query error we leave the local signal untouched,
/// so `is_stale` keeps returning true (over-hide) until a healthy leader is seen.
async fn mark_follower_freshness(state: &AppState) {
    follower_freshness_from_leader(state.pool(), &state.watch).await;
}

/// Pool-backed core of [`mark_follower_freshness`], split out so it is testable
/// without a full `AppState`. Reads the leader heartbeat and, if fresh, marks the
/// given status connected+advanced; otherwise leaves it untouched (fail closed).
async fn follower_freshness_from_leader(pool: &PgPool, status: &WatchStatus) {
    let fresh: Result<Option<bool>, sqlx::Error> = sqlx::query_scalar(
        "SELECT heartbeat_at > now() - make_interval(secs => $1)
         FROM watch_leader WHERE id = 1",
    )
    .bind(FOLLOWER_LEADER_FRESH_SECS as f64)
    .fetch_optional(pool)
    .await;
    if let Ok(Some(true)) = fresh {
        // A healthy leader is advancing the shared cursor; the shared tombstone
        // set is fresh. Reflect that locally so the fence does not fire.
        status.set_connected(true);
        status.mark_advance();
    }
    // else: no fresh leader → leave the local signal stale so the fence trips.
}

// ---------- durable cursor ----------

async fn load_cursor(pool: &PgPool) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT token FROM rebac_watch_cursor WHERE id = 1")
        .fetch_optional(pool)
        .await
}

async fn store_cursor(pool: &PgPool, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO rebac_watch_cursor (id, token) VALUES (1, $1)
         ON CONFLICT (id) DO UPDATE SET token = EXCLUDED.token, updated_at = now()",
    )
    .bind(token)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn clear_cursor(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM rebac_watch_cursor WHERE id = 1")
        .execute(pool)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rebac::escape_id;

    fn oid(tenant: TenantId, name: &str) -> String {
        format!("{tenant}_{}", escape_id(name))
    }

    fn delete_line(resource: &str, subject_type: &str, subject: &str, token: &str) -> String {
        format!(
            r#"{{"result":{{"updates":[{{"operation":"OPERATION_DELETE","relationship":{{"resource":{{"objectType":"group","objectId":"{resource}"}},"relation":"member","subject":{{"object":{{"objectType":"{subject_type}","objectId":"{subject}"}}}}}}}}],"changesThrough":{{"token":"{token}"}},"isCheckpoint":false}}}}"#
        )
    }

    #[test]
    fn watch_line_parses_deletes_and_checkpoints() {
        let t = uuid::Uuid::now_v7();
        // User-member delete.
        let line = delete_line(
            &oid(t, "sales"),
            "user",
            &oid(t, "alice@corp.example"),
            "tok1",
        );
        assert_eq!(
            parse_watch_line(&line).unwrap(),
            WatchLine::Updates {
                deletes: vec![MembershipDelete {
                    tenant: t,
                    group: "sales".into(),
                    member: Some((PrincipalKind::User, "alice@corp.example".into())),
                }],
                token: Some("tok1".into()),
            }
        );
        // Nested-group-member delete.
        let line = delete_line(&oid(t, "sales"), "group", &oid(t, "sales-west"), "tok2");
        assert_eq!(
            parse_watch_line(&line).unwrap(),
            WatchLine::Updates {
                deletes: vec![MembershipDelete {
                    tenant: t,
                    group: "sales".into(),
                    member: Some((PrincipalKind::Group, "sales-west".into())),
                }],
                token: Some("tok2".into()),
            }
        );
        // Checkpoint frame: no updates, cursor still advances.
        let line =
            r#"{"result":{"updates":[],"changesThrough":{"token":"tok3"},"isCheckpoint":true}}"#;
        assert_eq!(
            parse_watch_line(line).unwrap(),
            WatchLine::Updates {
                deletes: vec![],
                token: Some("tok3".into()),
            }
        );
        // Grants (TOUCH) are ignored — grant freshness stays "next mint".
        let line = format!(
            r#"{{"result":{{"updates":[{{"operation":"OPERATION_TOUCH","relationship":{{"resource":{{"objectType":"group","objectId":"{}"}},"relation":"member","subject":{{"object":{{"objectType":"user","objectId":"{}"}}}}}}}}],"changesThrough":{{"token":"tok4"}}}}}}"#,
            oid(t, "sales"),
            oid(t, "bob@corp.example"),
        );
        assert_eq!(
            parse_watch_line(&line).unwrap(),
            WatchLine::Updates {
                deletes: vec![],
                token: Some("tok4".into()),
            }
        );
    }

    #[test]
    fn watch_line_fails_closed_on_foreign_and_malformed_ids() {
        let t = uuid::Uuid::now_v7();
        let other = uuid::Uuid::now_v7();
        // Foreign (un-prefixed) RESOURCE id: skipped entirely — Verity never
        // wrote that tuple, so there are no tokens to revoke.
        let line = delete_line("watchprobe_g", "user", "watchprobe_u", "tok1");
        assert_eq!(
            parse_watch_line(&line).unwrap(),
            WatchLine::Updates {
                deletes: vec![],
                token: Some("tok1".into()),
            }
        );
        // Unparseable SUBJECT for a parseable resource: the delta survives
        // with member=None — over-hide, never skip the DELETE.
        let line = delete_line(&oid(t, "sales"), "user", "not-a-verity-id", "tok2");
        assert_eq!(
            parse_watch_line(&line).unwrap(),
            WatchLine::Updates {
                deletes: vec![MembershipDelete {
                    tenant: t,
                    group: "sales".into(),
                    member: None,
                }],
                token: Some("tok2".into()),
            }
        );
        // Cross-tenant subject (impossible by construction): same over-hide.
        let line = delete_line(&oid(t, "sales"), "user", &oid(other, "eve@corp"), "tok3");
        match parse_watch_line(&line).unwrap() {
            WatchLine::Updates { deletes, .. } => {
                assert_eq!(deletes.len(), 1);
                assert_eq!(deletes[0].member, None);
            }
            other => panic!("expected updates, got {other:?}"),
        }
        // Malformed JSON is an error (stream ends, frame replays).
        assert!(parse_watch_line("not json").is_err());
        // Frame with neither result nor error is an error.
        assert!(parse_watch_line(r#"{"unexpected":1}"#).is_err());
    }

    #[test]
    fn watch_line_error_frames_classify_as_gap_or_failure() {
        let line = r#"{"error":{"code":9,"message":"FAILED_PRECONDITION: requested start revision has been garbage collected"}}"#;
        match parse_watch_line(line).unwrap() {
            WatchLine::Error(msg) => assert!(cursor_rejected(&msg), "gap-classified: {msg}"),
            other => panic!("expected error frame, got {other:?}"),
        }
        let line = r#"{"error":{"code":13,"message":"internal hiccup"}}"#;
        match parse_watch_line(line).unwrap() {
            WatchLine::Error(msg) => assert!(!cursor_rejected(&msg), "not a gap: {msg}"),
            other => panic!("expected error frame, got {other:?}"),
        }
    }

    #[test]
    fn gap_marks_degraded_and_latches() {
        let ws = WatchStatus::new();
        assert!(!ws.snapshot()["degraded"].as_bool().unwrap());
        ws.mark_gap("FAILED_PRECONDITION: revision gc'd");
        let s = ws.snapshot();
        assert!(s["degraded"].as_bool().unwrap());
        assert_eq!(s["gaps"], 1);
        assert!(s["last_error"].as_str().unwrap().contains("gc'd"));
        // A later successful reconnect does NOT clear the latch: missed
        // revocations stay covered only by the windowed baseline until an
        // operator reconciles (restart clears).
        ws.set_connected(true);
        let s = ws.snapshot();
        assert!(s["connected"].as_bool().unwrap());
        assert!(s["degraded"].as_bool().unwrap(), "degraded latches");
    }

    #[test]
    fn fence_primitive_fails_closed_on_unhealthy_watch() {
        // Disabled watch: fence is INERT (baseline is the guarantee).
        let ws = WatchStatus::new();
        assert!(!ws.is_stale(900), "disabled watch must not fence");

        // Enabled but never advanced (no fresh evidence) → stale.
        ws.set_enabled(true);
        assert!(ws.lag_seconds_cached().is_none(), "no advance recorded yet");
        assert!(
            ws.is_stale(900),
            "enabled + never-advanced must fence (no fresh evidence)"
        );

        // Fresh advance + connected → NOT stale under a generous bound.
        ws.set_connected(true);
        ws.mark_advance();
        assert_eq!(ws.lag_seconds_cached(), Some(0), "just advanced → ~0s lag");
        assert!(!ws.is_stale(900), "fresh + connected must not fence");

        // A zero bound makes even a 0s lag NOT exceed it (0 > 0 is false), so
        // freshness still holds; disconnect is the decisive fence.
        ws.set_connected(false);
        assert!(
            ws.is_stale(900),
            "disconnected stream must fence regardless of lag"
        );
        ws.set_connected(true);

        // Degraded (a gap latched) → always fence, even freshly advanced.
        ws.mark_advance();
        ws.mark_gap("simulated gap");
        assert!(ws.is_stale(u64::MAX), "degraded latch must fence");
    }

    /// DSN-gated: a FOLLOWER whose own stream never connected must NOT fence
    /// while a healthy leader is heartbeating the shared cursor — the shared
    /// materialized tombstone set is fresh, so the follower reads it safely. A
    /// STALE/absent leader heartbeat leaves the follower fenced (fail closed).
    /// This is the multi-replica false-positive the leader election must not
    /// introduce.
    #[tokio::test]
    async fn follower_does_not_fence_while_leader_heartbeat_is_fresh() {
        let Ok(dsn) = std::env::var("VERITY_TEST_DSN") else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return;
        };
        let pool = PgPool::connect(&dsn).await.expect("connect");
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS watch_leader (
                 id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
                 holder text,
                 heartbeat_at timestamptz NOT NULL DEFAULT now())",
        )
        .execute(&pool)
        .await
        .expect("ensure table");
        sqlx::query(
            "INSERT INTO watch_leader (id, holder) VALUES (1, 'leader') ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("seed row");

        // Follower: enabled, own stream NEVER connected/advanced → would fence.
        let follower = WatchStatus::new();
        follower.set_enabled(true);
        assert!(
            follower.is_stale(900),
            "a follower with no local stream activity fences before consulting the leader"
        );

        // Fresh leader heartbeat → follower must observe shared freshness.
        sqlx::query("UPDATE watch_leader SET heartbeat_at = now() WHERE id = 1")
            .execute(&pool)
            .await
            .expect("fresh heartbeat");
        follower_freshness_from_leader(&pool, &follower).await;
        assert!(
            !follower.is_stale(900),
            "follower must NOT fence while a healthy leader heartbeats the shared cursor"
        );

        // Stale leader heartbeat (older than the freshness bound) → fail closed.
        let stale = WatchStatus::new();
        stale.set_enabled(true);
        sqlx::query(
            "UPDATE watch_leader SET heartbeat_at = now() - make_interval(secs => $1) WHERE id = 1",
        )
        .bind((FOLLOWER_LEADER_FRESH_SECS + 60) as f64)
        .execute(&pool)
        .await
        .expect("stale heartbeat");
        follower_freshness_from_leader(&pool, &stale).await;
        assert!(
            stale.is_stale(900),
            "a follower with a STALE leader heartbeat must fence (fail closed)"
        );
    }

    #[test]
    fn lag_gauge_reserves_zero_as_never_advanced_sentinel() {
        // The stored stamp uses +1 so the "never advanced" sentinel (0) is
        // distinct from an advance at t≈0. lag_seconds_cached must therefore
        // report Some(0), not None, immediately after the first advance.
        let ws = WatchStatus::new();
        assert_eq!(ws.lag_seconds_cached(), None);
        ws.mark_advance();
        assert_eq!(ws.lag_seconds_cached(), Some(0));
    }

    #[tokio::test]
    async fn supervisor_respawns_after_a_panic() {
        // A supervised task that panics on its first run and succeeds on the
        // second: the supervisor must catch the panic and respawn, so the
        // second run executes. Mirrors run_supervised's spawn/await/backoff
        // shape without needing SpiceDB.
        use std::sync::atomic::{AtomicU64, Ordering};
        let runs = Arc::new(AtomicU64::new(0));
        let runs2 = Arc::clone(&runs);
        let body = move || {
            let runs = Arc::clone(&runs2);
            async move {
                let n = runs.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    panic!("simulated watch-task panic");
                }
                // Second run: succeed and return.
            }
        };
        // Inline supervisor loop identical in shape to run_supervised: spawn,
        // await, on panic respawn (bounded to 2 attempts here so the test ends).
        let mut backoff = Duration::from_millis(1);
        for _ in 0..3 {
            let handle = tokio::spawn(body());
            match handle.await {
                Ok(()) => break, // clean run reached (the respawned one)
                Err(e) if e.is_panic() => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            2,
            "supervisor must respawn after the panic (1 panicked run + 1 clean run)"
        );
    }

    #[test]
    fn dedupe_drops_only_recently_tombstoned_tokens() {
        let lost = vec![("group:sales".to_string(), 7), ("group:all".to_string(), 9)];
        assert_eq!(
            dedupe_lost(lost.clone(), &[7]),
            vec![("group:all".to_string(), 9)]
        );
        assert_eq!(dedupe_lost(lost.clone(), &[]), lost);
        assert!(dedupe_lost(lost, &[7, 9]).is_empty());
    }

    // ---------- live integration (gated on SpiceDB + DSN, skips otherwise) ----------

    async fn watch_test_state() -> Option<(Arc<AppState>, TenantId)> {
        let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
        let rebac = Rebac::from_env()?;
        if rebac.ensure_schema().await.is_err() {
            eprintln!("spicedb unreachable; skipping");
            return None;
        }
        // ISOLATED DATABASE, not the shared dev db: the watch cursor
        // (rebac_watch_cursor) is a single row per database, owned by exactly
        // ONE consumer. A dev server with VERITY_SPICEDB_WATCH=1 running
        // against the shared db (the default since dev wires every plane)
        // advances that cursor continuously, so a second in-test consumer
        // resumes past its own events and the assertion times out — found
        // 2026-07-12 the first night dev ran fully wired. One consumer per
        // database is the design invariant (see the module docs); tests
        // honor it by owning a scratch db.
        let scratch = {
            let base = sqlx::PgPool::connect(&dsn).await.expect("connect base");
            sqlx::query("DROP DATABASE IF EXISTS verity_watch_unit WITH (FORCE)")
                .execute(&base)
                .await
                .expect("drop scratch");
            sqlx::query("CREATE DATABASE verity_watch_unit")
                .execute(&base)
                .await
                .expect("create scratch");
            // No url-crate dep: swap the database segment by string surgery
            // (the DSN's last path segment is the database name).
            let cut = dsn.rfind('/').expect("dsn has a path");
            format!("{}/verity_watch_unit", &dsn[..cut])
        };
        let pg = verity_storage::PostgresAdapter::connect(&scratch)
            .await
            .expect("connect");
        pg.migrate().await.expect("migrate");
        use verity_core::adapter::StorageAdapter;
        let tenant = pg
            .create_tenant(&format!("watch-test-{}", uuid::Uuid::now_v7()))
            .await
            .expect("tenant");
        let state = Arc::new(AppState {
            storage: verity_storage::CachedAdapter::new(pg, 10_000),
            encoder: None,
            minter: crate::scope::ScopeMinter::ephemeral(),
            purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
            admin: crate::AdminAuth {
                key: [0u8; 32],
                expected_tag: None,
                allowed_origin: None,
            },
            rebac: Some(rebac),
            revocations: crate::revocation::RevocationPlane::new(300),
            allow_restricted_without_rebac: false,
            subscribers: crate::subscribe::Subscribers::new(16),
            auto_tag: false,
            knowledge_auto_merge: true,
            media_store: None,
            resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
            watch: Arc::new(WatchStatus::new()),
            watch_staleness_fence_secs: 900,
            folder_watchers: Arc::new(crate::folder_watch::WatcherRegistry::new()),
            folder_scans: Arc::new(crate::folder_watch::FolderScanPlane::new()),
            knowledge_worker: Arc::new(tokio::sync::Mutex::new(None)),
            directory: crate::directory_worker::DirectoryPlane::disabled(),
            connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
            sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
            repo_root: None,
            listen: "127.0.0.1:0".to_string(),
            admin_token: None,
            metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
        });
        Some((state, tenant))
    }

    /// SpiceDB+DSN-gated: a membership DELETE performed DIRECTLY against
    /// SpiceDB (no admin handler, no tombstone) must be materialized by the
    /// watch consumer as a revocation tombstone that the read-path
    /// subtraction picks up — WITHOUT the revocation window elapsing and
    /// without a re-mint.
    #[tokio::test]
    async fn watch_materializes_out_of_band_membership_delete() {
        let Some((state, tenant)) = watch_test_state().await else {
            eprintln!("VERITY_TEST_DSN / VERITY_SPICEDB_URL not set; skipping");
            return;
        };
        let rebac = state.rebac.as_ref().unwrap();
        let group = "watchers";
        let member = "wally@corp.example";
        rebac
            .write_membership(tenant, group, PrincipalKind::User, member)
            .await
            .expect("add member");
        let mappings = crate::upsert_principal_tokens(
            state.pool(),
            tenant,
            &[format!("group:{group}"), format!("user:{member}")],
        )
        .await
        .expect("tokens");
        let group_token = mappings
            .iter()
            .find(|(p, _)| p == &format!("group:{group}"))
            .expect("group token")
            .1;
        // Baseline: no tombstone, the token survives subtraction.
        // (B1 renamed the resolution-time subtraction to `subtract_window`; the
        // handle-relative `subtract` now takes an `issued_at`. This test asserts
        // "is this token currently revoked in-window", which is exactly the
        // window semantics.)
        assert_eq!(
            state
                .revocations
                .subtract_window(state.pool(), tenant, &[group_token])
                .await
                .unwrap(),
            vec![group_token]
        );

        // Open the watch BEFORE the delete so the event is on-stream. This
        // await returns promptly (rather than pending idle) because the
        // write_membership just above advanced the head revision — a fresh
        // watch replays recent events, flushing headers immediately.
        let resp = rebac.watch_connect(None).await.expect("watch connect");
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Out-of-band delete: straight to SpiceDB — the admin plane (and its
        // tombstone write) never runs.
        rebac
            .delete_membership(tenant, group, PrincipalKind::User, member)
            .await
            .expect("out-of-band delete");

        // Drive the consumer on that stream.
        let consumer_state = Arc::clone(&state);
        let consumer = tokio::spawn(async move {
            let rebac = consumer_state.rebac.as_ref().unwrap();
            let _ = consume_stream(&consumer_state, rebac, resp).await;
        });

        // The removal must bite on the read path well before the 300s window
        // machinery would matter and without any re-mint.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut revoked = false;
        while std::time::Instant::now() < deadline {
            let left = state
                .revocations
                .subtract_window(state.pool(), tenant, &[group_token])
                .await
                .unwrap();
            if left.is_empty() {
                revoked = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        consumer.abort();
        assert!(
            revoked,
            "watch consumer must tombstone an out-of-band membership delete"
        );
        let snap = state.watch.snapshot();
        assert!(snap["deltas_applied"].as_u64().unwrap() >= 1);
        assert!(snap["tombstones_written"].as_u64().unwrap() >= 1);
    }
}
