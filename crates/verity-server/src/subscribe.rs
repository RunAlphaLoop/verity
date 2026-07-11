//! Live memory subscriptions (roadmap task 21): `GET /v1/subscribe` streams
//! newly indexed chunks and recorded actions for a set of watched entities as
//! Server-Sent Events.
//!
//! Delivery is poll-based, deliberately: every second the stream re-runs the
//! same mandatory scope pre-filters the read verbs use (visibility ∩
//! principals minus in-window revocations, confidentiality ceiling, tenant,
//! `valid_to IS NULL`) against rows recorded since the connection's
//! high-water marks. There is no push path that could bypass the enforcement
//! layer — a subscriber sees an item only at the moment a `recall`/`activity`
//! call under the same handle would. Facts are skipped in v0: L1 rows carry
//! no entity-tag linkage to watch on.
//!
//! Fail-closed properties:
//! - entity-bound scopes may only watch entities they cover; a violation
//!   emits one SSE `error` event and closes (never a silent partial stream);
//! - an emptied principal set (revocation window) emits nothing but keeps
//!   polling — tokens may return when the window lapses;
//! - a mid-stream query error emits an `error` event and closes rather than
//!   guessing;
//! - the stream closes when the scope handle expires.
//!
//! High-water marks key on `recorded_at` (ingestion time, monotonic-ish per
//! connection): each poll fetches rows strictly newer than the last one seen.
//! A row committing with a `recorded_at` equal to an already-consumed mark
//! can be skipped — the v0 contract is at-most-once per row, freshness bound
//! by the poll interval.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::postgres::PgRow;
use sqlx::Row;
use uuid::Uuid;

use verity_core::types::{AclProvenance, ActionOutcome, ActionRecord, RecallHit, Scope, TrustTier};

use crate::{internal, AppState, HandlerResult};

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Per-poll fetch bound; a burst larger than this drains over later polls
/// (the high-water mark only advances past what was actually emitted).
const POLL_LIMIT: i64 = 256;
pub(crate) const DEFAULT_MAX_CONNECTIONS: usize = 64;

// ---------- connection cap ----------

/// Server-wide live-connection gauge. Beyond `max`, subscribe returns 429 —
/// a bounded poller fleet, not an unbounded one, is what keeps the 1s poll
/// cost honest.
#[derive(Clone)]
pub(crate) struct Subscribers(Arc<SubscribersInner>);

struct SubscribersInner {
    active: AtomicUsize,
    max: usize,
}

impl Subscribers {
    pub(crate) fn new(max: usize) -> Self {
        Self(Arc::new(SubscribersInner {
            active: AtomicUsize::new(0),
            max,
        }))
    }

    /// `VERITY_SSE_MAX_CONNS`, default 64.
    pub(crate) fn from_env() -> Self {
        let max = std::env::var("VERITY_SSE_MAX_CONNS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_CONNECTIONS);
        Self::new(max)
    }

    fn try_acquire(&self) -> Option<ConnectionGuard> {
        // Optimistic increment; back out on overflow. Marginal overshoot
        // between the add and the check is bounded by racing acquirers.
        if self.0.active.fetch_add(1, Ordering::SeqCst) >= self.0.max {
            self.0.active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ConnectionGuard(Arc::clone(&self.0)))
    }
}

/// Owned by the event stream; dropping it (client disconnect, close, panic)
/// releases the slot.
struct ConnectionGuard(Arc<SubscribersInner>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

// ---------- handler ----------

#[derive(Deserialize)]
pub(crate) struct SubscribeParams {
    scope_handle: String,
    /// Comma-separated entity tags to watch. Optional for entity-bound scopes
    /// (defaults to the scope's own entity set); required otherwise.
    #[serde(default)]
    entities: Option<String>,
}

/// GET /v1/subscribe: SSE stream of new chunks/actions touching the watched
/// entities, under the verified handle's scope. Events are
/// `{"type":"chunk"|"action","data":<same JSON as recall/activity items>}`;
/// heartbeat comments flow every 15s while idle.
pub(crate) async fn subscribe(
    State(state): State<Arc<AppState>>,
    Query(p): Query<SubscribeParams>,
) -> HandlerResult<Response> {
    let payload = state.verify_scope(&p.scope_handle)?;
    let watched: Vec<String> = p
        .entities
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect();

    // Entity resolution, same subset semantics as the write verbs (SPEC §7c):
    // bound scopes inherit their entity set when none is given and may never
    // watch beyond it; unbound scopes must say what they watch.
    let watched = if payload.entity_scope.is_empty() {
        if watched.is_empty() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "subscribe requires ?entities=a,b (unbound scopes watch nothing by default)".into(),
            ));
        }
        watched
    } else if watched.is_empty() {
        payload.entity_scope.clone()
    } else if watched.iter().all(|e| payload.entity_scope.contains(e)) {
        watched
    } else {
        // Fail closed as a stream, per the SSE contract: one error event,
        // then EOF — a subscriber never gets a silently narrowed watch set.
        return Ok(error_stream("entities outside the scope's entity_scope").into_response());
    };

    let Some(guard) = state.subscribers.try_acquire() else {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "subscription connection limit reached".into(),
        ));
    };

    // High-water marks start at the DATABASE clock, not the app clock —
    // recorded_at comparisons must live in one time domain.
    let connected_at: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(state.pool())
        .await
        .map_err(internal)?;

    let stream = async_stream::stream! {
        // Owned by the stream so disconnects release the slot.
        let _guard = guard;
        let mut chunk_hwm = connected_at;
        let mut action_hwm = connected_at;
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if Utc::now() >= payload.expires_at {
                yield Ok::<Event, Infallible>(error_event("scope handle expired"));
                break;
            }
            // Re-derive the enforcement scope every poll so in-window
            // revocations bite mid-stream, exactly as they do on recall.
            let scope = match state.scope_for(&payload).await {
                Ok(s) => s,
                Err((_, msg)) => {
                    yield Ok(error_event(&msg));
                    break;
                }
            };
            // Empty principal set emits nothing (fail closed) but keeps
            // polling: a revocation window lapsing can restore tokens.
            if scope.principals.is_empty() {
                continue;
            }
            match poll_chunks(state.pool(), &scope, &watched, chunk_hwm).await {
                Ok(rows) => {
                    for (hit, recorded_at) in rows {
                        chunk_hwm = chunk_hwm.max(recorded_at);
                        yield Ok(item_event("chunk", &hit));
                    }
                }
                Err((_, msg)) => {
                    yield Ok(error_event(&msg));
                    break;
                }
            }
            match poll_actions(state.pool(), &scope, &watched, action_hwm).await {
                Ok(rows) => {
                    for (action, recorded_at) in rows {
                        action_hwm = action_hwm.max(recorded_at);
                        yield Ok(item_event("action", &action));
                    }
                }
                Err((_, msg)) => {
                    yield Ok(error_event(&msg));
                    break;
                }
            }
        }
    };
    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(HEARTBEAT_INTERVAL))
        .into_response())
}

/// `{"type":"chunk"|"action","data":<item>}` with a matching SSE event name.
fn item_event<T: serde::Serialize>(kind: &str, item: &T) -> Event {
    Event::default()
        .event(kind)
        .json_data(serde_json::json!({ "type": kind, "data": item }))
        .expect("item serializes")
}

fn error_event(msg: &str) -> Event {
    Event::default()
        .event("error")
        .json_data(serde_json::json!({ "type": "error", "error": msg }))
        .expect("error serializes")
}

/// A stream that emits one error event and closes: the fail-closed SSE
/// response for requests that authenticated but violated the watch contract.
fn error_stream(
    msg: &str,
) -> Sse<futures_util::stream::BoxStream<'static, Result<Event, Infallible>>> {
    let event = error_event(msg);
    Sse::new(Box::pin(futures_util::stream::once(
        async move { Ok(event) },
    )))
}

// ---------- polling queries ----------

/// New current chunks touching the watched entities, under the full scope
/// pre-filter. Entity semantics match `latest_chunks`: a chunk qualifies via
/// its tags (`&&` against the watch set); entity-free rows — including
/// `kind='knowledge'` carve-out chunks — never match an entity watch.
async fn poll_chunks(
    pool: &sqlx::PgPool,
    scope: &Scope,
    watched: &[String],
    since: DateTime<Utc>,
) -> HandlerResult<Vec<(RecallHit, DateTime<Utc>)>> {
    let rows = sqlx::query(
        "SELECT id, document_id, seq, content, entity_tags, kind, support_tier, acl_provenance, trust_tier,
                valid_from, provenance, recorded_at
         FROM chunks
         WHERE tenant_id = $1
           AND recorded_at > $2
           AND valid_to IS NULL
           AND entity_tags && $3
           AND visibility && $4
           AND confidentiality <= $5
         ORDER BY recorded_at ASC
         LIMIT $6",
    )
    .bind(scope.tenant_id)
    .bind(since)
    .bind(watched)
    .bind(&scope.principals)
    .bind(scope.max_confidentiality as i16)
    .bind(POLL_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    rows.iter()
        .map(|row| {
            Ok((
                row_to_hit(row)?,
                row.try_get("recorded_at").map_err(internal)?,
            ))
        })
        .collect()
}

/// New actions touching the watched entities, same scope predicates as
/// `activity` (visibility ∩ principals, confidentiality ceiling).
async fn poll_actions(
    pool: &sqlx::PgPool,
    scope: &Scope,
    watched: &[String],
    since: DateTime<Utc>,
) -> HandlerResult<Vec<(ActionRecord, DateTime<Utc>)>> {
    let rows = sqlx::query(
        "SELECT id, action_id, actor_sub, actor_azp, action_type, entities, summary, payload,
                outcome, occurred_at, recorded_at, provenance
         FROM actions
         WHERE tenant_id = $1
           AND recorded_at > $2
           AND entities && $3
           AND visibility && $4
           AND confidentiality <= $5
         ORDER BY recorded_at ASC
         LIMIT $6",
    )
    .bind(scope.tenant_id)
    .bind(since)
    .bind(watched)
    .bind(&scope.principals)
    .bind(scope.max_confidentiality as i16)
    .bind(POLL_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    rows.iter()
        .map(|row| {
            Ok((
                row_to_action(row)?,
                row.try_get("recorded_at").map_err(internal)?,
            ))
        })
        .collect()
}

/// Same item shape as recall hits (score is 0.0 — subscriptions deliver by
/// recency, not relevance, like `latest_chunks`).
fn row_to_hit(row: &PgRow) -> HandlerResult<RecallHit> {
    Ok(RecallHit {
        chunk_id: row.try_get("id").map_err(internal)?,
        document_id: row.try_get("document_id").map_err(internal)?,
        seq: row.try_get("seq").map_err(internal)?,
        content: row.try_get("content").map_err(internal)?,
        score: 0.0,
        entity_tags: row.try_get("entity_tags").map_err(internal)?,
        kind: row.try_get("kind").map_err(internal)?,
        support_tier: row
            .try_get::<Option<String>, _>("support_tier")
            .ok()
            .flatten()
            .and_then(|s| match s.as_str() {
                "emerging" => Some(verity_core::types::SupportTier::Emerging),
                "established" => Some(verity_core::types::SupportTier::Established),
                "extensive" => Some(verity_core::types::SupportTier::Extensive),
                _ => None,
            }),
        acl_provenance: AclProvenance::from_str_lossy(
            &row.try_get::<String, _>("acl_provenance")
                .map_err(internal)?,
        ),
        trust_tier: match row.try_get::<i16, _>("trust_tier").map_err(internal)? {
            1 => TrustTier::Authoritative,
            _ => TrustTier::Observation,
        },
        valid_from: row.try_get("valid_from").map_err(internal)?,
        provenance: row.try_get("provenance").map_err(internal)?,
    })
}

/// Same item shape as activity records.
fn row_to_action(row: &PgRow) -> HandlerResult<ActionRecord> {
    let outcome = match row
        .try_get::<String, _>("outcome")
        .map_err(internal)?
        .as_str()
    {
        "succeeded" => ActionOutcome::Succeeded,
        "failed" => ActionOutcome::Failed,
        _ => ActionOutcome::Pending,
    };
    Ok(ActionRecord {
        id: row.try_get::<Uuid, _>("id").map_err(internal)?,
        action_id: row.try_get("action_id").map_err(internal)?,
        actor_sub: row.try_get("actor_sub").map_err(internal)?,
        actor_azp: row.try_get("actor_azp").map_err(internal)?,
        action_type: row.try_get("action_type").map_err(internal)?,
        entities: row.try_get("entities").map_err(internal)?,
        summary: row.try_get("summary").map_err(internal)?,
        payload: row.try_get("payload").map_err(internal)?,
        outcome,
        occurred_at: row.try_get("occurred_at").map_err(internal)?,
        recorded_at: row.try_get("recorded_at").map_err(internal)?,
        provenance: row.try_get("provenance").map_err(internal)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_cap_acquires_and_releases() {
        let subs = Subscribers::new(2);
        let a = subs.try_acquire().expect("slot 1");
        let _b = subs.try_acquire().expect("slot 2");
        assert!(subs.try_acquire().is_none(), "cap enforced at 2");
        drop(a);
        assert!(subs.try_acquire().is_some(), "slot released on drop");
    }
}
