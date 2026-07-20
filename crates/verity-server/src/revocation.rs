//! Revocation tombstones (SPEC §7b rule 3, v0.1 contract) and the
//! restricted-class recheck (SPEC §7b rule 4, v0.1 approximation).
//!
//! ## The v0.1 revocation contract, stated honestly
//!
//! On group-membership DELETE the server resolves the principals lost
//! (conservatively: the removed member subtree loses the group AND all its
//! transitive ancestors) and inserts durable `revocations` rows — BEFORE the
//! SpiceDB tuple is removed, so a failure over-hides rather than under-hides.
//!
//! Enforcement: for `VERITY_REVOCATION_WINDOW_SECS` (default 300s) after the
//! row's `at`, its `token` is subtracted from EVERY resolved principal set in
//! the tenant — at resolution time (`open_scope`) and at read time for
//! already-minted handles (`recall`/`activity`/`brief`). This is coarser than
//! per-user exclusion (users legitimately still in the group also lose that
//! group token for the window) but it is fail-closed, covers the SpiceDB
//! propagation gap AND the lifetime of already-minted handles, and is durable
//! in Postgres so cold starts can't forget a revocation. After the window,
//! fresh SpiceDB resolution is the source of truth again.
//!
//! Cost: one indexed query per read, memoized per tenant in a 5s-TTL moka
//! cache (invalidated locally on write, so same-process revocations are
//! immediate; cross-replica staleness is bounded by the TTL).

use std::sync::Arc;

use axum::http::StatusCode;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use verity_core::types::{ChunkId, Confidentiality, PrincipalToken, RecallHit, TenantId};

use crate::rebac::Rebac;
use crate::scope::ScopePayload;
use crate::{internal, AppState, HandlerResult};

const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const DEFAULT_WINDOW_SECS: i64 = 300;

pub(crate) struct RevocationPlane {
    /// Per-tenant set of tokens with an in-window revocation row.
    cache: moka::sync::Cache<TenantId, Arc<Vec<PrincipalToken>>>,
    window_secs: i64,
    /// M0 `/metrics`: `revocation_subtractions_total`, bumped by the number of
    /// tokens actually dropped in `subtract`. `None` until the server wires the
    /// shared counter (`set_subtraction_counter`); the increment is a cheap
    /// `Relaxed` add on the read path.
    subtractions: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl RevocationPlane {
    pub(crate) fn new(window_secs: i64) -> Self {
        Self {
            cache: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(CACHE_TTL)
                .build(),
            window_secs: window_secs.max(0),
            subtractions: None,
        }
    }

    /// Wire the shared `revocation_subtractions_total` counter (M0 `/metrics`).
    pub(crate) fn set_subtraction_counter(&mut self, counter: Arc<std::sync::atomic::AtomicU64>) {
        self.subtractions = Some(counter);
    }

    pub(crate) fn from_env() -> Self {
        let window_secs = std::env::var("VERITY_REVOCATION_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_WINDOW_SECS);
        Self::new(window_secs)
    }

    /// The configured revocation window in seconds. The Permission Graph admin
    /// plane reads this to re-implement `subtract`'s in-window subtraction
    /// inline (parity with the read path without sharing `scope_for`).
    pub(crate) fn window_secs(&self) -> i64 {
        self.window_secs
    }

    /// Tokens currently inside the revocation window for this tenant.
    pub(crate) async fn windowed_tokens(
        &self,
        pool: &PgPool,
        tenant: TenantId,
    ) -> HandlerResult<Arc<Vec<PrincipalToken>>> {
        if let Some(hit) = self.cache.get(&tenant) {
            return Ok(hit);
        }
        let rows = sqlx::query(
            "SELECT DISTINCT token FROM revocations
             WHERE tenant_id = $1 AND at > now() - make_interval(secs => $2)",
        )
        .bind(tenant)
        .bind(self.window_secs as f64)
        .fetch_all(pool)
        .await
        .map_err(internal)?;
        let tokens: Arc<Vec<PrincipalToken>> =
            Arc::new(rows.iter().map(|r| r.get::<i32, _>("token")).collect());
        self.cache.insert(tenant, Arc::clone(&tokens));
        Ok(tokens)
    }

    /// Subtract in-window revoked tokens from a principal set. Fail-closed by
    /// construction: an error refuses the read rather than skipping the
    /// subtraction.
    pub(crate) async fn subtract(
        &self,
        pool: &PgPool,
        tenant: TenantId,
        principals: &[PrincipalToken],
    ) -> HandlerResult<Vec<PrincipalToken>> {
        let revoked = self.windowed_tokens(pool, tenant).await?;
        if revoked.is_empty() {
            return Ok(principals.to_vec());
        }
        let kept: Vec<PrincipalToken> = principals
            .iter()
            .copied()
            .filter(|t| !revoked.contains(t))
            .collect();
        // M0: count the tokens actually dropped (never the whole set). Only the
        // subtract path that removes something increments the counter.
        if let Some(c) = &self.subtractions {
            let dropped = principals.len().saturating_sub(kept.len()) as u64;
            if dropped > 0 {
                c.fetch_add(dropped, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(kept)
    }

    /// Durably record revocation rows (one per affected principal × lost
    /// token), then drop the local cache entry so same-process reads exclude
    /// the tokens immediately.
    pub(crate) async fn record(
        &self,
        pool: &PgPool,
        tenant: TenantId,
        affected_principals: &[String],
        lost_tokens: &[(String, PrincipalToken)],
    ) -> HandlerResult<u64> {
        let mut inserted = 0u64;
        let mut tx = pool.begin().await.map_err(internal)?;
        for principal in affected_principals {
            for (_, token) in lost_tokens {
                sqlx::query(
                    "INSERT INTO revocations (id, tenant_id, principal, token)
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(Uuid::now_v7())
                .bind(tenant)
                .bind(principal)
                .bind(token)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
                inserted += 1;
            }
        }
        tx.commit().await.map_err(internal)?;
        self.cache.invalidate(&tenant);
        Ok(inserted)
    }
}

// ---------- restricted-class recheck (SPEC §7b rule 4, v0.1 approximation) ----------

/// Enforce the restricted-class contract on a hit list (recall and the
/// latest_chunks/brief path):
///
/// - ReBAC enabled: each restricted hit's visibility tokens must still
///   overlap the caller's CURRENT resolved set — the subject's groups are
///   re-resolved fresh from SpiceDB (bounded k ≤ 100 hits) and in-window
///   revocations subtracted. This approximates the §7b live BatchCheck until
///   per-item tuples exist. Handles minted from caller-supplied principals
///   (no subject) recheck against their minted set minus revocations.
/// - ReBAC disabled: restricted hits are DROPPED unless
///   `VERITY_ALLOW_RESTRICTED_WITHOUT_REBAC=1` — fail closed: without an
///   authorization engine nobody gets pricing-class content by default.
///
/// Any resolution failure drops the restricted hits (never the whole
/// response, never a permissive pass-through).
pub(crate) async fn enforce_restricted(
    state: &AppState,
    payload: &ScopePayload,
    hits: Vec<RecallHit>,
) -> HandlerResult<Vec<RecallHit>> {
    // Scopes below the Restricted ceiling can never have restricted hits —
    // the index pre-filter already excluded them.
    if hits.is_empty() || payload.max_confidentiality < Confidentiality::Restricted {
        return Ok(hits);
    }
    let ids: Vec<ChunkId> = hits.iter().map(|h| h.chunk_id).collect();
    let restricted = restricted_visibility(state.pool(), &ids).await?;
    if restricted.is_empty() {
        return Ok(hits);
    }

    let current: Option<Vec<PrincipalToken>> = match &state.rebac {
        None => {
            if state.allow_restricted_without_rebac {
                tracing::warn!(
                    "serving restricted-class hits without ReBAC (VERITY_ALLOW_RESTRICTED_WITHOUT_REBAC=1)"
                );
                return Ok(hits);
            }
            None // drop all restricted hits
        }
        Some(rebac) => match current_token_set(state, rebac, payload).await {
            Ok(tokens) => Some(tokens),
            Err(e) => {
                tracing::warn!(
                    "restricted recheck failed, dropping restricted hits: {}",
                    e.1
                );
                None
            }
        },
    };

    Ok(hits
        .into_iter()
        .filter(
            |h| match restricted.iter().find(|(id, _)| *id == h.chunk_id) {
                None => true, // not restricted
                Some((_, visibility)) => match &current {
                    None => false,
                    Some(current) => visibility.iter().any(|t| current.contains(t)),
                },
            },
        )
        .collect())
}

/// (chunk_id, visibility) for the restricted subset of the given hits.
async fn restricted_visibility(
    pool: &PgPool,
    ids: &[ChunkId],
) -> HandlerResult<Vec<(ChunkId, Vec<PrincipalToken>)>> {
    let rows =
        sqlx::query("SELECT id, visibility FROM chunks WHERE id = ANY($1) AND confidentiality = 3")
            .bind(ids)
            .fetch_all(pool)
            .await
            .map_err(internal)?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<Uuid, _>("id"), r.get::<Vec<i32>, _>("visibility")))
        .collect())
}

/// The caller's CURRENT resolved token set: fresh SpiceDB resolution when the
/// handle carries a subject, else the minted set; in-window revocations
/// subtracted either way.
async fn current_token_set(
    state: &AppState,
    rebac: &Rebac,
    payload: &ScopePayload,
) -> HandlerResult<Vec<PrincipalToken>> {
    let tokens = match &payload.subject {
        Some(subject) => {
            let (kind, name) = crate::rebac::parse_principal(subject).ok_or((
                StatusCode::UNPROCESSABLE_ENTITY,
                "scope subject is not a user principal".to_string(),
            ))?;
            if kind != crate::rebac::PrincipalKind::User {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "scope subject is not a user principal".to_string(),
                ));
            }
            let mut principals = vec![subject.clone()];
            principals.extend(
                rebac
                    .user_groups(payload.tenant_id, name)
                    .await
                    .map_err(internal)?,
            );
            crate::upsert_principal_tokens(state.pool(), payload.tenant_id, &principals)
                .await?
                .into_iter()
                .map(|(_, t)| t)
                .collect()
        }
        None => payload.principals.clone(),
    };
    state
        .revocations
        .subtract(state.pool(), payload.tenant_id, &tokens)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> (PgPool, TenantId) {
        let dsn = std::env::var("VERITY_TEST_DSN").expect(
            "VERITY_TEST_DSN must be set for the revocation-subtraction soundness test \
             (fail-closed window subtraction); refusing to silently no-op",
        );
        let adapter = verity_storage::PostgresAdapter::connect(&dsn)
            .await
            .expect("connect");
        adapter.migrate().await.expect("migrate");
        use verity_core::adapter::StorageAdapter;
        let tenant = adapter
            .create_tenant(&format!("revocation-test-{}", Uuid::now_v7()))
            .await
            .expect("tenant");
        (adapter.pool().clone(), tenant)
    }

    /// DSN-only: in-window rows are subtracted from any principal set;
    /// rows older than the window are not; recording invalidates the cache
    /// so exclusion is immediate in-process.
    #[tokio::test]
    async fn window_subtraction_is_immediate_and_expires() {
        let (pool, tenant) = test_pool().await;
        let plane = RevocationPlane::new(300);

        // Warm the cache with the empty set, then record: the invalidation
        // must make the new tombstone visible immediately.
        assert_eq!(
            plane.subtract(&pool, tenant, &[7, 9, 11]).await.unwrap(),
            vec![7, 9, 11]
        );
        plane
            .record(
                &pool,
                tenant,
                &["user:alice@corp.example".to_string()],
                &[("group:sales".to_string(), 7)],
            )
            .await
            .expect("record");
        assert_eq!(
            plane.subtract(&pool, tenant, &[7, 9, 11]).await.unwrap(),
            vec![9, 11],
            "in-window token subtracted immediately after record"
        );

        // A row older than the window no longer subtracts.
        sqlx::query(
            "INSERT INTO revocations (id, tenant_id, principal, token, at)
             VALUES ($1, $2, 'user:old', 9, now() - interval '10 minutes')",
        )
        .bind(Uuid::now_v7())
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("insert stale row");
        let fresh_plane = RevocationPlane::new(300);
        assert_eq!(
            fresh_plane.subtract(&pool, tenant, &[9, 11]).await.unwrap(),
            vec![9, 11],
            "out-of-window tombstone does not subtract"
        );
        // ...but a wider window still catches it (env-tunable contract).
        let wide_plane = RevocationPlane::new(3600);
        assert_eq!(
            wide_plane.subtract(&pool, tenant, &[9, 11]).await.unwrap(),
            vec![11]
        );
    }
}
