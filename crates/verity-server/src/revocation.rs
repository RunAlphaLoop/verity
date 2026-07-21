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
//! ## The M1 durable-tombstone upgrade (freshness keystone)
//!
//! The read path is now HANDLE-RELATIVE, not fixed-window. A read carrying a
//! minted handle drops token `t` iff some retained tombstone revoked `t` at-or-
//! after the handle was minted (`at >= payload.issued_at`), for the handle's
//! ENTIRE lifetime — up to `MAX_TTL_SECONDS` (12h), not the legacy 300s window.
//! This closes the leak where a 12h handle kept tier-≤2 access via an already-
//! minted handle for ~11h55m after the 300s window lapsed: `subtract` used to
//! forget a tombstone once it aged out of the 300s window regardless of handle
//! age. Because `verify` rejects handles past `MAX_TTL_SECONDS`, tombstones only
//! need durable retention `>= MAX_TTL_SECONDS + slack` (`RETENTION_SECS`); older
//! ones can never bite a still-live handle.
//!
//! The `issued_at`-relative rule is strictly correct, not just "widen the
//! window to 12h": a wider fixed window would wrongly drop a token from a NEWER
//! handle whose principal was legitimately re-granted after the revocation. The
//! cutoff is monotonic per handle, so a revocation older than a handle's mint
//! instant never retroactively bites that newer handle.
//!
//! Enforcement at RESOLUTION time (mint/admin plane, no handle in hand) keeps
//! the legacy window semantics via `subtract_window` (== `subtract` with the
//! cutoff pinned to `now() - VERITY_REVOCATION_WINDOW_SECS`): drop anything
//! revoked inside the configured window that is still live. This is coarser than
//! per-user exclusion (users legitimately still in the group also lose that
//! group token for the window) but it is fail-closed and covers the SpiceDB
//! propagation gap. The READ path uses the handle-relative cutoff instead.
//!
//! Cost: one indexed query per tenant per 5s (unchanged cadence; the widened
//! `at > now() - RETENTION_SECS` bound hits the same `(tenant_id, at DESC)`
//! index as before), memoized per tenant in a 5s-TTL moka cache. The query
//! COLLAPSES to one row per token keyed on the EARLIEST revocation instant
//! (`min(at)`), materialized as a `HashMap<token, first_at>`: a later duplicate
//! tombstone can never flip the `at >= issued_at` drop decision, so only
//! `min(at)` per token is load-bearing. This keeps the cardinality per-token
//! (== the pre-M1 `DISTINCT token` set size), NOT per physical revocation row —
//! group churn writing N×M rows collapses back to the distinct tokens. Per-read
//! work is a single `HashMap` lookup per caller principal (O(principals)), not a
//! nested scan of every retained row — no new DB round-trip, no live-ReBAC call,
//! and no latency/memory regression versus the pre-M1 windowed subtraction.
//!
//! Design-forward (M4 HA): the durable `(token, at)` set with a monotonic
//! per-handle cutoff is exactly what a future totally-ordered changelog feeds —
//! replace "read the revocations table" with "read the changelog offsets"
//! without touching the read path.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use verity_core::types::{ChunkId, Confidentiality, PrincipalToken, RecallHit, TenantId};

use crate::rebac::Rebac;
use crate::scope::{ScopePayload, MAX_TTL_SECONDS};
use crate::{internal, AppState, HandlerResult};

const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const DEFAULT_WINDOW_SECS: i64 = 300;

/// Durable retention floor for tombstones (M1). A live handle can be minted at
/// most `MAX_TTL_SECONDS` ago (verify rejects older), so keeping tombstones for
/// `MAX_TTL_SECONDS + 1h` slack guarantees every live handle can still observe
/// any tombstone recorded after it was minted. Older tombstones can never bite a
/// still-live handle. The read-path per-tenant scan is bounded by this window,
/// so its cost stays O(revoked-in-tenant-in-last-13h).
pub(crate) const RETENTION_SECS: i64 = MAX_TTL_SECONDS + 3600;

/// Per-tenant retained tombstone set: token → EARLIEST revocation instant. The
/// read-path subtraction drops a token from a handle iff `first_at >=
/// handle.issued_at`. Only `min(at)` per token is load-bearing (a later
/// duplicate can never flip that decision), so the map is keyed per-token, not
/// per physical revocation row.
type TombstoneSet = HashMap<PrincipalToken, DateTime<Utc>>;

/// Per-tenant DURABLE (indefinite) revoked-principal token set (M2 2a). Unlike
/// `TombstoneSet` this carries NO instant — a deprovision is permanent, so the
/// subtraction drops these tokens UNCONDITIONALLY (no `issued_at` comparison),
/// for every handle, forever, until reinstate. Bounded by
/// revoked-principals-in-tenant (partial `revoked_principal_active_idx`).
type RevokedSet = std::collections::HashSet<PrincipalToken>;

pub(crate) struct RevocationPlane {
    /// Per-tenant retained tombstone set (min-`at` per token within
    /// `RETENTION_SECS`). The per-handle `issued_at` cutoff is applied in-memory
    /// AFTER the cache read, so one cache entry serves every handle of the tenant
    /// regardless of mint time.
    cache: moka::sync::Cache<TenantId, Arc<TombstoneSet>>,
    /// Per-tenant DURABLE revoked-principal set (M2 2a). A SECOND dimension beside
    /// `cache`, mirroring its 5s-TTL memoization: the read-path `subtract` unions
    /// this in UNCONDITIONALLY (indefinite, `issued_at`-independent) on top of the
    /// windowed handle-relative tombstones. Invalidated on revoke/reinstate.
    revoked: moka::sync::Cache<TenantId, Arc<RevokedSet>>,
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
            revoked: moka::sync::Cache::builder()
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

    /// The tenant's retained tombstone set as token → EARLIEST-`at`, one entry
    /// per revoked token within `RETENTION_SECS` (the DB `GROUP BY token` /
    /// `min(at)` collapses the N×M physical rows a group removal writes down to
    /// the distinct tokens). Bounded by DISTINCT-revoked-tokens-in-tenant over
    /// the last ~13h — the same cardinality as the pre-M1 `DISTINCT token`
    /// windowed set. Memoized 5s; the `at` bound + grouping is served by the
    /// existing `(tenant_id, at DESC)` index.
    pub(crate) async fn retained_tombstones(
        &self,
        pool: &PgPool,
        tenant: TenantId,
    ) -> HandlerResult<Arc<TombstoneSet>> {
        if let Some(hit) = self.cache.get(&tenant) {
            return Ok(hit);
        }
        let rows = sqlx::query(
            "SELECT token, min(at) AS at FROM revocations
             WHERE tenant_id = $1 AND at > now() - make_interval(secs => $2)
             GROUP BY token",
        )
        .bind(tenant)
        .bind(RETENTION_SECS as f64)
        .fetch_all(pool)
        .await
        .map_err(internal)?;
        let tombstones: Arc<TombstoneSet> = Arc::new(
            rows.iter()
                .map(|r| (r.get::<i32, _>("token"), r.get::<DateTime<Utc>, _>("at")))
                .collect(),
        );
        self.cache.insert(tenant, Arc::clone(&tombstones));
        Ok(tombstones)
    }

    /// The tenant's DURABLE revoked-principal token set (M2 2a): every token
    /// whose principal is CURRENTLY revoked (`reinstated_at IS NULL`), with NO
    /// time bound. Served by the partial `revoked_principal_active_idx`
    /// (O(revoked-in-tenant)), memoized 5s exactly like `retained_tombstones`.
    /// This is what makes a direct-grant deprovision INDEFINITE: the subtract
    /// drops these tokens for every handle regardless of `issued_at` or age.
    pub(crate) async fn revoked_set(
        &self,
        pool: &PgPool,
        tenant: TenantId,
    ) -> HandlerResult<Arc<RevokedSet>> {
        if let Some(hit) = self.revoked.get(&tenant) {
            return Ok(hit);
        }
        let rows = sqlx::query(
            "SELECT token FROM revoked_principal
             WHERE tenant_id = $1 AND reinstated_at IS NULL",
        )
        .bind(tenant)
        .fetch_all(pool)
        .await
        .map_err(internal)?;
        let set: Arc<RevokedSet> =
            Arc::new(rows.iter().map(|r| r.get::<i32, _>("token")).collect());
        self.revoked.insert(tenant, Arc::clone(&set));
        Ok(set)
    }

    /// Durably (INDEFINITELY) revoke a principal by its token — writes the
    /// `revoked_principal` row then invalidates the local cache so the mint gate
    /// and read-path subtraction deny it immediately in-process. Idempotent: a
    /// re-revoke of a previously-reinstated principal clears `reinstated_at`.
    pub(crate) async fn revoke_principal(
        &self,
        pool: &PgPool,
        tenant: TenantId,
        principal: &str,
        token: PrincipalToken,
    ) -> HandlerResult<()> {
        sqlx::query(
            "INSERT INTO revoked_principal (tenant_id, token, principal)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id, token)
             DO UPDATE SET reinstated_at = NULL, revoked_at = now(),
                           principal = EXCLUDED.principal",
        )
        .bind(tenant)
        .bind(token)
        .bind(principal)
        .execute(pool)
        .await
        .map_err(internal)?;
        self.revoked.invalidate(&tenant);
        Ok(())
    }

    /// Clear a durable revocation (invalidate-don't-delete: sets `reinstated_at`)
    /// so NEW grants resolve again. Returns whether the principal WAS revoked.
    /// Already-swept chunks stay invalidated until re-ingest — the caller must
    /// document this (a reinstate does not resurrect the retracted materialized
    /// token).
    pub(crate) async fn reinstate_principal(
        &self,
        pool: &PgPool,
        tenant: TenantId,
        token: PrincipalToken,
    ) -> HandlerResult<bool> {
        let affected = sqlx::query(
            "UPDATE revoked_principal SET reinstated_at = now()
             WHERE tenant_id = $1 AND token = $2 AND reinstated_at IS NULL",
        )
        .bind(tenant)
        .bind(token)
        .execute(pool)
        .await
        .map_err(internal)?
        .rows_affected();
        self.revoked.invalidate(&tenant);
        Ok(affected > 0)
    }

    /// Subtract tokens revoked at-or-after a handle's mint instant (`issued_at`)
    /// from that handle's principal set — the M1 handle-relative model — AND drop
    /// any token in the DURABLE revoked-principal set unconditionally (M2 2a,
    /// indefinite). A token is dropped iff (a) its principal is durably revoked
    /// (no `issued_at` gate — permanent), OR (b) SOME retained tombstone for it
    /// has `at >= issued_at`. Fail-closed by construction: an error refuses the
    /// read rather than skipping the subtraction.
    pub(crate) async fn subtract(
        &self,
        pool: &PgPool,
        tenant: TenantId,
        principals: &[PrincipalToken],
        issued_at: DateTime<Utc>,
    ) -> HandlerResult<Vec<PrincipalToken>> {
        let tombstones = self.retained_tombstones(pool, tenant).await?;
        let revoked = self.revoked_set(pool, tenant).await?;
        if tombstones.is_empty() && revoked.is_empty() {
            return Ok(principals.to_vec());
        }
        // O(principals): one HashMap + one HashSet lookup per caller principal
        // (both sets 5s-cached, no per-read DB round-trip). A token drops iff:
        //   (2a) it is in the DURABLE revoked set — indefinite, unconditional; or
        //   (M1) its EARLIEST tombstone is at-or-after this handle's mint instant.
        // `min(at)` is sufficient for (M1) — if the earliest tombstone predates
        // the handle no later duplicate can bite it; if it post-dates, the token
        // drops regardless of duplicates.
        let kept: Vec<PrincipalToken> = principals
            .iter()
            .copied()
            .filter(|t| {
                !revoked.contains(t)
                    && tombstones
                        .get(t)
                        .is_none_or(|first_at| *first_at < issued_at)
            })
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

    /// Resolution-time / admin-plane subtraction (no handle in hand): drop any
    /// token revoked inside the configured `window_secs` that is still live. This
    /// is `subtract` with the cutoff pinned to `now() - window_secs`, preserving
    /// the legacy window semantics for the mint path and the admin re-impl. The
    /// READ path uses `subtract` with the handle's own `issued_at` instead.
    pub(crate) async fn subtract_window(
        &self,
        pool: &PgPool,
        tenant: TenantId,
        principals: &[PrincipalToken],
    ) -> HandlerResult<Vec<PrincipalToken>> {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.window_secs);
        self.subtract(pool, tenant, principals, cutoff).await
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
    // Read-path recheck: use the handle's own mint instant so tombstones
    // recorded after this handle was minted are subtracted for its full life.
    state
        .revocations
        .subtract(state.pool(), payload.tenant_id, &tokens, payload.issued_at)
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

    /// DSN-only: resolution-time (`subtract_window`) in-window rows are
    /// subtracted from any principal set; rows older than the window are not;
    /// recording invalidates the cache so exclusion is immediate in-process.
    #[tokio::test]
    async fn window_subtraction_is_immediate_and_expires() {
        let (pool, tenant) = test_pool().await;
        let plane = RevocationPlane::new(300);

        // Warm the cache with the empty set, then record: the invalidation
        // must make the new tombstone visible immediately.
        assert_eq!(
            plane
                .subtract_window(&pool, tenant, &[7, 9, 11])
                .await
                .unwrap(),
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
            plane
                .subtract_window(&pool, tenant, &[7, 9, 11])
                .await
                .unwrap(),
            vec![9, 11],
            "in-window token subtracted immediately after record"
        );

        // A row older than the resolution window no longer subtracts at
        // resolution time.
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
            fresh_plane
                .subtract_window(&pool, tenant, &[9, 11])
                .await
                .unwrap(),
            vec![9, 11],
            "out-of-window tombstone does not subtract at resolution time"
        );
        // ...but a wider window still catches it (env-tunable contract).
        let wide_plane = RevocationPlane::new(3600);
        assert_eq!(
            wide_plane
                .subtract_window(&pool, tenant, &[9, 11])
                .await
                .unwrap(),
            vec![11]
        );
    }

    /// M1 KEYSTONE (fails on pre-M1 code, passes after): a token revoked AFTER a
    /// 12h handle was minted is dropped for the handle's FULL lifetime, even past
    /// the legacy 300s window. This is the exact leak M1 closes — the old
    /// wall-clock `subtract` forgot the tombstone once it aged out of 300s,
    /// leaving ~11h55m of stale tier-≤2 access on an already-minted handle.
    #[tokio::test]
    async fn revocation_outlives_max_ttl_for_prior_minted_handle() {
        let (pool, tenant) = test_pool().await;

        // A handle minted ~12h ago is represented by an issued_at in the past.
        let issued_at = Utc::now() - chrono::Duration::seconds(MAX_TTL_SECONDS);

        // No tombstones yet: nothing is dropped from the handle's minted set.
        let plane = RevocationPlane::new(300); // legacy window is irrelevant now
        assert_eq!(
            plane
                .subtract(&pool, tenant, &[7, 9, 11], issued_at)
                .await
                .unwrap(),
            vec![7, 9, 11],
            "no tombstones yet: nothing dropped"
        );

        // Token 7 is revoked (recorded now), i.e. AFTER the handle was minted.
        plane
            .record(
                &pool,
                tenant,
                &["user:alice@corp.example".to_string()],
                &[("group:sales".to_string(), 7)],
            )
            .await
            .expect("record");

        // Age the tombstone to 30 minutes ago — well past the legacy 300s window
        // relative to any per-read wall clock, but still AFTER issued_at (12h ago).
        sqlx::query(
            "UPDATE revocations SET at = now() - interval '30 minutes'
             WHERE tenant_id = $1 AND token = 7",
        )
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("age the tombstone");

        // A cold-cache plane 30min after the revocation, on a handle minted 12h
        // ago. Legacy 300s window => token 7 survives (THE LEAK). M1 durable
        // model => issued_at (12h ago) <= at (30min ago) => DROP token 7.
        let fresh = RevocationPlane::new(300);
        assert_eq!(
            fresh
                .subtract(&pool, tenant, &[7, 9, 11], issued_at)
                .await
                .unwrap(),
            vec![9, 11],
            "token revoked 30min ago (past the 300s window) must STILL drop for a 12h handle"
        );

        // Correctness guard that distinguishes this from "just widen the window":
        // a handle minted AFTER the revocation KEEPS the token (the principal was
        // legitimately re-granted before this newer handle was minted). A wider
        // fixed window would wrongly drop it here; the issued_at-relative model
        // does not.
        let later = Utc::now();
        assert_eq!(
            fresh
                .subtract(&pool, tenant, &[7, 9, 11], later)
                .await
                .unwrap(),
            vec![7, 9, 11],
            "revocation older than issued_at does not retroactively bite a newer handle"
        );
    }

    /// M2 2a KEYSTONE: a DURABLE principal revocation subtracts the principal's
    /// token INDEFINITELY — past RETENTION_SECS (~13h), for ANY handle regardless
    /// of `issued_at`. This is the exact difference from the M1 windowed tombstone
    /// (`revocation_outlives_max_ttl_for_prior_minted_handle`): no `issued_at`
    /// gate, no window bound. A deprovisioned human re-minting years later stays
    /// denied.
    #[tokio::test]
    async fn revoked_principal_subtraction_is_indefinite() {
        let (pool, tenant) = test_pool().await;
        let plane = RevocationPlane::new(300);

        // A FRESH handle minted RIGHT NOW (issued_at = now). Under the M1 windowed
        // model this handle would keep any token whose tombstone predates it — but
        // the durable revoked set has NO issued_at gate, so token 7 must still drop.
        let now = Utc::now();
        assert_eq!(
            plane
                .subtract(&pool, tenant, &[7, 9, 11], now)
                .await
                .unwrap(),
            vec![7, 9, 11],
            "nothing revoked yet"
        );

        plane
            .revoke_principal(&pool, tenant, "user:alice@corp.example", 7)
            .await
            .expect("revoke");

        // Age the durable record to 20 HOURS ago — WELL past RETENTION_SECS (~13h)
        // and past MAX_TTL. A windowed/handle-relative rule would have forgotten it.
        sqlx::query(
            "UPDATE revoked_principal SET revoked_at = now() - interval '20 hours'
             WHERE tenant_id = $1 AND token = 7",
        )
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("age the durable record");

        // A cold-cache plane, ANY handle instant (now, or an ancient handle) — the
        // durable revoked token drops unconditionally.
        let fresh = RevocationPlane::new(300);
        assert_eq!(
            fresh
                .subtract(&pool, tenant, &[7, 9, 11], Utc::now())
                .await
                .unwrap(),
            vec![9, 11],
            "durably-revoked token drops for a fresh handle past RETENTION_SECS"
        );
        let ancient = Utc::now() - chrono::Duration::seconds(MAX_TTL_SECONDS);
        assert_eq!(
            fresh
                .subtract(&pool, tenant, &[7, 9, 11], ancient)
                .await
                .unwrap(),
            vec![9, 11],
            "and for a 12h-old handle too — indefinite, issued_at-independent"
        );
        // subtract_window (mint/admin plane) inherits the same drop.
        assert_eq!(
            fresh
                .subtract_window(&pool, tenant, &[7, 9, 11])
                .await
                .unwrap(),
            vec![9, 11],
            "the mint/admin subtract_window path omits a durably-revoked token too"
        );
    }

    /// Reinstate clears the durable revocation so the token resolves again on the
    /// read/mint path (already-swept chunks are a storage concern, not this set).
    #[tokio::test]
    async fn reinstate_clears_durable_revocation() {
        let (pool, tenant) = test_pool().await;
        let plane = RevocationPlane::new(300);

        plane
            .revoke_principal(&pool, tenant, "user:bob@corp.example", 42)
            .await
            .expect("revoke");
        assert_eq!(
            plane
                .subtract(&pool, tenant, &[42, 43], Utc::now())
                .await
                .unwrap(),
            vec![43],
            "revoked token dropped"
        );

        let was_revoked = plane
            .reinstate_principal(&pool, tenant, 42)
            .await
            .expect("reinstate");
        assert!(was_revoked, "reinstate reports it was revoked");
        assert_eq!(
            plane
                .subtract(&pool, tenant, &[42, 43], Utc::now())
                .await
                .unwrap(),
            vec![42, 43],
            "reinstated token resolves again (cache invalidated on reinstate)"
        );

        // Reinstating a not-currently-revoked token reports false, idempotently.
        let again = plane
            .reinstate_principal(&pool, tenant, 42)
            .await
            .expect("reinstate again");
        assert!(!again, "second reinstate is a no-op");
    }
}
