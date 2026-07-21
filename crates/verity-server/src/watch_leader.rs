//! Leader election for the SpiceDB Watch consumer (SPEC §7b, M1).
//!
//! ## Why this exists
//!
//! The durable watch cursor (`rebac_watch_cursor`) is a SINGLE row owned by
//! exactly one running consumer. Two consumers sharing a database fight over
//! it — each resumes past events the other processed — and BOTH go quietly
//! blind (the disclosed v0 limitation in `rebac_watch.rs` / migration 0025).
//! On >1 replica that is a silent freshness failure, exactly the class of leak
//! M1 closes. Leader election removes it: only ONE consumer per database
//! consumes the stream and advances the cursor at a time.
//!
//! ## Mechanism — a session-level Postgres advisory lock
//!
//! [`WatchLeadership::try_acquire`] pulls a DEDICATED connection out of the
//! pool and takes a SESSION-level `pg_try_advisory_lock(hashtext(KEY))` on it.
//! The lock is held for the guard's lifetime (the whole consumer run), NOT one
//! transaction — so it spans the long-lived Watch stream. `pg_try_advisory_lock`
//! is non-blocking: it returns `true` (this replica is the leader) or `false`
//! (another replica already leads → this one is a follower and must not
//! consume). Session advisory locks auto-release when the holding connection
//! closes, so a leader that dies (process crash, connection drop) releases the
//! lock and a polling follower takes over WITHOUT any lease/heartbeat timeout
//! to tune. The heartbeat row is primarily observability, but because it runs on
//! the lock-holding connection its FAILURE also serves as a liveness probe: the
//! consumer treats a heartbeat error as loss of leadership and stops advancing
//! the cursor, so a leader whose lock connection silently dropped cannot become
//! a zombie racing the new leader.
//!
//! Fail-closed posture: acquisition or heartbeat FAILURE is treated as "not the
//! leader" (return `Ok(None)` / drop the guard), never "assume leadership" — a
//! replica that cannot prove it holds the lock must not advance the cursor.
//!
//! ## Design-forward (M4 HA on-ramp)
//!
//! The advisory lock is the swap point for the future totally-ordered changelog
//! spine: replace the lock source inside [`WatchLeadership::try_acquire`] with
//! the changelog's leadership primitive and `rebac_watch::run` never changes.
//! The dedicated held connection + RAII drop shape is deliberately the same one
//! a lease-based coordinator would use.

use sqlx::pool::PoolConnection;
use sqlx::{PgPool, Postgres};

/// Fixed, documented advisory-lock key namespace for the watch cursor. Hashed
/// to a bigint via `hashtext` inside the query — stable across processes and
/// releases, distinct from the per-tenant token-allocation lock
/// (`hashtext($tenant)` in main.rs) since that keys on a tenant uuid string.
pub(crate) const LEADER_LOCK_KEY: &str = "verity_rebac_watch_cursor";

/// RAII leadership guard. Holds a dedicated [`PoolConnection`] carrying a
/// SESSION-level advisory lock; only the holder may consume the Watch stream
/// and advance the cursor. Dropping the guard (or losing the connection)
/// releases the lock, letting a follower take over.
pub(crate) struct WatchLeadership {
    /// The dedicated connection the session advisory lock lives on. Held for
    /// the guard's lifetime; MUST NOT be returned to the pool while leading
    /// (returning it would drop the lock). `Drop` releases it — and with it the
    /// session lock — automatically.
    conn: PoolConnection<Postgres>,
    /// The advisory-lock key string this guard holds. `LEADER_LOCK_KEY` in
    /// production; a process-unique key in tests so the mutual-exclusion test
    /// isn't starved by a running dev consumer holding the shared prod key.
    key: String,
}

impl WatchLeadership {
    /// Try to become the watch leader for this database.
    ///
    /// * `Ok(Some(guard))` — this replica acquired the lock and is the leader.
    ///   Consume the stream and advance the cursor for as long as `guard` lives.
    /// * `Ok(None)` — another replica already leads (or we could not prove
    ///   leadership). This replica is a FOLLOWER: it must NOT consume; it should
    ///   poll-retry on its reconnect backoff and take over if the leader dies.
    /// * `Err(_)` — the pool could not hand out a connection; the caller treats
    ///   this like a follower (retry later), never as leadership.
    pub(crate) async fn try_acquire(pool: &PgPool) -> Result<Option<Self>, sqlx::Error> {
        Self::try_acquire_with_key(pool, LEADER_LOCK_KEY).await
    }

    /// `try_acquire` against a specific advisory-lock key. Production always uses
    /// `LEADER_LOCK_KEY`; tests pass a process-unique key so the mutual-exclusion
    /// test doesn't collide with a running dev consumer holding the prod key on
    /// the shared dev database.
    async fn try_acquire_with_key(
        pool: &PgPool,
        lock_key: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;
        // Non-blocking, session-scoped. Held until `conn` is dropped.
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1::text))")
            .bind(lock_key)
            .fetch_one(conn.as_mut())
            .await?;
        if acquired {
            // FAIL-SAFE against a session-level lock leaking back into the pool:
            // sqlx 0.9's PoolConnection return path does NOT issue
            // `pg_advisory_unlock`/`DISCARD ALL`, so a plain drop of a still-locked
            // connection would return it to the shared pool STILL HOLDING the
            // lock, and the next `try_acquire` (on a different physical
            // connection) would see `false` forever — permanently demoting the
            // sole watch consumer to follower after the first reconnect. Arming
            // `close_on_drop` guarantees that ANY drop of this guard (normal
            // relinquish, early return, or panic) physically CLOSES the
            // connection, which is what actually releases the session lock; the
            // connection is never returned to the pool while locked. Leadership
            // relinquish is infrequent (only on stream end/reconnect), so the
            // per-relinquish connection recycle is negligible, and it removes the
            // whole class of "lock leaked into a pooled connection" bugs.
            conn.close_on_drop();
            Ok(Some(Self {
                conn,
                key: lock_key.to_string(),
            }))
        } else {
            // Not the leader: return the connection to the pool (no lock held).
            Ok(None)
        }
    }

    /// Explicitly release leadership PROMPTLY: unlock the session advisory lock
    /// on the held connection before dropping, so a follower can take over
    /// immediately rather than waiting for the OS/pool to tear the connection
    /// down. Best-effort — if the unlock query fails (dead connection), the
    /// `close_on_drop` fail-safe armed in `try_acquire` still physically closes
    /// the connection on drop, releasing the lock either way. The lock is NEVER
    /// leaked back into the pool.
    pub(crate) async fn release(mut self) {
        let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1::text))")
            .bind(&self.key)
            .execute(self.conn.as_mut())
            .await;
        // `self` drops here; close_on_drop closes the (now-unlocked) connection.
    }

    /// Record who currently leads, for `/v1/admin/rebac-watch` and future HA
    /// observers. Runs on the SAME connection that holds the leadership advisory
    /// lock, so it can never be starved out by pool pressure — and, crucially,
    /// its failure is a PROXY for the lock connection dying: the caller
    /// (`consume_while_leading`) treats a heartbeat `Err` as loss of leadership
    /// and stops consuming, so a leader whose lock connection silently dropped
    /// does not become a zombie racing the new leader on the single cursor.
    pub(crate) async fn heartbeat(&mut self, holder: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE watch_leader SET holder = $1, heartbeat_at = now() WHERE id = 1")
            .bind(holder)
            .execute(self.conn.as_mut())
            .await
            .map(|_| ())
    }
}

// Drop releases the session advisory lock by PHYSICALLY CLOSING the held
// connection: `try_acquire` arms `close_on_drop`, so the guard's drop closes the
// connection instead of returning a still-locked one to the pool. Session-level
// advisory locks auto-release when their owning connection closes. This holds on
// EVERY drop path — normal `release()`, early `return`, or a panic — so the lock
// can never leak into a pooled connection (the sqlx 0.9 return path issues
// neither `pg_advisory_unlock` nor `DISCARD ALL`). `release()` additionally runs
// an explicit `pg_advisory_unlock` first so a follower takes over promptly.

#[cfg(test)]
mod tests {
    use super::*;

    /// DSN-gated: the advisory lock is mutually exclusive — a second
    /// `try_acquire` on the same database returns `None` (follower) while the
    /// first guard is alive, and succeeds again once the first is dropped.
    #[tokio::test]
    async fn leader_lock_is_mutually_exclusive() {
        let Ok(dsn) = std::env::var("VERITY_TEST_DSN") else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return;
        };
        let pool = PgPool::connect(&dsn).await.expect("connect");
        // A PROCESS-UNIQUE lock key so this mutual-exclusion test is not starved
        // by a running dev :7717 consumer holding the shared production
        // LEADER_LOCK_KEY on the same dev database. All three acquires below use
        // this same key, so they still prove mutual exclusion among themselves.
        let key = format!("verity_test_leader_lock_{}", std::process::id());

        // First acquirer becomes leader.
        let leader = WatchLeadership::try_acquire_with_key(&pool, &key)
            .await
            .expect("acquire")
            .expect("first caller leads");

        // Second acquirer, same database, must be a follower.
        let follower = WatchLeadership::try_acquire_with_key(&pool, &key)
            .await
            .expect("acquire follower");
        assert!(
            follower.is_none(),
            "a second consumer must NOT lead while the first holds the lock"
        );

        // Release the leader → the session lock releases → leadership is
        // available. `release()` runs pg_advisory_unlock then closes the conn.
        leader.release().await;
        // A fresh acquire now succeeds. Retry briefly to absorb pool bookkeeping.
        let mut took_over = None;
        for _ in 0..50 {
            if let Some(g) = WatchLeadership::try_acquire_with_key(&pool, &key)
                .await
                .expect("reacquire")
            {
                took_over = Some(g);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            took_over.is_some(),
            "leadership must be re-acquirable after the leader drops"
        );
    }

    /// DSN-gated regression for the pool-leak bug: on a bounded multi-connection
    /// pool, a leader that is plainly DROPPED (not `release()`d — the panic/early
    /// -return path) must NOT leave the advisory lock stuck in a pooled
    /// connection. A subsequent `try_acquire`, even after the pool has handed out
    /// and reclaimed other connections, must regain leadership. Pre-fix this
    /// wedged into a permanent follower after the first drop.
    #[tokio::test]
    async fn leadership_regained_after_bare_drop_on_pooled_conn() {
        let Ok(dsn) = std::env::var("VERITY_TEST_DSN") else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return;
        };
        use sqlx::postgres::PgPoolOptions;
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect(&dsn)
            .await
            .expect("connect");

        {
            let Some(leader) = WatchLeadership::try_acquire(&pool).await.expect("acquire") else {
                eprintln!("shared-db leader lock already held; skipping");
                return;
            };
            // Bare drop — exercises the close_on_drop fail-safe, NOT release().
            drop(leader);
        }
        // Churn the pool so the next acquire is likely a DIFFERENT physical conn
        // than the one that held the lock — the exact condition that used to see
        // pg_try_advisory_lock return false forever.
        for _ in 0..5 {
            let _: i32 = sqlx::query_scalar("SELECT 1")
                .fetch_one(&pool)
                .await
                .expect("ping");
        }
        let mut regained = None;
        for _ in 0..100 {
            if let Some(g) = WatchLeadership::try_acquire(&pool)
                .await
                .expect("reacquire")
            {
                regained = Some(g);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            regained.is_some(),
            "leadership must be regained after a bare drop — the lock must not leak into the pool"
        );
        if let Some(g) = regained {
            g.release().await;
        }
    }

    /// DSN-gated: the heartbeat writes the observability row on the held
    /// connection.
    #[tokio::test]
    async fn heartbeat_records_holder() {
        let Ok(dsn) = std::env::var("VERITY_TEST_DSN") else {
            eprintln!("VERITY_TEST_DSN not set; skipping");
            return;
        };
        let pool = PgPool::connect(&dsn).await.expect("connect");
        // Ensure the table/row exists (idempotent with the migration).
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
            "INSERT INTO watch_leader (id, holder) VALUES (1, NULL) ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("seed row");

        let Some(mut leader) = WatchLeadership::try_acquire(&pool).await.expect("acquire") else {
            // Another consumer already holds the shared-db lock; skip.
            eprintln!("leader lock already held on this db; skipping heartbeat assertion");
            return;
        };
        leader.heartbeat("test-replica").await.expect("heartbeat");
        let holder: Option<String> =
            sqlx::query_scalar("SELECT holder FROM watch_leader WHERE id = 1")
                .fetch_one(&pool)
                .await
                .expect("read holder");
        assert_eq!(holder.as_deref(), Some("test-replica"));
    }
}
