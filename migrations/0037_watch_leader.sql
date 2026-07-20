-- 0037_watch_leader.sql — leader election observability for the rebac-watch
-- consumer. The election MECHANISM is a SESSION-level advisory lock
-- (pg_try_advisory_lock(hashtext('verity_rebac_watch_cursor'))) held on a
-- dedicated connection for the consumer's lifetime; only the lock holder
-- connects the Watch stream and advances rebac_watch_cursor. This makes the
-- single-row cursor safe on >1 replica (removes the "two consumers go quietly
-- blind" invariant documented in migration 0025 / rebac_watch.rs).
--
-- This table is OBSERVABILITY ONLY (who leads, last heartbeat) — the advisory
-- lock, not this row, is the source of truth for leadership. Follower replicas
-- poll-retry the lock on their reconnect backoff and take over automatically
-- when the leader's session lock auto-releases (process death / connection loss).
--
-- Design-forward for M4 HA: a future totally-ordered changelog spine swaps the
-- lock source (WatchLeadership::try_acquire) WITHOUT touching the cursor
-- contract or rebac_watch::run.
CREATE TABLE watch_leader (
    id           integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    holder       text,
    heartbeat_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO watch_leader (id, holder) VALUES (1, NULL) ON CONFLICT (id) DO NOTHING;
