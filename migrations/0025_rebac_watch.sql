-- SpiceDB Watch cursor (SPEC §7b watch-driven materialization, opt-in via
-- VERITY_SPICEDB_WATCH=1 — see crates/verity-server/src/rebac_watch.rs).
-- Single row: the last ZedToken (`changesThrough.token`) whose deltas were
-- fully materialized as revocation tombstones. The cursor advances only AFTER
-- a frame's tombstones are durably recorded, so a crash replays the frame;
-- replay is safe because tombstone insertion is additive/over-hiding (and
-- deduped by a short recent-token window). On an unresumable cursor
-- (datastore GC'd the revision) the consumer treats it as a GAP — latches
-- degraded, clears this row, resumes from head — never a silent fresh start.
--
-- v0.1 posture: one server process consumes the watch. Multiple replicas
-- would contend on this row harmlessly (last-writer-wins, replay-safe), just
-- redundantly.
CREATE TABLE rebac_watch_cursor (
    id         int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    token      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
