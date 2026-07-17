-- 0032_backfill_skipped.sql — a `skipped` accumulator on backfill_run.
--
-- The in-process folder initial-scan (folder_watch.rs) reports its progress
-- through the SAME backfill_run pipeline every connector uses, but a folder
-- scan has a third honest number connectors don't surface: files it walked but
-- DECLINED to ingest (over the per-file size cap, hidden/temp/editor-swap, an
-- empty not-yet-flushed read). Those are neither "processed" (never ingested)
-- nor an error (the skip is deliberate and logged) — folding them into
-- `error`/`cursor` text would lie about the shape of both. So this adds a
-- dedicated accumulator, mirroring `processed`: a monotonic count of reported
-- skip deltas, best-effort telemetry (never an audit ledger), so the progress
-- strip can honestly say "N / M files · K skipped (too large / hidden)".
--
-- Backward compatible: every existing run and every connector that never posts
-- a skipped delta keeps skipped = 0. Append-only migration file.

ALTER TABLE backfill_run
    ADD COLUMN skipped bigint NOT NULL DEFAULT 0;
