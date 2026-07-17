-- 0031_backfill_degraded_acl_state.sql — Phase-4: add the 'degraded_acl'
-- terminal state to the backfill_run lifecycle vocabulary.
--
-- A HubSpot backfill can complete a full crawl while the connector's HubSpot
-- app lacks the `crm.objects.owners.read` scope. When that happens the owner
-- roster comes back empty (a 403 on /crm/v3/owners), so owner/team ACLs cannot
-- be materialized and every record falls back to the admin-assigned
-- `--visibility` policy. That is NOT a failure (the crawl delivered every
-- record) and it is NOT a clean success (the fine-grained ACLs were silently
-- coarsened) — surfacing it as `completed` would be a false honesty claim.
--
-- The connector emits a distinct machine-readable signal
-- (`verity.backfill.degraded_acl`) both to stdout and via
-- `BackfillReporter.finish(error=...)`; the server's reap greps the child log
-- for it and reconciles the run to `degraded_acl` (never clobbering it back to
-- `completed`), so the UI can show an honest "owner/team ACLs unavailable —
-- using the admin-assigned visibility policy" badge.
--
-- 0021 pinned the state set with an inline CHECK; a CHECK cannot be widened in
-- place, so this drops and re-adds it with the extra value. Append-only.

ALTER TABLE backfill_run
    DROP CONSTRAINT backfill_run_state_check;

ALTER TABLE backfill_run
    ADD CONSTRAINT backfill_run_state_check CHECK (
        state IN ('running', 'paused', 'completed', 'failed', 'degraded_acl')
    );
