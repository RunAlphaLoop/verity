-- Connector backfill runs (task 49): the bounded, historical initial-sync job
-- that catches a cold source up before the change feed takes over. This is a
-- DIFFERENT shape from connector_status (migrations/0012): that table is an
-- unbounded, monotonic heartbeat counter with no denominator — a liveness
-- signal. A backfill run is a *job* with a beginning and an end: a discovered
-- (or estimated) total, a running processed count, a lifecycle state, and a
-- terminal outcome. That's what a progress bar and an ETA need, and neither is
-- derivable from a heartbeat.
--
-- One row per RUN, keyed by a run_id the orchestration mints when a backfill
-- begins (the same place the cursor lives — Temporal event history, not a
-- file). A source can be backfilled more than once over its life (re-onboard,
-- schema change, full re-sync), so the key is the run, not the source; the
-- dashboard shows the latest run per source and can list history.
--
-- Written best-effort by the ingest side via POST /v1/admin/backfill, exactly
-- like the heartbeat: a failed progress post must never fail (or replay) a
-- sync that already delivered. So processed accumulates reported deltas and can
-- undercount on a missed post — it is telemetry, never an audit ledger. The
-- authoritative row count stays in the L0/L1 rows the ingest endpoints wrote.
-- Append-only migration file.

CREATE TABLE backfill_run (
    -- Run identity, minted by the orchestration at backfill start and threaded
    -- through every progress post for this run (like the cursor).
    id          uuid NOT NULL PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    source      text NOT NULL,
    -- Lifecycle: running → completed | failed, with paused as a reversible
    -- middle state. A CHECK keeps the set honest; the UI colors on it.
    state       text NOT NULL DEFAULT 'running'
                CHECK (state IN ('running', 'paused', 'completed', 'failed')),
    -- Discovered/estimated total items in the backfill window. NULL when the
    -- source can't be cheaply counted up front (many can't) — the dashboard
    -- then shows an indeterminate bar and a raw processed count, never a
    -- fabricated percentage.
    total       bigint,
    processed   bigint NOT NULL DEFAULT 0,
    -- The backfill's own checkpoint, opaque (a Drive pageToken, an ISO
    -- timestamp, a row offset). Display/resume aid; the authoritative cursor
    -- lives in the workflow.
    cursor      text,
    -- Populated only when state = 'failed': the last error, for the operator.
    error       text,
    started_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Latest-run-per-source lookups and history listing both order by start time
-- within a tenant/source.
CREATE INDEX backfill_run_tenant_source_started
    ON backfill_run (tenant_id, source, started_at DESC);
