-- 0033_sync_schedules.sql — durable continuous-sync schedules (Phase-4).
--
-- Continuous sync is a per-(tenant, source) SCHEDULER that fires a SHORT-LIVED
-- incremental "--once" poll cycle on a fixed interval — NOT a persistent
-- long-running child. This table is the DURABLE record of which (tenant, source)
-- pairs have continuous sync armed and at what cadence, so the server can re-arm
-- every enabled schedule on boot (like folder_watches re-establishes watches).
--
-- The AUTHORITATIVE cursor is NOT here — it lives in the connector's own
-- per-(tenant, source) state file (see the server's poll-cursor dir). This table
-- only records the SCHEDULE (interval + enabled) and a lightweight last-run
-- stamp; connector_status carries the opaque cursor for display.
--
-- Enabling/disabling is durable: the row persists across a Stop (enabled=false)
-- for audit/history, exactly like folder_watches keeps a stopped watch. A hard
-- delete is not modelled — a schedule is operator config, toggled, never a ledger.
--
-- INTERVAL FLOOR (CHECK interval_secs >= 60): continuous sync must never hammer a
-- source API / trip rate limits. 60s is the hard floor enforced at the DB; the
-- server default is a saner 300s. The CHECK makes a sub-floor interval
-- unrepresentable, so no code path (boot re-arm, toggle, a hand-written row) can
-- ever arm a scheduler tighter than the floor.
--
-- Append-only migration file.

CREATE TABLE sync_schedules (
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    -- The connector source this schedule polls: gdrive / gmail / hubspot. (The
    -- gdirectory continuous plane and the always-on folder watcher are NOT
    -- scheduled here — they have their own planes.) Text, not an enum, to match
    -- the connector_status / connector_credentials source-column convention.
    source       text NOT NULL,
    -- Poll cadence in seconds. NOT NULL — a schedule always has a concrete
    -- interval. CHECK floors it at 60s (rate-limit guard); 300s is the sane
    -- server default the toggle applies when the caller omits one.
    interval_secs integer NOT NULL,
    -- Soft on/off: a disabled schedule stays in the table (durable audit) but is
    -- NOT re-armed on boot and does not fire. Defaults false so a freshly
    -- inserted row is inert until the toggle explicitly enables it.
    enabled      boolean NOT NULL DEFAULT false,
    -- Lightweight last-run stamp: when the most recent --once poll cycle for this
    -- (tenant, source) was fired. Display-only ("last synced 4m ago"); the
    -- authoritative cursor is the connector state file, not this column. NULL
    -- until the first cycle runs.
    last_run_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    -- One schedule per (tenant, source): the toggle upserts on this key, so a
    -- second enable rotates the interval in place rather than stacking rows.
    UNIQUE (tenant_id, source),
    CONSTRAINT sync_schedules_interval_floor CHECK (interval_secs >= 60)
);

-- Boot re-arm scans enabled schedules across all tenants.
CREATE INDEX sync_schedules_enabled_idx ON sync_schedules (enabled) WHERE enabled;
