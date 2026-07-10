-- Connector heartbeat/status (v0.2 observability): one row per
-- (tenant, source), upserted by POST /v1/admin/connector-status. Written
-- best-effort by the ingest sinks after each delivery batch — a failed
-- heartbeat never fails a sync, so this table is telemetry, not a ledger:
-- items_synced accumulates the batch deltas the sinks report and can
-- undercount (missed heartbeats), never the reverse. Append-only migration
-- file.

CREATE TABLE connector_status (
    tenant_id     uuid NOT NULL REFERENCES tenants(id),
    source        text NOT NULL,
    -- The connector's own checkpoint (opaque: ISO timestamp for HubSpot/
    -- Salesforce, a Drive pageToken for gdrive). Display/debugging only —
    -- the authoritative cursor stays in the connector's state file.
    cursor        text,
    items_synced  bigint NOT NULL DEFAULT 0,
    -- Source-side timestamp of the newest event delivered (drives the
    -- staleness coloring in /ui). NULL until a batch carries one.
    last_event_at timestamptz,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source)
);
