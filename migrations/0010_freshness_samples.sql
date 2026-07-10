-- Freshness SLO samples (roadmap task 21): one row per ingested event,
-- pairing the event's source-side timestamp (event_at) with the moment it
-- became queryable in Verity (queryable_at, stamped by the database clock at
-- insert — i.e. after the L0/L1/chunk writes committed). The SLO endpoint
-- computes p50/p95 of (queryable_at - event_at) per source with
-- percentile_cont. Telemetry plane: written by the debezium ingest handler
-- and the webhook receiver, best-effort (a failed sample never fails the
-- ingest). Append-only migration file.

CREATE TABLE freshness_samples (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    source       text NOT NULL,
    event_at     timestamptz NOT NULL,
    queryable_at timestamptz NOT NULL DEFAULT now()
);
-- The SLO query: samples for a tenant (optionally one source) in a window.
CREATE INDEX freshness_samples_window_idx
    ON freshness_samples (tenant_id, source, queryable_at DESC);
