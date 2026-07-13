-- 0027_folder_watches.sql — persistent local-folder watches (ingest write-path).
--
-- The dev server runs on the operator's own machine, so a "watch this folder,
-- turn dropped files into memory" capability belongs SERVER-SIDE: the browser
-- can't reach the filesystem, the local server can. This table is the durable
-- config the server re-establishes on boot; the watcher itself (folder_watch.rs)
-- runs in-process and ingests via the same choke point as POST /v1/ingest/documents.
--
-- Fail-closed (SPEC §5e, non-negotiable): a watch MUST be created with an
-- explicit visibility policy — the principal tokens allowed to see files from
-- this folder. There is NO permissive default; `visibility = '{}'` is a
-- deliberate "nobody can read these", still a policy, never "everyone".
-- acl_provenance is admin-assigned (the operator declared who can see it),
-- mirroring the manifest/connector bound-policy pattern.
--
-- Append-only migration file.

CREATE TABLE folder_watches (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    -- Human-facing label; the connector_status / freshness source is
    -- "folder:<name>" so the folder shows up live in Sources & Freshness
    -- exactly like any other source. Unique per tenant so "folder:<name>"
    -- is an unambiguous source key.
    name            text NOT NULL,
    -- Absolute filesystem path the server watches. Server-local (the machine
    -- running verity), never browser-side.
    path            text NOT NULL,
    -- Materialized principal-token set: who can see files ingested from this
    -- folder. Empty = invisible to scoped reads (fail closed), never permissive.
    visibility      int[] NOT NULL,
    -- 0 public / 1 internal / 2 confidential / 3 restricted — identical to
    -- chunks/facts. Files from a folder default to Internal at the UI.
    confidentiality smallint NOT NULL DEFAULT 1,
    -- High-water mark for boot re-scan: on restart the watcher re-scans the
    -- folder and ingests anything whose mtime is newer than last_seen (files
    -- dropped while the server was down), then re-arms the live watch. NULL
    -- until the first scan completes.
    last_seen       timestamptz,
    -- Soft-stop: a stopped watch stays in the table (audit/history) but is not
    -- re-armed on boot and drops live events. "Stop" is a no-op on already-
    -- ingested memory (invalidate-don't-delete): stopping a watch never forgets.
    active          boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

-- Boot re-establishment scans active watches across all tenants.
CREATE INDEX folder_watches_active_idx ON folder_watches (active) WHERE active;
