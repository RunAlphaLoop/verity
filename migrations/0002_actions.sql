-- Action records: the cross-agent activity timeline (SPEC §2, v1.2).
-- Append-only events — no supersession, no updates. The actor identity is
-- stamped by the server from the authenticated token, never client-supplied.

CREATE TABLE actions (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    action_id       text NOT NULL,        -- client idempotency key
    actor_sub       text,                 -- user principal
    actor_azp       text,                 -- agent identity
    action_type     text NOT NULL,        -- namespaced verb: "quote.issued", "email.sent"
    entities        text[] NOT NULL,      -- target entity tags (⊆ writing scope's entity_scope)
    summary         text NOT NULL,
    payload         jsonb NOT NULL DEFAULT '{}',
    outcome         text NOT NULL,        -- succeeded | failed | pending
    occurred_at     timestamptz NOT NULL, -- event time
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    visibility      int[] NOT NULL,       -- same fail-closed semantics as chunks
    confidentiality smallint NOT NULL DEFAULT 1,
    provenance      uuid NOT NULL REFERENCES episodes(id),
    UNIQUE (tenant_id, action_id)
);

CREATE INDEX actions_entities_idx ON actions USING gin (entities);
CREATE INDEX actions_timeline_idx ON actions (tenant_id, occurred_at DESC);
CREATE INDEX actions_type_idx ON actions (tenant_id, action_type text_pattern_ops);
