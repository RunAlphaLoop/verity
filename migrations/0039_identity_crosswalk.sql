-- 0039_identity_crosswalk.sql — M2 slice 2b: canonical-principal registry + crosswalk.
--
-- The canonical principal for a human is the directory-verified Google primary
-- email rendered as the string `user:<primary-email.lower()>` — the EXACT string
-- open_scope tokenizes at mint and Google-native connectors already stamp. These
-- three tables map every non-Google source-local owner id to that same canonical
-- string AT INGEST, feeding the existing upsert_principal_tokens unchanged. There
-- is ONE identity space and ZERO bridge (no `cp_<uuid>`). Recall stays a pure
-- static-int overlap — nothing here touches the read path.
--
-- Invalidate-don't-delete: deprovision/unlink flips `active=false`, never DELETE.
-- No FK constraints (matches the repo's sqlx-runtime, migration-only convention;
-- the app layer enforces referential intent). Writers store `idp_subject`,
-- `alias`, and email-shaped `local_id`s lowercased.

CREATE TABLE canonical_principal (
    tenant_id   uuid    NOT NULL,
    canonical   text    NOT NULL,   -- 'user:alice@corp.com' — a VALID recall subject
    kind        text    NOT NULL,   -- 'user' | 'group'
    idp_subject text    NOT NULL,   -- verified subject; for users = primary email (lower)
    active      boolean NOT NULL DEFAULT true,
    epoch       integer NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, canonical),
    UNIQUE (tenant_id, idp_subject)  -- the no-weld firewall (necessary; see design N4)
);

CREATE TABLE principal_sso_alias (
    tenant_id uuid NOT NULL,
    canonical text NOT NULL,   -- the canonical this alias resolves to
    alias     text NOT NULL,   -- an SSO subject / SAML NameID mapping to this human
    source    text NOT NULL,   -- 'google_customschema' | 'admin_declared'
    UNIQUE (tenant_id, alias)  -- one alias -> one human (under-merge protection)
);

CREATE INDEX principal_sso_alias_canonical_idx
    ON principal_sso_alias (tenant_id, canonical);

CREATE TABLE principal_crosswalk (
    tenant_id   uuid    NOT NULL,
    source      text    NOT NULL,   -- 'salesforce' | 'hubspot' | 'gdirectory' | ...
    local_id    text    NOT NULL,   -- '005ALICE' | '77' | '<dir-id>'
    canonical   text    NOT NULL,
    link_method text    NOT NULL,   -- 'directory_vouched'|'provider_verified'|'admin_explicit'|'email_fallback'
    active      boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant_id, source, local_id)
);

-- Keep resolve_crosswalk O(active rows); mirrors revoked_principal_active_idx (0038).
CREATE INDEX principal_crosswalk_active_idx
    ON principal_crosswalk (tenant_id, source, local_id) WHERE active;
