-- 0028_connector_credentials.sql — Phase-2 connector secret intake (encrypt-at-rest).
--
-- BYOT (bring-your-own-token) credential store for the ingest connectors. Two
-- kinds live here, keyed one row per (tenant, source):
--
--   'bearer' — a tier-C static bearer token (HubSpot Service Key / legacy
--     private-app token; later Salesforce). Stored as AES-256-GCM CIPHERTEXT
--     under the tenant DEK (the SAME envelope used for L0 payloads, crypto.rs):
--     `ciphertext` carries nonce(12) || ciphertext+16-byte tag; `path` is NULL.
--     Storing a bearer HARD-REFUSES when VERITY_KEK is unset, or when the tenant
--     DEK is plaintext-provenance (stored length <= 32) — a secret is never
--     written warn-and-plaintext, unlike the L0 path which tolerates a no-KEK dev
--     deployment. This is the non-negotiable encrypt-at-rest contract.
--
--   'path' — a tier-A Google service-account key FILE PATH (all three Google
--     connectors read GOOGLE_APPLICATION_CREDENTIALS). The path is NOT a secret;
--     `path` holds it verbatim and `ciphertext` is NULL. No crypto.
--
-- `fingerprint` is a SALTED-HMAC prefix of the secret (bearer) / path (path),
-- computed under VERITY_SCOPE_KEY — NEVER a bare sha256 of the plaintext (that
-- would be a confirmation oracle). It is the only thing ever echoed back; the
-- secret itself is never returned by any read.
--
-- Append-only migration file.

CREATE TABLE connector_credentials (
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    -- Connector source key: 'hubspot' / 'salesforce' (bearer),
    -- 'gdrive' / 'gmail' / 'gdirectory' (path). One credential per source.
    source     text NOT NULL,
    -- 'bearer' → encrypted-at-rest secret in `ciphertext`; 'path' → file path
    -- in `path`. A CHECK enforces the column that must be populated per kind.
    kind       text NOT NULL,
    -- AES-256-GCM(secret) under the tenant DEK: nonce(12) || ciphertext+tag.
    -- Populated for 'bearer', NULL for 'path'.
    ciphertext bytea,
    -- Google SA-key file path (not a secret). Populated for 'path', NULL for
    -- 'bearer'.
    path       text,
    -- Salted-HMAC prefix (VERITY_SCOPE_KEY) of the secret/path — the only value
    -- ever echoed back to an operator. Never the plaintext, never a bare hash.
    fingerprint text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source),
    CONSTRAINT connector_credentials_kind_shape CHECK (
        (kind = 'bearer' AND ciphertext IS NOT NULL AND path IS NULL) OR
        (kind = 'path'   AND path IS NOT NULL AND ciphertext IS NULL)
    )
);
