-- 0029_connector_credential_subject.sql — Phase-3 carry-over: persist the
-- non-secret per-source impersonation SUBJECT for Google 'path' credentials.
--
-- Phase-2 (0028) stored only the SA-key file path for a Google connector and
-- validated-then-DISCARDED the domain-wide-delegation subject at intake. A
-- Phase-3 browser-triggered backfill spawn must resolve `--subject` for gmail
-- (hard-required) and optionally gdrive. The only prior source of a subject was
-- the server env var (VERITY_GDIRECTORY_SUBJECT), so a store-backed spawn had no
-- subject at all. This migration persists it.
--
-- The subject is a Workspace admin address for domain-wide-delegation
-- impersonation — NOT a secret, NOT encrypted (same posture as the path). It is
-- populated only for 'path' rows; a 'bearer' credential has no impersonation
-- subject, so a CHECK keeps it NULL there (fail-closed shape parity with the
-- existing kind_shape CHECK). Nullable even for 'path' (gdrive subject is
-- optional; a service account can be granted directly on shared drives).
--
-- It does NOT participate in the salted-HMAC `fingerprint` (which covers the
-- path bytes only) — a subject-only change intentionally leaves the echoed
-- fingerprint unchanged.
--
-- Append-only migration file.

ALTER TABLE connector_credentials
    ADD COLUMN subject text;

ALTER TABLE connector_credentials
    ADD CONSTRAINT connector_credentials_subject_shape CHECK (
        kind = 'path' OR subject IS NULL
    );
