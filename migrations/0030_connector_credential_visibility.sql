-- 0030_connector_credential_visibility.sql — Phase-4 carry-over: persist the
-- tier-C VISIBILITY policy (a set of principal tokens) for 'bearer' credentials.
--
-- Phase-2 (0028) validated the tier-C visibility set at intake (fail-closed:
-- empty refused) but DISCARDED it — there was no column to hold it, and
-- asserting a sharing scope had been applied when nothing was persisted would
-- have been a false enforcement claim. A Phase-4 browser-triggered HubSpot
-- backfill spawn must resolve `--visibility` from the store (a tier-C backfill
-- with an absent/empty stored visibility fails closed with a 422). This
-- migration persists it.
--
-- The visibility set is a list of PrincipalToken (i32) values — NOT a secret,
-- NOT encrypted (same posture as the path/subject side-fields). It is populated
-- only for 'bearer' rows; a 'path' (Google) credential has no tier-C visibility
-- policy, so a CHECK keeps it NULL there (fail-closed shape parity with the
-- existing kind_shape CHECK). integer[] matches PrincipalToken = i32.
--
-- It does NOT participate in the salted-HMAC `fingerprint` (which covers the
-- secret bytes only) — a visibility-only change intentionally leaves the echoed
-- fingerprint unchanged, exactly like the 0029 subject precedent.
--
-- Append-only migration file.

ALTER TABLE connector_credentials
    ADD COLUMN visibility integer[];

ALTER TABLE connector_credentials
    ADD CONSTRAINT connector_credentials_visibility_shape CHECK (
        kind = 'bearer' OR visibility IS NULL
    );
