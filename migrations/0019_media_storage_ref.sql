-- Task #47: move media blobs off Postgres bytea to S3-compatible object
-- storage. A media row is now EITHER inline bytea (dev-grade, the pre-existing
-- path) OR an external object referenced by `storage_ref` (the object key in
-- the configured bucket, e.g. `media/<tenant>/<sha256>`). Append-only.
--
-- Both columns are nullable and the CHECK enforces exactly-one-of: legacy rows
-- keep their bytea (bytes NOT NULL historically); new rows written while an
-- object store is configured carry storage_ref and NULL bytes. The signed-URL
-- scheme is unchanged — storage_ref changes only where the bytes physically
-- live, never how a blob is addressed or authorized.

ALTER TABLE media ALTER COLUMN bytes DROP NOT NULL;
ALTER TABLE media ADD COLUMN storage_ref text;

-- Exactly one backing store per row: inline bytea xor an external object key.
ALTER TABLE media
    ADD CONSTRAINT media_backing_one_of
    CHECK ((bytes IS NULL) <> (storage_ref IS NULL));
