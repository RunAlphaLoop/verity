# Verity operations — backup/restore, encryption keys, erasure (v0)

Operational companion to SPEC §8 (deletion, retention & compliance) and
§11b (backup/restore/DR). Everything here describes the **v0 slice** that
actually ships; where the spec promises more than the code does, the gap is
listed explicitly rather than implied away.

## Backup

```
verity-cli backup <dir>
```

What it does:

- Runs `pg_dump -U verity -Fc verity` inside the `verity-postgres` container
  and writes `<dir>/verity-<timestamp>.dump` (custom format, `pg_restore`-able).
- Writes `<dir>/manifest.json` with:
  - `schema_version` — the highest applied sqlx migration in the dumped DB;
  - `created_at` — UTC timestamp;
  - `kek_set` — whether `VERITY_KEK` was set in the backup environment.
    This is an honest hint for the restore runbook, not an attestation about
    the server process: if your server runs with a KEK, run backups from an
    environment that has it too, or fix the flag by hand.

What it does **not** capture (v0):

- **SpiceDB state** (group tuples). Back up SpiceDB's datastore separately;
  SPEC §11b's consistent-ordering protocol (SpiceDB snapshot first, then
  Postgres) is a documented procedure here, not yet tooling-enforced.
- Anything outside Postgres — there is no Lance/S3 tier yet; media blobs
  live in the `media` table and ARE captured by the dump.

Key-table caveat (SPEC §8a): `tenant_deks` rides inside the same dump. The
spec's requirement that key-table backups have a *shorter retention lag* than
data backups (so a destroyed key cannot be resurrected) is an operational
requirement on your backup retention, not something v0 tooling enforces.

## Restore

```
verity-cli restore <file>
```

- Stop the verity server first — live connections can block `--clean` drops,
  and a serving process must never overlap a restore.
- Runs `pg_restore --clean --if-exists` into the container's `verity` DB.
- **SPEC §11b ordering (printed after every restore): ReBAC/SpiceDB state
  must be restored or reconciled BEFORE serving traffic.** Content newer than
  ACLs is permission drift — a leak. The dangerous direction is exactly
  ACL-state-older-than-content; restore/reconcile SpiceDB first, then start
  the server. The server itself boots fail-closed (scope state is
  re-materialized at startup; no in-memory serving state survives), so a
  fresh start after ACL reconciliation is safe by default.
- If `manifest.json` says `kek_set: true`, the same `VERITY_KEK` must be
  present at restore or every encrypted L0 payload and wrapped tenant DEK in
  the dump is permanently unreadable. That property is also the point:
  see crypto-shredding below.

## Envelope encryption & the KEK (SPEC §8a, v0)

- `VERITY_KEK` = 64 hex chars (32 bytes). Generate:
  `openssl rand -hex 32`.
- With the KEK set: each tenant gets a lazily provisioned 32-byte DEK
  (`tenant_deks`), stored AES-256-GCM-wrapped under the KEK; new L0 episode
  payloads are stored AES-256-GCM under the tenant DEK in
  `episodes.payload_enc`, with `payload = '{}'::jsonb` as a sentinel. Reads
  that need a payload (DSAR export, forensics) decrypt on demand
  (`PostgresAdapter::episode_payload`); the serving read path never reads L0
  payloads, so recall latency is unaffected.
- Without the KEK: a startup warning fires
  (`at-rest envelope encryption disabled — set VERITY_KEK`), DEKs are stored
  as plaintext bytes (length is the wrap marker: 32 = plaintext,
  longer = wrapped), and payloads stay plaintext jsonb.
- **v0 encryption coverage, stated honestly:** episode payloads written via
  `append_episode` (agent observations, CDC envelopes, webhook payloads,
  document-version metadata). NOT yet encrypted: episodes written inline by
  `record_action` and `publish_knowledge`, chunk/fact plaintext projections
  (they are hard-purged by lineage instead), `media.bytes`, and
  `quarantine_preview.payload`. DEK granularity is per-tenant, not yet
  per-data-subject/per-source.

### KEK rotation (v0 stance: offline re-wrap, documented not automated)

1. Stop the server.
2. For every `tenant_deks` row: unwrap `dek` with the old KEK, re-wrap with
   the new KEK, UPDATE the row (a ~20-line operator script against the DB;
   episode ciphertexts do NOT need rewriting — only DEKs are wrapped).
3. Start the server with the new `VERITY_KEK`.
4. Old backups remain readable only with the old KEK — keep it in escrow
   until every backup taken under it has aged out.

Turning encryption ON for an existing deployment encrypts **new** episodes
only; historical plaintext rows keep their plaintext payload (re-encryption
backfill is future work). Plaintext-stored DEKs from a KEK-less era remain
plaintext until rotated by the same offline procedure.

## Erasure (`POST /v1/admin/erasure`) — the GDPR path

```
POST /v1/admin/erasure          (admin bearer token)
{ "tenant_id": "...", "subject": "user:jane@corp.example" }   // and/or "entity": "contact:jane@corp.example"
```

Distinct from `memory.forget` (SPEC §8f): forget is scope-bound
*invalidation* (rows survive with `valid_to`); erasure is an admin-only,
lineage-driven **hard DELETE** in one transaction, never reachable from an
agent scope handle. Returns per-table counts.

What subject erasure removes: episodes with `writer_sub = subject`; the
chunks and facts derived from those episodes (by provenance); the subject's
actions (`actor_sub`) and their L0 provenance episodes; knowledge-evidence
rows from those episodes — with a support recount that invalidates published
items falling below the k=3 floor and retires their retrieval chunks;
quarantine-preview payloads containing the subject string; the subject's own
audit rows.

Entity erasure additionally removes: facts keyed on the entity, and **every
chunk tagged with the entity — multi-tag chunks are deleted whole, never
tag-stripped** (conservative over-deletion: a shared chunk that mentions the
erased entity goes away for everyone).

One audit row survives per erasure: `verb = 'erasure'`, the per-table counts,
and sha256 hashes of the subject/entity — no plaintext identifiers.

**What erasure does NOT cover yet (v0, honest list):**

- **SpiceDB tuples** — group memberships naming the subject must be removed
  via `DELETE /v1/admin/groups` / SpiceDB directly.
- **Media blobs** (`media` table) — no subject attribution exists on media
  rows yet; purge manually if a blob is subject-attributable.
- `freshness_samples` — telemetry only; carries source names and timestamps,
  no subject data (documented n/a).
- Other actors' audit rows whose `result_ids` reference now-deleted rows —
  the ids are opaque UUIDs with no payload (the SPEC §8b "skeleton").
- Per-subject **crypto-shredding**: DEKs are per-tenant in v0, so erasure is
  the hard-delete walk above, not key destruction. Deleted rows age out of
  PITR/backups per your backup retention window — state that window in any
  erasure commitment (SPEC §8b default language: purge time + retention,
  35 days).
- The entity/subject match is exact-string (`writer_sub`, `source_entity`,
  tags); alias resolution (§7f) does not exist yet — erase each known alias.

## DSAR export (`GET /v1/admin/dsar/export`)

```
GET /v1/admin/dsar/export?tenant_id=...&subject=user:jane@corp.example   (admin bearer token)
```

One JSON bundle: the subject's L0 episodes (payloads **decrypted** under
admin authority — the export itself writes a `dsar_export` audit row), the
chunks derived from them, the subject's actions, their access-event skeleton
from the audit log, and knowledge items they proposed. Same exact-string
subject matching caveat as erasure.
