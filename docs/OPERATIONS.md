# Verity operations — backup/restore, encryption keys, erasure, ingest orchestration (v0)

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
- **Encryption coverage (v0.2), stated honestly:** ALL episode payloads —
  every insert into `episodes` flows through one shared encrypted path
  (`PostgresAdapter::insert_episode_tx`): `append_episode` (agent
  observations, CDC envelopes, webhook payloads, document-version metadata),
  `record_action` (the serialized action provenance episode), and
  `publish_knowledge` (the publish provenance episode). NOT yet encrypted:
  chunk/fact plaintext projections (they are hard-purged by lineage instead),
  `media.bytes`, and `quarantine_preview.payload`. DEK granularity is
  per-tenant, not yet per-data-subject/per-source.

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
                                                              // and/or "media_ids": ["<uuid>", ...]
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

**SpiceDB tuples (v0.2):** when ReBAC is configured (`VERITY_SPICEDB_URL`)
and the subject is a `user:` principal, the subject's relationship tuples
are deleted from SpiceDB **before** the storage purge. Ordering is
fail-closed by construction: a tuple-delete failure aborts the whole erasure
with 502 and nothing is purged — at worst the retry over-retains for a
while; the reverse order could leave a purged subject still granting group
membership after a partial failure. Without ReBAC (or for non-`user:`
subjects, which have no SpiceDB object) the response reports
`rebac_tuples_deleted: false` and tuples must be removed via
`DELETE /v1/admin/groups` / SpiceDB directly.

**Media blobs (v0.2):** media rows carry no subject attribution, so erasure
never *walks* to them — the operator names them: list candidates with
`GET /v1/admin/media?tenant_id=` (id, filename, sha256, size, created;
metadata only) and pass the subject-attributable ids as `media_ids` on the
erasure request. Named blobs are hard-deleted in the same transaction,
tenant-checked (a foreign or unknown id deletes nothing and shows up as a
shortfall in the returned `media` count).

One audit row survives per erasure: `verb = 'erasure'`, the per-table counts,
and sha256 hashes of the subject/entity — no plaintext identifiers.

**What erasure does NOT cover yet (v0, honest list):**

- **Automatic media discovery** — `media_ids` is operator-named; nothing
  links a blob to a subject server-side yet. Chunks derived from text-like
  media ARE walked (by episode provenance) when the uploader is the erased
  subject, but the blob itself must be named explicitly.
- `connector_status` / `freshness_samples` — telemetry only; carries source names and timestamps,
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

## Ingest orchestration (Temporal) — durable connector scheduling

Operational companion to SPEC §5: "the ingest plane … runs on durable
execution; **Temporal is mandatory before the managed connector fleet
ships**." This replaces running the connectors' `--once` runners under cron.
The connector code itself is unchanged — orchestration wraps the existing
`poll()` + sink classes; the one behavioral difference is that **the cursor
lives in Temporal workflow state, not in `.verity/*_cursor` files**.

### Dev vs production Temporal (read this first)

`deploy/docker-compose.yml` ships a `temporal` service running the
single-binary **dev server** (`temporalio/temporal` CLI image,
`temporal server start-dev`): gRPC on `localhost:7233`, Web UI on
`http://localhost:8233`. It keeps state in memory and **loses all workflow
history on restart — by design**. That is safe here because nothing critical
lives only in Temporal: on a lost chain the Schedule restarts the workflow
with `cursor=None` and the connectors replay (HubSpot/Salesforce from epoch
into deterministic keyed L1 upserts; Drive re-arms its change feed and the
reconciliation crawl covers the gap). At-least-once, never silent loss.

**Production deployments run a real Temporal cluster** — self-hosted
(`temporalio/auto-setup` or Helm, backed by a durable Postgres/Cassandra
datastore) or Temporal Cloud. The dev server is single-process,
unreplicated, and unsupported for production by Temporal themselves. Point
`TEMPORAL_ADDRESS`/`TEMPORAL_NAMESPACE` at the cluster; nothing else changes.

### Running the worker

```
pip install 'verity-ingest[orchestration]'          # temporalio SDK (optional extra)
docker compose -f deploy/docker-compose.yml up -d temporal

export TEMPORAL_ADDRESS=localhost:7233              # default
export VERITY_CONNECTORS=hubspot,salesforce         # EMPTY by default: enabling a sync is explicit
export VERITY_SYNC_INTERVAL=300                     # seconds; per-connector: VERITY_SYNC_INTERVAL_HUBSPOT=60
export HUBSPOT_PRIVATE_APP_TOKEN=... HUBSPOT_VISIBILITY=1,2      # connector's own env contract
export VERITY_TENANT_ID=<tenant uuid> VERITY_URL=http://127.0.0.1:7717

python -m verity_ingest.orchestration.worker
```

The worker registers `ConnectorSyncWorkflow` + the poll-cycle activity on
task queue `verity-ingest` (`VERITY_TASK_QUEUE`). Run more workers on the
same queue to scale horizontally. Visibility policies stay fail-closed:
`HUBSPOT_VISIBILITY` / `SALESFORCE_VISIBILITY` are required, no default.

### Applying schedules

```
python -m verity_ingest.orchestration.schedules             # dry-run: prints the plan
python -m verity_ingest.orchestration.schedules --apply     # create/update
```

One Temporal Schedule per enabled connector (`verity-sync-<connector>`,
overlap policy SKIP). The workflow itself loops durably — activity → cursor
into workflow state → sleep interval → continue-as-new — so the Schedule is
a supervisor: it starts the chain and restarts it if it ever dies; while the
chain is alive every tick is skipped. Re-run `--apply` after changing
intervals; it updates in place.

### What happens on failure

- A poll or delivery failure fails the **activity attempt**; Temporal
  retries it with exponential backoff (5s initial, ×2, capped at 5 min,
  unlimited attempts — a dead credential should page via connector-status
  staleness, not silently drop the sync).
- The cursor advances **only after sink delivery succeeds**: the activity
  returns the next cursor last, so every retry re-polls the same window.
  At-least-once into deterministic keyed upserts; a window is never skipped.
- Config errors (missing visibility policy, unknown connector) are
  **non-retryable** — they surface immediately in the workflow instead of
  burning a backoff loop on an operator omission.
- Activities heartbeat per page/delivery; a 2-minute heartbeat gap fails the
  attempt (hung SaaS call), and the retry takes over.
- Watch it all in the dev UI: `http://localhost:8233`.

### One-off smoke test (no schedule)

```
temporal workflow execute --task-queue verity-ingest --type ConnectorSyncWorkflow \
  --workflow-id connector-sync-hubspot-once \
  --input '{"connector": "hubspot", "max_cycles": 1}'
```

`max_cycles: 1` is the `--once` equivalent: one poll cycle, returns the
resulting cursor, no sleep, no continue-as-new.

## Consolidation plane (sleep-time L2 extraction + knowledge, v0.3)

The consolidation worker is the async plane that turns unstructured L0
episodes into structured memory (SPEC §2 L2, knowledge items, §7d tagging).
It runs in the trusted server plane — like connectors, it is not an agent and
has no conversational output channel.

### Loop

```
python3 -m verity_ingest.consolidation \
  --base-url http://127.0.0.1:7717 --tenant-id <uuid> \
  --extractor deterministic          # or: anthropic (needs ANTHROPIC_API_KEY)
```

`--once` does a single lease → extract → complete pass (tests, cron). The
admin token rides `--admin-token` or `$VERITY_ADMIN_TOKEN`.

- `POST /v1/admin/consolidation/lease {tenant_id, limit}` hands out
  unprocessed **non-CDC** episodes (observation / webhook / doc_version) with
  payloads decrypted, leased 5 minutes. CDC episodes are skipped by
  construction: their L1 extraction is deterministic at ingest (SPEC §2 L1 —
  structured data never goes through LLM extraction).
- `POST /v1/admin/consolidation/complete` writes the extraction. Completing
  twice is an acknowledged no-op (`already_processed`), so crashed workers
  just retry after lease expiry.

### What complete() writes

- **L2 facts** become deterministic bi-temporal upserts under source `l2`,
  keyed `(l2, normalized subject, normalized relation)` — same-key writes
  supersede structurally, exactly like L1. Read them back via
  `GET /v1/records/l2/<subject>/<relation>`.
- **Tag suggestions** (SPEC §7d probabilistic tags) land in a review queue:
  `GET /v1/admin/tag-suggestions`, `POST /v1/admin/tag-suggestions/{id}/approve`.
  **Suggest-only is the default.** `VERITY_AUTO_TAG=1` applies suggestions at
  confidence >= 0.9 immediately (acl_provenance/visibility untouched) — note
  that adding a tag WIDENS what entity-bound scopes can retrieve, which is why
  the default posture is human review.
- **Knowledge candidates** go through the existing propose_knowledge gate,
  after the Phase-2 merge cascade (`knowledge-merge-tuning.md` §2): a candidate
  accrues its evidence onto an existing item ONLY via (1) the deterministic
  **canonical-exact** fast path (byte-identical `canonical_statement`, no
  embedding/LLM cost) or (2) a worker-supplied **judged** `merge_into` the
  server validates and records (with its reason). The old bare cosine
  auto-merge (τ=0.85) is **removed** — a false merge fabricates cross-customer
  support. On crossing k-support the item becomes **eligible** (auto-publish
  OFF, the default) or is auto-published through the gate (opt-in). See
  "Knowledge consolidation: trust & controls" below for the full control set.

### Extractors

`DeterministicExtractor` (default, used by all tests) is regex/rule-based:
"X is Y" sentences, "key: value" lines, entity-name echo into tag suggestions
at 0.95, and a knowledge candidate for sentences carrying a generalization
marker ("always", "consistently", "customers … tend"). `AnthropicExtractor`
is the LLM seam behind `ANTHROPIC_API_KEY` (Messages API, strict-JSON
structured outputs); without the key it refuses to construct and the
deterministic extractor is the honest fallback.

## Knowledge consolidation: trust & controls (v0.3, Phase 3)

Auto-derived, cross-customer knowledge is the most trust-sensitive thing
Verity does — the knowledge layer is how the organization *learns across
customers without one customer's specifics reaching another*. This section is
the operator/buyer-facing statement of the controls (design:
`docs/design/knowledge-merge-tuning.md` §5). Everything here is enforced in
code and covered by DSN-gated tests.

### What is never automatic (the load-bearing promises)

1. **Publishing is never automatic on the read path.** Merging only accrues
   *candidate* support. Crossing k-support (≥3 distinct entities, default) makes
   an item **eligible for review** — a new `eligible` status between `candidate`
   and `published` — not published. Nothing an agent reads is ever the trigger
   for a publish.
2. **Auto-publish is opt-in, default OFF.** With the default posture, an
   eligible item **waits** for a human (or an explicitly configured policy) to
   call the publish endpoint. `POST /v1/knowledge/{id}/publish` (admin bearer)
   stays the human gate; it enforces k-support + corroboration + de-id before it
   mints the retrievable §7g carve-out chunk. **The OSS build ships OFF.**
3. **No judged merge is authoritative without the judge's recorded reason.**
   Every worker-judged merge stores the LLM's rationale (`merge_reason`) and is
   auditable/reversible; the deterministic canonical-exact merge needs no judge.

### Auto-publish opt-in (per tenant)

Auto-publish is a per-tenant setting in the `settings` table (key
`knowledge_auto_publish`, absent = OFF):

```
-- opt a tenant in (background/admin path may then auto-publish through the gate)
INSERT INTO settings (tenant_id, key, value)
VALUES ('<tenant-uuid>', 'knowledge_auto_publish', 'true')
ON CONFLICT (COALESCE(tenant_id,'00000000-0000-0000-0000-000000000000'::uuid), key)
DO UPDATE SET value = 'true';

-- the audience auto-publish uses (required when ON; comma-separated principal tokens)
INSERT INTO settings (tenant_id, key, value)
VALUES ('<tenant-uuid>', 'knowledge_auto_publish_visibility', '7,9') ...;
```

When ON, a candidate that crosses **all** gates (k-support, corroboration,
de-id) is promoted through the **same** publish gate on the async worker/admin
path — **still never on the read path**. If no default visibility is configured,
the item is held `eligible` rather than published to an unknown audience
(fail-safe). When OFF (the default), it becomes `eligible` and waits.

### Kill switch — `VERITY_KNOWLEDGE_AUTO_MERGE`

Default ON. Set to `0` to disable the worker-judged merge leg entirely: the
server then **ignores worker-supplied `merge_into`**, and only the deterministic
canonical-exact fast path can merge. Consolidation degrades to
assisted/human-clustered — candidates queue for human review — **never a silent
judged merge**. A false merge fabricates cross-customer support (the governing
asymmetry: a false merge is far worse than a missed one), so this is the
emergency stop for the semantic-merge leg. The canonical-exact merge and every
gate keep working under the kill switch.

### Support-tier disclosure (buckets, never exact counts)

Published/eligible items carry a **bucketed support tier**, derived from the
distinct-entity count:

| tier | distinct entities |
|---|---|
| `emerging` | 3–4 |
| `established` | 5–9 |
| `extensive` | 10+ |

A consuming agent sees only the **tier** on `kind=knowledge` recall hits
(`support_tier`), so it can weight the knowledge without a false precision.
**Exact `distinct_entities` counts are admin-only** — they appear on the
admin review surfaces (`GET /v1/knowledge`, `GET /v1/admin/knowledge/{id}`) but
never on a scoped recall hit, to blunt membership inference (SPEC §2). The tier
on the carve-out chunk is recomputed as support accrues (emerging → established
→ extensive).

### Review surfaces (admin bearer-gated)

- `GET /v1/knowledge?tenant_id=&status=` — the review queue. Per item: status,
  admin-exact `distinct_entities`, bucketed `support_tier`, the judge's
  `merge_reason`, corroboration signals, and the evidence episode/entity list.
- `GET /v1/admin/knowledge/{id}?tenant_id=` — full detail for one item: the
  above plus the **de-identification gate result** (passed + reason).
- `POST /v1/admin/knowledge/{id}/reject {tenant_id, reason}` — a reviewer
  refuses a candidate/eligible item. **Rejection is remembered:** status becomes
  `rejected` and the same `canonical_statement` will not resurface as a fresh
  candidate — the propose path returns the remembered rejected row unchanged.
  (Rejecting a *published* item is refused; retraction is `memory.forget`'s job,
  which runs the k-support recount + auto-invalidation cascade.)
- The read-only `/ui` "Knowledge review" panel lists candidates/eligible/
  published with status badge, support tier, merge reason, and evidence count.
  It is a pure inspector — approve/reject are documented API/CLI actions, never
  buttons on the page.

### The one-paragraph stance for a security review

*Verity learns patterns across your customers but never lets one customer's
specifics reach another. Generalizations are de-identified deterministically,
must be independently supported by ≥3 distinct customers, are judged for
sameness by a model whose reasoning is recorded and auditable, and are never
published without human approval — which is off by default. A wrong
generalization is structurally harder to publish than a real one is, and both
are fully reversible.*
