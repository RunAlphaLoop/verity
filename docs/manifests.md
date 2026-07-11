# Source manifests: connectors are config

A source manifest (SPEC §5e.3) turns any system that can POST JSON into a
Verity source with a reviewable YAML file — no connector code, no vendor
OAuth app. The manifest is **data, not code**: the Rust runtime
(`crates/verity-manifest`) interprets it with hard evaluator limits and a
fail-closed ACL gate; nothing in a manifest can execute.

One manifest serves both lanes: `webhook` (freshness, executed today) and
`poll` (reconciliation backstop — **parse-and-store only in v0**, no poll
executor runs yet; SPEC §5e.7 schedules it).

The shipped, fixture-verified example is [`examples/linear.yaml`](../examples/linear.yaml).

## Lifecycle

```
upload (draft) ──► activate (THE human gate) ──► bind to a minted webhook ──► deliveries
      │                    │                              │
  schema-validated    refused unless the           inbound payloads route
  yaml, stored        acl_policy exists and        through the manifest
  verbatim            matches the declared tier    runtime; anything the
                                                   runtime can't claim →
                                                   quarantine_preview
```

1. `POST /v1/manifests` (admin) — `{tenant_id, yaml}`. Validates with
   `verity-manifest` and stores a **draft**. Re-uploading the same
   `source.name` replaces the YAML and demotes it back to draft: every edit
   re-crosses the human gate.
2. `POST /v1/manifests/{id}/activate` (admin) — `{tenant_id, approved_by}`.
   The human gate. Refuses (422) when `acl_policy` is absent or violates the
   declared tier contract. The approval is stored on the row and recorded in
   `audit_log` (`verb = manifest_activate`).
3. `GET /v1/manifests?tenant_id=` (admin) — list with status/tier/acl summary.
4. `POST /v1/webhooks` with `"manifest_id": "<uuid>"` — binds the minted URL
   to the manifest. Binding a draft is legal; it quarantines every delivery
   until activation. The mint-time `visibility` remains the fallback set for
   `static` mode without `static_visibility`.
5. `POST /wh/{token}` — deliveries now route through the manifest runtime
   instead of the native payload shape.

Migration `0013_manifests.sql` adds the `manifests` table and
`webhooks.manifest_id`.

## Format (manifest_version: 1)

```yaml
manifest_version: 1
source:
  name: linear                       # [a-z0-9_-]; becomes the L1 `source`
  tier: B                            # A | B | C (optional tier claim, see below)
  auth:                              # optional (poll lane); NEVER inline creds
    ref: secret://linear-service-key
    shape: static_key                # static_key | client_credentials |
                                     # refresh_token | service_account_jwt
  webhook:
    signature:
      scheme: hmac_sha256            # hex HMAC-SHA256 of the raw request body
      header: Linear-Signature
      secret_ref: secret://linear-webhook-secret

entities:
  - type: issue
    route:
      when: "type = 'Issue' and action in ['create','update']"
      operation: upsert              # only upsert in v1
    primary_key: "data.id"           # deterministic PK → idempotent replays
    valid_from: "data.updatedAt"     # dot-path or $now(); absent = $now()
    map:                             # field → dot-path or $now()
      title: "data.title"
      state: "data.state.name"
    content: "data.description"      # optional: text → a retrieval chunk

poll:                                # optional; parse-and-store only in v0
  endpoint: "https://api.linear.app/graphql"
  interval: 15m
  cursor: opaque

acl_policy:                          # REQUIRED-BY-ABSENCE-BEHAVIOR (see below)
  mode: map                          # map | static | quarantine
  identity_namespace: source_native_id
  principals: "data.team.members[].id"
  approximation: true
  note: "Team membership approximates issue visibility."

fixtures:
  - input: fixtures/issue_update.json
    expect:
      facts: fixtures/issue_update.facts.json
      chunks: fixtures/issue_update.chunks.json
      acl_envelopes: fixtures/issue_update.acl.json
  - input: fixtures/project_create.json
    expect: { quarantined: true, reason_contains: "no entity route matched" }
```

Unknown fields anywhere are rejected (`deny_unknown_fields`): a hallucinated
key is a parse error, not a silent no-op.

## Mapping language: the Verity dot-path subset

SPEC §5e.3 names JSONata as the target dialect and explicitly allows "a
Verity-defined subset" as fallback. v1 ships the subset. The July 2026 crate
survey behind that decision:

| Crate | Verdict |
|---|---|
| `jsonata-rs` (Stedi) | Alpha; ~800/1000+ reference tests; documented to panic on unimplemented features. A panicking evaluator inside the fail-closed write path is disqualifying. |
| `jsonata-core` | Full reference conformance, but a single-maintainer ~183K-line dependency (simd-json, stacker, regex) with no built-in evaluator resource limits — SPEC makes wall-time/depth/output caps mandatory because JSONata permits recursion. Validating it is its own SPEC-scheduled spike, off this critical path. |

The subset (`crates/verity-manifest/src/path.rs`):

- `data.title` — object traversal
- `data.labels[0].name` — array indexing
- `team.members[].id` — array fan-out (multi-valued; only legal where a set
  is expected, i.e. `acl_policy.principals`)
- `$now()` — the only builtin (receipt-time timestamps)

Route predicates (`predicate.rs`): `path = literal`, `path != literal`,
`path in [lit, …]`, joined by `and`. Literals: `'single-quoted strings'`,
numbers, `true`/`false`/`null`. No `or`, no functions, no eval. A missing
path makes a term false — routing claims payloads on evidence, never absence.

Every dot-path is valid JSONata, so the dialect can grow toward the SPEC
target without breaking manifests.

**Hard limits regardless** (`verity_manifest::limits`): 64 KB manifest, 64
entities, 128 mapped fields/entity, 512-char expressions, 32 path segments,
payload nesting ≤ 64, 64 KB per mapped value, 512 KB total output, 1024
principals. The evaluator is non-recursive and cannot touch the network.

## acl_policy: three modes, no default

| mode | behavior | provenance tag |
|---|---|---|
| `map` | `principals` dot-path extracts the visibility set from the payload; resolved through the principal registry (`principals` table), allocating tokens on first sight | `mirrored` (approximation: false) / `approximated` (true) |
| `static` | `static_visibility` principal strings (or, absent, the binding webhook's mint-time visibility) | `admin-assigned` |
| `quarantine` | everything quarantines | `quarantined` |
| *(absent)* | parses fine; activation refused; runtime quarantines everything | `quarantined` |

`identity_namespace` fixes the registry vocabulary for extracted principals:
`email` → `user:<value>`, `source_native_id` → `<source.name>:<value>`,
`verity_group` → `group:<value>`. Callers gain access when directory sync /
`POST /v1/admin/principals` maps the same strings for them.

**Tier contracts, gate-enforced** (`source.tier`):

- **A** — must be `map` with `approximation: false` (real mirrored ACLs).
- **B** — must be `map` with `approximation: true` **and** a human-readable
  `note` (surfaced to the approving admin).
- **C** — must be `static`; the source cannot start without an assigned
  policy, so quarantine is an onboarding step, never a runtime surprise.
- No tier claim — only the generic mode validity rules apply.

**LLM authoring stance**: drafts may contain everything *except* a reviewed
`acl_policy` — an unreviewed manifest can only quarantine, structurally. The
human gate (`activate` + `approved_by`) is the single point where visibility
semantics become live.

**Fail closed, always**: unmatched route, missing/multi-valued mapped path,
unparseable `valid_from`, empty principal extraction, over-cap payloads,
inactive manifests, unresolvable signature secrets — all land in
`quarantine_preview` (HTTP 202, `{"quarantined": true}`), never a partial or
mis-filed write. A declared signature that fails to verify is a 401 and no
ingestion at all.

## Secrets

`secret://<name>` resolves from process env in v0:
`secret://linear-webhook-secret` → `VERITY_SECRET_LINEAR_WEBHOOK_SECRET`
(uppercase; `-`/`.` → `_`). Mount a real secret manager by injecting env
vars; the ref shape in manifests never changes. Credentials never appear
inline — the schema rejects them.

## Conformance harness (ships with the format)

Fixtures run under a pinned clock (2026-01-01T00:00:00Z) so `$now()` is
deterministic, and compare canonical JSON:

- `expect.facts` — `[{entity_type, entity_id, valid_from, fields{…}}]`
- `expect.chunks` — `[{entity_type, entity_id, content}]`
- `expect.acl_envelopes` — `[{mode, acl_provenance, identity_namespace?, principals}]`
- `expect.quarantined` / `reason_contains` — fail-closed assertions are
  first-class.

Run it:

```console
$ cargo run -p verity-manifest --bin manifest-test -- examples/linear.yaml
== examples/linear.yaml
   parsed: source=linear tier=Some(B) acl_mode=Map entities=2
   activation gate: would pass (still requires admin approval)
   PASS fixtures/issue_update.json
   PASS fixtures/comment_create.json
   PASS fixtures/project_create.json
```

or as a library: `verity_manifest::run_manifest_fixtures(path)`. The shipped
example is additionally enforced by a `cargo test -p verity-manifest` test,
so CI breaks if the format and its flagship example ever drift apart.

## Convention over configuration

A webhook minted **without** a manifest binding keeps the documented
Verity-native payload shape (`content`/`observation`/`facts[]`) with zero
mapping — the 5-minute path stays: mint URL, curl payload, fact queryable.
Manifests are the graduation step for real vendor payload shapes.

## Community registry

SPEC §5e.3 defers a registry to "a git repo of signed YAML files at v0.1
(near-zero cost)," with certification tiers and fetch machinery waiting until
≥10 community manifests exist. That minimal first cut ships as the top-level
[`registry/`](../registry/) directory and the `verity-cli manifest`
subcommand.

### Layout

```
registry/
  index.json                 # catalog: [{name, version, description, tier, path, sha256, signature_ref?}]
  manifests/<name>.yaml       # one manifest per source (seeded: linear, community tier)
  manifests/fixtures/…        # conformance fixtures, resolved relative to the manifest
  signatures/<name>.sig       # detached signature — verified tier only
  README.md                   # layout, contributing, tier policy
```

`index.json` is a versioned catalog; each entry carries the manifest's
`source.name`, a one-line description, a tier, the registry-relative `path`,
the lowercase-hex `sha256` of the manifest bytes (the integrity anchor), and an
optional `signature_ref`.

### Tiers

| tier | meaning | signature |
|---|---|---|
| `community` | **Self-attested** — unsigned-by-us. Integrity (sha256) is guaranteed; maintainers have not vouched for the ACL semantics. Anyone may contribute one. | optional (contributor-attested if present) |
| `verified` | **Maintainer-vouched** — signed by a Verity maintainer key after review of the `acl_policy` block. | required |

`verified` is documented, not yet operated: no manifest ships `verified` until
the maintainer key process is real. We do not build a CA — the maintainer key
location is documented, not a hierarchy.

### Signing / integrity — the honest v0 limit

Manifest-file signatures **reuse verity-manifest's HMAC-SHA256 primitive** (the
same one the webhook lane uses), signing the manifest bytes; the `.sig` file
holds the hex digest. The maintainer key resolves from
`VERITY_REGISTRY_SIGNING_KEY` (mirroring `secret://` → `VERITY_SECRET_*`). This
is deliberate — it adds **zero new supply-chain dependencies** to a crate whose
whole premise is "no supply-chain code execution."

The limit, stated plainly:

- **`sha256` in `index.json` is *integrity*, not authenticity** — it proves the
  bytes match the catalog, not who authored them.
- **HMAC is a *symmetric* MAC** — a valid signature proves the signer held the
  shared maintainer key, but because verify and sign use the same key, anyone
  who can verify can also forge. The key stays maintainer-only and is never
  shipped to verify-only clients. Real non-repudiation for the `verified` tier
  wants a **public-key (ed25519)** signature so verifiers hold only a public
  key — that is the documented next step, gated on ≥10 manifests existing.

### The verify → fixtures → activation chain (fail closed at every hop)

```
verify (sha256 + signature)  →  fixtures gate (conformance runner)  →  human activation
```

- `manifest verify <name>` — sha256 integrity + signature, clear pass/fail.
- `manifest fetch <name> [--out <dir>]` — verify, **then run the manifest's own
  fixtures** (`run_manifest_fixtures`), then copy the manifest + fixtures
  locally. A verify failure OR any fixture failure **refuses the copy** — no
  bytes are written (fail closed). Connectors-as-config with a test gate: a
  manifest that declares no fixture cannot pass.
- `manifest install <name> --tenant <id> --admin-token <t>` — verify + fixtures,
  then `POST /v1/manifests` as a **draft**. Activation — the point where ACL
  semantics go live — remains the separate, human-gated admin call
  (`POST /v1/manifests/{id}/activate` with an `approved_by`). The registry never
  lowers that bar.

### The CLI surface

```console
$ verity-cli manifest list                       # read index.json
$ verity-cli manifest show <name>                # metadata + yaml
$ verity-cli manifest verify <name>              # sha256 + signature → pass/fail
$ verity-cli manifest fetch <name> --out ./dir   # verify + fixtures → copy (fail closed)
$ verity-cli manifest install <name> --tenant <id> --admin-token <t>
```

The registry root defaults to `./registry`; override with `--registry <dir>` or
`VERITY_MANIFEST_REGISTRY`. Only a **local directory** is read today; a git/HTTP
URL is rejected with a next-step message and is the documented next hop.
Contributing is a PR of a signed (or self-attested) manifest — see
[`registry/README.md`](../registry/README.md).

## What manifests do not do (v0)

- Execute `poll` blocks (stored for the future reconciliation loop).
- Delete/retire entities (`operation: upsert` only).
- Per-entity ACL overrides — one `acl_policy` per source.
- Companion permission fetches for `map` mode — principals come from the
  payload itself; sources needing permission-API joins belong to the native
  connector lane (SPEC §5e.6).
