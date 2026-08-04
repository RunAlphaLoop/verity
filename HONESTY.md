# What Verity does NOT do yet

Verity is a security tool, so the honesty matters more than the pitch. This is the
list we'd want to read before trusting it. If anything here drifts out of date or
reads as spin, that's a bug — open an issue.

## Latency is not flat

The one number never to trust is a single p95. Verity's recall latency depends on the
retrieval path, the corpus size, the ACL selectivity of your scope, and whether the
index working set fits page cache. Measured, with conditions stated:

- **Point reads** (`current_fact`) ~0.5ms p95, and **BM25** ~23ms p95 — fast, and they
  hold at 1M chunks.
- **Dense / hybrid recall** is **<50ms p95 warm at 100k chunks** (see `docs/BENCHMARKS.md`),
  but at **1M chunks** it rises with selectivity and cache pressure: filtered-ANN 75ms p95
  @0.1% up to ~1.2s p95 @50% under memory contention, and end-to-end (encode + retrieve)
  worst case ~1.24s p95 (`docs/benchmark/RESULTS-2026-07-11.md`, Apple M3 Pro, in-process,
  no HTTP hop).

We publish the whole curve on purpose. Do not quote us a flat sub-50ms; quote the curve.

## The leak audit is a test suite, not a third-party audit

`verity-bench srb` reports **0 cross-entity leaks across 1,220 adversarial probes** — every
read path, per-customer Restricted sentinels, and cross-customer prompt-injection strings,
with a non-zero exit if a single probe leaks. That is a **rigorous, reproducible test suite
self-graded against sentinels we planted on synthetic fixtures** — not an independent audit
of a partner's real ACLs.

The one place we reconcile against an outside oracle: the Salesforce connector's
ACL-fidelity harness checks Verity's grant against Salesforce's own `UserRecordAccess`
decision and found **0 disagreements** — but on a trial org with synthetic data, not a
production org at scale.

## Connectors — what's real, and how faithful

All six source connectors (Google Drive, Gmail, HubSpot, Salesforce, Notion, Intercom) plus
two directory syncs (Google Workspace and Microsoft Entra ID) and a SharePoint Online/OneDrive content connector ship on `main` and are tested
in CI **against recorded fixtures — no live credentials run in CI.** Each has also been
validated once against a live account during development. That is a development validation, not continuous testing and not a turnkey,
production-hardened integration. ACL fidelity varies by what each source's API actually
exposes:

- **Google Drive / Gmail** — real per-item ACL inheritance, including transitive (nested)
  Google Group membership. The strongest fidelity.
- **HubSpot** — CRM object visibility.
- **Salesforce** — OWD / role-hierarchy / object-share / View-All reconstruction, reconciled
  against Salesforce's own access oracle (0 disagreements, trial org). Sharing-rule and
  territory reconstruction are **deferred** until a real org can measure them.
- **Notion — approximated.** The public Notion API exposes no per-page sharing, so Notion
  content rides an admin-assigned visibility floor: **fail-closed** (it over-hides, never
  leaks), but it is *not* true per-page ACL inheritance like Drive.
- **SharePoint/OneDrive** — per-item Graph permissions mirrored on the Entra identity plane,
  live-proven end to end on a (scratch) tenant including deletion-to-dark: a source-deleted
  document is detected, retired via `/v1/admin/retire`, and stops resolving on the next cycle.
  Honest limits: SP-native site groups quarantine until the SP-REST lane exists; a drive
  without a configured completeness canary quarantines wholesale (Graph returns partial ACLs
  to under-privileged callers with a 200); change subscriptions not yet wired (poll lane only).
- **Intercom** — conversations ride the operator-declared teammate-audience floor plus the
  resolved assignee as a provable superset; fail-closed on unassigned.

Directory sync (nested-group ACL inheritance) is proven end-to-end and fixture-verified for
both IdPs — Google Workspace against a real workspace, and Microsoft Entra against a real
(scratch) tenant, including the delete-a-user proof: a hard-deleted user's group edges are
purged from the connector's own snapshot even though Graph's group-delta stream never
reports them. Honest limits on the Entra side: cross-IdP SSO-alias welding is fail-closed
inert on cloud-only tenants (`onPremisesImmutableId` is null, so zero aliases are written —
surfaced as a warning, never guessed) and has not been confirmed against a federated
tenant. Neither directory sync has been run at scale against a large production tenant, and
the Entra sync is the identity plane the SharePoint/OneDrive content connector resolves
its group grants through.

## Two different fail-closed guarantees — and a stalled sync only gets you one

"Fail closed" covers two distinct promises, and Verity currently delivers them unevenly:

1. **Fail closed on "you don't have access"** — enforced everywhere, always: the in-index
   pre-filter, quarantine-on-unresolvable-ACL, empty-scope-matches-nothing.
2. **Fail closed on "we don't know if this is still valid"** — enforced today only on the
   **identity plane**: recall sits behind a staleness fence keyed off the authorization
   datastore's change stream, and returns empty rather than serve permission data whose
   freshness it cannot positively confirm.

What a **silently stalled source connector** (rate-limited API, expired token) gets you by
default is still NOT the second guarantee — but the per-source freshness gate now exists,
**opt-in**. Every recall hit is annotated with its source connector's last successful
heartbeat (`source_synced_at`, keyed off `connector_status.updated_at`; idle cycles beat
too), and when a staleness bound is set (`VERITY_SOURCE_FRESHNESS_MAX_SECS`, or a request's
`max_source_staleness_secs` — the stricter wins) recall DROPS hits from connector sources
whose last heartbeat is older than the bound, disclosing the drop in an
`X-Verity-Source-Fence` header and a `source_fence_drops_total` counter. The gate covers
**recall only**: `get_record` point reads, briefs/`latest_chunks`, and `subscribe`
deliveries are not yet gated. Exemptions, stated
plainly: `agent`, `webhook:*`, `folder:*`, and ad-hoc sources ingested outside the
connector registry have no polling connector to stall and always pass. A registry connector
source that has **never** heartbeated fails closed while the gate is on (never-synced is
indistinguishable from stalled). With the gate off — the default — assume a stalled
connector serves ACLs as stale as the stall is long, and monitor the heartbeats.

## No users, no SOC 2, no hosted cloud

There are no production users yet. There is no SOC 2 (or any) compliance attestation. There
is no managed/hosted offering — you run the Rust server and Postgres yourself. Do not put
Verity on the read path for production-sensitive data expecting an enterprise-grade managed
service; it is a v0.1 you self-host and audit.

## Erasure is real; "crypto-shredding" is not built

Cryptographic shredding — per-tenant data-encryption keys destroyed to render payloads
unrecoverable — is **designed but not implemented**. What ships is **lineage hard-purge plus
a disclosed retention window**: effective and honest erasure, but not the cryptographic
guarantee the term "crypto-shred" implies. We corrected earlier copy that overstated this.

## Throughput under load has not met the SPEC target

Verity's serving core is single-node. Concurrent-load throughput is measured
(`verity-bench run --sweep`, closed-loop), and sustained QPS under load does **not** yet meet
the SPEC target. Latency figures above are per-request, not under-load.

---

*The point of this file is that you shouldn't have to take our word for the good numbers —
run `verity-bench srb` on your own hardware, and tell us where it breaks.*
