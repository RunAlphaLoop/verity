//! Server-side cross-source entity resolution tests (SPEC §7f, task 50),
//! exercising the real handlers in-process: admin alias/precedence config and
//! the scope-handle-gated merged read. Scoping mirrors get_record — a bad
//! handle fails closed (401).
//! Requires VERITY_TEST_DSN; skips when absent.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::{ScopeMinter, ScopePayload};
use crate::{AdminAuth, AppState};

async fn test_state() -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("er-test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 10_000),
        encoder: None,
        minter: ScopeMinter::ephemeral(),
        purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
        admin: AdminAuth {
            key: [0u8; 32],
            expected_tag: None,
            allowed_origin: None,
        },
        rebac: None,
        revocations: RevocationPlane::new(300),
        watch: std::sync::Arc::new(crate::rebac_watch::WatchStatus::new()),
        watch_staleness_fence_secs: 900,
        folder_watchers: std::sync::Arc::new(crate::folder_watch::WatcherRegistry::new()),
        folder_scans: std::sync::Arc::new(crate::folder_watch::FolderScanPlane::new()),
        knowledge_worker: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
        sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
        allow_restricted_without_rebac: false,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    Some((state, tenant))
}

async fn fact(
    state: &AppState,
    tenant: TenantId,
    source: &str,
    entity_id: &str,
    field: &str,
    value: serde_json::Value,
) {
    let episode = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: source.into(),
            source_entity: Some(entity_id.into()),
            kind: EpisodeKind::CdcEvent,
            payload: json!({ field: value }),
            content_hash: format!("{source}-{entity_id}-{field}-{value}"),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("episode");
    state
        .storage
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: source.into(),
                entity_id: entity_id.into(),
                field: field.into(),
            },
            value,
            valid_from: Utc::now(),
            visibility: vec![1],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        })
        .await
        .expect("fact");
}

fn handle(state: &AppState, tenant: TenantId) -> String {
    let (h, _) = state.minter.mint(
        ScopePayload {
            tenant_id: tenant,
            // Match the seeded fact visibility ([1]); the scoped merged read now
            // enforces `visibility && principals`, so a mismatched scope would
            // (correctly) resolve over zero visible facts.
            principals: vec![1],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted,
            actor_sub: None,
            actor_azp: None,
            subject: None,
            issued_at: Utc::now(),
            expires_at: Utc::now(),
        },
        300,
    );
    h
}

/// Full server flow: admin aliases + admin precedence + scope-gated GET
/// /v1/entities → merged record with the precedence winner and the superseded
/// alternative.
#[tokio::test]
async fn merged_entity_endpoint_resolves_precedence() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    fact(&state, tenant, "hubspot", "hs-1", "name", json!("Acme HS")).await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-1",
        "name",
        json!("Acme SF"),
    )
    .await;

    // Admin: alias both into account:acme.
    let _ = crate::admin_entity_aliases(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "tenant_id": tenant,
                "canonical": "account:acme",
                "members": [
                    {"source": "hubspot", "entity_id": "hs-1"},
                    {"source": "salesforce", "entity_id": "sf-1"}
                ]
            }))
            .unwrap(),
        ),
    )
    .await
    .expect("aliases");

    // Admin: salesforce wins `name`.
    let _ = crate::admin_entity_precedence(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "tenant_id": tenant,
                "canonical": "account:acme",
                "field": "name",
                "source_order": ["salesforce", "hubspot"]
            }))
            .unwrap(),
        ),
    )
    .await
    .expect("precedence");

    // Scoped read.
    let h = handle(&state, tenant);
    let Json(merged) = crate::get_merged_entity(
        State(Arc::clone(&state)),
        Path("account:acme".to_string()),
        Query(serde_json::from_value(json!({ "scope_handle": h })).unwrap()),
    )
    .await
    .expect("merged");

    assert_eq!(merged.canonical_entity, "account:acme");
    assert_eq!(merged.members.len(), 2);
    let name = &merged.fields["name"];
    assert_eq!(name.winning_source, "salesforce");
    assert_eq!(name.value, json!("Acme SF"));
    assert_eq!(name.superseded_alternatives.len(), 1);
    assert_eq!(name.superseded_alternatives[0].source, "hubspot");
}

/// **Live Tier-1 entity resolution, end-to-end (§4.2 S1 → S4).** Ingest real L1
/// facts for the SAME company across TWO sources, then drive the actual
/// produce+run path (`resolver::run_resolution` = `produce_tier1_evidence` → the
/// `run_full_fold` materializer) and assert the merge is correct, badged
/// deterministically, and — the security check — that a DIFFERENT company (an
/// internal-directory actor sharing a byte-identical name/local, and a free-mail
/// contact) never welds in. Finally re-run to prove idempotency.
///
/// This exercises the WHOLE live pipeline off L1: nothing here writes evidence or
/// aliases by hand — the producer reads `list_current_facts_grouped`, the fold
/// materializes `entity_aliases` + `entity_link_meta`, and the read path
/// (`merged_record` + the badge) sees only what the worker plane produced.
#[tokio::test]
async fn live_tier1_resolution_merges_company_across_sources_and_fences_others() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };

    // ---- ACME, the company we expect to resolve into one canonical. ----
    // Salesforce Account: Website (a domain-bearing field, MEDIUM) + a synced
    // DUNS crosswalk (STRONG external_id — the key that clears min_independent_keys
    // on its own). The Website/domain pair is deliberately present to prove the
    // MEDIUM key alone is NOT what merges; the STRONG external_id is.
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-acme",
        "Website",
        json!("https://www.acme.com"),
    )
    .await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-acme",
        "duns",
        json!("123456789"),
    )
    .await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-acme",
        "name",
        json!("Acme Corp (SF)"),
    )
    .await;
    // HubSpot company: domain + the SAME DUNS.
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-acme",
        "domain",
        json!("acme.com"),
    )
    .await;
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-acme",
        "duns",
        json!("123456789"),
    )
    .await;
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-acme",
        "name",
        json!("Acme Corp (HS)"),
    )
    .await;

    // Two customer contacts for ACME sharing a corporate email → they resolve into
    // their OWN canonical (a person), independently, in the customer_contact
    // namespace. This is the "matching contact email" second independent key path.
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-jane",
        "Email",
        json!("jane@acme.com"),
    )
    .await;
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-jane",
        "email",
        json!("jane@acme.com"),
    )
    .await;

    // ---- The security fence: DIFFERENT identities that must NOT merge in. ----
    // (1) An INTERNAL actor whose email is jane@acme.dev — a Linear-origin
    //     `email` is stamped internal_directory (§4.4). Even though it is a "jane"
    //     at an acme-ish domain, the namespace fence forbids any edge to the
    //     customer_contact jane, and nothing welds it to the ACME account.
    fact(
        &state,
        tenant,
        "linear",
        "lin-jane",
        "email",
        json!("jane@acme.dev"),
    )
    .await;
    // (2) A free-mail contact (gmail.com is denylisted) — never a key, never an
    //     edge, so bob resolves to nothing shared even though a second gmail bob
    //     exists in another source.
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-bob",
        "email",
        json!("bob@gmail.com"),
    )
    .await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-bob",
        "Email",
        json!("bob@gmail.com"),
    )
    .await;

    // ---- Run the LIVE produce+run path (S1 producers → S4 fold materializer). ----
    let report1 = crate::resolver::run_resolution(&state, tenant)
        .await
        .expect("run_resolution");
    assert!(
        report1.evidence_produced >= 2,
        "producer must emit ≥2 tier-1 edges (acme external_id + jane email_exact); got {}",
        report1.evidence_produced
    );

    let storage = state.storage.inner();

    // ---- ASSERT 1: exactly one canonical for ACME, with BOTH source members. ----
    let acme_canon = storage
        .resolve_canonical(tenant, "salesforce", "sf-acme")
        .await
        .unwrap()
        .expect("sf-acme must resolve to a canonical");
    assert_eq!(
        storage
            .resolve_canonical(tenant, "hubspot", "hs-acme")
            .await
            .unwrap()
            .as_deref(),
        Some(acme_canon.as_str()),
        "both sources must resolve to the SAME canonical"
    );
    // Canonical name is deterministic: canon:<lexically-min source:entity_id>.
    assert_eq!(acme_canon, "canon:hubspot:hs-acme");

    let members = storage
        .list_entity_aliases(tenant, &acme_canon)
        .await
        .unwrap();
    assert_eq!(
        members.len(),
        2,
        "exactly two source members in the canonical"
    );
    assert!(members.contains(&AliasMember {
        source: "salesforce".into(),
        entity_id: "sf-acme".into()
    }));
    assert!(members.contains(&AliasMember {
        source: "hubspot".into(),
        entity_id: "hs-acme".into()
    }));

    // merged_record reflects the same two members (the read-path view is
    // unchanged). Facts are seeded visibility [1]; scope the read to match.
    let scope = Scope {
        tenant_id: tenant,
        principals: vec![1],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    };
    let merged = storage.merged_record(&scope, &acme_canon).await.unwrap();
    assert_eq!(
        merged.members.len(),
        2,
        "merged_record: both members present"
    );

    // ---- ASSERT 2: the entity_link_meta confidence badge is present + deterministic. ----
    let badge = storage
        .link_meta_for_canonical(tenant, &acme_canon)
        .await
        .unwrap()
        .expect("acme canonical must carry a materialized badge");
    assert_eq!(
        badge.confidence, "deterministic",
        "a Tier-1 external_id merge is deterministic, never approximated"
    );
    assert_eq!(
        badge.strongest_method.as_deref(),
        Some("external_id"),
        "the strongest justifying method is the STRONG external_id key"
    );
    assert!(
        badge.evidence_count >= 1,
        "badge must cite ≥1 justifying evidence row"
    );

    // The two customer contacts share one corporate email — under the MEASURED
    // default (email min_independent_keys = 2; email_exact demoted from the
    // lone-weld strong set, RESULTS-key-independence-2026-07-11.md) a lone
    // shared email does NOT auto-weld: shared humans (fractional CFO, agency
    // contact) measured email-alone FMR 3/4 eligible negatives. The pair stays
    // separate pending review; a tenant can opt person↔person lone-email welds
    // back in per namespace (config email → min_independent_keys = 1, covered
    // by the fold unit test same_namespace_email_merges).
    assert_eq!(
        storage
            .resolve_canonical(tenant, "hubspot", "hs-jane")
            .await
            .unwrap(),
        None,
        "a lone shared email must not auto-weld under the measured default"
    );
    assert_eq!(
        storage
            .resolve_canonical(tenant, "salesforce", "sf-jane")
            .await
            .unwrap(),
        None,
        "the salesforce contact likewise stays its own entity pending review"
    );

    // ---- ASSERT 3 (the security check): the DIFFERENT company never merges in. ----
    // The internal-directory actor is fenced out of BOTH the customer person and
    // the account: it resolves to NOTHING shared (no alias row at all).
    assert_eq!(
        storage
            .resolve_canonical(tenant, "linear", "lin-jane")
            .await
            .unwrap(),
        None,
        "internal_directory jane@acme.dev must never weld to a customer_contact entity"
    );
    // The ACME canonical must contain no linear member.
    assert!(
        !members.iter().any(|m| m.source == "linear"),
        "no internal actor may appear inside the customer account canonical"
    );
    // Free-mail contacts form no edge → each resolves to nothing shared.
    assert_eq!(
        storage
            .resolve_canonical(tenant, "hubspot", "hs-bob")
            .await
            .unwrap(),
        None,
        "gmail.com is denylisted — never a key, never a merge"
    );
    assert_eq!(
        storage
            .resolve_canonical(tenant, "salesforce", "sf-bob")
            .await
            .unwrap(),
        None,
        "the second free-mail bob likewise stays unmerged"
    );

    // ---- ASSERT 4: idempotency — a second run adds no evidence, stable canonical. ----
    let report2 = crate::resolver::run_resolution(&state, tenant)
        .await
        .expect("second run_resolution");
    assert_eq!(
        report2.evidence_produced, 0,
        "re-running over unchanged L1 facts produces NO duplicate evidence (deterministic evidence_id + ON CONFLICT DO NOTHING)"
    );
    // Canonical + membership are unchanged after the repeat run.
    assert_eq!(
        storage
            .resolve_canonical(tenant, "salesforce", "sf-acme")
            .await
            .unwrap()
            .as_deref(),
        Some(acme_canon.as_str()),
        "canonical is stable across repeat runs"
    );
    let members2 = storage
        .list_entity_aliases(tenant, &acme_canon)
        .await
        .unwrap();
    assert_eq!(members2.len(), 2, "no duplicate members after re-run");
    // Still exactly one badge row for the canonical (idempotent upsert).
    assert!(
        storage
            .link_meta_for_canonical(tenant, &acme_canon)
            .await
            .unwrap()
            .is_some(),
        "badge survives the idempotent re-materialize"
    );
}

/// The merged read is scope-handle gated exactly like get_record: a garbage
/// handle fails closed with 401 (never leaks the merged view).
#[tokio::test]
async fn merged_entity_bad_handle_fails_closed() {
    let Some((state, _tenant)) = test_state().await else {
        return;
    };
    let err = crate::get_merged_entity(
        State(Arc::clone(&state)),
        Path("account:acme".to_string()),
        Query(serde_json::from_value(json!({ "scope_handle": "not-a-real-handle" })).unwrap()),
    )
    .await
    .expect_err("must reject");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
}

/// Admin WRITE endpoints must fail CLEANLY (404) — not 500 — when handed a
/// nonexistent tenant_id. Before the `ensure_tenant` guard, the raw Postgres
/// foreign-key violation on the tenant-scoped INSERT bubbled up as
/// `StorageError::Database` → `internal()` → 500. This drives a representative
/// sample of those handlers with a freshly-random tenant that was never
/// created and asserts each returns 404 (the guard fired before the mutating
/// storage call), proving the FK-500 class of bug is closed.
#[tokio::test]
async fn admin_writes_reject_unknown_tenant_with_404_not_500() {
    let Some((state, _real_tenant)) = test_state().await else {
        return;
    };
    // A tenant id that was never created — every guarded write must 404 on it.
    let ghost: TenantId = uuid::Uuid::now_v7();

    // 1. entity-resolution/decide
    let err = crate::admin_entity_decide(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "tenant_id": ghost,
                "left_ref": "salesforce:001",
                "right_ref": "hubspot:42",
                "decision": "confirm"
            }))
            .unwrap(),
        ),
    )
    .await
    .expect_err("decide must reject unknown tenant");
    assert_eq!(err.0, StatusCode::NOT_FOUND, "decide: {}", err.1);

    // 2. entity-evidence (insert)
    let err = crate::admin_evidence_insert(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "tenant_id": ghost,
                "left_ref": "salesforce:001",
                "right_ref": "hubspot:42",
                "tier": 1,
                "method": "external_id"
            }))
            .unwrap(),
        ),
    )
    .await
    .expect_err("evidence insert must reject unknown tenant");
    assert_eq!(err.0, StatusCode::NOT_FOUND, "evidence: {}", err.1);

    // 3. entity-aliases
    let err = crate::admin_entity_aliases(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "tenant_id": ghost,
                "canonical": "account:acme",
                "members": [{"source": "hubspot", "entity_id": "hs-1"}]
            }))
            .unwrap(),
        ),
    )
    .await
    .expect_err("aliases must reject unknown tenant");
    assert_eq!(err.0, StatusCode::NOT_FOUND, "aliases: {}", err.1);

    // 4. principals
    let err = crate::admin_principals(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "tenant_id": ghost,
                "principals": ["user:alice@corp.example"]
            }))
            .unwrap(),
        ),
    )
    .await
    .expect_err("principals must reject unknown tenant");
    assert_eq!(err.0, StatusCode::NOT_FOUND, "principals: {}", err.1);

    // 5. knowledge publish (random id is fine — the tenant guard fires first)
    let err = crate::publish_knowledge(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Path(uuid::Uuid::now_v7()),
        Json(
            serde_json::from_value(json!({
                "tenant_id": ghost,
                "visibility": [7]
            }))
            .unwrap(),
        ),
    )
    .await
    .expect_err("knowledge publish must reject unknown tenant");
    assert_eq!(err.0, StatusCode::NOT_FOUND, "publish: {}", err.1);
}

/// Unit-level proof of the two building blocks the guard rests on:
/// `ensure_tenant` produces `UnknownTenant` for an absent id (and `Ok` for a
/// real one), and `storage_status` maps that variant to 404.
#[tokio::test]
async fn ensure_tenant_and_storage_status_map_unknown_tenant_to_404() {
    // storage_status is a pure mapper — assert it independent of the DB.
    let ghost: TenantId = uuid::Uuid::now_v7();
    assert_eq!(
        crate::storage_status(StorageError::UnknownTenant(ghost)).0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        crate::storage_status(StorageError::InvalidInput("x".into())).0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        crate::storage_status(StorageError::Database("boom".into())).0,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    let Some((state, real_tenant)) = test_state().await else {
        return;
    };
    // A real tenant resolves Ok; a random one is UnknownTenant.
    state
        .storage
        .inner()
        .ensure_tenant(real_tenant)
        .await
        .expect("real tenant exists");
    let err = state
        .storage
        .inner()
        .ensure_tenant(ghost)
        .await
        .expect_err("ghost tenant must be unknown");
    assert!(matches!(err, StorageError::UnknownTenant(_)));
}

/// DSN-gated: mark a tenant dirty and drive ONE scheduler pass (the body of
/// `auto_resolve_loop`, minus the timer), asserting `run_resolution` actually
/// ran for that tenant. Uses a tiny debounce so a never-resolved dirty tenant
/// is immediately due. Mirrors the loop's stamp-regardless semantics.
#[tokio::test]
async fn scheduler_pass_runs_resolution_for_dirty_tenant() {
    let Some((state, tenant)) = test_state().await else {
        return;
    };
    // A resolvable cross-source pair: same email AND same external_id under
    // two sources → two independent Tier-1 keys, clearing the measured
    // min_independent_keys bar (a lone email no longer welds by default —
    // RESULTS-key-independence-2026-07-11.md). Gives run_resolution real work.
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-1",
        "email",
        json!("a@x.com"),
    )
    .await;
    fact(&state, tenant, "hubspot", "hs-1", "email", json!("a@x.com")).await;
    fact(
        &state,
        tenant,
        "salesforce",
        "sf-1",
        "external_id",
        json!("crm-42"),
    )
    .await;
    fact(
        &state,
        tenant,
        "hubspot",
        "hs-1",
        "external_id",
        json!("crm-42"),
    )
    .await;

    // Build an ENABLED scheduler (test_state's is disabled) and mark dirty.
    let sched = crate::scheduler::ResolutionScheduler::with_debounce_seconds(900.0);
    assert!(sched.enabled());
    // Not dirty yet → nothing due.
    let now = std::time::Instant::now();
    assert!(sched.due_tenants(now).is_empty());
    sched.mark_dirty(tenant);
    // Dirty & never resolved → immediately due.
    assert_eq!(sched.due_tenants(now), vec![tenant]);

    // Drive one pass over the due set (the loop body).
    let mut ran = false;
    for due_tenant in sched.due_tenants(now) {
        let report = crate::resolver::run_resolution(&state, due_tenant)
            .await
            .expect("run_resolution");
        // The pair shares an email → the fold produced ≥1 evidence row and at
        // least one canonical, proving resolution actually executed.
        assert!(report.evidence_produced >= 1, "expected Tier-1 evidence");
        assert!(report.materialize.canonicals >= 1);
        sched.stamp_resolved(due_tenant, std::time::Instant::now());
        ran = true;
    }
    assert!(ran, "scheduler pass must have resolved the dirty tenant");

    // After stamping, the tenant is no longer due (dirty cleared) even past the
    // window — no hot-loop.
    let later = now + std::time::Duration::from_secs(10_000);
    assert!(sched.due_tenants(later).is_empty());
}
