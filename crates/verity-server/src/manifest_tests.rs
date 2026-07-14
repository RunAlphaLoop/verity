//! Manifest-plane integration tests (task 30), exercising the real handlers
//! in-process: upload → activate (human gate) → bind webhook → deliver
//! fixture payloads → assert facts/chunks/provenance and fail-closed
//! quarantines. DSN-gated on VERITY_TEST_DSN, like identity_tests.

use std::path::Path as FsPath;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::Json;
use serde_json::json;
use uuid::Uuid;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::ScopeMinter;
use crate::{AdminAuth, AppState};

const WEBHOOK_SECRET: &str = "whsec_manifest_test";

async fn test_state() -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    // v0 secret store is process env; the manifest references
    // secret://linear-webhook-secret.
    std::env::set_var("VERITY_SECRET_LINEAR_WEBHOOK_SECRET", WEBHOOK_SECRET);
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("manifest-test-{}", Uuid::now_v7()))
        .await
        .expect("tenant");
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 10_000),
        encoder: None,
        minter: ScopeMinter::ephemeral(),
        purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
        admin: AdminAuth {
            key: [0u8; 32],
            expected_tag: None, // dev mode: admin surfaces open
        },
        rebac: None,
        revocations: RevocationPlane::new(300),
        watch: std::sync::Arc::new(crate::rebac_watch::WatchStatus::new()),
        folder_watchers: std::sync::Arc::new(crate::folder_watch::WatcherRegistry::new()),
        knowledge_worker: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        allow_restricted_without_rebac: false,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    Some((state, tenant))
}

fn linear_yaml() -> String {
    let path = FsPath::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/linear.yaml");
    std::fs::read_to_string(path).expect("examples/linear.yaml readable")
}

fn fixture(name: &str) -> String {
    let path = FsPath::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures")
        .join(name);
    std::fs::read_to_string(path).expect("fixture readable")
}

async fn upload(state: &Arc<AppState>, tenant: TenantId, yaml: &str) -> serde_json::Value {
    let req = serde_json::from_value(json!({ "tenant_id": tenant, "yaml": yaml })).unwrap();
    let Json(v) =
        crate::manifests::upload_manifest(State(Arc::clone(state)), HeaderMap::new(), Json(req))
            .await
            .expect("upload");
    v
}

async fn activate(
    state: &Arc<AppState>,
    tenant: TenantId,
    id: Uuid,
) -> crate::HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "approved_by": "admin@corp.example",
    }))
    .unwrap();
    crate::manifests::activate_manifest(
        State(Arc::clone(state)),
        HeaderMap::new(),
        Path(id),
        Json(req),
    )
    .await
    .map(|Json(v)| v)
}

async fn mint_bound_webhook(
    state: &Arc<AppState>,
    tenant: TenantId,
    manifest_id: Uuid,
) -> (Uuid, String) {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "name": "linear-inbound",
        "visibility": [999], // static fallback set; map mode supersedes it
        "manifest_id": manifest_id,
    }))
    .unwrap();
    let Json(v) =
        crate::webhooks::mint_webhook(State(Arc::clone(state)), HeaderMap::new(), Json(req))
            .await
            .expect("mint");
    let url = v["url"].as_str().unwrap();
    (
        serde_json::from_value(v["webhook_id"].clone()).unwrap(),
        url.strip_prefix("/wh/").unwrap().to_string(),
    )
}

fn signed_headers(body: &str) -> HeaderMap {
    let sig =
        verity_manifest::signature::hmac_sha256_hex(WEBHOOK_SECRET.as_bytes(), body.as_bytes());
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("linear-signature"),
        HeaderValue::from_str(&sig).unwrap(),
    );
    headers
}

async fn post_webhook(
    state: &Arc<AppState>,
    token: &str,
    headers: HeaderMap,
    body: &str,
) -> crate::HandlerResult<(StatusCode, serde_json::Value)> {
    crate::webhooks::webhook_post(
        State(Arc::clone(state)),
        Path(token.to_string()),
        headers,
        axum::body::Bytes::from(body.to_string()),
    )
    .await
    .map(|(status, Json(v))| (status, v))
}

async fn quarantine_reasons(state: &Arc<AppState>, tenant: TenantId) -> Vec<String> {
    sqlx::query_scalar("SELECT reason FROM quarantine_preview WHERE tenant_id = $1 ORDER BY at")
        .bind(tenant)
        .fetch_all(state.pool())
        .await
        .expect("quarantine rows")
}

/// The whole §5e.3 lane: upload → human gate → bound webhook → fixture
/// payloads → facts with approximated provenance + mapped-principal chunk
/// visibility; unmatched/tampered/draft deliveries fail closed.
#[tokio::test]
async fn manifest_webhook_end_to_end() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };

    // Upload: draft, gate-ready.
    let uploaded = upload(&state, tenant, &linear_yaml()).await;
    let manifest_id: Uuid = serde_json::from_value(uploaded["manifest_id"].clone()).unwrap();
    assert_eq!(uploaded["status"], "draft");
    assert_eq!(uploaded["acl_mode"], "map");
    assert_eq!(uploaded["activation_ready"], json!(true));

    // Bind while still a draft: deliveries quarantine (fail closed).
    let (webhook_id, token) = mint_bound_webhook(&state, tenant, manifest_id).await;
    let issue = fixture("issue_update.json");
    let (status, resp) = post_webhook(&state, &token, signed_headers(&issue), &issue)
        .await
        .expect("draft delivery accepted into quarantine");
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(resp["quarantined"], json!(true));

    // The human gate.
    let activated = activate(&state, tenant, manifest_id)
        .await
        .expect("activates");
    assert_eq!(activated["status"], "active");
    assert_eq!(activated["approved_by"], "admin@corp.example");

    // Missing signature header: 401, nothing ingested.
    let err = post_webhook(&state, &token, HeaderMap::new(), &issue)
        .await
        .expect_err("unsigned delivery refused");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    // Tampered body: 401.
    let tampered = issue.replace("Fix webhook handler timeout", "EVIL");
    let err = post_webhook(&state, &token, signed_headers(&issue), &tampered)
        .await
        .expect_err("tampered delivery refused");
    assert_eq!(err.0, StatusCode::UNAUTHORIZED);

    // Signed issue update: facts land under source=linear with approximated
    // provenance (Tier B map mode).
    let (status, resp) = post_webhook(&state, &token, signed_headers(&issue), &issue)
        .await
        .expect("delivery");
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["source"], "linear");
    assert_eq!(resp["facts_written"], 6);
    assert_eq!(resp["chunks_indexed"], 0);
    assert_eq!(resp["acl_provenance"], "approximated");
    // Map mode (Tier B): the fact's visibility is the MAPPED organization
    // principal (`organizationId` → registry token), NOT the webhook's static
    // [999] fallback. Resolve that token and scope the read to it — the scoped
    // read now enforces `visibility && principals`.
    let org_token: i32 =
        sqlx::query_scalar("SELECT token FROM principals WHERE tenant_id = $1 AND principal = $2")
            .bind(tenant)
            .bind("linear:0a2f6c4e-9d31-4b8a-b7e2-5c1d8f6a3e90")
            .fetch_one(state.pool())
            .await
            .expect("mapped org principal allocated a registry token");
    let hook_scope = Scope {
        tenant_id: tenant,
        principals: vec![org_token],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Internal,
    };
    let fact = state
        .storage
        .current_fact(
            &hook_scope,
            &FactKey {
                source: "linear".into(),
                entity_id: "d5e1f3a0-6c2b-4f9e-8a51-0b3f4c9d7e21".into(),
                field: "title".into(),
            },
        )
        .await
        .expect("fact query")
        .expect("fact present");
    assert_eq!(fact.value, json!("Fix webhook handler timeout"));
    assert_eq!(fact.acl_provenance, AclProvenance::Approximated);
    assert_eq!(
        fact.valid_from
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "2026-07-01T12:34:56.789Z",
        "bi-temporal event time extracted from data.updatedAt"
    );

    // Signed comment: a chunk visible ONLY to the mapped workspace principal.
    let comment = fixture("comment_create.json");
    let (status, resp) = post_webhook(&state, &token, signed_headers(&comment), &comment)
        .await
        .expect("comment delivery");
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["chunks_indexed"], 1);
    let org_token: i32 =
        sqlx::query_scalar("SELECT token FROM principals WHERE tenant_id = $1 AND principal = $2")
            .bind(tenant)
            .bind("linear:0a2f6c4e-9d31-4b8a-b7e2-5c1d8f6a3e90")
            .fetch_one(state.pool())
            .await
            .expect("mapped principal allocated a registry token");

    let recall = |principals: Vec<i32>| {
        let state = Arc::clone(&state);
        async move {
            let (handle, _) = state.minter.mint(
                crate::scope::ScopePayload {
                    tenant_id: tenant,
                    principals,
                    entity_scope: vec![],
                    max_confidentiality: Confidentiality::Internal,
                    actor_sub: None,
                    actor_azp: None,
                    subject: None,
                    expires_at: chrono::Utc::now(),
                },
                300,
            );
            let req = serde_json::from_value(json!({
                "scope_handle": handle,
                "text": "delivery timeout encoder",
                "k": 8,
            }))
            .unwrap();
            let Json(hits) = crate::recall(State(state), Json(req))
                .await
                .expect("recall");
            hits
        }
    };
    let hits = recall(vec![org_token]).await;
    assert!(
        hits.iter().any(|h| h.content.contains("Repro confirmed")
            && h.acl_provenance == AclProvenance::Approximated),
        "workspace member sees the comment chunk: {hits:?}"
    );
    assert!(
        recall(vec![424_242]).await.is_empty(),
        "a stranger principal sees nothing"
    );

    // Unmatched route: 202 + quarantine_preview, never mis-filed.
    let project = fixture("project_create.json");
    let (status, resp) = post_webhook(&state, &token, signed_headers(&project), &project)
        .await
        .expect("unmatched delivery accepted into quarantine");
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(resp["quarantined"], json!(true));
    let reasons = quarantine_reasons(&state, tenant).await;
    assert!(
        reasons.iter().any(|r| r.contains("not active")),
        "draft-phase quarantine recorded: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("no entity route matched")),
        "unmatched-route quarantine recorded: {reasons:?}"
    );
    assert!(
        state
            .storage
            .current_fact(
                &Scope {
                    tenant_id: tenant,
                    principals: vec![999],
                    entity_scope: vec![],
                    max_confidentiality: Confidentiality::Internal,
                },
                &FactKey {
                    source: "linear".into(),
                    entity_id: "prj-5d6e7f80-0003-4abc-9def-555555555555".into(),
                    field: "name".into(),
                },
            )
            .await
            .expect("query")
            .is_none(),
        "quarantined payloads write no facts"
    );
    let _ = webhook_id;
}

/// The LLM-authoring stance, end to end: a manifest without acl_policy
/// uploads fine (draft), is refused at the human gate, and — bound anyway —
/// quarantines every delivery.
#[tokio::test]
async fn acl_less_manifest_parses_but_never_indexes() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // Strip the acl_policy block (it sits between the entities/poll blocks
    // and the fixtures block). Upload validates the schema only — fixture
    // expectations are not executed server-side.
    let yaml = linear_yaml();
    let start = yaml.find("acl_policy:").expect("acl block");
    let end = yaml.find("fixtures:").expect("fixtures block");
    let acl_less = format!("{}{}", &yaml[..start], &yaml[end..]);

    let uploaded = upload(&state, tenant, &acl_less).await;
    let manifest_id: Uuid = serde_json::from_value(uploaded["manifest_id"].clone()).unwrap();
    assert_eq!(uploaded["status"], "draft");
    assert_eq!(uploaded["acl_mode"], "quarantine", "absent ⇒ quarantine");
    assert_ne!(uploaded["activation_ready"], json!(true));

    // The human gate refuses.
    let err = activate(&state, tenant, manifest_id)
        .await
        .expect_err("activation refused without acl_policy");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(err.1.contains("acl_policy"), "{}", err.1);

    // Force-activate at the DB level to prove the RUNTIME also fails closed
    // (defense in depth: the gate is not the only guard).
    sqlx::query("UPDATE manifests SET status = 'active' WHERE id = $1")
        .bind(manifest_id)
        .execute(state.pool())
        .await
        .expect("force-activate");
    let (_, token) = mint_bound_webhook(&state, tenant, manifest_id).await;
    let issue = fixture("issue_update.json");
    let (status, resp) = post_webhook(&state, &token, signed_headers(&issue), &issue)
        .await
        .expect("delivery quarantines");
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(resp["quarantined"], json!(true));
    let reasons = quarantine_reasons(&state, tenant).await;
    assert!(
        reasons.iter().any(|r| r.contains("acl_policy absent")),
        "{reasons:?}"
    );
}

async fn dry_run(
    state: &Arc<AppState>,
    tenant: TenantId,
    yaml: &str,
    payload: serde_json::Value,
) -> crate::HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(json!({
        "tenant_id": tenant,
        "manifest_yaml": yaml,
        "sample_payload": payload,
    }))
    .unwrap();
    crate::manifests::dry_run_manifest(State(Arc::clone(state)), HeaderMap::new(), Json(req))
        .await
        .map(|Json(v)| v)
}

/// The wizard's live-preview backend, end to end through the real handler:
/// a valid map manifest projects mapped writes + a who-can-see-it envelope of
/// namespaced principals, under the pinned fixture clock, persisting NOTHING.
#[tokio::test]
async fn dry_run_valid_map_returns_envelope() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let issue: serde_json::Value = serde_json::from_str(&fixture("issue_update.json")).unwrap();
    let v = dry_run(&state, tenant, &linear_yaml(), issue)
        .await
        .expect("dry-run ok");
    assert_eq!(v["outcome"], "writes");
    assert_eq!(v["source"], "linear");
    // The single issue write, canonical EntityWrites::to_json — no content key.
    let w = &v["writes"][0];
    assert_eq!(w["entity_id"], "d5e1f3a0-6c2b-4f9e-8a51-0b3f4c9d7e21");
    assert_eq!(w["valid_from"], "2026-07-01T12:34:56.789Z");
    assert_eq!(w["fields"]["title"], "Fix webhook handler timeout");
    assert!(
        w.get("content").is_none(),
        "writes[] carries no content key"
    );
    // Who can see it: mapped, approximated (Tier B), namespaced principals.
    assert_eq!(v["acl"]["mode"], "map");
    assert_eq!(v["acl"]["acl_provenance"], "approximated");
    assert_eq!(v["acl"]["identity_namespace"], "source_native_id");
    assert_eq!(
        v["acl"]["principals"],
        json!(["linear:0a2f6c4e-9d31-4b8a-b7e2-5c1d8f6a3e90"])
    );
    // Persisted nothing: no manifest row, no fact, no principal token.
    let manifests: i64 = sqlx::query_scalar("SELECT count(*) FROM manifests WHERE tenant_id = $1")
        .bind(tenant)
        .fetch_one(state.pool())
        .await
        .unwrap();
    assert_eq!(manifests, 0, "dry-run must not persist a manifest row");
    let principals: i64 =
        sqlx::query_scalar("SELECT count(*) FROM principals WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(state.pool())
            .await
            .unwrap();
    assert_eq!(principals, 0, "dry-run must not allocate principal tokens");
}

/// Fail-closed: a manifest whose acl_policy is absent dry-runs to a VISIBLE
/// quarantine — the wizard shows "held, no one could see it" — never a silent
/// permissive default.
#[tokio::test]
async fn dry_run_absent_acl_quarantines_visibly() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let yaml = linear_yaml();
    let start = yaml.find("acl_policy:").expect("acl block");
    let end = yaml.find("fixtures:").expect("fixtures block");
    let acl_less = format!("{}{}", &yaml[..start], &yaml[end..]);
    let issue: serde_json::Value = serde_json::from_str(&fixture("issue_update.json")).unwrap();
    let v = dry_run(&state, tenant, &acl_less, issue)
        .await
        .expect("dry-run ok even without acl");
    assert_eq!(v["outcome"], "quarantine");
    assert!(
        v["reason"].as_str().unwrap().contains("acl_policy absent"),
        "{v}"
    );
    assert!(v.get("acl").is_none(), "quarantine names no audience");
    assert!(v.get("writes").is_none(), "quarantine emits no writes");
}

/// A bad route.when returns 422 with the verbatim parser error — this powers
/// the wizard's live field validation, mapped client-side to the bad step.
#[tokio::test]
async fn dry_run_bad_expression_returns_typed_422() {
    let Some((state, tenant)) = test_state().await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // Corrupt the route predicate into something the grammar rejects.
    let yaml = linear_yaml().replace(
        "when: \"type = 'Issue' and action in ['create','update']\"",
        "when: \"type ~~~ nonsense\"",
    );
    let issue: serde_json::Value = serde_json::from_str(&fixture("issue_update.json")).unwrap();
    let err = dry_run(&state, tenant, &yaml, issue)
        .await
        .expect_err("bad expression refused");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!err.1.is_empty(), "verbatim parser error surfaced");
}
