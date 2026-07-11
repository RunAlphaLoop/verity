//! SSE subscription + freshness SLO integration tests (roadmap task 21),
//! exercising the real router over HTTP (subscriptions are streams — the
//! transport is part of the contract) and the real handlers in-process for
//! the SLO plane.
//!
//! Gating follows the VERITY_TEST_DSN pattern: everything here skips without
//! a database.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::{ScopeMinter, ScopePayload};
use crate::subscribe::Subscribers;
use crate::{AdminAuth, AppState};

/// Real AppState against VERITY_TEST_DSN (no encoder, no ReBAC, dev-mode
/// admin), with a configurable subscription cap.
async fn test_state(max_conns: usize) -> Option<(Arc<AppState>, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("sse-test-{}", uuid::Uuid::now_v7()))
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
        allow_restricted_without_rebac: false,
        subscribers: Subscribers::new(max_conns),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    Some((state, tenant))
}

/// Bind the subscribe route on an ephemeral port; returns the base URL.
async fn spawn_server(state: Arc<AppState>) -> String {
    let app = Router::new()
        .route("/v1/subscribe", get(crate::subscribe::subscribe))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{addr}")
}

fn mint(state: &AppState, tenant: TenantId, entity_scope: Vec<String>) -> String {
    state
        .minter
        .mint(
            ScopePayload {
                tenant_id: tenant,
                principals: vec![7],
                entity_scope,
                max_confidentiality: Confidentiality::Internal,
                actor_sub: Some("user:test".into()),
                actor_azp: Some("agent:sse-test".into()),
                subject: None,
                expires_at: Utc::now(),
            },
            300,
        )
        .0
}

async fn index_chunk(
    state: &AppState,
    tenant: TenantId,
    doc: &str,
    visibility: Vec<PrincipalToken>,
    entity_tags: Vec<String>,
) {
    let episode = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "test".into(),
            source_entity: entity_tags.first().cloned(),
            kind: EpisodeKind::DocVersion,
            payload: json!({ "doc": doc }),
            content_hash: format!("{doc}-hash"),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("episode");
    state
        .storage
        .upsert_chunks(vec![ChunkWrite {
            tenant_id: tenant,
            source: "test".into(),
            document_id: doc.into(),
            seq: 0,
            content: format!("content of {doc}"),
            content_hash: format!("{doc}-0"),
            embedding: None,
            visibility,
            entity_tags,
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
        }])
        .await
        .expect("chunk");
}

/// Minimal SSE consumer over reqwest's byte stream. Heartbeat comments are
/// skipped; returns (event_name, parsed_data) or None on timeout/EOF.
struct SseClient {
    resp: reqwest::Response,
    buf: String,
}

impl SseClient {
    async fn connect(url: &str) -> Self {
        let resp = reqwest::get(url).await.expect("connect");
        assert_eq!(resp.status(), reqwest::StatusCode::OK, "SSE handshake");
        assert!(resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream")));
        Self {
            resp,
            buf: String::new(),
        }
    }

    async fn next_event(&mut self, timeout: Duration) -> Option<(String, serde_json::Value)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Drain complete frames already buffered.
            while let Some(pos) = self.buf.find("\n\n") {
                let frame = self.buf[..pos].to_string();
                self.buf.drain(..pos + 2);
                let mut event = String::from("message");
                let mut data = String::new();
                for line in frame.lines() {
                    if let Some(v) = line.strip_prefix("event:") {
                        event = v.trim().to_string();
                    } else if let Some(v) = line.strip_prefix("data:") {
                        data.push_str(v.trim());
                    }
                    // Lines starting with ':' are heartbeat comments — skipped.
                }
                if !data.is_empty() {
                    return Some((event, serde_json::from_str(&data).expect("event JSON")));
                }
            }
            let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
            match tokio::time::timeout(remaining, self.resp.chunk()).await {
                Ok(Ok(Some(bytes))) => self.buf.push_str(&String::from_utf8_lossy(&bytes)),
                Ok(Ok(None)) | Ok(Err(_)) => return None, // stream closed
                Err(_) => return None,                    // timeout
            }
        }
    }
}

/// DSN-only: a chunk written AFTER connect and inside the scope arrives
/// within ~2s; out-of-scope writes (wrong visibility, unwatched entity) are
/// never delivered; an in-scope action arrives too.
#[tokio::test]
async fn sse_delivers_in_scope_writes_only() {
    let Some((state, tenant)) = test_state(64).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn_server(Arc::clone(&state)).await;
    let handle = mint(&state, tenant, vec![]);
    let url = format!("{base}/v1/subscribe?scope_handle={handle}&entities=account:acme");
    let mut client = SseClient::connect(&url).await;

    // Out of scope: visibility disjoint from the handle's principals.
    index_chunk(
        &state,
        tenant,
        "doc-hidden",
        vec![99],
        vec!["account:acme".into()],
    )
    .await;
    // Out of scope: entity not watched.
    index_chunk(
        &state,
        tenant,
        "doc-elsewhere",
        vec![7],
        vec!["account:other".into()],
    )
    .await;
    // In scope.
    let written_at = std::time::Instant::now();
    index_chunk(
        &state,
        tenant,
        "doc-live",
        vec![7],
        vec!["account:acme".into()],
    )
    .await;
    state
        .storage
        .record_action(ActionWrite {
            tenant_id: tenant,
            action_id: "act-live-1".into(),
            actor_sub: Some("user:test".into()),
            actor_azp: Some("agent:sse-test".into()),
            action_type: "quote.issued".into(),
            entities: vec!["account:acme".into()],
            summary: "issued the acme quote".into(),
            payload: json!({}),
            outcome: ActionOutcome::Succeeded,
            occurred_at: Utc::now(),
            visibility: vec![7],
            confidentiality: Confidentiality::Internal,
        })
        .await
        .expect("action");

    let (event, body) = client
        .next_event(Duration::from_secs(5))
        .await
        .expect("first event arrives");
    assert_eq!(event, "chunk");
    assert_eq!(body["type"], json!("chunk"));
    assert_eq!(body["data"]["document_id"], json!("doc-live"));
    assert!(
        written_at.elapsed() < Duration::from_secs(3),
        "chunk delivered within ~2s of the write (took {:?})",
        written_at.elapsed()
    );

    // record_action also writes an entity-tagged agent chunk (the recall
    // surface for actions), so expect that chunk plus the action record —
    // in either order — and nothing else.
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let (event, body) = client
            .next_event(Duration::from_secs(5))
            .await
            .expect("action-derived events arrive");
        match event.as_str() {
            "action" => {
                assert_eq!(body["data"]["action_id"], json!("act-live-1"));
                assert_eq!(body["data"]["action_type"], json!("quote.issued"));
            }
            "chunk" => {
                assert_eq!(body["data"]["document_id"], json!("action:act-live-1"));
            }
            other => panic!("unexpected event {other}: {body}"),
        }
        kinds.push(event);
    }
    assert!(kinds.contains(&"action".to_string()), "{kinds:?}");

    // The out-of-scope writes must never surface.
    assert!(
        client
            .next_event(Duration::from_millis(2500))
            .await
            .is_none(),
        "no further events: out-of-scope chunks are not delivered"
    );
}

/// DSN-only: an entity-bound scope watching an uncovered entity gets one SSE
/// error event and a closed stream — fail closed, never a silent filter.
#[tokio::test]
async fn sse_entity_bound_violation_errors_and_closes() {
    let Some((state, tenant)) = test_state(64).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn_server(Arc::clone(&state)).await;
    let handle = mint(&state, tenant, vec!["account:acme".into()]);
    let url = format!("{base}/v1/subscribe?scope_handle={handle}&entities=account:evil");
    let mut client = SseClient::connect(&url).await;

    let (event, body) = client
        .next_event(Duration::from_secs(2))
        .await
        .expect("error event");
    assert_eq!(event, "error");
    assert_eq!(body["type"], json!("error"));
    assert!(
        body["error"].as_str().unwrap().contains("entity_scope"),
        "{body}"
    );
    // Stream is closed: EOF, immediately (not a poll-interval timeout).
    let start = std::time::Instant::now();
    assert!(client.next_event(Duration::from_secs(2)).await.is_none());
    assert!(start.elapsed() < Duration::from_secs(2), "EOF, not timeout");
}

/// DSN-only: connections beyond the cap get 429; closing one frees the slot.
#[tokio::test]
async fn sse_connection_cap_returns_429() {
    let Some((state, tenant)) = test_state(1).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn_server(Arc::clone(&state)).await;
    let handle = mint(&state, tenant, vec![]);
    let url = format!("{base}/v1/subscribe?scope_handle={handle}&entities=account:acme");

    let first = SseClient::connect(&url).await; // holds the only slot
    let second = reqwest::get(&url).await.expect("request");
    assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    drop(first);
    // The slot frees when the server notices the disconnect; poll briefly.
    let mut freed = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let resp = reqwest::get(&url).await.expect("request");
        if resp.status() == reqwest::StatusCode::OK {
            freed = true;
            break;
        }
    }
    assert!(freed, "slot released after client disconnect");
}

/// DSN-only: unauthenticated (bad handle) and unbound-without-entities are
/// rejected before any stream starts.
#[tokio::test]
async fn sse_rejects_bad_handle_and_missing_entities() {
    let Some((state, tenant)) = test_state(64).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let base = spawn_server(Arc::clone(&state)).await;

    let resp = reqwest::get(format!("{base}/v1/subscribe?scope_handle=vs_garbage"))
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let handle = mint(&state, tenant, vec![]);
    let resp = reqwest::get(format!("{base}/v1/subscribe?scope_handle={handle}"))
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

/// DSN-only: two debezium posts with known ts_ms produce freshness samples
/// whose percentiles are sane (p50 between the two latencies, p50 <= p95).
#[tokio::test]
async fn freshness_slo_reports_sane_percentiles() {
    let Some((state, tenant)) = test_state(64).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let now_ms = Utc::now().timestamp_millis();
    let envelope = |id: i64, ts_ms: i64| {
        json!({
            "payload": {
                "before": null,
                "after": {"id": id, "stage": "won"},
                "source": {"connector": "postgresql", "db": "crm", "schema": "public",
                           "table": "deals", "ts_ms": ts_ms},
                "op": "c",
                "ts_ms": ts_ms + 5
            }
        })
    };
    // Known event times: ~5s and ~1s before now.
    for (id, ts) in [(1, now_ms - 5000), (2, now_ms - 1000)] {
        let params = serde_json::from_value(json!({ "tenant_id": tenant })).expect("params");
        let Json(v) = crate::ingest_debezium(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Query(params),
            Json(envelope(id, ts)),
        )
        .await
        .expect("ingest");
        assert_eq!(v["facts_inserted"], json!(1), "{v}");
    }

    let params = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": "postgresql:crm.public.deals",
        "window_hours": 24,
    }))
    .expect("params");
    let Json(report) =
        crate::slo::freshness(State(Arc::clone(&state)), HeaderMap::new(), Query(params))
            .await
            .expect("slo");
    assert_eq!(report.len(), 1, "{report:?}");
    let row = &report[0];
    assert_eq!(row["source"], json!("postgresql:crm.public.deals"));
    assert_eq!(row["samples"], json!(2));
    let p50 = row["p50_ms"].as_f64().expect("p50");
    let p95 = row["p95_ms"].as_f64().expect("p95");
    // p99 is the console-seams addition: it must be present (not null) and
    // monotone above p95 — the honest tail number the freshness panel now shows.
    let p99 = row["p99_ms"].as_f64().expect("p99 present");
    // Latencies are ~1000ms and ~5000ms (plus processing): the interpolated
    // median sits between them, and p95/p99 approach the slower sample.
    assert!(p50 > 900.0 && p50 < 20_000.0, "p50 sane: {p50}");
    assert!(p95 >= p50, "p95 >= p50: {p95} vs {p50}");
    assert!(
        p95 > 3_000.0 && p95 < 60_000.0,
        "p95 near the 5s sample: {p95}"
    );
    assert!(p99 >= p95, "p99 >= p95: {p99} vs {p95}");
    assert!(p99 < 60_000.0, "p99 near the 5s sample: {p99}");

    // A source filter that matches nothing returns an empty report.
    let params = serde_json::from_value(json!({
        "tenant_id": tenant,
        "source": "nope:missing",
    }))
    .expect("params");
    let Json(report) = crate::slo::freshness(State(state), HeaderMap::new(), Query(params))
        .await
        .expect("slo");
    assert!(report.is_empty(), "{report:?}");
}

/// DSN-only: the erasure DRY RUN reports the counts a real purge WOULD delete
/// and PURGES NOTHING. We ingest a debezium fact for an entity, preview an
/// erasure of that entity, assert the response is `dry_run:true` with a
/// non-zero `would_erase` count, then preview a SECOND time and assert the
/// identical counts — proving the first preview rolled back (a destructive
/// erase would have left the second preview at zero). Also asserts the honest
/// dev-mode signal: the ephemeral-key minter reports the surviving audit trail
/// stays clean (no 'erasure' audit row is written by a preview).
#[tokio::test]
async fn erasure_preview_reports_counts_without_purging() {
    let Some((state, tenant)) = test_state(64).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    // Ingest one CDC fact so the entity has something to (dry-run) erase.
    let now_ms = Utc::now().timestamp_millis();
    let envelope = json!({
        "payload": {
            "before": null,
            "after": {"id": 4242, "stage": "won"},
            "source": {"connector": "postgresql", "db": "crm", "schema": "public",
                       "table": "deals", "ts_ms": now_ms},
            "op": "c",
            "ts_ms": now_ms + 5
        }
    });
    let params = serde_json::from_value(json!({ "tenant_id": tenant })).expect("params");
    let Json(v) = crate::ingest_debezium(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Query(params),
        Json(envelope),
    )
    .await
    .expect("ingest");
    assert_eq!(v["facts_inserted"], json!(1), "{v}");
    let entity = "4242"; // debezium keys the fact by the pk value

    let req = |t: TenantId| -> crate::compliance::ErasureRequest {
        serde_json::from_value(json!({
            "tenant_id": t,
            "entity": entity,
            "media_ids": [],
        }))
        .expect("erasure req")
    };

    // First preview: dry_run true, at least one fact would be erased, coverage
    // gaps disclosed, ReBAC flag false (no ReBAC configured, and this is an
    // entity target not a user: subject).
    let Json(first) = crate::compliance::admin_erasure_preview(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(req(tenant)),
    )
    .await
    .expect("preview");
    assert_eq!(first["dry_run"], json!(true), "{first}");
    let facts_first = first["would_erase"]["facts"].as_u64().expect("facts count");
    assert!(facts_first >= 1, "at least the ingested fact: {first}");
    assert!(
        first["coverage_gaps"]["backup_retention_window"].is_string(),
        "coverage gaps disclosed: {first}"
    );
    assert_eq!(
        first["rebac_tuples_would_delete"],
        json!(false),
        "no ReBAC + entity target: {first}"
    );

    // Second preview: identical counts prove the first rolled back — a real
    // erase would have dropped this to zero.
    let Json(second) = crate::compliance::admin_erasure_preview(
        State(Arc::clone(&state)),
        HeaderMap::new(),
        Json(req(tenant)),
    )
    .await
    .expect("preview 2");
    assert_eq!(
        second["would_erase"]["facts"], first["would_erase"]["facts"],
        "preview must not purge: counts stable across runs ({first} vs {second})"
    );

    // A preview leaves NO surviving 'erasure' audit row (that is the real
    // purge's trace; a dry run leaves none).
    let audit_erasures: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND verb = 'erasure'",
    )
    .bind(tenant)
    .fetch_one(state.storage.inner().pool())
    .await
    .expect("audit count");
    assert_eq!(audit_erasures, 0, "preview wrote an erasure audit row");
}
