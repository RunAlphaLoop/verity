//! Dev-stack E2E proof: every plane `verity-cli dev` wires must be
//! FUNCTIONAL, not merely configured — verified over HTTP against the
//! RUNNING server + compose stack (the founder directive behind this file).
//!
//! This is a black-box suite on purpose: verity-server is a bin-only crate,
//! so these tests exercise the same surface agents and the CLI use — no
//! in-process shortcuts, no enforcement re-implementation.
//!
//! Gating (honest skips, sibling-test style — each names the missing piece):
//! - `VERITY_TEST_DSN` unset            → every section skips (no live stack).
//! - no server answering /healthz       → every section skips (run `verity-cli dev`).
//! - `VERITY_SPICEDB_URL` unset         → identity + watch sections skip.
//! - server booted without the watch    → watch section skips, loudly.
//! - `VERITY_MEDIA_S3_ENDPOINT`/_BUCKET unset → the media section still proves
//!   the round-trip, but skips the "blob physically landed in MinIO" check.
//!
//! Sections: [identity] [watch] [media] [resolution] [encoder+recall] [freshness].
//!
//! Run against the live dev stack:
//!   VERITY_TEST_DSN=postgres://verity:verity@localhost:5433/verity \
//!   VERITY_SPICEDB_URL=http://localhost:8443 \
//!   VERITY_MEDIA_S3_ENDPOINT=http://localhost:9000 VERITY_MEDIA_BUCKET=verity-media \
//!   VERITY_MEDIA_ACCESS_KEY=minioadmin VERITY_MEDIA_SECRET_KEY=minioadmin \
//!   cargo test -p verity-server --test dev_stack_e2e -- --nocapture

use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use uuid::Uuid;

const DEFAULT_URL: &str = "http://127.0.0.1:7717";

struct Stack {
    http: reqwest::Client,
    url: String,
    /// Bearer for admin surfaces; None = dev-mode server (unauthenticated).
    admin: Option<String>,
    tenant: Uuid,
}

impl Stack {
    fn admin_headers(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.admin {
            Some(token) => rb.bearer_auth(token),
            None => rb,
        }
    }

    /// Admin POST that must succeed; panics with the server's own words.
    async fn admin_post(&self, path: &str, body: Value) -> Value {
        let resp = self
            .admin_headers(self.http.post(format!("{}{path}", self.url)))
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {path}: {e}"));
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        assert!(status.is_success(), "POST {path} answered {status}: {text}");
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("POST {path} non-JSON: {e}: {text}"))
    }

    /// Admin GET that must succeed.
    async fn admin_get(&self, path_and_query: &str) -> Value {
        let resp = self
            .admin_headers(self.http.get(format!("{}{path_and_query}", self.url)))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path_and_query}: {e}"));
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        assert!(
            status.is_success(),
            "GET {path_and_query} answered {status}: {text}"
        );
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("GET {path_and_query} non-JSON: {e}: {text}"))
    }

    /// Mint a scope handle (panics on refusal — minting is under test too).
    async fn mint(&self, body: Value) -> String {
        let v = self.admin_post("/v1/scopes", body).await; // not admin-gated; bearer is harmless
        v["scope_handle"]
            .as_str()
            .expect("scope response carries scope_handle")
            .to_string()
    }

    /// Scoped recall; returns the hits array.
    async fn recall(&self, handle: &str, text: &str) -> Vec<Value> {
        let v = self
            .admin_post(
                "/v1/recall",
                json!({ "scope_handle": handle, "text": text, "k": 8 }),
            )
            .await;
        v.as_array().cloned().expect("recall returns an array")
    }
}

/// The whole-suite gate: VERITY_TEST_DSN present (live stack expected) AND a
/// server answering /healthz. Creates a fresh tenant per section so sections
/// never interfere.
async fn live_stack(section: &str) -> Option<Stack> {
    if std::env::var("VERITY_TEST_DSN").is_err() {
        eprintln!("skipping [{section}]: VERITY_TEST_DSN not set (live dev stack required)");
        return None;
    }
    let url = std::env::var("VERITY_E2E_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .build()
        .expect("client builds");
    let healthy = http
        .get(format!("{url}/healthz"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    if !healthy {
        eprintln!("skipping [{section}]: no verity server at {url} — run `verity-cli dev`");
        return None;
    }
    let mut stack = Stack {
        http,
        url,
        admin: std::env::var("VERITY_ADMIN_TOKEN").ok(),
        tenant: Uuid::nil(),
    };
    let v = stack
        .admin_post(
            "/v1/admin/tenants",
            json!({ "name": format!("e2e-{section}-{}", Uuid::now_v7()) }),
        )
        .await;
    stack.tenant = v["tenant_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("tenant_id");
    Some(stack)
}

/// Identity/watch sections additionally need SpiceDB.
fn spicedb_env(section: &str) -> Option<(String, String)> {
    match std::env::var("VERITY_SPICEDB_URL") {
        Ok(url) => Some((
            url,
            std::env::var("VERITY_SPICEDB_KEY").unwrap_or_else(|_| "verity-dev-key".into()),
        )),
        Err(_) => {
            eprintln!("skipping [{section}]: VERITY_SPICEDB_URL not set (identity plane required)");
            None
        }
    }
}

/// Decode the readable middle of a `vs_` handle (base64 JSON by design —
/// HMAC-signed against tampering, not encrypted).
fn decode_handle(handle: &str) -> Value {
    let rest = handle.strip_prefix("vs_").expect("vs_ prefix");
    let (body, _sig) = rest.split_once('.').expect("payload.signature shape");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).expect("base64 payload"))
        .expect("payload is JSON")
}

// ================================================================
// [identity] principal + group + membership → subject-resolved mint
// ================================================================

/// Create a group membership through the admin plane, then mint a scope BY
/// SUBJECT (the production shape) and prove the decoded handle carries BOTH
/// materialized tokens — the user's and the transitively-resolved group's.
#[tokio::test]
async fn identity_membership_flows_into_subject_minted_handle() {
    let Some(s) = live_stack("identity").await else {
        return;
    };
    if spicedb_env("identity").is_none() {
        return;
    }

    // Membership write allocates both principal tokens eagerly.
    let added = s
        .admin_post(
            "/v1/admin/groups",
            json!({
                "tenant_id": s.tenant,
                "group": "group:e2e-team",
                "member": "user:e2e-alice",
            }),
        )
        .await;
    let user_token = added["tokens"]["user:e2e-alice"]
        .as_i64()
        .expect("user token");
    let group_token = added["tokens"]["group:e2e-team"]
        .as_i64()
        .expect("group token");

    // Mint by subject: the server resolves the principal set via SpiceDB —
    // the caller names WHO they are, never what powers they hold.
    let handle = s
        .mint(json!({
            "tenant_id": s.tenant,
            "subject": "user:e2e-alice",
            "actor_sub": "user:e2e-alice",
            "actor_azp": "test:dev-stack-e2e",
            "ttl_seconds": 300,
        }))
        .await;

    let payload = decode_handle(&handle);
    assert_eq!(
        payload["subject"], "user:e2e-alice",
        "identity-resolved handles carry the subject for the restricted recheck"
    );
    let principals: Vec<i64> = payload["principals"]
        .as_array()
        .expect("principals array")
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    assert!(
        principals.contains(&user_token) && principals.contains(&group_token),
        "decoded handle must carry the user token {user_token} AND the group token \
         {group_token}; got {principals:?}"
    );
}

// =====================================================================
// [watch] out-of-band SpiceDB delete revokes WITHOUT the window elapsing
// =====================================================================

/// Ingest a memory visible only to a group, mint a handle by subject, prove
/// recall sees it — then delete the membership DIRECTLY against SpiceDB
/// (bypassing the admin plane and its synchronous tombstone write) and assert
/// the SAME un-expired handle goes dark within seconds: the watch consumer
/// materialized the revocation without a re-mint and without the revocation
/// window mattering. Complements rebac_watch.rs's in-process integration test
/// (which drives consume_stream directly) — this one proves the LIVE server's
/// spawned consumer end-to-end over HTTP.
#[tokio::test]
async fn watch_materializes_direct_spicedb_delete_before_window() {
    let Some(s) = live_stack("watch").await else {
        return;
    };
    let Some((spicedb_url, spicedb_key)) = spicedb_env("watch") else {
        return;
    };
    let status = s.admin_get("/v1/admin/rebac-watch").await;
    if !status["enabled"].as_bool().unwrap_or(false) {
        eprintln!(
            "skipping [watch]: the running server was not booted with VERITY_SPICEDB_WATCH=1 \
             (re-run `verity-cli dev` — it wires the watch when SpiceDB is healthy)"
        );
        return;
    }

    // Membership + a memory only the group may see. Names stay in
    // [a-z0-9-] so the SpiceDB object id is the tenant prefix + raw name
    // (rebac.rs escape_id is the identity on this alphabet).
    let added = s
        .admin_post(
            "/v1/admin/groups",
            json!({
                "tenant_id": s.tenant,
                "group": "group:e2e-watchers",
                "member": "user:e2e-wally",
            }),
        )
        .await;
    let group_token = added["tokens"]["group:e2e-watchers"]
        .as_i64()
        .expect("group token");
    s.admin_post(
        "/v1/ingest/documents",
        json!({
            "tenant_id": s.tenant,
            "source": "e2e-watch",
            "document_id": "watch-canary",
            "content": "The emerald canary sings only for the watchers group.",
            "visibility": [group_token],
            "acl_provenance": "mirrored",
        }),
    )
    .await;

    // Handle minted BEFORE the removal — immutable, unexpired, group-bearing.
    let handle = s
        .mint(json!({
            "tenant_id": s.tenant,
            "subject": "user:e2e-wally",
            "actor_sub": "user:e2e-wally",
            "actor_azp": "test:dev-stack-e2e",
            "ttl_seconds": 600,
        }))
        .await;
    assert!(
        !s.recall(&handle, "emerald canary watchers")
            .await
            .is_empty(),
        "baseline: the group member must see the group-visible memory"
    );

    // The out-of-band removal: straight at SpiceDB's HTTP gateway — the
    // Verity admin plane (and its synchronous tombstone write) never runs.
    let oid = |name: &str| format!("{}_{name}", s.tenant);
    let resp = s
        .http
        .post(format!("{spicedb_url}/v1/relationships/write"))
        .bearer_auth(&spicedb_key)
        .json(&json!({
            "updates": [{
                "operation": "OPERATION_DELETE",
                "relationship": {
                    "resource": { "objectType": "group", "objectId": oid("e2e-watchers") },
                    "relation": "member",
                    "subject": { "object": { "objectType": "user", "objectId": oid("e2e-wally") } },
                }
            }]
        }))
        .send()
        .await
        .expect("spicedb reachable");
    assert!(
        resp.status().is_success(),
        "direct SpiceDB delete failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // The revocation must bite on the SAME handle within seconds — far
    // inside the 300s revocation window and with no re-mint anywhere.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut revoked = false;
    while Instant::now() < deadline {
        if s.recall(&handle, "emerald canary watchers")
            .await
            .is_empty()
        {
            revoked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        revoked,
        "an out-of-band SpiceDB membership delete must go dark via the watch consumer \
         (no window wait, no re-mint) — it did not within 30s"
    );
    let after = s.admin_get("/v1/admin/rebac-watch").await;
    assert!(
        after["tombstones_written"].as_u64().unwrap_or(0) >= 1,
        "the watch consumer must report the tombstones it wrote: {after}"
    );
}

// ==========================================================
// [media] blob upload → Verity-signed URL → byte round-trip
// ==========================================================

/// Upload a binary blob through POST /v1/files, mint its signed URL, redeem
/// it, and assert the bytes round-trip exactly. When the media object-store
/// envs are present, additionally prove the blob PHYSICALLY landed in the
/// object store under the content-addressed key (the tier is live, not just
/// configured); without them, the round-trip still proves the media path on
/// whatever tier the server booted with.
#[tokio::test]
async fn media_blob_round_trips_through_verity_signed_url() {
    let Some(s) = live_stack("media").await else {
        return;
    };
    let handle = s
        .mint(json!({
            "tenant_id": s.tenant,
            "principals": [1],
            "actor_azp": "test:dev-stack-e2e",
            "ttl_seconds": 300,
        }))
        .await;

    // Deliberately non-UTF-8 so the blob is store-only (never indexed).
    let mut blob: Vec<u8> = b"e2e media blob \xfe\xff\x00".to_vec();
    blob.extend(s.tenant.as_bytes()); // unique per run → fresh object key
    let sha256 = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(&blob))
    };

    let part = reqwest::multipart::Part::bytes(blob.clone())
        .file_name("e2e-blob.bin")
        .mime_str("application/octet-stream")
        .expect("mime parses");
    let form = reqwest::multipart::Form::new()
        .text("scope_handle", handle.clone())
        .part("file", part);
    let resp = s
        .http
        .post(format!("{}/v1/files", s.url))
        .multipart(form)
        .send()
        .await
        .expect("upload sends");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "upload answered {status}: {body}");
    let uploaded: Value = serde_json::from_str(&body).expect("upload JSON");
    let media_id = uploaded["media_id"].as_str().expect("media_id").to_string();
    assert_eq!(
        uploaded["chunks_indexed"], 0,
        "binary media is store-only, never indexed"
    );

    let signed = s
        .admin_post(
            &format!("/v1/media/{media_id}/sign"),
            json!({ "scope_handle": handle, "ttl_seconds": 120 }),
        )
        .await;
    let url = signed["url"].as_str().expect("signed url");
    let got = s
        .http
        .get(format!("{}{url}", s.url))
        .send()
        .await
        .expect("signed GET sends");
    assert!(got.status().is_success(), "signed GET: {}", got.status());
    let got = got.bytes().await.expect("body bytes");
    assert_eq!(
        got.as_ref(),
        blob.as_slice(),
        "bytes must round-trip exactly"
    );

    // Tier proof, env-gated: the object must exist in the store itself.
    let (Ok(endpoint), Ok(bucket)) = (
        std::env::var("VERITY_MEDIA_S3_ENDPOINT"),
        std::env::var("VERITY_MEDIA_BUCKET"),
    ) else {
        eprintln!(
            "[media] round-trip proven; skipping the object-store tier check \
             (VERITY_MEDIA_S3_ENDPOINT / VERITY_MEDIA_BUCKET not set)"
        );
        return;
    };
    use object_store::ObjectStoreExt;
    let store = object_store::aws::AmazonS3Builder::new()
        .with_endpoint(&endpoint)
        .with_bucket_name(&bucket)
        .with_access_key_id(
            std::env::var("VERITY_MEDIA_ACCESS_KEY")
                .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
                .expect("VERITY_MEDIA_ACCESS_KEY"),
        )
        .with_secret_access_key(
            std::env::var("VERITY_MEDIA_SECRET_KEY")
                .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
                .expect("VERITY_MEDIA_SECRET_KEY"),
        )
        .with_region(std::env::var("VERITY_MEDIA_REGION").unwrap_or_else(|_| "us-east-1".into()))
        .with_allow_http(endpoint.starts_with("http://"))
        .with_virtual_hosted_style_request(false)
        .build()
        .expect("object store builds");
    let key = object_store::path::Path::from(format!("media/{}/{sha256}", s.tenant));
    let in_store = store
        .get(&key)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "blob must exist in the object store at {key} — the media tier is configured \
                 but the server did not write there: {e}"
            )
        })
        .bytes()
        .await
        .expect("object bytes");
    assert_eq!(
        in_store.as_ref(),
        blob.as_slice(),
        "the object-store copy must match the uploaded bytes"
    );
}

// ======================================================================
// [resolution] cross-source strong-key pair → one canonical, live-folded
// ======================================================================

/// Seed the SAME entity in two sources via the real CDC lane (a shared
/// STRONG external_id crosswalk plus a shared email), drive the live
/// producer+fold via POST /v1/admin/entity-resolution/run, and read the merge
/// back through the scoped merged-entity endpoint: exactly one canonical with
/// both source members.
#[tokio::test]
async fn resolution_welds_cross_source_strong_key_pair_into_one_canonical() {
    let Some(s) = live_stack("resolution").await else {
        return;
    };
    let ts = chrono::Utc::now().timestamp_millis();
    // Inline verity_acl at the §5e choke point: since migration 0026 every L1
    // fact must carry a resolvable visibility or the CDC lane refuses it
    // (fail-closed, `facts_refused_no_acl`). Grant the token this test later
    // mints with (`principals: [1]`) so the welded canonical is readable back.
    let envelope = |connector: &str, table: &str, id: &str| {
        json!({
            "op": "c",
            "after": { "id": id, "email": "e2e@corp-acme.com", "external_id": "crm-42" },
            "source": { "connector": connector, "db": "crm", "table": table, "ts_ms": ts },
            "verity_acl": { "visibility": [1], "confidentiality": "internal" },
        })
    };
    let ingested = s
        .admin_post(
            &format!("/v1/ingest/debezium?tenant_id={}", s.tenant),
            json!([
                envelope("salesforce", "accounts", "sf-1"),
                envelope("hubspot", "companies", "hs-1"),
            ]),
        )
        .await;
    assert!(
        ingested["facts_inserted"].as_u64().unwrap_or(0) >= 4,
        "CDC lane must write the L1 facts: {ingested}"
    );

    let report = s
        .admin_post(
            "/v1/admin/entity-resolution/run",
            json!({ "tenant_id": s.tenant }),
        )
        .await;
    assert!(
        report["evidence_produced"].as_u64().unwrap_or(0) >= 1,
        "the Tier-1 producer must emit evidence for the shared strong key: {report}"
    );
    assert!(
        report["canonicals"].as_u64().unwrap_or(0) >= 1,
        "the fold must materialize at least one canonical: {report}"
    );

    // Deterministic canonical: canon:<lexically-min source:entity_id>.
    let canonical = "canon:hubspot:crm.companies:hs-1";
    let handle = s
        .mint(json!({
            "tenant_id": s.tenant,
            "principals": [1],
            "actor_azp": "test:dev-stack-e2e",
            "ttl_seconds": 300,
        }))
        .await;
    let merged = s
        .admin_get(&format!("/v1/entities/{canonical}?scope_handle={handle}"))
        .await;
    let members = merged["members"].as_array().expect("members");
    assert_eq!(
        members.len(),
        2,
        "exactly the two source records weld into the canonical: {merged}"
    );
    // Compare full reconstructed refs (`source:entity_id`), not the split —
    // the alias splits a colon-bearing CDC source at the first colon.
    let refs: Vec<String> = members
        .iter()
        .map(|m| {
            format!(
                "{}:{}",
                m["source"].as_str().unwrap_or_default(),
                m["entity_id"].as_str().unwrap_or_default()
            )
        })
        .collect();
    assert!(
        refs.contains(&"salesforce:crm.accounts:sf-1".to_string())
            && refs.contains(&"hubspot:crm.companies:hs-1".to_string()),
        "both source records must be members: {refs:?}"
    );
}

// =========================================================
// [encoder + recall] scoped hybrid recall over ingested text
// =========================================================

/// Ingest a distinctive text under an explicit visibility, recall it under a
/// matching scope (and NOT under a non-matching one — the pre-filter is
/// mandatory), then observe via the admin debug trace that the query actually
/// ran the DENSE leg — i.e. the local encoder is loaded, not silently absent.
#[tokio::test]
async fn encoder_dense_leg_and_scoped_recall_return_ingested_text() {
    let Some(s) = live_stack("encoder").await else {
        return;
    };
    s.admin_post(
        "/v1/ingest/documents",
        json!({
            "tenant_id": s.tenant,
            "source": "e2e-encoder",
            "document_id": "enc-1",
            "content": "The zebra-striped umbrella factory ships quarterly on Thursdays.",
            "visibility": [1],
            "acl_provenance": "mirrored",
        }),
    )
    .await;

    let handle = s
        .mint(json!({
            "tenant_id": s.tenant,
            "principals": [1],
            "actor_azp": "test:dev-stack-e2e",
            "ttl_seconds": 300,
        }))
        .await;
    let hits = s.recall(&handle, "zebra umbrella factory").await;
    assert!(
        hits.iter().any(|h| h["content"]
            .as_str()
            .unwrap_or("")
            .contains("umbrella factory")),
        "scoped recall must return the ingested text: {hits:?}"
    );

    // Fail-closed cross-check: a scope WITHOUT token 1 sees nothing.
    let outsider = s
        .mint(json!({
            "tenant_id": s.tenant,
            "principals": [99],
            "actor_azp": "test:dev-stack-e2e",
            "ttl_seconds": 300,
        }))
        .await;
    assert!(
        s.recall(&outsider, "zebra umbrella factory")
            .await
            .is_empty(),
        "a non-overlapping principal set must see nothing"
    );

    // The dense-leg observation: the admin debug trace reports which leg the
    // text probe ran — "dense" iff the local encoder is actually loaded.
    let trace = s
        .admin_post(
            "/v1/admin/debug/recall",
            json!({ "scope_handle": handle, "text": "zebra umbrella factory", "candidates": 5 }),
        )
        .await;
    assert_eq!(
        trace["query"]["leg"], "dense",
        "dev mode must have the encoder loaded (dense leg); observed: {}",
        trace["query"]
    );
}

// ==================================================
// [freshness] every ingest lane records an SLO sample
// ==================================================

/// After a document ingest, the freshness SLO plane must hold at least one
/// sample for that source, with real (non-null) percentiles computed in SQL.
#[tokio::test]
async fn freshness_slo_records_a_sample_for_the_ingest() {
    let Some(s) = live_stack("freshness").await else {
        return;
    };
    s.admin_post(
        "/v1/ingest/documents",
        json!({
            "tenant_id": s.tenant,
            "source": "e2e-freshness",
            "document_id": "fresh-1",
            "content": "Freshness sample canary.",
            "visibility": [1],
            "acl_provenance": "mirrored",
        }),
    )
    .await;
    let rows = s
        .admin_get(&format!(
            "/v1/slo/freshness?tenant_id={}&source=e2e-freshness",
            s.tenant
        ))
        .await;
    let rows = rows.as_array().expect("freshness rows");
    assert_eq!(rows.len(), 1, "one per-source row expected: {rows:?}");
    assert!(
        rows[0]["samples"].as_i64().unwrap_or(0) >= 1,
        "the ingest must have recorded a sample: {rows:?}"
    );
    assert!(
        rows[0]["p50_ms"].as_f64().is_some(),
        "percentiles are computed from real samples, never null with samples >= 1: {rows:?}"
    );
}
