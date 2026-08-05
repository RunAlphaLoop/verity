//! Input-derived visibility for agent writes (`POST /v1/episodes`) — the full
//! leak matrix for the SPEC §2 L3 intersection invariant extended to Tier-2:
//! a privileged writer summarizing a narrowly-ACL'd input must NOT widen it to
//! the writer's own scope (intra-tenant laundering), unseen lineage refs must
//! refuse the whole write, and provenance-less writes are honestly labeled
//! `writer-scoped` at the writer's COMPILED (revocation-subtracted) scope.
//!
//! Gating is HARD-ERROR (panic) on a missing `VERITY_TEST_DSN`, the
//! `retire_tests` posture: these are enforcement-soundness tests — a missing
//! database is a misconfiguration to surface loudly, never a silent no-op.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde_json::json;
use sqlx::Row;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{CachedAdapter, PostgresAdapter};

use crate::revocation::RevocationPlane;
use crate::scope::{ScopeMinter, ScopePayload};
use crate::{AdminAuth, AppState, HandlerResult};

/// Minimal real AppState against `VERITY_TEST_DSN`. No encoder (the derived
/// chunk still indexes via BM25 — the recall assertions ride the sparse leg),
/// no ReBAC (dev-mode principal handles, exactly the surface the laundering
/// bug lived on). `require_lineage` mirrors `VERITY_REMEMBER_REQUIRE_LINEAGE`.
async fn derivation_state(require_lineage: bool) -> (Arc<AppState>, TenantId) {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the derived-visibility enforcement tests; \
         refusing to silently no-op",
    );
    let pg = PostgresAdapter::connect(&dsn).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = pg
        .create_tenant(&format!("derivation-test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    let state = Arc::new(AppState {
        storage: CachedAdapter::new(pg, 10_000),
        encoder: None,
        minter: ScopeMinter::ephemeral(),
        purposes: crate::purpose::PurposePack::from_env().expect("purposes"),
        admin: AdminAuth::for_test(None, None),
        rebac: None,
        revocations: RevocationPlane::new(300),
        watch: std::sync::Arc::new(crate::rebac_watch::WatchStatus::new()),
        watch_staleness_fence_secs: 900,
        folder_watchers: std::sync::Arc::new(crate::folder_watch::WatcherRegistry::new()),
        folder_scans: std::sync::Arc::new(crate::folder_watch::FolderScanPlane::new()),
        knowledge_worker: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        directory: crate::directory_worker::DirectoryPlane::disabled(),
        entra_directory: crate::directory_worker::EntraDirectoryPlane::disabled(),
        connectors: std::sync::Arc::new(crate::connector_worker::ConnectorPlane::disabled()),
        sync: std::sync::Arc::new(crate::sync_scheduler::SyncPlane::new()),
        repo_root: None,
        listen: "127.0.0.1:0".to_string(),
        admin_token: None,
        source_freshness: crate::source_freshness::SourceFreshnessPlane::new(None),
        metrics: std::sync::Arc::new(crate::metrics::Metrics::new()),
        allow_restricted_without_rebac: true,
        remember_require_lineage: require_lineage,
        subscribers: crate::subscribe::Subscribers::new(crate::subscribe::DEFAULT_MAX_CONNECTIONS),
        auto_tag: false,
        knowledge_auto_merge: true,
        resolution: crate::scheduler::ResolutionScheduler::with_debounce_seconds(0.0),
        media_store: None,
    });
    (state, tenant)
}

/// Mint a dev-mode scope handle for the given principal set + ceiling.
fn handle(
    state: &AppState,
    tenant: TenantId,
    principals: Vec<PrincipalToken>,
    ceiling: Confidentiality,
) -> String {
    state
        .minter
        .mint(
            ScopePayload {
                tenant_id: tenant,
                principals,
                entity_scope: vec![],
                max_confidentiality: ceiling,
                actor_sub: Some("test-user".into()),
                actor_azp: Some("test-agent".into()),
                subject: None,
                issued_at: Utc::now(),
                expires_at: Utc::now(),
            },
            3600,
        )
        .0
}

/// Seed ONE source document as `chunk_count` current chunks under one L0
/// episode. `vis[i]` is chunk seq i's visibility. Returns the episode id and
/// the chunk ids in seq order.
async fn seed_document(
    state: &AppState,
    tenant: TenantId,
    doc: &str,
    vis: &[Vec<PrincipalToken>],
    conf: Confidentiality,
    content: &str,
) -> (EpisodeId, Vec<ChunkId>) {
    let episode = state
        .storage
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "crm".into(),
            source_entity: Some(doc.into()),
            kind: EpisodeKind::DocVersion,
            payload: json!({ "doc": doc }),
            content_hash: format!("{doc}-hash"),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("episode");
    let chunks: Vec<ChunkWrite> = vis
        .iter()
        .enumerate()
        .map(|(seq, v)| ChunkWrite {
            tenant_id: tenant,
            source: "crm".into(),
            document_id: doc.into(),
            seq: seq as i32,
            content: format!("{content} part {seq}"),
            content_hash: format!("{doc}-{seq}"),
            embedding: None,
            visibility: v.clone(),
            entity_tags: vec![],
            confidentiality: conf,
            trust_tier: TrustTier::Authoritative,
            valid_from: Utc::now(),
            provenance: episode,
            acl_provenance: AclProvenance::Mirrored,
            derived_from: vec![],
        })
        .collect();
    state.storage.upsert_chunks(chunks).await.expect("chunks");
    let ids: Vec<ChunkId> =
        sqlx::query("SELECT id FROM chunks WHERE tenant_id = $1 AND document_id = $2 ORDER BY seq")
            .bind(tenant)
            .bind(doc)
            .fetch_all(state.storage.inner().pool())
            .await
            .expect("chunk ids")
            .iter()
            .map(|r| r.get("id"))
            .collect();
    (episode, ids)
}

async fn remember(
    state: &Arc<AppState>,
    body: serde_json::Value,
) -> HandlerResult<serde_json::Value> {
    let req = serde_json::from_value(body).expect("request shape");
    let Json(v) = crate::remember(State(Arc::clone(state)), Json(req)).await?;
    Ok(v)
}

/// The stored agent-observation chunk for one remembered episode:
/// `(visibility, acl_provenance, derived_from, confidentiality)`.
async fn observation_chunk(
    state: &AppState,
    tenant: TenantId,
    episode_id: &str,
) -> (Vec<PrincipalToken>, String, Vec<uuid::Uuid>, i16) {
    let row = sqlx::query(
        "SELECT visibility, acl_provenance, derived_from, confidentiality
         FROM chunks WHERE tenant_id = $1 AND document_id = $2 AND valid_to IS NULL",
    )
    .bind(tenant)
    .bind(format!("obs:{episode_id}"))
    .fetch_one(state.storage.inner().pool())
    .await
    .expect("observation chunk");
    (
        row.get("visibility"),
        row.get("acl_provenance"),
        row.get("derived_from"),
        row.get("confidentiality"),
    )
}

/// Scoped BM25 recall (the enforcement predicate, sparse leg — no encoder in
/// this state), returning the matched contents.
async fn recall_contents(
    state: &AppState,
    tenant: TenantId,
    principals: Vec<PrincipalToken>,
    ceiling: Confidentiality,
    text: &str,
) -> Vec<String> {
    state
        .storage
        .recall(RecallQuery {
            scope: Scope {
                tenant_id: tenant,
                principals,
                entity_scope: vec![],
                max_confidentiality: ceiling,
            },
            embedding: None,
            text: Some(text.into()),
            k: 8,
        })
        .await
        .expect("recall")
        .into_iter()
        .map(|h| h.content)
        .collect()
}

/// `(agent_episodes, agent_chunks)` — what the remember verb has written for
/// this tenant. Both must be 0 after a refused derived write.
async fn agent_write_counts(state: &AppState, tenant: TenantId) -> (i64, i64) {
    let episodes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM episodes WHERE tenant_id = $1 AND source = 'agent'",
    )
    .bind(tenant)
    .fetch_one(state.storage.inner().pool())
    .await
    .expect("episode count");
    let chunks: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chunks WHERE tenant_id = $1 AND source = 'agent'")
            .bind(tenant)
            .fetch_one(state.storage.inner().pool())
            .await
            .expect("chunk count");
    (episodes, chunks)
}

/// THE laundering fix: a privileged writer (tokens {7, 99}) summarizing a
/// narrow input (visibility {7}) stamps the INTERSECTION {7} — a reader
/// holding only the writer's wide token 99 gets nothing on recall, while a
/// reader holding 7 still sees it. Lineage is persisted on chunk AND episode.
#[tokio::test]
async fn derived_write_stamps_input_intersection_not_writer_scope() {
    let (state, tenant) = derivation_state(false).await;
    let (input_episode, input_chunks) = seed_document(
        &state,
        tenant,
        "crm:narrow-deal",
        &[vec![7]],
        Confidentiality::Internal,
        "confidential renewal pricing zzsourcealpha",
    )
    .await;

    let h = handle(&state, tenant, vec![7, 99], Confidentiality::Internal);
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "summary of the renewal pricing zzderivalpha",
            "derived_from": [input_chunks[0]],
        }),
    )
    .await
    .expect("derived remember");
    assert_eq!(v["acl_provenance"], "derived");
    assert_eq!(v["visibility_count"], 1);
    assert!(
        v.get("hint").is_none(),
        "non-empty intersection has no hint"
    );

    let episode_id = v["episode_id"].as_str().expect("episode id").to_string();
    let (vis, prov, lineage, _) = observation_chunk(&state, tenant, &episode_id).await;
    assert_eq!(vis, vec![7], "intersection, NOT the writer's {{7,99}}");
    assert_eq!(prov, "derived");
    assert_eq!(lineage, vec![input_episode], "normalized to the episode id");

    // L0 lineage rides the episode payload too.
    let payload: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM episodes WHERE id = $1::uuid")
            .bind(&episode_id)
            .fetch_one(state.storage.inner().pool())
            .await
            .expect("episode payload");
    assert_eq!(payload["derived_from"], json!([input_episode]));

    // Reader with ONLY the wide token: ∅ (this was the leak).
    let wide = recall_contents(
        &state,
        tenant,
        vec![99],
        Confidentiality::Internal,
        "zzderivalpha",
    )
    .await;
    assert!(wide.is_empty(), "token-99 reader must NOT see the summary");
    // Reader with the narrow token still sees it.
    let narrow = recall_contents(
        &state,
        tenant,
        vec![7],
        Confidentiality::Internal,
        "zzderivalpha",
    )
    .await;
    assert_eq!(narrow.len(), 1, "token-7 reader sees the derived summary");
}

/// Every flavor of unseen ref — wrong principal, other tenant, retired
/// (valid_to set) row, over-ceiling confidentiality — is a 403 naming the
/// unresolved id, and NOTHING is written: no L0 episode, no chunk. (Decision:
/// nothing-at-all, not even L0 — a partial write would let a refused request
/// still smuggle content into memory.)
#[tokio::test]
async fn unseen_refs_forbid_and_nothing_is_written() {
    let (state, tenant) = derivation_state(false).await;
    let h = handle(&state, tenant, vec![7], Confidentiality::Internal);

    // (a) visible to a principal the writer doesn't hold.
    let (_, wrong_principal) = seed_document(
        &state,
        tenant,
        "crm:foreign-acl",
        &[vec![55]],
        Confidentiality::Internal,
        "someone else's zzforeign",
    )
    .await;
    // (b) another tenant entirely.
    let other_tenant = state
        .storage
        .inner()
        .create_tenant(&format!("derivation-other-{}", uuid::Uuid::now_v7()))
        .await
        .expect("other tenant");
    let (_, cross_tenant) = seed_document(
        &state,
        other_tenant,
        "crm:other-tenant-doc",
        &[vec![7]],
        Confidentiality::Internal,
        "cross tenant zzcross",
    )
    .await;
    // (c) a retired (non-current) row.
    let (_, retired) = seed_document(
        &state,
        tenant,
        "crm:retired-doc",
        &[vec![7]],
        Confidentiality::Internal,
        "retired zzretired",
    )
    .await;
    sqlx::query("UPDATE chunks SET valid_to = now() WHERE id = $1")
        .bind(retired[0])
        .execute(state.storage.inner().pool())
        .await
        .expect("retire row");
    // (d) above the writer's confidentiality ceiling.
    let (_, over_ceiling) = seed_document(
        &state,
        tenant,
        "crm:board-only",
        &[vec![7]],
        Confidentiality::Confidential,
        "board only zzboard",
    )
    .await;

    for (case, bad_ref) in [
        ("wrong principal", wrong_principal[0]),
        ("other tenant", cross_tenant[0]),
        ("retired row", retired[0]),
        ("over-ceiling confidentiality", over_ceiling[0]),
    ] {
        let err = remember(
            &state,
            json!({
                "scope_handle": h,
                "observation": "attempted summary zzsmuggle",
                "derived_from": [bad_ref],
            }),
        )
        .await
        .expect_err(&format!("{case}: must refuse"));
        assert_eq!(err.0, StatusCode::FORBIDDEN, "{case}");
        assert!(
            err.1.contains(&bad_ref.to_string()),
            "{case}: 403 lists the unresolved id: {}",
            err.1
        );
    }
    assert_eq!(
        agent_write_counts(&state, tenant).await,
        (0, 0),
        "a refused derived write leaves NOTHING behind — not even L0"
    );
}

/// No lineage, no policy: stamped `writer-scoped` (NOT the historical
/// `admin-assigned` mislabel) with the COMPILED principal set — a durably
/// revoked token is subtracted even though the handle still carries it.
#[tokio::test]
async fn no_lineage_is_writer_scoped_at_compiled_principals() {
    let (state, tenant) = derivation_state(false).await;
    // Handle minted with {7, 99}; 99 is then durably revoked.
    let h = handle(&state, tenant, vec![7, 99], Confidentiality::Internal);
    state
        .revocations
        .revoke_principal(state.pool(), tenant, "user:revoked@example.com", 99)
        .await
        .expect("revoke");

    let v = remember(
        &state,
        json!({ "scope_handle": h, "observation": "plain observation zzplain" }),
    )
    .await
    .expect("plain remember");
    assert_eq!(v["acl_provenance"], "writer-scoped");
    assert_eq!(v["visibility_count"], 1);

    let episode_id = v["episode_id"].as_str().expect("episode id").to_string();
    let (vis, prov, lineage, _) = observation_chunk(&state, tenant, &episode_id).await;
    assert_eq!(
        vis,
        vec![7],
        "compiled scope: revoked 99 subtracted, raw handle principals NOT trusted"
    );
    assert_eq!(prov, "writer-scoped", "honest label, never admin-assigned");
    assert!(lineage.is_empty());
}

/// VERITY_REMEMBER_REQUIRE_LINEAGE=1: a provenance-less remember is a 422;
/// the same write WITH lineage still lands. (Policy-ONLY under the knob is
/// tested separately — the fail-closed reading refuses it: a policy is an
/// asserted audience, not a provenance claim, so it does NOT satisfy the knob.)
#[tokio::test]
async fn require_lineage_knob_rejects_provenance_less_writes() {
    let (state, tenant) = derivation_state(true).await;
    let h = handle(&state, tenant, vec![7], Confidentiality::Internal);

    let err = remember(
        &state,
        json!({ "scope_handle": h, "observation": "no lineage zzstrict" }),
    )
    .await
    .expect_err("strict mode must refuse");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(agent_write_counts(&state, tenant).await, (0, 0));

    let (_, chunks) = seed_document(
        &state,
        tenant,
        "crm:strict-input",
        &[vec![7]],
        Confidentiality::Internal,
        "strict input zzstrictinput",
    )
    .await;
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "with lineage zzstrictok",
            "derived_from": [chunks[0]],
        }),
    )
    .await
    .expect("lineage satisfies strict mode");
    assert_eq!(v["acl_provenance"], "derived");
}

/// Explicit visibility_policy is clamped-by-rejection: a principal outside the
/// writer's compiled set (or unknown entirely) is a 422 NAMING it — never a
/// silent clamp. An in-set policy lands as `declared`, and with lineage
/// present the policy may NARROW WITHIN the intersection (a strict subset)
/// while lineage is still validated and persisted.
#[tokio::test]
async fn visibility_policy_clamps_by_rejection_and_narrows_within_intersection() {
    let (state, tenant) = derivation_state(false).await;
    let mapped = crate::upsert_principal_tokens(
        state.pool(),
        tenant,
        &[
            "user:in@example.com".into(),
            "user:out@example.com".into(),
            "group:eng@example.com".into(),
        ],
    )
    .await
    .expect("principal tokens");
    let (t_in, _t_out, t_eng) = (mapped[0].1, mapped[1].1, mapped[2].1);
    let h = handle(&state, tenant, vec![t_in, t_eng], Confidentiality::Internal);

    // Widening beyond the writer: 422 naming the principal, nothing written.
    let err = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "widened zzwiden",
            "visibility_policy": ["user:in@example.com", "user:out@example.com"],
        }),
    )
    .await
    .expect_err("widening policy must be rejected");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        err.1.contains("user:out@example.com"),
        "422 names the offending principal: {}",
        err.1
    );
    // Unknown principal string: same rejection (it cannot be in the set).
    let err = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "ghost zzghost",
            "visibility_policy": ["user:ghost@example.com"],
        }),
    )
    .await
    .expect_err("unknown principal must be rejected");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(err.1.contains("user:ghost@example.com"));
    assert_eq!(agent_write_counts(&state, tenant).await, (0, 0));

    // In-set narrowing lands as `declared`.
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "narrowed to one user zzdeclared",
            "visibility_policy": ["user:in@example.com"],
        }),
    )
    .await
    .expect("in-set policy");
    assert_eq!(v["acl_provenance"], "declared");
    let episode_id = v["episode_id"].as_str().expect("episode id").to_string();
    let (vis, prov, _, _) = observation_chunk(&state, tenant, &episode_id).await;
    assert_eq!(vis, vec![t_in]);
    assert_eq!(prov, "declared");

    // Policy + lineage: policy NARROWS WITHIN the intersection ({t_in, t_eng}
    // → {t_in}, a strict subset), stays `declared`, lineage still persisted.
    let (input_episode, chunks) = seed_document(
        &state,
        tenant,
        "crm:policy-input",
        &[vec![t_in, t_eng]],
        Confidentiality::Internal,
        "policy input zzpolicyinput",
    )
    .await;
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "policy over lineage zzpolicyover",
            "derived_from": [chunks[0]],
            "visibility_policy": ["user:in@example.com"],
        }),
    )
    .await
    .expect("policy + lineage");
    assert_eq!(v["acl_provenance"], "declared");
    let episode_id = v["episode_id"].as_str().expect("episode id").to_string();
    let (vis, prov, lineage, _) = observation_chunk(&state, tenant, &episode_id).await;
    assert_eq!(
        vis,
        vec![t_in],
        "policy narrows below the {{t_in, t_eng}} intersection"
    );
    assert_eq!(prov, "declared");
    assert_eq!(
        lineage,
        vec![input_episode],
        "lineage persisted alongside the policy"
    );
}

/// Disjoint inputs: the intersection is EMPTY — the write still happens
/// (episode + chunk with visibility {}), it is invisible to EVERYONE including
/// the writer, and the response discloses it with a hint.
#[tokio::test]
async fn disjoint_inputs_write_invisible_and_disclose() {
    let (state, tenant) = derivation_state(false).await;
    let (_, a) = seed_document(
        &state,
        tenant,
        "crm:only-seven",
        &[vec![7]],
        Confidentiality::Internal,
        "seven only zzseven",
    )
    .await;
    let (_, b) = seed_document(
        &state,
        tenant,
        "crm:only-eight",
        &[vec![8]],
        Confidentiality::Internal,
        "eight only zzeight",
    )
    .await;
    let h = handle(&state, tenant, vec![7, 8], Confidentiality::Internal);
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "cross-silo synthesis zzdisjoint",
            "derived_from": [a[0], b[0]],
        }),
    )
    .await
    .expect("disjoint derived remember still writes");
    assert_eq!(v["visibility_count"], 0);
    assert_eq!(v["acl_provenance"], "derived");
    assert!(
        v["hint"]
            .as_str()
            .expect("hint")
            .contains("visibility_policy"),
        "disclosed hint tells the writer how to fix it"
    );

    let episode_id = v["episode_id"].as_str().expect("episode id").to_string();
    let (vis, _, _, _) = observation_chunk(&state, tenant, &episode_id).await;
    assert!(vis.is_empty(), "fail-closed: visible to nobody");
    // Invisible even to the WRITER's own full scope.
    let mine = recall_contents(
        &state,
        tenant,
        vec![7, 8],
        Confidentiality::Internal,
        "zzdisjoint",
    )
    .await;
    assert!(
        mine.is_empty(),
        "empty visibility hides it from the writer too"
    );
}

/// Mixed refs: an EPISODE ref spans all its current chunks (the intersection
/// covers every seq), mixed freely with a chunk-id ref from another document;
/// stored lineage is the normalized episode-id set.
#[tokio::test]
async fn episode_ref_spans_multichunk_document_and_mixes_with_chunk_refs() {
    let (state, tenant) = derivation_state(false).await;
    // Two-chunk episode: seq0 {7,9}, seq1 {7,8} → episode intersection {7}.
    let (multi_episode, _) = seed_document(
        &state,
        tenant,
        "crm:multi-chunk",
        &[vec![7, 9], vec![7, 8]],
        Confidentiality::Internal,
        "multi chunk doc zzmulti",
    )
    .await;
    // Chunk ref from a second document, visibility {7, 8}.
    let (other_episode, other_chunks) = seed_document(
        &state,
        tenant,
        "crm:other-doc",
        &[vec![7, 8]],
        Confidentiality::Internal,
        "other doc zzother",
    )
    .await;

    let h = handle(&state, tenant, vec![7, 8, 9], Confidentiality::Internal);
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "mixed refs zzmixed",
            "derived_from": [multi_episode, other_chunks[0]],
        }),
    )
    .await
    .expect("mixed refs remember");
    assert_eq!(v["acl_provenance"], "derived");
    assert_eq!(v["visibility_count"], 1);

    let episode_id = v["episode_id"].as_str().expect("episode id").to_string();
    let (vis, _, lineage, _) = observation_chunk(&state, tenant, &episode_id).await;
    assert_eq!(
        vis,
        vec![7],
        "intersection spans BOTH chunks of the episode ref ({{7,9}} ∩ {{7,8}}) ∩ {{7,8}}"
    );
    assert_eq!(lineage, vec![multi_episode, other_episode]);
}

/// Confidentiality propagates as MAX over the inputs and enforces on read:
/// deriving from a Confidential input yields a Confidential memory that an
/// Internal-ceiling reader cannot recall even with the right principal.
#[tokio::test]
async fn confidentiality_max_propagates_and_enforces_on_read() {
    let (state, tenant) = derivation_state(false).await;
    let (_, chunks) = seed_document(
        &state,
        tenant,
        "crm:conf-input",
        &[vec![7]],
        Confidentiality::Confidential,
        "confidential input zzconfinput",
    )
    .await;
    let h = handle(&state, tenant, vec![7], Confidentiality::Confidential);
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "derived from confidential zzconfderived",
            "derived_from": [chunks[0]],
        }),
    )
    .await
    .expect("confidential derived remember");

    let episode_id = v["episode_id"].as_str().expect("episode id").to_string();
    let (_, _, _, conf) = observation_chunk(&state, tenant, &episode_id).await;
    assert_eq!(
        conf,
        Confidentiality::Confidential as i16,
        "max(input confidentiality), not the writer's default"
    );

    // Right principal, Internal ceiling: hidden.
    let low = recall_contents(
        &state,
        tenant,
        vec![7],
        Confidentiality::Internal,
        "zzconfderived",
    )
    .await;
    assert!(
        low.is_empty(),
        "over-ceiling derived memory must not surface"
    );
    // Confidential ceiling: visible.
    let high = recall_contents(
        &state,
        tenant,
        vec![7],
        Confidentiality::Confidential,
        "zzconfderived",
    )
    .await;
    assert_eq!(high.len(), 1);
}

/// (a) Lineage + policy where the policy is a SUBSET OF THE INTERSECTION: the
/// stamped visibility is exactly the policy set, the label is `declared`, and a
/// reader holding the surviving token recalls it. The intersection is
/// {t_a, t_b}; the policy narrows to {t_a}; the write lands at {t_a}.
#[tokio::test]
async fn lineage_plus_policy_subset_of_intersection_narrows_and_recalls() {
    let (state, tenant) = derivation_state(false).await;
    let mapped = crate::upsert_principal_tokens(
        state.pool(),
        tenant,
        &["user:a@example.com".into(), "user:b@example.com".into()],
    )
    .await
    .expect("principal tokens");
    let (t_a, t_b) = (mapped[0].1, mapped[1].1);

    // Input visible to {t_a, t_b} → intersection {t_a, t_b}.
    let (input_episode, chunks) = seed_document(
        &state,
        tenant,
        "crm:subset-input",
        &[vec![t_a, t_b]],
        Confidentiality::Internal,
        "shared input zzsubsetinput",
    )
    .await;

    let h = handle(&state, tenant, vec![t_a, t_b], Confidentiality::Internal);
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "narrowed derived zzsubsetderived",
            "derived_from": [chunks[0]],
            "visibility_policy": ["user:a@example.com"],
        }),
    )
    .await
    .expect("policy ⊆ intersection lands");
    assert_eq!(v["acl_provenance"], "declared");
    assert_eq!(v["visibility_count"], 1);

    let episode_id = v["episode_id"].as_str().expect("episode id").to_string();
    let (vis, prov, lineage, _) = observation_chunk(&state, tenant, &episode_id).await;
    assert_eq!(vis, vec![t_a], "stamped = the policy set, ⊆ intersection");
    assert_eq!(prov, "declared");
    assert_eq!(lineage, vec![input_episode], "lineage still persisted");

    // The surviving-token reader recalls it.
    let seen = recall_contents(
        &state,
        tenant,
        vec![t_a],
        Confidentiality::Internal,
        "zzsubsetderived",
    )
    .await;
    assert_eq!(seen.len(), 1, "user:a recalls the narrowed derived memory");
    // The token dropped by the policy (still in the intersection) gets ∅.
    let dropped = recall_contents(
        &state,
        tenant,
        vec![t_b],
        Confidentiality::Internal,
        "zzsubsetderived",
    )
    .await;
    assert!(dropped.is_empty(), "user:b was narrowed out by the policy");
}

/// (b) The re-widen path is DEAD: lineage + a policy naming a token that is IN
/// the writer's scope but OUTSIDE the lineage intersection is a 422 (nothing
/// written), and — critically — a reader holding that very token gets ∅ on
/// recall, proving the widened row never existed. Writer holds {t_narrow,
/// t_wide}; input is visible only to {t_narrow} → intersection {t_narrow}; the
/// policy tries to re-add t_wide.
#[tokio::test]
async fn lineage_plus_policy_rewiden_past_intersection_is_dead() {
    let (state, tenant) = derivation_state(false).await;
    let mapped = crate::upsert_principal_tokens(
        state.pool(),
        tenant,
        &[
            "user:narrow@example.com".into(),
            "user:wide@example.com".into(),
        ],
    )
    .await
    .expect("principal tokens");
    let (t_narrow, t_wide) = (mapped[0].1, mapped[1].1);

    // Input visible ONLY to t_narrow → intersection {t_narrow}. t_wide is in
    // writer scope but NOT in the intersection.
    let (_, chunks) = seed_document(
        &state,
        tenant,
        "crm:rewiden-input",
        &[vec![t_narrow]],
        Confidentiality::Internal,
        "narrow input zzrewideninput",
    )
    .await;

    let h = handle(
        &state,
        tenant,
        vec![t_narrow, t_wide],
        Confidentiality::Internal,
    );
    let err = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "attempted re-widen zzrewiden",
            "derived_from": [chunks[0]],
            "visibility_policy": ["user:narrow@example.com", "user:wide@example.com"],
        }),
    )
    .await
    .expect_err("a policy re-widening past the intersection must be rejected");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        err.1.contains("user:wide@example.com"),
        "422 names the offending token: {}",
        err.1
    );
    // Nothing written: no agent episode, no agent chunk.
    assert_eq!(agent_write_counts(&state, tenant).await, (0, 0));

    // THE proof the re-widen path is dead: the reader holding the very token
    // the policy tried to re-add gets ∅ — the widened row was never created.
    let wide_reader = recall_contents(
        &state,
        tenant,
        vec![t_wide],
        Confidentiality::Internal,
        "zzrewiden",
    )
    .await;
    assert!(
        wide_reader.is_empty(),
        "the re-widen target token recalls nothing — the write never happened"
    );
}

/// (c) Fail-closed reading of VERITY_REMEMBER_REQUIRE_LINEAGE: a POLICY-ONLY
/// write (no `derived_from`) does NOT satisfy the knob — a policy is an
/// asserted audience, not a provenance claim — so it is a 422, nothing written.
/// The same write with lineage added lands. This is what makes the knob mean
/// exactly "require lineage".
#[tokio::test]
async fn require_lineage_knob_rejects_policy_only_writes() {
    let (state, tenant) = derivation_state(true).await;
    let mapped =
        crate::upsert_principal_tokens(state.pool(), tenant, &["user:p@example.com".into()])
            .await
            .expect("principal token");
    let t_p = mapped[0].1;
    let h = handle(&state, tenant, vec![t_p], Confidentiality::Internal);

    // Policy alone under the knob: refused.
    let err = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "policy only under strict zzpolicystrict",
            "visibility_policy": ["user:p@example.com"],
        }),
    )
    .await
    .expect_err("policy alone does not satisfy require-lineage");
    assert_eq!(err.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        err.1.contains("derived_from"),
        "the refusal explains lineage is required: {}",
        err.1
    );
    assert_eq!(agent_write_counts(&state, tenant).await, (0, 0));

    // Same policy WITH lineage: satisfies the knob and lands (policy ⊆
    // intersection {t_p}).
    let (_, chunks) = seed_document(
        &state,
        tenant,
        "crm:strict-policy-input",
        &[vec![t_p]],
        Confidentiality::Internal,
        "strict policy input zzstrictpolicyinput",
    )
    .await;
    let v = remember(
        &state,
        json!({
            "scope_handle": h,
            "observation": "policy with lineage under strict zzstrictpolicyok",
            "derived_from": [chunks[0]],
            "visibility_policy": ["user:p@example.com"],
        }),
    )
    .await
    .expect("lineage + policy satisfies strict mode");
    assert_eq!(v["acl_provenance"], "declared");
    assert_eq!(v["visibility_count"], 1);
}

/// Hermetic: the new provenance labels round-trip and the rolling-upgrade
/// lossy fallback maps unknowns to admin-assigned (the documented caveat).
#[test]
fn new_acl_provenance_labels_round_trip() {
    for (variant, label) in [
        (AclProvenance::Derived, "derived"),
        (AclProvenance::WriterScoped, "writer-scoped"),
        (AclProvenance::Declared, "declared"),
    ] {
        assert_eq!(variant.as_str(), label);
        assert_eq!(AclProvenance::from_str_lossy(label), variant);
    }
    assert_eq!(
        AclProvenance::from_str_lossy("from-the-future"),
        AclProvenance::AdminAssigned
    );
}
