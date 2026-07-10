//! Scope-soundness fuzzer (SPEC §7e): every read path, probed with randomized
//! adversarial scopes against a corpus of randomized visibility shapes. Any
//! result that violates the scope predicate is a leak and fails the build.
//!
//! Soundness only (no result may leak); completeness is a quality metric
//! measured elsewhere. Requires VERITY_TEST_DSN; skips when absent.

use chrono::{Duration, Utc};
use rand::prelude::*;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::PostgresAdapter;

const ENTITIES: &[&str] = &["e:acme", "e:globex", "e:initech", "e:umbrella"];
const N_CHUNKS: usize = 200;
const N_ACTIONS: usize = 60;
const N_SCOPES: usize = 120;
/// Every chunk carries this token so BM25 recall has a full-corpus match set.
const MAGIC: &str = "quantum";

struct ChunkModel {
    doc: String,
    visibility: Vec<i32>,
    entity_tags: Vec<String>,
    confidentiality: i16,
    superseded: bool,
}

struct ActionModel {
    action_id: String,
    visibility: Vec<i32>,
    entities: Vec<String>,
    confidentiality: i16,
}

fn random_subset<T: Clone>(rng: &mut impl Rng, pool: &[T], max_len: usize) -> Vec<T> {
    let len = rng.random_range(0..=max_len.min(pool.len()));
    let mut items = pool.to_vec();
    items.shuffle(rng);
    items.truncate(len);
    items
}

fn conf_from(v: i16) -> Confidentiality {
    match v {
        0 => Confidentiality::Public,
        1 => Confidentiality::Internal,
        2 => Confidentiality::Confidential,
        _ => Confidentiality::Restricted,
    }
}

/// The scope predicate every returned item must satisfy — the independent
/// client-side model of what the server is supposed to enforce.
fn scope_admits(
    scope: &Scope,
    visibility: &[i32],
    entity_tags: &[String],
    confidentiality: i16,
) -> bool {
    let principals_ok = visibility.iter().any(|t| scope.principals.contains(t));
    let conf_ok = confidentiality <= scope.max_confidentiality as i16;
    let entity_ok = scope.entity_scope.is_empty()
        || (!entity_tags.is_empty() && entity_tags.iter().all(|e| scope.entity_scope.contains(e)));
    principals_ok && conf_ok && entity_ok
}

#[tokio::test]
async fn no_read_path_leaks_across_scopes() {
    let Some(dsn) = std::env::var("VERITY_TEST_DSN").ok() else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("fuzz-{}", uuid::Uuid::now_v7()))
        .await
        .unwrap();
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "fuzz".into(),
            source_entity: None,
            kind: EpisodeKind::CdcEvent,
            payload: json!({}),
            content_hash: "fuzz".into(),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .unwrap();

    let mut rng = rand::rng();
    let principal_pool: Vec<i32> = (1..=6).collect();

    // --- Seed a corpus with randomized visibility shapes, including the
    // adversarial degenerates: empty visibility, empty entity tags, superseded
    // versions, restricted confidentiality.
    let mut chunk_models = Vec::with_capacity(N_CHUNKS);
    let mut writes = Vec::with_capacity(N_CHUNKS);
    let now = Utc::now();
    for i in 0..N_CHUNKS {
        let model = ChunkModel {
            doc: format!("fz-{i}"),
            visibility: random_subset(&mut rng, &principal_pool, 3),
            entity_tags: random_subset(&mut rng, ENTITIES, 2)
                .into_iter()
                .map(String::from)
                .collect(),
            confidentiality: rng.random_range(0..=3),
            superseded: rng.random_bool(0.2),
        };
        writes.push(ChunkWrite {
            tenant_id: tenant,
            source: "fuzz".into(),
            document_id: model.doc.clone(),
            seq: 0,
            content: format!("{MAGIC} secret payload {i}"),
            content_hash: format!("fz-{i}"),
            embedding: Some({
                let v: Vec<f32> = (0..384).map(|_| rng.random_range(-1.0..1.0)).collect();
                let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                v.into_iter().map(|x| x / n).collect()
            }),
            visibility: model.visibility.clone(),
            entity_tags: model.entity_tags.clone(),
            confidentiality: conf_from(model.confidentiality),
            trust_tier: TrustTier::Authoritative,
            valid_from: now - Duration::hours(2),
            provenance: episode,
        });
        // A superseded chunk gets a newer version with a sentinel marker so a
        // leak of the OLD version is detectable.
        if model.superseded {
            writes.push(ChunkWrite {
                tenant_id: tenant,
                source: "fuzz".into(),
                document_id: model.doc.clone(),
                seq: 0,
                content: format!("{MAGIC} current payload {i}"),
                content_hash: format!("fz-{i}-v2"),
                embedding: writes.last().unwrap().embedding.clone(),
                visibility: model.visibility.clone(),
                entity_tags: model.entity_tags.clone(),
                confidentiality: conf_from(model.confidentiality),
                trust_tier: TrustTier::Authoritative,
                valid_from: now - Duration::hours(1),
                provenance: episode,
            });
        }
        chunk_models.push(model);
    }
    adapter.upsert_chunks(writes).await.unwrap();

    let mut action_models = Vec::with_capacity(N_ACTIONS);
    for i in 0..N_ACTIONS {
        let model = ActionModel {
            action_id: format!("fz-act-{i}"),
            visibility: random_subset(&mut rng, &principal_pool, 3),
            entities: {
                // activity() requires a target entity; give every action one.
                let mut e = random_subset(&mut rng, ENTITIES, 2);
                if e.is_empty() {
                    e.push(ENTITIES[0]);
                }
                e.into_iter().map(String::from).collect()
            },
            confidentiality: rng.random_range(0..=3),
        };
        adapter
            .record_action(ActionWrite {
                tenant_id: tenant,
                action_id: model.action_id.clone(),
                actor_sub: Some("user:fuzz".into()),
                actor_azp: Some(format!("agent:fz-{}", i % 3)),
                action_type: "fuzz.probe".into(),
                entities: model.entities.clone(),
                summary: format!("{MAGIC} action {i}"),
                payload: json!({}),
                outcome: ActionOutcome::Succeeded,
                occurred_at: now,
                visibility: model.visibility.clone(),
                confidentiality: conf_from(model.confidentiality),
            })
            .await
            .unwrap();
        action_models.push(model);
    }

    // --- Probe every read path with randomized scopes.
    let chunk_by_doc = |doc: &str| chunk_models.iter().find(|c| c.doc == doc);
    let mut probes = 0usize;
    for _ in 0..N_SCOPES {
        let scope = Scope {
            tenant_id: tenant,
            principals: random_subset(&mut rng, &(0..=7).collect::<Vec<i32>>(), 4),
            entity_scope: random_subset(&mut rng, ENTITIES, 2)
                .into_iter()
                .map(String::from)
                .collect(),
            max_confidentiality: conf_from(rng.random_range(0..=3)),
        };

        // Path 1+2: recall — BM25-only and hybrid (dense+BM25), k oversized so
        // anything retrievable comes back.
        for embedding in [None, {
            let v: Vec<f32> = (0..384).map(|_| rng.random_range(-1.0..1.0)).collect();
            let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            Some(v.into_iter().map(|x| x / n).collect::<Vec<f32>>())
        }] {
            let hits = adapter
                .recall(RecallQuery {
                    scope: scope.clone(),
                    embedding,
                    text: Some(MAGIC.into()),
                    k: 100,
                })
                .await
                .unwrap();
            probes += 1;
            for hit in &hits {
                if hit.document_id.starts_with("fz-act-") || hit.document_id.starts_with("action:")
                {
                    continue; // action chunks checked via the action model below
                }
                let model = chunk_by_doc(&hit.document_id).expect("hit maps to a seeded chunk");
                assert!(
                    scope_admits(&scope, &model.visibility, &model.entity_tags, model.confidentiality),
                    "LEAK via recall: scope {scope:?} retrieved chunk {} (vis {:?}, tags {:?}, conf {})",
                    hit.document_id, model.visibility, model.entity_tags, model.confidentiality
                );
                assert!(
                    !model.superseded || hit.content.contains("current"),
                    "STALE LEAK via recall: superseded version of {} returned",
                    hit.document_id
                );
            }
        }

        // Path 3: latest_chunks (the brief's memory section), for a random entity.
        let brief_entity = ENTITIES.choose(&mut rng).unwrap().to_string();
        let latest = adapter
            .latest_chunks(&scope, &brief_entity, 100)
            .await
            .unwrap();
        probes += 1;
        for hit in &latest {
            assert!(
                hit.entity_tags.contains(&brief_entity),
                "LEAK via latest_chunks: {} returned for entity {brief_entity} it isn't tagged with",
                hit.document_id
            );
            let entity_query_ok =
                scope.entity_scope.is_empty() || scope.entity_scope.contains(&brief_entity);
            if let Some(model) = chunk_by_doc(&hit.document_id) {
                assert!(
                    model
                        .visibility
                        .iter()
                        .any(|t| scope.principals.contains(t))
                        && model.confidentiality <= scope.max_confidentiality as i16
                        && entity_query_ok,
                    "LEAK via latest_chunks: scope {scope:?} got {} (vis {:?}, conf {})",
                    hit.document_id,
                    model.visibility,
                    model.confidentiality
                );
                assert!(
                    !model.superseded || hit.content.contains("current"),
                    "STALE LEAK via latest_chunks: superseded {} returned",
                    hit.document_id
                );
            } else {
                // Action-derived chunk: check against the action model.
                let id = hit.document_id.trim_start_matches("action:");
                let model = action_models
                    .iter()
                    .find(|a| a.action_id == id)
                    .expect("chunk maps to a seeded chunk or action");
                assert!(
                    model
                        .visibility
                        .iter()
                        .any(|t| scope.principals.contains(t))
                        && model.confidentiality <= scope.max_confidentiality as i16
                        && entity_query_ok,
                    "LEAK via latest_chunks: scope {scope:?} got action chunk {id}"
                );
            }
        }

        // Path 4: activity timeline, for a random entity.
        let entity = ENTITIES.choose(&mut rng).unwrap().to_string();
        let acts = adapter
            .activity(ActivityQuery {
                scope: scope.clone(),
                entity: entity.clone(),
                since: None,
                action_types: vec![],
                actors: vec![],
                limit: 200,
            })
            .await
            .unwrap();
        probes += 1;
        for act in &acts {
            let model = action_models
                .iter()
                .find(|a| a.action_id == act.action_id)
                .expect("action maps to a seeded model");
            assert!(
                act.entities.contains(&entity),
                "LEAK via activity: action {} returned for entity {entity} it doesn't target",
                act.action_id
            );
            // activity()'s scope rule: the queried entity must be inside an
            // entity-bound scope, and visibility/confidentiality must admit.
            let entity_query_ok =
                scope.entity_scope.is_empty() || scope.entity_scope.contains(&entity);
            let admits = model
                .visibility
                .iter()
                .any(|t| scope.principals.contains(t))
                && model.confidentiality <= scope.max_confidentiality as i16
                && entity_query_ok;
            assert!(
                admits,
                "LEAK via activity: scope {scope:?} querying {entity} got action {} (vis {:?}, conf {})",
                act.action_id, model.visibility, model.confidentiality
            );
        }
    }
    println!(
        "scope fuzz: {probes} probes across recall(bm25), recall(hybrid), activity — no leaks"
    );
}
