//! Scope-soundness fuzzer for the Qdrant hybrid profile (SPEC §7e): the SAME
//! adversarial corpus and independent predicate model as the Postgres
//! profile's `verity-storage/tests/scope_fuzz.rs` (adapted copy — kept in
//! sync by construction, any leak fails the build), probing every read path
//! of `QdrantAdapter`: hybrid recall exercises the Qdrant dense leg + the
//! delegated BM25 leg + RRF fusion; latest_chunks is served from Qdrant
//! scroll; activity delegates to Postgres.
//!
//! Requires VERITY_TEST_DSN + VERITY_QDRANT_URL; skips when either is absent.

use chrono::{Duration, Utc};
use rand::prelude::*;
use serde_json::json;

use chrono::DateTime;
use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::AclCorrectionReason;
use verity_storage_qdrant::QdrantAdapter;

const ENTITIES: &[&str] = &["e:acme", "e:globex", "e:initech", "e:umbrella"];
const N_CHUNKS: usize = 200;
const N_ACTIONS: usize = 60;
const N_FACTS: usize = 120;
const N_SCOPES: usize = 120;
/// Every chunk carries this token so BM25 recall has a full-corpus match set.
const MAGIC: &str = "quantum";
/// The FIELDS a fact key can carry — a small fixed set so multiple sources map
/// onto the same canonical field and `merged_record` precedence is exercised.
const FIELDS: &[&str] = &["name", "domain", "stage", "amount"];
const SOURCES: &[&str] = &["hubspot", "salesforce"];

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

/// The client-side model of one L1 fact KEY — mirror of the Postgres fuzzer's
/// `FactModel`. Since QdrantAdapter delegates every fact read to inner Postgres,
/// probing here proves the delegators thread `scope` (no bypass).
struct FactModel {
    source: String,
    entity: String,
    field: String,
    history: Vec<(DateTime<chrono::Utc>, serde_json::Value)>,
    visibility: Vec<i32>,
    confidentiality: i16,
}

impl FactModel {
    fn key(&self) -> FactKey {
        FactKey {
            source: self.source.clone(),
            entity_id: self.entity.clone(),
            field: self.field.clone(),
        }
    }
    fn current_value(&self) -> &serde_json::Value {
        &self.history.last().unwrap().1
    }
    fn value_as_of(&self, at: DateTime<chrono::Utc>) -> Option<&serde_json::Value> {
        self.history
            .iter()
            .rev()
            .find(|(vf, _)| *vf <= at)
            .map(|(_, v)| v)
    }
}

/// The ONE shared oracle: build a synthetic `FactRow` carrying the model's
/// CURRENT ACL and ask verity-core's `fact_visible` — the exact predicate the
/// adapter enforces, no drifting copy.
fn fact_oracle(scope: &Scope, m: &FactModel) -> bool {
    let row = FactRow {
        id: uuid::Uuid::nil(),
        tenant_id: scope.tenant_id,
        key: m.key(),
        value: serde_json::Value::Null,
        valid_from: Utc::now(),
        valid_to: None,
        superseded_by: None,
        recorded_at: Utc::now(),
        visibility: m.visibility.clone(),
        confidentiality: conf_from(m.confidentiality),
        provenance: uuid::Uuid::nil(),
        acl_provenance: AclProvenance::AdminAssigned,
    };
    fact_visible(scope, &row)
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
    let (Some(dsn), Some(qurl)) = (
        std::env::var("VERITY_TEST_DSN").ok(),
        std::env::var("VERITY_QDRANT_URL").ok(),
    ) else {
        eprintln!("VERITY_TEST_DSN / VERITY_QDRANT_URL not set; skipping");
        return;
    };
    let adapter = QdrantAdapter::connect(&dsn, &qurl).await.expect("connect");
    adapter.inner().migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("qfuzz-{}", uuid::Uuid::now_v7()))
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
            acl_provenance: AclProvenance::AdminAssigned,
            derived_from: vec![],
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
                acl_provenance: AclProvenance::AdminAssigned,
                derived_from: vec![],
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

    // --- Seed L1 FACTS over the (source × entity × field) grid (mirror of the
    // Postgres fuzzer). QdrantAdapter delegates every fact read to inner
    // Postgres, so this proves the delegators forward `scope` — a delegator that
    // dropped the scope arg would leak here. Each key gets 1..=3 value versions
    // and, on ~1/3 of keys, a replayed in-place ACL correction.
    let mut fact_models: Vec<FactModel> = Vec::new();
    let mut idx = 0usize;
    for source in SOURCES {
        for entity in ENTITIES {
            for field in FIELDS {
                idx += 1;
                if idx > N_FACTS {
                    break;
                }
                let key = FactKey {
                    source: (*source).to_string(),
                    entity_id: (*entity).to_string(),
                    field: (*field).to_string(),
                };
                let mut visibility = random_subset(&mut rng, &principal_pool, 3);
                let mut confidentiality = rng.random_range(0..=3);
                let versions = rng.random_range(1..=3);
                let mut history = Vec::new();
                for v in 0..versions {
                    let vf = now - Duration::hours((versions - v) as i64);
                    let value = json!(format!("{source}-{entity}-{field}-v{v}"));
                    adapter
                        .upsert_fact(FactWrite {
                            tenant_id: tenant,
                            key: key.clone(),
                            value: value.clone(),
                            valid_from: vf,
                            visibility: visibility.clone(),
                            confidentiality: conf_from(confidentiality),
                            provenance: episode,
                            acl_provenance: AclProvenance::AdminAssigned,
                        })
                        .await
                        .unwrap();
                    history.push((vf, value));
                }
                if rng.random_bool(0.33) {
                    visibility = random_subset(&mut rng, &principal_pool, 3);
                    confidentiality = rng.random_range(0..=3);
                    adapter
                        .inner()
                        .correct_fact_acl(
                            tenant,
                            &key,
                            &visibility,
                            conf_from(confidentiality),
                            AclCorrectionReason::SourceReshare,
                            AclProvenance::Mirrored,
                            Some("qfuzz"),
                        )
                        .await
                        .unwrap();
                }
                fact_models.push(FactModel {
                    source: (*source).to_string(),
                    entity: (*entity).to_string(),
                    field: (*field).to_string(),
                    history,
                    visibility,
                    confidentiality,
                });
            }
        }
    }

    // --- DETERMINISTIC ADVERSARIAL SCENARIO: the playground denial. A fact
    // visible ONLY to token 20; a caller with token 21 must get None from the
    // delegated current_fact/fact_as_of and must not see it win in merged_record.
    let denial_key = FactKey {
        source: "hubspot".into(),
        entity_id: "qdet:denial".into(),
        field: "secret".into(),
    };
    let denial_value = json!("classified-denial-value");
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: denial_key.clone(),
            value: denial_value.clone(),
            valid_from: now - Duration::hours(2),
            visibility: vec![20],
            confidentiality: Confidentiality::Internal,
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();
    {
        let denied = Scope {
            tenant_id: tenant,
            principals: vec![21],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted,
        };
        assert!(
            adapter
                .current_fact(&denied, &denial_key)
                .await
                .unwrap()
                .is_none(),
            "DENIAL LEAK (qdrant): current_fact returned the fact to an excluded caller"
        );
        assert!(
            adapter
                .fact_as_of(&denied, &denial_key, now)
                .await
                .unwrap()
                .is_none(),
            "DENIAL LEAK (qdrant): fact_as_of returned the fact to an excluded caller"
        );
        let merged = adapter
            .inner()
            .merged_record(&denied, "qdet:denial")
            .await
            .unwrap();
        assert!(
            merged
                .fields
                .get("secret")
                .map(|f| f.value != denial_value)
                .unwrap_or(true),
            "DENIAL LEAK (qdrant): merged_record surfaced the denied value"
        );
        let allowed = Scope {
            tenant_id: tenant,
            principals: vec![20],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Internal,
        };
        assert_eq!(
            adapter
                .current_fact(&allowed, &denial_key)
                .await
                .unwrap()
                .expect("authorized caller must see the denial fact")
                .value,
            denial_value,
        );
    }

    // --- Probe every read path with randomized scopes.
    let chunk_by_doc = |doc: &str| chunk_models.iter().find(|c| c.doc == doc);
    let mut probes = 3usize; // deterministic denial assertions above
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

        // Path 1+2: recall — BM25-only (delegated) and hybrid (Qdrant dense +
        // delegated BM25, RRF-fused), k oversized so anything retrievable
        // comes back.
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

        // Path 3: latest_chunks (Qdrant scroll), for a random entity.
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

        // Path 4: activity timeline (delegated), for a random entity.
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

        // Path 5: L1 POINT READS — current_fact + fact_as_of (delegated to inner
        // Postgres). Returned IFF the shared oracle admits; value must be
        // current / as-of. A delegator that dropped `scope` leaks here.
        for m in &fact_models {
            let key = m.key();
            let oracle = fact_oracle(&scope, m);

            let got = adapter.current_fact(&scope, &key).await.unwrap();
            probes += 1;
            match &got {
                Some(row) => {
                    assert!(
                        oracle,
                        "LEAK via current_fact (qdrant): scope {scope:?} read {key:?} the oracle forbids"
                    );
                    assert_eq!(&row.value, m.current_value(), "wrong current value {key:?}");
                    assert!(fact_visible(&scope, row), "current_fact row fails fact_visible");
                }
                None => assert!(
                    !oracle,
                    "COMPLETENESS GAP via current_fact (qdrant): scope {scope:?} should see {key:?} but got None"
                ),
            }

            let firstvf = m.history.first().unwrap().0;
            for at in [
                firstvf - Duration::minutes(30),
                firstvf + Duration::minutes(1),
                now - Duration::minutes(1),
                now + Duration::hours(1),
            ] {
                let got = adapter.fact_as_of(&scope, &key, at).await.unwrap();
                probes += 1;
                let expected_value = m.value_as_of(at);
                match (&got, expected_value) {
                    (Some(row), Some(val)) => {
                        assert!(
                            oracle,
                            "LEAK via fact_as_of (qdrant): scope {scope:?} read {key:?} @ {at} the oracle forbids"
                        );
                        assert_eq!(&row.value, val, "fact_as_of wrong value {key:?} @ {at}");
                        assert!(fact_visible(&scope, row), "fact_as_of row fails fact_visible");
                    }
                    (Some(_), None) => panic!(
                        "fact_as_of (qdrant) returned a row for {key:?} @ {at} before its first write"
                    ),
                    (None, _) => {}
                }
            }
        }

        // Path 6: merged_record (inner) — precedence over caller-VISIBLE facts.
        for entity in ENTITIES {
            let merged = adapter.inner().merged_record(&scope, entity).await.unwrap();
            probes += 1;
            for (field, mf) in &merged.fields {
                let winner = fact_models
                    .iter()
                    .find(|m| {
                        m.source == mf.winning_source
                            && &m.entity == entity
                            && &m.field == field
                            && m.current_value() == &mf.value
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "merged_record winner {field}={:?} maps to no seeded fact",
                            mf.value
                        )
                    });
                assert!(
                    fact_oracle(&scope, winner),
                    "LEAK via merged_record (qdrant): field {field} won by an INVISIBLE fact (source {}, vis {:?})",
                    winner.source, winner.visibility
                );
                for alt in &mf.superseded_alternatives {
                    let am = fact_models
                        .iter()
                        .find(|m| {
                            m.source == alt.source
                                && &m.entity == entity
                                && &m.field == field
                                && m.current_value() == &alt.value
                        })
                        .expect("alternative maps to a seeded fact");
                    assert!(
                        fact_oracle(&scope, am),
                        "LEAK via merged_record (qdrant): an INVISIBLE fact surfaced as a superseded_alternative for {field}"
                    );
                }
            }
        }
    }
    println!(
        "qdrant scope fuzz: {probes} probes across recall(bm25), recall(hybrid: qdrant dense + bm25), \
         latest_chunks(qdrant), activity, current_fact, fact_as_of, merged_record — no leaks"
    );
}
