//! Scope-soundness fuzzer (SPEC §7e): every read path, probed with randomized
//! adversarial scopes against a corpus of randomized visibility shapes. Any
//! result that violates the scope predicate is a leak and fails the build.
//!
//! Soundness only (no result may leak); completeness is a quality metric
//! measured elsewhere. Requires VERITY_TEST_DSN; HARD-ERRORS (panics) when
//! absent — a scope-soundness gate that silently no-ops is worse than no gate.

use chrono::{DateTime, Duration, Utc};
use rand::prelude::*;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{AclCorrectionReason, PostgresAdapter};

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

/// The client-side model of one L1 fact KEY (source, entity, field), tracking
/// its value history and its CURRENT (post-correction) ACL — the independent
/// oracle for the point-read/merged probes. Visibility/confidentiality here are
/// what the DB column holds NOW (corrections are in-place across all rows of the
/// key), so the same values gate both the current row and every historical row.
struct FactModel {
    source: String,
    entity: String,
    field: String,
    /// (valid_from, value) in ascending event-time order. The last is current.
    history: Vec<(DateTime<Utc>, serde_json::Value)>,
    /// Current materialized visibility (after any replayed ACL correction).
    visibility: Vec<i32>,
    /// Current confidentiality (after any replayed correction).
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
    /// The current value = the latest history entry.
    fn current_value(&self) -> &serde_json::Value {
        &self.history.last().unwrap().1
    }
    /// The value that was current as of `at` (bi-temporal), or None if `at`
    /// predates the first write.
    fn value_as_of(&self, at: DateTime<Utc>) -> Option<&serde_json::Value> {
        self.history
            .iter()
            .rev()
            .find(|(vf, _)| *vf <= at)
            .map(|(_, v)| v)
    }
}

/// The ONE shared oracle: build a synthetic `FactRow` carrying the model's
/// CURRENT ACL and ask verity-core's `fact_visible`. This is the exact predicate
/// the adapter enforces — no second copy that can drift.
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
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for scope-soundness test no_read_path_leaks_across_scopes; \
         refusing to silently no-op — a scope-fuzzer that skips is the exact process gap that let \
         the §5e.6a L1-fact leak survive",
    );
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

    // --- Seed L1 FACTS over the full (source × entity × field) grid so every
    // KEY is unique (one FactModel per key — no aliasing that would desync the
    // oracle) while two sources still share each (entity, field) so
    // `merged_record` precedence + the visible-only carve-out are exercised.
    // Each key gets randomized (visibility, confidentiality), 1..=3 value
    // versions (superseded history), and — on ~1/3 of keys — a replayed IN-PLACE
    // ACL correction that rewrites the ACL across ALL rows of the key.
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
                // Value history: 1..=3 versions at strictly increasing event time.
                let versions = rng.random_range(1..=3);
                let mut history = Vec::new();
                for v in 0..versions {
                    let vf = now - Duration::hours((versions - v) as i64);
                    // Value unique per key+version so merged_record winners map
                    // back to exactly one seeded fact.
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
                        .correct_fact_acl(
                            tenant,
                            &key,
                            &visibility,
                            conf_from(confidentiality),
                            AclCorrectionReason::SourceReshare,
                            AclProvenance::Mirrored,
                            Some("fuzz"),
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

    // Materialize an L3 brief per entity under the BROAD materialization scope
    // (this is what the sleep-time worker does). Its body sees everything; the
    // point of the brief probe below is that materializing it must NOT change
    // what a caller-scoped brief read (latest_chunks — the item-serving path)
    // returns. If materialization ever leaked into serving, Path 5 would catch
    // it because latest_chunks is exactly the brief handler's memory leg.
    for entity in ENTITIES {
        adapter.refresh_brief(tenant, entity).await.unwrap();
    }

    // --- DETERMINISTIC ADVERSARIAL SCENARIOS -------------------------------
    // The randomized grid above exercises the point-read/merged oracle broadly,
    // but three high-value shapes deserve a fixed, always-run probe so a
    // regression can't hide behind an unlucky seed:
    //
    //   (A) colon-in-source Debezium keys under a MULTI-MEMBER canonical whose
    //       members carry DIFFERENT visibility — the merged view must resolve
    //       precedence over caller-visible members only, and a scope that sees
    //       one member must never see the other member's value win.
    //   (B) the EXACT playground denial scenario — a principal whose tokens do
    //       NOT include a fact's visibility must get None from current_fact and
    //       must not see that fact's value win in merged_record.
    //   (C) legacy-style empty-visibility rows — invisible to EVERY scope,
    //       including a broad all-principal / restricted-ceiling scope.
    //
    // A distinct canonical + entity namespace ("det:*") keeps these out of the
    // ENTITIES/SOURCES grid so the randomized oracle above is undisturbed.
    let det_conf = Confidentiality::Internal;

    // (A) Two members of ONE canonical, one keyed on a colon-bearing Debezium
    // source ("connector1:db.public.deals"). Member LO is visible to token 11;
    // member HI (colon source, higher precedence by recency) is visible ONLY to
    // token 12. A scope holding token 11 alone must see LO's value win, never
    // HI's — even though HI is the more-recent (would-win) fact.
    let det_canonical = "det:canon-acme";
    let member_lo_source = "hubspot"; // no colon
    let member_lo_entity = "det:acme-lo";
    let member_hi_source = "connector1:db.public.deals"; // COLON in source (Debezium)
    let member_hi_entity = "det:acme-hi";
    let tok_lo: i32 = 11;
    let tok_hi: i32 = 12;
    adapter
        .upsert_entity_alias(tenant, member_lo_source, member_lo_entity, det_canonical)
        .await
        .unwrap();
    adapter
        .upsert_entity_alias(tenant, member_hi_source, member_hi_entity, det_canonical)
        .await
        .unwrap();
    // Both members supply the SAME field "name" so they contend on precedence.
    let det_lo_value = json!("acme-name-LO");
    let det_hi_value = json!("acme-name-HI");
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: member_lo_source.into(),
                entity_id: member_lo_entity.into(),
                field: "name".into(),
            },
            value: det_lo_value.clone(),
            valid_from: now - Duration::hours(3),
            visibility: vec![tok_lo],
            confidentiality: det_conf,
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: member_hi_source.into(),
                entity_id: member_hi_entity.into(),
                field: "name".into(),
            },
            value: det_hi_value.clone(),
            // More recent than LO → wins on the recency tie-break when visible.
            valid_from: now - Duration::hours(1),
            visibility: vec![tok_hi],
            confidentiality: det_conf,
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();

    // (B) The playground denial fact: visible ONLY to token 20. A caller holding
    // token 21 (which is NOT in the fact's visibility) is the exact shape the
    // documented playground get-by-id leak hit.
    let denial_source = "hubspot";
    let denial_entity = "det:denial";
    let denial_field = "secret";
    let denial_value = json!("classified-denial-value");
    let denial_tok: i32 = 20;
    let denial_caller_tok: i32 = 21;
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: FactKey {
                source: denial_source.into(),
                entity_id: denial_entity.into(),
                field: denial_field.into(),
            },
            value: denial_value.clone(),
            valid_from: now - Duration::hours(2),
            visibility: vec![denial_tok],
            confidentiality: det_conf,
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();

    // (C) Legacy-style empty-visibility row: seed with a real token, then correct
    // its ACL to '{}' (models the 0026 fail-closed backfill / a full un-share).
    // Must be invisible to EVERY scope, including a broad all-principal one.
    let legacy_source = "salesforce";
    let legacy_entity = "det:legacy";
    let legacy_field = "name";
    let legacy_key = FactKey {
        source: legacy_source.into(),
        entity_id: legacy_entity.into(),
        field: legacy_field.into(),
    };
    adapter
        .upsert_fact(FactWrite {
            tenant_id: tenant,
            key: legacy_key.clone(),
            value: json!("legacy-name"),
            valid_from: now - Duration::hours(2),
            visibility: vec![1],
            confidentiality: Confidentiality::Public,
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        })
        .await
        .unwrap();
    let emptied = adapter
        .correct_fact_acl(
            tenant,
            &legacy_key,
            &[], // empty visibility — the fail-closed / legacy shape
            Confidentiality::Public,
            AclCorrectionReason::SourceUnshare,
            AclProvenance::AdminAssigned,
            Some("fuzz-legacy"),
        )
        .await
        .unwrap();
    assert!(
        emptied >= 1,
        "correct_fact_acl should have rewritten the legacy row's ACL in place"
    );

    // Probe (A): a scope holding ONLY tok_lo (+ the det conf ceiling, + the
    // canonical in entity_scope range via empty entity_scope) must see LO win
    // and never HI.
    {
        let lo_only = Scope {
            tenant_id: tenant,
            principals: vec![tok_lo],
            entity_scope: vec![],
            max_confidentiality: det_conf,
        };
        let merged = adapter
            .merged_record(&lo_only, det_canonical)
            .await
            .unwrap();
        let name = merged
            .fields
            .get("name")
            .expect("lo_only should see the LO member's name");
        assert_eq!(
            name.value, det_lo_value,
            "merged_record leaked the HI (invisible) member's value to a LO-only scope"
        );
        assert!(
            name.superseded_alternatives
                .iter()
                .all(|a| a.value != det_hi_value),
            "merged_record surfaced the invisible HI member as a superseded_alternative"
        );
        // current_fact on the HI member itself must be None for this scope.
        let hi_key = FactKey {
            source: member_hi_source.into(),
            entity_id: member_hi_entity.into(),
            field: "name".into(),
        };
        assert!(
            adapter
                .current_fact(&lo_only, &hi_key)
                .await
                .unwrap()
                .is_none(),
            "current_fact leaked the colon-source HI member to a LO-only scope"
        );

        // The mirror scope (tok_hi only) sees HI win — proves the colon-source
        // member is reachable at all (guards against a silent colon-drop making
        // the test vacuous).
        let hi_only = Scope {
            tenant_id: tenant,
            principals: vec![tok_hi],
            entity_scope: vec![],
            max_confidentiality: det_conf,
        };
        let merged_hi = adapter
            .merged_record(&hi_only, det_canonical)
            .await
            .unwrap();
        assert_eq!(
            merged_hi.fields.get("name").expect("hi sees name").value,
            det_hi_value,
            "colon-source HI member should win for a scope that can see it"
        );
        // Admin plane sees HI win (higher recency) over EVERYTHING.
        let merged_admin = adapter
            .merged_record_admin(tenant, det_canonical)
            .await
            .unwrap();
        assert_eq!(
            merged_admin
                .fields
                .get("name")
                .expect("admin sees name")
                .value,
            det_hi_value,
            "admin merged_record should resolve over all members"
        );
    }

    // Probe (B): the playground denial scenario. A caller with denial_caller_tok
    // (not in the fact's visibility) gets None from current_fact + fact_as_of,
    // and the value never wins in merged_record over the denial entity.
    {
        let denied = Scope {
            tenant_id: tenant,
            principals: vec![denial_caller_tok],
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted, // ceiling can't rescue it
        };
        let denial_key = FactKey {
            source: denial_source.into(),
            entity_id: denial_entity.into(),
            field: denial_field.into(),
        };
        assert!(
            adapter
                .current_fact(&denied, &denial_key)
                .await
                .unwrap()
                .is_none(),
            "DENIAL LEAK: current_fact returned the fact to a caller whose tokens exclude it"
        );
        assert!(
            adapter
                .fact_as_of(&denied, &denial_key, now)
                .await
                .unwrap()
                .is_none(),
            "DENIAL LEAK: fact_as_of returned the fact to a caller whose tokens exclude it"
        );
        let merged = adapter.merged_record(&denied, denial_entity).await.unwrap();
        assert!(
            merged
                .fields
                .get(denial_field)
                .map(|f| f.value != denial_value)
                .unwrap_or(true),
            "DENIAL LEAK: merged_record surfaced the denied fact's value"
        );
        // The authorized caller (token 20) DOES see it — proves the fact exists
        // and the denial above is real, not vacuous.
        let allowed = Scope {
            tenant_id: tenant,
            principals: vec![denial_tok],
            entity_scope: vec![],
            max_confidentiality: det_conf,
        };
        let ok = adapter.current_fact(&allowed, &denial_key).await.unwrap();
        assert_eq!(
            ok.expect("authorized caller must see the denial fact")
                .value,
            denial_value,
            "authorized caller saw the wrong value"
        );
    }

    // Probe (C): the emptied legacy row is invisible to a broad all-principal,
    // top-ceiling scope — the strongest possible reader.
    {
        let broad = Scope {
            tenant_id: tenant,
            principals: (0..=63).collect(),
            entity_scope: vec![],
            max_confidentiality: Confidentiality::Restricted,
        };
        assert!(
            adapter
                .current_fact(&broad, &legacy_key)
                .await
                .unwrap()
                .is_none(),
            "LEGACY LEAK: an empty-visibility fact was visible to a broad scope"
        );
        assert!(
            adapter
                .fact_as_of(&broad, &legacy_key, now)
                .await
                .unwrap()
                .is_none(),
            "LEGACY LEAK: empty-visibility fact reachable via fact_as_of"
        );
        // Admin plane still sees it (remediation path).
        let admin = adapter
            .merged_record_admin(tenant, legacy_entity)
            .await
            .unwrap();
        assert!(
            admin.fields.contains_key(legacy_field),
            "admin plane should still see the emptied legacy row for remediation"
        );
    }
    let det_probes = 12usize; // fixed deterministic scope assertions above

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

        // Path 5: materialized brief item-serving (SPEC §2 L3). The brief is
        // materialized under a broad scope, but the SERVED items come through
        // the caller-scoped latest_chunks path — probe it against an entity
        // that already has a materialized (broad) brief and assert the same
        // no-leak predicate. This is the "materialized brief never leaks an
        // item the caller's scope excludes" invariant.
        let brief_entity = ENTITIES.choose(&mut rng).unwrap().to_string();
        // The brief exists (materialized above); serving is caller-scoped.
        let brief_items = adapter
            .latest_chunks(&scope, &brief_entity, 100)
            .await
            .unwrap();
        probes += 1;
        let entity_query_ok =
            scope.entity_scope.is_empty() || scope.entity_scope.contains(&brief_entity);
        for hit in &brief_items {
            assert!(
                hit.entity_tags.contains(&brief_entity),
                "LEAK via brief: {} returned for entity {brief_entity} it isn't tagged with",
                hit.document_id
            );
            if let Some(model) = chunk_by_doc(&hit.document_id) {
                assert!(
                    model.visibility.iter().any(|t| scope.principals.contains(t))
                        && model.confidentiality <= scope.max_confidentiality as i16
                        && entity_query_ok,
                    "LEAK via brief: materialized brief for {brief_entity} served item {} the scope {scope:?} excludes (vis {:?}, conf {})",
                    hit.document_id, model.visibility, model.confidentiality
                );
                assert!(
                    !model.superseded || hit.content.contains("current"),
                    "STALE LEAK via brief: superseded {} served",
                    hit.document_id
                );
            }
        }

        // Path 6: L1 POINT READS — current_fact + fact_as_of. This is the exact
        // gap the fuzzer previously did not cover (it probed only recall), which
        // is why the L1 fact-visibility leak survived. For every seeded key, the
        // scoped read must return the row IFF the shared oracle admits it — and
        // when it returns, it must carry the right value (current, or as-of).
        for m in &fact_models {
            let key = m.key();
            let oracle = fact_oracle(&scope, m);

            let got = adapter.current_fact(&scope, &key).await.unwrap();
            probes += 1;
            match &got {
                Some(row) => {
                    assert!(
                        oracle,
                        "LEAK via current_fact: scope {scope:?} read {key:?} (vis {:?}, conf {}) the oracle forbids",
                        m.visibility, m.confidentiality
                    );
                    assert_eq!(
                        &row.value,
                        m.current_value(),
                        "current_fact returned a non-current value for {key:?}"
                    );
                    // Defense in depth: the returned row must itself pass the oracle.
                    assert!(fact_visible(&scope, row), "current_fact row fails fact_visible");
                }
                None => assert!(
                    !oracle,
                    "COMPLETENESS GAP via current_fact: scope {scope:?} should see {key:?} (vis {:?}, conf {}) but got None",
                    m.visibility, m.confidentiality
                ),
            }

            // fact_as_of at several points, incl. before the first write and
            // between versions. Because ACL corrections are in-place across all
            // rows, the CURRENT ACL gates every historical read too — the oracle
            // is the same regardless of `at`.
            let firstvf = m.history.first().unwrap().0;
            for at in [
                firstvf - Duration::minutes(30), // before any value existed
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
                            "LEAK via fact_as_of: scope {scope:?} read {key:?} @ {at} the oracle forbids"
                        );
                        assert_eq!(&row.value, val, "fact_as_of wrong value for {key:?} @ {at}");
                        assert!(
                            fact_visible(&scope, row),
                            "fact_as_of row fails fact_visible"
                        );
                    }
                    (Some(_), None) => panic!(
                        "fact_as_of returned a row for {key:?} @ {at} before its first write"
                    ),
                    (None, _) => {
                        // None is correct when EITHER the oracle forbids OR there
                        // was no value at `at`. A leak would be Some-when-forbidden,
                        // caught above.
                    }
                }
            }
        }

        // Path 7: merged_record — precedence resolves over caller-VISIBLE facts
        // only. For each canonical entity, the winning value of every resolved
        // field must come from an oracle-VISIBLE fact, and no superseded
        // alternative may be oracle-invisible. Compare against merged_record_admin
        // (all-seeing) to confirm the scoped view is a strict subset.
        for entity in ENTITIES {
            let merged = adapter.merged_record(&scope, entity).await.unwrap();
            probes += 1;
            for (field, mf) in &merged.fields {
                // The winning (source, entity, field, value) must be an
                // oracle-visible seeded fact.
                let winner = fact_models.iter().find(|m| {
                    m.source == mf.winning_source
                        && &m.entity == entity
                        && &m.field == field
                        && m.current_value() == &mf.value
                });
                let winner = winner.unwrap_or_else(|| {
                    panic!(
                        "merged_record winner {field}={:?} maps to no seeded fact",
                        mf.value
                    )
                });
                assert!(
                    fact_oracle(&scope, winner),
                    "LEAK via merged_record: scope {scope:?} field {field} won by an INVISIBLE fact (source {}, vis {:?})",
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
                        "LEAK via merged_record: an INVISIBLE fact surfaced as a superseded_alternative for {field}"
                    );
                }
            }
        }
    }
    probes += det_probes;
    println!(
        "scope fuzz: {probes} probes ({det_probes} deterministic: colon-source multi-member \
         canonical, playground denial, legacy empty-visibility) across recall(bm25), \
         recall(hybrid), activity, brief, current_fact, fact_as_of, merged_record — no leaks"
    );
}

// ============================================================================
// M1 PERMISSION-CHANGE FUZZER BATTERY (build #4)
//
// The scope-soundness fuzzer above proves a STATIC corpus never leaks. This
// battery proves the CHANGE surface: after a source ACL TIGHTENS (a principal
// loses access), the read path DROPS the content — and stays dropped
// independent of when the reader's handle was minted (a 12h handle minted
// before the change must still see the content vanish; the ACL rewrite is
// bi-temporal-history-inclusive so `?as_of=` can't resurface it either).
//
// LANE COVERAGE. The four revocation lanes named in the M1 plan converge on two
// storage-observable mechanisms:
//   * object un-share  → `correct_fact_acl` / `correct_chunk_acl` (in-place ACL
//     rewrite across the whole lineage). EXERCISED HERE, at the storage layer.
//   * admin group-remove / directory-sync diff / out-of-band Watch delete →
//     `RevocationPlane::record` + the durable `subtract` keyed off the handle's
//     `issued_at`. That plane lives in verity-server; its cross-window-boundary
//     + past-TTL assertion is the B1 must-have test
//     `revocation_outlives_max_ttl_for_prior_minted_handle` (revocation.rs).
//     This battery is the object-un-share half of the same guarantee.
//
// SLO. Per lane we time source-change→invisible (the correction call + the
// first read that returns empty) and report p50/p95, honest at the stated
// corpus size + hardware — the revocation-window security property is derived
// from these measured numbers, not a bare env default.
// ============================================================================

/// Wall-clock for one lane's source-change→invisible measurement.
fn pctl(mut xs: Vec<f64>, p: f64) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((xs.len() as f64 - 1.0) * p).round() as usize;
    xs[idx]
}

#[tokio::test]
async fn permission_change_drops_content_across_lanes() {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the M1 permission-change battery \
         permission_change_drops_content_across_lanes; refusing to silently no-op — a change-surface \
         freshness gate that skips is exactly the M1 leak it exists to close",
    );
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("permchange-{}", uuid::Uuid::now_v7()))
        .await
        .unwrap();
    let episode = adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "fuzz".into(),
            source_entity: None,
            kind: EpisodeKind::CdcEvent,
            payload: json!({}),
            content_hash: "permchange".into(),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .unwrap();

    let now = Utc::now();
    // The reader's token. `keeper` is a principal that KEEPS access; `loser` is
    // the one un-shared each round. A scope holding only `loser` must go blind
    // after the correction; a scope holding `keeper` must still see the content
    // (proves the rewrite retracts precisely, not indiscriminately).
    let loser: i32 = 7;
    let keeper: i32 = 3;

    // A scope minted "12h ago" is modeled here by the fact that a storage-layer
    // ACL rewrite is TIME-INDEPENDENT: it rewrites current + superseded rows, so
    // any handle — freshly minted or minted before the change — reads the new
    // ACL. We probe with a plain Scope (the enforcement predicate is the same
    // one every handle age compiles to); the past-TTL/window-boundary dimension
    // for the tombstone lanes is covered in revocation.rs.
    let loser_scope = Scope {
        tenant_id: tenant,
        principals: vec![loser],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    };
    let keeper_scope = Scope {
        tenant_id: tenant,
        principals: vec![keeper],
        entity_scope: vec![],
        max_confidentiality: Confidentiality::Restricted,
    };

    const ROUNDS: usize = 40;
    let mut chunk_latencies: Vec<f64> = Vec::with_capacity(ROUNDS);
    let mut fact_latencies: Vec<f64> = Vec::with_capacity(ROUNDS);

    for r in 0..ROUNDS {
        // ---- LANE: object un-share of a DOCUMENT (fan-out lineage) -----------
        // One document, multiple seqs + a superseded version, all visible to
        // BOTH loser and keeper. Then un-share to keeper-only and assert the
        // loser goes blind while the keeper still sees it.
        let doc = format!("permchange-doc-{r}");
        let entity = ENTITIES[r % ENTITIES.len()].to_string();
        let mut writes = Vec::new();
        for seq in 0..3 {
            writes.push(ChunkWrite {
                tenant_id: tenant,
                source: "fuzz".into(),
                document_id: doc.clone(),
                seq,
                content: format!("{MAGIC} unshare payload {r}-{seq}"),
                content_hash: format!("{doc}-{seq}"),
                embedding: None,
                visibility: vec![loser, keeper],
                entity_tags: vec![entity.clone()],
                confidentiality: Confidentiality::Internal,
                trust_tier: TrustTier::Authoritative,
                valid_from: now - Duration::hours(2),
                provenance: episode,
                acl_provenance: AclProvenance::AdminAssigned,
                derived_from: vec![],
            });
        }
        // A superseded version of seq 0 (a prior value row) — must ALSO be
        // rewritten so `?as_of=` can't resurface the old permissive ACL.
        writes.push(ChunkWrite {
            tenant_id: tenant,
            source: "fuzz".into(),
            document_id: doc.clone(),
            seq: 0,
            content: format!("{MAGIC} unshare current {r}"),
            content_hash: format!("{doc}-0-v2"),
            embedding: None,
            visibility: vec![loser, keeper],
            entity_tags: vec![entity.clone()],
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: now - Duration::hours(1),
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
            derived_from: vec![],
        });
        adapter.upsert_chunks(writes).await.unwrap();

        // BEFORE: the loser sees the document.
        let before = adapter
            .latest_chunks(&loser_scope, &entity, 100)
            .await
            .unwrap();
        assert!(
            before.iter().any(|c| c.document_id == doc),
            "round {r}: loser should see the document BEFORE the un-share"
        );

        // CHANGE + first-invisible read: time source-change→invisible.
        let t0 = std::time::Instant::now();
        let rewritten = adapter
            .correct_chunk_acl(
                tenant,
                "fuzz",
                &doc,
                &[keeper], // un-share the loser: keeper-only now
                Confidentiality::Internal,
                AclCorrectionReason::SourceUnshare,
                AclProvenance::Mirrored,
                Some("permchange-fuzz"),
            )
            .await
            .unwrap();
        assert!(
            rewritten >= 4,
            "round {r}: un-share must rewrite all 3 seqs + the superseded row (got {rewritten})"
        );
        let after = adapter
            .latest_chunks(&loser_scope, &entity, 100)
            .await
            .unwrap();
        chunk_latencies.push(t0.elapsed().as_secs_f64() * 1000.0);
        assert!(
            !after.iter().any(|c| c.document_id == doc),
            "RETRACTION LEAK round {r}: loser STILL sees the un-shared document via latest_chunks"
        );

        // The keeper still sees every current seq (precise retraction).
        let keeper_view = adapter
            .latest_chunks(&keeper_scope, &entity, 100)
            .await
            .unwrap();
        let keeper_seqs = keeper_view.iter().filter(|c| c.document_id == doc).count();
        assert!(
            keeper_seqs >= 3,
            "round {r}: keeper must still see all 3 seqs after the loser's un-share (saw {keeper_seqs})"
        );
        // recall(bm25) must also drop it for the loser.
        let recalled = adapter
            .recall(RecallQuery {
                scope: loser_scope.clone(),
                embedding: None,
                text: Some(MAGIC.to_string()),
                k: 100,
            })
            .await
            .unwrap();
        assert!(
            !recalled.iter().any(|h| h.document_id == doc),
            "RETRACTION LEAK round {r}: loser STILL recalls the un-shared document"
        );

        // ---- LANE: object un-share of a FACT (value-history carve-out) -------
        let fkey = FactKey {
            source: "fuzz".into(),
            entity_id: format!("permchange-ent-{r}"),
            field: "name".into(),
        };
        // Two value versions so the correction must touch history too.
        for (v, vf) in [(0, now - Duration::hours(2)), (1, now - Duration::hours(1))] {
            adapter
                .upsert_fact(FactWrite {
                    tenant_id: tenant,
                    key: fkey.clone(),
                    value: json!(format!("permchange-{r}-v{v}")),
                    valid_from: vf,
                    visibility: vec![loser, keeper],
                    confidentiality: Confidentiality::Internal,
                    provenance: episode,
                    acl_provenance: AclProvenance::AdminAssigned,
                })
                .await
                .unwrap();
        }
        // BEFORE: loser reads it (current + historical).
        assert!(
            adapter
                .current_fact(&loser_scope, &fkey)
                .await
                .unwrap()
                .is_some(),
            "round {r}: loser should read the fact BEFORE the un-share"
        );

        let t1 = std::time::Instant::now();
        let n = adapter
            .correct_fact_acl(
                tenant,
                &fkey,
                &[keeper],
                Confidentiality::Internal,
                AclCorrectionReason::SourceUnshare,
                AclProvenance::Mirrored,
                Some("permchange-fuzz"),
            )
            .await
            .unwrap();
        assert!(
            n >= 1,
            "round {r}: fact un-share must rewrite the key in place"
        );
        let after_fact = adapter.current_fact(&loser_scope, &fkey).await.unwrap();
        fact_latencies.push(t1.elapsed().as_secs_f64() * 1000.0);
        assert!(
            after_fact.is_none(),
            "RETRACTION LEAK round {r}: loser STILL reads the un-shared fact (current_fact)"
        );
        // `?as_of=` must NOT resurface the old permissive ACL (value-history
        // carve-out — the §5e.6b guard).
        let historical = adapter
            .fact_as_of(&loser_scope, &fkey, now - Duration::minutes(90))
            .await
            .unwrap();
        assert!(
            historical.is_none(),
            "VALUE-HISTORY LEAK round {r}: loser reached a historical value via ?as_of= after un-share"
        );
        // The keeper still reads it.
        assert!(
            adapter
                .current_fact(&keeper_scope, &fkey)
                .await
                .unwrap()
                .is_some(),
            "round {r}: keeper must still read the fact after the loser's un-share"
        );
    }

    let chunk_p50 = pctl(chunk_latencies.clone(), 0.50);
    let chunk_p95 = pctl(chunk_latencies.clone(), 0.95);
    let fact_p50 = pctl(fact_latencies.clone(), 0.50);
    let fact_p95 = pctl(fact_latencies.clone(), 0.95);
    println!(
        "M1 permission-change battery: {ROUNDS} rounds x 2 object-un-share lanes — no retraction \
         leaks. source-change→invisible (correction + first-empty read), ParadeDB PG17 local:\n  \
         object-unshare/chunk: p50 {chunk_p50:.1}ms p95 {chunk_p95:.1}ms\n  \
         object-unshare/fact:  p50 {fact_p50:.1}ms p95 {fact_p95:.1}ms\n  \
         (tombstone lanes — admin-remove / dir-sync / watch-delete — measured in \
         revocation.rs: durable subtract across the window boundary AND past handle-TTL)"
    );
}
