//! RESOLUTION SCOPE-LEAK FUZZER (SPEC §7e, resolution cases — design
//! `docs/design/cross-source-entity-resolution.md` §6 defense 5 / §8 MVP):
//! seed ADVERSARIAL cross-entity evidence for a tenant, run the deterministic
//! fold through the real storage methods (the same ledger→fold→materialize path
//! the worker runs), then try to retrieve customer A's data through a scope
//! bound to customer B's canonical entity. ANY cross-entity result is a
//! mis-link surfacing across scope handles — a scope leak — and FAILS the
//! build.
//!
//! This mirrors the spirit of `scope_fuzz.rs` (handle enforcement) but probes
//! the RESOLUTION layer: the thing under test is that no adversarial evidence
//! shape (lone shared domain, free-mail collision, cross-namespace actor
//! email, unconfirmed Tier-2, Tier-3 mention, anti-linked strong evidence) can
//! fold A and B into one canonical or drag A's chunks into B's entity scope.
//!
//! Requires VERITY_TEST_DSN; HARD-ERRORS (panics) when absent — a resolution
//! scope-leak gate that silently skips defeats the §7e handle-enforcement
//! invariant; CI sets the DSN so this gate is always live.

use chrono::{Duration, Utc};
use rand::prelude::*;
use rand::rngs::StdRng;
use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::resolve::{
    fold_with_known_canonicals, parse_chunk_ref, FoldConfig, FoldPlan, KnownCanonicals,
};
use verity_storage::PostgresAdapter;

const ITERS: u64 = 5;
const MAGIC: &str = "quantum";

async fn setup() -> PostgresAdapter {
    let dsn = std::env::var("VERITY_TEST_DSN").expect(
        "VERITY_TEST_DSN must be set for the resolution scope-leak soundness fuzzer (SPEC §7e \
         resolution cases); refusing to silently no-op",
    );
    let adapter = PostgresAdapter::connect(&dsn).await.expect("connect");
    adapter.migrate().await.expect("migrate");
    adapter
}

/// The worker-plane fold + materialization, via EXISTING storage methods only:
/// read the live ledger + config, run the pure fold, write aliases / link_meta
/// / chunk tags. This is exactly the surface the read path consumes.
async fn run_fold_and_materialize(a: &PostgresAdapter, t: TenantId) -> FoldPlan {
    let evidence = a.all_live_evidence(t).await.expect("live evidence");
    let rows = a.list_resolution_config(t).await.expect("config rows");
    let fallback = a
        .read_resolution_config(t, "*", "*")
        .await
        .expect("fallback config");
    let cfg = FoldConfig::new(t, rows, fallback);
    let pre = a
        .list_canonical_entities(t, 1000)
        .await
        .expect("pre-existing canonicals");
    let known = KnownCanonicals::new(pre.iter().map(|c| c.canonical_entity.as_str()), []);

    let plan = fold_with_known_canonicals(&evidence, &cfg, &known);

    for al in &plan.aliases {
        a.upsert_entity_alias(t, &al.source, &al.entity_id, &al.canonical_entity)
            .await
            .expect("alias write");
    }
    for m in &plan.link_meta {
        a.upsert_entity_link_meta(m).await.expect("meta write");
    }
    for ct in &plan.chunk_tags {
        if let Some((src, doc, seq)) = parse_chunk_ref(&ct.subject_ref) {
            a.chunk_entity_tags_upsert(t, &src, &doc, seq, &ct.tags)
                .await
                .expect("tag write");
        }
    }
    plan
}

#[allow(clippy::too_many_arguments)]
async fn evidence(
    a: &PostgresAdapter,
    t: TenantId,
    left: &str,
    right: &str,
    tier: i16,
    method: &str,
    key_value: Option<&str>,
    key_namespace: Option<&str>,
    polarity: i16,
) {
    a.insert_evidence(EvidenceWrite {
        tenant_id: t,
        left_ref: left.into(),
        right_ref: right.into(),
        tier,
        method: method.into(),
        key_value: key_value.map(str::to_string),
        key_namespace: key_namespace.map(str::to_string),
        score: if tier == 1 { None } else { Some(0.97) },
        evidence_l0_ref: None,
        polarity,
    })
    .await
    .expect("insert evidence");
}

async fn name_fact(a: &PostgresAdapter, t: TenantId, source: &str, entity_id: &str, name: &str) {
    let episode = a
        .append_episode(NewEpisode {
            tenant_id: t,
            source: source.into(),
            source_entity: Some(entity_id.into()),
            kind: EpisodeKind::CdcEvent,
            payload: json!({ "name": name }),
            content_hash: format!("h-{source}-{entity_id}-{name}"),
            trust_tier: TrustTier::Authoritative,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .unwrap();
    a.upsert_fact(FactWrite {
        tenant_id: t,
        key: FactKey {
            source: source.into(),
            entity_id: entity_id.into(),
            field: "name".into(),
        },
        value: json!(name),
        valid_from: Utc::now(),
        visibility: vec![1],
        confidentiality: Confidentiality::Internal,
        provenance: episode,
        acl_provenance: AclProvenance::Mirrored,
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn no_resolution_cross_entity_scope_leak() {
    let a = setup().await;

    for seed in 0..ITERS {
        let mut rng = StdRng::seed_from_u64(seed);
        let t = a
            .create_tenant(&format!("er-fuzz-{}", uuid::Uuid::now_v7()))
            .await
            .unwrap();

        // ---- Tenant config: freemail denylist, §4.4 namespace fence,
        // min_independent_keys = 2 (the OSS defaults, made explicit). ----
        let mut domain_rule = EntityResolutionConfig::defaults(t, "domain", "customer_contact");
        domain_rule.denylist_values = vec!["gmail.com".into(), "hotmail.com".into()];
        a.write_resolution_config(&domain_rule).await.unwrap();
        let mut internal_email = EntityResolutionConfig::defaults(t, "email", "internal_directory");
        internal_email.eligible_as_edge = false;
        a.write_resolution_config(&internal_email).await.unwrap();

        // ---- Two REAL customers, each two source records + a strong key. ----
        let (a1, a2) = (
            format!("salesforce:A1-{seed}"),
            format!("hubspot:A2-{seed}"),
        );
        let (b1, b2) = (
            format!("salesforce:B1-{seed}"),
            format!("hubspot:B2-{seed}"),
        );
        evidence(
            &a,
            t,
            &a1,
            &a2,
            1,
            "external_id",
            Some(&format!("XID-A-{seed}")),
            Some("customer_contact"),
            1,
        )
        .await;
        evidence(
            &a,
            t,
            &b1,
            &b2,
            1,
            "external_id",
            Some(&format!("XID-B-{seed}")),
            Some("customer_contact"),
            1,
        )
        .await;
        name_fact(&a, t, "salesforce", &format!("A1-{seed}"), "SECRET-A name").await;
        name_fact(&a, t, "salesforce", &format!("B1-{seed}"), "B name").await;

        // ---- Adversarial cross-entity evidence: every §6 attack shape,
        // randomized per seed. NONE of these may fold A and B together. ----
        // lone shared MEDIUM domain (min_independent_keys=2):
        evidence(
            &a,
            t,
            &a1,
            &b1,
            1,
            "domain_match",
            Some(&format!("collide-{seed}.com")),
            Some("customer_contact"),
            1,
        )
        .await;
        // free-mail domain collision (denylisted):
        evidence(
            &a,
            t,
            &a2,
            &b2,
            1,
            "domain_match",
            Some("gmail.com"),
            Some("customer_contact"),
            1,
        )
        .await;
        // cross-namespace actor email (the §4.4 fence):
        evidence(
            &a,
            t,
            &a1,
            &b2,
            1,
            "email_exact",
            Some(&format!("jane-{seed}@evil.dev")),
            Some("internal_directory"),
            1,
        )
        .await;
        // Tier-2 fuzzy WITHOUT human confirmation:
        evidence(
            &a,
            t,
            &a1,
            &b1,
            2,
            "name+domain_fuzzy",
            Some("Acme"),
            Some("customer_contact"),
            1,
        )
        .await;
        // Tier-3 mention:
        evidence(
            &a,
            t,
            &a2,
            &b1,
            3,
            "llm_mention",
            Some("Acme"),
            Some("customer_contact"),
            1,
        )
        .await;
        // Anti-link variant: on odd seeds, ALSO plant a strong positive
        // cross-edge plus a human anti-link — the anti-link must win and the
        // touched component must quarantine (fail closed), never merge.
        let anti_variant = rng.random_bool(0.5);
        if anti_variant {
            evidence(
                &a,
                t,
                &a1,
                &b1,
                1,
                "crm_fk",
                None,
                Some("customer_contact"),
                1,
            )
            .await;
            evidence(
                &a,
                t,
                &a1,
                &b1,
                1,
                "human_rejected",
                None,
                Some("customer_contact"),
                -1,
            )
            .await;
        }

        // ---- Fold + materialize (the worker plane), then read back. ----
        run_fold_and_materialize(&a, t).await;

        let canon_a1 = a.resolve_canonical_for_ref(t, &a1).await.unwrap();
        let canon_a2 = a.resolve_canonical_for_ref(t, &a2).await.unwrap();
        let canon_b1 = a.resolve_canonical_for_ref(t, &b1).await.unwrap();
        let canon_b2 = a.resolve_canonical_for_ref(t, &b2).await.unwrap();

        // The load-bearing assertion: A and B are NEVER the same canonical.
        for ca in [&canon_a1, &canon_a2] {
            for cb in [&canon_b1, &canon_b2] {
                assert_ne!(
                    ca, cb,
                    "seed {seed}: FALSE CROSS-ENTITY MERGE: {ca} == {cb} (anti_variant={anti_variant})"
                );
            }
        }
        if anti_variant {
            // Fail-closed: the anti-linked component quarantines — nobody in
            // the touched component gets an alias (each ref stays its own
            // implicit canonical).
            assert_eq!(canon_a1, a1, "seed {seed}: quarantined ref got aliased");
            assert_eq!(canon_b1, b1, "seed {seed}: quarantined ref got aliased");
        } else {
            // Recall sanity (the fuzzer isn't vacuous): the two LEGIT strong
            // links did fold.
            assert_eq!(canon_a1, canon_a2, "seed {seed}: legit A merge missing");
            assert_eq!(canon_b1, canon_b2, "seed {seed}: legit B merge missing");
        }

        // ---- merged_record through B's canonical must not carry A. ----
        // Use the admin-all plane: entity-resolution isolation must hold even
        // when NO visibility filter can mask a cross-entity member leak.
        let merged_b = a.merged_record_admin(t, &canon_b1).await.unwrap();
        for m in &merged_b.members {
            assert!(
                !m.entity_id.starts_with("A1-") && !m.entity_id.starts_with("A2-"),
                "seed {seed}: merged_record({canon_b1}) leaked member {m:?}"
            );
        }
        for (field, v) in &merged_b.fields {
            assert!(
                !v.value.to_string().contains("SECRET-A"),
                "seed {seed}: merged_record({canon_b1}) field {field} leaked A's value"
            );
        }

        // ---- Chunks: A's doc is tagged with A's canonical, B's with B's. A
        // scope handle bound to B must NEVER surface A's content. ----
        let episode = a
            .append_episode(NewEpisode {
                tenant_id: t,
                source: "fuzz".into(),
                source_entity: None,
                kind: EpisodeKind::CdcEvent,
                payload: json!({}),
                content_hash: format!("er-fuzz-{seed}"),
                trust_tier: TrustTier::Authoritative,
                writer_sub: None,
                writer_azp: None,
            })
            .await
            .unwrap();
        let now = Utc::now();
        let chunk = |doc: &str, content: String, tags: Vec<String>| ChunkWrite {
            tenant_id: t,
            source: "fuzz".into(),
            document_id: doc.into(),
            seq: 0,
            content,
            content_hash: format!("{doc}-{seed}"),
            embedding: None,
            visibility: vec![1], // SAME principal for both: the ONLY separator
            entity_tags: tags,   // is the entity scope — the surface under test.
            confidentiality: Confidentiality::Internal,
            trust_tier: TrustTier::Authoritative,
            valid_from: now - Duration::hours(1),
            provenance: episode,
            acl_provenance: AclProvenance::AdminAssigned,
        };
        let doc_a = format!("doc-A-{seed}");
        let doc_b = format!("doc-B-{seed}");
        a.upsert_chunks(vec![
            chunk(
                &doc_a,
                format!("{MAGIC} SECRET-A payload {seed}"),
                vec![canon_a1.clone()],
            ),
            chunk(
                &doc_b,
                format!("{MAGIC} b-payload {seed}"),
                vec![canon_b1.clone()],
            ),
        ])
        .await
        .unwrap();

        // ---- Adversarial Tier-3 mention trying to drag A's doc into B's
        // scope: evidence that chunk doc-A "mentions" B's canonical. With
        // auto_link_tier3 OFF (default) and no deterministic co-signal, the
        // fold must ABSTAIN — doc-A keeps its A tag, never gains B's. ----
        evidence(
            &a,
            t,
            &format!("chunk:fuzz:{doc_a}:0"),
            &canon_b1,
            3,
            "llm_mention",
            Some("B Corp"),
            Some("customer_contact"),
            1,
        )
        .await;
        let plan2 = run_fold_and_materialize(&a, t).await;
        assert!(
            !plan2
                .chunk_tags
                .iter()
                .any(|ct| ct.subject_ref.contains(&doc_a)),
            "seed {seed}: Tier-3 mention re-tagged A's chunk without co-signal/human: {plan2:?}"
        );

        // ---- The scope handle bound to entity B. ----
        let scope_b = Scope {
            tenant_id: t,
            principals: vec![1],
            entity_scope: vec![canon_b1.clone()],
            max_confidentiality: Confidentiality::Restricted,
        };

        // recall through B's scope: A's secret must never come back.
        let hits = a
            .recall(RecallQuery {
                scope: scope_b.clone(),
                embedding: None,
                text: Some(MAGIC.into()),
                k: 50,
            })
            .await
            .unwrap();
        for h in &hits {
            assert!(
                !h.content.contains("SECRET-A"),
                "seed {seed}: SCOPE LEAK: B-bound scope retrieved A's chunk {} via recall",
                h.document_id
            );
            assert_ne!(
                h.document_id, doc_a,
                "seed {seed}: SCOPE LEAK: B-bound scope retrieved doc-A via recall"
            );
        }

        // latest_chunks (the brief item-serving leg): a B-bound handle asking
        // for A's entity gets NOTHING; asking for B gets no A content.
        let cross = a.latest_chunks(&scope_b, &canon_a1, 50).await.unwrap();
        assert!(
            cross.is_empty(),
            "seed {seed}: SCOPE LEAK: B-bound scope browsed A's entity feed: {:?}",
            cross.iter().map(|c| &c.document_id).collect::<Vec<_>>()
        );
        let own = a.latest_chunks(&scope_b, &canon_b1, 50).await.unwrap();
        for h in &own {
            assert!(
                !h.content.contains("SECRET-A"),
                "seed {seed}: SCOPE LEAK: A content served in B's entity feed ({})",
                h.document_id
            );
        }
    }
    println!("resolution scope fuzz: {ITERS} seeded tenants, zero cross-entity leaks");
}
