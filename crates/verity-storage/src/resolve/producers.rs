//! S1 — Tier-1 exact-key producers (deterministic, no LLM).
//! `docs/design/cross-source-entity-resolution.md` §4.2 (S1), §4.4.
//!
//! These functions turn a tenant's current L1 facts into `tier=1`
//! [`EvidenceWrite`] rows for the append-only ledger. Three producers, matching
//! the three STRONG deterministic keys the codebase actually has (§1):
//!
//! 1. **intra-CRM FK** ([`tier1_crm_fk_evidence`]) — `Contact.AccountId` and
//!    friends: an *exact* foreign key *within one CRM*. `method = "crm_fk"`.
//! 2. **exact email person↔person WITHIN a namespace**
//!    ([`tier1_email_within_namespace_evidence`]) — two contacts sharing a
//!    canonical email are the same person, but **only** if they are in the same
//!    `key_namespace` (§4.4 fence — an internal actor email never welds to a
//!    customer contact). `method = "email_exact"`.
//! 3. **exact external_id crosswalk** ([`tier1_external_id_evidence`]) — two
//!    refs carrying the same synced third-party id (e.g. a shared
//!    `stripe_customer_id`). `method = "external_id"`.
//!
//! **Purity for testability.** Every producer is a pure function over plain
//! input records (`&[…Fact]`) returning `Vec<EvidenceWrite>` — no DB, no I/O.
//! The DB-backed [`Tier1Producers`] driver wraps them: it reads
//! `entity_resolution_config` (for `eligible_as_edge` + tenant `denylist_values`)
//! and calls `insert_evidence`.
//!
//! **What these do NOT decide.** A producer emits *evidence that a key matched*.
//! Whether that evidence *auto-merges* two refs is the fold's (S4) job, subject
//! to `min_independent_keys` and anti-links. A lone shared domain producing one
//! Tier-1 row does not, by itself, merge anything — that guard lives in the fold.

use std::collections::HashMap;

use verity_core::types::*;

use super::canon::{
    canonicalize_domain, canonicalize_email, is_denylisted, CanonKey, KeyKind, KeyNamespace,
};

/// A member of an email-key group: `(ref, canonical_email, evidence_l0_ref)`.
type EmailGroupMember = (String, String, Option<String>);
/// A member of an external-id group: `(ref, evidence_l0_ref)`.
type ExternalIdGroupMember = (String, Option<String>);

/// Build a canonical ref string `source:entity_id` (the ledger's `left_ref` /
/// `right_ref` shape). The fold splits it back on the first `:` — so `source`
/// must not contain a `:`; entity_id may.
pub fn make_ref(source: &str, entity_id: &str) -> String {
    format!("{source}:{entity_id}")
}

/// Order two refs deterministically so an edge `(a,b)` and `(b,a)` produce the
/// same `(left_ref, right_ref)` — the ledger stays dedupe-friendly and the fold
/// reproducible. Returns `(left, right)` with `left <= right`.
fn ordered(a: String, b: String) -> (String, String) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

// ---------------------------------------------------------------------------
// Input records (plain data — the fold/ingestion layer fills these from L1).
// ---------------------------------------------------------------------------

/// A CRM contact/child row carrying an intra-CRM foreign key to a parent (the
/// `Contact.AccountId` shape). `source` is the CRM (`salesforce`/`hubspot`);
/// `entity_id` is this row's native id; `parent_kind`+`parent_id` name the FK
/// target (e.g. `account` / `001xACME`). `evidence_l0_ref` is the L0 lineage
/// pointer (optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrmContactFact {
    pub source: String,
    pub entity_id: String,
    /// The FK target kind, e.g. `account`. Used only to build the parent ref.
    pub parent_kind: String,
    /// The FK target native id, e.g. `001xACME`. Empty / whitespace ⇒ no edge.
    pub parent_id: String,
    pub evidence_l0_ref: Option<String>,
}

/// A contact-with-email fact. `source:entity_id` names the person ref; `email`
/// is the *raw* address (canonicalized here); `field` names the source field it
/// was read from so the §4.4 namespace can be stamped mechanically, OR the
/// caller may pass an explicit `namespace` override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailFact {
    pub source: String,
    pub entity_id: String,
    pub email: String,
    /// The canonicalized population this email belongs to (§4.4). Producers
    /// require this to be explicit — it is a provenance fact, not derivable from
    /// the string.
    pub namespace: KeyNamespace,
    pub evidence_l0_ref: Option<String>,
}

/// A ref carrying a shared external identifier synced from a third party (e.g.
/// a `stripe_customer_id`, a data-provider id). Two refs with the same
/// `(id_kind, id_value)` are the same entity. `id_value` is compared *exactly*
/// after trimming — external ids are opaque, so no lexical normalization beyond
/// trim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdFact {
    pub source: String,
    pub entity_id: String,
    /// The id namespace, e.g. `stripe_customer`, `duns`. Used as the config
    /// `key_namespace` so an edge only forms within one id system.
    pub id_kind: String,
    pub id_value: String,
    pub evidence_l0_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// Pure producers.
// ---------------------------------------------------------------------------

/// **intra-CRM FK producer.** For each contact/child fact carrying a non-empty
/// parent FK, emit one `tier=1, method="crm_fk"` link between the child ref and
/// the parent ref, *both within the same CRM source*. This is exact and
/// deterministic — no key normalization needed beyond trimming the id.
///
/// The parent ref is `source:parent_id` — i.e. the FK stays inside the CRM
/// (Salesforce `Contact.AccountId` points at a Salesforce `Account`), never
/// crossing sources. `key_value` records `parent_kind:parent_id` for audit;
/// `key_namespace` is `None` (an FK is not an email/domain population key).
pub fn tier1_crm_fk_evidence(tenant: TenantId, facts: &[CrmContactFact]) -> Vec<EvidenceWrite> {
    let mut out = Vec::new();
    for f in facts {
        let parent_id = f.parent_id.trim();
        let child_id = f.entity_id.trim();
        if parent_id.is_empty() || child_id.is_empty() || f.source.trim().is_empty() {
            continue;
        }
        let child_ref = make_ref(&f.source, child_id);
        let parent_ref = make_ref(&f.source, parent_id);
        if child_ref == parent_ref {
            continue; // self-reference is not evidence.
        }
        let (left_ref, right_ref) = ordered(child_ref, parent_ref);
        out.push(EvidenceWrite {
            tenant_id: tenant,
            left_ref,
            right_ref,
            tier: 1,
            method: "crm_fk".to_string(),
            key_value: Some(format!("{}:{}", f.parent_kind.trim(), parent_id)),
            key_namespace: None,
            score: None,
            evidence_l0_ref: f.evidence_l0_ref.clone(),
            polarity: 1,
        });
    }
    out
}

/// **exact email person↔person WITHIN a namespace producer.** Canonicalize every
/// email (lowercase, strip `+tag`, drop denylisted role/free-mail addresses),
/// then group refs by `(namespace, canonical_email)` and emit a `tier=1,
/// method="email_exact"` link between **every pair** of distinct refs in a
/// group.
///
/// **The §4.4 fence is structural here:** grouping is keyed by *namespace as well
/// as email*, so an `internal_directory` `jane@acme.dev` and a
/// `customer_contact` `jane@acme.dev` land in *different* groups and never form
/// an edge — even with a byte-identical address. Refs sharing an email within a
/// group are ordered so the ledger stays dedupe-friendly.
///
/// `denylist` is the tenant's *additional* denied values (from
/// `entity_resolution_config`), applied on top of the built-in floor; pass an
/// empty slice for the pure/default behavior.
pub fn tier1_email_within_namespace_evidence(
    tenant: TenantId,
    facts: &[EmailFact],
    denylist: &[String],
) -> Vec<EvidenceWrite> {
    // group key -> Vec<(ref, canonical_email, l0)>
    let mut groups: HashMap<(KeyNamespace, String), Vec<EmailGroupMember>> = HashMap::new();

    for f in facts {
        if f.source.trim().is_empty() || f.entity_id.trim().is_empty() {
            continue;
        }
        let Some(key) = canonicalize_email(&f.email, f.namespace) else {
            continue; // malformed / denylisted (free-mail, role local).
        };
        if is_tenant_denied(&key, denylist) {
            continue;
        }
        let r = make_ref(f.source.trim(), f.entity_id.trim());
        groups
            .entry((key.namespace, key.value.clone()))
            .or_default()
            .push((r, key.value, f.evidence_l0_ref.clone()));
    }

    let mut out = Vec::new();
    for ((namespace, email), mut members) in groups {
        // Distinct refs only, sorted for determinism.
        members.sort_by(|a, b| a.0.cmp(&b.0));
        members.dedup_by(|a, b| a.0 == b.0);
        if members.len() < 2 {
            continue; // a single ref bearing an email is not a link.
        }
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                let (left_ref, right_ref) = ordered(members[i].0.clone(), members[j].0.clone());
                // Carry either side's l0 pointer (prefer the left one present).
                let l0 = members[i].2.clone().or_else(|| members[j].2.clone());
                out.push(EvidenceWrite {
                    tenant_id: tenant,
                    left_ref,
                    right_ref,
                    tier: 1,
                    method: "email_exact".to_string(),
                    key_value: Some(email.clone()),
                    key_namespace: Some(namespace.as_str().to_string()),
                    score: None,
                    evidence_l0_ref: l0,
                    polarity: 1,
                });
            }
        }
    }
    // Stable output order for reproducible ingestion.
    out.sort_by(|a, b| {
        (&a.left_ref, &a.right_ref, &a.key_value).cmp(&(&b.left_ref, &b.right_ref, &b.key_value))
    });
    out
}

/// **exact external_id crosswalk producer.** Group refs by `(id_kind,
/// trimmed id_value)` and emit a `tier=1, method="external_id"` link between
/// every pair sharing the same external id. `key_namespace` is the `id_kind`
/// (an edge only forms within one id system); `key_value` is the id value.
///
/// Empty id values are ignored. Like the email producer, output is pairwise over
/// each group and deterministically ordered.
pub fn tier1_external_id_evidence(
    tenant: TenantId,
    facts: &[ExternalIdFact],
    denylist: &[String],
) -> Vec<EvidenceWrite> {
    let mut groups: HashMap<(String, String), Vec<ExternalIdGroupMember>> = HashMap::new();
    for f in facts {
        let id_value = f.id_value.trim();
        let id_kind = f.id_kind.trim();
        if id_value.is_empty()
            || id_kind.is_empty()
            || f.source.trim().is_empty()
            || f.entity_id.trim().is_empty()
        {
            continue;
        }
        if denylist.iter().any(|d| d.eq_ignore_ascii_case(id_value)) {
            continue;
        }
        let r = make_ref(f.source.trim(), f.entity_id.trim());
        groups
            .entry((id_kind.to_string(), id_value.to_string()))
            .or_default()
            .push((r, f.evidence_l0_ref.clone()));
    }

    let mut out = Vec::new();
    for ((id_kind, id_value), mut members) in groups {
        members.sort_by(|a, b| a.0.cmp(&b.0));
        members.dedup_by(|a, b| a.0 == b.0);
        if members.len() < 2 {
            continue;
        }
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                let (left_ref, right_ref) = ordered(members[i].0.clone(), members[j].0.clone());
                let l0 = members[i].1.clone().or_else(|| members[j].1.clone());
                out.push(EvidenceWrite {
                    tenant_id: tenant,
                    left_ref,
                    right_ref,
                    tier: 1,
                    method: "external_id".to_string(),
                    key_value: Some(id_value.clone()),
                    key_namespace: Some(id_kind.clone()),
                    score: None,
                    evidence_l0_ref: l0,
                    polarity: 1,
                });
            }
        }
    }
    out.sort_by(|a, b| {
        (&a.left_ref, &a.right_ref, &a.key_namespace).cmp(&(
            &b.left_ref,
            &b.right_ref,
            &b.key_namespace,
        ))
    });
    out
}

/// Is `key` denied by the tenant's *additional* denylist (case-insensitive)?
/// The built-in floor is already applied inside the canonicalizers; this layers
/// the per-tenant `entity_resolution_config.denylist_values` on top.
fn is_tenant_denied(key: &CanonKey, denylist: &[String]) -> bool {
    denylist.iter().any(|d| d.eq_ignore_ascii_case(&key.value))
}

/// Public re-export of the domain canonicalizer + denylist check, so a caller
/// building account-level domain evidence (SF `Website` → domain, HubSpot
/// `domain`) can normalize before pairing. (Account-level domain pairing itself
/// is a MEDIUM key gated by `min_independent_keys` in the fold; we expose the
/// building block, not an auto-merge producer, per §4.4.)
pub fn account_domain_key(raw: &str, namespace: KeyNamespace) -> Option<CanonKey> {
    let k = canonicalize_domain(raw, namespace)?;
    if is_denylisted(KeyKind::Domain, &k.value) {
        return None;
    }
    Some(k)
}

// ---------------------------------------------------------------------------
// DB-backed driver.
// ---------------------------------------------------------------------------

use crate::PostgresAdapter;

/// Storage-backed S1 driver: runs the pure producers, then consults
/// `entity_resolution_config` (`eligible_as_edge` + tenant `denylist_values`)
/// and appends each surviving row via `insert_evidence`. This is the seam the
/// ingestion worker calls; it never touches the read path.
///
/// Config lookup is per `(key_kind, key_namespace)`: the email producer looks up
/// `("email", <namespace>)`, external_id looks up `("external_id", <id_kind>)`,
/// and the CRM-FK producer needs no key config (an FK is not a fuzzy key) — it
/// is always eligible. `read_resolution_config` returns sane defaults when no
/// row exists (eligible=true), so an unconfigured tenant still gets Tier-1
/// edges — the fold's `min_independent_keys` is the real merge guard.
pub struct Tier1Producers<'a> {
    adapter: &'a PostgresAdapter,
}

impl<'a> Tier1Producers<'a> {
    pub fn new(adapter: &'a PostgresAdapter) -> Self {
        Self { adapter }
    }

    /// Emit + persist intra-CRM FK evidence. Always eligible (FKs are exact,
    /// not key-quality-gated). Returns the inserted rows.
    pub async fn run_crm_fk(
        &self,
        tenant: TenantId,
        facts: &[CrmContactFact],
    ) -> Result<Vec<EvidenceRow>> {
        let writes = tier1_crm_fk_evidence(tenant, facts);
        self.persist(writes).await
    }

    /// Emit + persist exact-email evidence, gated per-namespace by config. Facts
    /// are partitioned by namespace; each partition's config is read once, and a
    /// namespace whose `("email", ns)` config is `eligible_as_edge = false`
    /// contributes no edges. The tenant `denylist_values` from that config are
    /// applied on top of the built-in floor.
    pub async fn run_email_exact(
        &self,
        tenant: TenantId,
        facts: &[EmailFact],
    ) -> Result<Vec<EvidenceRow>> {
        // Partition by namespace so each gets its own config lookup.
        let mut by_ns: HashMap<&'static str, (KeyNamespace, Vec<EmailFact>)> = HashMap::new();
        for f in facts {
            by_ns
                .entry(f.namespace.as_str())
                .or_insert_with(|| (f.namespace, Vec::new()))
                .1
                .push(f.clone());
        }
        let mut inserted = Vec::new();
        for (ns_str, (ns, ns_facts)) in by_ns {
            let cfg = self
                .adapter
                .read_resolution_config(tenant, KeyKind::Email.as_str(), ns_str)
                .await?;
            let _ = ns; // namespace already carried on each fact.
            if !cfg.eligible_as_edge {
                continue; // this key kind may not form an edge for this namespace.
            }
            let writes =
                tier1_email_within_namespace_evidence(tenant, &ns_facts, &cfg.denylist_values);
            inserted.extend(self.persist(writes).await?);
        }
        Ok(inserted)
    }

    /// Emit + persist exact external_id evidence, gated per-id-system by config
    /// (`("external_id", <id_kind>)`).
    pub async fn run_external_id(
        &self,
        tenant: TenantId,
        facts: &[ExternalIdFact],
    ) -> Result<Vec<EvidenceRow>> {
        // Partition by id_kind for per-system config.
        let mut by_kind: HashMap<String, Vec<ExternalIdFact>> = HashMap::new();
        for f in facts {
            by_kind
                .entry(f.id_kind.trim().to_string())
                .or_default()
                .push(f.clone());
        }
        let mut inserted = Vec::new();
        for (id_kind, kind_facts) in by_kind {
            if id_kind.is_empty() {
                continue;
            }
            let cfg = self
                .adapter
                .read_resolution_config(tenant, KeyKind::ExternalId.as_str(), &id_kind)
                .await?;
            if !cfg.eligible_as_edge {
                continue;
            }
            let writes = tier1_external_id_evidence(tenant, &kind_facts, &cfg.denylist_values);
            inserted.extend(self.persist(writes).await?);
        }
        Ok(inserted)
    }

    async fn persist(&self, writes: Vec<EvidenceWrite>) -> Result<Vec<EvidenceRow>> {
        let mut rows = Vec::with_capacity(writes.len());
        for w in writes {
            rows.push(self.adapter.insert_evidence(w).await?);
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn tenant() -> TenantId {
        Uuid::nil()
    }

    // ---- crm fk -----------------------------------------------------------

    #[test]
    fn crm_fk_emits_child_to_parent_edge() {
        let facts = vec![CrmContactFact {
            source: "salesforce".into(),
            entity_id: "003xJANE".into(),
            parent_kind: "account".into(),
            parent_id: "001xACME".into(),
            evidence_l0_ref: Some("l0:1".into()),
        }];
        let out = tier1_crm_fk_evidence(tenant(), &facts);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(e.tier, 1);
        assert_eq!(e.method, "crm_fk");
        assert_eq!(e.polarity, 1);
        assert!(e.key_namespace.is_none());
        // Both refs are in the same CRM source.
        assert!(e.left_ref.starts_with("salesforce:"));
        assert!(e.right_ref.starts_with("salesforce:"));
        // Deterministic ordering.
        assert!(e.left_ref <= e.right_ref);
        assert_eq!(e.key_value.as_deref(), Some("account:001xACME"));
    }

    #[test]
    fn crm_fk_skips_empty_parent() {
        let facts = vec![CrmContactFact {
            source: "salesforce".into(),
            entity_id: "003xJANE".into(),
            parent_kind: "account".into(),
            parent_id: "   ".into(),
            evidence_l0_ref: None,
        }];
        assert!(tier1_crm_fk_evidence(tenant(), &facts).is_empty());
    }

    #[test]
    fn crm_fk_skips_self_reference() {
        let facts = vec![CrmContactFact {
            source: "salesforce".into(),
            entity_id: "001xACME".into(),
            parent_kind: "account".into(),
            parent_id: "001xACME".into(),
            evidence_l0_ref: None,
        }];
        assert!(tier1_crm_fk_evidence(tenant(), &facts).is_empty());
    }

    // ---- email exact ------------------------------------------------------

    #[test]
    fn email_exact_links_same_person_same_namespace() {
        let facts = vec![
            EmailFact {
                source: "salesforce".into(),
                entity_id: "003A".into(),
                email: "Jane+promo@Acme.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
            EmailFact {
                source: "hubspot".into(),
                entity_id: "77".into(),
                email: "jane@acme.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
        ];
        let out = tier1_email_within_namespace_evidence(tenant(), &facts, &[]);
        assert_eq!(out.len(), 1, "one cross-CRM person edge");
        let e = &out[0];
        assert_eq!(e.method, "email_exact");
        assert_eq!(e.tier, 1);
        assert_eq!(e.key_value.as_deref(), Some("jane@acme.com"));
        assert_eq!(e.key_namespace.as_deref(), Some("customer_contact"));
    }

    #[test]
    fn email_exact_namespace_fence_blocks_internal_to_customer() {
        // Same byte-identical email, DIFFERENT namespace -> NO edge (§4.4).
        let facts = vec![
            EmailFact {
                source: "linear".into(),
                entity_id: "ENG-42".into(),
                email: "jane@acme.com".into(),
                namespace: KeyNamespace::InternalDirectory,
                evidence_l0_ref: None,
            },
            EmailFact {
                source: "salesforce".into(),
                entity_id: "003A".into(),
                email: "jane@acme.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
        ];
        let out = tier1_email_within_namespace_evidence(tenant(), &facts, &[]);
        assert!(
            out.is_empty(),
            "internal_directory email must never weld to a customer_contact ref"
        );
    }

    #[test]
    fn email_exact_links_within_internal_namespace() {
        // Two internal actors sharing an email DO link — the fence is per
        // namespace, not a blanket ban.
        let facts = vec![
            EmailFact {
                source: "linear".into(),
                entity_id: "u1".into(),
                email: "jane@acme.dev".into(),
                namespace: KeyNamespace::InternalDirectory,
                evidence_l0_ref: None,
            },
            EmailFact {
                source: "linear".into(),
                entity_id: "u2".into(),
                email: "jane@acme.dev".into(),
                namespace: KeyNamespace::InternalDirectory,
                evidence_l0_ref: None,
            },
        ];
        let out = tier1_email_within_namespace_evidence(tenant(), &facts, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key_namespace.as_deref(), Some("internal_directory"));
    }

    #[test]
    fn email_exact_denylisted_freemail_forms_no_edge() {
        let facts = vec![
            EmailFact {
                source: "salesforce".into(),
                entity_id: "a".into(),
                email: "jane@gmail.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
            EmailFact {
                source: "hubspot".into(),
                entity_id: "b".into(),
                email: "jane@gmail.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
        ];
        assert!(tier1_email_within_namespace_evidence(tenant(), &facts, &[]).is_empty());
    }

    #[test]
    fn email_exact_role_local_forms_no_edge() {
        let facts = vec![
            EmailFact {
                source: "salesforce".into(),
                entity_id: "a".into(),
                email: "info@acme.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
            EmailFact {
                source: "hubspot".into(),
                entity_id: "b".into(),
                email: "info@acme.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
        ];
        assert!(tier1_email_within_namespace_evidence(tenant(), &facts, &[]).is_empty());
    }

    #[test]
    fn email_exact_tenant_denylist_applied() {
        let facts = vec![
            EmailFact {
                source: "salesforce".into(),
                entity_id: "a".into(),
                email: "jane@contractor.io".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
            EmailFact {
                source: "hubspot".into(),
                entity_id: "b".into(),
                email: "jane@contractor.io".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
        ];
        // Tenant denies this specific canonical email.
        let out = tier1_email_within_namespace_evidence(
            tenant(),
            &facts,
            &["jane@contractor.io".to_string()],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn email_exact_three_refs_form_all_pairs() {
        let facts = vec![
            EmailFact {
                source: "salesforce".into(),
                entity_id: "a".into(),
                email: "jane@acme.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
            EmailFact {
                source: "hubspot".into(),
                entity_id: "b".into(),
                email: "jane@acme.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
            EmailFact {
                source: "zendesk".into(),
                entity_id: "c".into(),
                email: "jane@acme.com".into(),
                namespace: KeyNamespace::CustomerContact,
                evidence_l0_ref: None,
            },
        ];
        let out = tier1_email_within_namespace_evidence(tenant(), &facts, &[]);
        assert_eq!(out.len(), 3, "3 refs -> C(3,2) = 3 pairwise edges");
    }

    #[test]
    fn email_exact_single_ref_no_edge() {
        let facts = vec![EmailFact {
            source: "salesforce".into(),
            entity_id: "a".into(),
            email: "jane@acme.com".into(),
            namespace: KeyNamespace::CustomerContact,
            evidence_l0_ref: None,
        }];
        assert!(tier1_email_within_namespace_evidence(tenant(), &facts, &[]).is_empty());
    }

    // ---- external id ------------------------------------------------------

    #[test]
    fn external_id_links_shared_id() {
        let facts = vec![
            ExternalIdFact {
                source: "salesforce".into(),
                entity_id: "001xACME".into(),
                id_kind: "stripe_customer".into(),
                id_value: "cus_123".into(),
                evidence_l0_ref: None,
            },
            ExternalIdFact {
                source: "hubspot".into(),
                entity_id: "4207".into(),
                id_kind: "stripe_customer".into(),
                id_value: "cus_123".into(),
                evidence_l0_ref: None,
            },
        ];
        let out = tier1_external_id_evidence(tenant(), &facts, &[]);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(e.method, "external_id");
        assert_eq!(e.key_namespace.as_deref(), Some("stripe_customer"));
        assert_eq!(e.key_value.as_deref(), Some("cus_123"));
    }

    #[test]
    fn external_id_different_id_systems_no_cross_edge() {
        // Same id VALUE but different id_kind -> different namespaces -> no edge.
        let facts = vec![
            ExternalIdFact {
                source: "salesforce".into(),
                entity_id: "a".into(),
                id_kind: "stripe_customer".into(),
                id_value: "123".into(),
                evidence_l0_ref: None,
            },
            ExternalIdFact {
                source: "hubspot".into(),
                entity_id: "b".into(),
                id_kind: "duns".into(),
                id_value: "123".into(),
                evidence_l0_ref: None,
            },
        ];
        assert!(tier1_external_id_evidence(tenant(), &facts, &[]).is_empty());
    }

    #[test]
    fn external_id_skips_empty_value() {
        let facts = vec![ExternalIdFact {
            source: "salesforce".into(),
            entity_id: "a".into(),
            id_kind: "duns".into(),
            id_value: "  ".into(),
            evidence_l0_ref: None,
        }];
        assert!(tier1_external_id_evidence(tenant(), &facts, &[]).is_empty());
    }

    // ---- ref helpers ------------------------------------------------------

    #[test]
    fn ordered_is_commutative() {
        assert_eq!(
            ordered("b".into(), "a".into()),
            ordered("a".into(), "b".into())
        );
    }

    #[test]
    fn make_ref_shape() {
        assert_eq!(make_ref("salesforce", "001xACME"), "salesforce:001xACME");
    }

    // ---- account domain building block -----------------------------------

    #[test]
    fn account_domain_key_from_website_and_freemail() {
        assert_eq!(
            account_domain_key("https://www.acme.com", KeyNamespace::CustomerContact)
                .unwrap()
                .value,
            "acme.com"
        );
        assert!(account_domain_key("gmail.com", KeyNamespace::CustomerContact).is_none());
    }
}
