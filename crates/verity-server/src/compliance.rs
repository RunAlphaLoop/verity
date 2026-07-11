//! Compliance plane v0 (SPEC §8, roadmap task 23): the admin-only erasure
//! and DSAR-export surfaces.
//!
//! Both are admin verbs, never reachable from an agent scope handle
//! (SPEC §8f — an injected prompt must not be able to trigger destruction of
//! evidence). The heavy lifting lives in verity-storage (erasure.rs); this
//! module is auth + plumbing + the L1 cache flush erasure requires.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use verity_core::types::TenantId;

use crate::{internal, storage_status, AppState, HandlerResult};

/// Domain-separation tag for purge-report HMACs — keeps a purge signature from
/// ever being replayable as a scope handle or a media URI (they share the key).
const PURGE_REPORT_DOMAIN: &str = "verity.erasure.purge-report.v1";

#[derive(Deserialize)]
pub(crate) struct ErasureRequest {
    tenant_id: TenantId,
    /// Data subject: erases episodes with `writer_sub = subject`, actions
    /// with `actor_sub = subject`, the subject's audit rows, and everything
    /// derived from those episodes.
    #[serde(default)]
    subject: Option<String>,
    /// Entity: erases episodes with `source_entity = entity`, facts keyed on
    /// it, chunks tagged with it (multi-tag chunks deleted whole), actions
    /// targeting it. At least one of subject/entity/media_ids is required.
    #[serde(default)]
    entity: Option<String>,
    /// Explicit media blobs to purge in the same transaction (tenant-checked
    /// in storage). Media rows carry no subject attribution in v0, so the
    /// operator names them — GET /v1/admin/media lists the candidates.
    #[serde(default)]
    media_ids: Vec<Uuid>,
}

/// POST /v1/admin/erasure/preview (admin) — the erasure DRY RUN. Walks the
/// EXACT same lineage as `admin_erasure` (via the shared `erase_preview` →
/// `walk_lineage` in verity-storage, inside a transaction that is rolled back),
/// so it PURGES NOTHING but returns the per-table counts a real erasure WOULD
/// delete, plus the honest coverage-gap disclosure (operator-named media,
/// exact-string matching, backup-retention window). Because preview and erase
/// share the walk code, the numbers cannot drift from what erasure does.
///
/// Note the deliberate asymmetry vs `admin_erasure`: the preview does NOT touch
/// SpiceDB (no tuple delete on a dry run) and does NOT enumerate object-store
/// blobs — it reports the DB-row counts a purge would produce. Object-store
/// blob deletion is a side effect of naming `media_ids`, surfaced as the
/// `media` count and the coverage-gap note, not previewed byte-for-byte.
pub(crate) async fn admin_erasure_preview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ErasureRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let preview = state
        .storage
        .inner()
        .erase_preview(
            req.tenant_id,
            req.subject.as_deref(),
            req.entity.as_deref(),
            &req.media_ids,
        )
        .await
        .map_err(storage_status)?;
    // Honest ReBAC signal, mirroring the erasure response: on a REAL erasure of
    // a `user:` subject with SpiceDB configured, tuples would be deleted first.
    let rebac_would_delete = state.rebac.is_some()
        && req
            .subject
            .as_deref()
            .and_then(crate::rebac::parse_principal)
            .map(|(kind, _)| matches!(kind, crate::rebac::PrincipalKind::User))
            .unwrap_or(false);
    Ok(Json(serde_json::json!({
        "dry_run": true,
        "would_erase": preview.would_erase,
        "coverage_gaps": preview.coverage_gaps,
        "rebac_tuples_would_delete": rebac_would_delete,
    })))
}

/// POST /v1/admin/erasure (admin) — the GDPR hard-purge path (SPEC §8b),
/// distinct from `memory.forget` invalidation. One transaction; returns
/// per-table hard-delete counts; leaves exactly one audit row (verb
/// 'erasure', sha256-hashed identifiers, no plaintext PII).
///
/// ReBAC ordering (task 28, fail closed): when SpiceDB is configured and the
/// subject is a `user:` principal, the subject's relationship tuples are
/// deleted FIRST. A tuple-delete failure aborts the whole erasure with 502 —
/// nothing is purged, nothing is half-erased; the operator retries once
/// SpiceDB is healthy. The alternative order (storage first) could leave a
/// deleted subject still granting group membership after a partial failure,
/// which is the direction that leaks; this order at worst over-RETAINS
/// (tuples gone, data pending retry), never over-grants.
pub(crate) async fn admin_erasure(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ErasureRequest>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    state
        .storage
        .inner()
        .ensure_tenant(req.tenant_id)
        .await
        .map_err(storage_status)?;
    let mut rebac_tuples_deleted = false;
    if let (Some(rebac), Some(subject)) = (&state.rebac, req.subject.as_deref()) {
        if let Some((crate::rebac::PrincipalKind::User, name)) =
            crate::rebac::parse_principal(subject)
        {
            rebac
                .delete_subject_relationships(req.tenant_id, name)
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("spicedb tuple delete failed — erasure aborted (fail closed, nothing was purged): {e}"),
                    )
                })?;
            rebac_tuples_deleted = true;
        }
        // Non-`user:` subjects have no SpiceDB object by construction
        // (rebac.rs models users and groups only) — nothing to delete.
    }
    // Object-store purge (task 47, SPEC §8): the DB `erase()` DELETEs media
    // rows in one transaction inside verity-storage, but the physical blobs of
    // storage_ref-backed rows live in object storage and must be purged too.
    // Capture the storage_refs of the named media_ids BEFORE the DB delete,
    // then delete the objects AFTER the row purge commits — so a failed DB
    // erasure never orphans a live row from its deleted blob. bytea rows have
    // NULL storage_ref and are purged with the transaction, nothing to do.
    let storage_refs: Vec<String> = if state.media_store.is_some() && !req.media_ids.is_empty() {
        sqlx::query_scalar(
            "SELECT storage_ref FROM media
             WHERE tenant_id = $1 AND id = ANY($2) AND storage_ref IS NOT NULL",
        )
        .bind(req.tenant_id)
        .bind(&req.media_ids)
        .fetch_all(state.pool())
        .await
        .map_err(internal)?
    } else {
        Vec::new()
    };

    let report = state
        .storage
        .inner()
        .erase(
            req.tenant_id,
            req.subject.as_deref(),
            req.entity.as_deref(),
            &req.media_ids,
        )
        .await
        .map_err(storage_status)?;

    // Rows are gone; now purge their objects. Best-effort per object (a
    // missing object is a no-op); a hard object-store failure surfaces as 502
    // so the operator knows a blob may survive in the bucket and can retry the
    // named media_ids (the DB rows are already gone — re-running erasure with
    // the same ids is a safe no-op on the DB side).
    if let Some(ms) = &state.media_store {
        for key in &storage_refs {
            ms.delete(key).await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("media row purged but object storage delete failed for {key}: {e}"),
                )
            })?;
        }
    }
    // Facts were hard-deleted underneath the L1 current-truth cache.
    state.storage.flush_facts();

    // SERVER-SIGNED PURGE REPORT (replaces the old client-assembled
    // attestation). We sign the *purge facts* — the refs purged (per-table
    // counts), keys destroyed (facts + media are the crypto-shredded rows),
    // timestamps, and the retention window — with an HMAC under the server
    // signing key (same key/minter as scope handles + media URIs, domain-
    // separated). The console now shows a signature the SERVER produced, not
    // one the browser assembled from returned numbers.
    let signed_at = chrono::Utc::now();
    let facts = serde_json::json!({
        "kind": "verity.erasure.purge-report",
        "tenant_id": req.tenant_id,
        // Identifiers are hashed, never plaintext PII — mirrors the surviving
        // audit row so a holder of the report can cross-check it against audit.
        "subject_sha256": req.subject.as_deref().map(sha256_hex),
        "entity_sha256": req.entity.as_deref().map(sha256_hex),
        "media_ids": req.media_ids,
        // The purge facts being attested: refs purged + keys destroyed.
        "erased": report,
        "rebac_tuples_deleted": rebac_tuples_deleted,
        "signed_at": signed_at,
        // The disclosed window during which physical backups may still hold
        // now-purged rows until they age out and are crypto-shredded.
        "retention_window": "Physical backups taken before this purge persist until they age out \
                             of the backup-retention window and are then crypto-shredded; live \
                             rows and keys are destroyed now.",
    });

    let purge_report = sign_purge_report(&state.minter, facts).map_err(internal)?;

    Ok(Json(serde_json::json!({
        "erased": report,
        // Honest signal for the operator runbook: false means either ReBAC
        // is not configured (delete tuples via SpiceDB directly) or the
        // subject was not a `user:` principal (no tuples exist for it).
        "rebac_tuples_deleted": rebac_tuples_deleted,
        "purge_report": purge_report,
    })))
}

/// Build the server-signed purge report envelope over a `facts` object.
///
/// The signature is an HMAC-SHA256 over the *compact* canonical serialization
/// of `facts`, domain-separated under `PURGE_REPORT_DOMAIN` so a purge-report
/// tag can never be replayed as a scope handle or media URI (they share the
/// key). The console recomputes the HMAC over exactly these bytes to verify.
///
/// Honest dev-mode seam: a DURABLE attestation requires a persistent signing
/// key (`VERITY_SIGNING_KEY`, or the scope key). Under an ephemeral per-process
/// key we deliberately emit `signed: false` and NO `signature` — presenting a
/// process-scoped tag (verifiable only within this one process lifetime) as if
/// it were a durable attestation would be a fabricated guarantee. The operator
/// sees `signature: null` and knows to set a persistent key to sign durably.
fn sign_purge_report(
    minter: &crate::scope::ScopeMinter,
    facts: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    // Canonical bytes = compact serialization of the facts object.
    let canonical = serde_json::to_vec(&facts)?;
    let (signature, signed) = if minter.has_persistent_key() {
        (
            serde_json::Value::String(minter.sign_bytes(PURGE_REPORT_DOMAIN, &canonical)),
            true,
        )
    } else {
        // No persistent key: no durable attestation exists. Do not fabricate
        // one — emit null and label it honestly.
        (serde_json::Value::Null, false)
    };
    Ok(serde_json::json!({
        // `facts` is the exact signed object; `signature` (when present) is
        // HMAC-SHA256 over its compact JSON under the server key with the
        // domain tag `verity.erasure.purge-report.v1`.
        "facts": facts,
        "algorithm": "HMAC-SHA256",
        "domain": PURGE_REPORT_DOMAIN,
        // null under an ephemeral key (dev mode): no durable signature emitted.
        "signature": signature,
        // false => ephemeral key: no durable attestation was produced. Set
        // VERITY_SIGNING_KEY (or VERITY_SCOPE_KEY) to sign durably.
        "signed": signed,
    }))
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

#[derive(Deserialize)]
pub(crate) struct DsarParams {
    tenant_id: TenantId,
    subject: String,
}

/// GET /v1/admin/dsar/export?tenant_id=&subject= (admin, SPEC §8e): one
/// machine-readable JSON bundle of everything attributable to the subject —
/// episodes (payloads decrypted under admin authority), their derived
/// chunks, the subject's actions, access-event skeleton, and proposed
/// knowledge items. The export itself is audited.
pub(crate) async fn dsar_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(p): axum::extract::Query<DsarParams>,
) -> HandlerResult<Json<serde_json::Value>> {
    state.admin.check(&headers)?;
    let bundle = state
        .storage
        .inner()
        .dsar_export(p.tenant_id, &p.subject)
        .await
        .map_err(internal)?;
    // Decrypted-under-admin-authority access is itself audited (SPEC §8e).
    let pool = state.pool().clone();
    let tenant_id = p.tenant_id;
    tokio::spawn(async move {
        let result = sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, actor_sub, actor_azp, verb, principals,
                                    entity_scope, confidentiality, query_summary, result_ids)
             VALUES ($1, $2, NULL, NULL, 'dsar_export', '{}', '{}', 0, $3, '{}')",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind("dsar export (subject withheld from log)")
        .execute(&pool)
        .await;
        if let Err(e) = result {
            tracing::warn!("dsar_export audit insert failed: {e}");
        }
    });
    Ok(Json(bundle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{ScopeMinter, ScopeError};

    /// A representative purge-facts object, shaped exactly like `admin_erasure`
    /// builds it: hashed identifiers only, per-table counts, timestamps.
    fn sample_facts() -> serde_json::Value {
        serde_json::json!({
            "kind": "verity.erasure.purge-report",
            "tenant_id": uuid::Uuid::now_v7(),
            "subject_sha256": super::sha256_hex("user:alice@example.com"),
            "entity_sha256": serde_json::Value::Null,
            "media_ids": Vec::<uuid::Uuid>::new(),
            "erased": serde_json::json!({ "episodes": 3, "chunks": 12, "facts": 5, "actions": 1 }),
            "rebac_tuples_deleted": true,
            "signed_at": chrono::Utc::now(),
            "retention_window": "backups age out then crypto-shredded; live rows destroyed now",
        })
    }

    /// (a) With a persistent signing key, the purge report carries a real
    /// signature, `signed == true`, and the signature VERIFIES against the
    /// exact facts under the purge-report domain.
    #[test]
    fn persistent_key_signs_durably_and_verifies() {
        let minter = ScopeMinter::from_key_persistent([0x42u8; 32]);
        let facts = sample_facts();
        let report = sign_purge_report(&minter, facts.clone()).expect("build report");

        assert_eq!(report["signed"], serde_json::json!(true));
        assert_eq!(report["algorithm"], serde_json::json!("HMAC-SHA256"));
        assert_eq!(report["domain"], serde_json::json!(PURGE_REPORT_DOMAIN));

        let sig = report["signature"].as_str().expect("signature present");
        // Recompute over the SAME canonical bytes the signer used: compact
        // serialization of the facts object echoed back in the report.
        let canonical = serde_json::to_vec(&report["facts"]).expect("canon");
        minter
            .verify_bytes(PURGE_REPORT_DOMAIN, &canonical, sig)
            .expect("signature verifies against the signed facts");

        // The echoed facts are byte-identical to the input we signed.
        assert_eq!(report["facts"], facts);
    }

    /// (a') Domain separation is load-bearing: the same tag must NOT verify
    /// under a different domain (e.g. a media-URI or scope-handle surface),
    /// so a purge signature can never be replayed as another credential.
    #[test]
    fn signature_is_domain_separated() {
        let minter = ScopeMinter::from_key_persistent([0x11u8; 32]);
        let report = sign_purge_report(&minter, sample_facts()).expect("build report");
        let sig = report["signature"].as_str().expect("signature present");
        let canonical = serde_json::to_vec(&report["facts"]).expect("canon");

        assert!(matches!(
            minter.verify_bytes("verity.media.v1", &canonical, sig),
            Err(ScopeError::BadSignature)
        ));
    }

    /// (b) With NO persistent key (dev / ephemeral), the report is honestly
    /// `signed == false` and emits NO signature — a process-scoped tag is never
    /// dressed up as a durable attestation.
    #[test]
    fn ephemeral_key_emits_no_signature() {
        let minter = ScopeMinter::ephemeral();
        let report = sign_purge_report(&minter, sample_facts()).expect("build report");

        assert_eq!(report["signed"], serde_json::json!(false));
        assert!(
            report["signature"].is_null(),
            "no bogus signature under an ephemeral key, got {:?}",
            report["signature"]
        );
        // The facts and metadata are still present and honest.
        assert_eq!(report["algorithm"], serde_json::json!("HMAC-SHA256"));
        assert_eq!(report["facts"]["kind"], serde_json::json!("verity.erasure.purge-report"));
    }

    /// (c) Tampering with the signed facts breaks verification: a holder who
    /// alters a per-table count (or any field) cannot re-derive a valid tag
    /// without the server key.
    #[test]
    fn tampering_with_facts_breaks_verification() {
        let minter = ScopeMinter::from_key_persistent([0x7fu8; 32]);
        let facts = sample_facts();
        let report = sign_purge_report(&minter, facts.clone()).expect("build report");
        let sig = report["signature"].as_str().expect("signature present");

        // Flip a purge count in the attested facts, re-serialize canonically.
        let mut tampered = facts;
        tampered["erased"]["episodes"] = serde_json::json!(9999);
        let tampered_canonical = serde_json::to_vec(&tampered).expect("canon");

        assert!(matches!(
            minter.verify_bytes(PURGE_REPORT_DOMAIN, &tampered_canonical, sig),
            Err(ScopeError::BadSignature)
        ));

        // Sanity: the untampered facts still verify with the same tag.
        let good_canonical = serde_json::to_vec(&report["facts"]).expect("canon");
        assert!(minter
            .verify_bytes(PURGE_REPORT_DOMAIN, &good_canonical, sig)
            .is_ok());
    }

    /// The report's hashed subject identifier matches the sha256 the surviving
    /// audit row would carry — never plaintext PII — so a holder can cross-check
    /// the report against audit.
    #[test]
    fn signed_facts_use_sha256_not_plaintext() {
        let subject = "user:carol@example.com";
        let hashed = super::sha256_hex(subject);
        // 64 hex chars, and it is NOT the plaintext.
        assert_eq!(hashed.len(), 64);
        assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hashed, subject);

        let minter = ScopeMinter::from_key_persistent([0x01u8; 32]);
        let facts = serde_json::json!({
            "kind": "verity.erasure.purge-report",
            "subject_sha256": hashed,
        });
        let report = sign_purge_report(&minter, facts).expect("build report");
        assert_eq!(report["facts"]["subject_sha256"], serde_json::json!(hashed));
        // The plaintext subject appears nowhere in the signed report.
        let blob = serde_json::to_string(&report).unwrap();
        assert!(!blob.contains(subject), "plaintext PII leaked into purge report");
    }
}
