//! Phase-2 connector secret intake (SPEC §5e): encrypt-at-rest bearer store,
//! non-secret status read, decrypt-on-demand materialize, and lifecycle
//! (revoke). The fail-closed hermetic cases (KEK-unset refuses; a
//! plaintext-provenance DEK refuses) run without a DB; the round-trip cases
//! require VERITY_TEST_DSN and skip when absent.

use serde_json::json;

use verity_core::adapter::StorageAdapter;
use verity_core::types::*;
use verity_storage::{Kek, PostgresAdapter};

const TEST_KEK_HEX: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";

fn kek() -> Kek {
    Kek::from_hex(TEST_KEK_HEX).expect("valid test KEK")
}

async fn setup(kek: Option<Kek>) -> Option<(PostgresAdapter, TenantId)> {
    let dsn = std::env::var("VERITY_TEST_DSN").ok()?;
    let adapter = PostgresAdapter::connect_with_kek(&dsn, kek)
        .await
        .expect("connect");
    adapter.migrate().await.expect("migrate");
    let tenant = adapter
        .create_tenant(&format!("test-{}", uuid::Uuid::now_v7()))
        .await
        .expect("tenant");
    Some((adapter, tenant))
}

/// Mint the tenant DEK as PLAINTEXT provenance: a keyless deployment writes an
/// L0 episode, which lazily provisions the DEK stored as raw 32 bytes.
async fn mint_plaintext_dek(adapter: &PostgresAdapter, tenant: TenantId) {
    adapter
        .append_episode(NewEpisode {
            tenant_id: tenant,
            source: "agent".into(),
            source_entity: None,
            kind: EpisodeKind::Observation,
            payload: json!({ "seed": "provision the DEK" }),
            content_hash: format!("seed-{}", uuid::Uuid::now_v7()),
            trust_tier: TrustTier::Observation,
            writer_sub: None,
            writer_azp: None,
        })
        .await
        .expect("seed episode");
}

// ---------- fail-closed hard-refuse (require a DB to reach the tenant DEK) ----------

/// Storing a tier-C bearer with VERITY_KEK unset must REFUSE — never
/// warn-and-store-plaintext (unlike the L0 payload path).
#[tokio::test]
async fn kek_unset_store_bearer_refuses() {
    let Some((adapter, tenant)) = setup(None).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let err = adapter
        .store_connector_bearer(tenant, "hubspot", b"pat-secret-abc")
        .await
        .expect_err("no-KEK store must fail closed");
    let msg = format!("{err}");
    assert!(
        msg.contains("VERITY_KEK"),
        "refusal must name the missing KEK: {msg}"
    );
    // And nothing was persisted.
    assert!(adapter
        .get_connector_credential_status(tenant, "hubspot")
        .await
        .unwrap()
        .is_none());
}

/// A DEK minted plaintext BEFORE a KEK was set stays plaintext even after
/// VERITY_KEK is added; storing a secret against it must REFUSE.
#[tokio::test]
async fn plaintext_provenance_dek_store_bearer_refuses() {
    // Phase 1: keyless deployment mints a plaintext DEK for the tenant.
    let Some((keyless, tenant)) = setup(None).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    mint_plaintext_dek(&keyless, tenant).await;

    // Phase 2: a KEK is now configured, but the stored DEK is still plaintext.
    let dsn = std::env::var("VERITY_TEST_DSN").unwrap();
    let keyed = PostgresAdapter::connect_with_kek(&dsn, Some(kek()))
        .await
        .unwrap();
    let err = keyed
        .store_connector_bearer(tenant, "hubspot", b"pat-secret-abc")
        .await
        .expect_err("plaintext-provenance DEK must refuse a secret");
    let msg = format!("{err}");
    assert!(
        msg.contains("plaintext-provenance"),
        "refusal must name the plaintext-provenance DEK: {msg}"
    );
    assert!(keyed
        .get_connector_credential_status(tenant, "hubspot")
        .await
        .unwrap()
        .is_none());
}

// ---------- store → status → materialize → revoke round-trips ----------

/// store → status returns the fingerprint (never the secret); materialize
/// round-trips the plaintext; revoke deletes the row.
#[tokio::test]
async fn bearer_store_status_materialize_revoke_roundtrip() {
    let Some((adapter, tenant)) = setup(Some(kek())).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let secret = b"pat-super-secret-token-value";

    let fingerprint = adapter
        .store_connector_bearer(tenant, "hubspot", secret)
        .await
        .expect("store bearer under KEK");
    assert!(
        fingerprint.starts_with("fp:"),
        "fingerprint is a salted-HMAC prefix: {fingerprint}"
    );
    assert_ne!(
        fingerprint,
        String::from_utf8_lossy(secret),
        "fingerprint must never be the secret"
    );

    // Status discloses only kind/fingerprint/updated_at — never the secret.
    let status = adapter
        .get_connector_credential_status(tenant, "hubspot")
        .await
        .unwrap()
        .expect("status present");
    assert_eq!(status.kind, ConnectorCredentialKind::Bearer);
    assert_eq!(status.fingerprint, fingerprint);
    let status_json = serde_json::to_string(&status).unwrap();
    assert!(
        !status_json.contains("pat-super-secret"),
        "status must never carry the secret: {status_json}"
    );

    // At rest: ciphertext present, path NULL, and the ciphertext is NOT the
    // plaintext secret.
    let row = sqlx::query_as::<_, (Option<Vec<u8>>, Option<String>)>(
        "SELECT ciphertext, path FROM connector_credentials
         WHERE tenant_id = $1 AND source = 'hubspot'",
    )
    .bind(tenant)
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    let ciphertext = row.0.expect("bearer ciphertext present");
    assert!(row.1.is_none(), "bearer stores no path");
    assert_ne!(
        ciphertext.as_slice(),
        secret.as_slice(),
        "the secret must not sit in plaintext at rest"
    );

    // Materialize decrypts on demand back to the exact plaintext.
    let plaintext = adapter
        .materialize_connector_bearer(tenant, "hubspot")
        .await
        .unwrap()
        .expect("bearer materializes");
    assert_eq!(plaintext, secret);

    // A cold-cache fresh adapter with the same KEK also materializes.
    let dsn = std::env::var("VERITY_TEST_DSN").unwrap();
    let fresh = PostgresAdapter::connect_with_kek(&dsn, Some(kek()))
        .await
        .unwrap();
    assert_eq!(
        fresh
            .materialize_connector_bearer(tenant, "hubspot")
            .await
            .unwrap()
            .as_deref(),
        Some(secret.as_slice())
    );

    // Rotation is an upsert: a second store replaces the secret in place.
    let fp2 = adapter
        .store_connector_bearer(tenant, "hubspot", b"rotated-token")
        .await
        .unwrap();
    assert_ne!(fp2, fingerprint, "rotation changes the fingerprint");
    assert_eq!(
        adapter
            .materialize_connector_bearer(tenant, "hubspot")
            .await
            .unwrap()
            .as_deref(),
        Some(b"rotated-token".as_slice())
    );

    // Revoke deletes the row; a second revoke is an honest no-op.
    assert!(adapter
        .revoke_connector_credential(tenant, "hubspot")
        .await
        .unwrap());
    assert!(adapter
        .get_connector_credential_status(tenant, "hubspot")
        .await
        .unwrap()
        .is_none());
    assert!(
        !adapter
            .revoke_connector_credential(tenant, "hubspot")
            .await
            .unwrap(),
        "revoking an absent credential is a no-op, not an error"
    );
    assert!(adapter
        .materialize_connector_bearer(tenant, "hubspot")
        .await
        .unwrap()
        .is_none());
}

/// A tier-A Google SA-key PATH stores with no crypto (KEK not required), gets a
/// fingerprint, reports the `path` kind, and cannot be materialized as a bearer.
#[tokio::test]
async fn path_store_status_and_no_bearer_materialize() {
    // No KEK: path storage must still work (it is not a secret).
    let Some((adapter, tenant)) = setup(None).await else {
        eprintln!("VERITY_TEST_DSN not set; skipping");
        return;
    };
    let path = "/etc/verity/creds/sa-key.json";
    let fingerprint = adapter
        .store_connector_path(tenant, "gdrive", path)
        .await
        .expect("path store needs no KEK");
    assert!(fingerprint.starts_with("fp:"));

    let status = adapter
        .get_connector_credential_status(tenant, "gdrive")
        .await
        .unwrap()
        .expect("path status present");
    assert_eq!(status.kind, ConnectorCredentialKind::Path);
    assert_eq!(status.fingerprint, fingerprint);

    // At rest: path present verbatim, ciphertext NULL.
    let row = sqlx::query_as::<_, (Option<Vec<u8>>, Option<String>)>(
        "SELECT ciphertext, path FROM connector_credentials
         WHERE tenant_id = $1 AND source = 'gdrive'",
    )
    .bind(tenant)
    .fetch_one(adapter.pool())
    .await
    .unwrap();
    assert!(row.0.is_none(), "path kind stores no ciphertext");
    assert_eq!(row.1.as_deref(), Some(path));

    // A path credential has no bearer secret to materialize.
    assert!(adapter
        .materialize_connector_bearer(tenant, "gdrive")
        .await
        .is_err());

    // Revoke removes it.
    assert!(adapter
        .revoke_connector_credential(tenant, "gdrive")
        .await
        .unwrap());
}
