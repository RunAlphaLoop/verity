//! Envelope-encryption plumbing (SPEC §8a, v0 slice — roadmap task 23).
//!
//! The v0 contract, stated honestly:
//!
//! - One 32-byte data-encryption key (DEK) per tenant (not yet per-data-
//!   subject/per-source — that granularity refinement is a schema addition,
//!   not a redesign), generated lazily on the tenant's first L0 write and
//!   stored in `tenant_deks`.
//! - The DEK is itself wrapped with AES-256-GCM under a deployment KEK from
//!   env `VERITY_KEK` (64 hex chars). No KEK configured means the DEK is
//!   stored as raw plaintext bytes and a startup warning fires — envelope
//!   encryption is plumbed but not protecting anything until the KEK exists.
//!   The stored length is the wrap marker: 32 bytes = plaintext DEK,
//!   longer = KEK-wrapped (12-byte nonce || ciphertext+16-byte tag).
//! - When (and only when) a KEK is set, `append_episode` encrypts the L0
//!   payload with the tenant DEK into `episodes.payload_enc` and writes the
//!   `'{}'::jsonb` sentinel into `episodes.payload`. Reads that need the
//!   payload (DSAR export, admin forensics) decrypt on demand via
//!   `PostgresAdapter::episode_payload`. The serving read path never touches
//!   L0 payloads, so recall latency is unaffected.
//! - KEK rotation is offline re-wrap in v0 (documented in
//!   docs/OPERATIONS.md), not automated.
//!
//! Ciphertext layout everywhere: `nonce(12) || AES-256-GCM ciphertext+tag`.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use rand_core::RngCore;

use verity_core::types::{Result, StorageError};

pub(crate) const DEK_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

/// The deployment key-encryption key (SPEC §8a: "file-based in dev" — here,
/// env-based; KMS wrapping is a cloud profile).
pub struct Kek([u8; 32]);

impl Kek {
    /// Read `VERITY_KEK` (64 hex chars). Absent → None with the documented
    /// startup warning; malformed → hard error (a deployment that configured
    /// encryption never runs silently without it).
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var("VERITY_KEK") {
            Ok(hex) if !hex.trim().is_empty() => {
                Ok(Some(Self::from_hex(hex.trim()).map_err(|e| {
                    StorageError::InvalidInput(format!(
                        "VERITY_KEK is set but unusable ({e}); refusing to start"
                    ))
                })?))
            }
            _ => {
                tracing::warn!("at-rest envelope encryption disabled — set VERITY_KEK");
                Ok(None)
            }
        }
    }

    pub fn from_hex(hex: &str) -> std::result::Result<Self, String> {
        if hex.len() != 64 {
            return Err(format!("expected 64 hex chars, got {}", hex.len()));
        }
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| "not valid hex".to_string())?;
        }
        Ok(Self(key))
    }
}

pub(crate) fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    dek
}

/// Wrap a DEK under the KEK: nonce || ciphertext+tag (60 bytes).
pub(crate) fn wrap_dek(kek: &Kek, dek: &[u8; 32]) -> Result<Vec<u8>> {
    encrypt(&kek.0, dek)
}

/// Recover a stored DEK. Length is the wrap marker (see module docs): raw
/// 32 bytes pass through; anything longer requires the KEK to unwrap —
/// fail closed when it is missing.
pub(crate) fn unwrap_dek(kek: Option<&Kek>, stored: &[u8]) -> Result<[u8; 32]> {
    if stored.len() == DEK_BYTES {
        let mut dek = [0u8; 32];
        dek.copy_from_slice(stored);
        return Ok(dek);
    }
    let kek = kek.ok_or_else(|| {
        StorageError::InvalidInput(
            "tenant DEK is KEK-wrapped but VERITY_KEK is not set — cannot decrypt".into(),
        )
    })?;
    let plain = decrypt(&kek.0, stored)?;
    plain
        .try_into()
        .map_err(|_| StorageError::Database("unwrapped DEK has the wrong length".into()))
}

/// AES-256-GCM encrypt: fresh random nonce, output nonce || ciphertext+tag.
pub(crate) fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| StorageError::Database("AES-GCM encryption failed".into()))?;
    let mut out = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Inverse of `encrypt`. Tamper (or wrong key) fails the GCM tag check.
pub(crate) fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_BYTES {
        return Err(StorageError::Database("ciphertext too short".into()));
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_BYTES);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            StorageError::Database("AES-GCM decryption failed (wrong key or tampered data)".into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip_and_tamper_detection() {
        let key = generate_dek();
        let blob = encrypt(&key, b"hello world").unwrap();
        assert_eq!(decrypt(&key, &blob).unwrap(), b"hello world");
        // Nonce is fresh per call: same plaintext, different ciphertext.
        assert_ne!(blob, encrypt(&key, b"hello world").unwrap());
        // Flip a ciphertext byte: tag check fails.
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt(&key, &tampered).is_err());
        // Wrong key fails.
        assert!(decrypt(&generate_dek(), &blob).is_err());
    }

    #[test]
    fn dek_wrap_unwrap_and_plaintext_marker() {
        let kek = Kek::from_hex(&"ab".repeat(32)).unwrap();
        let dek = generate_dek();
        let wrapped = wrap_dek(&kek, &dek).unwrap();
        assert_ne!(
            wrapped.len(),
            DEK_BYTES,
            "wrapped DEK must not look plaintext"
        );
        assert_eq!(unwrap_dek(Some(&kek), &wrapped).unwrap(), dek);
        // Plaintext-stored DEK (no-KEK deployments) passes through by length.
        assert_eq!(unwrap_dek(None, &dek).unwrap(), dek);
        // Wrapped DEK without a KEK fails closed.
        assert!(unwrap_dek(None, &wrapped).is_err());
    }

    #[test]
    fn kek_hex_parsing() {
        assert!(Kek::from_hex(&"0f".repeat(32)).is_ok());
        assert!(Kek::from_hex("deadbeef").is_err());
        assert!(Kek::from_hex(&"zz".repeat(32)).is_err());
    }
}
