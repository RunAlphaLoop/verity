//! Community manifest registry support (SPEC §5e.3: "a git repo of signed
//! YAML files at v0.1").
//!
//! This module owns the *registry-support* types only — it does NOT touch the
//! manifest schema or runtime semantics. It provides:
//!
//! - [`RegistryIndex`] / [`RegistryEntry`]: the `index.json` catalog shape.
//! - sha256 integrity ([`sha256_hex`]) over the manifest bytes.
//! - detached manifest-file *signatures* ([`sign_manifest`] / [`verify_manifest_signature`]),
//!   distinct from the webhook HMAC in [`crate::signature`].
//! - [`verify_entry`]: the fail-closed check that `manifest fetch`/`install`
//!   run before touching a manifest — integrity first, then signature.
//!
//! # Signing decision (v0) — honest limits
//!
//! We reuse verity-manifest's existing HMAC-SHA256 primitive rather than pull
//! in an ed25519 stack, for two reasons: (1) zero new supply-chain
//! dependencies in a crate whose whole premise is "connectors are data, not
//! code — no supply-chain code execution"; (2) the webhook lane already
//! establishes HMAC-SHA256 as the crate's trust primitive.
//!
//! A signature here is a **detached hex HMAC-SHA256 of the manifest bytes**
//! under a maintainer key resolved from the environment
//! (`VERITY_REGISTRY_SIGNING_KEY`, mirroring the `secret://` env story). The
//! `.sig` file holds the hex digest.
//!
//! **The honest limitation, stated plainly:** HMAC is a *symmetric* MAC. It
//! proves the signer held the shared maintainer key — it is authenticity
//! relative to that key, not public-key non-repudiation. Anyone who can verify
//! can also forge, so the key must stay maintainer-only (never shipped to
//! clients that merely *verify*). The sha256 in `index.json` is *integrity*
//! only: it proves the bytes match the catalog, not who authored them. This is
//! deliberately a v0 story. The `verified` tier's real threat model wants a
//! public-key signature (ed25519) so verifiers hold only a public key; that is
//! the documented next step (see `registry/README.md`), gated — like the rest
//! of the certification machinery — on ≥10 community manifests existing.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::signature::{hmac_sha256_hex, verify_hmac_sha256_hex};

/// Env var holding the maintainer HMAC signing key, mirroring the
/// `secret://` → `VERITY_SECRET_*` convention in [`crate::signature`].
pub const SIGNING_KEY_ENV: &str = "VERITY_REGISTRY_SIGNING_KEY";

/// Certification tier for a registry entry (SPEC §5e.3). `community` is the
/// only tier that ships at v0; `verified` is documented, not yet operated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryTier {
    /// Self-attested: unsigned-by-us. Integrity (sha256) is guaranteed; a
    /// signature, if present, is contributor-attested, not maintainer-vouched.
    Community,
    /// Signed by a Verity maintainer key. Documented for v0; the maintainer
    /// key story is HMAC (see module docs), pending the ed25519 upgrade.
    Verified,
}

impl RegistryTier {
    pub fn as_str(self) -> &'static str {
        match self {
            RegistryTier::Community => "community",
            RegistryTier::Verified => "verified",
        }
    }
}

/// One catalog entry in `registry/index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// The manifest's `source.name` — the catalog key and CLI selector.
    pub name: String,
    /// The manifest version string (mirrors `manifest_version` / a semver the
    /// contributor stamps). Free-form; used for display + fetch naming.
    pub version: String,
    /// One-line human description for `manifest list`.
    pub description: String,
    /// Certification tier.
    pub tier: RegistryTier,
    /// Registry-relative path to the manifest YAML (e.g. `manifests/linear.yaml`).
    pub path: String,
    /// Lowercase hex sha256 of the manifest bytes at `path` — the integrity
    /// anchor. Checked before every fetch/install; a mismatch fails closed.
    pub sha256: String,
    /// Registry-relative path to the detached signature file, when present
    /// (e.g. `signatures/linear.sig`). `None` ⇒ unsigned (only ever legal for
    /// the `community` tier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_ref: Option<String>,
}

/// The `index.json` document: a versioned catalog of entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryIndex {
    /// Catalog schema version (1). Distinct from any manifest's version.
    pub registry_version: u32,
    pub entries: Vec<RegistryEntry>,
}

impl RegistryIndex {
    /// Parse an `index.json` byte slice.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("invalid registry index.json: {e}"))
    }

    /// Look up an entry by `source.name`.
    pub fn find(&self, name: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|e| e.name == name)
    }
}

/// Lowercase hex sha256 of `bytes` — the `index.json` integrity anchor.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Sign manifest bytes with a maintainer key → detached hex HMAC-SHA256, the
/// content of a `.sig` file. Distinct from the webhook body HMAC only by
/// intent; the primitive is shared on purpose.
pub fn sign_manifest(signing_key: &[u8], manifest_bytes: &[u8]) -> String {
    hmac_sha256_hex(signing_key, manifest_bytes)
}

/// Verify a detached manifest signature: `signature_hex` must be the HMAC of
/// `manifest_bytes` under `signing_key`. Any malformation fails closed.
pub fn verify_manifest_signature(
    signing_key: &[u8],
    manifest_bytes: &[u8],
    signature_hex: &str,
) -> bool {
    verify_hmac_sha256_hex(signing_key, manifest_bytes, signature_hex)
}

/// Read the maintainer signing key from the environment. None (fail closed)
/// when unset/empty — a `verified`-tier verify without a key cannot pass.
pub fn signing_key_from_env() -> Option<Vec<u8>> {
    match std::env::var(SIGNING_KEY_ENV) {
        Ok(v) if !v.is_empty() => Some(v.into_bytes()),
        _ => None,
    }
}

/// Outcome of verifying a fetched manifest against its catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// sha256(manifest bytes) matched the entry's `sha256`.
    pub integrity_ok: bool,
    /// Signature state — see [`SignatureState`].
    pub signature: SignatureState,
}

impl VerifyReport {
    /// Fail-closed pass/fail: integrity must hold, and the signature must not
    /// be a hard failure. A `community` entry with no signature passes on
    /// integrity alone; a `verified` entry that is unsigned or fails its
    /// signature does NOT pass.
    pub fn passed(&self) -> bool {
        self.integrity_ok
            && matches!(
                self.signature,
                SignatureState::Ok | SignatureState::NoneCommunity
            )
    }
}

/// The signature dimension of a verify, kept separate from integrity so the
/// CLI can report exactly why a check passed or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureState {
    /// A signature was present and verified under the maintainer key.
    Ok,
    /// No signature, and the entry is `community` tier — legal (self-attested).
    NoneCommunity,
    /// A `verified` entry carries no `signature_ref` — a fail-closed refusal.
    MissingButRequired,
    /// A signature was present but did not verify (tamper, wrong key).
    BadSignature,
    /// A signature was declared but the maintainer key is unavailable to
    /// verify it (`VERITY_REGISTRY_SIGNING_KEY` unset). Fail closed.
    KeyUnavailable,
}

impl SignatureState {
    pub fn describe(&self) -> &'static str {
        match self {
            SignatureState::Ok => "signature verified under the maintainer key",
            SignatureState::NoneCommunity => "no signature (community tier, self-attested)",
            SignatureState::MissingButRequired => {
                "verified tier requires a signature but none is present"
            }
            SignatureState::BadSignature => "signature did not verify (tampered or wrong key)",
            SignatureState::KeyUnavailable => {
                "signature present but VERITY_REGISTRY_SIGNING_KEY is unset — cannot verify"
            }
        }
    }
}

/// Verify a fetched manifest against its catalog entry, fail-closed.
///
/// - `entry`: the `index.json` row (carries expected sha256, tier, signature_ref).
/// - `manifest_bytes`: the bytes read from the manifest path.
/// - `signature_hex`: the `.sig` file content, when the entry declares one.
/// - `signing_key`: the maintainer key, when available (for `verified` tier).
///
/// Integrity is always checked. The signature dimension depends on tier +
/// whether a signature/key is present. `report.passed()` is the single gate.
pub fn verify_entry(
    entry: &RegistryEntry,
    manifest_bytes: &[u8],
    signature_hex: Option<&str>,
    signing_key: Option<&[u8]>,
) -> VerifyReport {
    let actual = sha256_hex(manifest_bytes);
    let integrity_ok = actual.eq_ignore_ascii_case(&entry.sha256);

    let signature = match (entry.signature_ref.as_deref(), signature_hex) {
        // No signature declared/present.
        (None, _) | (_, None) => match entry.tier {
            RegistryTier::Community => SignatureState::NoneCommunity,
            RegistryTier::Verified => SignatureState::MissingButRequired,
        },
        // A signature is present: it must verify under a maintainer key.
        (Some(_), Some(sig)) => match signing_key {
            None => SignatureState::KeyUnavailable,
            Some(key) => {
                if verify_manifest_signature(key, manifest_bytes, sig) {
                    SignatureState::Ok
                } else {
                    SignatureState::BadSignature
                }
            }
        },
    };

    VerifyReport {
        integrity_ok,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &[u8] = b"manifest_version: 1\nsource:\n  name: linear\n";
    const KEY: &[u8] = b"maintainer-key-v0";

    fn entry(tier: RegistryTier, sig: Option<&str>) -> RegistryEntry {
        RegistryEntry {
            name: "linear".into(),
            version: "1".into(),
            description: "Linear".into(),
            tier,
            path: "manifests/linear.yaml".into(),
            sha256: sha256_hex(MANIFEST),
            signature_ref: sig.map(String::from),
        }
    }

    #[test]
    fn sha256_is_stable_and_lowercase_hex() {
        let h = sha256_hex(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sig = sign_manifest(KEY, MANIFEST);
        assert!(verify_manifest_signature(KEY, MANIFEST, &sig));
        // Tampered bytes, wrong key, malformed sig: all fail closed.
        assert!(!verify_manifest_signature(KEY, b"tampered", &sig));
        assert!(!verify_manifest_signature(b"other-key", MANIFEST, &sig));
        assert!(!verify_manifest_signature(KEY, MANIFEST, "zz"));
    }

    #[test]
    fn community_unsigned_passes_on_integrity() {
        let e = entry(RegistryTier::Community, None);
        let r = verify_entry(&e, MANIFEST, None, None);
        assert!(r.integrity_ok);
        assert_eq!(r.signature, SignatureState::NoneCommunity);
        assert!(r.passed());
    }

    #[test]
    fn tampered_manifest_fails_integrity() {
        let e = entry(RegistryTier::Community, None);
        let r = verify_entry(&e, b"tampered manifest bytes", None, None);
        assert!(!r.integrity_ok);
        assert!(!r.passed());
    }

    #[test]
    fn community_signed_verifies_when_key_present() {
        let sig = sign_manifest(KEY, MANIFEST);
        let e = entry(RegistryTier::Community, Some("signatures/linear.sig"));
        let r = verify_entry(&e, MANIFEST, Some(&sig), Some(KEY));
        assert_eq!(r.signature, SignatureState::Ok);
        assert!(r.passed());
    }

    #[test]
    fn signed_entry_with_bad_signature_fails() {
        let e = entry(RegistryTier::Community, Some("signatures/linear.sig"));
        let r = verify_entry(&e, MANIFEST, Some("deadbeef"), Some(KEY));
        assert_eq!(r.signature, SignatureState::BadSignature);
        assert!(!r.passed());
    }

    #[test]
    fn verified_tier_unsigned_is_refused() {
        let e = entry(RegistryTier::Verified, None);
        let r = verify_entry(&e, MANIFEST, None, None);
        assert_eq!(r.signature, SignatureState::MissingButRequired);
        assert!(!r.passed());
    }

    #[test]
    fn verified_signed_but_no_key_fails_closed() {
        let sig = sign_manifest(KEY, MANIFEST);
        let e = entry(RegistryTier::Verified, Some("signatures/linear.sig"));
        let r = verify_entry(&e, MANIFEST, Some(&sig), None);
        assert_eq!(r.signature, SignatureState::KeyUnavailable);
        assert!(!r.passed());
    }

    #[test]
    fn index_roundtrips_and_finds() {
        let idx = RegistryIndex {
            registry_version: 1,
            entries: vec![entry(RegistryTier::Community, None)],
        };
        let bytes = serde_json::to_vec(&idx).unwrap();
        let back = RegistryIndex::from_json(&bytes).unwrap();
        assert!(back.find("linear").is_some());
        assert!(back.find("nope").is_none());
    }
}
