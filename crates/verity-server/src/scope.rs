//! MemoryScope handles (SPEC §7c, Milestone B start): server-minted,
//! HMAC-signed, stateless scope credentials.
//!
//! A handle binds tenant, principal set, entity scope, confidentiality
//! ceiling, and actor identity for a session. Every read/write verb accepts
//! ONLY the handle — scope parameters can never be widened by agent-supplied
//! arguments, because the enforcement inputs are inside the signed payload.
//!
//! Milestone A/B seam, stated honestly: at MINT time the caller still supplies
//! principals directly (`POST /v1/scopes`), because the token→SpiceDB→principal
//! resolution plane doesn't exist yet. What this module already guarantees is
//! that scope cannot change AFTER minting — recall/activity/remember/actions
//! all derive enforcement solely from the verified payload.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use verity_core::types::{Confidentiality, PrincipalToken, Scope, TenantId};

type HmacSha256 = Hmac<Sha256>;

const PREFIX: &str = "vs_";
pub const MAX_TTL_SECONDS: i64 = 12 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopePayload {
    pub tenant_id: TenantId,
    pub principals: Vec<PrincipalToken>,
    pub entity_scope: Vec<String>,
    pub max_confidentiality: Confidentiality,
    pub actor_sub: Option<String>,
    pub actor_azp: Option<String>,
    /// Identity-resolved handles (roadmap task 10): the `user:<id>` principal
    /// the token set was resolved FROM. Present iff the scope was minted via
    /// ReBAC subject resolution; read paths use it to re-resolve the caller's
    /// CURRENT group set for the restricted-class recheck. serde-defaulted so
    /// pre-identity handles keep verifying.
    #[serde(default)]
    pub subject: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl ScopePayload {
    pub fn to_scope(&self) -> Scope {
        Scope {
            tenant_id: self.tenant_id,
            principals: self.principals.clone(),
            entity_scope: self.entity_scope.clone(),
            max_confidentiality: self.max_confidentiality,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    #[error("malformed scope handle")]
    Malformed,
    #[error("scope handle signature invalid")]
    BadSignature,
    #[error("scope handle expired")]
    Expired,
}

pub struct ScopeMinter {
    key: [u8; 32],
    /// True when the key came from the environment (survives restarts, shared
    /// across replicas) rather than a random per-process key. Purge-report
    /// signatures made under an ephemeral key are honestly labeled dev-mode:
    /// they verify only within this one process lifetime.
    persistent_key: bool,
}

impl ScopeMinter {
    /// Key from `VERITY_SCOPE_KEY` (64 hex chars) — required for multi-replica
    /// or restart-surviving handles. Absent, a random per-process key is used
    /// and a warning logged: dev-mode handles die with the process, fail closed.
    pub fn from_env() -> Self {
        // A dedicated `VERITY_SIGNING_KEY` takes precedence for the server's
        // signing surface (scope handles, media URIs, purge reports); it falls
        // back to `VERITY_SCOPE_KEY` so existing single-key deployments keep
        // working. Either yields a persistent, restart-surviving key.
        let hex =
            std::env::var("VERITY_SIGNING_KEY").or_else(|_| std::env::var("VERITY_SCOPE_KEY"));
        match hex {
            Ok(hex) => {
                let mut key = [0u8; 32];
                match const_hex_decode(&hex, &mut key) {
                    Ok(()) => Self {
                        key,
                        persistent_key: true,
                    },
                    Err(()) => {
                        tracing::error!(
                            "VERITY_SIGNING_KEY/VERITY_SCOPE_KEY must be 64 hex chars; using ephemeral key"
                        );
                        Self::ephemeral()
                    }
                }
            }
            Err(_) => {
                tracing::warn!(
                    "VERITY_SIGNING_KEY/VERITY_SCOPE_KEY not set: scope handles and purge-report \
                     signatures will not survive a restart (dev mode)"
                );
                Self::ephemeral()
            }
        }
    }

    pub(crate) fn ephemeral() -> Self {
        let mut key = [0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut key);
        Self {
            key,
            persistent_key: false,
        }
    }

    /// Test-only: build a minter from an explicit 32-byte key, flagged as
    /// PERSISTENT — the equivalent of a `VERITY_SIGNING_KEY`-configured server,
    /// but without touching the process environment (so tests stay hermetic and
    /// parallel-safe). Lets a test both produce a purge-report signature and
    /// independently recompute the HMAC over the same facts to verify it.
    #[cfg(test)]
    pub(crate) fn from_key_persistent(key: [u8; 32]) -> Self {
        Self {
            key,
            persistent_key: true,
        }
    }

    /// Whether this minter's key is persistent (env-provided) rather than a
    /// random per-process key. A `false` here is the honest "dev-mode /
    /// process-scoped signature" signal the console surfaces on purge reports.
    pub fn has_persistent_key(&self) -> bool {
        self.persistent_key
    }

    /// Sign arbitrary canonical bytes under the server key — the primitive the
    /// purge-report signer uses. Returns the URL-safe base64 HMAC-SHA256 tag.
    /// Distinct from `sign_media`/scope handles by an explicit domain prefix so
    /// a signature from one surface can never be replayed as another.
    pub fn sign_bytes(&self, domain: &str, msg: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("any key length works");
        mac.update(domain.as_bytes());
        mac.update(b":");
        mac.update(msg);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Verify a URL-safe base64 tag produced by `sign_bytes` over `(domain,
    /// msg)`. Constant-time via the Mac trait; any malformation fails closed.
    /// This is the exact inverse of `sign_bytes` — the purge-report verifier
    /// (console-side, and the erasure tests) checks a report's signature with
    /// this so it can never diverge from how the tag was produced.
    // Exercised by the compliance tests only (the bin has no in-process
    // verifier yet — verification happens holder-side); keep it available
    // without tripping dead_code in non-test builds.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn verify_bytes(&self, domain: &str, msg: &[u8], sig: &str) -> Result<(), ScopeError> {
        let sig = URL_SAFE_NO_PAD
            .decode(sig)
            .map_err(|_| ScopeError::Malformed)?;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("any key length works");
        mac.update(domain.as_bytes());
        mac.update(b":");
        mac.update(msg);
        mac.verify_slice(&sig).map_err(|_| ScopeError::BadSignature)
    }

    pub fn mint(&self, mut payload: ScopePayload, ttl_seconds: i64) -> (String, DateTime<Utc>) {
        let ttl = ttl_seconds.clamp(60, MAX_TTL_SECONDS);
        payload.expires_at = Utc::now() + Duration::seconds(ttl);
        let body = serde_json::to_vec(&payload).expect("payload serializes");
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("any key length works");
        mac.update(&body);
        let sig = mac.finalize().into_bytes();
        let handle = format!(
            "{PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(&body),
            URL_SAFE_NO_PAD.encode(sig)
        );
        (handle, payload.expires_at)
    }

    /// Signed media URI (roadmap task 9): HMAC over "media:<id>:<exp>" under
    /// the same server key as scope handles. `expires_at` is unix seconds.
    pub fn sign_media(&self, media_id: uuid::Uuid, expires_at: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("any key length works");
        mac.update(format!("media:{media_id}:{expires_at}").as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Verify a signed media URI: expiry first, then constant-time signature
    /// check. Any malformation fails closed.
    pub fn verify_media(
        &self,
        media_id: uuid::Uuid,
        expires_at: i64,
        sig: &str,
    ) -> Result<(), ScopeError> {
        if expires_at < Utc::now().timestamp() {
            return Err(ScopeError::Expired);
        }
        let sig = URL_SAFE_NO_PAD
            .decode(sig)
            .map_err(|_| ScopeError::Malformed)?;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("any key length works");
        mac.update(format!("media:{media_id}:{expires_at}").as_bytes());
        mac.verify_slice(&sig).map_err(|_| ScopeError::BadSignature)
    }

    pub fn verify(&self, handle: &str) -> Result<ScopePayload, ScopeError> {
        let rest = handle.strip_prefix(PREFIX).ok_or(ScopeError::Malformed)?;
        let (body_b64, sig_b64) = rest.split_once('.').ok_or(ScopeError::Malformed)?;
        let body = URL_SAFE_NO_PAD
            .decode(body_b64)
            .map_err(|_| ScopeError::Malformed)?;
        let sig = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| ScopeError::Malformed)?;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("any key length works");
        mac.update(&body);
        // Constant-time comparison via the Mac trait.
        mac.verify_slice(&sig)
            .map_err(|_| ScopeError::BadSignature)?;
        let payload: ScopePayload =
            serde_json::from_slice(&body).map_err(|_| ScopeError::Malformed)?;
        if payload.expires_at < Utc::now() {
            return Err(ScopeError::Expired);
        }
        Ok(payload)
    }
}

/// Decode exactly 64 hex chars into 32 bytes.
fn const_hex_decode(hex: &str, out: &mut [u8; 32]) -> Result<(), ()> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(());
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> ScopePayload {
        ScopePayload {
            tenant_id: uuid::Uuid::now_v7(),
            principals: vec![7, 9],
            entity_scope: vec!["account:acme".into()],
            max_confidentiality: Confidentiality::Confidential,
            actor_sub: Some("user:matt".into()),
            actor_azp: Some("agent:sales-bot".into()),
            subject: None,
            expires_at: Utc::now(),
        }
    }

    #[test]
    fn roundtrip_and_tamper_resistance() {
        let minter = ScopeMinter::ephemeral();
        let (handle, _) = minter.mint(payload(), 300);
        let verified = minter.verify(&handle).expect("valid handle verifies");
        assert_eq!(verified.principals, vec![7, 9]);
        assert_eq!(verified.entity_scope, vec!["account:acme".to_string()]);

        // Any payload mutation breaks the signature: swap one body char.
        let body_region = &handle[PREFIX.len()..PREFIX.len() + 20];
        let flipped = body_region.replace(
            body_region.chars().next().unwrap(),
            if body_region.starts_with('A') {
                "B"
            } else {
                "A"
            },
        );
        let tampered = format!(
            "{PREFIX}{}{}",
            flipped,
            &handle[PREFIX.len() + body_region.len()..]
        );
        assert!(matches!(
            minter.verify(&tampered),
            Err(ScopeError::BadSignature) | Err(ScopeError::Malformed)
        ));

        // A different server key rejects the handle.
        assert!(matches!(
            ScopeMinter::ephemeral().verify(&handle),
            Err(ScopeError::BadSignature)
        ));
    }

    #[test]
    fn media_signatures_verify_and_fail_closed() {
        let minter = ScopeMinter::ephemeral();
        let id = uuid::Uuid::now_v7();
        let exp = Utc::now().timestamp() + 60;
        let sig = minter.sign_media(id, exp);
        assert!(minter.verify_media(id, exp, &sig).is_ok());
        // Wrong id, shifted expiry, expired stamp, foreign key: all rejected.
        assert!(minter
            .verify_media(uuid::Uuid::now_v7(), exp, &sig)
            .is_err());
        assert!(minter.verify_media(id, exp + 1, &sig).is_err());
        let past = Utc::now().timestamp() - 1;
        let stale = minter.sign_media(id, past);
        assert!(matches!(
            minter.verify_media(id, past, &stale),
            Err(ScopeError::Expired)
        ));
        assert!(ScopeMinter::ephemeral()
            .verify_media(id, exp, &sig)
            .is_err());
    }

    #[test]
    fn expiry_is_enforced_and_ttl_clamped() {
        let minter = ScopeMinter::ephemeral();
        let (handle, expires_at) = minter.mint(payload(), -5);
        // Negative TTL clamps to the 60s floor, so it verifies now...
        assert!(minter.verify(&handle).is_ok());
        assert!(expires_at > Utc::now());
        // ...and the ceiling clamps too.
        let (_, far) = minter.mint(payload(), i64::MAX);
        assert!(far <= Utc::now() + Duration::seconds(MAX_TTL_SECONDS + 5));
    }
}
