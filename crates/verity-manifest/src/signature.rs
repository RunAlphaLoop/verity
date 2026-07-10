//! Webhook signature verification and secret-reference resolution.
//!
//! v1 implements the `hmac_sha256` header scheme: the provider signs the raw
//! request body with a shared secret and sends the hex digest in a header
//! (Linear's `Linear-Signature`, GitHub's `X-Hub-Signature-256` sans prefix).
//! Comparison is constant-time via the `Mac` trait.
//!
//! Secret store, v0: process environment. `secret://linear-webhook-secret`
//! resolves to `VERITY_SECRET_LINEAR_WEBHOOK_SECRET` (uppercased, `-`/`.` →
//! `_`). Deployments mount real secret managers by injecting env vars; the
//! ref shape in the manifest never changes.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Verify a hex-encoded HMAC-SHA256 of `body` under `secret`. Any
/// malformation (odd length, non-hex) fails closed.
pub fn verify_hmac_sha256_hex(secret: &[u8], body: &[u8], header_value: &str) -> bool {
    let Some(expected) = hex_decode(header_value.trim()) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("any key length works");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Hex digest helper (used by tests and the smoke tooling).
pub fn hmac_sha256_hex(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("any key length works");
    mac.update(body);
    let out = mac.finalize().into_bytes();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Map `secret://<name>` to its env-var form and read it. None when the ref
/// is malformed or the variable is unset/empty — callers fail closed.
pub fn resolve_secret_ref(secret_ref: &str) -> Option<String> {
    let var = secret_ref_env_var(secret_ref)?;
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// `secret://linear-webhook-secret` → `VERITY_SECRET_LINEAR_WEBHOOK_SECRET`.
pub fn secret_ref_env_var(secret_ref: &str) -> Option<String> {
    let name = secret_ref.strip_prefix("secret://")?;
    if name.is_empty() {
        return None;
    }
    let mut var = String::from("VERITY_SECRET_");
    for c in name.chars() {
        match c {
            'a'..='z' => var.push(c.to_ascii_uppercase()),
            'A'..='Z' | '0'..='9' => var.push(c),
            '-' | '.' | '_' => var.push('_'),
            _ => return None,
        }
    }
    Some(var)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejections() {
        let secret = b"whsec_test";
        let body = br#"{"action":"create"}"#;
        let sig = hmac_sha256_hex(secret, body);
        assert!(verify_hmac_sha256_hex(secret, body, &sig));
        assert!(verify_hmac_sha256_hex(secret, body, &format!(" {sig} ")));
        // Wrong secret, tampered body, malformed header: all rejected.
        assert!(!verify_hmac_sha256_hex(b"other", body, &sig));
        assert!(!verify_hmac_sha256_hex(secret, b"{}", &sig));
        assert!(!verify_hmac_sha256_hex(secret, body, "zz"));
        assert!(!verify_hmac_sha256_hex(secret, body, "abc")); // odd length
        assert!(!verify_hmac_sha256_hex(secret, body, ""));
    }

    #[test]
    fn secret_ref_mapping() {
        assert_eq!(
            secret_ref_env_var("secret://linear-webhook-secret").as_deref(),
            Some("VERITY_SECRET_LINEAR_WEBHOOK_SECRET")
        );
        assert_eq!(secret_ref_env_var("secret://"), None);
        assert_eq!(secret_ref_env_var("vault://x"), None);
        assert_eq!(secret_ref_env_var("secret://bad name"), None);
    }
}
