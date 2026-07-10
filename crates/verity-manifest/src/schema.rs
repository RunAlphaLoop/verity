//! Manifest schema (manifest_version 1) — serde types, parse-time validation,
//! and the activation contract the human gate enforces.
//!
//! Parse and activation are deliberately different bars:
//! - `Manifest::from_yaml` accepts any structurally valid manifest, including
//!   one with NO `acl_policy` (that is the LLM-authoring stance: an unreviewed
//!   draft can only ever quarantine).
//! - `Manifest::activation_check` is the human gate: it refuses activation
//!   when `acl_policy` is absent or violates the declared tier contract.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::limits;
use crate::path::{Expr, Path};
use crate::predicate::Predicate;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest exceeds {} bytes", limits::MAX_MANIFEST_BYTES)]
    TooLarge,
    #[error("yaml parse error: {0}")]
    Yaml(String),
    #[error("invalid manifest: {0}")]
    Invalid(String),
    #[error("activation refused: {0}")]
    ActivationRefused(String),
    #[error("io error: {0}")]
    Io(String),
}

fn invalid(msg: impl Into<String>) -> ManifestError {
    ManifestError::Invalid(msg.into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: u32,
    pub source: Source,
    pub entities: Vec<EntitySpec>,
    /// Reconciliation backstop. Parse-and-store only in v0 — no poll executor
    /// exists yet; see crate docs.
    #[serde(default)]
    pub poll: Option<Poll>,
    /// REQUIRED-BY-ABSENCE-BEHAVIOR: absent parses fine but the runtime
    /// quarantines everything and activation is refused.
    #[serde(default)]
    pub acl_policy: Option<AclPolicy>,
    /// Conformance harness inputs — the format ships with its test rig.
    #[serde(default)]
    pub fixtures: Vec<Fixture>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub name: String,
    /// ACL-readability tier (SPEC §5e.2 survey). Drives the tier contract at
    /// activation; absent means "no tier claim" and only the generic
    /// acl_policy checks apply.
    #[serde(default)]
    pub tier: Option<Tier>,
    /// Credential reference for the poll lane. Never inline; always a
    /// secret-store ref. Optional: webhook-only manifests need no API
    /// credential.
    #[serde(default)]
    pub auth: Option<Auth>,
    #[serde(default)]
    pub webhook: Option<WebhookSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    A,
    B,
    C,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    /// `secret://<name>` — credentials never appear inline in a manifest.
    pub r#ref: String,
    pub shape: AuthShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthShape {
    StaticKey,
    ClientCredentials,
    RefreshToken,
    ServiceAccountJwt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookSpec {
    #[serde(default)]
    pub signature: Option<SignatureSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureSpec {
    pub scheme: SignatureScheme,
    /// HTTP header carrying the signature (e.g. `Linear-Signature`).
    pub header: String,
    /// `secret://<name>` reference to the shared webhook secret.
    pub secret_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    /// Hex-encoded HMAC-SHA256 of the raw request body (Linear, GitHub-style).
    HmacSha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitySpec {
    pub r#type: String,
    pub route: Route,
    /// Dot-path to the deterministic primary key (idempotent duplicate
    /// absorption). Missing at runtime ⇒ quarantine.
    pub primary_key: String,
    /// Bi-temporal event time: a dot-path or `$now()`. Absent = `$now()`
    /// (receipt time).
    #[serde(default)]
    pub valid_from: Option<String>,
    /// Accepted for forward-compatibility with the SPEC example; the runtime
    /// stamps observation time server-side, so only `$now()` is meaningful
    /// here today.
    #[serde(default)]
    pub observed_at: Option<String>,
    /// field name → dot-path/`$now()`. Every declared path must resolve at
    /// runtime or the payload quarantines (never a partial write).
    #[serde(default)]
    pub map: BTreeMap<String, String>,
    /// Optional dot-path to free text that becomes a retrieval chunk.
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Predicate over the payload (see `predicate`). A payload no entity
    /// claims is quarantined.
    pub when: String,
    #[serde(default)]
    pub operation: Operation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    #[default]
    Upsert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    pub endpoint: String,
    /// e.g. "15m" — opaque to v0 (stored, not executed).
    pub interval: String,
    /// Singer/Meltano-style opaque echoed cursor.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Exactly three modes, no defaultable value (SPEC §5e.3 hard rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclMode {
    Map,
    Static,
    Quarantine,
}

/// Which vocabulary extracted principals live in (Glean's distinction).
/// Determines the principal-registry string the server resolves tokens from:
/// `email` → `user:<value>`, `source_native_id` → `<source>:<value>`,
/// `verity_group` → `group:<value>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityNamespace {
    Email,
    SourceNativeId,
    VerityGroup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclPolicy {
    pub mode: AclMode,
    #[serde(default)]
    pub identity_namespace: Option<IdentityNamespace>,
    /// `map` mode: dot-path extracting the principal set from the payload.
    #[serde(default)]
    pub principals: Option<String>,
    /// Mandatory `true` for Tier B, with a human-readable `note`.
    #[serde(default)]
    pub approximation: bool,
    #[serde(default)]
    pub note: Option<String>,
    /// `static` mode: principal-registry strings this source's writes are
    /// visible to. Absent = the binding webhook's mint-time visibility.
    #[serde(default)]
    pub static_visibility: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    /// Payload JSON, relative to the manifest file.
    pub input: String,
    pub expect: Expect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    /// Expected fact writes (canonical runtime JSON), relative path.
    #[serde(default)]
    pub facts: Option<String>,
    /// Expected content chunks, relative path.
    #[serde(default)]
    pub chunks: Option<String>,
    /// Expected ACL envelopes, relative path.
    #[serde(default)]
    pub acl_envelopes: Option<String>,
    /// The payload must quarantine (fail-closed assertions are first-class).
    #[serde(default)]
    pub quarantined: bool,
    /// Substring the quarantine reason must contain.
    #[serde(default)]
    pub reason_contains: Option<String>,
}

impl Manifest {
    /// Parse + validate. Accepts manifests WITHOUT an acl_policy (they can
    /// only quarantine); refuses structural garbage, unknown fields, and any
    /// expression the bounded dialect cannot parse.
    pub fn from_yaml(yaml: &str) -> Result<Self, ManifestError> {
        if yaml.len() > limits::MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge);
        }
        let manifest: Manifest =
            serde_yaml_ng::from_str(yaml).map_err(|e| ManifestError::Yaml(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        if self.manifest_version != 1 {
            return Err(invalid(format!(
                "unsupported manifest_version {} (this build speaks 1)",
                self.manifest_version
            )));
        }
        let name = &self.source.name;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
        {
            return Err(invalid(format!(
                "source.name {name:?} must be non-empty [a-z0-9_-]"
            )));
        }
        if let Some(auth) = &self.source.auth {
            validate_secret_ref(&auth.r#ref, "source.auth.ref")?;
        }
        if let Some(sig) = self
            .source
            .webhook
            .as_ref()
            .and_then(|w| w.signature.as_ref())
        {
            validate_secret_ref(&sig.secret_ref, "webhook.signature.secret_ref")?;
            if sig.header.trim().is_empty() {
                return Err(invalid("webhook.signature.header must be non-empty"));
            }
        }
        if self.entities.is_empty() {
            return Err(invalid("entities must be non-empty"));
        }
        if self.entities.len() > limits::MAX_ENTITIES {
            return Err(invalid(format!(
                "at most {} entities per manifest",
                limits::MAX_ENTITIES
            )));
        }
        for entity in &self.entities {
            let t = &entity.r#type;
            if t.trim().is_empty() {
                return Err(invalid("entity type must be non-empty"));
            }
            Predicate::parse(&entity.route.when)
                .map_err(|e| invalid(format!("entity {t:?} route.when: {e}")))?;
            Path::parse(&entity.primary_key)
                .map_err(|e| invalid(format!("entity {t:?} primary_key: {e}")))?;
            if let Some(vf) = &entity.valid_from {
                Expr::parse(vf).map_err(|e| invalid(format!("entity {t:?} valid_from: {e}")))?;
            }
            if let Some(oa) = &entity.observed_at {
                Expr::parse(oa).map_err(|e| invalid(format!("entity {t:?} observed_at: {e}")))?;
            }
            if entity.map.len() > limits::MAX_MAP_FIELDS {
                return Err(invalid(format!(
                    "entity {t:?} maps more than {} fields",
                    limits::MAX_MAP_FIELDS
                )));
            }
            for (field, expr) in &entity.map {
                if field.trim().is_empty() {
                    return Err(invalid(format!("entity {t:?} has an empty map field name")));
                }
                Expr::parse(expr).map_err(|e| invalid(format!("entity {t:?} map.{field}: {e}")))?;
            }
            if let Some(content) = &entity.content {
                Path::parse(content).map_err(|e| invalid(format!("entity {t:?} content: {e}")))?;
            }
        }
        if let Some(policy) = &self.acl_policy {
            policy.validate()?;
        }
        for fixture in &self.fixtures {
            if fixture.input.trim().is_empty() {
                return Err(invalid("fixture input path must be non-empty"));
            }
        }
        Ok(())
    }

    /// Effective ACL mode: absent policy ⇒ quarantine (fail closed).
    pub fn acl_mode(&self) -> AclMode {
        self.acl_policy
            .as_ref()
            .map(|p| p.mode)
            .unwrap_or(AclMode::Quarantine)
    }

    /// The human gate (SPEC §5e.3): refuse activation when the acl_policy is
    /// absent or invalid for the declared tier. This runs server-side inside
    /// POST /v1/manifests/{id}/activate — an admin approves exactly what this
    /// check accepted.
    pub fn activation_check(&self) -> Result<(), ManifestError> {
        let refuse = |msg: String| Err(ManifestError::ActivationRefused(msg));
        let Some(policy) = &self.acl_policy else {
            return refuse(
                "manifest has no acl_policy — drafts without one can only quarantine \
                 (add an admin-reviewed acl_policy block, then activate)"
                    .into(),
            );
        };
        match (self.source.tier, policy.mode) {
            (Some(Tier::A), AclMode::Map) => {
                if policy.approximation {
                    return refuse(
                        "Tier A sources mirror real ACLs: approximation must be false".into(),
                    );
                }
            }
            (Some(Tier::A), other) => {
                return refuse(format!(
                    "Tier A sources MUST use acl_policy.mode: map (got {other:?})"
                ));
            }
            (Some(Tier::B), AclMode::Map) => {
                if !policy.approximation {
                    return refuse(
                        "Tier B container-membership mapping MUST set approximation: true".into(),
                    );
                }
                if policy
                    .note
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    return refuse("Tier B requires a human-readable approximation note".into());
                }
            }
            (Some(Tier::B), other) => {
                return refuse(format!(
                    "Tier B sources MUST use acl_policy.mode: map (got {other:?})"
                ));
            }
            (Some(Tier::C), AclMode::Static) => {}
            (Some(Tier::C), other) => {
                return refuse(format!(
                    "Tier C sources MUST use acl_policy.mode: static (got {other:?})"
                ));
            }
            (None, _) => {}
        }
        Ok(())
    }
}

impl AclPolicy {
    fn validate(&self) -> Result<(), ManifestError> {
        match self.mode {
            AclMode::Map => {
                let Some(principals) = &self.principals else {
                    return Err(invalid("acl_policy.mode map requires `principals`"));
                };
                Path::parse(principals)
                    .map_err(|e| invalid(format!("acl_policy.principals: {e}")))?;
                if self.identity_namespace.is_none() {
                    return Err(invalid("acl_policy.mode map requires `identity_namespace`"));
                }
                if self.static_visibility.is_some() {
                    return Err(invalid(
                        "static_visibility belongs to mode: static, not map",
                    ));
                }
            }
            AclMode::Static => {
                if self.principals.is_some() {
                    return Err(invalid("`principals` belongs to mode: map, not static"));
                }
                if let Some(vis) = &self.static_visibility {
                    if vis.is_empty() || vis.iter().any(|p| p.trim().is_empty()) {
                        return Err(invalid(
                            "static_visibility must be absent or a non-empty list of principals",
                        ));
                    }
                }
            }
            AclMode::Quarantine => {
                if self.principals.is_some() || self.static_visibility.is_some() {
                    return Err(invalid(
                        "mode quarantine takes no principals/static_visibility",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_secret_ref(r: &str, what: &str) -> Result<(), ManifestError> {
    let Some(name) = r.strip_prefix("secret://") else {
        return Err(invalid(format!(
            "{what} must be a secret store reference (secret://<name>), got {r:?} — \
             credentials never appear inline"
        )));
    };
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(invalid(format!("{what}: bad secret name {name:?}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(acl_block: &str, tier: &str) -> String {
        format!(
            r#"
manifest_version: 1
source:
  name: linear
{tier}
  webhook:
    signature:
      scheme: hmac_sha256
      header: Linear-Signature
      secret_ref: secret://linear-webhook-secret
entities:
  - type: issue
    route:
      when: "type = 'Issue' and action in ['create','update']"
      operation: upsert
    primary_key: "data.id"
    valid_from: "data.updatedAt"
    map:
      title: "data.title"
      state: "data.state.name"
{acl_block}
"#
        )
    }

    const MAP_ACL: &str = r#"
acl_policy:
  mode: map
  identity_namespace: source_native_id
  principals: "data.team.id"
  approximation: true
  note: "Team membership approximates issue visibility."
"#;

    #[test]
    fn parses_without_acl_but_refuses_activation() {
        let m = Manifest::from_yaml(&minimal("", "")).expect("parse OK without acl_policy");
        assert_eq!(m.acl_mode(), AclMode::Quarantine);
        let err = m.activation_check().unwrap_err();
        assert!(matches!(err, ManifestError::ActivationRefused(_)), "{err}");
    }

    #[test]
    fn tier_contracts() {
        // Tier B + map + approximation + note: activates.
        let m = Manifest::from_yaml(&minimal(MAP_ACL, "  tier: B")).unwrap();
        m.activation_check().expect("tier B map activates");

        // Tier B without approximation: refused.
        let no_approx = MAP_ACL.replace("approximation: true", "approximation: false");
        let m = Manifest::from_yaml(&minimal(&no_approx, "  tier: B")).unwrap();
        assert!(m.activation_check().is_err());

        // Tier A with approximation: refused; without: activates.
        let m = Manifest::from_yaml(&minimal(MAP_ACL, "  tier: A")).unwrap();
        assert!(m.activation_check().is_err());
        let m = Manifest::from_yaml(&minimal(&no_approx, "  tier: A")).unwrap();
        m.activation_check().expect("tier A mirrored map activates");

        // Tier A/B must not be static; Tier C must be static.
        let static_acl = "\nacl_policy:\n  mode: static\n  static_visibility: [\"group:eng\"]\n";
        let m = Manifest::from_yaml(&minimal(static_acl, "  tier: A")).unwrap();
        assert!(m.activation_check().is_err());
        let m = Manifest::from_yaml(&minimal(static_acl, "  tier: C")).unwrap();
        m.activation_check().expect("tier C static activates");
        let m = Manifest::from_yaml(&minimal(MAP_ACL, "  tier: C")).unwrap();
        assert!(m.activation_check().is_err());

        // Quarantine mode parses + never activates under a tier claim A.
        let q = "\nacl_policy:\n  mode: quarantine\n";
        let m = Manifest::from_yaml(&minimal(q, "  tier: A")).unwrap();
        assert!(m.activation_check().is_err());
        // ...but with no tier claim, quarantine mode may be activated (it
        // fails closed by definition).
        let m = Manifest::from_yaml(&minimal(q, "")).unwrap();
        m.activation_check().unwrap();
    }

    #[test]
    fn rejects_bad_shapes() {
        // Unknown top-level field.
        assert!(Manifest::from_yaml(&format!("{}\nbogus: 1", minimal(MAP_ACL, ""))).is_err());
        // Wrong version.
        let v2 = minimal(MAP_ACL, "").replace("manifest_version: 1", "manifest_version: 2");
        assert!(Manifest::from_yaml(&v2).is_err());
        // Inline secret.
        let inline = minimal(MAP_ACL, "").replace("secret://linear-webhook-secret", "hunter2");
        assert!(Manifest::from_yaml(&inline).is_err());
        // Unparseable route predicate.
        let bad_when = minimal(MAP_ACL, "").replace("type = 'Issue'", "type ~~ 'Issue'");
        assert!(Manifest::from_yaml(&bad_when).is_err());
        // map mode without principals.
        let no_principals = minimal(
            "\nacl_policy:\n  mode: map\n  identity_namespace: email\n",
            "",
        );
        assert!(Manifest::from_yaml(&no_principals).is_err());
        // Oversized manifest.
        let huge = format!(
            "{}\n# {}",
            minimal(MAP_ACL, ""),
            "x".repeat(limits::MAX_MANIFEST_BYTES)
        );
        assert!(matches!(
            Manifest::from_yaml(&huge),
            Err(ManifestError::TooLarge)
        ));
    }
}
